//! End-to-end WebSocket tests against an in-process echo server over a real
//! TCP socket. Unlike the unit tests (which drive the frame loop over an
//! in-memory mock), these exercise the full handshake, client-side masking,
//! and — for the CLI test — the `rsurl` binary's `ws://` mode.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use rsurl::{WebSocket, WsMessage};

const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Minimal RFC 4648 base64 (matches the client's encoder).
fn base64(input: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        out.push(A[(b[0] >> 2) as usize] as char);
        out.push(A[(((b[0] & 0x03) << 4) | (b[1] >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(A[(((b[1] & 0x0F) << 2) | (b[2] >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(A[(b[2] & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn accept_key(key: &str) -> String {
    use purecrypto::hash::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(key.as_bytes());
    h.update(GUID.as_bytes());
    base64(h.finalize().as_ref())
}

fn read_exact(s: &mut TcpStream, buf: &mut [u8]) -> std::io::Result<()> {
    let mut got = 0;
    while got < buf.len() {
        let n = s.read(&mut buf[got..])?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        got += n;
    }
    Ok(())
}

/// Read one client→server frame (always masked). Returns `(opcode, payload)`.
fn read_client_frame(s: &mut TcpStream) -> std::io::Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 2];
    read_exact(s, &mut hdr)?;
    let opcode = hdr[0] & 0x0F;
    let len7 = hdr[1] & 0x7F;
    let len = match len7 {
        126 => {
            let mut e = [0u8; 2];
            read_exact(s, &mut e)?;
            u16::from_be_bytes(e) as usize
        }
        127 => {
            let mut e = [0u8; 8];
            read_exact(s, &mut e)?;
            u64::from_be_bytes(e) as usize
        }
        n => n as usize,
    };
    let mut mask = [0u8; 4];
    read_exact(s, &mut mask)?;
    let mut payload = vec![0u8; len];
    read_exact(s, &mut payload)?;
    for (i, b) in payload.iter_mut().enumerate() {
        *b ^= mask[i & 3];
    }
    Ok((opcode, payload))
}

/// Build an unmasked server→client frame.
fn server_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x80 | opcode];
    let n = payload.len();
    if n < 126 {
        out.push(n as u8);
    } else if n <= u16::MAX as usize {
        out.push(126);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        out.push(127);
        out.extend_from_slice(&(n as u64).to_be_bytes());
    }
    out.extend_from_slice(payload);
    out
}

/// Spawn an echo server: completes the handshake, then echoes every data frame
/// back and replies to a client CLOSE with its own CLOSE. Returns the port.
fn start_echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let Ok((mut s, _)) = listener.accept() else {
            return;
        };
        s.set_read_timeout(Some(Duration::from_secs(10))).ok();

        // Read the handshake request up to the blank line, capturing the key.
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        while s.read(&mut byte).map(|n| n == 1).unwrap_or(false) {
            buf.push(byte[0]);
            if buf.ends_with(b"\r\n\r\n") {
                break;
            }
            if buf.len() > 64 * 1024 {
                return;
            }
        }
        let head = String::from_utf8_lossy(&buf);
        let key = head
            .lines()
            .find_map(|l| {
                l.split_once(':')
                    .filter(|(k, _)| k.eq_ignore_ascii_case("sec-websocket-key"))
            })
            .map(|(_, v)| v.trim().to_string())
            .unwrap_or_default();

        let resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {}\r\n\r\n",
            accept_key(&key)
        );
        if s.write_all(resp.as_bytes()).is_err() {
            return;
        }

        loop {
            let Ok((opcode, payload)) = read_client_frame(&mut s) else {
                return;
            };
            match opcode {
                // Echo text/binary straight back.
                0x1 | 0x2 if s.write_all(&server_frame(opcode, &payload)).is_err() => {
                    return;
                }
                0x1 | 0x2 => {}
                0x8 => {
                    // Client close → echo a close and finish.
                    let _ = s.write_all(&server_frame(0x8, &[]));
                    return;
                }
                0x9 => {
                    // Ping → pong.
                    let _ = s.write_all(&server_frame(0xA, &payload));
                }
                _ => {}
            }
        }
    });
    port
}

#[test]
fn library_round_trips_text_over_real_socket() {
    let port = start_echo_server();
    let mut ws = WebSocket::connect(&format!("ws://127.0.0.1:{port}/")).expect("connect");
    ws.send_text("hello over the wire").expect("send");
    match ws.recv().expect("recv") {
        Some(WsMessage::Text(t)) => assert_eq!(t, "hello over the wire"),
        other => panic!("expected echoed text, got {other:?}"),
    }
    ws.send_binary(&[1, 2, 3, 4]).expect("send binary");
    match ws.recv().expect("recv") {
        Some(WsMessage::Binary(b)) => assert_eq!(b, vec![1, 2, 3, 4]),
        other => panic!("expected echoed binary, got {other:?}"),
    }
    ws.close().expect("close");
    // After our close, draining yields the server's close echo.
    assert_eq!(ws.recv().expect("drain"), None);
}

/// #13: a server that selects a subprotocol from the offered list; the client
/// must surface it via `WebSocket::subprotocol()`.
#[test]
fn subprotocol_is_negotiated() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let Ok((mut s, _)) = listener.accept() else {
            return;
        };
        s.set_read_timeout(Some(Duration::from_secs(10))).ok();
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        while s.read(&mut byte).map(|n| n == 1).unwrap_or(false) {
            buf.push(byte[0]);
            if buf.ends_with(b"\r\n\r\n") {
                break;
            }
            if buf.len() > 64 * 1024 {
                return;
            }
        }
        let head = String::from_utf8_lossy(&buf);
        let key = head
            .lines()
            .find_map(|l| {
                l.split_once(':')
                    .filter(|(k, _)| k.eq_ignore_ascii_case("sec-websocket-key"))
            })
            .map(|(_, v)| v.trim().to_string())
            .unwrap_or_default();
        // Confirm the client offered the protocols, then pick the second.
        let offered = head
            .lines()
            .find_map(|l| {
                l.split_once(':')
                    .filter(|(k, _)| k.eq_ignore_ascii_case("sec-websocket-protocol"))
            })
            .map(|(_, v)| v.trim().to_string())
            .unwrap_or_default();
        assert!(offered.contains("chat.v1") && offered.contains("chat.v2"));
        let resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Protocol: chat.v2\r\n\
             Sec-WebSocket-Accept: {}\r\n\r\n",
            accept_key(&key)
        );
        let _ = s.write_all(resp.as_bytes());
        // Keep the socket open briefly so the client's close can land.
        thread::sleep(Duration::from_millis(200));
    });

    let ws = WebSocket::connect_with_subprotocols(
        &format!("ws://127.0.0.1:{port}/"),
        &["chat.v1", "chat.v2"],
    )
    .expect("connect");
    assert_eq!(ws.subprotocol(), Some("chat.v2"));
}

#[test]
fn cli_sends_stdin_lines_and_prints_echoes() {
    use std::process::{Command, Stdio};
    let port = start_echo_server();
    let bin = env!("CARGO_BIN_EXE_rsurl");

    let mut child = Command::new(bin)
        .arg(format!("ws://127.0.0.1:{port}/"))
        // --max-time bounds the run in case the server misbehaves; the closing
        // handshake should end it well before this.
        .arg("--max-time")
        .arg("10")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rsurl");

    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"alpha\nbeta\n")
        .expect("write stdin");

    let out = child.wait_with_output().expect("wait");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Each piped line was sent as a message and echoed back, one per line.
    assert!(
        stdout.contains("alpha"),
        "stdout missing 'alpha'.\nstdout={stdout:?}\nstderr={stderr:?}"
    );
    assert!(stdout.contains("beta"), "stdout missing 'beta': {stdout:?}");
    assert!(out.status.success(), "rsurl exited with {:?}", out.status);
}

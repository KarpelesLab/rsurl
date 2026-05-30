//! WebSocket support (RFC 6455).
//!
//! WS handshakes are HTTP/1.1 `Upgrade: websocket` requests followed by
//! binary/text frames. We perform the handshake by hand (so we can sit on the
//! raw stream without buffered-reader leftovers eating into the frame
//! channel), then drive a proper frame loop. For `wss://`, the TCP stream is
//! wrapped with [`crate::tls::connect_over`] before sending the upgrade.
//!
//! What this module does:
//!   * Send-side data frames: [`send_message`] writes a masked client
//!     text/binary frame (client frames MUST be masked, RFC 6455 §5.3).
//!   * Receive-side reassembly: [`read_message`] runs a frame loop that
//!     stitches an initial data frame (FIN=0) and its CONTINUATION frames
//!     (opcode 0x0) back into one message, enforcing the
//!     [`MAX_PAYLOAD_BYTES`] cap on the *cumulative* reassembled size so a
//!     fragmented bomb can't slip past it.
//!   * Control frames inline: a PING is answered with a PONG echoing its
//!     application data, an unsolicited PONG is ignored, and a CLOSE is
//!     answered with a CLOSE before returning cleanly. Control frames are
//!     handled both while waiting for the first data frame and in between
//!     fragments. Per §5.4/§5.5 control frames must not be fragmented and
//!     carry at most 125 bytes; violations are rejected as protocol errors.
//!
//! Limitations of this scaffold (intentionally deferred):
//!   * Streaming/large payloads — the whole message is buffered in memory.
//!   * permessage-deflate or any other extension.
//!   * Ping *intervals* / timer-driven keepalive; we react to peer pings but
//!     do not proactively send our own on a schedule.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use purecrypto::hash::{Digest, Sha1};

use crate::error::{Error, Result};
use crate::tls::TlsStream;
use crate::url::Url;

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

const OPCODE_CONT: u8 = 0x0;
const OPCODE_TEXT: u8 = 0x1;
const OPCODE_BINARY: u8 = 0x2;
const OPCODE_CLOSE: u8 = 0x8;
const OPCODE_PING: u8 = 0x9;
const OPCODE_PONG: u8 = 0xA;

const MAX_PAYLOAD_BYTES: u64 = 64 * 1024 * 1024;

/// Open a WS connection, read one full text or binary message (reassembling
/// fragments and answering any interleaved ping/close control frames), send a
/// close, and return that message's payload.
pub fn fetch(url: &Url) -> Result<Vec<u8>> {
    match url.scheme.as_str() {
        "ws" => {
            let mut sock = tcp_connect(url)?;
            handshake(&mut sock, url)?;
            read_data_and_close(&mut sock)
        }
        "wss" => {
            let tcp = tcp_connect(url)?;
            let mut tls = crate::tls::connect_over(tcp, &url.host)?;
            handshake(&mut tls, url)?;
            read_data_and_close(&mut tls)
        }
        other => Err(Error::UnsupportedScheme(other.to_string())),
    }
}

fn tcp_connect(url: &Url) -> Result<TcpStream> {
    let addr = format!("{}:{}", url.host, url.port);
    let addrs: Vec<_> = std::net::ToSocketAddrs::to_socket_addrs(&addr)?.collect();
    let first = addrs
        .into_iter()
        .next()
        .ok_or_else(|| Error::InvalidUrl(url.host.clone()))?;
    let stream = TcpStream::connect_timeout(&first, Duration::from_secs(30))?;
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    stream.set_write_timeout(Some(Duration::from_secs(60)))?;
    Ok(stream)
}

/// Drive the HTTP/1.1 upgrade handshake on `stream`. After this returns, the
/// stream sits at the first byte of the first WS frame.
fn handshake<S: Read + Write>(stream: &mut S, url: &Url) -> Result<()> {
    let key_bytes: [u8; 16] = random_16()?;
    let key_b64 = base64_encode(&key_bytes);

    let host_header =
        if (url.scheme == "ws" && url.port == 80) || (url.scheme == "wss" && url.port == 443) {
            url.host.clone()
        } else {
            format!("{}:{}", url.host, url.port)
        };

    let path = if url.path.is_empty() {
        "/"
    } else {
        url.path.as_str()
    };

    let req = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {key_b64}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n"
    );
    stream.write_all(req.as_bytes())?;
    stream.flush()?;

    // Read the response headers byte-by-byte so we don't over-read into the
    // post-handshake WS frame stream. RFC 6455 requires the response end at
    // \r\n\r\n with no extra data, so this is fine.
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    loop {
        let mut b = [0u8; 1];
        let n = stream.read(&mut b)?;
        if n == 0 {
            return Err(Error::UnexpectedEof);
        }
        buf.push(b[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            break;
        }
        if buf.len() > 64 * 1024 {
            return Err(Error::BadResponse("handshake response too large".into()));
        }
    }

    let head = std::str::from_utf8(&buf)
        .map_err(|_| Error::BadResponse("non-utf8 handshake response".into()))?;
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| Error::BadResponse("empty handshake response".into()))?;
    if !(status_line.starts_with("HTTP/1.1 101") || status_line.starts_with("HTTP/1.0 101")) {
        return Err(Error::BadResponse(format!(
            "expected 101 Switching Protocols, got: {status_line:?}"
        )));
    }

    let mut upgrade_ok = false;
    let mut connection_ok = false;
    let mut accept_value: Option<String> = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (k, v) = match line.split_once(':') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => continue,
        };
        if k.eq_ignore_ascii_case("upgrade") {
            if v.eq_ignore_ascii_case("websocket") {
                upgrade_ok = true;
            }
        } else if k.eq_ignore_ascii_case("connection") {
            // Connection can be a comma-separated list of tokens.
            if v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
            {
                connection_ok = true;
            }
        } else if k.eq_ignore_ascii_case("sec-websocket-accept") {
            accept_value = Some(v.to_string());
        }
    }
    if !upgrade_ok {
        return Err(Error::BadResponse(
            "missing or wrong Upgrade header in handshake response".into(),
        ));
    }
    if !connection_ok {
        return Err(Error::BadResponse(
            "missing or wrong Connection header in handshake response".into(),
        ));
    }
    let accept = accept_value
        .ok_or_else(|| Error::BadResponse("missing Sec-WebSocket-Accept header".into()))?;
    let expected = derive_accept(&key_b64);
    if accept != expected {
        return Err(Error::BadResponse(format!(
            "Sec-WebSocket-Accept mismatch: got {accept:?}, expected {expected:?}"
        )));
    }

    Ok(())
}

/// What [`read_message`] produced for the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Message {
    /// A reassembled text or binary message.
    Data { opcode: u8, payload: Vec<u8> },
    /// The peer initiated a close; we have already answered it.
    Closed,
}

/// Max payload of a control frame (RFC 6455 §5.5).
const MAX_CONTROL_PAYLOAD: usize = 125;

/// Run the receive frame loop until one full data message is reassembled or
/// the peer closes. Control frames (ping/pong/close) are handled inline:
///
///   * PING → reply with a PONG echoing the application data.
///   * PONG → ignored (unsolicited keepalive response).
///   * CLOSE → reply with a CLOSE and return [`Message::Closed`].
///
/// Control frames are honored both before the first data frame and in between
/// fragments. Data fragments (initial frame with FIN=0 followed by
/// CONTINUATION frames until FIN=1) are stitched together, with the
/// cumulative size enforced against [`MAX_PAYLOAD_BYTES`] so a fragmented
/// payload cannot exceed the cap that a single frame would be held to.
fn read_message<S: Read + Write>(stream: &mut S) -> Result<Message> {
    // State for an in-progress fragmented data message. `None` means we are
    // not currently inside a fragmentation chain.
    let mut frag_opcode: Option<u8> = None;
    let mut buf: Vec<u8> = Vec::new();

    loop {
        let frame = read_frame(stream)?;

        // Control frames (opcode >= 0x8) may be interleaved between fragments
        // but MUST NOT themselves be fragmented and MUST have payload <= 125.
        if frame.opcode >= 0x8 {
            if !frame.fin {
                return Err(Error::BadResponse(
                    "fragmented control frame (FIN=0 on a control opcode)".into(),
                ));
            }
            if frame.payload.len() > MAX_CONTROL_PAYLOAD {
                return Err(Error::BadResponse(format!(
                    "control frame payload too large: {} bytes (max {MAX_CONTROL_PAYLOAD})",
                    frame.payload.len()
                )));
            }
            match frame.opcode {
                OPCODE_PING => {
                    let pong = build_client_frame(OPCODE_PONG, &frame.payload)?;
                    stream.write_all(&pong)?;
                    stream.flush()?;
                    continue;
                }
                OPCODE_PONG => continue,
                OPCODE_CLOSE => {
                    // Echo the close (masked, per §5.3). Best-effort: if we
                    // can't build it we still report a clean close.
                    if let Ok(close) = build_client_frame(OPCODE_CLOSE, &[]) {
                        let _ = stream.write_all(&close);
                        let _ = stream.flush();
                    }
                    return Ok(Message::Closed);
                }
                other => {
                    return Err(Error::BadResponse(format!(
                        "unknown WS control opcode 0x{other:x}"
                    )));
                }
            }
        }

        // Data / continuation frames.
        match frame.opcode {
            OPCODE_TEXT | OPCODE_BINARY => {
                if frag_opcode.is_some() {
                    return Err(Error::BadResponse(
                        "new data frame began while a fragmented message was in progress".into(),
                    ));
                }
                accumulate(&mut buf, &frame.payload)?;
                if frame.fin {
                    return Ok(Message::Data {
                        opcode: frame.opcode,
                        payload: buf,
                    });
                }
                frag_opcode = Some(frame.opcode);
            }
            OPCODE_CONT => {
                let opcode = frag_opcode.ok_or_else(|| {
                    Error::BadResponse("continuation frame with no message in progress".into())
                })?;
                accumulate(&mut buf, &frame.payload)?;
                if frame.fin {
                    return Ok(Message::Data {
                        opcode,
                        payload: buf,
                    });
                }
            }
            other => {
                return Err(Error::BadResponse(format!("unknown WS opcode 0x{other:x}")));
            }
        }
    }
}

/// Append `chunk` to the reassembly buffer, enforcing the cumulative cap.
/// `read_frame` already bounds a single frame; this guards against many
/// small fragments adding up past [`MAX_PAYLOAD_BYTES`].
fn accumulate(buf: &mut Vec<u8>, chunk: &[u8]) -> Result<()> {
    let total = buf.len() as u64 + chunk.len() as u64;
    if total > MAX_PAYLOAD_BYTES {
        return Err(Error::BadResponse(format!(
            "reassembled WS message too large: {total} bytes (max {MAX_PAYLOAD_BYTES})"
        )));
    }
    buf.extend_from_slice(chunk);
    Ok(())
}

/// Send a masked client data frame. `opcode` must be [`OPCODE_TEXT`] or
/// [`OPCODE_BINARY`]; the payload is masked per RFC 6455 §5.3 using the
/// crate's CSPRNG. Exposed for a transfer/CLI layer to drive the send side
/// (not yet wired into the one-shot `fetch` path, hence `dead_code`).
#[allow(dead_code)]
fn send_message<S: Write>(stream: &mut S, opcode: u8, payload: &[u8]) -> Result<()> {
    if opcode != OPCODE_TEXT && opcode != OPCODE_BINARY {
        return Err(Error::BadResponse(format!(
            "send_message expects a data opcode (text/binary), got 0x{opcode:x}"
        )));
    }
    let frame = build_client_frame(opcode, payload)?;
    stream.write_all(&frame)?;
    stream.flush()?;
    Ok(())
}

/// Read frames until a full data message is reassembled, then send a close
/// frame and return that message's payload. Interleaved pings are answered
/// with pongs; a close from the server short-circuits to returning whatever
/// (likely empty) payload we have collected.
fn read_data_and_close<S: Read + Write>(stream: &mut S) -> Result<Vec<u8>> {
    let payload = match read_message(stream)? {
        Message::Data { payload, .. } => payload,
        // Peer closed before sending data; read_message already replied.
        Message::Closed => return Ok(Vec::new()),
    };

    // Polite close. Client→server frames must be masked (RFC 6455 §5.3),
    // including close frames; with a zero-length payload there's nothing to
    // mask, but we send the properly masked variant anyway to stay
    // spec-clean. A failure to obtain entropy for the close frame is
    // non-fatal: we've already captured the payload, so just skip the polite
    // close in that (extremely unlikely) case rather than discarding a good
    // result.
    if let Ok(close) = build_client_frame(OPCODE_CLOSE, &[]) {
        let _ = stream.write_all(&close);
        let _ = stream.flush();
    }
    Ok(payload)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Frame {
    fin: bool,
    opcode: u8,
    payload: Vec<u8>,
}

/// Parse a single frame off the wire. Server-to-client frames must NOT be
/// masked per RFC 6455 §5.1; a masked frame is rejected as a protocol error.
fn read_frame<S: Read>(stream: &mut S) -> Result<Frame> {
    let mut header = [0u8; 2];
    read_exact(stream, &mut header)?;
    let fin = (header[0] & 0x80) != 0;
    // RSV1/2/3 must be zero unless an extension has been negotiated.
    if (header[0] & 0x70) != 0 {
        return Err(Error::BadResponse(
            "non-zero RSV bits on incoming WS frame".into(),
        ));
    }
    let opcode = header[0] & 0x0F;
    let masked = (header[1] & 0x80) != 0;
    if masked {
        return Err(Error::BadResponse(
            "server-to-client frame is masked".into(),
        ));
    }
    let len7 = header[1] & 0x7F;
    let payload_len: u64 = match len7 {
        0..=125 => len7 as u64,
        126 => {
            let mut ext = [0u8; 2];
            read_exact(stream, &mut ext)?;
            u16::from_be_bytes(ext) as u64
        }
        127 => {
            let mut ext = [0u8; 8];
            read_exact(stream, &mut ext)?;
            u64::from_be_bytes(ext)
        }
        _ => unreachable!(),
    };
    if payload_len > MAX_PAYLOAD_BYTES {
        return Err(Error::BadResponse(format!(
            "WS payload too large: {payload_len} bytes"
        )));
    }
    let mut payload = vec![0u8; payload_len as usize];
    if payload_len > 0 {
        read_exact(stream, &mut payload)?;
    }
    Ok(Frame {
        fin,
        opcode,
        payload,
    })
}

/// Build an unfragmented client-to-server frame with the given opcode and
/// payload. Client frames must be masked (RFC 6455 §5.3), and the mask must
/// be unpredictable, so this fails if no secure entropy source is available.
fn build_client_frame(opcode: u8, payload: &[u8]) -> Result<Vec<u8>> {
    let mask: [u8; 4] = {
        let r = random_16()?;
        [r[0], r[1], r[2], r[3]]
    };
    let mut out = Vec::with_capacity(2 + 8 + 4 + payload.len());
    out.push(0x80 | (opcode & 0x0F)); // FIN=1 + opcode
    let n = payload.len();
    if n < 126 {
        out.push(0x80 | (n as u8));
    } else if n <= u16::MAX as usize {
        out.push(0x80 | 126);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        out.push(0x80 | 127);
        out.extend_from_slice(&(n as u64).to_be_bytes());
    }
    out.extend_from_slice(&mask);
    let start = out.len();
    out.extend_from_slice(payload);
    for (i, b) in out[start..].iter_mut().enumerate() {
        *b ^= mask[i & 3];
    }
    Ok(out)
}

fn read_exact<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<()> {
    let mut got = 0;
    while got < buf.len() {
        let n = r.read(&mut buf[got..])?;
        if n == 0 {
            return Err(Error::UnexpectedEof);
        }
        got += n;
    }
    Ok(())
}

/// `base64(sha1(key + WS_GUID))`. Used by both sides of the handshake to
/// prove the response was generated specifically for this request.
fn derive_accept(key_b64: &str) -> String {
    let mut h = Sha1::new();
    h.update(key_b64.as_bytes());
    h.update(WS_GUID.as_bytes());
    let digest = h.finalize();
    base64_encode(digest.as_ref())
}

/// 16 cryptographically-random bytes for the `Sec-WebSocket-Key` and frame
/// masks, sourced from the crate's vetted CSPRNG ([`purecrypto::rng::OsRng`],
/// the same source used by `mqtt.rs`).
///
/// `OsRng::fill_bytes` panics if it cannot read OS entropy (e.g. a missing
/// `/dev/urandom` in a locked-down sandbox). We catch that and surface it as
/// a connection error rather than either crashing the process or — worse —
/// falling back to predictable time/PID entropy: a guessable mask weakens the
/// masking the spec relies on, so failing closed is the secure choice.
fn random_16() -> Result<[u8; 16]> {
    use purecrypto::rng::{OsRng, RngCore};
    let mut out = [0u8; 16];
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        OsRng.fill_bytes(&mut out);
    }))
    .map_err(|_| Error::BadResponse("websocket: no secure entropy source available".into()))?;
    Ok(out)
}

/// Standard base64 (RFC 4648 §4) with `=` padding. Hand-rolled so we don't
/// pull in another dependency for ~30 lines of work. (Also reused by HTTP
/// Basic auth in `crate::http`.)
pub(crate) fn base64_encode(input: &[u8]) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= input.len() {
        let b0 = input[i];
        let b1 = input[i + 1];
        let b2 = input[i + 2];
        out.push(ALPHA[(b0 >> 2) as usize] as char);
        out.push(ALPHA[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(ALPHA[(((b1 & 0x0F) << 2) | (b2 >> 6)) as usize] as char);
        out.push(ALPHA[(b2 & 0x3F) as usize] as char);
        i += 3;
    }
    let rem = input.len() - i;
    if rem == 1 {
        let b0 = input[i];
        out.push(ALPHA[(b0 >> 2) as usize] as char);
        out.push(ALPHA[((b0 & 0x03) << 4) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let b0 = input[i];
        let b1 = input[i + 1];
        out.push(ALPHA[(b0 >> 2) as usize] as char);
        out.push(ALPHA[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(ALPHA[((b1 & 0x0F) << 2) as usize] as char);
        out.push('=');
    }
    out
}

// Silence unused-import warning in builds that take only the `ws://` path
// — `TlsStream` is referenced in docs but not directly in this module
// (we call `crate::tls::connect_over` instead).
#[allow(dead_code)]
fn _tlsstream_in_scope_for_docs<S: Read + Write>(_: TlsStream<S>) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// In-memory duplex stream: `inbound` is what the "server" sends to us
    /// (drained by `read`), `sent` captures what we write back. Lets us drive
    /// the full read/control-frame loop without a socket.
    struct MockStream {
        inbound: Cursor<Vec<u8>>,
        sent: Vec<u8>,
    }

    impl MockStream {
        fn new(inbound: Vec<u8>) -> Self {
            MockStream {
                inbound: Cursor::new(inbound),
                sent: Vec::new(),
            }
        }
    }

    impl Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.inbound.read(buf)
        }
    }

    impl Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.sent.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Build an unmasked server-to-client frame (server frames must not be
    /// masked) for feeding into the mock stream.
    fn server_frame(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let b0 = if fin { 0x80 } else { 0x00 } | (opcode & 0x0F);
        out.push(b0);
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

    /// Decode every frame the client wrote into `sent`, returning
    /// `(opcode, unmasked_payload)` pairs. Asserts each is masked, as client
    /// frames must be (RFC 6455 §5.3).
    fn decode_sent(sent: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut frames = Vec::new();
        let mut i = 0;
        while i < sent.len() {
            let opcode = sent[i] & 0x0F;
            let masked = (sent[i + 1] & 0x80) != 0;
            assert!(masked, "client frame must be masked");
            let len7 = sent[i + 1] & 0x7F;
            i += 2;
            let len = match len7 {
                0..=125 => len7 as usize,
                126 => {
                    let l = u16::from_be_bytes([sent[i], sent[i + 1]]) as usize;
                    i += 2;
                    l
                }
                127 => {
                    let mut b = [0u8; 8];
                    b.copy_from_slice(&sent[i..i + 8]);
                    i += 8;
                    u64::from_be_bytes(b) as usize
                }
                _ => unreachable!(),
            };
            let mask = [sent[i], sent[i + 1], sent[i + 2], sent[i + 3]];
            i += 4;
            let mut payload = sent[i..i + len].to_vec();
            i += len;
            for (j, b) in payload.iter_mut().enumerate() {
                *b ^= mask[j & 3];
            }
            frames.push((opcode, payload));
        }
        frames
    }

    #[test]
    fn base64_encode_hello() {
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
    }

    #[test]
    fn base64_encode_rfc4648_vectors() {
        // Classic RFC 4648 §10 vectors.
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn rfc6455_accept_derivation() {
        // The example from RFC 6455 §1.3.
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let expected = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
        assert_eq!(derive_accept(key), expected);
    }

    #[test]
    fn parse_short_text_frame() {
        // 0x81 = FIN + opcode 1 (text), 0x05 = unmasked length 5, "hello"
        let bytes = [0x81, 0x05, b'h', b'e', b'l', b'l', b'o'];
        let mut cur = Cursor::new(&bytes[..]);
        let f = read_frame(&mut cur).expect("frame parses");
        assert!(f.fin);
        assert_eq!(f.opcode, OPCODE_TEXT);
        assert_eq!(f.payload, b"hello");
    }

    #[test]
    fn parse_16bit_length_frame() {
        // 200-byte binary payload of 0x41 ('A'), length encoded as 126 + u16.
        let mut bytes: Vec<u8> = vec![0x82, 126, 0x00, 200];
        bytes.extend(std::iter::repeat(b'A').take(200));
        let mut cur = Cursor::new(bytes);
        let f = read_frame(&mut cur).expect("frame parses");
        assert_eq!(f.opcode, OPCODE_BINARY);
        assert_eq!(f.payload.len(), 200);
        assert!(f.payload.iter().all(|&b| b == b'A'));
    }

    #[test]
    fn reject_masked_server_frame() {
        // MASK bit set, length 0 — server is not allowed to mask.
        let bytes = [0x81, 0x80, 0, 0, 0, 0];
        let mut cur = Cursor::new(&bytes[..]);
        let err = read_frame(&mut cur).expect_err("masked server frame must be rejected");
        match err {
            Error::BadResponse(_) => {}
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn build_close_frame_short_payload() {
        // Empty close frame: header byte 0x88 (FIN + opcode 8), len byte has
        // MASK bit set + payload-len 0, plus a 4-byte mask. Total: 6 bytes.
        let frame = build_client_frame(OPCODE_CLOSE, &[]).unwrap();
        assert_eq!(frame.len(), 6);
        assert_eq!(frame[0], 0x88);
        assert_eq!(frame[1], 0x80); // mask flag set, length 0
    }

    #[test]
    fn build_text_frame_masks_payload() {
        let payload = b"hi";
        let frame = build_client_frame(OPCODE_TEXT, payload).unwrap();
        // Header (2) + mask (4) + payload (2) = 8.
        assert_eq!(frame.len(), 8);
        assert_eq!(frame[0], 0x81);
        assert_eq!(frame[1], 0x82);
        let mask = [frame[2], frame[3], frame[4], frame[5]];
        let unmasked: Vec<u8> = frame[6..]
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ mask[i & 3])
            .collect();
        assert_eq!(unmasked, payload);
    }

    #[test]
    fn build_frame_uses_16bit_length_for_medium_payload() {
        let payload = vec![0u8; 200];
        let frame = build_client_frame(OPCODE_BINARY, &payload).unwrap();
        assert_eq!(frame[0], 0x82);
        assert_eq!(frame[1], 0x80 | 126);
        let len = u16::from_be_bytes([frame[2], frame[3]]);
        assert_eq!(len, 200);
        // 2 (header) + 2 (ext len) + 4 (mask) + 200 (payload).
        assert_eq!(frame.len(), 208);
    }

    #[test]
    fn build_frame_uses_64bit_length_for_large_payload() {
        let payload = vec![0u8; 70_000];
        let frame = build_client_frame(OPCODE_BINARY, &payload).unwrap();
        assert_eq!(frame[1], 0x80 | 127);
        let len = u64::from_be_bytes([
            frame[2], frame[3], frame[4], frame[5], frame[6], frame[7], frame[8], frame[9],
        ]);
        assert_eq!(len, 70_000);
    }

    #[test]
    fn random_16_is_nonzero() {
        // Astronomically unlikely the CSPRNG returns all zeros.
        let r = random_16().expect("OS entropy available in the test environment");
        assert_ne!(r, [0u8; 16]);
    }

    #[test]
    fn random_16_is_not_constant() {
        // Two draws should differ — a sanity check that we're pulling fresh
        // entropy, not a fixed seed.
        let a = random_16().unwrap();
        let b = random_16().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn reassembles_fragmented_text_message() {
        // "Hel" (text, FIN=0) + "lo " (cont, FIN=0) + "world" (cont, FIN=1).
        let mut inbound = server_frame(false, OPCODE_TEXT, b"Hel");
        inbound.extend(server_frame(false, OPCODE_CONT, b"lo "));
        inbound.extend(server_frame(true, OPCODE_CONT, b"world"));
        let mut s = MockStream::new(inbound);
        let msg = read_message(&mut s).expect("reassembles");
        assert_eq!(
            msg,
            Message::Data {
                opcode: OPCODE_TEXT,
                payload: b"Hello world".to_vec(),
            }
        );
    }

    #[test]
    fn ping_between_fragments_gets_pong_and_message_completes() {
        // "foo" (text, FIN=0), a PING with "pingdata", then "bar" (cont,
        // FIN=1). The message must still reassemble and a PONG echoing the
        // ping data must have been sent.
        let mut inbound = server_frame(false, OPCODE_TEXT, b"foo");
        inbound.extend(server_frame(true, OPCODE_PING, b"pingdata"));
        inbound.extend(server_frame(true, OPCODE_CONT, b"bar"));
        let mut s = MockStream::new(inbound);
        let msg = read_message(&mut s).expect("completes despite ping");
        assert_eq!(
            msg,
            Message::Data {
                opcode: OPCODE_TEXT,
                payload: b"foobar".to_vec(),
            }
        );
        let sent = decode_sent(&s.sent);
        assert_eq!(sent.len(), 1, "exactly one pong expected");
        assert_eq!(sent[0].0, OPCODE_PONG);
        assert_eq!(sent[0].1, b"pingdata");
    }

    #[test]
    fn close_is_answered_and_returns_closed() {
        let inbound = server_frame(true, OPCODE_CLOSE, &[]);
        let mut s = MockStream::new(inbound);
        let msg = read_message(&mut s).expect("handles close");
        assert_eq!(msg, Message::Closed);
        let sent = decode_sent(&s.sent);
        assert_eq!(sent.len(), 1, "exactly one close reply expected");
        assert_eq!(sent[0].0, OPCODE_CLOSE);
    }

    #[test]
    fn unsolicited_pong_is_ignored_then_data_returns() {
        let mut inbound = server_frame(true, OPCODE_PONG, b"x");
        inbound.extend(server_frame(true, OPCODE_TEXT, b"hi"));
        let mut s = MockStream::new(inbound);
        let msg = read_message(&mut s).expect("ignores pong");
        assert_eq!(
            msg,
            Message::Data {
                opcode: OPCODE_TEXT,
                payload: b"hi".to_vec(),
            }
        );
        // Nothing should have been written for the pong.
        assert!(s.sent.is_empty(), "unsolicited pong must not be answered");
    }

    #[test]
    fn send_message_produces_masked_frame() {
        let mut s = MockStream::new(Vec::new());
        send_message(&mut s, OPCODE_TEXT, b"hello").expect("sends");
        // Raw bytes: FIN+text, MASK+len, 4-byte mask, 5 masked bytes.
        assert_eq!(s.sent[0], 0x81);
        assert_eq!(s.sent[1], 0x80 | 5);
        assert_eq!(s.sent.len(), 2 + 4 + 5);
        let decoded = decode_sent(&s.sent);
        assert_eq!(decoded, vec![(OPCODE_TEXT, b"hello".to_vec())]);
    }

    #[test]
    fn send_message_rejects_control_opcode() {
        let mut s = MockStream::new(Vec::new());
        let err = send_message(&mut s, OPCODE_PING, b"x")
            .expect_err("control opcode must be rejected for send_message");
        match err {
            Error::BadResponse(_) => {}
            other => panic!("wrong error: {other:?}"),
        }
        assert!(s.sent.is_empty());
    }

    #[test]
    fn oversized_cumulative_fragmented_payload_is_rejected() {
        // Two frames whose individual sizes are fine, but whose sum exceeds
        // MAX_PAYLOAD_BYTES — the cumulative cap must catch it. We forge the
        // header to claim a huge length without actually allocating the bytes
        // would still trip read_frame's per-frame cap, so instead we lower the
        // bar by checking `accumulate` directly against the cap boundary.
        let mut buf = vec![0u8; (MAX_PAYLOAD_BYTES - 1) as usize];
        // One more byte is exactly at the cap: allowed.
        accumulate(&mut buf, &[0u8]).expect("exactly at the cap is allowed");
        // The next byte pushes over the cap: rejected.
        let err = accumulate(&mut buf, &[0u8]).expect_err("over the cap must be rejected");
        match err {
            Error::BadResponse(_) => {}
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn fragmented_control_frame_is_rejected() {
        // A PING with FIN=0 is illegal: control frames must not be fragmented.
        let inbound = server_frame(false, OPCODE_PING, b"x");
        let mut s = MockStream::new(inbound);
        let err = read_message(&mut s).expect_err("fragmented control must be rejected");
        match err {
            Error::BadResponse(_) => {}
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn oversized_control_frame_is_rejected() {
        // A PING with a 126-byte payload exceeds the 125-byte control cap.
        let inbound = server_frame(true, OPCODE_PING, &[0u8; 126]);
        let mut s = MockStream::new(inbound);
        let err = read_message(&mut s).expect_err("oversized control must be rejected");
        match err {
            Error::BadResponse(_) => {}
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn new_data_frame_during_fragmentation_is_rejected() {
        // text(FIN=0) then a second text(FIN=1) without a continuation: the
        // peer must use opcode 0x0 to continue, so this is a protocol error.
        let mut inbound = server_frame(false, OPCODE_TEXT, b"a");
        inbound.extend(server_frame(true, OPCODE_TEXT, b"b"));
        let mut s = MockStream::new(inbound);
        let err = read_message(&mut s).expect_err("interleaved new data frame must be rejected");
        match err {
            Error::BadResponse(_) => {}
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn lone_continuation_frame_is_rejected() {
        // A continuation frame with no message in progress is illegal.
        let inbound = server_frame(true, OPCODE_CONT, b"x");
        let mut s = MockStream::new(inbound);
        let err = read_message(&mut s).expect_err("lone continuation must be rejected");
        match err {
            Error::BadResponse(_) => {}
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn read_data_and_close_returns_reassembled_payload_and_sends_close() {
        let mut inbound = server_frame(false, OPCODE_BINARY, &[1, 2, 3]);
        inbound.extend(server_frame(true, OPCODE_CONT, &[4, 5]));
        let mut s = MockStream::new(inbound);
        let payload = read_data_and_close(&mut s).expect("reads message");
        assert_eq!(payload, vec![1, 2, 3, 4, 5]);
        // A polite close should have been written.
        let sent = decode_sent(&s.sent);
        assert_eq!(sent.last().map(|f| f.0), Some(OPCODE_CLOSE));
    }
}

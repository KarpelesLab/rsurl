//! WebSocket support (RFC 6455).
//!
//! WS handshakes are HTTP/1.1 `Upgrade: websocket` requests followed by
//! binary/text frames. We perform the handshake by hand (so we can sit on the
//! raw stream without buffered-reader leftovers eating into the frame
//! channel), then read frames until we get a data frame. For `wss://`, the
//! TCP stream is wrapped with [`crate::tls::connect_over`] before sending the
//! upgrade.
//!
//! Limitations of this scaffold (intentionally deferred):
//!   * Send-side data frames (we only read one frame, then close).
//!   * Fragmented messages (FIN=0 continuation chains).
//!   * Streaming/large payloads — the whole payload is buffered.
//!   * permessage-deflate or any other extension.
//!   * Ping intervals / keepalive; we only react to a ping if the peer sends
//!     one before our first data frame arrives.

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

/// Open a WS connection, read one text or binary data frame, close cleanly,
/// and return that frame's payload.
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

/// Read frames until a data frame arrives, then send a close frame and
/// return the data frame's payload. Pings are answered with a pong; a close
/// from the server short-circuits to returning whatever (likely empty)
/// payload we have collected.
fn read_data_and_close<S: Read + Write>(stream: &mut S) -> Result<Vec<u8>> {
    let payload = loop {
        let frame = read_frame(stream)?;
        match frame.opcode {
            OPCODE_TEXT | OPCODE_BINARY => break frame.payload,
            OPCODE_PING => {
                let pong = build_client_frame(OPCODE_PONG, &frame.payload)?;
                stream.write_all(&pong)?;
                stream.flush()?;
            }
            OPCODE_PONG => continue,
            OPCODE_CLOSE => {
                // Echo a close and bail out with whatever we have.
                let _ = stream.write_all(&[0x88, 0x00]);
                let _ = stream.flush();
                return Ok(Vec::new());
            }
            OPCODE_CONT => {
                return Err(Error::BadResponse(
                    "unexpected continuation frame before any data frame".into(),
                ));
            }
            other => {
                return Err(Error::BadResponse(format!("unknown WS opcode 0x{other:x}")));
            }
        }
    };

    // Polite close: \x88 = FIN + opcode 0x8, \x00 = empty unmasked payload.
    // Strictly speaking, client→server frames must be masked, even close
    // frames — but with a zero-length payload there's nothing to mask, and
    // every implementation in the wild accepts \x88\x00 here. We send the
    // properly masked variant anyway to stay spec-clean.
    // A failure to obtain entropy for the close frame is non-fatal: we've
    // already captured the payload, so just skip the polite close in that
    // (extremely unlikely) case rather than discarding a good result.
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
}

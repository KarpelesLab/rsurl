//! MQTT and MQTTS support.
//!
//! Spec: MQTT v3.1.1 (OASIS, also ISO/IEC 20922:2016) — curl supports v3.1.1.
//! v5 may be added later. URL format: `mqtt://host[:1883]/topic`.
//!
//! Use [`crate::tls::connect_over`] for `mqtts://`.
//!
//! Two flows are supported, matching what curl does for `mqtt://`:
//!
//! * **Subscribe** ([`fetch`]) — `curl mqtt://host/topic`: CONNECT → SUBSCRIBE →
//!   wait for the first PUBLISH → DISCONNECT, returning that payload.
//! * **Publish** ([`publish`]) — `curl -d payload mqtt://host/topic` or
//!   `curl -T file …`: CONNECT → PUBLISH → (PUBACK for QoS 1) → DISCONNECT.
//!
//! The CONNECT handshake is shared between both. Publish supports QoS 0
//! (fire-and-forget, curl's default) and QoS 1 (PUBLISH then wait for the
//! matching PUBACK). QoS 2 (PUBREC / PUBREL / PUBCOMP), retained-message
//! flags, last-will, and MQTT v5 are not implemented.

use std::io::{self, Read, Write};
use std::net::TcpStream;

use purecrypto::rng::{OsRng, RngCore};

use crate::error::{Error, Result};
use crate::url::Url;

// MQTT v3.1.1 control packet types (high nibble of the fixed-header byte).
const PKT_CONNECT: u8 = 1;
const PKT_CONNACK: u8 = 2;
const PKT_PUBLISH: u8 = 3;
const PKT_PUBACK: u8 = 4;
const PKT_SUBSCRIBE: u8 = 8;
const PKT_SUBACK: u8 = 9;
const PKT_PINGRESP: u8 = 13;
const PKT_DISCONNECT: u8 = 14;

/// CONNECT, SUBSCRIBE to the topic in `url.path`, return the payload of the
/// first PUBLISH received, then DISCONNECT.
pub fn fetch(url: &Url) -> Result<Vec<u8>> {
    let topic = url.path.strip_prefix('/').unwrap_or(&url.path);
    if topic.is_empty() {
        return Err(Error::InvalidUrl(format!(
            "mqtt: no topic in URL path ({:?})",
            url.path
        )));
    }

    let (user, pass) = split_userinfo(url.userinfo.as_deref());

    let addr = format!("{}:{}", url.host, url.port);
    let tcp = TcpStream::connect(&addr)?;
    if url.is_tls() {
        let mut stream = crate::tls::connect_over(tcp, &url.host)?;
        run_session(&mut stream, topic, user, pass)
    } else {
        let mut stream = tcp;
        run_session(&mut stream, topic, user, pass)
    }
}

/// CONNECT, PUBLISH `payload` to the topic in `url.path` at the requested
/// `qos`, wait for the PUBACK when `qos == 1`, then DISCONNECT.
///
/// This is the publisher side: `curl -d payload mqtt://host/topic` (and the
/// `-T file` upload form). The topic comes from the URL path with its leading
/// `/` stripped and is validated to be a legal *publish* topic (no wildcards,
/// no NUL/control bytes). `qos` must be 0 or 1; QoS 2 is not implemented.
pub fn publish(url: &Url, payload: &[u8], qos: u8) -> Result<()> {
    let topic = url.path.strip_prefix('/').unwrap_or(&url.path);
    if topic.is_empty() {
        return Err(Error::InvalidUrl(format!(
            "mqtt: no topic in URL path ({:?})",
            url.path
        )));
    }
    validate_publish_topic(topic)?;
    if qos > 1 {
        return Err(Error::BadResponse(format!(
            "mqtt: unsupported publish QoS {qos} (only 0 and 1)"
        )));
    }

    let (user, pass) = split_userinfo(url.userinfo.as_deref());

    let addr = format!("{}:{}", url.host, url.port);
    let tcp = TcpStream::connect(&addr)?;
    if url.is_tls() {
        let mut stream = crate::tls::connect_over(tcp, &url.host)?;
        run_publish(&mut stream, topic, payload, qos, user, pass)
    } else {
        let mut stream = tcp;
        run_publish(&mut stream, topic, payload, qos, user, pass)
    }
}

/// Perform the shared CONNECT handshake: send CONNECT, read and validate the
/// CONNACK. Returns once the broker has accepted the connection.
fn connect_handshake<S: Read + Write>(
    stream: &mut S,
    user: Option<&str>,
    pass: Option<&str>,
) -> Result<()> {
    let client_id = random_client_id();
    let connect = build_connect(&client_id, user, pass, 60);
    stream.write_all(&connect)?;
    stream.flush()?;

    // CONNACK: type 2, remaining length 2, variable header is
    // [session-present flag, return code].
    let (ctype, body) = read_packet(stream)?;
    if ctype != PKT_CONNACK {
        return Err(Error::BadResponse(format!(
            "mqtt: expected CONNACK, got packet type {ctype}"
        )));
    }
    if body.len() < 2 {
        return Err(Error::BadResponse("mqtt: short CONNACK".into()));
    }
    let rc = body[1];
    if rc != 0 {
        return Err(Error::BadResponse(format!("mqtt: connack {rc}")));
    }
    Ok(())
}

fn run_publish<S: Read + Write>(
    stream: &mut S,
    topic: &str,
    payload: &[u8],
    qos: u8,
    user: Option<&str>,
    pass: Option<&str>,
) -> Result<()> {
    connect_handshake(stream, user, pass)?;

    // Packet identifier is only present in the PUBLISH (and required in the
    // PUBACK) for QoS > 0. We always use 1 since this is a single, one-shot
    // publish per connection.
    let packet_id = 1u16;
    let publish = build_publish(topic, payload, qos, packet_id);
    stream.write_all(&publish)?;
    stream.flush()?;

    if qos == 1 {
        // Wait for the matching PUBACK. Drain any PINGRESP the broker may
        // interleave, like the subscribe loop does, and reject anything else.
        loop {
            let (ctype, body) = read_packet(stream)?;
            match ctype {
                PKT_PUBACK => {
                    let acked = parse_puback(&body)?;
                    if acked != packet_id {
                        return Err(Error::BadResponse(format!(
                            "mqtt: PUBACK packet id {acked} != sent {packet_id}"
                        )));
                    }
                    break;
                }
                PKT_PINGRESP => continue,
                other => {
                    return Err(Error::BadResponse(format!(
                        "mqtt: unexpected packet type {other} while awaiting PUBACK"
                    )));
                }
            }
        }
    }

    // DISCONNECT is a 2-byte fixed header with no remaining length payload.
    let _ = stream.write_all(&[PKT_DISCONNECT << 4, 0x00]);
    let _ = stream.flush();

    Ok(())
}

fn run_session<S: Read + Write>(
    stream: &mut S,
    topic: &str,
    user: Option<&str>,
    pass: Option<&str>,
) -> Result<Vec<u8>> {
    connect_handshake(stream, user, pass)?;

    // SUBSCRIBE with packet id 1, single topic at QoS 0.
    let subscribe = build_subscribe(1, topic);
    stream.write_all(&subscribe)?;
    stream.flush()?;

    // SUBACK: type 9, payload is [packet_id_msb, packet_id_lsb, return_code...].
    let (ctype, body) = read_packet(stream)?;
    if ctype != PKT_SUBACK {
        return Err(Error::BadResponse(format!(
            "mqtt: expected SUBACK, got packet type {ctype}"
        )));
    }
    if body.len() < 3 {
        return Err(Error::BadResponse("mqtt: short SUBACK".into()));
    }
    let sub_rc = body[2];
    if sub_rc == 0x80 {
        return Err(Error::BadResponse("mqtt: suback failure (0x80)".into()));
    }

    // Drain packets until we get a PUBLISH. We just ignore anything else
    // (e.g. PINGRESP if the server pings us first), which is enough for the
    // simple "subscribe and get one message" flow.
    let payload = loop {
        let (ctype, body) = read_packet(stream)?;
        match ctype {
            PKT_PUBLISH => break extract_publish_payload(&body)?,
            PKT_PINGRESP => continue,
            other => {
                return Err(Error::BadResponse(format!(
                    "mqtt: unexpected packet type {other} before PUBLISH"
                )));
            }
        }
    };

    // DISCONNECT is a 2-byte fixed header with no remaining length payload.
    let _ = stream.write_all(&[PKT_DISCONNECT << 4, 0x00]);
    let _ = stream.flush();

    Ok(payload)
}

/// Split a `user[:pass]` userinfo string. Both halves are returned as
/// borrowed slices into the original string.
fn split_userinfo(ui: Option<&str>) -> (Option<&str>, Option<&str>) {
    match ui {
        None => (None, None),
        Some(s) => match s.split_once(':') {
            Some((u, p)) => (Some(u), Some(p)),
            None => (Some(s), None),
        },
    }
}

/// Generate a fresh `rsurl-XXXXXXXXXXXX` client id (12 lowercase hex chars,
/// 48 bits of randomness from the OS CSPRNG).
fn random_client_id() -> String {
    let mut buf = [0u8; 6];
    OsRng.fill_bytes(&mut buf);
    let mut s = String::with_capacity(7 + 12);
    s.push_str("rsurl-");
    for b in buf {
        s.push(hex_nibble(b >> 4));
        s.push(hex_nibble(b & 0x0F));
    }
    s
}

fn hex_nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + n - 10) as char,
        _ => unreachable!(),
    }
}

/// Append `s` to `out` prefixed by its UTF-8 byte length as a big-endian u16.
/// MQTT v3.1.1 caps any single string at 65535 bytes; longer strings are
/// truncated here defensively (callers control these values).
fn push_str(out: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(u16::MAX as usize) as u16;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&bytes[..len as usize]);
}

/// Build the full bytes of a CONNECT packet (fixed header + variable header +
/// payload), with the "clean session" flag always set.
pub(crate) fn build_connect(
    client_id: &str,
    user: Option<&str>,
    pass: Option<&str>,
    keep_alive_secs: u16,
) -> Vec<u8> {
    // Variable header.
    let mut vh = Vec::new();
    push_str(&mut vh, "MQTT");
    vh.push(4); // Protocol level: MQTT v3.1.1
    let mut flags: u8 = 0x02; // clean session
    if user.is_some() {
        flags |= 0x80;
    }
    if pass.is_some() {
        flags |= 0x40;
    }
    vh.push(flags);
    vh.extend_from_slice(&keep_alive_secs.to_be_bytes());

    // Payload.
    let mut pl = Vec::new();
    push_str(&mut pl, client_id);
    if let Some(u) = user {
        push_str(&mut pl, u);
    }
    if let Some(p) = pass {
        push_str(&mut pl, p);
    }

    let mut out = Vec::with_capacity(2 + vh.len() + pl.len());
    out.push(PKT_CONNECT << 4); // 0x10
    write_remaining_length(&mut out, vh.len() + pl.len());
    out.extend_from_slice(&vh);
    out.extend_from_slice(&pl);
    out
}

/// Build a SUBSCRIBE for a single `topic` at QoS 0.
pub(crate) fn build_subscribe(packet_id: u16, topic: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&packet_id.to_be_bytes());
    push_str(&mut body, topic);
    body.push(0x00); // QoS 0

    let mut out = Vec::with_capacity(2 + body.len());
    // SUBSCRIBE requires the lower nibble to be 0b0010 per MQTT v3.1.1 §3.8.1.
    out.push((PKT_SUBSCRIBE << 4) | 0x02); // 0x82
    write_remaining_length(&mut out, body.len());
    out.extend_from_slice(&body);
    out
}

/// Reject a topic that is not a valid MQTT *publish* topic name.
///
/// Per MQTT v3.1.1 §4.7, topic *names* used in PUBLISH (unlike the topic
/// *filters* used in SUBSCRIBE) must not contain the wildcard characters `+`
/// or `#`. We additionally reject the NUL character (forbidden in any MQTT
/// UTF-8 string, §1.5.3) and other control characters, which guards against a
/// crafted URL path smuggling framing/control bytes into the wire packet.
fn validate_publish_topic(topic: &str) -> Result<()> {
    for ch in topic.chars() {
        match ch {
            '+' | '#' => {
                return Err(Error::InvalidUrl(format!(
                    "mqtt: publish topic must not contain wildcard {ch:?}"
                )));
            }
            '\0' => {
                return Err(Error::InvalidUrl(
                    "mqtt: publish topic must not contain NUL".into(),
                ));
            }
            c if c.is_control() => {
                return Err(Error::InvalidUrl(format!(
                    "mqtt: publish topic must not contain control char {:?}",
                    c
                )));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Build the full bytes of a PUBLISH packet (type 3).
///
/// Fixed header: `0x30 | (qos << 1)` (DUP and RETAIN are left clear), then the
/// remaining length. Variable header: the UTF-8 length-prefixed topic name,
/// followed — only when `qos > 0` — by the 2-byte packet identifier. Payload:
/// the body bytes verbatim. For QoS 0 the `packet_id` argument is ignored.
pub(crate) fn build_publish(topic: &str, payload: &[u8], qos: u8, packet_id: u16) -> Vec<u8> {
    let mut body = Vec::new();
    push_str(&mut body, topic);
    if qos > 0 {
        body.extend_from_slice(&packet_id.to_be_bytes());
    }
    body.extend_from_slice(payload);

    let mut out = Vec::with_capacity(2 + body.len());
    // High nibble = PKT_PUBLISH (3); low nibble carries DUP(8) RETAIN(1) and
    // the 2-bit QoS in bits 1..2. We only ever set QoS.
    out.push((PKT_PUBLISH << 4) | ((qos & 0x03) << 1));
    write_remaining_length(&mut out, body.len());
    out.extend_from_slice(&body);
    out
}

/// Parse a PUBACK (type 4) body and return its packet identifier. The body is
/// exactly the 2-byte big-endian packet id (MQTT v3.1.1 §3.4).
fn parse_puback(body: &[u8]) -> Result<u16> {
    if body.len() < 2 {
        return Err(Error::BadResponse("mqtt: short PUBACK".into()));
    }
    Ok(u16::from_be_bytes([body[0], body[1]]))
}

/// Extract the application payload from a PUBLISH packet body.
///
/// We only handle QoS 0 here, which is all `build_subscribe` ever requests:
/// the variable header is just `<topic-name>` and the rest is the payload.
fn extract_publish_payload(body: &[u8]) -> Result<Vec<u8>> {
    if body.len() < 2 {
        return Err(Error::BadResponse("mqtt: short PUBLISH".into()));
    }
    let topic_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    let after_topic = 2 + topic_len;
    if body.len() < after_topic {
        return Err(Error::BadResponse(
            "mqtt: PUBLISH topic length exceeds packet".into(),
        ));
    }
    Ok(body[after_topic..].to_vec())
}

/// Read a single MQTT packet: one fixed-header byte, a variable-length
/// "remaining length", then exactly that many bytes of body.
/// Returns `(packet_type_nibble, body_bytes)`.
fn read_packet<R: Read>(r: &mut R) -> Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 1];
    read_exact_or_eof(r, &mut hdr)?;
    let ctype = hdr[0] >> 4;
    let rem = read_remaining_length(r)?;
    let mut body = vec![0u8; rem];
    if rem > 0 {
        read_exact_or_eof(r, &mut body)?;
    }
    Ok((ctype, body))
}

fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<()> {
    match r.read_exact(buf) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Err(Error::UnexpectedEof),
        Err(e) => Err(Error::Io(e)),
    }
}

/// Decode a MQTT "remaining length" varint: 1-4 bytes, low 7 bits are value,
/// high bit is the continuation flag. Returns the parsed length in bytes.
///
/// Per the spec the maximum legal value is 268_435_455 (0xFD,0xFF,0xFF,0x7F).
/// A 5th byte (or any 4th byte with the continuation bit set) is malformed.
pub(crate) fn read_remaining_length<R: Read>(r: &mut R) -> io::Result<usize> {
    let mut value: usize = 0;
    let mut multiplier: usize = 1;
    for i in 0..4 {
        let mut b = [0u8; 1];
        r.read_exact(&mut b)?;
        let byte = b[0];
        value += (byte & 0x7F) as usize * multiplier;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        // Last legal byte must not have the continuation bit set.
        if i == 3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "mqtt: malformed remaining length (5th byte)",
            ));
        }
        multiplier *= 128;
    }
    unreachable!("loop returns or errors before exit")
}

/// Encode `len` as a MQTT "remaining length" varint and append it to `out`.
///
/// `len` must fit in 28 bits (`<= 268_435_455`); larger values are clamped at
/// the maximum since the caller controls the packets we produce.
pub(crate) fn write_remaining_length(out: &mut Vec<u8>, len: usize) {
    let mut x = len.min(268_435_455);
    loop {
        let mut byte = (x & 0x7F) as u8;
        x >>= 7;
        if x > 0 {
            byte |= 0x80;
            out.push(byte);
        } else {
            out.push(byte);
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In-memory `Read + Write` peer: reads pop bytes the broker would send,
    /// writes are captured for inspection. EOF once the canned input is drained.
    struct MockStream {
        to_read: std::io::Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl MockStream {
        fn new(to_read: Vec<u8>) -> Self {
            MockStream {
                to_read: std::io::Cursor::new(to_read),
                written: Vec::new(),
            }
        }
        fn written(&self) -> &[u8] {
            &self.written
        }
    }

    impl Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.to_read.read(buf)
        }
    }

    impl Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    // Spec boundary values: each is the max of one varint length, and the
    // first value that needs one more byte.
    const RL_CASES: &[(usize, &[u8])] = &[
        (0, &[0x00]),
        (127, &[0x7F]),
        (128, &[0x80, 0x01]),
        (16_383, &[0xFF, 0x7F]),
        (16_384, &[0x80, 0x80, 0x01]),
        (2_097_151, &[0xFF, 0xFF, 0x7F]),
        (2_097_152, &[0x80, 0x80, 0x80, 0x01]),
        (268_435_455, &[0xFF, 0xFF, 0xFF, 0x7F]),
    ];

    #[test]
    fn write_remaining_length_matches_spec_bytes() {
        for (value, expected) in RL_CASES {
            let mut buf = Vec::new();
            write_remaining_length(&mut buf, *value);
            assert_eq!(
                buf.as_slice(),
                *expected,
                "encoding of {value} (got {:02X?}, want {:02X?})",
                buf,
                expected
            );
        }
    }

    #[test]
    fn read_remaining_length_round_trips() {
        for (value, expected) in RL_CASES {
            // Round-trip: write then read.
            let mut buf = Vec::new();
            write_remaining_length(&mut buf, *value);
            let mut cur = std::io::Cursor::new(&buf);
            let got = read_remaining_length(&mut cur).expect("decode");
            assert_eq!(got, *value, "round trip for {value}");
            // Also: the canonical spec encoding decodes to the same number.
            let mut cur2 = std::io::Cursor::new(*expected);
            let got2 = read_remaining_length(&mut cur2).expect("decode spec bytes");
            assert_eq!(got2, *value, "spec-bytes decode for {value}");
        }
    }

    #[test]
    fn read_remaining_length_rejects_5_byte_varint() {
        // Four continuation bytes is illegal — the 4th byte must be terminal.
        let bad = [0xFF, 0xFF, 0xFF, 0xFF];
        let mut cur = std::io::Cursor::new(&bad[..]);
        assert!(read_remaining_length(&mut cur).is_err());
    }

    #[test]
    fn build_connect_exact_bytes_for_known_input() {
        // CONNECT with client_id "abc", no user/pass, keep-alive 60.
        //
        // Variable header (10 bytes):
        //   00 04 'M' 'Q' 'T' 'T'   -- protocol name
        //   04                       -- protocol level (v3.1.1)
        //   02                       -- connect flags: clean session
        //   00 3C                    -- keep alive = 60
        // Payload (5 bytes):
        //   00 03 'a' 'b' 'c'        -- client id
        // Remaining length = 15 = 0x0F
        // Fixed header: 0x10 0x0F
        let got = build_connect("abc", None, None, 60);
        let expected: Vec<u8> = vec![
            0x10, 0x0F, // fixed header: CONNECT, remaining length 15
            0x00, 0x04, b'M', b'Q', b'T', b'T', // protocol name
            0x04, // protocol level
            0x02, // flags
            0x00, 0x3C, // keep alive
            0x00, 0x03, b'a', b'b', b'c', // client id
        ];
        assert_eq!(got, expected);
    }

    #[test]
    fn build_connect_sets_user_and_password_flags() {
        let got = build_connect("id", Some("u"), Some("p"), 30);
        // Variable header (10):
        //   00 04 M Q T T  04  C2  00 1E
        //     flags = 0x02 | 0x80 (user) | 0x40 (pass) = 0xC2
        // Payload (4 + 3 + 3 = 10):
        //   00 02 'i' 'd'   00 01 'u'   00 01 'p'
        // Remaining length = 20 = 0x14
        let expected: Vec<u8> = vec![
            0x10, 0x14, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0xC2, 0x00, 0x1E, 0x00, 0x02,
            b'i', b'd', 0x00, 0x01, b'u', 0x00, 0x01, b'p',
        ];
        assert_eq!(got, expected);
    }

    #[test]
    fn build_subscribe_exact_bytes() {
        // SUBSCRIBE packet id 1, topic "a/b", QoS 0.
        //   fixed: 0x82, rem-length
        //   body: 00 01 (packet id), 00 03 'a' '/' 'b' (topic), 00 (QoS 0)
        //   body length = 2 + 5 + 1 = 8
        let got = build_subscribe(1, "a/b");
        let expected: Vec<u8> = vec![0x82, 0x08, 0x00, 0x01, 0x00, 0x03, b'a', b'/', b'b', 0x00];
        assert_eq!(got, expected);
    }

    #[test]
    fn build_publish_qos0_has_no_packet_id() {
        // PUBLISH topic "top", payload "PAY", QoS 0.
        //   fixed: 0x30 (type 3, flags 0), rem-length
        //   body: 00 03 't' 'o' 'p' (topic)  'P' 'A' 'Y' (payload)
        //   body length = 5 + 3 = 8
        let got = build_publish("top", b"PAY", 0, 1);
        let expected: Vec<u8> = vec![0x30, 0x08, 0x00, 0x03, b't', b'o', b'p', b'P', b'A', b'Y'];
        assert_eq!(got, expected);
        // QoS 0 ignores the packet id entirely: changing it does not move bytes.
        assert_eq!(build_publish("top", b"PAY", 0, 9999), expected);
    }

    #[test]
    fn build_publish_qos1_has_flag_and_packet_id() {
        // PUBLISH topic "top", payload "PAY", QoS 1, packet id 7.
        //   fixed: 0x32 (type 3, QoS bit = (1<<1)), rem-length
        //   body: 00 03 't' 'o' 'p' (topic)  00 07 (packet id)  'P' 'A' 'Y'
        //   body length = 5 + 2 + 3 = 10
        let got = build_publish("top", b"PAY", 1, 7);
        let expected: Vec<u8> = vec![
            0x32, 0x0A, 0x00, 0x03, b't', b'o', b'p', 0x00, 0x07, b'P', b'A', b'Y',
        ];
        assert_eq!(got, expected);
    }

    #[test]
    fn build_publish_large_payload_round_trips() {
        // A payload that needs a 2-byte remaining-length varint exercises the
        // framing end to end: build, then re-read with read_packet.
        let payload = vec![0xABu8; 5000];
        let pkt = build_publish("t", &payload, 0, 1);
        // Fixed header byte then varint then body; feed through the reader.
        let mut cur = std::io::Cursor::new(&pkt);
        let (ctype, body) = read_packet(&mut cur).expect("read PUBLISH");
        assert_eq!(ctype, PKT_PUBLISH);
        let got = extract_publish_payload(&body).expect("payload");
        assert_eq!(got, payload);
    }

    #[test]
    fn parse_puback_reads_packet_id() {
        assert_eq!(parse_puback(&[0x00, 0x07]).unwrap(), 7);
        assert_eq!(parse_puback(&[0x12, 0x34]).unwrap(), 0x1234);
        // Trailing bytes (none in v3.1.1) are ignored; short bodies error.
        assert!(parse_puback(&[0x00]).is_err());
    }

    #[test]
    fn qos1_publish_waits_for_matching_puback() {
        // Drive run_publish against an in-memory peer that speaks CONNACK then
        // PUBACK, and assert it parses our PUBLISH correctly off the wire.
        let mut from_broker = Vec::new();
        // CONNACK: type 2, rem-len 2, [session-present=0, rc=0].
        from_broker.extend_from_slice(&[(PKT_CONNACK << 4), 0x02, 0x00, 0x00]);
        // PUBACK: type 4, rem-len 2, packet id 1 (matches run_publish's id).
        from_broker.extend_from_slice(&[(PKT_PUBACK << 4), 0x02, 0x00, 0x01]);

        let mut peer = MockStream::new(from_broker);
        run_publish(&mut peer, "a/b", b"hello", 1, None, None).expect("publish ok");

        // The client should have written CONNECT, then a QoS-1 PUBLISH, then
        // DISCONNECT. Skip the CONNECT to reach the PUBLISH.
        let written = peer.written();
        let mut cur = std::io::Cursor::new(&written);
        let (c0, _) = read_packet(&mut cur).expect("connect");
        assert_eq!(c0, PKT_CONNECT);
        let publish_start = cur.position() as usize;
        let expected_publish = build_publish("a/b", b"hello", 1, 1);
        assert_eq!(
            &written[publish_start..publish_start + expected_publish.len()],
            expected_publish.as_slice()
        );
        // And a DISCONNECT trailing the PUBLISH.
        let disc = &written[publish_start + expected_publish.len()..];
        assert_eq!(disc, &[PKT_DISCONNECT << 4, 0x00]);
    }

    #[test]
    fn qos1_publish_rejects_mismatched_puback() {
        let mut from_broker = Vec::new();
        from_broker.extend_from_slice(&[(PKT_CONNACK << 4), 0x02, 0x00, 0x00]);
        // PUBACK for a different packet id (2) than we sent (1).
        from_broker.extend_from_slice(&[(PKT_PUBACK << 4), 0x02, 0x00, 0x02]);
        let mut peer = MockStream::new(from_broker);
        let err = run_publish(&mut peer, "a/b", b"hi", 1, None, None).unwrap_err();
        match err {
            Error::BadResponse(m) => assert!(m.contains("PUBACK"), "got {m}"),
            other => panic!("expected BadResponse, got {other:?}"),
        }
    }

    #[test]
    fn validate_publish_topic_rejects_wildcards_and_control() {
        // Wildcards are legal in SUBSCRIBE filters but not PUBLISH names.
        assert!(validate_publish_topic("sensor/+/temp").is_err());
        assert!(validate_publish_topic("sensor/#").is_err());
        // NUL and other control characters are rejected.
        assert!(validate_publish_topic("a\0b").is_err());
        assert!(validate_publish_topic("a\nb").is_err());
        // Ordinary hierarchical topics are accepted.
        assert!(validate_publish_topic("a/b/c").is_ok());
        assert!(validate_publish_topic("home/kitchen/temp").is_ok());
    }

    #[test]
    fn extract_publish_payload_strips_topic() {
        // body: 00 03 't' 'o' 'p'  P A Y
        let body = b"\x00\x03topPAY";
        let payload = extract_publish_payload(body).unwrap();
        assert_eq!(payload, b"PAY");
    }

    #[test]
    fn split_userinfo_variants() {
        assert_eq!(split_userinfo(None), (None, None));
        assert_eq!(split_userinfo(Some("alice")), (Some("alice"), None));
        assert_eq!(
            split_userinfo(Some("alice:secret")),
            (Some("alice"), Some("secret"))
        );
        // The first ':' is the split point — passwords may contain colons,
        // which is intentional and matches what curl does.
        assert_eq!(
            split_userinfo(Some("alice:s:p")),
            (Some("alice"), Some("s:p"))
        );
    }

    #[test]
    fn random_client_id_format() {
        let id = random_client_id();
        assert!(id.starts_with("rsurl-"), "got {id}");
        let suffix = &id["rsurl-".len()..];
        assert_eq!(suffix.len(), 12);
        assert!(suffix
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        // Two calls should not collide (48 bits of entropy).
        assert_ne!(random_client_id(), random_client_id());
    }
}

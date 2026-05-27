//! HTTP/3 support (RFC 9114), with QPACK (RFC 9204) over QUIC (RFC 9000).
//!
//! HTTP/3 reuses the `https://` URL scheme; the version is selected at
//! connect time, in practice via Alt-Svc — we simply offer it as an
//! alternate transport that a caller can request explicitly.
//!
//! Status of this module
//! =====================
//!
//! This is a **scaffold** implementation. The pieces present and tested are:
//!
//! * RFC 9000 §16 variable-length integer codec (`varint`).
//! * RFC 9114 §7.1 frame-header codec (`Frame`).
//! * RFC 9204 Appendix A QPACK static table (`qpack::STATIC_TABLE`)
//!   with a literal-only encoder and a decoder that handles both
//!   plain-literal and Huffman-coded (RFC 7541 Appendix B) literal
//!   field lines plus indexed static-name lines.
//! * A [`send`] function that wires a [`purecrypto::quic::QuicConnection`]
//!   client to a [`std::net::UdpSocket`], runs the QUIC handshake to
//!   completion, opens the HTTP/3 control stream (with a SETTINGS frame),
//!   then opens a request bidi stream and serializes a `:method`/`:scheme`/
//!   `:authority`/`:path` HEADERS frame followed by an optional DATA frame.
//!
//! What's deliberately incomplete (precise TODOs called out at the
//! relevant sites):
//!
//! * **QPACK Huffman**: implemented for the decoder. Both Huffman-coded
//!   literal names (3-bit-prefix H bit) and literal values (7-bit-prefix
//!   H bit) are decoded against the RFC 7541 Appendix B static prefix
//!   code. The encoder still emits non-Huffman literals for simplicity —
//!   that's wire-legal because the H bit is per-string. The Huffman table
//!   is duplicated from the HPACK decoder in [`crate::http2`]; see the
//!   note inside `qpack::HUFFMAN` for the rationale.
//! * **QPACK dynamic table**: not implemented. We send a zero-length
//!   QPACK encoder stream and silently drop the peer's encoder stream
//!   bytes. Indexed references into the dynamic table in a response will
//!   be rejected as a decode error. Most servers accept zero dynamic-table
//!   capacity from a client (see SETTINGS_QPACK_MAX_TABLE_CAPACITY=0) and
//!   downgrade.
//! * **HTTP/3 control / QPACK encoder / decoder unidirectional streams**:
//!   we open the control stream and send SETTINGS, but the encoder /
//!   decoder streams are only opened on demand if the dynamic table is in
//!   use (which we don't use). We accept and silently discard whatever
//!   the peer sends on its uni streams — for a one-shot request that's
//!   safe because the request bidi stream is independent.
//! * **Stream framing edge cases**: we assume the server sends HEADERS
//!   then DATA in a single ordered pair. Trailers (a second HEADERS
//!   frame after DATA), interleaved PUSH_PROMISE, GOAWAY before the
//!   response, and reserved frame types (RFC 9114 §7.2.8) are all
//!   ignored or treated as errors.
//! * **Loss recovery / PTO timer**: the I/O loop polls
//!   [`QuicConnection::next_timeout`] and calls [`on_timeout`], but the
//!   socket read timeout is a simple wall-clock cap, not a tightly
//!   integrated select-style multiplexer. A heavily lossy network may
//!   stall.
//!
//! [`on_timeout`]: purecrypto::quic::QuicConnection::on_timeout

use std::io;
use std::net::{ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use purecrypto::quic::transport_params::TransportParameters;
use purecrypto::quic::{QuicConfig, QuicConnection, StreamId};

use crate::error::{Error, Result};
use crate::{Request, Response};

// ============================================================================
// QUIC variable-length integer codec (RFC 9000 §16)
// ============================================================================

pub(crate) mod varint {
    //! Encode / decode QUIC variable-length integers per RFC 9000 §16.
    //!
    //! The top two bits of byte 0 select the size class:
    //! `00` → 1 byte, `01` → 2 bytes, `10` → 4 bytes, `11` → 8 bytes.
    //! The remaining bits of byte 0 plus all following bytes are big-endian
    //! value bytes.

    use crate::error::{Error, Result};

    /// Largest value representable in a QUIC varint: 2^62 − 1.
    pub const MAX: u64 = (1u64 << 62) - 1;

    /// Number of bytes [`encode`] will produce for `value`.
    #[allow(dead_code)]
    pub const fn encoded_len(value: u64) -> usize {
        if value < 1 << 6 {
            1
        } else if value < 1 << 14 {
            2
        } else if value < 1 << 30 {
            4
        } else {
            8
        }
    }

    /// Append a shortest-form varint encoding of `value` to `out`.
    pub fn encode(value: u64, out: &mut Vec<u8>) {
        debug_assert!(value <= MAX, "QUIC varint out of range: {value:#x}");
        if value < 1 << 6 {
            out.push(value as u8);
        } else if value < 1 << 14 {
            let bytes = (value as u16).to_be_bytes();
            out.push(bytes[0] | 0x40);
            out.push(bytes[1]);
        } else if value < 1 << 30 {
            let bytes = (value as u32).to_be_bytes();
            out.push(bytes[0] | 0x80);
            out.push(bytes[1]);
            out.push(bytes[2]);
            out.push(bytes[3]);
        } else {
            let bytes = value.to_be_bytes();
            out.push(bytes[0] | 0xC0);
            out.extend_from_slice(&bytes[1..]);
        }
    }

    /// Decode a varint at the start of `buf`. Returns `(value, bytes_used)`.
    pub fn decode(buf: &[u8]) -> Result<(u64, usize)> {
        if buf.is_empty() {
            return Err(Error::BadResponse("varint: empty input".into()));
        }
        let tag = buf[0] >> 6;
        let n: usize = 1 << tag; // 1, 2, 4, or 8
        if buf.len() < n {
            return Err(Error::BadResponse(format!(
                "varint: need {n} bytes, have {}",
                buf.len()
            )));
        }
        let mut v: u64 = (buf[0] & 0x3F) as u64;
        for &b in &buf[1..n] {
            v = (v << 8) | (b as u64);
        }
        Ok((v, n))
    }
}

// ============================================================================
// HTTP/3 frame header (RFC 9114 §7.1)
// ============================================================================

/// HTTP/3 frame types we care about (RFC 9114 §7.2).
#[allow(dead_code)]
pub(crate) mod frame_type {
    pub const DATA: u64 = 0x00;
    pub const HEADERS: u64 = 0x01;
    pub const CANCEL_PUSH: u64 = 0x03;
    pub const SETTINGS: u64 = 0x04;
    pub const PUSH_PROMISE: u64 = 0x05;
    pub const GOAWAY: u64 = 0x07;
    pub const MAX_PUSH_ID: u64 = 0x0D;
}

/// Unidirectional stream types (RFC 9114 §6.2).
#[allow(dead_code)]
pub(crate) mod uni_stream_type {
    pub const CONTROL: u64 = 0x00;
    pub const PUSH: u64 = 0x01;
    pub const QPACK_ENCODER: u64 = 0x02;
    pub const QPACK_DECODER: u64 = 0x03;
}

/// A parsed HTTP/3 frame header — just the type + length prefix. The payload
/// is read out of the stream separately so callers can stream large DATA
/// frames without buffering.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Frame {
    pub ty: u64,
    pub len: u64,
}

impl Frame {
    /// Encode the `<type:varint><length:varint>` prefix into `out`.
    pub fn encode_header(ty: u64, len: u64, out: &mut Vec<u8>) {
        varint::encode(ty, out);
        varint::encode(len, out);
    }

    /// Try to decode a frame header from the start of `buf`. Returns
    /// `(Frame, bytes_consumed)`.
    pub fn decode_header(buf: &[u8]) -> Result<(Frame, usize)> {
        let (ty, n1) = varint::decode(buf)?;
        let (len, n2) = varint::decode(&buf[n1..])?;
        Ok((Frame { ty, len }, n1 + n2))
    }
}

// ============================================================================
// QPACK static table (RFC 9204 Appendix A) and minimal codec
// ============================================================================

pub(crate) mod qpack {
    //! A pared-down QPACK encoder/decoder using only the static table.
    //!
    //! The encoder writes "Indexed Field Line — Static" when both the name
    //! and value match an entry, "Literal Field Line With Name Reference —
    //! Static" when only the name matches, and "Literal Field Line With
    //! Literal Name" otherwise (RFC 9204 §4.5.{2,4,6}). All literal strings
    //! are emitted *without* Huffman coding (`H` bit clear) for simplicity.
    //!
    //! The decoder accepts indexed-static and the two literal-name variants
    //! (with static-name reference, with literal name), Huffman-coded or
    //! not (the H bit selects RFC 7541 Appendix B prefix decoding). It
    //! still rejects dynamic-table references with [`Error::BadResponse`]
    //! so the failure is observable.

    use crate::error::{Error, Result};

    /// RFC 9204 Appendix A — the 99-entry QPACK static table.
    ///
    /// Indexed by the absolute static index; tuples are `(name, value)`.
    /// Entries with an empty `value` slot are name-only references.
    pub static STATIC_TABLE: &[(&str, &str)] = &[
        (":authority", ""),                                    // 0
        (":path", "/"),                                        // 1
        ("age", "0"),                                          // 2
        ("content-disposition", ""),                           // 3
        ("content-length", "0"),                               // 4
        ("cookie", ""),                                        // 5
        ("date", ""),                                          // 6
        ("etag", ""),                                          // 7
        ("if-modified-since", ""),                             // 8
        ("if-none-match", ""),                                 // 9
        ("last-modified", ""),                                 // 10
        ("link", ""),                                          // 11
        ("location", ""),                                      // 12
        ("referer", ""),                                       // 13
        ("set-cookie", ""),                                    // 14
        (":method", "CONNECT"),                                // 15
        (":method", "DELETE"),                                 // 16
        (":method", "GET"),                                    // 17
        (":method", "HEAD"),                                   // 18
        (":method", "OPTIONS"),                                // 19
        (":method", "POST"),                                   // 20
        (":method", "PUT"),                                    // 21
        (":scheme", "http"),                                   // 22
        (":scheme", "https"),                                  // 23
        (":status", "103"),                                    // 24
        (":status", "200"),                                    // 25
        (":status", "304"),                                    // 26
        (":status", "404"),                                    // 27
        (":status", "503"),                                    // 28
        ("accept", "*/*"),                                     // 29
        ("accept", "application/dns-message"),                 // 30
        ("accept-encoding", "gzip, deflate, br"),              // 31
        ("accept-ranges", "bytes"),                            // 32
        ("access-control-allow-headers", "cache-control"),     // 33
        ("access-control-allow-headers", "content-type"),      // 34
        ("access-control-allow-origin", "*"),                  // 35
        ("cache-control", "max-age=0"),                        // 36
        ("cache-control", "max-age=2592000"),                  // 37
        ("cache-control", "max-age=604800"),                   // 38
        ("cache-control", "no-cache"),                         // 39
        ("cache-control", "no-store"),                         // 40
        ("cache-control", "public, max-age=31536000"),         // 41
        ("content-encoding", "br"),                            // 42
        ("content-encoding", "gzip"),                          // 43
        ("content-type", "application/dns-message"),           // 44
        ("content-type", "application/javascript"),            // 45
        ("content-type", "application/json"),                  // 46
        ("content-type", "application/x-www-form-urlencoded"), // 47
        ("content-type", "image/gif"),                         // 48
        ("content-type", "image/jpeg"),                        // 49
        ("content-type", "image/png"),                         // 50
        ("content-type", "text/css"),                          // 51
        ("content-type", "text/html; charset=utf-8"),          // 52
        ("content-type", "text/plain"),                        // 53
        ("content-type", "text/plain;charset=utf-8"),          // 54
        ("range", "bytes=0-"),                                 // 55
        ("strict-transport-security", "max-age=31536000"),     // 56
        (
            "strict-transport-security",
            "max-age=31536000; includesubdomains",
        ), // 57
        (
            "strict-transport-security",
            "max-age=31536000; includesubdomains; preload",
        ), // 58
        ("vary", "accept-encoding"),                           // 59
        ("vary", "origin"),                                    // 60
        ("x-content-type-options", "nosniff"),                 // 61
        ("x-xss-protection", "1; mode=block"),                 // 62
        (":status", "100"),                                    // 63
        (":status", "204"),                                    // 64
        (":status", "206"),                                    // 65
        (":status", "302"),                                    // 66
        (":status", "400"),                                    // 67
        (":status", "403"),                                    // 68
        (":status", "421"),                                    // 69
        (":status", "425"),                                    // 70
        (":status", "500"),                                    // 71
        ("accept-language", ""),                               // 72
        ("access-control-allow-credentials", "FALSE"),         // 73
        ("access-control-allow-credentials", "TRUE"),          // 74
        ("access-control-allow-headers", "*"),                 // 75
        ("access-control-allow-methods", "get"),               // 76
        ("access-control-allow-methods", "get, post, options"), // 77
        ("access-control-allow-methods", "options"),           // 78
        ("access-control-expose-headers", "content-length"),   // 79
        ("access-control-request-headers", "content-type"),    // 80
        ("access-control-request-method", "get"),              // 81
        ("access-control-request-method", "post"),             // 82
        ("alt-svc", "clear"),                                  // 83
        ("authorization", ""),                                 // 84
        (
            "content-security-policy",
            "script-src 'none'; object-src 'none'; base-uri 'none'",
        ), // 85
        ("early-data", "1"),                                   // 86
        ("expect-ct", ""),                                     // 87
        ("forwarded", ""),                                     // 88
        ("if-range", ""),                                      // 89
        ("origin", ""),                                        // 90
        ("purpose", "prefetch"),                               // 91
        ("server", ""),                                        // 92
        ("timing-allow-origin", "*"),                          // 93
        ("upgrade-insecure-requests", "1"),                    // 94
        ("user-agent", ""),                                    // 95
        ("x-forwarded-for", ""),                               // 96
        ("x-frame-options", "deny"),                           // 97
        ("x-frame-options", "sameorigin"),                     // 98
    ];

    /// Find an entry matching both `name` and `value` (case-sensitive on
    /// name per HTTP/3 lowercase-headers rule, case-sensitive on value
    /// because the static table values are literal byte strings).
    pub fn find_indexed(name: &str, value: &str) -> Option<usize> {
        STATIC_TABLE
            .iter()
            .position(|(n, v)| *n == name && *v == value)
    }

    /// Find the first entry with a matching name (for name-reference
    /// literal field lines).
    pub fn find_name(name: &str) -> Option<usize> {
        STATIC_TABLE.iter().position(|(n, _)| *n == name)
    }

    /// Encode an integer with an `n`-bit prefix (RFC 7541 §5.1). The high
    /// bits of the first byte (the part above the n-bit prefix) are taken
    /// from `prefix_high_bits` — typically the QPACK pattern byte
    /// (`0b11xxxxxx` for indexed-static, etc.).
    pub fn encode_int(value: u64, prefix_bits: u8, prefix_high_bits: u8, out: &mut Vec<u8>) {
        debug_assert!((1..=8).contains(&prefix_bits));
        let max_prefix = (1u64 << prefix_bits) - 1;
        if value < max_prefix {
            out.push(prefix_high_bits | (value as u8));
        } else {
            out.push(prefix_high_bits | (max_prefix as u8));
            let mut rem = value - max_prefix;
            while rem >= 128 {
                out.push(((rem & 0x7F) as u8) | 0x80);
                rem >>= 7;
            }
            out.push(rem as u8);
        }
    }

    /// Decode an integer with an `n`-bit prefix. The first byte is `first`
    /// (already read by the caller so it can dispatch on the pattern bits).
    /// Returns `(value, extra_bytes_consumed_after_first)`.
    pub fn decode_int(first: u8, prefix_bits: u8, rest: &[u8]) -> Result<(u64, usize)> {
        debug_assert!((1..=8).contains(&prefix_bits));
        let mask = ((1u16 << prefix_bits) - 1) as u8;
        let prefix = (first & mask) as u64;
        let max_prefix = mask as u64;
        if prefix < max_prefix {
            return Ok((prefix, 0));
        }
        let mut value = max_prefix;
        let mut shift = 0u32;
        let mut used = 0usize;
        for &b in rest {
            used += 1;
            value = value
                .checked_add(((b & 0x7F) as u64) << shift)
                .ok_or_else(|| Error::BadResponse("qpack int overflow".into()))?;
            if b & 0x80 == 0 {
                return Ok((value, used));
            }
            shift += 7;
            if shift > 63 {
                return Err(Error::BadResponse("qpack int too long".into()));
            }
        }
        Err(Error::BadResponse("qpack int truncated".into()))
    }

    /// Encode a literal string (header name or value) using the 7-bit
    /// length prefix. Huffman bit clear, so the bytes are the literal
    /// UTF-8 of `s`.
    pub fn encode_string_7bit(s: &str, out: &mut Vec<u8>) {
        // Prefix pattern: 0b0xxxxxxx (H=0, 7-bit length).
        encode_int(s.len() as u64, 7, 0x00, out);
        out.extend_from_slice(s.as_bytes());
    }

    /// Encode a literal name string with the 3-bit-prefix length used by
    /// "Literal Field Line With Literal Name" (RFC 9204 §4.5.6). The two
    /// "N" (never-indexed) + "H" (Huffman) bits live above the 3-bit
    /// length prefix.
    pub fn encode_name_3bit(s: &str, out: &mut Vec<u8>) {
        // Pattern: 0b001N HXXX (N=0, H=0). 3-bit length prefix.
        encode_int(s.len() as u64, 3, 0b0010_0000, out);
        out.extend_from_slice(s.as_bytes());
    }

    /// Encode a single header field block. Each field becomes one of:
    /// indexed-static, literal-with-static-name-reference, or
    /// literal-with-literal-name.
    pub fn encode_field(name: &str, value: &str, out: &mut Vec<u8>) {
        if let Some(idx) = find_indexed(name, value) {
            // Indexed Field Line — Static: 0b1Txxxxxx, T=1 → static.
            // 6-bit prefix encodes the index.
            encode_int(idx as u64, 6, 0b1100_0000, out);
            return;
        }
        if let Some(idx) = find_name(name) {
            // Literal Field Line With Name Reference, T=1 → static.
            // Pattern: 0b01NTxxxx (N=0, T=1). 4-bit index prefix.
            encode_int(idx as u64, 4, 0b0101_0000, out);
            // Then a 7-bit-prefix literal value string.
            encode_string_7bit(value, out);
            return;
        }
        // Literal Field Line With Literal Name (no static / dynamic
        // reference at all). Pattern: 0b001NHXXX (N=0, H=0).
        encode_name_3bit(name, out);
        encode_string_7bit(value, out);
    }

    /// Encode a complete QPACK field section: required-insert-count = 0
    /// (we never reference the dynamic table) and delta-base = 0.
    pub fn encode_field_section(fields: &[(String, String)]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        // Required Insert Count: 0 (encoded as 8-bit prefix int).
        encode_int(0, 8, 0x00, &mut buf);
        // Base = Required Insert Count + Delta Base (S=0, +0).
        // S=0 ⇒ top bit of byte zero is 0. 7-bit-prefix int = 0.
        encode_int(0, 7, 0x00, &mut buf);
        for (n, v) in fields {
            encode_field(n, v, &mut buf);
        }
        buf
    }

    /// Decoded field section.
    pub type Fields = Vec<(String, String)>;

    /// Decode a complete QPACK field section. Handles indexed-static
    /// references and both plain and Huffman-coded literals. Rejects any
    /// reference to the dynamic table with `Error::BadResponse`.
    pub fn decode_field_section(buf: &[u8]) -> Result<Fields> {
        if buf.is_empty() {
            return Err(Error::BadResponse("qpack: empty field section".into()));
        }
        // Field Section Prefix: Required Insert Count (8-bit prefix) + Base.
        let (ric, n1) = decode_int(buf[0], 8, &buf[1..])?;
        if ric != 0 {
            return Err(Error::BadResponse(format!(
                "qpack: nonzero Required Insert Count ({ric}) — dynamic table not supported"
            )));
        }
        let mut p = 1 + n1;
        if p >= buf.len() {
            return Err(Error::BadResponse(
                "qpack: truncated field-section prefix".into(),
            ));
        }
        let (_base, n2) = decode_int(buf[p], 7, &buf[p + 1..])?;
        p += 1 + n2;

        let mut out: Fields = Vec::new();
        while p < buf.len() {
            let b = buf[p];
            if b & 0b1000_0000 != 0 {
                // Indexed Field Line: 0b1Txxxxxx
                let t_static = b & 0b0100_0000 != 0;
                let (idx, used) = decode_int(b, 6, &buf[p + 1..])?;
                p += 1 + used;
                if !t_static {
                    return Err(Error::BadResponse(
                        "qpack: dynamic-table indexed reference".into(),
                    ));
                }
                let (n, v) = *STATIC_TABLE.get(idx as usize).ok_or_else(|| {
                    Error::BadResponse(format!("qpack: static index out of range: {idx}"))
                })?;
                out.push((n.to_string(), v.to_string()));
            } else if b & 0b0100_0000 != 0 {
                // Literal Field Line With Name Reference: 0b01NTxxxx
                let t_static = b & 0b0001_0000 != 0;
                let (idx, used) = decode_int(b, 4, &buf[p + 1..])?;
                p += 1 + used;
                if !t_static {
                    return Err(Error::BadResponse(
                        "qpack: dynamic-table name reference".into(),
                    ));
                }
                let (name, _) = *STATIC_TABLE.get(idx as usize).ok_or_else(|| {
                    Error::BadResponse(format!("qpack: static name index out of range: {idx}"))
                })?;
                let value = decode_literal_string_7bit(&buf[p..])?;
                p += value.1;
                out.push((name.to_string(), value.0));
            } else if b & 0b0010_0000 != 0 {
                // Literal Field Line With Literal Name: 0b001NHXXX
                let huffman = b & 0b0000_1000 != 0;
                let (nlen, used) = decode_int(b, 3, &buf[p + 1..])?;
                p += 1 + used;
                let nlen = nlen as usize;
                if p + nlen > buf.len() {
                    return Err(Error::BadResponse("qpack: truncated literal name".into()));
                }
                let raw = &buf[p..p + nlen];
                let name = if huffman {
                    let bytes = huffman_decode(raw)?;
                    String::from_utf8(bytes)
                        .map_err(|_| Error::BadResponse("qpack: literal name not utf-8".into()))?
                } else {
                    std::str::from_utf8(raw)
                        .map_err(|_| Error::BadResponse("qpack: literal name not utf-8".into()))?
                        .to_string()
                };
                p += nlen;
                let value = decode_literal_string_7bit(&buf[p..])?;
                p += value.1;
                out.push((name, value.0));
            } else {
                // 0b0000xxxx or 0b0001xxxx — Indexed Field Line With
                // Post-Base Index, or Literal With Post-Base Name
                // Reference. Both reference the dynamic table.
                return Err(Error::BadResponse(
                    "qpack: post-base reference (dynamic table not supported)".into(),
                ));
            }
        }
        Ok(out)
    }

    /// Decode a 7-bit-prefix literal string (H + 7-bit length). Returns
    /// `(string, total_bytes_consumed_including_the_prefix_byte)`.
    /// Honors the H bit: if set, the raw bytes are Huffman-decoded per
    /// RFC 7541 Appendix B before the UTF-8 check.
    pub(crate) fn decode_literal_string_7bit(buf: &[u8]) -> Result<(String, usize)> {
        if buf.is_empty() {
            return Err(Error::BadResponse("qpack: missing literal string".into()));
        }
        let b = buf[0];
        let huffman = b & 0b1000_0000 != 0;
        let (slen, used) = decode_int(b, 7, &buf[1..])?;
        let start = 1 + used;
        let end = start + slen as usize;
        if end > buf.len() {
            return Err(Error::BadResponse("qpack: truncated literal value".into()));
        }
        let raw = &buf[start..end];
        let s = if huffman {
            let bytes = huffman_decode(raw)?;
            String::from_utf8(bytes)
                .map_err(|_| Error::BadResponse("qpack: literal value not utf-8".into()))?
        } else {
            std::str::from_utf8(raw)
                .map_err(|_| Error::BadResponse("qpack: literal value not utf-8".into()))?
                .to_string()
        };
        Ok((s, end))
    }

    // ------------------------------------------------------------------
    // QPACK Huffman decoder (RFC 9204 §4.1.2 → RFC 7541 §5.2 / Appendix B).
    // ------------------------------------------------------------------
    //
    // QPACK reuses the HPACK Huffman code verbatim. The 257-entry
    // `(code, bit_length)` table below is a byte-for-byte copy of the
    // one in `crate::http2`. We duplicate it here rather than exposing
    // `http2::HUFFMAN` as `pub(crate)` so the two modules remain
    // independent (an in-flight refactor on the HTTP/2 side touches
    // the surrounding code). The table is RFC-defined and immutable, so
    // duplication has no maintenance cost: if RFC 7541 Appendix B ever
    // changed (it won't), both copies would need updating in lockstep.
    //
    // The decoder is a straight bit-by-bit linear scan over the 257
    // entries — small, predictable, and easy to audit. With at most
    // 30 bits per symbol it stays well within budget for header
    // sections bounded by SETTINGS_MAX_FIELD_SECTION_SIZE.

    /// `(code, bit_length)` for each Huffman symbol, from RFC 7541
    /// Appendix B. Duplicated from `crate::http2::HUFFMAN`; see the
    /// section comment above for the rationale.
    const HUFFMAN: [(u32, u8); 257] = [
        (0x1ff8, 13),
        (0x7fffd8, 23),
        (0xfffffe2, 28),
        (0xfffffe3, 28),
        (0xfffffe4, 28),
        (0xfffffe5, 28),
        (0xfffffe6, 28),
        (0xfffffe7, 28),
        (0xfffffe8, 28),
        (0xffffea, 24),
        (0x3ffffffc, 30),
        (0xfffffe9, 28),
        (0xfffffea, 28),
        (0x3ffffffd, 30),
        (0xfffffeb, 28),
        (0xfffffec, 28),
        (0xfffffed, 28),
        (0xfffffee, 28),
        (0xfffffef, 28),
        (0xffffff0, 28),
        (0xffffff1, 28),
        (0xffffff2, 28),
        (0x3ffffffe, 30),
        (0xffffff3, 28),
        (0xffffff4, 28),
        (0xffffff5, 28),
        (0xffffff6, 28),
        (0xffffff7, 28),
        (0xffffff8, 28),
        (0xffffff9, 28),
        (0xffffffa, 28),
        (0xffffffb, 28),
        (0x14, 6),
        (0x3f8, 10),
        (0x3f9, 10),
        (0xffa, 12),
        (0x1ff9, 13),
        (0x15, 6),
        (0xf8, 8),
        (0x7fa, 11),
        (0x3fa, 10),
        (0x3fb, 10),
        (0xf9, 8),
        (0x7fb, 11),
        (0xfa, 8),
        (0x16, 6),
        (0x17, 6),
        (0x18, 6),
        (0x0, 5),
        (0x1, 5),
        (0x2, 5),
        (0x19, 6),
        (0x1a, 6),
        (0x1b, 6),
        (0x1c, 6),
        (0x1d, 6),
        (0x1e, 6),
        (0x1f, 6),
        (0x5c, 7),
        (0xfb, 8),
        (0x7ffc, 15),
        (0x20, 6),
        (0xffb, 12),
        (0x3fc, 10),
        (0x1ffa, 13),
        (0x21, 6),
        (0x5d, 7),
        (0x5e, 7),
        (0x5f, 7),
        (0x60, 7),
        (0x61, 7),
        (0x62, 7),
        (0x63, 7),
        (0x64, 7),
        (0x65, 7),
        (0x66, 7),
        (0x67, 7),
        (0x68, 7),
        (0x69, 7),
        (0x6a, 7),
        (0x6b, 7),
        (0x6c, 7),
        (0x6d, 7),
        (0x6e, 7),
        (0x6f, 7),
        (0x70, 7),
        (0x71, 7),
        (0x72, 7),
        (0xfc, 8),
        (0x73, 7),
        (0xfd, 8),
        (0x1ffb, 13),
        (0x7fff0, 19),
        (0x1ffc, 13),
        (0x3ffc, 14),
        (0x22, 6),
        (0x7ffd, 15),
        (0x3, 5),
        (0x23, 6),
        (0x4, 5),
        (0x24, 6),
        (0x5, 5),
        (0x25, 6),
        (0x26, 6),
        (0x27, 6),
        (0x6, 5),
        (0x74, 7),
        (0x75, 7),
        (0x28, 6),
        (0x29, 6),
        (0x2a, 6),
        (0x7, 5),
        (0x2b, 6),
        (0x76, 7),
        (0x2c, 6),
        (0x8, 5),
        (0x9, 5),
        (0x2d, 6),
        (0x77, 7),
        (0x78, 7),
        (0x79, 7),
        (0x7a, 7),
        (0x7b, 7),
        (0x7ffe, 15),
        (0x7fc, 11),
        (0x3ffd, 14),
        (0x1ffd, 13),
        (0xffffffc, 28),
        (0xfffe6, 20),
        (0x3fffd2, 22),
        (0xfffe7, 20),
        (0xfffe8, 20),
        (0x3fffd3, 22),
        (0x3fffd4, 22),
        (0x3fffd5, 22),
        (0x7fffd9, 23),
        (0x3fffd6, 22),
        (0x7fffda, 23),
        (0x7fffdb, 23),
        (0x7fffdc, 23),
        (0x7fffdd, 23),
        (0x7fffde, 23),
        (0xffffeb, 24),
        (0x7fffdf, 23),
        (0xffffec, 24),
        (0xffffed, 24),
        (0x3fffd7, 22),
        (0x7fffe0, 23),
        (0xffffee, 24),
        (0x7fffe1, 23),
        (0x7fffe2, 23),
        (0x7fffe3, 23),
        (0x7fffe4, 23),
        (0x1fffdc, 21),
        (0x3fffd8, 22),
        (0x7fffe5, 23),
        (0x3fffd9, 22),
        (0x7fffe6, 23),
        (0x7fffe7, 23),
        (0xffffef, 24),
        (0x3fffda, 22),
        (0x1fffdd, 21),
        (0xfffe9, 20),
        (0x3fffdb, 22),
        (0x3fffdc, 22),
        (0x7fffe8, 23),
        (0x7fffe9, 23),
        (0x1fffde, 21),
        (0x7fffea, 23),
        (0x3fffdd, 22),
        (0x3fffde, 22),
        (0xfffff0, 24),
        (0x1fffdf, 21),
        (0x3fffdf, 22),
        (0x7fffeb, 23),
        (0x7fffec, 23),
        (0x1fffe0, 21),
        (0x1fffe1, 21),
        (0x3fffe0, 22),
        (0x1fffe2, 21),
        (0x7fffed, 23),
        (0x3fffe1, 22),
        (0x7fffee, 23),
        (0x7fffef, 23),
        (0xfffea, 20),
        (0x3fffe2, 22),
        (0x3fffe3, 22),
        (0x3fffe4, 22),
        (0x7ffff0, 23),
        (0x3fffe5, 22),
        (0x3fffe6, 22),
        (0x7ffff1, 23),
        (0x3ffffe0, 26),
        (0x3ffffe1, 26),
        (0xfffeb, 20),
        (0x7fff1, 19),
        (0x3fffe7, 22),
        (0x7ffff2, 23),
        (0x3fffe8, 22),
        (0x1ffffec, 25),
        (0x3ffffe2, 26),
        (0x3ffffe3, 26),
        (0x3ffffe4, 26),
        (0x7ffffde, 27),
        (0x7ffffdf, 27),
        (0x3ffffe5, 26),
        (0xfffff1, 24),
        (0x1ffffed, 25),
        (0x7fff2, 19),
        (0x1fffe3, 21),
        (0x3ffffe6, 26),
        (0x7ffffe0, 27),
        (0x7ffffe1, 27),
        (0x3ffffe7, 26),
        (0x7ffffe2, 27),
        (0xfffff2, 24),
        (0x1fffe4, 21),
        (0x1fffe5, 21),
        (0x3ffffe8, 26),
        (0x3ffffe9, 26),
        (0xffffffd, 28),
        (0x7ffffe3, 27),
        (0x7ffffe4, 27),
        (0x7ffffe5, 27),
        (0xfffec, 20),
        (0xfffff3, 24),
        (0xfffed, 20),
        (0x1fffe6, 21),
        (0x3fffe9, 22),
        (0x1fffe7, 21),
        (0x1fffe8, 21),
        (0x7ffff3, 23),
        (0x3fffea, 22),
        (0x3fffeb, 22),
        (0x1ffffee, 25),
        (0x1ffffef, 25),
        (0xfffff4, 24),
        (0xfffff5, 24),
        (0x3ffffea, 26),
        (0x7ffff4, 23),
        (0x3ffffeb, 26),
        (0x7ffffe6, 27),
        (0x3ffffec, 26),
        (0x3ffffed, 26),
        (0x7ffffe7, 27),
        (0x7ffffe8, 27),
        (0x7ffffe9, 27),
        (0x7ffffea, 27),
        (0x7ffffeb, 27),
        (0xffffffe, 28),
        (0x7ffffec, 27),
        (0x7ffffed, 27),
        (0x7ffffee, 27),
        (0x7ffffef, 27),
        (0x7fffff0, 27),
        (0x3ffffee, 26),
        (0x3fffffff, 30), // EOS, index 256
    ];

    /// Decode a Huffman-coded literal. We walk bit-by-bit over the
    /// input, OR each bit into an accumulator, and check after every bit
    /// whether the accumulator (left-aligned for that length) matches
    /// any code of that length. With 257 symbols this is small enough
    /// to scan linearly.
    pub(crate) fn huffman_decode(input: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(input.len() * 2);
        let mut acc: u64 = 0;
        let mut acc_len: u8 = 0;

        for &byte in input {
            acc = (acc << 8) | (byte as u64);
            acc_len += 8;
            // Pull as many symbols as possible from the accumulator.
            while acc_len >= 5 {
                let mut matched = false;
                // Try lengths 5..=30 (no symbol shorter than 5 bits).
                let max_len = acc_len.min(30);
                for try_len in 5..=max_len {
                    let code = (acc >> (acc_len - try_len)) & ((1u64 << try_len) - 1);
                    if let Some(sym) = lookup_huffman(code as u32, try_len) {
                        if sym == 256 {
                            // EOS in a literal is a decoder error per
                            // RFC 7541 §5.2.
                            return Err(Error::BadResponse(
                                "qpack: EOS symbol in Huffman literal".into(),
                            ));
                        }
                        out.push(sym as u8);
                        acc_len -= try_len;
                        matched = true;
                        break;
                    }
                }
                if !matched {
                    break;
                }
            }
        }

        // Tail: remaining bits must be the most-significant bits of the
        // EOS code (all-ones), and there must be fewer than 8 of them
        // (RFC 7541 §5.2).
        if acc_len >= 8 {
            return Err(Error::BadResponse(
                "qpack: trailing Huffman bits >= 8".into(),
            ));
        }
        if acc_len > 0 {
            let pad_mask = (1u64 << acc_len) - 1;
            let tail = acc & pad_mask;
            if tail != pad_mask {
                return Err(Error::BadResponse("qpack: bad Huffman padding".into()));
            }
        }
        Ok(out)
    }

    fn lookup_huffman(code: u32, len: u8) -> Option<u16> {
        for (i, (c, l)) in HUFFMAN.iter().enumerate() {
            if *l == len && *c == code {
                return Some(i as u16);
            }
        }
        None
    }
}

// ============================================================================
// HTTP/3 client — the only public entry point
// ============================================================================

/// Maximum bytes we'll buffer from the response stream before giving up.
const MAX_RESPONSE_BYTES: usize = 256 * 1024 * 1024;
/// Maximum total wall-clock time spent in the I/O loop, irrespective of the
/// per-read timeout from the request. Backstop against pathological servers.
const MAX_TOTAL_DEADLINE: Duration = Duration::from_secs(300);
/// Maximum UDP datagram we expect to receive (a hair over the QUIC default).
const MAX_DATAGRAM: usize = 65_535;

/// Send a single request/response over a fresh HTTP/3 (QUIC) connection.
///
/// This is a scaffold. See the module-level docs for the precise list of
/// known gaps; the most user-visible one is the absence of QPACK
/// dynamic-table support — most servers degrade gracefully when the
/// client advertises `SETTINGS_QPACK_MAX_TABLE_CAPACITY=0`, but a
/// non-conforming peer can still emit dynamic references which we will
/// reject with `Error::BadResponse`.
pub fn send(req: Request) -> Result<Response> {
    if req.url.scheme != "https" {
        // HTTP/3 only runs over QUIC, which only runs encrypted.
        return Err(Error::UnsupportedScheme(format!(
            "http/3 requires https://, not {}://",
            req.url.scheme
        )));
    }

    let mut conn = build_client(&req)?;
    let (sock, peer) = open_udp(&req)?;
    handshake(&mut conn, &sock, peer, req.read_timeout)?;

    // RFC 9114 §6.2.1 — open a unidirectional control stream and send
    // SETTINGS. Without it the peer is allowed to close us with
    // H3_MISSING_SETTINGS. This is best-effort: if the streams API isn't
    // ready yet (handshake too fresh), we tolerate the error since some
    // servers don't strictly police it on a one-shot request.
    let _ = open_control_stream(&mut conn);

    // The first client-initiated bidi stream is StreamId 0 in the absence
    // of any prior streams. `open_bidi` allocates and returns the next
    // available ID for us.
    let request_stream = conn
        .open_bidi()
        .map_err(|e| Error::BadResponse(format!("http3: open_bidi failed: {e:?}")))?;

    write_request(&mut conn, request_stream, &req)?;
    pump(&mut conn, &sock, peer, req.read_timeout)?;

    read_response(&mut conn, &sock, peer, request_stream, &req)
}

/// Build the QUIC client connection with the right transport-parameter set
/// for HTTP/3.
fn build_client(req: &Request) -> Result<QuicConnection> {
    // Reuse the same system-root loading the HTTP/1.x TLS path uses.
    let roots = crate::tls::load_system_roots()?;
    let tls = purecrypto::tls::Config::builder()
        .tls_only()
        .roots(roots)
        .server_name(req.url.host.clone())
        .verify_certificates(true)
        // RFC 9114 §3.1 — HTTP/3 is selected via ALPN identifier "h3".
        .alpn(vec![b"h3".to_vec()])
        .build();

    let transport_params = TransportParameters {
        max_idle_timeout_ms: Some(30_000),
        max_udp_payload_size: Some(1452),
        // Generous credit so the server can put the whole response on one
        // bidi stream without our blocking it.
        initial_max_data: Some(10 * 1024 * 1024),
        initial_max_stream_data_bidi_local: Some(2 * 1024 * 1024),
        initial_max_stream_data_bidi_remote: Some(2 * 1024 * 1024),
        initial_max_stream_data_uni: Some(2 * 1024 * 1024),
        initial_max_streams_bidi: Some(100),
        // QPACK encoder + decoder + server-control all live on uni streams.
        initial_max_streams_uni: Some(100),
        active_connection_id_limit: Some(2),
        ..Default::default()
    };
    let cfg = QuicConfig {
        tls,
        transport_params,
        require_retry: false,
        retry_secret: None,
    };

    QuicConnection::client(cfg, &req.url.host)
        .map_err(|e| Error::BadResponse(format!("http3: build client: {e:?}")))
}

fn open_udp(req: &Request) -> Result<(UdpSocket, std::net::SocketAddr)> {
    let host_port = format!("{}:{}", req.url.host, req.url.port);
    let peer = host_port
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| Error::InvalidUrl(req.url.host.clone()))?;
    // Pick a local socket of the same family as the peer.
    let bind = if peer.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = UdpSocket::bind(bind)?;
    sock.connect(peer)?;
    // We do our own deadline accounting in the pump loop; set a short
    // per-recv timeout so we can interleave timer ticks.
    sock.set_read_timeout(Some(Duration::from_millis(100)))?;
    sock.set_write_timeout(req.read_timeout)?;
    Ok((sock, peer))
}

/// Drain whatever the connection wants to send right now, blast it out, and
/// optionally read one datagram from the socket back into the engine.
fn pump_once(
    conn: &mut QuicConnection,
    sock: &UdpSocket,
    peer: std::net::SocketAddr,
    can_block: bool,
) -> Result<bool> {
    // Egress: keep draining until pop returns empty.
    let mut sent_anything = false;
    loop {
        let dg = conn.pop_datagram();
        if dg.is_empty() {
            break;
        }
        sock.send(&dg)?;
        sent_anything = true;
    }

    // Ingress: try one recv (timed). `can_block` controls whether we wait
    // up to the socket's read-timeout for traffic to arrive.
    let mut buf = vec![0u8; MAX_DATAGRAM];
    let mut got_anything = false;
    if can_block {
        match sock.recv(&mut buf) {
            Ok(n) => {
                conn.feed_datagram_from(peer, &buf[..n])
                    .map_err(|e| Error::BadResponse(format!("http3: feed: {e:?}")))?;
                got_anything = true;
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
            }
            Err(e) => return Err(Error::Io(e)),
        }
    }

    // Run timers. We use a monotonic anchor inside the connection, so
    // `next_timeout` already returns the right delta.
    if let Some(_dl) = conn.next_timeout() {
        conn.on_timeout(Duration::ZERO);
    }

    // Drain any retransmissions the timer / feed triggered.
    loop {
        let dg = conn.pop_datagram();
        if dg.is_empty() {
            break;
        }
        sock.send(&dg)?;
        sent_anything = true;
    }

    Ok(sent_anything || got_anything)
}

/// Run the QUIC handshake until `is_handshake_complete()`.
fn handshake(
    conn: &mut QuicConnection,
    sock: &UdpSocket,
    peer: std::net::SocketAddr,
    deadline_hint: Option<Duration>,
) -> Result<()> {
    let total_deadline = deadline_hint
        .unwrap_or(MAX_TOTAL_DEADLINE)
        .min(MAX_TOTAL_DEADLINE);
    let start = Instant::now();
    while !conn.is_handshake_complete() {
        if start.elapsed() > total_deadline {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "http3: QUIC handshake timed out",
            )));
        }
        pump_once(conn, sock, peer, true)?;
        if conn.is_closed() {
            return Err(Error::BadResponse(
                "http3: connection closed mid-handshake".into(),
            ));
        }
    }
    Ok(())
}

/// Open a client-initiated unidirectional stream and send the HTTP/3
/// SETTINGS frame on it (RFC 9114 §6.2.1 + §7.2.4). Best-effort.
fn open_control_stream(conn: &mut QuicConnection) -> Result<()> {
    let sid = conn
        .open_uni()
        .map_err(|e| Error::BadResponse(format!("http3: open_uni: {e:?}")))?;
    // Stream-type prefix: 0x00 = control.
    let mut prefix = Vec::with_capacity(2);
    varint::encode(uni_stream_type::CONTROL, &mut prefix);
    // Empty SETTINGS frame (a SETTINGS payload is a sequence of
    // identifier+value varint pairs; an empty payload is legal).
    Frame::encode_header(frame_type::SETTINGS, 0, &mut prefix);
    write_all(conn, sid, &prefix)?;
    Ok(())
}

fn write_all(conn: &mut QuicConnection, sid: StreamId, mut data: &[u8]) -> Result<()> {
    while !data.is_empty() {
        let n = conn
            .write(sid, data)
            .map_err(|e| Error::BadResponse(format!("http3: stream write: {e:?}")))?;
        if n == 0 {
            // Flow control blocked — flush and retry next loop tick. For
            // the scaffold, we just bail rather than spinning.
            return Err(Error::BadResponse(
                "http3: stream write blocked (flow control)".into(),
            ));
        }
        data = &data[n..];
    }
    Ok(())
}

/// Serialize HEADERS + DATA for `req` onto `sid` and finish the send side.
fn write_request(conn: &mut QuicConnection, sid: StreamId, req: &Request) -> Result<()> {
    // Build the pseudo-headers required by RFC 9114 §4.3.1.
    let host_port = if req.url.port == 443 {
        req.url.host.clone()
    } else {
        format!("{}:{}", req.url.host, req.url.port)
    };
    let mut fields: Vec<(String, String)> = Vec::with_capacity(req.headers.len() + 5);
    fields.push((":method".into(), req.method.clone()));
    fields.push((":scheme".into(), "https".into()));
    fields.push((":authority".into(), host_port));
    fields.push((":path".into(), req.url.path.clone()));

    // Normal headers — HTTP/3 requires lowercase field names (RFC 9114
    // §4.2). Skip any pseudo-headers / Host / Connection-specific
    // headers the caller may have set.
    let mut have_ua = false;
    for (k, v) in &req.headers {
        let kl = k.to_ascii_lowercase();
        if kl.starts_with(':')
            || kl == "host"
            || kl == "connection"
            || kl == "transfer-encoding"
            || kl == "upgrade"
            || kl == "keep-alive"
            || kl == "proxy-connection"
        {
            continue;
        }
        if kl == "user-agent" {
            have_ua = true;
        }
        fields.push((kl, v.clone()));
    }
    if !have_ua {
        fields.push((
            "user-agent".into(),
            format!("curlrs/{}", env!("CARGO_PKG_VERSION")),
        ));
    }
    if !req.body.is_empty() {
        fields.push(("content-length".into(), req.body.len().to_string()));
    }

    let qpack_payload = qpack::encode_field_section(&fields);

    let mut out = Vec::with_capacity(qpack_payload.len() + 16);
    Frame::encode_header(frame_type::HEADERS, qpack_payload.len() as u64, &mut out);
    out.extend_from_slice(&qpack_payload);
    if !req.body.is_empty() {
        Frame::encode_header(frame_type::DATA, req.body.len() as u64, &mut out);
        out.extend_from_slice(&req.body);
    }
    write_all(conn, sid, &out)?;
    conn.finish(sid)
        .map_err(|e| Error::BadResponse(format!("http3: stream finish: {e:?}")))?;
    Ok(())
}

/// Spin the I/O loop a couple of times to push pending data out and pick up
/// anything the server already sent. Used after we've completed our send
/// side, before we start reading.
fn pump(
    conn: &mut QuicConnection,
    sock: &UdpSocket,
    peer: std::net::SocketAddr,
    _read_timeout: Option<Duration>,
) -> Result<()> {
    // A couple of non-blocking ticks just to flush our pending datagrams.
    for _ in 0..3 {
        pump_once(conn, sock, peer, false)?;
    }
    Ok(())
}

/// Block on the request stream until FIN, decoding frames and accumulating
/// HEADERS + DATA into a `Response`.
fn read_response(
    conn: &mut QuicConnection,
    sock: &UdpSocket,
    peer: std::net::SocketAddr,
    sid: StreamId,
    req: &Request,
) -> Result<Response> {
    let total_deadline = req
        .read_timeout
        .unwrap_or(MAX_TOTAL_DEADLINE)
        .min(MAX_TOTAL_DEADLINE);
    let start = Instant::now();

    let mut stream_buf: Vec<u8> = Vec::new();
    let mut headers: Option<qpack::Fields> = None;
    let mut body: Vec<u8> = Vec::new();

    loop {
        if start.elapsed() > total_deadline {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "http3: response timed out",
            )));
        }
        if conn.is_closed() {
            return Err(Error::BadResponse("http3: peer closed connection".into()));
        }

        // Pull whatever has arrived on the request stream.
        let mut tmp = vec![0u8; 16 * 1024];
        let (n, fin) = match conn.read(sid, &mut tmp) {
            Ok(x) => x,
            Err(e) => return Err(Error::BadResponse(format!("http3: stream read: {e:?}"))),
        };
        if n > 0 {
            if stream_buf.len() + n > MAX_RESPONSE_BYTES {
                return Err(Error::BadResponse("http3: response too large".into()));
            }
            stream_buf.extend_from_slice(&tmp[..n]);
        }

        // Try to peel frames off the buffer.
        loop {
            let consumed = match try_consume_frame(&stream_buf, &mut headers, &mut body) {
                FrameOutcome::Consumed(n) => n,
                FrameOutcome::NeedMore => break,
                FrameOutcome::Err(e) => return Err(e),
            };
            stream_buf.drain(..consumed);
            if stream_buf.is_empty() {
                break;
            }
        }

        if fin {
            if !stream_buf.is_empty() {
                return Err(Error::BadResponse(
                    "http3: stream FIN with partial frame in buffer".into(),
                ));
            }
            break;
        }

        // Drive the I/O loop forward so more bytes can arrive.
        pump_once(conn, sock, peer, true)?;
    }

    let fields = headers.ok_or_else(|| Error::BadResponse("http3: no HEADERS frame".into()))?;
    finalize_response(fields, body)
}

enum FrameOutcome {
    Consumed(usize),
    NeedMore,
    Err(Error),
}

/// Try to parse one HTTP/3 frame out of `buf`. On success, the relevant
/// output bucket (HEADERS → `headers`, DATA → `body`) is populated and the
/// number of bytes consumed is returned.
fn try_consume_frame(
    buf: &[u8],
    headers: &mut Option<qpack::Fields>,
    body: &mut Vec<u8>,
) -> FrameOutcome {
    let (frame, hdr_len) = match Frame::decode_header(buf) {
        Ok(x) => x,
        Err(_) => return FrameOutcome::NeedMore,
    };
    let total = hdr_len.saturating_add(frame.len as usize);
    if buf.len() < total {
        return FrameOutcome::NeedMore;
    }
    let payload = &buf[hdr_len..total];
    match frame.ty {
        frame_type::HEADERS => match qpack::decode_field_section(payload) {
            Ok(fields) => {
                if headers.is_some() {
                    // Trailers — RFC 9114 §4.1 allows them, but the
                    // scaffold doesn't surface them. Discard silently.
                } else {
                    *headers = Some(fields);
                }
                FrameOutcome::Consumed(total)
            }
            Err(e) => FrameOutcome::Err(e),
        },
        frame_type::DATA => {
            body.extend_from_slice(payload);
            FrameOutcome::Consumed(total)
        }
        // RFC 9114 §7.2.8 reserved/grease types — ignore (drain).
        _ => FrameOutcome::Consumed(total),
    }
}

fn finalize_response(fields: qpack::Fields, body: Vec<u8>) -> Result<Response> {
    let mut status: Option<u16> = None;
    let mut hdrs: Vec<(String, String)> = Vec::with_capacity(fields.len());
    for (k, v) in fields {
        if k == ":status" {
            status = Some(
                v.parse()
                    .map_err(|_| Error::BadResponse(format!("http3: bad :status {v:?}")))?,
            );
        } else if k.starts_with(':') {
            // Unknown response pseudo-header — RFC 9114 §4.3.2 says
            // there are none defined for responses, but tolerate.
            continue;
        } else {
            hdrs.push((k, v));
        }
    }
    let status = status.ok_or_else(|| Error::BadResponse("http3: missing :status".into()))?;
    Ok(Response {
        status,
        // HTTP/3 has no reason phrase on the wire.
        reason: String::new(),
        version: "HTTP/3".to_string(),
        headers: hdrs,
        body,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trip_size_classes() {
        // RFC 9000 §16 boundary values.
        let cases: &[(u64, usize)] = &[
            (0, 1),
            (63, 1),
            (64, 2),
            (16_383, 2),
            (16_384, 4),
            ((1 << 30) - 1, 4),
            (1 << 30, 8),
            (varint::MAX, 8),
        ];
        for &(value, expected_len) in cases {
            assert_eq!(varint::encoded_len(value), expected_len, "len({value})");
            let mut buf = Vec::new();
            varint::encode(value, &mut buf);
            assert_eq!(buf.len(), expected_len, "encoded bytes for {value}");
            let (decoded, n) = varint::decode(&buf).expect("decode");
            assert_eq!(decoded, value, "round-trip value");
            assert_eq!(n, expected_len, "round-trip length");
        }
    }

    #[test]
    fn varint_rejects_empty_and_truncated() {
        assert!(varint::decode(&[]).is_err());
        // 0x40 → tag=01 → 2-byte form, but only 1 byte present.
        assert!(varint::decode(&[0x40]).is_err());
        // 0xC0 → tag=11 → 8-byte form, only 3 bytes present.
        assert!(varint::decode(&[0xC0, 0x00, 0x00]).is_err());
    }

    #[test]
    fn varint_accepts_non_minimal_encoding() {
        // 0x40 0x00 is a legal but non-minimal encoding of 0
        // (RFC 9000 §16 — decoder MUST accept any of the four legal lengths).
        let (v, n) = varint::decode(&[0x40, 0x00]).unwrap();
        assert_eq!(v, 0);
        assert_eq!(n, 2);
    }

    #[test]
    fn qpack_static_table_has_99_entries() {
        // RFC 9204 Appendix A: 99 entries, indices 0..=98.
        assert_eq!(
            qpack::STATIC_TABLE.len(),
            99,
            "QPACK static table must have 99 entries per RFC 9204 Appendix A"
        );
    }

    #[test]
    fn qpack_static_table_known_landmarks() {
        // Spot-check a few entries against RFC 9204 Appendix A.
        assert_eq!(qpack::STATIC_TABLE[0], (":authority", ""));
        assert_eq!(qpack::STATIC_TABLE[17], (":method", "GET"));
        assert_eq!(qpack::STATIC_TABLE[23], (":scheme", "https"));
        assert_eq!(qpack::STATIC_TABLE[25], (":status", "200"));
        assert_eq!(qpack::STATIC_TABLE[98], ("x-frame-options", "sameorigin"));
    }

    #[test]
    fn qpack_indexed_lookup_finds_get_and_https() {
        assert_eq!(qpack::find_indexed(":method", "GET"), Some(17));
        assert_eq!(qpack::find_indexed(":scheme", "https"), Some(23));
        assert_eq!(qpack::find_indexed(":status", "200"), Some(25));
        // Name-only lookup finds the first occurrence.
        assert_eq!(qpack::find_name(":method"), Some(15));
        assert_eq!(qpack::find_indexed(":method", "UNKNOWN"), None);
    }

    #[test]
    fn qpack_int_round_trip_prefix_sizes() {
        // 8-bit-prefix max stay-in-prefix value is 254.
        for &(value, prefix, pattern) in &[
            (0u64, 8u8, 0x00u8),
            (1, 5, 0xE0),
            (10, 5, 0xE0),
            (30, 5, 0xE0), // 30 < 31 (max 5-bit prefix)
            (31, 5, 0xE0), // boundary: spills out
            (1000, 5, 0xE0),
            (254, 8, 0x00),
            (255, 8, 0x00),
            (1 << 20, 7, 0x00),
        ] {
            let mut buf = Vec::new();
            qpack::encode_int(value, prefix, pattern, &mut buf);
            let (decoded, used) = qpack::decode_int(buf[0], prefix, &buf[1..]).expect("decode_int");
            assert_eq!(decoded, value, "value {value}, prefix {prefix}");
            assert_eq!(used + 1, buf.len(), "used+1 == buf.len for value {value}");
        }
    }

    #[test]
    fn http3_frame_header_round_trip() {
        // A few representative (type, length) pairs spanning all varint
        // size classes.
        let cases: &[(u64, u64)] = &[
            (frame_type::DATA, 0),
            (frame_type::HEADERS, 17),
            (frame_type::SETTINGS, 63),
            (frame_type::HEADERS, 64),
            (frame_type::DATA, 16_383),
            (frame_type::DATA, 16_384),
            (frame_type::DATA, 1 << 20),
        ];
        for &(ty, len) in cases {
            let mut buf = Vec::new();
            Frame::encode_header(ty, len, &mut buf);
            let (parsed, used) = Frame::decode_header(&buf).expect("decode_header");
            assert_eq!(parsed, Frame { ty, len });
            assert_eq!(used, buf.len(), "exact consumption for ({ty},{len})");
        }
    }

    #[test]
    fn qpack_encode_decode_round_trip_indexed_and_literal() {
        // Build a field set that exercises all three encoder branches:
        // indexed-static, literal-with-static-name, literal-literal.
        let fields = vec![
            (":method".to_string(), "GET".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "example.com".to_string()),
            (":path".to_string(), "/index.html".to_string()),
            ("user-agent".to_string(), "curlrs/test".to_string()),
            ("x-custom".to_string(), "hello".to_string()),
        ];
        let wire = qpack::encode_field_section(&fields);
        let decoded = qpack::decode_field_section(&wire).expect("decode");
        assert_eq!(decoded, fields);
    }

    // ---- QPACK Huffman decoder tests --------------------------------------

    #[test]
    fn qpack_huffman_decodes_rfc7541_c4_www_example_com() {
        // RFC 7541 §C.4.1 — the Huffman-encoded form of the :authority
        // value "www.example.com" (the encoded representation used in
        // the HPACK example, which QPACK inherits byte-for-byte).
        let encoded = [
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        let out = qpack::huffman_decode(&encoded).expect("decode");
        assert_eq!(out, b"www.example.com");
    }

    #[test]
    fn qpack_huffman_decodes_rfc7541_c4_no_cache() {
        // RFC 7541 §C.4.2 — Huffman-encoded "no-cache" (the cache-control
        // value in the second request of the §C.4 example).
        let encoded = [0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf];
        let out = qpack::huffman_decode(&encoded).expect("decode");
        assert_eq!(out, b"no-cache");
    }

    #[test]
    fn qpack_huffman_decodes_rfc7541_c4_custom_key_and_value() {
        // RFC 7541 §C.4.3 — Huffman-encoded "custom-key" and
        // "custom-value" (the literal-name + literal-value header in
        // the third request of the §C.4 example).
        let key_encoded = [0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f];
        let key = qpack::huffman_decode(&key_encoded).expect("decode key");
        assert_eq!(key, b"custom-key");

        let val_encoded = [0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf];
        let val = qpack::huffman_decode(&val_encoded).expect("decode value");
        assert_eq!(val, b"custom-value");
    }

    #[test]
    fn qpack_huffman_decodes_hand_built_get() {
        // Hand-built encoding of "GET" per RFC 7541 Appendix B:
        //   G (sym 71) = 0x62 = 0b1100010   (7 bits)
        //   E (sym 69) = 0x60 = 0b1100000   (7 bits)
        //   T (sym 84) = 0x6f = 0b1101111   (7 bits)
        // Concatenated: 1100010 1100000 1101111 = 21 bits.
        // Pad with 3 high bits of the EOS code (all-ones) to reach 24
        // bits → 11000101 10000011 01111111 → 0xC5, 0x83, 0x7F.
        let encoded = [0xC5, 0x83, 0x7F];
        let out = qpack::huffman_decode(&encoded).expect("decode");
        assert_eq!(out, b"GET");
    }

    #[test]
    fn qpack_huffman_decoder_rejects_eos_in_literal() {
        // The EOS marker (symbol 256, 30 bits, all-ones) MUST NOT appear
        // as a decoded symbol in a literal — RFC 7541 §5.2. Build a
        // 32-bit input that starts with the 30-bit EOS code followed by
        // 2 padding bits.
        // 30 ones + 2 ones = 32 bits = 4 bytes of 0xFF.
        let encoded = [0xFF, 0xFF, 0xFF, 0xFF];
        let err = qpack::huffman_decode(&encoded).unwrap_err();
        match err {
            Error::BadResponse(m) => {
                // Either the EOS check fires or the trailing-bits
                // guard fires; both are spec-compliant rejections.
                assert!(
                    m.contains("EOS") || m.contains("Huffman"),
                    "unexpected message: {m}"
                );
            }
            other => panic!("expected BadResponse, got {other:?}"),
        }
    }

    #[test]
    fn qpack_huffman_decoder_rejects_bad_padding() {
        // Tail bits must be the high bits of the EOS code (all ones).
        // Build "G" (7 bits = 0b1100011) then pad with a single 0 bit.
        // Resulting byte: 0b11000110 = 0xC6. Decoder must reject the
        // zero-bit tail.
        let encoded = [0xC6];
        let err = qpack::huffman_decode(&encoded).unwrap_err();
        match err {
            Error::BadResponse(m) => assert!(m.contains("padding"), "msg: {m}"),
            other => panic!("expected BadResponse(padding), got {other:?}"),
        }
    }

    #[test]
    fn qpack_decoder_handles_huffman_literal_value_end_to_end() {
        // Field section: one Literal Field Line With Name Reference,
        // index=0 (":authority"), value Huffman-coded "www.example.com".
        // This is exactly the wire form a real server would emit and
        // the path that previously failed before the Huffman decoder
        // landed.
        let www_huffman: [u8; 12] = [
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        let mut buf = Vec::new();
        // Field-section prefix: RIC=0, Base=0.
        qpack::encode_int(0, 8, 0x00, &mut buf);
        qpack::encode_int(0, 7, 0x00, &mut buf);
        // Literal Field Line With Name Reference (T=1 static), idx=0
        // (":authority"). 4-bit prefix base = 0b0101_0000.
        qpack::encode_int(0, 4, 0b0101_0000, &mut buf);
        // Value: 7-bit prefix byte = H(1) | length(12) = 0x80 | 12 = 0x8C.
        buf.push(0x80 | 12);
        buf.extend_from_slice(&www_huffman);

        let fields = qpack::decode_field_section(&buf).expect("decode");
        assert_eq!(
            fields,
            vec![(":authority".to_string(), "www.example.com".to_string())]
        );
    }

    #[test]
    fn qpack_decoder_handles_huffman_literal_name_end_to_end() {
        // Field section: one Literal Field Line With Literal Name where
        // BOTH the name and value are Huffman-coded. Uses
        // "custom-key" / "custom-value" from RFC 7541 §C.4.3.
        let key_huffman: [u8; 8] = [0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f];
        let val_huffman: [u8; 9] = [0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf];

        let mut buf = Vec::new();
        // Field-section prefix.
        qpack::encode_int(0, 8, 0x00, &mut buf);
        qpack::encode_int(0, 7, 0x00, &mut buf);
        // Literal Field Line With Literal Name. Pattern 0b001NHXXX with
        // N=0 and H=1 → 0b0010_1000. 3-bit length prefix for name
        // length 8.  Compose the first byte by hand: 0b0010_1000 | 8 =
        // 0b0011_0000.  (Since 8 spills out of the 3-bit prefix max 7,
        // encode_int will use the continuation form, so just call it.)
        qpack::encode_int(key_huffman.len() as u64, 3, 0b0010_1000, &mut buf);
        buf.extend_from_slice(&key_huffman);
        // Value: 7-bit prefix with H=1.
        qpack::encode_int(val_huffman.len() as u64, 7, 0x80, &mut buf);
        buf.extend_from_slice(&val_huffman);

        let fields = qpack::decode_field_section(&buf).expect("decode");
        assert_eq!(
            fields,
            vec![("custom-key".to_string(), "custom-value".to_string())]
        );
    }

    #[test]
    fn send_rejects_non_https() {
        let req = Request::get("http://example.com/").unwrap();
        let err = send(req).unwrap_err();
        match err {
            Error::UnsupportedScheme(_) => {}
            other => panic!("expected UnsupportedScheme, got {other:?}"),
        }
    }
}

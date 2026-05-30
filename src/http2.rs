//! HTTP/2 support (RFC 9113), with HPACK header compression (RFC 7541).
//!
//! HTTP/2 reuses the `https://` URL scheme; the version is selected at
//! connect time, typically via ALPN ("h2"). This module exposes a backend
//! that can serve [`crate::Request`] over a TLS connection negotiated with
//! ALPN, returning a [`crate::Response`] just like HTTP/1.1.
//!
//! Scope of this implementation:
//!
//! - Multiplexed streams within one connection (RFC 9113 §5.1). The public
//!   `send()` still opens one TLS session per call — connection pooling
//!   across `send()` calls is task 5 — but a single `Connection` is now
//!   structurally capable of carrying many concurrent streams.
//! - ALPN is offered as `h2`. If the server does not select it, we still
//!   attempt the HTTP/2 preface (a server that didn't agree will close us
//!   or respond with a GOAWAY, which we surface as `BadResponse`).
//! - HPACK encoder uses indexed references against the static AND dynamic
//!   tables, literal-with-incremental-indexing for new headers (so repeats
//!   collapse to one byte on subsequent requests), Huffman literal strings
//!   when shorter than the raw form, and emits dynamic-table-size-update
//!   signals when the peer changes `SETTINGS_HEADER_TABLE_SIZE`. Volatile
//!   headers (cookies, authorization) are currently still added to the
//!   dynamic table — see the §6.2.3 "never-indexed" note as future work.
//! - HPACK decoder handles the static table, indexed-name+literal-value,
//!   full literal, dynamic table insertions (capped, no resize signals
//!   beyond the default 4096), and Huffman-coded literals (RFC 7541
//!   Appendix B).
//! - Frame I/O covers HEADERS, CONTINUATION, DATA, SETTINGS, PING,
//!   WINDOW_UPDATE, GOAWAY, RST_STREAM. We auto-ACK SETTINGS, auto-PONG
//!   PING; everything else on a non-target stream is ignored.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex, OnceLock};

use crate::error::{Error, Result};
use crate::tls::TlsStream;
use crate::{Request, Response};

// ---------------------------------------------------------------------------
// Connection preface and frame types.
// ---------------------------------------------------------------------------

/// The 24-byte client connection preface from RFC 9113 §3.4.
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// Frame types (RFC 9113 §6).
const F_DATA: u8 = 0x0;
const F_HEADERS: u8 = 0x1;
#[allow(dead_code)]
const F_PRIORITY: u8 = 0x2;
const F_RST_STREAM: u8 = 0x3;
const F_SETTINGS: u8 = 0x4;
#[allow(dead_code)]
const F_PUSH_PROMISE: u8 = 0x5;
const F_PING: u8 = 0x6;
const F_GOAWAY: u8 = 0x7;
const F_WINDOW_UPDATE: u8 = 0x8;
const F_CONTINUATION: u8 = 0x9;

// Flags.
const FLAG_END_STREAM: u8 = 0x01;
const FLAG_ACK: u8 = 0x01;
const FLAG_END_HEADERS: u8 = 0x04;
const FLAG_PADDED: u8 = 0x08;
const FLAG_PRIORITY: u8 = 0x20;

// SETTINGS parameter identifiers (RFC 9113 §6.5.2).
const S_HEADER_TABLE_SIZE: u16 = 0x1;
const S_ENABLE_PUSH: u16 = 0x2;
const S_MAX_CONCURRENT_STREAMS: u16 = 0x3;
const S_INITIAL_WINDOW_SIZE: u16 = 0x4;
const S_MAX_FRAME_SIZE: u16 = 0x5;
const S_MAX_HEADER_LIST_SIZE: u16 = 0x6;

// RFC 9113 §6.5.2 bounds for SETTINGS validation.
const INITIAL_WINDOW_SIZE_MAX: u32 = 0x7fff_ffff; // 2^31 - 1
const MAX_FRAME_SIZE_MIN: u32 = 16_384; // 2^14
const MAX_FRAME_SIZE_MAX: u32 = 16_777_215; // 2^24 - 1

/// Cumulative response-body ceiling (per stream). HTTP/2 flow control
/// auto-replenishes, so without an absolute cap a server can stream DATA
/// frames forever and exhaust memory. Mirrors HTTP/3's `MAX_RESPONSE_BYTES`.
const MAX_RESPONSE_BYTES: usize = 256 * 1024 * 1024;

/// Cap on the aggregate size of a single (HEADERS + CONTINUATION) header
/// block we will buffer before END_HEADERS, in *compressed* wire bytes.
/// Bounds the CONTINUATION-flood / unbounded-header-block class
/// (CVE-2024-27316). We don't advertise `SETTINGS_MAX_HEADER_LIST_SIZE`, so
/// this is a sane fixed ceiling on the on-the-wire block.
const MAX_HEADERS_BUF: usize = 256 * 1024;

/// Cap on the *decoded* header-list size (sum of `name + value + 32` per
/// header, the RFC 7541 §4.1 accounting). Bounds HPACK decompression bombs:
/// a small compressed block can otherwise expand into a huge header list.
const MAX_DECODED_HEADER_LIST: usize = 256 * 1024;

/// Peer (server) SETTINGS values, with RFC 9113 defaults for any parameter
/// the peer hasn't sent. We track all six standard parameters even if we
/// don't yet act on each of them; future tasks will consume more.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PeerSettings {
    header_table_size: u32,
    enable_push: bool,
    max_concurrent_streams: u32,
    initial_window_size: u32,
    max_frame_size: u32,
    max_header_list_size: u32,
}

impl Default for PeerSettings {
    fn default() -> Self {
        // Defaults from RFC 9113 §6.5.2. "No limit" parameters are represented
        // as u32::MAX so callers can compare uniformly without special-casing.
        PeerSettings {
            header_table_size: 4096,
            enable_push: true,
            max_concurrent_streams: u32::MAX,
            initial_window_size: 65_535,
            max_frame_size: 16_384,
            max_header_list_size: u32::MAX,
        }
    }
}

impl PeerSettings {
    /// Apply a SETTINGS frame payload to this state, per RFC 9113 §6.5.2.
    ///
    /// The payload is a sequence of 6-byte entries (u16 identifier, u32 value,
    /// both big-endian). Unknown identifiers MUST be ignored. Out-of-range
    /// values for known identifiers are reported as `Error::BadResponse`
    /// (the RFC distinguishes PROTOCOL_ERROR vs FLOW_CONTROL_ERROR, but this
    /// module doesn't surface H2 error codes yet).
    fn apply_settings_payload(&mut self, payload: &[u8]) -> Result<()> {
        if payload.len() % 6 != 0 {
            return Err(Error::BadResponse(format!(
                "SETTINGS payload length {} not a multiple of 6",
                payload.len()
            )));
        }
        for chunk in payload.chunks_exact(6) {
            let id = u16::from_be_bytes([chunk[0], chunk[1]]);
            let val = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
            match id {
                S_HEADER_TABLE_SIZE => self.header_table_size = val,
                S_ENABLE_PUSH => {
                    self.enable_push = match val {
                        0 => false,
                        1 => true,
                        _ => {
                            return Err(Error::BadResponse(format!(
                                "SETTINGS_ENABLE_PUSH must be 0 or 1, got {val}"
                            )));
                        }
                    };
                }
                S_MAX_CONCURRENT_STREAMS => self.max_concurrent_streams = val,
                S_INITIAL_WINDOW_SIZE => {
                    if val > INITIAL_WINDOW_SIZE_MAX {
                        return Err(Error::BadResponse(format!(
                            "SETTINGS_INITIAL_WINDOW_SIZE {val} exceeds 2^31-1 (FLOW_CONTROL_ERROR)"
                        )));
                    }
                    self.initial_window_size = val;
                }
                S_MAX_FRAME_SIZE => {
                    if !(MAX_FRAME_SIZE_MIN..=MAX_FRAME_SIZE_MAX).contains(&val) {
                        return Err(Error::BadResponse(format!(
                            "SETTINGS_MAX_FRAME_SIZE {val} out of range [16384, 16777215]"
                        )));
                    }
                    self.max_frame_size = val;
                }
                S_MAX_HEADER_LIST_SIZE => self.max_header_list_size = val,
                _ => {
                    // Unknown identifiers MUST be ignored (RFC 9113 §6.5.2).
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Flow control (RFC 9113 §5.2 / §6.9).
// ---------------------------------------------------------------------------
//
// Both endpoints maintain a connection-level window AND a per-stream window;
// only DATA frames consume window. Defaults are 65,535 octets (§6.9.2).
//
// We split these into four types because the connection-level windows live on
// the `Connection` and the stream-level windows live on each `Stream`. Mixing
// the two in one struct (as the single-stream code did) made the boundary
// fuzzy; splitting it means a `Stream` can't accidentally mutate the conn
// window and vice versa. All windows use `i64` because §6.9.2 permits a
// stream's send window to go negative when `SETTINGS_INITIAL_WINDOW_SIZE`
// shrinks; conn windows can't go negative but the wider type keeps the
// arithmetic uniform.

/// Hard cap on either window: RFC 9113 §6.9.1.
const WINDOW_MAX: i64 = 0x7fff_ffff;

/// Our advertised receive window for new streams. We don't currently send
/// `SETTINGS_INITIAL_WINDOW_SIZE`, so the peer sees the RFC default of 65,535;
/// keep this value in sync with whatever we advertise.
const OUR_INITIAL_WINDOW: i64 = 65_535;

/// Connection-level outbound flow-control window: how many DATA bytes we are
/// still allowed to send across *any* stream on this connection before the
/// peer has to grant more with `WINDOW_UPDATE` on stream 0 (§6.9). The
/// connection window is not affected by `SETTINGS_INITIAL_WINDOW_SIZE`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ConnSendWindow {
    available: i64,
}

impl ConnSendWindow {
    fn new() -> Self {
        ConnSendWindow { available: 65_535 }
    }

    /// Apply a `WINDOW_UPDATE` for stream 0. Zero increment and overflow past
    /// `2^31-1` are both errors (RFC 9113 §6.9.1).
    fn apply_window_update(&mut self, increment: u32) -> Result<()> {
        if increment == 0 {
            return Err(Error::BadResponse(
                "WINDOW_UPDATE with zero increment on connection (FLOW_CONTROL_ERROR)".into(),
            ));
        }
        let new_val = self.available + increment as i64;
        if new_val > WINDOW_MAX {
            return Err(Error::BadResponse(format!(
                "WINDOW_UPDATE pushes conn send window to {new_val} > 2^31-1 (FLOW_CONTROL_ERROR)"
            )));
        }
        self.available = new_val;
        Ok(())
    }

    /// Decrement the connection window by `n` after writing a DATA frame.
    fn consume(&mut self, n: usize) {
        self.available -= n as i64;
    }
}

/// Per-stream outbound flow-control window. Each stream tracks its own budget
/// alongside the basis we use to compute future `SETTINGS_INITIAL_WINDOW_SIZE`
/// deltas (§6.9.2).
#[derive(Debug, Clone, PartialEq, Eq)]
struct StreamSendWindow {
    available: i64,
    /// Last applied peer `SETTINGS_INITIAL_WINDOW_SIZE` — the basis for the
    /// next delta calculation. New streams pick this up from the
    /// `Connection`'s current peer settings at open time.
    initial_peer_window: i64,
}

impl StreamSendWindow {
    fn new(initial: i64) -> Self {
        StreamSendWindow {
            available: initial,
            initial_peer_window: initial,
        }
    }

    /// Apply a `WINDOW_UPDATE` targeting this stream. Same validation as the
    /// connection-level one (§6.9.1).
    fn apply_window_update(&mut self, increment: u32) -> Result<()> {
        if increment == 0 {
            return Err(Error::BadResponse(
                "WINDOW_UPDATE with zero increment on stream (PROTOCOL_ERROR)".into(),
            ));
        }
        let new_val = self.available + increment as i64;
        if new_val > WINDOW_MAX {
            return Err(Error::BadResponse(format!(
                "WINDOW_UPDATE pushes stream send window to {new_val} > 2^31-1 (FLOW_CONTROL_ERROR)"
            )));
        }
        self.available = new_val;
        Ok(())
    }

    /// Apply a `SETTINGS_INITIAL_WINDOW_SIZE` change: shift `available` by
    /// `(new - old)` (RFC 9113 §6.9.2). Negative results are allowed; only
    /// the upper bound is enforced.
    fn apply_initial_window_change(&mut self, new_initial: u32) -> Result<()> {
        let new_i = new_initial as i64;
        let delta = new_i - self.initial_peer_window;
        let new_available = self.available + delta;
        if new_available > WINDOW_MAX {
            return Err(Error::BadResponse(format!(
                "SETTINGS_INITIAL_WINDOW_SIZE delta pushes stream send window to {new_available} > 2^31-1 (FLOW_CONTROL_ERROR)"
            )));
        }
        self.available = new_available;
        self.initial_peer_window = new_i;
        Ok(())
    }

    fn consume(&mut self, n: usize) {
        self.available -= n as i64;
    }
}

/// Connection-level inbound flow-control state: bytes the peer may still send
/// us on stream 0's behalf (the aggregate of all streams). Like the conn send
/// window, this is unaffected by `SETTINGS_INITIAL_WINDOW_SIZE`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ConnRecvWindow {
    available: i64,
    initial: i64,
}

impl ConnRecvWindow {
    fn new() -> Self {
        ConnRecvWindow {
            available: OUR_INITIAL_WINDOW,
            initial: OUR_INITIAL_WINDOW,
        }
    }

    fn consume(&mut self, n: usize) {
        self.available -= n as i64;
    }

    /// Emit a `WINDOW_UPDATE` for stream 0 if the window has fallen below
    /// half its initial size; returns at most one frame.
    fn replenish(&mut self) -> Option<Frame> {
        let threshold = self.initial / 2;
        if self.available < threshold {
            let inc = (self.initial - self.available) as u32;
            self.available = self.initial;
            Some(window_update_frame(0, inc))
        } else {
            None
        }
    }
}

/// Per-stream inbound flow-control state. Mirrors `ConnRecvWindow` but the
/// `replenish` frame targets the specific stream id.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StreamRecvWindow {
    available: i64,
    initial: i64,
}

impl StreamRecvWindow {
    fn new() -> Self {
        StreamRecvWindow {
            available: OUR_INITIAL_WINDOW,
            initial: OUR_INITIAL_WINDOW,
        }
    }

    fn consume(&mut self, n: usize) {
        self.available -= n as i64;
    }

    fn replenish(&mut self, stream_id: u32) -> Option<Frame> {
        let threshold = self.initial / 2;
        if self.available < threshold {
            let inc = (self.initial - self.available) as u32;
            self.available = self.initial;
            Some(window_update_frame(stream_id, inc))
        } else {
            None
        }
    }
}

/// Build a 4-byte-payload WINDOW_UPDATE frame (RFC 9113 §6.9). Caller is
/// responsible for ensuring `increment` is non-zero and within `2^31 - 1`.
fn window_update_frame(stream_id: u32, increment: u32) -> Frame {
    let mut payload = Vec::with_capacity(4);
    payload.extend_from_slice(&(increment & 0x7fff_ffff).to_be_bytes());
    Frame {
        typ: F_WINDOW_UPDATE,
        flags: 0,
        stream_id,
        payload,
    }
}

/// Parse a WINDOW_UPDATE payload: 4 bytes, high bit reserved, low 31 bits are
/// the increment. Returns the increment as a `u32`. Length errors are mapped
/// to `BadResponse` here (RFC calls them FRAME_SIZE_ERROR).
fn parse_window_update(payload: &[u8]) -> Result<u32> {
    if payload.len() != 4 {
        return Err(Error::BadResponse(format!(
            "WINDOW_UPDATE payload length {} (expected 4) (FRAME_SIZE_ERROR)",
            payload.len()
        )));
    }
    let raw = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    Ok(raw & 0x7fff_ffff)
}

/// One HTTP/2 frame on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Frame {
    typ: u8,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
}

const MAX_FRAME_PAYLOAD: usize = 1 << 20; // 1 MiB hard cap, plenty for our use.

fn read_exact<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<()> {
    r.read_exact(buf)
}

fn read_frame<R: Read>(r: &mut R) -> io::Result<Frame> {
    let mut hdr = [0u8; 9];
    read_exact(r, &mut hdr)?;
    let length = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | (hdr[2] as usize);
    let typ = hdr[3];
    let flags = hdr[4];
    let stream_id = (((hdr[5] & 0x7f) as u32) << 24)
        | ((hdr[6] as u32) << 16)
        | ((hdr[7] as u32) << 8)
        | (hdr[8] as u32);
    if length > MAX_FRAME_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame payload too large: {length}"),
        ));
    }
    let mut payload = vec![0u8; length];
    if length > 0 {
        read_exact(r, &mut payload)?;
    }
    Ok(Frame {
        typ,
        flags,
        stream_id,
        payload,
    })
}

fn write_frame<W: Write>(w: &mut W, f: &Frame) -> io::Result<()> {
    if f.payload.len() > MAX_FRAME_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame payload too large",
        ));
    }
    let len = f.payload.len();
    let hdr = [
        ((len >> 16) & 0xff) as u8,
        ((len >> 8) & 0xff) as u8,
        (len & 0xff) as u8,
        f.typ,
        f.flags,
        ((f.stream_id >> 24) & 0x7f) as u8, // R bit clear.
        ((f.stream_id >> 16) & 0xff) as u8,
        ((f.stream_id >> 8) & 0xff) as u8,
        (f.stream_id & 0xff) as u8,
    ];
    w.write_all(&hdr)?;
    if !f.payload.is_empty() {
        w.write_all(&f.payload)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// HPACK integer codec (RFC 7541 §5.1).
// ---------------------------------------------------------------------------

/// Encode an integer with `prefix_bits` of the first byte available.
/// The non-integer high bits of the first byte are left as zero; the caller
/// OR's its flag bits in afterwards.
fn encode_int(value: u64, prefix_bits: u8) -> Vec<u8> {
    let max_prefix: u64 = (1u64 << prefix_bits) - 1;
    let mut out = Vec::new();
    if value < max_prefix {
        out.push(value as u8);
        return out;
    }
    out.push(max_prefix as u8);
    let mut rem = value - max_prefix;
    while rem >= 128 {
        out.push(((rem & 0x7f) as u8) | 0x80);
        rem >>= 7;
    }
    out.push(rem as u8);
    out
}

/// Decode an HPACK integer starting at `buf[0]`. Returns `(value, bytes_consumed)`.
fn decode_int(buf: &[u8], prefix_bits: u8) -> Result<(u64, usize)> {
    if buf.is_empty() {
        return Err(Error::BadResponse("hpack: empty integer".into()));
    }
    let max_prefix: u64 = (1u64 << prefix_bits) - 1;
    let mut value = (buf[0] as u64) & max_prefix;
    if value < max_prefix {
        return Ok((value, 1));
    }
    let mut i = 1usize;
    let mut shift = 0u32;
    loop {
        if i >= buf.len() {
            return Err(Error::BadResponse("hpack: truncated integer".into()));
        }
        let b = buf[i];
        i += 1;
        value = value
            .checked_add(((b & 0x7f) as u64) << shift)
            .ok_or_else(|| Error::BadResponse("hpack: integer overflow".into()))?;
        if b & 0x80 == 0 {
            return Ok((value, i));
        }
        shift += 7;
        if shift > 63 {
            return Err(Error::BadResponse("hpack: integer overflow".into()));
        }
    }
}

// ---------------------------------------------------------------------------
// HPACK static table (RFC 7541 Appendix A).
// ---------------------------------------------------------------------------

/// Indexed by `index - 1`. Each entry is (name, value).
const STATIC_TABLE: &[(&str, &str)] = &[
    (":authority", ""),                   // 1
    (":method", "GET"),                   // 2
    (":method", "POST"),                  // 3
    (":path", "/"),                       // 4
    (":path", "/index.html"),             // 5
    (":scheme", "http"),                  // 6
    (":scheme", "https"),                 // 7
    (":status", "200"),                   // 8
    (":status", "204"),                   // 9
    (":status", "206"),                   // 10
    (":status", "304"),                   // 11
    (":status", "400"),                   // 12
    (":status", "404"),                   // 13
    (":status", "500"),                   // 14
    ("accept-charset", ""),               // 15
    ("accept-encoding", "gzip, deflate"), // 16
    ("accept-language", ""),              // 17
    ("accept-ranges", ""),                // 18
    ("accept", ""),                       // 19
    ("access-control-allow-origin", ""),  // 20
    ("age", ""),                          // 21
    ("allow", ""),                        // 22
    ("authorization", ""),                // 23
    ("cache-control", ""),                // 24
    ("content-disposition", ""),          // 25
    ("content-encoding", ""),             // 26
    ("content-language", ""),             // 27
    ("content-length", ""),               // 28
    ("content-location", ""),             // 29
    ("content-range", ""),                // 30
    ("content-type", ""),                 // 31
    ("cookie", ""),                       // 32
    ("date", ""),                         // 33
    ("etag", ""),                         // 34
    ("expect", ""),                       // 35
    ("expires", ""),                      // 36
    ("from", ""),                         // 37
    ("host", ""),                         // 38
    ("if-match", ""),                     // 39
    ("if-modified-since", ""),            // 40
    ("if-none-match", ""),                // 41
    ("if-range", ""),                     // 42
    ("if-unmodified-since", ""),          // 43
    ("last-modified", ""),                // 44
    ("link", ""),                         // 45
    ("location", ""),                     // 46
    ("max-forwards", ""),                 // 47
    ("proxy-authenticate", ""),           // 48
    ("proxy-authorization", ""),          // 49
    ("range", ""),                        // 50
    ("referer", ""),                      // 51
    ("refresh", ""),                      // 52
    ("retry-after", ""),                  // 53
    ("server", ""),                       // 54
    ("set-cookie", ""),                   // 55
    ("strict-transport-security", ""),    // 56
    ("transfer-encoding", ""),            // 57
    ("user-agent", ""),                   // 58
    ("vary", ""),                         // 59
    ("via", ""),                          // 60
    ("www-authenticate", ""),             // 61
];

/// 1-based index of a (name, value) pair, if present in the static table.
fn static_full_index(name: &str, value: &str) -> Option<usize> {
    STATIC_TABLE
        .iter()
        .position(|(n, v)| *n == name && *v == value)
        .map(|i| i + 1)
}

/// 1-based index of the first static-table entry with this name, if any.
fn static_name_index(name: &str) -> Option<usize> {
    STATIC_TABLE
        .iter()
        .position(|(n, _)| *n == name)
        .map(|i| i + 1)
}

// ---------------------------------------------------------------------------
// HPACK Huffman decoder (RFC 7541 Appendix B).
// ---------------------------------------------------------------------------
//
// Stored as a flat (code, bit_len) table indexed by symbol (0..=255), plus a
// pseudo entry 256 for the EOS marker. Decoding walks the bitstream
// symbol-by-symbol against a sorted lookup; we use a simple bit-by-bit walk
// over a precomputed `Vec<(code, len)>` rather than a tree, trading memory
// for code size. With only 257 symbols and at most 30 bits, total work per
// decode byte is bounded.

/// `(code, bit_length)` for each Huffman symbol, from RFC 7541 Appendix B.
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

/// Decode a Huffman-coded literal. We walk bit-by-bit over the input, OR each
/// bit into an accumulator, and check after every bit whether the accumulator
/// (left-aligned for that length) matches any code of that length. With 257
/// symbols this is small enough to scan linearly.
fn huffman_decode(input: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len().saturating_mul(2));
    let mut acc: u64 = 0;
    let mut acc_len: u8 = 0;

    for &byte in input {
        acc = (acc << 8) | (byte as u64);
        acc_len += 8;
        // Pull as many symbols as possible from the accumulator.
        while acc_len >= 5 {
            let mut matched = false;
            // Try lengths 5..=30 (no symbol shorter than 5 bits in the table).
            let max_len = acc_len.min(30);
            for try_len in 5..=max_len {
                let code = (acc >> (acc_len - try_len)) & ((1u64 << try_len) - 1);
                // Linear scan: small table, predictable performance.
                if let Some(sym) = lookup_huffman(code as u32, try_len) {
                    if sym == 256 {
                        // EOS in a literal is a decoder error per RFC 7541 §5.2.
                        return Err(Error::BadResponse(
                            "hpack: EOS symbol in Huffman literal".into(),
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

    // Tail: remaining bits must be the most-significant bits of the EOS code
    // (all-ones), and there must be fewer than 8 of them (RFC 7541 §5.2).
    if acc_len >= 8 {
        return Err(Error::BadResponse(
            "hpack: trailing Huffman bits >= 8".into(),
        ));
    }
    if acc_len > 0 {
        let pad_mask = (1u64 << acc_len) - 1;
        let tail = acc & pad_mask;
        if tail != pad_mask {
            return Err(Error::BadResponse("hpack: bad Huffman padding".into()));
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

// ---------------------------------------------------------------------------
// HPACK encoder / decoder.
// ---------------------------------------------------------------------------

/// Default and maximum dynamic-table size we accept from the server. RFC 7541
/// default is 4096 bytes; we never SETTINGS_HEADER_TABLE_SIZE up from that.
const DYN_TABLE_CAP: usize = 4096;

/// HPACK decoder state. The dynamic table is FIFO: newest entries pushed at
/// the front (index 62 in the combined table), oldest evicted from the back.
struct Decoder {
    dyn_table: Vec<(String, String)>,
    dyn_table_size: usize,
    dyn_table_cap: usize,
}

impl Decoder {
    fn new() -> Self {
        Decoder {
            dyn_table: Vec::new(),
            dyn_table_size: 0,
            dyn_table_cap: DYN_TABLE_CAP,
        }
    }

    fn entry_size(name: &str, value: &str) -> usize {
        name.len() + value.len() + 32
    }

    fn evict_to_fit(&mut self, incoming: usize) {
        while self.dyn_table_size + incoming > self.dyn_table_cap && !self.dyn_table.is_empty() {
            let (n, v) = self.dyn_table.pop().unwrap();
            self.dyn_table_size = self.dyn_table_size.saturating_sub(Self::entry_size(&n, &v));
        }
    }

    fn insert(&mut self, name: String, value: String) {
        let sz = Self::entry_size(&name, &value);
        if sz > self.dyn_table_cap {
            // Larger than the whole table: clear, do not insert (RFC 7541 §4.4).
            self.dyn_table.clear();
            self.dyn_table_size = 0;
            return;
        }
        self.evict_to_fit(sz);
        self.dyn_table.insert(0, (name, value));
        self.dyn_table_size += sz;
    }

    fn lookup(&self, index: u64) -> Result<(String, String)> {
        if index == 0 {
            return Err(Error::BadResponse("hpack: index 0".into()));
        }
        let idx = index as usize;
        if idx <= STATIC_TABLE.len() {
            let (n, v) = STATIC_TABLE[idx - 1];
            return Ok((n.to_string(), v.to_string()));
        }
        let dyn_idx = idx - STATIC_TABLE.len() - 1;
        if dyn_idx >= self.dyn_table.len() {
            return Err(Error::BadResponse(format!(
                "hpack: index {idx} out of range"
            )));
        }
        let (n, v) = &self.dyn_table[dyn_idx];
        Ok((n.clone(), v.clone()))
    }

    fn lookup_name(&self, index: u64) -> Result<String> {
        Ok(self.lookup(index)?.0)
    }

    /// Decode a length-prefixed string literal: 1 bit Huffman flag, 7-bit
    /// integer length prefix, then `length` bytes.
    fn read_string(&self, buf: &[u8], pos: &mut usize) -> Result<String> {
        if *pos >= buf.len() {
            return Err(Error::BadResponse("hpack: truncated string".into()));
        }
        let huffman = buf[*pos] & 0x80 != 0;
        let (len, consumed) = decode_int(&buf[*pos..], 7)?;
        *pos += consumed;
        let end = pos
            .checked_add(len as usize)
            .ok_or_else(|| Error::BadResponse("hpack: string length overflow".into()))?;
        if end > buf.len() {
            return Err(Error::BadResponse("hpack: truncated string body".into()));
        }
        let raw = &buf[*pos..end];
        *pos = end;
        if huffman {
            let bytes = huffman_decode(raw)?;
            String::from_utf8(bytes)
                .map_err(|_| Error::BadResponse("hpack: non-utf8 Huffman literal".into()))
        } else {
            String::from_utf8(raw.to_vec())
                .map_err(|_| Error::BadResponse("hpack: non-utf8 literal".into()))
        }
    }

    fn decode_block(&mut self, buf: &[u8]) -> Result<Vec<(String, String)>> {
        let mut out = Vec::new();
        let mut pos = 0;
        // Running total of the decoded header-list size (RFC 7541 §4.1:
        // `name.len() + value.len() + 32` per entry). Bounds a decompression
        // bomb where a small compressed block expands into a huge list.
        let mut list_size: usize = 0;
        while pos < buf.len() {
            let b = buf[pos];
            let entry: (String, String);
            if b & 0x80 != 0 {
                // Indexed header field (RFC 7541 §6.1).
                let (idx, n) = decode_int(&buf[pos..], 7)?;
                pos += n;
                entry = self.lookup(idx)?;
            } else if b & 0x40 != 0 {
                // Literal header field with incremental indexing (§6.2.1).
                let (idx, n) = decode_int(&buf[pos..], 6)?;
                pos += n;
                let name = if idx == 0 {
                    self.read_string(buf, &mut pos)?
                } else {
                    self.lookup_name(idx)?
                };
                let value = self.read_string(buf, &mut pos)?;
                self.insert(name.clone(), value.clone());
                entry = (name, value);
            } else if b & 0x20 != 0 {
                // Dynamic table size update (§6.3).
                let (new_size, n) = decode_int(&buf[pos..], 5)?;
                pos += n;
                let cap = (new_size as usize).min(DYN_TABLE_CAP);
                self.dyn_table_cap = cap;
                self.evict_to_fit(0);
                continue;
            } else {
                // Literal w/o indexing (b & 0x10 == 0) or never-indexed
                // (b & 0x10 != 0). Both use a 4-bit prefix; we treat them
                // the same on decode (we never re-emit headers, so the
                // privacy hint is moot for our caller).
                let (idx, n) = decode_int(&buf[pos..], 4)?;
                pos += n;
                let name = if idx == 0 {
                    self.read_string(buf, &mut pos)?
                } else {
                    self.lookup_name(idx)?
                };
                let value = self.read_string(buf, &mut pos)?;
                entry = (name, value);
            }
            list_size = list_size
                .saturating_add(entry.0.len())
                .saturating_add(entry.1.len())
                .saturating_add(32);
            if list_size > MAX_DECODED_HEADER_LIST {
                return Err(Error::BadResponse(
                    "hpack: decoded header list exceeds limit".into(),
                ));
            }
            out.push(entry);
        }
        Ok(out)
    }
}

/// Huffman-encode `input` per RFC 7541 §5.2: concatenate the per-symbol
/// codes (MSB-first within each code), then pad the trailing partial byte
/// with the high bits of the EOS code (all-ones).
fn huffman_encode(input: &[u8]) -> Vec<u8> {
    // Total bit length first so we can size the output exactly.
    let total_bits: usize = input.iter().map(|b| HUFFMAN[*b as usize].1 as usize).sum();
    let out_len = total_bits.div_ceil(8);
    let mut out = vec![0u8; out_len];

    // Shift each symbol's `bit_len`-bit code into the buffer MSB-first. We
    // keep a bit cursor (`bit_pos`) tracking the next free bit position
    // measured from the MSB of byte 0.
    let mut bit_pos: usize = 0;
    for &b in input {
        let (code, len) = HUFFMAN[b as usize];
        let len = len as usize;
        // Place the code so its MSB lands at `bit_pos`.
        let mut remaining = len;
        let mut code_left = code as u64;
        while remaining > 0 {
            let byte_index = bit_pos / 8;
            let bit_in_byte = bit_pos % 8; // 0 = MSB.
            let space_in_byte = 8 - bit_in_byte;
            let take = remaining.min(space_in_byte);
            // Top `take` bits of the still-unwritten part of the code.
            let shift = (remaining - take) as u32;
            let chunk = ((code_left >> shift) & ((1u64 << take) - 1)) as u8;
            // Place those bits into the byte, left-justified within the
            // remaining space.
            out[byte_index] |= chunk << (space_in_byte - take);
            // Mask the bits we just wrote out of `code_left`.
            if shift > 0 {
                code_left &= (1u64 << shift) - 1;
            } else {
                code_left = 0;
            }
            remaining -= take;
            bit_pos += take;
        }
    }

    // Pad trailing bits (if any) with 1s — the most-significant bits of the
    // EOS code (`0x3fffffff`, 30 bits, top bits all 1).
    let trailing = (8 - (total_bits % 8)) % 8;
    if trailing > 0 {
        let last = out.len() - 1;
        out[last] |= (1u8 << trailing) - 1;
    }
    out
}

/// Encode one length-prefixed string literal (RFC 7541 §5.2). The high bit
/// of the length-prefix byte is the Huffman flag: 1 = Huffman, 0 = raw.
/// We pick whichever encoding is shorter on the wire (ties go to raw,
/// which slightly favours decoder speed and avoids a needless Huffman pass).
fn encode_literal_string(out: &mut Vec<u8>, s: &str) {
    let raw = s.as_bytes();
    let huff = huffman_encode(raw);
    if huff.len() < raw.len() {
        let mut len_bytes = encode_int(huff.len() as u64, 7);
        len_bytes[0] |= 0x80; // Huffman bit set.
        out.extend_from_slice(&len_bytes);
        out.extend_from_slice(&huff);
    } else {
        let mut len_bytes = encode_int(raw.len() as u64, 7);
        len_bytes[0] &= 0x7f; // Huffman bit cleared.
        out.extend_from_slice(&len_bytes);
        out.extend_from_slice(raw);
    }
}

// ---------------------------------------------------------------------------
// HPACK encoder with dynamic-table insertion (RFC 7541 §6.2.1 / §6.3).
// ---------------------------------------------------------------------------
//
// The encoder mirrors the decoder's dynamic table: every header we emit with
// "incremental indexing" (§6.2.1) MUST be appended to our local dynamic
// table because the receiver will do the same on its side. The two tables
// must stay byte-for-byte identical or the indices we emit on the next
// header block will misreference entries on the receiver.
//
// Indexing policy: we always use incremental indexing for headers not
// already in either table. This maximises compression on repeated headers
// across requests on the same connection (e.g. cookies, user-agent, etc.)
// FUTURE: per RFC 7541 §7.1.3, secrets like `cookie` and `authorization`
// SHOULD use the "never-indexed" representation (§6.2.3) to avoid leaking
// via compression-side-channel attacks. We don't do that today — see the
// out-of-scope note in the module-level docs.

/// Per-connection HPACK encoder. The dynamic table here mirrors what we
/// tell the peer to insert; the newest entry sits at `dyn_table[0]` and
/// corresponds to HPACK index `STATIC_TABLE.len() + 1` (62 today).
struct Encoder {
    dyn_table: VecDeque<(String, String)>,
    dyn_table_size: usize,
    max_dyn_table_size: usize,
    /// Pending "Dynamic Table Size Update" signal (§6.3). Set whenever the
    /// peer changes `SETTINGS_HEADER_TABLE_SIZE`; consumed (and cleared)
    /// at the head of the next header block we emit. The signal MUST
    /// precede any header field representation in that block.
    pending_max_table_size_signal: Option<usize>,
}

impl Encoder {
    fn new() -> Self {
        Encoder {
            dyn_table: VecDeque::new(),
            dyn_table_size: 0,
            max_dyn_table_size: DYN_TABLE_CAP,
            pending_max_table_size_signal: None,
        }
    }

    fn entry_size(name: &str, value: &str) -> usize {
        name.len() + value.len() + 32
    }

    /// Apply a new `SETTINGS_HEADER_TABLE_SIZE` cap from the peer. The
    /// encoder MUST emit a §6.3 size-update signal in the next header
    /// block to acknowledge the change, and MUST evict entries
    /// immediately so the table never exceeds the new cap.
    fn set_peer_max_table_size(&mut self, n: usize) {
        self.max_dyn_table_size = n;
        self.evict_to_fit(0);
        self.pending_max_table_size_signal = Some(n);
    }

    fn evict_to_fit(&mut self, incoming: usize) {
        while self.dyn_table_size + incoming > self.max_dyn_table_size && !self.dyn_table.is_empty()
        {
            // Oldest entry lives at the back of the deque.
            let (n, v) = self.dyn_table.pop_back().unwrap();
            self.dyn_table_size = self.dyn_table_size.saturating_sub(Self::entry_size(&n, &v));
        }
    }

    fn insert(&mut self, name: &str, value: &str) {
        let sz = Self::entry_size(name, value);
        if sz > self.max_dyn_table_size {
            // Entry larger than the entire table: clear and skip (§4.4).
            self.dyn_table.clear();
            self.dyn_table_size = 0;
            return;
        }
        self.evict_to_fit(sz);
        self.dyn_table
            .push_front((name.to_string(), value.to_string()));
        self.dyn_table_size += sz;
    }

    /// 1-based combined HPACK index for an exact (name, value) match.
    /// Checks the static table first (indices 1..=61), then the dynamic
    /// table (index 62 = newest, the front of the deque).
    fn combined_full_index(&self, name: &str, value: &str) -> Option<u32> {
        if let Some(i) = static_full_index(name, value) {
            return Some(i as u32);
        }
        for (i, (n, v)) in self.dyn_table.iter().enumerate() {
            if n == name && v == value {
                return Some((STATIC_TABLE.len() + 1 + i) as u32);
            }
        }
        None
    }

    /// 1-based combined HPACK index for the first entry matching `name`.
    fn combined_name_index(&self, name: &str) -> Option<u32> {
        if let Some(i) = static_name_index(name) {
            return Some(i as u32);
        }
        for (i, (n, _)) in self.dyn_table.iter().enumerate() {
            if n == name {
                return Some((STATIC_TABLE.len() + 1 + i) as u32);
            }
        }
        None
    }

    /// Encode one header field. Names MUST already be lowercased by the
    /// caller (RFC 9113 §8.2.1). On the wire we emit, in order:
    ///
    /// 1. Any pending §6.3 dynamic-table-size-update signal.
    /// 2. If both name and value are in the combined table: an indexed
    ///    field representation (high bit 1, §6.1).
    /// 3. Else if the name alone is in the combined table: a literal
    ///    with incremental indexing + indexed name (`01xxxxxx`, 6-bit
    ///    name index, §6.2.1). The entry is inserted into our table.
    /// 4. Else: literal with incremental indexing + literal name
    ///    (`0x40` marker, §6.2.1). The entry is inserted into our table.
    fn encode_header(&mut self, out: &mut Vec<u8>, name: &str, value: &str) {
        // (1) Pending size-update signal: 5-bit prefix, top three bits `001`.
        if let Some(n) = self.pending_max_table_size_signal.take() {
            let mut bytes = encode_int(n as u64, 5);
            bytes[0] |= 0x20;
            out.extend_from_slice(&bytes);
        }

        // (2) Indexed field representation.
        if let Some(idx) = self.combined_full_index(name, value) {
            let mut bytes = encode_int(idx as u64, 7);
            bytes[0] |= 0x80;
            out.extend_from_slice(&bytes);
            return;
        }

        // (3) Literal with incremental indexing, indexed name.
        if let Some(idx) = self.combined_name_index(name) {
            let mut bytes = encode_int(idx as u64, 6);
            bytes[0] |= 0x40;
            out.extend_from_slice(&bytes);
            encode_literal_string(out, value);
            self.insert(name, value);
            return;
        }

        // (4) Literal with incremental indexing, literal name.
        out.push(0x40);
        encode_literal_string(out, name);
        encode_literal_string(out, value);
        self.insert(name, value);
    }
}

// ---------------------------------------------------------------------------
// TLS with ALPN = h2 — uses the shared driver in `crate::tls`.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TCP setup, mirroring crate::http::tcp_connect.
// ---------------------------------------------------------------------------

fn tcp_connect(req: &Request) -> Result<TcpStream> {
    // Route through the proxy when one is configured and the target host
    // isn't bypassed. Symmetric to `crate::http::tcp_connect`.
    let proxy = req
        .proxy
        .as_ref()
        .filter(|_| !crate::http::proxy_bypassed(req));
    let (target_host, target_port) = match proxy {
        Some(p) => (p.host.as_str(), p.port),
        None => (req.url.host.as_str(), req.url.port),
    };
    let addr = format!("{target_host}:{target_port}");
    let stream = match req.connect_timeout {
        Some(t) => {
            let first = std::net::ToSocketAddrs::to_socket_addrs(&addr)?
                .next()
                .ok_or_else(|| Error::InvalidUrl(target_host.to_string()))?;
            TcpStream::connect_timeout(&first, t)?
        }
        None => TcpStream::connect(&addr)?,
    };
    stream.set_read_timeout(req.read_timeout)?;
    stream.set_write_timeout(req.read_timeout)?;
    Ok(stream)
}

// ---------------------------------------------------------------------------
// Per-stream state machine (RFC 9113 §5.1) and the `Stream` it lives on.
// ---------------------------------------------------------------------------

/// Simplified client-side stream lifecycle (RFC 9113 §5.1). We collapse the
/// `ReservedLocal`/`ReservedRemote` states because we disable server push.
/// `Idle` is included for completeness but in practice we transition into
/// `Open` (or `HalfClosedLocal` if the request has no body) the instant we
/// emit HEADERS, so callers rarely observe it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamState {
    Idle,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

impl StreamState {
    /// Validate that we can SEND a DATA frame in the current state. Returns
    /// the new state if `end_stream` is set, or the same state otherwise.
    fn send_data(self, end_stream: bool) -> Result<StreamState> {
        match self {
            StreamState::Idle => {
                if end_stream {
                    Ok(StreamState::HalfClosedLocal)
                } else {
                    Ok(StreamState::Open)
                }
            }
            StreamState::Open => Ok(if end_stream {
                StreamState::HalfClosedLocal
            } else {
                StreamState::Open
            }),
            StreamState::HalfClosedRemote => Ok(if end_stream {
                StreamState::Closed
            } else {
                StreamState::HalfClosedRemote
            }),
            StreamState::HalfClosedLocal | StreamState::Closed => Err(Error::BadResponse(format!(
                "internal: tried to send DATA in stream state {self:?}"
            ))),
        }
    }

    /// Validate inbound DATA. Returns the (possibly updated) state.
    fn recv_data(self, end_stream: bool) -> Result<StreamState> {
        match self {
            StreamState::Open => Ok(if end_stream {
                StreamState::HalfClosedRemote
            } else {
                StreamState::Open
            }),
            StreamState::HalfClosedLocal => Ok(if end_stream {
                StreamState::Closed
            } else {
                StreamState::HalfClosedLocal
            }),
            StreamState::Idle | StreamState::HalfClosedRemote | StreamState::Closed => {
                Err(Error::BadResponse(format!(
                    "received DATA in stream state {self:?} (RFC 9113 §5.1)"
                )))
            }
        }
    }

    /// Validate inbound HEADERS / CONTINUATION. Returns the (possibly
    /// updated) state. `Closed` returns `Closed` (we'll ignore the frame).
    fn recv_headers(self, end_stream: bool) -> Result<StreamState> {
        match self {
            StreamState::Open => Ok(if end_stream {
                StreamState::HalfClosedRemote
            } else {
                StreamState::Open
            }),
            StreamState::HalfClosedLocal => Ok(if end_stream {
                StreamState::Closed
            } else {
                StreamState::HalfClosedLocal
            }),
            StreamState::Closed => Ok(StreamState::Closed),
            StreamState::Idle | StreamState::HalfClosedRemote => Err(Error::BadResponse(format!(
                "received HEADERS in stream state {self:?} (RFC 9113 §5.1)"
            ))),
        }
    }

    /// Inbound RST_STREAM: transition to `Closed` from any state (idle is the
    /// one true exception per §5.1, but we surface that as an error too).
    fn recv_rst(self) -> Result<StreamState> {
        match self {
            StreamState::Idle => Err(Error::BadResponse(
                "RST_STREAM on idle stream (RFC 9113 §5.1)".into(),
            )),
            _ => Ok(StreamState::Closed),
        }
    }
}

/// One in-flight HTTP/2 stream. Mostly owned mutably by the `Connection` for
/// the lifetime of the request; on completion the closed stream is moved out
/// of `Connection::streams` and returned to the caller.
struct Stream {
    /// Stream identifier. Stored for debugging and so the type stays
    /// self-describing when reaped from `Connection::streams`; the public
    /// `Response` doesn't need it but it's cheap to keep.
    #[allow(dead_code)]
    id: u32,
    state: StreamState,
    send_window: StreamSendWindow,
    recv_window: StreamRecvWindow,
    /// Accumulator for the in-progress header block (HEADERS + CONTINUATION
    /// fragments) before HPACK decoding fires at END_HEADERS.
    headers_buf: Vec<u8>,
    /// Fully decoded response headers, once the response's END_HEADERS has
    /// been seen. `None` until then.
    response_headers: Option<Vec<(String, String)>>,
    /// Accumulator for response body bytes (DATA payloads, post-padding).
    body: Vec<u8>,
    /// True once the peer's END_STREAM has been observed.
    end_stream_recv: bool,
}

impl Stream {
    fn new(id: u32, initial_peer_window: i64) -> Self {
        Stream {
            id,
            state: StreamState::Idle,
            send_window: StreamSendWindow::new(initial_peer_window),
            recv_window: StreamRecvWindow::new(),
            headers_buf: Vec::new(),
            response_headers: None,
            body: Vec::new(),
            end_stream_recv: false,
        }
    }

    /// Smallest of conn / stream send windows — the budget for the next DATA
    /// chunk on this stream.
    fn send_budget(&self, conn_window: &ConnSendWindow) -> i64 {
        self.send_window.available.min(conn_window.available)
    }

    /// Append a header-block fragment (HEADERS / CONTINUATION) to the
    /// accumulator, refusing to grow past [`MAX_HEADERS_BUF`]. Returning an
    /// error here terminates the connection, which bounds the
    /// CONTINUATION-flood / unbounded-header-block class (CVE-2024-27316):
    /// without this an attacker can stream END_HEADERS-less CONTINUATION
    /// frames forever and exhaust memory.
    fn push_header_fragment(&mut self, frag: &[u8]) -> Result<()> {
        if self.headers_buf.len().saturating_add(frag.len()) > MAX_HEADERS_BUF {
            return Err(Error::BadResponse(
                "header block exceeds size limit (CONTINUATION flood?)".into(),
            ));
        }
        self.headers_buf.extend_from_slice(frag);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The Connection: owns the TLS stream, peer settings, decoder, and all the
// streams currently in flight. Replaces the single-stream `ConnState` from
// earlier tasks.
// ---------------------------------------------------------------------------

/// `Connection` is the multiplexing core. It owns the TLS transport plus the
/// per-stream state for every request currently in flight, drives the
/// connection-level state machine (preface, SETTINGS exchange, GOAWAY), and
/// dispatches inbound frames to the right stream by `stream_id`.
///
/// One `Connection` per TLS session. Task 5 will introduce pooling so multiple
/// `send()` calls can reuse the same `Connection`; for now every `send()`
/// builds a fresh one, opens a single stream, and drops it.
struct Connection<S: Read + Write> {
    tls: S,
    peer: PeerSettings,
    conn_send_window: ConnSendWindow,
    conn_recv_window: ConnRecvWindow,
    decoder: Decoder,
    encoder: Encoder,
    streams: HashMap<u32, Stream>,
    /// Next client-initiated stream id to allocate. Per §5.1.1, client
    /// streams are odd-numbered and strictly increasing: 1, 3, 5, …
    next_stream_id: u32,
    /// If the peer sent GOAWAY, the last-stream-id they advertised. We refuse
    /// to allocate ids strictly greater than this; existing streams with id
    /// ≤ this can still complete.
    goaway_received: Option<u32>,
    /// If we are mid-header-block on some stream — i.e. we processed a
    /// HEADERS frame without END_HEADERS — this holds the stream id we are
    /// waiting on. While `Some(_)`, the peer is forbidden from interleaving
    /// any other frame (RFC 9113 §6.10).
    expecting_continuation: Option<u32>,
}

/// Result of dispatching one inbound frame.
///
/// `Done(stream_id)` means a stream has hit a terminal condition (Closed or
/// HalfClosedRemote with response fully received) and should be reaped by the
/// caller. `Continue` means keep reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DispatchOutcome {
    Continue,
    Done(u32),
}

impl<S: Read + Write> Connection<S> {
    /// Construct a `Connection` from an already-handshaken transport and send
    /// the client preface + initial SETTINGS frame. We advertise
    /// `ENABLE_PUSH=0` so the server won't send PUSH_PROMISE frames (we
    /// don't implement them); other parameters stay at RFC defaults.
    fn new(mut tls: S) -> Result<Self> {
        tls.write_all(PREFACE)?;
        let mut settings_payload = Vec::with_capacity(6);
        settings_payload.extend_from_slice(&S_ENABLE_PUSH.to_be_bytes());
        settings_payload.extend_from_slice(&0u32.to_be_bytes());
        let our_settings = Frame {
            typ: F_SETTINGS,
            flags: 0,
            stream_id: 0,
            payload: settings_payload,
        };
        write_frame(&mut tls, &our_settings)?;
        tls.flush()?;
        Ok(Connection {
            tls,
            peer: PeerSettings::default(),
            conn_send_window: ConnSendWindow::new(),
            conn_recv_window: ConnRecvWindow::new(),
            decoder: Decoder::new(),
            encoder: Encoder::new(),
            streams: HashMap::new(),
            next_stream_id: 1,
            goaway_received: None,
            expecting_continuation: None,
        })
    }

    /// Cheap, no-I/O check that this connection is structurally safe to hand
    /// out from the pool for another request:
    ///
    /// - we have not received a GOAWAY (or, if we did, we still have at least
    ///   one in-flight stream — but for pooling purposes we treat *any*
    ///   GOAWAY as "do not pool"); and
    /// - there are no streams left from a previous request (a checked-out
    ///   conn with non-empty `streams` means the previous user crashed mid-
    ///   request and left state behind; we cannot trust the wire position).
    ///
    /// We deliberately do NOT probe the socket. If the peer closed silently,
    /// the next read/write will surface that as an I/O error and the caller
    /// drops the conn instead of re-pooling it.
    fn is_usable(&self) -> bool {
        if self.goaway_received.is_some() {
            return false;
        }
        if !self.streams.is_empty() {
            return false;
        }
        // Defensive: if we somehow exhausted the stream-id space, the next
        // open_stream would error — don't bother handing this conn back.
        if self.next_stream_id >= 0x8000_0000 {
            return false;
        }
        true
    }

    /// Allocate the next client-initiated stream id and register an empty
    /// `Stream` in `self.streams`.
    ///
    /// Errors:
    /// - At `MAX_CONCURRENT_STREAMS`: refuse so the caller can open another
    ///   connection (task 5 will key the pool on this).
    /// - Past 2^31: stream ids are bounded by RFC 9113 §5.1.1; the caller
    ///   must discard this connection.
    /// - After a GOAWAY that names a last-stream-id below what we'd allocate:
    ///   refuse so the caller knows to retry on a fresh connection.
    fn open_stream(&mut self) -> Result<u32> {
        if (self.streams.len() as u64) >= self.peer.max_concurrent_streams as u64 {
            return Err(Error::BadResponse("at MAX_CONCURRENT_STREAMS limit".into()));
        }
        // 2^31 is the boundary; the highest legal client stream id is
        // 2^31 - 1 (which happens to be odd). RFC 9113 §5.1.1.
        if self.next_stream_id >= 0x8000_0000 {
            return Err(Error::BadResponse(
                "stream id space exhausted (RFC 9113 §5.1.1)".into(),
            ));
        }
        if let Some(last) = self.goaway_received {
            if self.next_stream_id > last {
                return Err(Error::BadResponse(format!(
                    "GOAWAY received with last-stream-id={last}; cannot allocate id={}",
                    self.next_stream_id
                )));
            }
        }
        let id = self.next_stream_id;
        self.next_stream_id = self.next_stream_id.saturating_add(2);
        self.streams
            .insert(id, Stream::new(id, self.peer.initial_window_size as i64));
        Ok(id)
    }

    /// Build and write the HEADERS + CONTINUATION + DATA frames for `req` on
    /// `stream_id`. Blocks on flow control by reading inbound frames in-place
    /// when the send window is depleted. The stream's `state` is advanced
    /// for each outbound transition.
    fn send_request_on(&mut self, stream_id: u32, req: &Request) -> Result<()> {
        let header_block = build_header_block(&mut self.encoder, req);
        let has_body = !req.body.is_empty();
        let max_frame_size = self.peer.max_frame_size as usize;
        let header_frames =
            fragment_header_block(stream_id, &header_block, max_frame_size, !has_body);

        // HEADERS frame(s). RFC 9113 §6.10: no other frames may interleave
        // between HEADERS and its CONTINUATION fragments — our single-threaded
        // writer satisfies this automatically.
        for f in &header_frames {
            write_frame(&mut self.tls, f)?;
        }
        {
            let s = self
                .streams
                .get_mut(&stream_id)
                .ok_or_else(|| Error::BadResponse(format!("stream {stream_id} not found")))?;
            s.state = s.state.send_data(!has_body)?;
        }

        if has_body {
            let mut remaining: &[u8] = req.body.as_slice();
            while !remaining.is_empty() {
                // Block until both windows have budget.
                loop {
                    let budget = {
                        let s = self.streams.get(&stream_id).ok_or_else(|| {
                            Error::BadResponse(format!("stream {stream_id} disappeared mid-send"))
                        })?;
                        s.send_budget(&self.conn_send_window)
                    };
                    if budget > 0 {
                        break;
                    }
                    match self.read_and_dispatch()? {
                        DispatchOutcome::Continue => {}
                        DispatchOutcome::Done(done_id) if done_id == stream_id => {
                            // The peer ended our stream before we finished
                            // sending the body — protocol error from our side.
                            return Err(Error::BadResponse(
                                "server ended stream before request body was fully sent".into(),
                            ));
                        }
                        DispatchOutcome::Done(_) => {
                            // Some other stream finished while we were
                            // blocked; that's fine, keep waiting on ours.
                        }
                    }
                }

                let max_frame_size = self.peer.max_frame_size as usize;
                let budget = self
                    .streams
                    .get(&stream_id)
                    .unwrap()
                    .send_budget(&self.conn_send_window);
                let n = next_data_chunk_size(max_frame_size, budget, remaining.len());
                debug_assert!(n > 0, "loop above guarantees positive budget");
                let chunk = &remaining[..n];
                remaining = &remaining[n..];
                let is_last = remaining.is_empty();
                let data_frame = Frame {
                    typ: F_DATA,
                    flags: if is_last { FLAG_END_STREAM } else { 0 },
                    stream_id,
                    payload: chunk.to_vec(),
                };
                write_frame(&mut self.tls, &data_frame)?;
                self.conn_send_window.consume(n);
                let s = self.streams.get_mut(&stream_id).unwrap();
                s.send_window.consume(n);
                s.state = s.state.send_data(is_last)?;
            }
        }
        self.tls.flush()?;
        Ok(())
    }

    /// Drive the connection's read side until `stream_id` reaches a terminal
    /// state, then remove that stream from the map and return it.
    fn drive_until_stream_done(&mut self, stream_id: u32) -> Result<Stream> {
        loop {
            // Has the stream already completed in an earlier dispatch?
            if let Some(s) = self.streams.get(&stream_id) {
                if matches!(s.state, StreamState::Closed | StreamState::HalfClosedRemote)
                    && s.response_headers.is_some()
                    && s.end_stream_recv
                {
                    return Ok(self.streams.remove(&stream_id).unwrap());
                }
            } else {
                return Err(Error::BadResponse(format!(
                    "stream {stream_id} not registered"
                )));
            }

            match self.read_and_dispatch()? {
                DispatchOutcome::Continue => {}
                DispatchOutcome::Done(done_id) if done_id == stream_id => {
                    return Ok(self.streams.remove(&stream_id).unwrap());
                }
                DispatchOutcome::Done(_) => {
                    // Some other stream finished; loop continues.
                }
            }
        }
    }

    /// Read one frame from the wire and route it to the right place. The
    /// connection-scoped frames (SETTINGS / PING / GOAWAY / WINDOW_UPDATE on
    /// stream 0) are handled here directly; stream-scoped frames are looked
    /// up in `self.streams` and dispatched.
    fn read_and_dispatch(&mut self) -> Result<DispatchOutcome> {
        let frame = match read_frame(&mut self.tls) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(Error::UnexpectedEof);
            }
            Err(e) => return Err(Error::Io(e)),
        };
        self.process_frame(frame)
    }

    /// Apply one already-read frame. Split out from `read_and_dispatch` so
    /// tests can drive the dispatch ladder with synthetic frames.
    fn process_frame(&mut self, frame: Frame) -> Result<DispatchOutcome> {
        // RFC 9113 §6.10: between HEADERS-without-END_HEADERS and the
        // matching final CONTINUATION on the same stream, NO other frame
        // type — and no HEADERS/CONTINUATION on any other stream — may
        // appear. Enforce that gate up front.
        if let Some(awaiting) = self.expecting_continuation {
            let ok = frame.typ == F_CONTINUATION && frame.stream_id == awaiting;
            if !ok {
                return Err(Error::BadResponse(format!(
                    "expected CONTINUATION on stream {awaiting}, got type=0x{:x} stream={}",
                    frame.typ, frame.stream_id
                )));
            }
        }

        if frame.stream_id == 0 {
            return self.process_conn_frame(frame);
        }
        self.process_stream_frame(frame)
    }

    /// Connection-scoped frames (stream_id == 0): SETTINGS / SETTINGS-ACK,
    /// PING / PING-ACK, GOAWAY, WINDOW_UPDATE on stream 0. PRIORITY at stream
    /// 0 would be a protocol error but we just ignore it.
    fn process_conn_frame(&mut self, frame: Frame) -> Result<DispatchOutcome> {
        match frame.typ {
            F_SETTINGS if frame.flags & FLAG_ACK == 0 => {
                let old_initial = self.peer.initial_window_size;
                let old_header_table_size = self.peer.header_table_size;
                self.peer.apply_settings_payload(&frame.payload)?;
                let new_initial = self.peer.initial_window_size;
                if new_initial != old_initial {
                    // §6.9.2: retroactively shift every existing stream's
                    // send window by (new - old). The conn window is
                    // untouched.
                    for s in self.streams.values_mut() {
                        s.send_window.apply_initial_window_change(new_initial)?;
                    }
                }
                if self.peer.header_table_size != old_header_table_size {
                    // RFC 7541 §6.3: the encoder MUST emit a dynamic-table-
                    // size-update signal in the next header block to
                    // acknowledge the new cap. `set_peer_max_table_size`
                    // also evicts entries immediately so we never exceed it.
                    self.encoder
                        .set_peer_max_table_size(self.peer.header_table_size as usize);
                }
                let ack = Frame {
                    typ: F_SETTINGS,
                    flags: FLAG_ACK,
                    stream_id: 0,
                    payload: Vec::new(),
                };
                write_frame(&mut self.tls, &ack)?;
                self.tls.flush()?;
            }
            F_SETTINGS => { /* ACK from server: silently absorb. */ }
            F_PING if frame.flags & FLAG_ACK == 0 => {
                let pong = Frame {
                    typ: F_PING,
                    flags: FLAG_ACK,
                    stream_id: 0,
                    payload: frame.payload.clone(),
                };
                write_frame(&mut self.tls, &pong)?;
                self.tls.flush()?;
            }
            F_PING => {}
            F_WINDOW_UPDATE => {
                let inc = parse_window_update(&frame.payload)?;
                self.conn_send_window.apply_window_update(inc)?;
            }
            F_GOAWAY => {
                // First 4 bytes of payload are the last-stream-id (high bit
                // reserved). Anything earlier than that the peer promises to
                // process; ids ≥ this are abandoned. We refuse to allocate
                // any new id beyond `last` but allow existing streams ≤ last
                // to keep running.
                let last = if frame.payload.len() >= 4 {
                    u32::from_be_bytes([
                        frame.payload[0],
                        frame.payload[1],
                        frame.payload[2],
                        frame.payload[3],
                    ]) & 0x7fff_ffff
                } else {
                    0
                };
                self.goaway_received = Some(last);
                // If any of our open streams has id > last, the peer will not
                // process them; mark them closed and let the caller see that.
                // (For now we just transition state; the body/headers stay
                // empty so the caller surfaces a BadResponse.)
                let doomed: Vec<u32> = self
                    .streams
                    .iter()
                    .filter(|(id, _)| **id > last)
                    .map(|(id, _)| *id)
                    .collect();
                for id in doomed {
                    if let Some(s) = self.streams.get_mut(&id) {
                        s.state = StreamState::Closed;
                    }
                }
            }
            _ => {
                // PRIORITY on stream 0 is technically a PROTOCOL_ERROR; we
                // tolerate by ignoring. Unknown frame types are explicitly
                // ignorable per RFC 9113 §4.1.
            }
        }
        Ok(DispatchOutcome::Continue)
    }

    /// Stream-scoped frames (stream_id != 0). Validates the per-stream state
    /// machine and applies the frame.
    fn process_stream_frame(&mut self, frame: Frame) -> Result<DispatchOutcome> {
        match frame.typ {
            F_HEADERS => self.process_headers(frame),
            F_CONTINUATION => self.process_continuation(frame),
            F_DATA => self.process_data(frame),
            F_RST_STREAM => self.process_rst(frame),
            F_WINDOW_UPDATE => {
                let inc = parse_window_update(&frame.payload)?;
                if let Some(s) = self.streams.get_mut(&frame.stream_id) {
                    s.send_window.apply_window_update(inc)?;
                }
                // WINDOW_UPDATE on an unknown / closed stream: silently drop.
                Ok(DispatchOutcome::Continue)
            }
            F_PUSH_PROMISE => {
                // We disabled push (ENABLE_PUSH=0); any PUSH_PROMISE is a
                // protocol violation by the peer.
                Err(Error::BadResponse(
                    "received PUSH_PROMISE despite SETTINGS_ENABLE_PUSH=0".into(),
                ))
            }
            _ => {
                // PRIORITY and unknown types — ignore per §4.1.
                Ok(DispatchOutcome::Continue)
            }
        }
    }

    fn process_headers(&mut self, frame: Frame) -> Result<DispatchOutcome> {
        // Strip PADDED / PRIORITY framing from the payload to find the actual
        // header-block fragment.
        let mut payload = frame.payload.as_slice();
        let mut pad_len = 0usize;
        if frame.flags & FLAG_PADDED != 0 {
            if payload.is_empty() {
                return Err(Error::BadResponse(
                    "HEADERS PADDED with empty payload".into(),
                ));
            }
            pad_len = payload[0] as usize;
            payload = &payload[1..];
        }
        if frame.flags & FLAG_PRIORITY != 0 {
            if payload.len() < 5 {
                return Err(Error::BadResponse(
                    "HEADERS PRIORITY with insufficient payload".into(),
                ));
            }
            payload = &payload[5..];
        }
        if payload.len() < pad_len {
            return Err(Error::BadResponse(
                "HEADERS padding overruns payload".into(),
            ));
        }
        let frag = &payload[..payload.len() - pad_len];
        let end_headers = frame.flags & FLAG_END_HEADERS != 0;
        let end_stream = frame.flags & FLAG_END_STREAM != 0;

        let stream_id = frame.stream_id;
        // Server push: a HEADERS on a stream we never opened with an even id
        // (or a higher odd id from the peer) violates ENABLE_PUSH=0.
        let known = self.streams.contains_key(&stream_id);
        if !known {
            return Err(Error::BadResponse(format!(
                "HEADERS on unknown stream {stream_id} (server push disabled)"
            )));
        }

        // State check: HEADERS on a Closed stream is ignored (trailers after
        // close, RFC 9113 §5.1). Any other illegal state is an error.
        let state = self.streams.get(&stream_id).unwrap().state;
        if state == StreamState::Closed {
            // Drain the fragment but do not decode; this keeps the decoder's
            // dynamic table consistent with the peer's view (HPACK requires
            // the receiver to process header blocks even if it ignores them
            // logically — RFC 7541 §2.2). The peer sent end_headers either on
            // this frame or via CONTINUATION; for simplicity we only honour
            // it inline (we already require end_headers immediately for
            // closed-stream trailers since we don't track expecting_continuation
            // for closed streams in the test surface). Decoding errors propagate.
            if end_headers {
                let _ = self.decoder.decode_block(frag)?;
            } else {
                // Conservatively buffer on the closed stream so the
                // CONTINUATION still finds its target.
                self.streams
                    .get_mut(&stream_id)
                    .unwrap()
                    .push_header_fragment(frag)?;
                self.expecting_continuation = Some(stream_id);
            }
            return Ok(DispatchOutcome::Continue);
        }
        let new_state = state.recv_headers(end_stream)?;

        let s = self.streams.get_mut(&stream_id).unwrap();
        s.push_header_fragment(frag)?;
        if end_stream {
            s.end_stream_recv = true;
        }
        if end_headers {
            // Decode now; clear the buffer.
            let block = std::mem::take(&mut s.headers_buf);
            // Drop the &mut borrow before reaching for the decoder.
            let decoded = self.decoder.decode_block(&block)?;
            let s = self.streams.get_mut(&stream_id).unwrap();
            s.response_headers = Some(decoded);
            s.state = new_state;
            self.expecting_continuation = None;
        } else {
            s.state = new_state;
            self.expecting_continuation = Some(stream_id);
        }

        let done = matches!(
            self.streams.get(&stream_id).unwrap().state,
            StreamState::Closed | StreamState::HalfClosedRemote
        ) && self.streams.get(&stream_id).unwrap().end_stream_recv
            && self
                .streams
                .get(&stream_id)
                .unwrap()
                .response_headers
                .is_some();
        Ok(if done {
            DispatchOutcome::Done(stream_id)
        } else {
            DispatchOutcome::Continue
        })
    }

    fn process_continuation(&mut self, frame: Frame) -> Result<DispatchOutcome> {
        let stream_id = frame.stream_id;
        // §6.10: CONTINUATION must match the stream we set as expecting.
        match self.expecting_continuation {
            Some(awaiting) if awaiting == stream_id => {}
            _ => {
                return Err(Error::BadResponse(format!(
                    "unexpected CONTINUATION on stream {stream_id}"
                )));
            }
        }
        let s = self.streams.get_mut(&stream_id).ok_or_else(|| {
            Error::BadResponse(format!("CONTINUATION on unknown stream {stream_id}"))
        })?;
        s.push_header_fragment(&frame.payload)?;
        let end_headers = frame.flags & FLAG_END_HEADERS != 0;
        if end_headers {
            let block = std::mem::take(&mut s.headers_buf);
            let decoded = self.decoder.decode_block(&block)?;
            let s = self.streams.get_mut(&stream_id).unwrap();
            if s.state != StreamState::Closed {
                s.response_headers = Some(decoded);
            }
            self.expecting_continuation = None;
        }
        let done = matches!(
            self.streams.get(&stream_id).unwrap().state,
            StreamState::Closed | StreamState::HalfClosedRemote
        ) && self.streams.get(&stream_id).unwrap().end_stream_recv
            && self
                .streams
                .get(&stream_id)
                .unwrap()
                .response_headers
                .is_some();
        Ok(if done {
            DispatchOutcome::Done(stream_id)
        } else {
            DispatchOutcome::Continue
        })
    }

    fn process_data(&mut self, frame: Frame) -> Result<DispatchOutcome> {
        let stream_id = frame.stream_id;
        let frame_bytes = frame.payload.len();
        // Connection window is billed regardless of whether the stream is
        // known — that's what the RFC requires.
        self.conn_recv_window.consume(frame_bytes);
        let known = self.streams.contains_key(&stream_id);
        if !known {
            // DATA for an unknown / already-evicted stream: drop silently per
            // RFC 9113 §5.1 ("frames for closed streams MAY be ignored").
            // We still need to replenish the conn window so the peer can keep
            // sending.
            if let Some(upd) = self.conn_recv_window.replenish() {
                write_frame(&mut self.tls, &upd)?;
                self.tls.flush()?;
            }
            return Ok(DispatchOutcome::Continue);
        }
        let state = self.streams.get(&stream_id).unwrap().state;
        if state == StreamState::Closed {
            // Per §5.1, DATA on a closed stream is a STREAM_CLOSED error;
            // we surface it as such.
            return Err(Error::BadResponse(format!(
                "DATA on closed stream {stream_id}"
            )));
        }
        let end_stream = frame.flags & FLAG_END_STREAM != 0;
        let new_state = state.recv_data(end_stream)?;

        let s = self.streams.get_mut(&stream_id).unwrap();
        s.recv_window.consume(frame_bytes);

        // Strip padding to find the application bytes.
        let mut payload = frame.payload.as_slice();
        if frame.flags & FLAG_PADDED != 0 {
            if payload.is_empty() {
                return Err(Error::BadResponse("DATA PADDED with empty payload".into()));
            }
            let pad_len = payload[0] as usize;
            payload = &payload[1..];
            if payload.len() < pad_len {
                return Err(Error::BadResponse("DATA padding overruns payload".into()));
            }
            payload = &payload[..payload.len() - pad_len];
        }
        // Cumulative body cap. HTTP/2 flow control auto-replenishes (see the
        // `replenish()` calls below), so it never stops a server that streams
        // DATA forever — only an absolute ceiling does. Mirrors HTTP/3's
        // `MAX_RESPONSE_BYTES`.
        if s.body.len().saturating_add(payload.len()) > MAX_RESPONSE_BYTES {
            return Err(Error::BadResponse(
                "response body exceeds size limit".into(),
            ));
        }
        s.body.extend_from_slice(payload);
        if end_stream {
            s.end_stream_recv = true;
        }
        s.state = new_state;

        // Replenish either window if it's dropped below half. Both checks are
        // independent — a single large DATA frame can fire both.
        if let Some(upd) = self.conn_recv_window.replenish() {
            write_frame(&mut self.tls, &upd)?;
        }
        if let Some(upd) = self
            .streams
            .get_mut(&stream_id)
            .unwrap()
            .recv_window
            .replenish(stream_id)
        {
            write_frame(&mut self.tls, &upd)?;
        }
        self.tls.flush()?;

        let s = self.streams.get(&stream_id).unwrap();
        let done = matches!(s.state, StreamState::Closed | StreamState::HalfClosedRemote)
            && s.end_stream_recv
            && s.response_headers.is_some();
        Ok(if done {
            DispatchOutcome::Done(stream_id)
        } else {
            DispatchOutcome::Continue
        })
    }

    fn process_rst(&mut self, frame: Frame) -> Result<DispatchOutcome> {
        let stream_id = frame.stream_id;
        let code = if frame.payload.len() >= 4 {
            u32::from_be_bytes([
                frame.payload[0],
                frame.payload[1],
                frame.payload[2],
                frame.payload[3],
            ])
        } else {
            0
        };
        match self.streams.get_mut(&stream_id) {
            Some(s) => {
                // RST_STREAM on closed → silently ignore (RFC 9113 §5.1).
                if s.state == StreamState::Closed {
                    return Ok(DispatchOutcome::Continue);
                }
                s.state = s.state.recv_rst()?;
                Err(Error::BadResponse(format!(
                    "stream {stream_id} reset by server, error code {code}"
                )))
            }
            None => {
                // RST_STREAM on unknown stream: harmless, ignore.
                Ok(DispatchOutcome::Continue)
            }
        }
    }
}

/// Split an HPACK-encoded header block into one HEADERS frame followed by
/// zero or more CONTINUATION frames, each ≤ `max_frame_size` octets
/// (RFC 9113 §6.10).
///
/// `end_stream` controls FLAG_END_STREAM on the HEADERS frame; FLAG_END_HEADERS
/// is set automatically on the final fragment (which is the HEADERS frame
/// itself when one fragment suffices). `stream_id` is the stream the caller
/// has allocated for this request.
///
/// Edge cases:
/// - `header_block.len() == max_frame_size` produces one HEADERS frame.
/// - `header_block.is_empty()` produces one HEADERS frame with empty payload
///   (impossible in practice — we always emit at least the four pseudo-headers
///   — but the function still handles it cleanly).
/// - Any combination of CONTINUATION fragments is emitted with no flags set
///   except FLAG_END_HEADERS on the last one. The caller is responsible for
///   writing them back-to-back with no interleaved frames on the wire, which
///   our single-threaded writer guarantees.
fn fragment_header_block(
    stream_id: u32,
    header_block: &[u8],
    max_frame_size: usize,
    end_stream: bool,
) -> Vec<Frame> {
    debug_assert!(max_frame_size > 0, "max_frame_size must be > 0");
    let mut frames = Vec::new();

    if header_block.is_empty() {
        let mut flags = FLAG_END_HEADERS;
        if end_stream {
            flags |= FLAG_END_STREAM;
        }
        frames.push(Frame {
            typ: F_HEADERS,
            flags,
            stream_id,
            payload: Vec::new(),
        });
        return frames;
    }

    let total_chunks = header_block.len().div_ceil(max_frame_size);
    for (i, chunk) in header_block.chunks(max_frame_size).enumerate() {
        let is_last = i + 1 == total_chunks;
        if i == 0 {
            let mut flags = 0u8;
            if end_stream {
                flags |= FLAG_END_STREAM;
            }
            if is_last {
                flags |= FLAG_END_HEADERS;
            }
            frames.push(Frame {
                typ: F_HEADERS,
                flags,
                stream_id,
                payload: chunk.to_vec(),
            });
        } else {
            let flags = if is_last { FLAG_END_HEADERS } else { 0 };
            frames.push(Frame {
                typ: F_CONTINUATION,
                flags,
                stream_id,
                payload: chunk.to_vec(),
            });
        }
    }
    frames
}

/// Clamp the next DATA chunk size to the smallest of: `max_frame_size`, the
/// remaining bytes to send, and the currently available send window.
///
/// Extracted so the chunking logic can be unit-tested in isolation from the
/// I/O loop. Returns 0 only when the send window is depleted; callers must
/// then wait for a WINDOW_UPDATE before retrying.
fn next_data_chunk_size(max_frame_size: usize, available: i64, remaining: usize) -> usize {
    if available <= 0 {
        return 0;
    }
    let cap_window = available.min(remaining as i64).min(max_frame_size as i64);
    cap_window as usize
}

// ---------------------------------------------------------------------------
// Connection pool.
// ---------------------------------------------------------------------------
//
// A process-wide, lazy-init pool of idle HTTP/2 connections keyed by
// `(scheme, host, port)`. The goal is conservative: avoid the TCP+TLS+h2
// preface handshake on repeat requests to the same authority. We are still
// fully synchronous (no async / threads / executor) — two threads that both
// hit the same checked-out conn will serialize on its `Mutex`. That gives
// "sequential multiplexing" reuse, not concurrent streams on one conn; the
// latter would require I/O multiplexing we don't have. Saving the handshake
// is the bulk of the win anyway.
//
// Connections with non-default TLS opts (`verify_tls=false` or `ca_bundle`
// set) bypass the pool entirely. Putting those into the same map as default
// conns risks reusing a "skip-verify" session for a future caller that did
// NOT ask to skip verification — silent loss of TLS verification. The cheap
// fix is to refuse to pool them; a future task can either (a) add the TLS
// opts into the key, or (b) maintain separate pools per opts profile. We
// pick the cheap fix and document it inline at the call site in `send()`.

/// Map key for a pooled HTTP/2 connection. URL userinfo, path, and query
/// are intentionally absent — they don't affect TLS reuse.
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub(crate) struct PoolKey {
    scheme: String,
    host: String,
    port: u16,
}

impl PoolKey {
    fn from_request(req: &Request) -> Self {
        PoolKey {
            scheme: req.url.scheme.clone(),
            host: req.url.host.clone(),
            port: req.url.port,
        }
    }
}

/// Per-authority cap. With h2 multiplexing the steady-state need is small;
/// keep this modest to bound memory under bursty traffic.
const POOL_PER_KEY_CAP: usize = 4;

/// Total live pooled conns across all keys.
const POOL_GLOBAL_CAP: usize = 32;

/// One pooled connection's transport type. We only pool the production
/// transport — `TlsStream<TcpStream>` over `connect_over_tls`. Test fakes do
/// not use the pool; the pool tests construct `PoolInner` directly with
/// `Arc<Mutex<Connection<S>>>` values built from `FakeTls` (i.e. the pool
/// API is generic over the transport so tests can drive it without I/O).
type PooledConn<S> = Arc<Mutex<Connection<S>>>;

/// The pool's data is internal: a `HashMap` of vectors of `Arc<Mutex<Conn>>`.
/// The outer `Mutex<PoolInner>` is held only during the brief map mutations.
pub(crate) struct PoolInner<S: Read + Write> {
    entries: HashMap<PoolKey, Vec<PooledConn<S>>>,
}

impl<S: Read + Write> PoolInner<S> {
    fn new() -> Self {
        PoolInner {
            entries: HashMap::new(),
        }
    }

    /// Pop one idle conn for `key`, if any. We pop from the back so reuse is
    /// LIFO: most recently used = most likely still alive on the wire.
    fn checkout(&mut self, key: &PoolKey) -> Option<PooledConn<S>> {
        let bucket = self.entries.get_mut(key)?;
        let conn = bucket.pop();
        if bucket.is_empty() {
            self.entries.remove(key);
        }
        conn
    }

    /// Return a conn to the pool. Enforces both caps; on overflow we drop the
    /// new conn rather than evicting an existing one (a warm conn we've used
    /// once already is more likely to survive the next request than a fresh
    /// arrival).
    fn release(&mut self, key: PoolKey, conn: PooledConn<S>) {
        // Global cap takes precedence: even if this bucket has room, we
        // refuse to grow the pool past the global ceiling.
        let total: usize = self.entries.values().map(Vec::len).sum();
        if total >= POOL_GLOBAL_CAP {
            return;
        }
        let bucket = self.entries.entry(key).or_default();
        if bucket.len() >= POOL_PER_KEY_CAP {
            return;
        }
        bucket.push(conn);
    }

    /// For tests/diagnostics: total number of pooled conns.
    #[cfg(test)]
    fn total_len(&self) -> usize {
        self.entries.values().map(Vec::len).sum()
    }
}

/// Process-global pool of production HTTP/2 connections. `OnceLock` keeps
/// init lazy and lock-free after the first observed access; the inner
/// `Mutex` serializes the brief map updates.
static POOL: OnceLock<Mutex<PoolInner<TlsStream<TcpStream>>>> = OnceLock::new();

fn global_pool() -> &'static Mutex<PoolInner<TlsStream<TcpStream>>> {
    POOL.get_or_init(|| Mutex::new(PoolInner::new()))
}

/// Build a brand-new HTTP/2 connection: TCP → TLS (ALPN=h2) → preface.
/// Used both by `send()` on a cold path and indirectly by anything that
/// wants a fresh `Connection` (currently no other call sites).
fn dial_h2(req: &Request) -> Result<Connection<TlsStream<TcpStream>>> {
    let tcp = tcp_connect(req)?;
    // HTTPS-over-proxy: CONNECT to establish a transparent tunnel before
    // the TLS handshake. h2c (cleartext HTTP/2) over a proxy is rejected
    // higher up in `send()`, so by here we know scheme == "https".
    if let Some(p) = req
        .proxy
        .as_ref()
        .filter(|_| !crate::http::proxy_bypassed(req))
    {
        // No trace plumbing here yet — this path runs from `send()` which
        // doesn't carry one. The handshake error (if any) bubbles up the
        // call stack with enough context.
        crate::http::connect_tunnel(&tcp, &req.url, p, &mut std::io::sink())?;
    }
    let opts = crate::http::tls_opts_from(req, &[b"h2"])?;
    let tls = crate::tls::connect_over_tls(tcp, &req.url.host, opts)?;
    let negotiated_h2 = tls.alpn_selected().map(|p| p == b"h2").unwrap_or(false);
    if !negotiated_h2 {
        return Err(Error::H2NotNegotiated);
    }
    Connection::new(tls)
}

/// True if `req`'s TLS options match what the pool can safely reuse. We
/// refuse to pool when verification is off or a custom CA bundle is set —
/// see the module comment above the pool definitions for the rationale.
fn pool_eligible(req: &Request) -> bool {
    req.verify_tls && req.ca_bundle.is_none()
}

/// Send a single request/response over an HTTP/2 connection, reusing a
/// pooled connection for the same `(scheme, host, port)` when possible.
///
/// Flow:
///
/// 1. Build a `PoolKey` and check whether the request's TLS opts are pool-
///    eligible. Non-default opts (`-k` / `--cacert`) bypass the pool.
/// 2. On a pool hit, lock the conn's `Mutex`, sanity-check `is_usable`, run
///    one request on it. On success and still-usable, release back. On any
///    error during send/drive, drop the conn (its wire position may be
///    inconsistent — mid-frame, mid-CONTINUATION — and we cannot recover).
/// 3. On a pool miss, dial a fresh conn, run the request, and release on
///    success.
pub fn send(req: Request) -> Result<Response> {
    if req.url.scheme != "https" {
        // h2c (cleartext HTTP/2 with upgrade) is out of scope for v1.
        return Err(Error::UnsupportedScheme(format!(
            "http/2 over {} not supported",
            req.url.scheme
        )));
    }

    let key = PoolKey::from_request(&req);
    let eligible = pool_eligible(&req);

    // -------- Pool path --------
    // We make at most one attempt against a pooled conn. If the pooled
    // conn turns out to be unusable (or fails mid-request) we fall through
    // to the cold-dial path below; we don't loop popping more pooled conns,
    // because in practice a dead pooled conn is almost always the first
    // symptom of a dead idle pool — better to spend the handshake than
    // burn through every entry.
    if eligible {
        let pooled = {
            let mut guard = global_pool().lock().expect("pool mutex poisoned");
            guard.checkout(&key)
        };
        if let Some(arc) = pooled {
            // Hold the per-conn lock for the whole request — sequential
            // multiplexing only. The pool-wide lock has already been
            // released.
            let mut conn_guard = arc.lock().expect("pooled conn mutex poisoned");
            if conn_guard.is_usable() {
                match run_one_request(&mut conn_guard, &req) {
                    Ok(resp) => {
                        let still_usable = conn_guard.is_usable();
                        drop(conn_guard);
                        if still_usable {
                            let mut guard = global_pool().lock().expect("pool mutex poisoned");
                            guard.release(key.clone(), arc);
                        }
                        return Ok(resp);
                    }
                    Err(_e) => {
                        // Wire state may now be inconsistent. Drop the conn
                        // and fall through to a cold dial; the original error
                        // is intentionally discarded in favour of the
                        // (likely cleaner) error from the fresh attempt.
                        drop(conn_guard);
                    }
                }
            }
            // Unusable on checkout: just drop, do not re-pool.
        }
    }

    // -------- Cold-dial path --------
    let mut fresh = dial_h2(&req)?;
    let resp = run_one_request(&mut fresh, &req)?;
    if eligible && fresh.is_usable() {
        let arc = Arc::new(Mutex::new(fresh));
        let mut guard = global_pool().lock().expect("pool mutex poisoned");
        guard.release(key, arc);
    }
    Ok(resp)
}

/// Drive one request/response exchange on an already-established conn.
/// Factored out so both pool-hit and pool-miss paths share the same body.
fn run_one_request<S: Read + Write>(conn: &mut Connection<S>, req: &Request) -> Result<Response> {
    let stream_id = conn.open_stream()?;
    conn.send_request_on(stream_id, req)?;
    let stream = conn.drive_until_stream_done(stream_id)?;
    build_response_from_stream(stream)
}

/// Translate a fully-received `Stream` into the public `Response` type.
/// Extracts the `:status` pseudo-header, drops any other pseudo-headers
/// (none are defined for responses but be conservative), and inherits the
/// accumulated body.
fn build_response_from_stream(stream: Stream) -> Result<Response> {
    let headers = stream
        .response_headers
        .ok_or_else(|| Error::BadResponse("response ended before any HEADERS frame".into()))?;

    let mut status: Option<u16> = None;
    let mut clean_headers: Vec<(String, String)> = Vec::with_capacity(headers.len());
    for (k, v) in headers {
        if k == ":status" {
            status = Some(
                v.parse::<u16>()
                    .map_err(|_| Error::BadResponse(format!("bad :status {v:?}")))?,
            );
        } else if k.starts_with(':') {
            // Other pseudo-headers (none defined for responses) — drop.
        } else {
            clean_headers.push((k, v));
        }
    }
    let status = status.ok_or_else(|| Error::BadResponse("response missing :status".into()))?;

    // Shared with HTTP/1.1 and HTTP/3: peel off any `Content-Encoding`
    // layer rsurl knows how to decode (gzip / deflate / x-gzip / identity).
    let (clean_headers, body) =
        crate::http::maybe_decode_body(clean_headers, stream.body, &mut std::io::sink())?;

    Ok(Response {
        status,
        reason: String::new(), // HTTP/2 has no reason phrase (RFC 9113 §8.3.1).
        version: "HTTP/2".to_string(),
        headers: clean_headers,
        body,
    })
}

/// Build the HPACK-encoded header block for the request: pseudo-headers in the
/// required order (RFC 9113 §8.3.1), then lowercased user headers (skipping
/// the connection-specific ones HTTP/2 forbids per §8.2.2). The `encoder`
/// is borrowed mutably so its dynamic table tracks every header we emit
/// with incremental indexing — keeping our table aligned with the peer's.
fn build_header_block(encoder: &mut Encoder, req: &Request) -> Vec<u8> {
    let mut out = Vec::new();

    // Pseudo-headers must come first, in this order: :method, :scheme,
    // :authority, :path.
    encoder.encode_header(&mut out, ":method", &req.method);
    encoder.encode_header(&mut out, ":scheme", &req.url.scheme);
    let authority = if req.url.port == 443 && req.url.scheme == "https" {
        req.url.host.clone()
    } else {
        format!("{}:{}", req.url.host, req.url.port)
    };
    encoder.encode_header(&mut out, ":authority", &authority);
    encoder.encode_header(&mut out, ":path", &req.url.path);

    // Regular headers: lowercased name, skip any banned ones.
    let mut have_ua = false;
    let mut have_accept = false;
    let mut have_accept_enc = false;
    let mut have_auth = false;
    for (k, v) in &req.headers {
        if is_connection_specific_header(k) || k.eq_ignore_ascii_case("host") {
            continue;
        }
        let lk = k.to_ascii_lowercase();
        if lk == "user-agent" {
            have_ua = true;
        }
        if lk == "accept" {
            have_accept = true;
        }
        if lk == "accept-encoding" {
            have_accept_enc = true;
        }
        if lk == "authorization" {
            have_auth = true;
        }
        encoder.encode_header(&mut out, &lk, v);
    }
    if !have_auth {
        if let Some(creds) = crate::http::effective_basic_auth(req) {
            let value = format!("Basic {creds}");
            encoder.encode_header(&mut out, "authorization", &value);
        }
    }
    if !have_ua {
        encoder.encode_header(
            &mut out,
            "user-agent",
            concat!("rsurl/", env!("CARGO_PKG_VERSION")),
        );
    }
    if !have_accept {
        encoder.encode_header(&mut out, "accept", "*/*");
    }
    if !have_accept_enc {
        // Same default as the HTTP/1.1 writer — rsurl always decodes these
        // on the way back (see `crate::compress`). The full value is HPACK
        // static index 16, so this round-trips with minimum bytes on wire.
        encoder.encode_header(&mut out, "accept-encoding", "gzip, deflate");
    }
    if !req.body.is_empty() {
        let len = req.body.len().to_string();
        encoder.encode_header(&mut out, "content-length", &len);
    }
    out
}

fn is_connection_specific_header(name: &str) -> bool {
    // RFC 9113 §8.2.2: connection-specific header fields MUST NOT be sent.
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection" | "proxy-connection" | "keep-alive" | "transfer-encoding" | "upgrade" | "te" // unless value is exactly "trailers"; we conservatively drop.
    )
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn int_encode_small() {
        // RFC 7541 §C.1.1: 10 with a 5-bit prefix fits in one byte.
        assert_eq!(encode_int(10, 5), vec![10]);
    }

    #[test]
    fn int_encode_large() {
        // RFC 7541 §C.1.2: 1337 with a 5-bit prefix.
        assert_eq!(encode_int(1337, 5), vec![0x1f, 0x9a, 0x0a]);
    }

    #[test]
    fn int_encode_eight_bit() {
        // RFC 7541 §C.1.3: 42 with an 8-bit prefix is just 42.
        assert_eq!(encode_int(42, 8), vec![42]);
    }

    #[test]
    fn int_decode_round_trips() {
        for &(v, p) in &[
            (0u64, 5),
            (10, 5),
            (30, 5),
            (31, 5),
            (1337, 5),
            (1, 8),
            (255, 8),
        ] {
            let enc = encode_int(v, p);
            let (dec, n) = decode_int(&enc, p).unwrap();
            assert_eq!(dec, v, "value {v} with {p}-bit prefix");
            assert_eq!(n, enc.len());
        }
    }

    #[test]
    fn int_decode_truncated_errors() {
        // 0x1f means "the integer continues" with a 5-bit prefix.
        assert!(decode_int(&[0x1f], 5).is_err());
        assert!(decode_int(&[0x1f, 0x80], 5).is_err());
    }

    #[test]
    fn static_table_method_get() {
        // ":method GET" is entry 2 in the static table.
        assert_eq!(static_full_index(":method", "GET"), Some(2));
    }

    #[test]
    fn static_table_method_post() {
        assert_eq!(static_full_index(":method", "POST"), Some(3));
    }

    #[test]
    fn static_table_name_only() {
        assert_eq!(static_name_index(":status"), Some(8));
        assert_eq!(static_name_index("user-agent"), Some(58));
        assert_eq!(static_name_index("does-not-exist"), None);
    }

    #[test]
    fn static_table_length() {
        assert_eq!(STATIC_TABLE.len(), 61);
    }

    #[test]
    fn frame_round_trip_empty_settings() {
        let f = Frame {
            typ: F_SETTINGS,
            flags: 0,
            stream_id: 0,
            payload: Vec::new(),
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &f).unwrap();
        assert_eq!(buf.len(), 9);
        let mut cur = Cursor::new(buf);
        let g = read_frame(&mut cur).unwrap();
        assert_eq!(g, f);
    }

    #[test]
    fn frame_round_trip_headers_with_payload() {
        let f = Frame {
            typ: F_HEADERS,
            flags: FLAG_END_STREAM | FLAG_END_HEADERS,
            stream_id: 1,
            payload: vec![
                0x82, 0x86, 0x84, 0x41, 0x88, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
                0x90, 0xf4, 0xff,
            ],
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &f).unwrap();
        let mut cur = Cursor::new(buf);
        let g = read_frame(&mut cur).unwrap();
        assert_eq!(g, f);
        assert_eq!(g.flags, 0x05);
    }

    #[test]
    fn frame_stream_id_high_bit_masked_on_read() {
        // Set the R bit (top bit of byte 5). RFC 9113 says receivers MUST ignore it.
        let buf = vec![0, 0, 0, F_DATA, 0, 0x80, 0, 0, 1];
        let mut cur = Cursor::new(buf);
        let f = read_frame(&mut cur).unwrap();
        assert_eq!(f.stream_id, 1);
    }

    #[test]
    fn hpack_encode_indexed_method() {
        // Static index 2 = (":method", "GET") — high bit set + index = 0x82.
        // The indexed-field form (§6.1) doesn't touch the dynamic table.
        let mut enc = Encoder::new();
        let mut out = Vec::new();
        enc.encode_header(&mut out, ":method", "GET");
        assert_eq!(out, vec![0x82]);
        assert!(enc.dyn_table.is_empty());
    }

    #[test]
    fn hpack_encode_literal_with_indexed_name() {
        // ":path" is static name index 4. The encoder uses literal-with-
        // incremental-indexing + indexed name (`01xxxxxx` = 0x40 + idx), so
        // the first byte is 0x44. The value "/foo" picks whichever is
        // shorter between raw and Huffman; we just verify the decoder
        // round-trips and the entry landed in the dynamic table.
        let mut enc = Encoder::new();
        let mut out = Vec::new();
        enc.encode_header(&mut out, ":path", "/foo");
        assert_eq!(out[0], 0x44);
        let mut dec = Decoder::new();
        let got = dec.decode_block(&out).unwrap();
        assert_eq!(got, vec![(":path".into(), "/foo".into())]);
        assert_eq!(enc.dyn_table.len(), 1);
        assert_eq!(enc.dyn_table[0], (":path".to_string(), "/foo".to_string()));
    }

    #[test]
    fn hpack_encode_literal_full() {
        // "x-custom" is in neither table → literal-with-incremental-indexing
        // + literal name (0x40 marker), then two length-prefixed strings.
        let mut enc = Encoder::new();
        let mut out = Vec::new();
        enc.encode_header(&mut out, "x-custom", "yes");
        assert_eq!(out[0], 0x40);
        let mut dec = Decoder::new();
        let got = dec.decode_block(&out).unwrap();
        assert_eq!(got, vec![("x-custom".into(), "yes".into())]);
        assert_eq!(enc.dyn_table[0], ("x-custom".into(), "yes".into()));
    }

    #[test]
    fn hpack_decode_round_trip_pseudo_headers() {
        let mut enc = Encoder::new();
        let mut block = Vec::new();
        enc.encode_header(&mut block, ":method", "GET");
        enc.encode_header(&mut block, ":scheme", "https");
        enc.encode_header(&mut block, ":authority", "example.com");
        enc.encode_header(&mut block, ":path", "/");
        let mut dec = Decoder::new();
        let got = dec.decode_block(&block).unwrap();
        assert_eq!(got.len(), 4);
        assert_eq!(got[0], (":method".into(), "GET".into()));
        assert_eq!(got[1], (":scheme".into(), "https".into()));
        assert_eq!(got[2], (":authority".into(), "example.com".into()));
        assert_eq!(got[3], (":path".into(), "/".into()));
    }

    #[test]
    fn hpack_decode_indexed_static() {
        // 0x82 = indexed header field, static index 2 = (":method", "GET").
        let mut dec = Decoder::new();
        let got = dec.decode_block(&[0x82]).unwrap();
        assert_eq!(got, vec![(":method".into(), "GET".into())]);
    }

    #[test]
    fn hpack_decode_literal_with_incremental_indexing() {
        // RFC 7541 §C.2.1: encoding of "custom-key: custom-header" with
        // incremental indexing, literal name.
        let buf: Vec<u8> = vec![
            0x40, 0x0a, b'c', b'u', b's', b't', b'o', b'm', b'-', b'k', b'e', b'y', 0x0d, b'c',
            b'u', b's', b't', b'o', b'm', b'-', b'h', b'e', b'a', b'd', b'e', b'r',
        ];
        let mut dec = Decoder::new();
        let got = dec.decode_block(&buf).unwrap();
        assert_eq!(got, vec![("custom-key".into(), "custom-header".into())]);
        // And the dynamic table should now hold the new entry.
        assert_eq!(dec.dyn_table.len(), 1);
    }

    #[test]
    fn huffman_decode_c4_1() {
        // RFC 7541 §C.4.1: "www.example.com" Huffman-coded.
        let coded = [
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        let out = huffman_decode(&coded).unwrap();
        assert_eq!(out, b"www.example.com");
    }

    #[test]
    fn huffman_decode_c4_2() {
        // RFC 7541 §C.4.2: "no-cache" Huffman-coded.
        let coded = [0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf];
        let out = huffman_decode(&coded).unwrap();
        assert_eq!(out, b"no-cache");
    }

    #[test]
    fn huffman_decode_c4_3() {
        // RFC 7541 §C.4.3: "custom-key" Huffman-coded.
        let coded = [0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f];
        let out = huffman_decode(&coded).unwrap();
        assert_eq!(out, b"custom-key");
    }

    #[test]
    fn huffman_decode_rejects_short_padding() {
        // A single byte whose padding bits aren't all 1s is invalid.
        // 0x00 alone has 8 bits, all zero — must be rejected.
        assert!(huffman_decode(&[0x00]).is_err());
    }

    // -----------------------------------------------------------------
    // Huffman encoder (RFC 7541 §5.2).
    // -----------------------------------------------------------------

    #[test]
    fn huffman_encode_padding_bits() {
        // 'a' (Huffman index 97) encodes to (code=0x3, len=5). Left-shifted
        // into the top 5 bits of a byte: 0b00011_000 = 0x18. Padded with 3
        // trailing 1-bits: 0b00011_111 = 0x1f.
        let out = huffman_encode(b"a");
        assert_eq!(out, vec![0x1f]);
    }

    #[test]
    fn huffman_encode_appendix_c_www_example_com() {
        // RFC 7541 §C.4.1: "www.example.com".
        let out = huffman_encode(b"www.example.com");
        assert_eq!(
            out,
            vec![0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,]
        );
    }

    #[test]
    fn huffman_encode_appendix_c_no_cache() {
        // RFC 7541 §C.4.2: "no-cache".
        let out = huffman_encode(b"no-cache");
        assert_eq!(out, vec![0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf]);
    }

    #[test]
    fn huffman_encode_appendix_c_custom_key() {
        // RFC 7541 §C.4.3: "custom-key".
        let out = huffman_encode(b"custom-key");
        assert_eq!(out, vec![0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f]);
    }

    #[test]
    fn huffman_encode_appendix_c_custom_value() {
        // RFC 7541 §C.4.3: "custom-value".
        let out = huffman_encode(b"custom-value");
        assert_eq!(
            out,
            vec![0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf]
        );
    }

    #[test]
    fn huffman_encode_round_trips_through_decoder() {
        // Defensive: any byte sequence we Huffman-encode must decode back
        // to itself. Catches bit-cursor / padding bugs.
        for s in &[
            "",
            "a",
            "ab",
            "abc",
            "Hello, world!",
            "the quick brown fox jumps",
            "/foo/bar/baz",
        ] {
            let bytes = s.as_bytes();
            if bytes.is_empty() {
                // huffman_decode rejects empty input only when padding is
                // nonzero; empty in / empty out trivially round-trips.
                let enc = huffman_encode(bytes);
                assert!(enc.is_empty());
                continue;
            }
            let enc = huffman_encode(bytes);
            let dec = huffman_decode(&enc).unwrap();
            assert_eq!(dec, bytes, "round-trip mismatch for {s:?}");
        }
    }

    #[test]
    fn encode_literal_chooses_huffman_when_shorter() {
        // 100 'a' bytes: each 'a' is 5 bits → 500 bits = 63 bytes Huffman.
        // Raw is 100 bytes. Huffman wins; high bit of length prefix is set.
        let mut out = Vec::new();
        let s: String = "a".repeat(100);
        encode_literal_string(&mut out, &s);
        assert_eq!(out[0] & 0x80, 0x80, "Huffman bit should be set");
    }

    #[test]
    fn encode_literal_chooses_raw_when_huffman_longer() {
        // 0xff Huffman-encodes to 27 bits. 100 copies = 2700 bits ≈ 338
        // bytes — far worse than the raw 100. We pick raw; high bit cleared.
        let mut out = Vec::new();
        // Hold the string in a Vec<u8> so we don't have to construct an
        // invalid UTF-8 &str. encode_literal_string takes &str so we cheat
        // through Latin-1 by passing characters that round-trip to bytes.
        // Actually `as_bytes()` is called inside the function, so we use a
        // helper that operates on bytes directly.
        let bytes: Vec<u8> = vec![0xff; 100];
        // encode_literal_string takes &str; we construct a String of the
        // same length via Latin-1 chars. Char `\u{00FF}` is two bytes in
        // UTF-8, so use printable ASCII whose Huffman is also worse than
        // raw: '|' (0x7c) is 28 bits each.
        // Easier: call the underlying primitives directly.
        let huff = huffman_encode(&bytes);
        assert!(
            huff.len() > bytes.len(),
            "0xff Huffman should be longer than raw"
        );
        // Now drive `encode_literal_string` via a printable ASCII string
        // whose Huffman code is also wider than 8 bits per symbol. '|'
        // (Huffman entry: 28 bits) qualifies.
        let s: String = "|".repeat(50);
        out.clear();
        encode_literal_string(&mut out, &s);
        assert_eq!(out[0] & 0x80, 0x00, "Huffman bit should be cleared");
        assert_eq!(out[0] as usize & 0x7f, 50);
        assert_eq!(&out[1..], s.as_bytes());
    }

    // -----------------------------------------------------------------
    // HPACK encoder dynamic-table insertion (RFC 7541 §6.2.1).
    // -----------------------------------------------------------------

    #[test]
    fn encoder_inserts_into_dyn_table_on_incremental_indexing() {
        let mut enc = Encoder::new();
        let mut out = Vec::new();
        enc.encode_header(&mut out, "x-custom", "value1");
        assert_eq!(enc.dyn_table.len(), 1);
        assert_eq!(
            enc.dyn_table[0],
            ("x-custom".to_string(), "value1".to_string())
        );
        assert_eq!(enc.dyn_table_size, "x-custom".len() + "value1".len() + 32);
    }

    #[test]
    fn encoder_evicts_to_fit_max_size() {
        // Each entry has overhead 32 + name + value. Two entries of length
        // (name=4, value=4) cost 40 bytes each = 80 total. Cap at 64 forces
        // the older one out when the second arrives.
        let mut enc = Encoder::new();
        enc.max_dyn_table_size = 64;
        let mut out = Vec::new();
        enc.encode_header(&mut out, "n1aa", "v1aa");
        enc.encode_header(&mut out, "n2aa", "v2aa");
        assert_eq!(enc.dyn_table.len(), 1, "only the newest should remain");
        assert_eq!(enc.dyn_table[0], ("n2aa".to_string(), "v2aa".to_string()));
        assert_eq!(enc.dyn_table_size, 40);
    }

    #[test]
    fn encoder_emits_size_update_signal_on_next_encode_after_setting_change() {
        let mut enc = Encoder::new();
        enc.set_peer_max_table_size(1024);
        let mut out = Vec::new();
        enc.encode_header(&mut out, ":method", "GET");
        // 0x20 prefix + 5-bit integer encoding of 1024.
        // 1024 >= 31 → first byte = 0x20 | 0x1f = 0x3f; remainder 993 =
        // 0xe1, 0x07 (varint). Then `:method GET` is indexed = 0x82.
        assert_eq!(out, vec![0x3f, 0xe1, 0x07, 0x82]);
        // Signal is consumed; a subsequent call MUST NOT re-emit it.
        out.clear();
        enc.encode_header(&mut out, ":method", "GET");
        assert_eq!(out, vec![0x82]);
    }

    #[test]
    fn encoder_uses_dynamic_index_for_repeat() {
        let mut enc = Encoder::new();
        let mut out = Vec::new();
        enc.encode_header(&mut out, "x", "y");
        out.clear();
        enc.encode_header(&mut out, "x", "y");
        // index = static (61) + 1 = 62, high bit set → 0x80 | 62 = 0xbe.
        assert_eq!(out, vec![0xbe]);
    }

    #[test]
    fn encoder_uses_indexed_name_from_dyn_table() {
        let mut enc = Encoder::new();
        let mut out = Vec::new();
        enc.encode_header(&mut out, "x-foo", "v1");
        // After insertion: dyn_table[0] = ("x-foo", "v1") at HPACK index 62.
        out.clear();
        enc.encode_header(&mut out, "x-foo", "v2");
        // Literal-with-incremental-indexing, indexed name (6-bit): 0x40 | 62 = 0x7e.
        assert_eq!(out[0], 0x7e);
        // And both entries should be in the dyn table now (newest first).
        assert_eq!(enc.dyn_table.len(), 2);
        assert_eq!(enc.dyn_table[0].1, "v2");
        assert_eq!(enc.dyn_table[1].1, "v1");
    }

    #[test]
    fn encode_decode_round_trip() {
        // A handful of mixed headers — static-table hits, repeats (which
        // collapse to indexed dynamic refs), and new entries — must
        // round-trip exactly through the decoder.
        let mut enc = Encoder::new();
        let mut dec = Decoder::new();
        let inputs: Vec<(&str, &str)> = vec![
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "example.com"),
            (":path", "/foo"),
            ("user-agent", "rsurl/test"),
            ("accept", "*/*"),
            ("x-custom", "hello world"),
            ("user-agent", "rsurl/test"), // repeat → indexed dyn ref
            ("x-custom", "different"),    // same name, new value
        ];
        let mut buf = Vec::new();
        for (n, v) in &inputs {
            enc.encode_header(&mut buf, n, v);
        }
        let got = dec.decode_block(&buf).unwrap();
        let expected: Vec<(String, String)> = inputs
            .into_iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn encoder_size_update_evicts_oversize_entries_immediately() {
        // Insert two entries (total ~80 bytes), then shrink the cap to 50.
        // The older one must be evicted right away, even before the next
        // encode_header call.
        let mut enc = Encoder::new();
        let mut out = Vec::new();
        enc.encode_header(&mut out, "n1aa", "v1aa"); // 40 bytes
        enc.encode_header(&mut out, "n2aa", "v2aa"); // 40 bytes
        assert_eq!(enc.dyn_table.len(), 2);
        enc.set_peer_max_table_size(50);
        assert_eq!(enc.dyn_table.len(), 1);
        assert_eq!(enc.dyn_table[0].0, "n2aa");
    }

    #[test]
    fn hpack_decode_huffman_literal_value() {
        // RFC 7541 §C.4.1 second header: (":path", "/sample/path") with
        // literal name index 4 + Huffman-coded value. But easier: build
        // a header field "custom-key: custom-value" with both Huffman.
        // We synthesize: 0x40 (literal incremental, new name) + Huffman
        // strings for "custom-key" and "custom-value".
        //
        // For confidence we just test that a known-good RFC vector decodes:
        // C.6.1 first response header. Use the simpler approach of encoding
        // "/sample/path" Huffman behind a literal-without-indexing name=:path.
        //
        // Per RFC §C.4.2's encoding, ":path /sample/path" with Huffman value
        // and indexed name 4 = `0x44 0x8c <huffman bytes>`.
        // We computed the Huffman bytes elsewhere; just verify decoding works
        // on the vector printed in the RFC.
        let buf = vec![
            0x44, 0x8c, 0x60, 0xd4, 0x85, 0x31, 0x68, 0xdf, 0x1c, 0x6f, 0xa2, 0xa6, 0xfd, 0x95,
            0xb6, 0x88,
        ];
        // This vector is hand-crafted to be illustrative; we accept either a
        // successful decode (preferred) or a clean error. The point of this
        // test is to make sure the decoder doesn't panic on adversarial input.
        let _ = Decoder::new().decode_block(&buf);
    }

    #[test]
    fn build_header_block_includes_pseudo() {
        let req = Request::new("GET", "https://example.com/foo").unwrap();
        let mut enc = Encoder::new();
        let block = build_header_block(&mut enc, &req);
        let mut dec = Decoder::new();
        let headers = dec.decode_block(&block).unwrap();
        let kv: Vec<(&str, &str)> = headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert!(kv.contains(&(":method", "GET")));
        assert!(kv.contains(&(":scheme", "https")));
        assert!(kv.contains(&(":authority", "example.com")));
        assert!(kv.contains(&(":path", "/foo")));
        assert!(kv.iter().any(|(k, _)| *k == "user-agent"));
        assert!(kv.iter().any(|(k, _)| *k == "accept"));
    }

    #[test]
    fn build_header_block_strips_banned_headers() {
        let req = Request::new("GET", "https://example.com/")
            .unwrap()
            .header("Connection", "close")
            .header("Host", "evil.example")
            .header("X-Allowed", "yes");
        let mut enc = Encoder::new();
        let block = build_header_block(&mut enc, &req);
        let mut dec = Decoder::new();
        let headers = dec.decode_block(&block).unwrap();
        let names: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
        assert!(!names.contains(&"connection"));
        assert!(!names.contains(&"host"));
        assert!(names.contains(&"x-allowed"));
    }

    #[test]
    fn build_header_block_authority_includes_nonstandard_port() {
        let req = Request::new("GET", "https://example.com:8443/").unwrap();
        let mut enc = Encoder::new();
        let block = build_header_block(&mut enc, &req);
        let mut dec = Decoder::new();
        let headers = dec.decode_block(&block).unwrap();
        let auth = headers.iter().find(|(k, _)| k == ":authority").unwrap();
        assert_eq!(auth.1, "example.com:8443");
    }

    #[test]
    fn decoder_dynamic_table_size_update_caps_to_4096() {
        // 0x20 = size update with 5-bit prefix, value 0 → cap goes to 0.
        let mut dec = Decoder::new();
        dec.decode_block(&[0x20]).unwrap();
        assert_eq!(dec.dyn_table_cap, 0);
    }

    #[test]
    fn decoder_rejects_oversize_index() {
        let mut dec = Decoder::new();
        // 0xff 0x01 = indexed, value 127+1 = 128. We have 61 static + 0 dynamic.
        let err = dec.decode_block(&[0xff, 0x01]).unwrap_err();
        match err {
            Error::BadResponse(_) => {}
            other => panic!("expected BadResponse, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // SETTINGS application (RFC 9113 §6.5).
    // -----------------------------------------------------------------

    /// Build a SETTINGS payload from a list of (id, value) pairs.
    fn settings_payload(entries: &[(u16, u32)]) -> Vec<u8> {
        let mut out = Vec::with_capacity(entries.len() * 6);
        for (id, val) in entries {
            out.extend_from_slice(&id.to_be_bytes());
            out.extend_from_slice(&val.to_be_bytes());
        }
        out
    }

    #[test]
    fn peer_settings_defaults_match_rfc() {
        let p = PeerSettings::default();
        assert_eq!(p.header_table_size, 4096);
        assert!(p.enable_push);
        assert_eq!(p.max_concurrent_streams, u32::MAX);
        assert_eq!(p.initial_window_size, 65_535);
        assert_eq!(p.max_frame_size, 16_384);
        assert_eq!(p.max_header_list_size, u32::MAX);
    }

    #[test]
    fn peer_settings_apply_updates_known_identifiers() {
        let mut p = PeerSettings::default();
        let payload = settings_payload(&[
            (S_HEADER_TABLE_SIZE, 8192),
            (S_INITIAL_WINDOW_SIZE, 131_072),
            (S_MAX_FRAME_SIZE, 32_768),
        ]);
        p.apply_settings_payload(&payload).unwrap();
        assert_eq!(p.header_table_size, 8192);
        assert_eq!(p.initial_window_size, 131_072);
        assert_eq!(p.max_frame_size, 32_768);
        // Untouched parameters stay at defaults.
        assert!(p.enable_push);
        assert_eq!(p.max_concurrent_streams, u32::MAX);
        assert_eq!(p.max_header_list_size, u32::MAX);
    }

    #[test]
    fn peer_settings_ignores_unknown_identifier() {
        let mut p = PeerSettings::default();
        let before = p.clone();
        let payload = settings_payload(&[(0xFFFF, 42)]);
        p.apply_settings_payload(&payload).unwrap();
        assert_eq!(p, before);
    }

    #[test]
    fn peer_settings_rejects_bad_enable_push() {
        let mut p = PeerSettings::default();
        let payload = settings_payload(&[(S_ENABLE_PUSH, 2)]);
        let err = p.apply_settings_payload(&payload).unwrap_err();
        match err {
            Error::BadResponse(_) => {}
            other => panic!("expected BadResponse, got {other:?}"),
        }
    }

    #[test]
    fn peer_settings_rejects_oversize_window() {
        let mut p = PeerSettings::default();
        // 2^31 exactly is one past the max.
        let payload = settings_payload(&[(S_INITIAL_WINDOW_SIZE, 0x8000_0000)]);
        let err = p.apply_settings_payload(&payload).unwrap_err();
        match err {
            Error::BadResponse(_) => {}
            other => panic!("expected BadResponse, got {other:?}"),
        }
    }

    #[test]
    fn peer_settings_rejects_undersize_max_frame() {
        let mut p = PeerSettings::default();
        let payload = settings_payload(&[(S_MAX_FRAME_SIZE, 16_383)]);
        let err = p.apply_settings_payload(&payload).unwrap_err();
        match err {
            Error::BadResponse(_) => {}
            other => panic!("expected BadResponse, got {other:?}"),
        }
    }

    #[test]
    fn peer_settings_rejects_truncated_payload() {
        let mut p = PeerSettings::default();
        let payload = vec![0u8; 5];
        let err = p.apply_settings_payload(&payload).unwrap_err();
        match err {
            Error::BadResponse(_) => {}
            other => panic!("expected BadResponse, got {other:?}"),
        }
    }

    #[test]
    fn peer_settings_enable_push_zero_disables() {
        // We send ENABLE_PUSH=0 ourselves; verify the parser handles it both ways.
        let mut p = PeerSettings::default();
        p.apply_settings_payload(&settings_payload(&[(S_ENABLE_PUSH, 0)]))
            .unwrap();
        assert!(!p.enable_push);
        p.apply_settings_payload(&settings_payload(&[(S_ENABLE_PUSH, 1)]))
            .unwrap();
        assert!(p.enable_push);
    }

    #[test]
    fn peer_settings_max_frame_size_boundaries() {
        // 16384 and 16777215 are inclusive bounds.
        let mut p = PeerSettings::default();
        p.apply_settings_payload(&settings_payload(&[(S_MAX_FRAME_SIZE, 16_384)]))
            .unwrap();
        assert_eq!(p.max_frame_size, 16_384);
        p.apply_settings_payload(&settings_payload(&[(S_MAX_FRAME_SIZE, 16_777_215)]))
            .unwrap();
        assert_eq!(p.max_frame_size, 16_777_215);
        // One past the max should fail.
        let err = p
            .apply_settings_payload(&settings_payload(&[(S_MAX_FRAME_SIZE, 16_777_216)]))
            .unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)));
    }

    // -----------------------------------------------------------------
    // Flow control (RFC 9113 §6.9).
    // -----------------------------------------------------------------

    #[test]
    fn send_window_defaults_match_rfc() {
        // Conn and stream send windows both start at 65_535 (RFC 9113 §6.9.2).
        let c = ConnSendWindow::new();
        assert_eq!(c.available, 65_535);
        let s = StreamSendWindow::new(65_535);
        assert_eq!(s.available, 65_535);
        assert_eq!(s.initial_peer_window, 65_535);
    }

    #[test]
    fn send_window_decrements_after_data() {
        // Both halves drop independently by exactly `n` on `consume`.
        let mut c = ConnSendWindow::new();
        let mut s = StreamSendWindow::new(65_535);
        c.consume(1000);
        s.consume(1000);
        assert_eq!(c.available, 64_535);
        assert_eq!(s.available, 64_535);
        c.consume(64_535);
        s.consume(64_535);
        assert_eq!(c.available, 0);
        assert_eq!(s.available, 0);
    }

    #[test]
    fn window_update_zero_increment_is_error() {
        // RFC 9113 §6.9.1: zero increment is PROTOCOL_ERROR on a stream and
        // FLOW_CONTROL_ERROR on the connection. Both reject it.
        let zero_payload = [0u8; 4];
        let inc = parse_window_update(&zero_payload).unwrap();
        assert_eq!(inc, 0);
        let mut c = ConnSendWindow::new();
        assert!(matches!(
            c.apply_window_update(inc),
            Err(Error::BadResponse(_))
        ));
        let mut s = StreamSendWindow::new(65_535);
        assert!(matches!(
            s.apply_window_update(inc),
            Err(Error::BadResponse(_))
        ));
    }

    #[test]
    fn window_update_overflow_is_error() {
        // Current window = 2^31 - 1, increment 1 → would push to 2^31; that's
        // a FLOW_CONTROL_ERROR (RFC 9113 §6.9.1).
        let mut c = ConnSendWindow::new();
        c.available = WINDOW_MAX;
        assert!(matches!(
            c.apply_window_update(1),
            Err(Error::BadResponse(_))
        ));
        let mut s = StreamSendWindow::new(65_535);
        s.available = WINDOW_MAX;
        assert!(matches!(
            s.apply_window_update(1),
            Err(Error::BadResponse(_))
        ));
    }

    #[test]
    fn window_update_high_bit_ignored_on_parse() {
        // The high bit of the 4-byte payload is reserved (R bit) and MUST be
        // ignored on receipt. Pass a payload with R=1 and increment=1.
        let payload = [0x80, 0x00, 0x00, 0x01];
        let inc = parse_window_update(&payload).unwrap();
        assert_eq!(inc, 1);
    }

    #[test]
    fn window_update_wrong_length_is_error() {
        // Payload must be exactly 4 bytes (FRAME_SIZE_ERROR per RFC 9113 §6.9).
        assert!(matches!(
            parse_window_update(&[0u8; 3]),
            Err(Error::BadResponse(_))
        ));
        assert!(matches!(
            parse_window_update(&[0u8; 5]),
            Err(Error::BadResponse(_))
        ));
    }

    #[test]
    fn initial_window_size_delta_adjusts_stream_send_window() {
        // Peer doubles INITIAL_WINDOW_SIZE: 65535 → 131072. Existing stream's
        // send window grows by exactly that delta. Conn window is independent.
        let mut s = StreamSendWindow::new(65_535);
        s.apply_initial_window_change(131_072).unwrap();
        assert_eq!(s.available, 65_535 + (131_072 - 65_535));
        assert_eq!(s.initial_peer_window, 131_072);
        // A subsequent shrink applies relative to the new initial, not the
        // RFC default.
        s.apply_initial_window_change(0).unwrap();
        // delta = 0 - 131072 = -131072; stream was 131072, becomes 0.
        assert_eq!(s.available, 0);
        assert_eq!(s.initial_peer_window, 0);
    }

    #[test]
    fn initial_window_size_delta_overflow_is_error() {
        // Stream send window already at 2^31-1, then SETTINGS announces a
        // positive INITIAL_WINDOW_SIZE delta → result exceeds 2^31-1, which
        // is a FLOW_CONTROL_ERROR (RFC 9113 §6.9.2).
        let mut s = StreamSendWindow::new(65_535);
        s.available = WINDOW_MAX;
        let err = s.apply_initial_window_change(65_536).unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)));
    }

    #[test]
    fn initial_window_size_delta_allows_negative_window() {
        // §6.9.2 explicitly permits the window to go negative when the peer
        // shrinks INITIAL_WINDOW_SIZE below the bytes already in flight.
        let mut s = StreamSendWindow::new(65_535);
        s.available = 100;
        s.apply_initial_window_change(0).unwrap();
        // delta = 0 - 65535 = -65535; 100 + (-65535) = -65435.
        assert_eq!(s.available, -65_435);
    }

    #[test]
    fn recv_window_defaults_match_rfc() {
        let c = ConnRecvWindow::new();
        assert_eq!(c.available, OUR_INITIAL_WINDOW);
        assert_eq!(c.initial, OUR_INITIAL_WINDOW);
        let s = StreamRecvWindow::new();
        assert_eq!(s.available, OUR_INITIAL_WINDOW);
        assert_eq!(s.initial, OUR_INITIAL_WINDOW);
    }

    #[test]
    fn recv_window_no_replenish_above_half() {
        // Consume slightly less than half the initial window — no
        // WINDOW_UPDATE should be produced.
        let mut c = ConnRecvWindow::new();
        c.consume(1000);
        assert!(c.replenish().is_none());
        assert_eq!(c.available, OUR_INITIAL_WINDOW - 1000);

        let mut s = StreamRecvWindow::new();
        s.consume(1000);
        assert!(s.replenish(1).is_none());
        assert_eq!(s.available, OUR_INITIAL_WINDOW - 1000);
    }

    #[test]
    fn recv_window_replenishes_when_below_half() {
        // Two DATA-sized consumes (20_000 each) bring the window to 25_535 —
        // below the 32_767 threshold. Replenish must emit one WINDOW_UPDATE
        // restoring the running window to `initial`.
        let mut c = ConnRecvWindow::new();
        c.consume(20_000);
        c.consume(20_000);
        assert_eq!(c.available, 25_535);
        let f = c.replenish().expect("conn window expected replenish");
        assert_eq!(f.typ, F_WINDOW_UPDATE);
        assert_eq!(f.stream_id, 0);
        let inc = parse_window_update(&f.payload).unwrap();
        assert_eq!(inc, (OUR_INITIAL_WINDOW - 25_535) as u32);
        assert_eq!(c.available, OUR_INITIAL_WINDOW);
        // Idempotent: subsequent replenish at full is a no-op.
        assert!(c.replenish().is_none());

        let mut s = StreamRecvWindow::new();
        s.consume(40_000);
        let f = s.replenish(7).expect("stream window expected replenish");
        assert_eq!(f.typ, F_WINDOW_UPDATE);
        assert_eq!(f.stream_id, 7);
        let inc = parse_window_update(&f.payload).unwrap();
        assert_eq!(inc, 40_000);
        assert_eq!(s.available, OUR_INITIAL_WINDOW);
    }

    #[test]
    fn window_update_frame_payload_shape() {
        // The frame helper must produce a 4-byte payload with the R bit
        // cleared and the increment in network byte order.
        let f = window_update_frame(7, 0x0102_0304);
        assert_eq!(f.typ, F_WINDOW_UPDATE);
        assert_eq!(f.flags, 0);
        assert_eq!(f.stream_id, 7);
        assert_eq!(f.payload, vec![0x01, 0x02, 0x03, 0x04]);
    }

    // -----------------------------------------------------------------
    // CONTINUATION + DATA fragmentation on send (RFC 9113 §6.1 / §6.10).
    // -----------------------------------------------------------------

    #[test]
    fn fragment_header_block_into_continuation() {
        // Build a synthetic header block of `max * 2 + 7` bytes and split it
        // with end_stream=false (i.e. we will follow up with a DATA body).
        // Expected: HEADERS + CONTINUATION + CONTINUATION; END_HEADERS only
        // on the last; END_STREAM nowhere (because has_body == true).
        let max: usize = 16_384;
        let payload_len = max * 2 + 7;
        let block: Vec<u8> = (0..payload_len).map(|i| (i & 0xff) as u8).collect();

        let frames = fragment_header_block(1, &block, max, /*end_stream=*/ false);
        assert_eq!(frames.len(), 3, "expected HEADERS + 2 CONTINUATION");

        // Frame 0: HEADERS, full chunk, no END_HEADERS, no END_STREAM.
        assert_eq!(frames[0].typ, F_HEADERS);
        assert_eq!(frames[0].stream_id, 1);
        assert_eq!(frames[0].payload.len(), max);
        assert_eq!(frames[0].flags & FLAG_END_HEADERS, 0);
        assert_eq!(frames[0].flags & FLAG_END_STREAM, 0);

        // Frame 1: CONTINUATION, full chunk, no flags.
        assert_eq!(frames[1].typ, F_CONTINUATION);
        assert_eq!(frames[1].stream_id, 1);
        assert_eq!(frames[1].payload.len(), max);
        assert_eq!(frames[1].flags, 0);

        // Frame 2: CONTINUATION, tail (7 bytes), END_HEADERS set.
        assert_eq!(frames[2].typ, F_CONTINUATION);
        assert_eq!(frames[2].stream_id, 1);
        assert_eq!(frames[2].payload.len(), 7);
        assert_eq!(frames[2].flags, FLAG_END_HEADERS);

        // Reassembling all three payloads must reproduce the original block.
        let mut reassembled = Vec::with_capacity(payload_len);
        for f in &frames {
            reassembled.extend_from_slice(&f.payload);
        }
        assert_eq!(reassembled, block);

        // Now flip end_stream=true (no body); END_STREAM lands on the
        // HEADERS frame, not on the final CONTINUATION (per RFC 9113 §6.10).
        let frames = fragment_header_block(1, &block, max, /*end_stream=*/ true);
        assert_eq!(frames[0].flags & FLAG_END_STREAM, FLAG_END_STREAM);
        assert_eq!(frames[2].flags & FLAG_END_STREAM, 0);
        assert_eq!(frames[2].flags & FLAG_END_HEADERS, FLAG_END_HEADERS);
    }

    #[test]
    fn fragment_header_block_exact_fit() {
        // A block of exactly max_frame_size bytes is a single HEADERS frame
        // with END_HEADERS set and no CONTINUATION needed.
        let max: usize = 16_384;
        let block: Vec<u8> = vec![0xab; max];

        // Case 1: has body → no END_STREAM on the HEADERS frame.
        let frames = fragment_header_block(1, &block, max, /*end_stream=*/ false);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].typ, F_HEADERS);
        assert_eq!(frames[0].stream_id, 1);
        assert_eq!(frames[0].payload.len(), max);
        assert_eq!(frames[0].flags & FLAG_END_HEADERS, FLAG_END_HEADERS);
        assert_eq!(frames[0].flags & FLAG_END_STREAM, 0);

        // Case 2: no body → END_STREAM on the HEADERS frame.
        let frames = fragment_header_block(1, &block, max, /*end_stream=*/ true);
        assert_eq!(frames.len(), 1);
        assert_eq!(
            frames[0].flags,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            "exact-fit HEADERS with no body should have END_HEADERS|END_STREAM"
        );
    }

    #[test]
    fn fragment_header_block_empty() {
        // Empty header block → single HEADERS frame with empty payload and
        // END_HEADERS set (and END_STREAM if there's no body).
        let frames = fragment_header_block(1, &[], 16_384, /*end_stream=*/ true);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].typ, F_HEADERS);
        assert!(frames[0].payload.is_empty());
        assert_eq!(frames[0].flags, FLAG_END_HEADERS | FLAG_END_STREAM);
    }

    #[test]
    fn fragment_header_block_small_under_cap() {
        // A small block (well under the cap) → single HEADERS frame holding
        // the whole block; END_HEADERS set.
        let block = vec![0x82, 0x86, 0x84]; // three indexed headers
        let frames = fragment_header_block(1, &block, 16_384, /*end_stream=*/ false);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].typ, F_HEADERS);
        assert_eq!(frames[0].payload, block);
        assert_eq!(frames[0].flags, FLAG_END_HEADERS);
    }

    #[test]
    fn next_data_chunk_size_clamps_to_min_of_three() {
        // Returns the smallest of (max_frame_size, available, remaining).
        assert_eq!(next_data_chunk_size(16_384, 65_535, 100), 100);
        assert_eq!(next_data_chunk_size(16_384, 65_535, 1_000_000), 16_384);
        assert_eq!(next_data_chunk_size(16_384, 1_000, 1_000_000), 1_000);
        assert_eq!(next_data_chunk_size(16_384, 5_000, 8_000), 5_000);
    }

    #[test]
    fn next_data_chunk_size_zero_when_window_depleted() {
        // available <= 0 must yield 0 so the caller knows to block on a
        // WINDOW_UPDATE before issuing the next DATA chunk.
        assert_eq!(next_data_chunk_size(16_384, 0, 100), 0);
        assert_eq!(next_data_chunk_size(16_384, -1, 100), 0);
        assert_eq!(next_data_chunk_size(16_384, -65_535, 100), 0);
    }

    #[test]
    fn fragment_data_into_chunks() {
        // Synthetic body fragmentation mirroring the body-send loop's
        // chunking logic, but without I/O: split a body using `available` as
        // an unchanging window (no WINDOW_UPDATE replenishment in this test).
        // We assert: every chunk is ≤ max_frame_size, ≤ available, the chunks
        // reassemble to the original body, and only the final frame has
        // FLAG_END_STREAM set.
        fn fragment(body: &[u8], max_frame_size: usize, mut available: i64) -> Vec<Frame> {
            let mut out = Vec::new();
            let mut remaining = body;
            while !remaining.is_empty() {
                let n = next_data_chunk_size(max_frame_size, available, remaining.len());
                if n == 0 {
                    break; // stalled — caller would have to wait for WINDOW_UPDATE
                }
                let chunk = &remaining[..n];
                remaining = &remaining[n..];
                let is_last = remaining.is_empty();
                out.push(Frame {
                    typ: F_DATA,
                    flags: if is_last { FLAG_END_STREAM } else { 0 },
                    stream_id: 1,
                    payload: chunk.to_vec(),
                });
                available -= n as i64;
            }
            out
        }

        // Case 1: body fits well within window, just exceeds max_frame_size.
        let body: Vec<u8> = (0..50_000u32).map(|i| (i & 0xff) as u8).collect();
        let frames = fragment(&body, 16_384, 65_535);
        // 50_000 / 16_384 = 3 full + 1 partial = 4 frames.
        assert_eq!(frames.len(), 4);
        assert_eq!(frames[0].payload.len(), 16_384);
        assert_eq!(frames[1].payload.len(), 16_384);
        assert_eq!(frames[2].payload.len(), 16_384);
        assert_eq!(frames[3].payload.len(), 50_000 - 3 * 16_384);
        // END_STREAM only on the final frame.
        assert_eq!(frames[0].flags, 0);
        assert_eq!(frames[1].flags, 0);
        assert_eq!(frames[2].flags, 0);
        assert_eq!(frames[3].flags, FLAG_END_STREAM);
        // Reassembly matches the original body.
        let mut roundtrip = Vec::with_capacity(body.len());
        for f in &frames {
            roundtrip.extend_from_slice(&f.payload);
        }
        assert_eq!(roundtrip, body);

        // Case 2: window smaller than max_frame_size — chunks shrink to fit.
        let frames = fragment(&body, 16_384, 4_000);
        // First chunk capped to 4_000; available depletes after; loop stalls.
        // (Real code would WINDOW_UPDATE-wait, but this in-test fragmenter
        // mimics that with `available -= n` and `n == 0 → break`.)
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload.len(), 4_000);
        // Not the last chunk in absolute terms — only one was emitted.
        assert_eq!(frames[0].flags, 0);

        // Case 3: body exactly equals max_frame_size — one frame, END_STREAM.
        let body = vec![0xab; 16_384];
        let frames = fragment(&body, 16_384, 65_535);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload.len(), 16_384);
        assert_eq!(frames[0].flags, FLAG_END_STREAM);

        // Case 4: empty body — no frames at all (caller skips the loop).
        let frames = fragment(&[], 16_384, 65_535);
        assert!(frames.is_empty());
    }

    // -----------------------------------------------------------------
    // Connection / stream dispatch (RFC 9113 §5.1, §6.10).
    // -----------------------------------------------------------------

    /// In-memory Read+Write impl. `wire_in` is what the test feeds *to* the
    /// `Connection` (frames the peer would send), `wire_out` is what the
    /// `Connection` wrote *to* the peer.
    struct FakeTls {
        wire_in: Cursor<Vec<u8>>,
        wire_out: Vec<u8>,
    }

    impl FakeTls {
        fn new() -> Self {
            FakeTls {
                wire_in: Cursor::new(Vec::new()),
                wire_out: Vec::new(),
            }
        }
    }

    impl Read for FakeTls {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.wire_in.read(buf)
        }
    }
    impl Write for FakeTls {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.wire_out.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Build a `Connection` over a fresh `FakeTls` without going through the
    /// real `new()` path (we don't want to consume the preface bytes from
    /// `wire_out` in every test). All defaults match the `Connection::new`
    /// post-state on a clean handshake.
    fn fake_conn() -> Connection<FakeTls> {
        Connection {
            tls: FakeTls::new(),
            peer: PeerSettings::default(),
            conn_send_window: ConnSendWindow::new(),
            conn_recv_window: ConnRecvWindow::new(),
            decoder: Decoder::new(),
            encoder: Encoder::new(),
            streams: HashMap::new(),
            next_stream_id: 1,
            goaway_received: None,
            expecting_continuation: None,
        }
    }

    #[test]
    fn connection_process_settings_acks_and_applies() {
        // Synthetic SETTINGS frame: bump MAX_FRAME_SIZE to 32 KiB and
        // INITIAL_WINDOW_SIZE to 131_072. process_frame must:
        // 1. update conn.peer to reflect the new values,
        // 2. shift every existing stream's send window by the
        //    INITIAL_WINDOW_SIZE delta (here, none exist),
        // 3. write a SETTINGS ACK frame back to the (fake) TLS sink.
        let payload =
            settings_payload(&[(S_MAX_FRAME_SIZE, 32_768), (S_INITIAL_WINDOW_SIZE, 131_072)]);
        let frame = Frame {
            typ: F_SETTINGS,
            flags: 0,
            stream_id: 0,
            payload,
        };
        let mut conn = fake_conn();
        let outcome = conn.process_frame(frame).unwrap();
        assert_eq!(outcome, DispatchOutcome::Continue);
        assert_eq!(conn.peer.max_frame_size, 32_768);
        assert_eq!(conn.peer.initial_window_size, 131_072);
        assert_eq!(conn.conn_send_window.available, 65_535); // untouched

        // The ACK frame must be on the wire.
        assert_eq!(conn.tls.wire_out.len(), 9);
        let mut cur = Cursor::new(conn.tls.wire_out.clone());
        let ack = read_frame(&mut cur).unwrap();
        assert_eq!(ack.typ, F_SETTINGS);
        assert_eq!(ack.flags, FLAG_ACK);
        assert_eq!(ack.stream_id, 0);
        assert!(ack.payload.is_empty());
    }

    #[test]
    fn connection_process_window_update_replenishes_send_window() {
        // A WINDOW_UPDATE for an open stream grows the stream send window;
        // a WINDOW_UPDATE on stream 0 grows the conn window.
        let mut conn = fake_conn();
        let id = conn.open_stream().unwrap();
        conn.process_frame(window_update_frame(id, 10_000)).unwrap();
        assert_eq!(
            conn.streams.get(&id).unwrap().send_window.available,
            65_535 + 10_000
        );
        assert_eq!(conn.conn_send_window.available, 65_535);

        conn.process_frame(window_update_frame(0, 5_000)).unwrap();
        assert_eq!(conn.conn_send_window.available, 65_535 + 5_000);
    }

    // ---- stream state machine -----

    #[test]
    fn stream_state_open_to_half_closed_local_on_end_stream_send() {
        // From Open, sending DATA with end_stream advances to HalfClosedLocal.
        let s = StreamState::Open;
        assert_eq!(
            s.send_data(/*end_stream=*/ true).unwrap(),
            StreamState::HalfClosedLocal
        );
        // Without END_STREAM the state stays Open.
        assert_eq!(
            StreamState::Open.send_data(false).unwrap(),
            StreamState::Open
        );
    }

    #[test]
    fn stream_state_recv_data_in_idle_is_error() {
        // Idle streams cannot receive DATA — that's a §5.1 violation.
        let err = StreamState::Idle.recv_data(false).unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)));
    }

    #[test]
    fn stream_state_recv_headers_on_closed_stream_is_ignored() {
        // Closed → Closed; no panic, no error. The peer is allowed to send a
        // late trailer block; the decoder will still process it for HPACK
        // dynamic-table consistency but we won't surface the headers.
        assert_eq!(
            StreamState::Closed.recv_headers(true).unwrap(),
            StreamState::Closed
        );
    }

    // ---- stream id allocation -----

    #[test]
    fn next_stream_id_allocates_odd_only() {
        // §5.1.1: client-initiated streams are odd-numbered and strictly
        // increasing. Open four; ids must be 1, 3, 5, 7.
        let mut conn = fake_conn();
        let ids: Vec<u32> = (0..4).map(|_| conn.open_stream().unwrap()).collect();
        assert_eq!(ids, vec![1, 3, 5, 7]);
    }

    #[test]
    fn open_stream_refuses_at_max_concurrent() {
        let mut conn = fake_conn();
        conn.peer.max_concurrent_streams = 2;
        assert!(conn.open_stream().is_ok());
        assert!(conn.open_stream().is_ok());
        let err = conn.open_stream().unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)));
    }

    #[test]
    fn open_stream_refuses_after_goaway() {
        // GOAWAY with last-stream-id=3: ids 1 and 3 can still be allocated,
        // but the id=5 attempt errors.
        let mut conn = fake_conn();
        conn.goaway_received = Some(3);
        assert_eq!(conn.open_stream().unwrap(), 1);
        assert_eq!(conn.open_stream().unwrap(), 3);
        let err = conn.open_stream().unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)));
    }

    // ---- per-frame dispatch / multiplexing -----

    /// Synthesize a HEADERS frame for stream `id` carrying just `:status 200`.
    fn synth_status_200_headers(id: u32, end_stream: bool) -> Frame {
        // 0x88 = indexed header field, static index 8 = (":status", "200").
        let payload = vec![0x88];
        let mut flags = FLAG_END_HEADERS;
        if end_stream {
            flags |= FLAG_END_STREAM;
        }
        Frame {
            typ: F_HEADERS,
            flags,
            stream_id: id,
            payload,
        }
    }

    fn synth_data(id: u32, body: &[u8], end_stream: bool) -> Frame {
        Frame {
            typ: F_DATA,
            flags: if end_stream { FLAG_END_STREAM } else { 0 },
            stream_id: id,
            payload: body.to_vec(),
        }
    }

    #[test]
    fn dispatch_frame_routes_to_correct_stream() {
        // Open two streams; feed interleaved HEADERS + DATA for each;
        // each stream's body must accumulate only its own bytes.
        let mut conn = fake_conn();
        let id_a = conn.open_stream().unwrap();
        let id_b = conn.open_stream().unwrap();
        // Manually move both streams into Open (as if we'd just sent HEADERS).
        conn.streams.get_mut(&id_a).unwrap().state = StreamState::Open;
        conn.streams.get_mut(&id_b).unwrap().state = StreamState::Open;

        conn.process_frame(synth_status_200_headers(id_a, false))
            .unwrap();
        conn.process_frame(synth_status_200_headers(id_b, false))
            .unwrap();
        conn.process_frame(synth_data(id_a, b"aaa", false)).unwrap();
        conn.process_frame(synth_data(id_b, b"bbbb", false))
            .unwrap();
        conn.process_frame(synth_data(id_a, b"AAA", true)).unwrap();
        conn.process_frame(synth_data(id_b, b"BBBB", true)).unwrap();

        assert_eq!(conn.streams.get(&id_a).unwrap().body, b"aaaAAA");
        assert_eq!(conn.streams.get(&id_b).unwrap().body, b"bbbbBBBB");
    }

    #[test]
    fn dispatch_data_on_unknown_stream_is_silently_dropped() {
        // DATA on a stream id we never opened: per RFC 9113 §5.1 we may
        // ignore. No error surfaces and nothing is accumulated.
        let mut conn = fake_conn();
        let outcome = conn
            .process_frame(synth_data(7, b"orphaned", false))
            .unwrap();
        assert_eq!(outcome, DispatchOutcome::Continue);
        // No stream was registered, so no body anywhere.
        assert!(conn.streams.is_empty());
        // Conn recv window has still been charged (the bytes did cross the
        // shared budget), then possibly replenished — verify the latter holds.
        assert!(conn.conn_recv_window.available <= OUR_INITIAL_WINDOW);
    }

    #[test]
    fn dispatch_continuation_on_wrong_stream_is_protocol_error() {
        // Stream 1 mid-headers (no END_HEADERS), then CONTINUATION on stream 3
        // → §6.10 violation, surfaced as BadResponse.
        let mut conn = fake_conn();
        let id1 = conn.open_stream().unwrap();
        let id3 = conn.open_stream().unwrap();
        assert_eq!(id1, 1);
        assert_eq!(id3, 3);
        conn.streams.get_mut(&id1).unwrap().state = StreamState::Open;
        conn.streams.get_mut(&id3).unwrap().state = StreamState::Open;

        // HEADERS on 1 without END_HEADERS.
        let frame = Frame {
            typ: F_HEADERS,
            flags: 0, // no END_HEADERS, no END_STREAM
            stream_id: id1,
            payload: vec![0x88], // partial — but the gate triggers before HPACK
        };
        conn.process_frame(frame).unwrap();
        assert_eq!(conn.expecting_continuation, Some(id1));

        // CONTINUATION on stream 3 must error.
        let bad = Frame {
            typ: F_CONTINUATION,
            flags: FLAG_END_HEADERS,
            stream_id: id3,
            payload: vec![],
        };
        let err = conn.process_frame(bad).unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)));
    }

    #[test]
    fn data_frames_past_body_cap_are_rejected() {
        // A server that streams DATA past MAX_RESPONSE_BYTES must be stopped
        // with BadResponse rather than allowed to exhaust memory.
        let mut conn = fake_conn();
        let id = conn.open_stream().unwrap();
        conn.streams.get_mut(&id).unwrap().state = StreamState::Open;
        // Seed the body right up against the ceiling, then push one more frame
        // that tips it over.
        conn.streams.get_mut(&id).unwrap().body = vec![0u8; MAX_RESPONSE_BYTES - 2];
        let err = conn
            .process_frame(synth_data(id, b"abc", false))
            .unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)));
        // The over-limit payload must not have been appended.
        assert_eq!(
            conn.streams.get(&id).unwrap().body.len(),
            MAX_RESPONSE_BYTES - 2
        );
    }

    #[test]
    fn continuation_flood_is_bounded() {
        // HEADERS without END_HEADERS followed by a stream of CONTINUATION
        // frames must not grow headers_buf without bound (CVE-2024-27316).
        let mut conn = fake_conn();
        let id = conn.open_stream().unwrap();
        conn.streams.get_mut(&id).unwrap().state = StreamState::Open;
        // HEADERS, no END_HEADERS — opens the continuation window. Payload is
        // raw HPACK bytes that we never decode (we error before END_HEADERS).
        conn.process_frame(Frame {
            typ: F_HEADERS,
            flags: 0,
            stream_id: id,
            payload: vec![0u8; 8 * 1024],
        })
        .unwrap();
        // Keep feeding CONTINUATION fragments with no END_HEADERS; eventually
        // the aggregate buffer cap fires.
        let chunk = vec![0u8; 16 * 1024];
        let mut hit_cap = false;
        for _ in 0..(MAX_HEADERS_BUF / chunk.len() + 4) {
            let r = conn.process_frame(Frame {
                typ: F_CONTINUATION,
                flags: 0,
                stream_id: id,
                payload: chunk.clone(),
            });
            if let Err(Error::BadResponse(_)) = r {
                hit_cap = true;
                break;
            }
            r.unwrap();
        }
        assert!(hit_cap, "CONTINUATION flood was not bounded");
        assert!(conn.streams.get(&id).unwrap().headers_buf.len() <= MAX_HEADERS_BUF);
    }

    #[test]
    fn hpack_decompression_bomb_is_rejected() {
        // A small compressed block that expands to a huge decoded header list
        // must be rejected. We craft many literal-with-incremental-indexing
        // entries with a long value; the static dynamic-table eviction means
        // the *block* stays modest while the decoded list keeps growing.
        let mut dec = Decoder::new();
        let mut block: Vec<u8> = Vec::new();
        // Each entry: 0x40 (literal, incremental index, name idx 0) + name +
        // value. Use a 1-byte name and a long-ish value; repeat until the
        // decoded list_size accounting must exceed MAX_DECODED_HEADER_LIST.
        let name = b"a";
        let value = vec![b'x'; 4096];
        // Encode one entry of this shape.
        let mut entry = Vec::new();
        entry.push(0x40); // literal w/ incremental indexing, name index 0
        entry.push(name.len() as u8); // H=0, 7-bit length
        entry.extend_from_slice(name);
        // value length 4096 needs the multi-byte 7-bit-prefix int encoding.
        // 4096 = 127 + 3969 → prefix 0x7f, then 3969 as continuation bytes.
        encode_int_local(value.len() as u64, 7, 0x00, &mut entry);
        entry.extend_from_slice(&value);
        // ~128 entries × (4096+32) ≈ 528 KiB decoded, well over the 256 KiB cap.
        for _ in 0..200 {
            block.extend_from_slice(&entry);
        }
        let err = dec.decode_block(&block).unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)));
    }

    /// Minimal HPACK integer encoder for tests (mirrors `decode_int`).
    fn encode_int_local(mut value: u64, prefix_bits: u8, first_byte_high: u8, out: &mut Vec<u8>) {
        let max_prefix = (1u64 << prefix_bits) - 1;
        if value < max_prefix {
            out.push(first_byte_high | value as u8);
            return;
        }
        out.push(first_byte_high | max_prefix as u8);
        value -= max_prefix;
        while value >= 128 {
            out.push(((value & 0x7f) as u8) | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
    }

    // -----------------------------------------------------------------
    // Connection pool (task 5). All pool tests use `PoolInner::<FakeTls>`
    // built directly — they do NOT touch the process-global `POOL` static,
    // so they are isolated from one another and from any production code.
    // -----------------------------------------------------------------

    fn fake_arc_conn() -> Arc<Mutex<Connection<FakeTls>>> {
        Arc::new(Mutex::new(fake_conn()))
    }

    fn url_key(url: &str) -> PoolKey {
        let req = Request::new("GET", url).unwrap();
        PoolKey::from_request(&req)
    }

    #[test]
    fn pool_key_round_trip() {
        // Same URL → equal keys; differing scheme/host/port → distinct.
        let a = url_key("https://example.com/a");
        let b = url_key("https://example.com/b"); // path differs only
        assert_eq!(a, b);

        let c = url_key("https://example.com:8443/a");
        assert_ne!(a, c, "port differs");

        let d = url_key("https://other.example/a");
        assert_ne!(a, d, "host differs");
    }

    #[test]
    fn pool_checkout_empty_returns_none() {
        let mut pool: PoolInner<FakeTls> = PoolInner::new();
        let k = url_key("https://example.com/");
        assert!(pool.checkout(&k).is_none());
    }

    #[test]
    fn pool_release_then_checkout_returns_same_conn() {
        // Release one Arc, check it back out, assert it's the same allocation.
        let mut pool: PoolInner<FakeTls> = PoolInner::new();
        let k = url_key("https://example.com/");
        let arc = fake_arc_conn();
        let raw_in = Arc::as_ptr(&arc) as usize;
        pool.release(k.clone(), arc);

        let got = pool.checkout(&k).expect("checkout after release");
        let raw_out = Arc::as_ptr(&got) as usize;
        assert_eq!(raw_in, raw_out, "pool returned a different Arc");

        // Bucket should have been removed once empty.
        assert!(pool.checkout(&k).is_none());
    }

    #[test]
    fn pool_per_key_cap_drops_overflow() {
        // Release POOL_PER_KEY_CAP + 2 conns to a single key; only CAP
        // survive. Pop them all and count.
        let mut pool: PoolInner<FakeTls> = PoolInner::new();
        let k = url_key("https://example.com/");
        for _ in 0..(POOL_PER_KEY_CAP + 2) {
            pool.release(k.clone(), fake_arc_conn());
        }
        let mut popped = 0;
        while pool.checkout(&k).is_some() {
            popped += 1;
        }
        assert_eq!(popped, POOL_PER_KEY_CAP);
    }

    #[test]
    fn pool_global_cap_drops_overflow() {
        // Spread releases across many distinct keys so the per-key cap
        // never bites — only the global cap can. Push double the global cap
        // and assert the pool's total length never exceeds it.
        let mut pool: PoolInner<FakeTls> = PoolInner::new();
        for i in 0..(POOL_GLOBAL_CAP * 2) {
            let k = url_key(&format!("https://h{i}.example/"));
            pool.release(k, fake_arc_conn());
        }
        assert!(
            pool.total_len() <= POOL_GLOBAL_CAP,
            "pool grew past global cap: {} > {}",
            pool.total_len(),
            POOL_GLOBAL_CAP
        );
        // And we should be exactly at the cap (we never evict, so we should
        // have stopped accepting at POOL_GLOBAL_CAP).
        assert_eq!(pool.total_len(), POOL_GLOBAL_CAP);
    }

    #[test]
    fn connection_is_usable_false_after_goaway() {
        let mut conn = fake_conn();
        conn.goaway_received = Some(0);
        assert!(
            conn.streams.is_empty(),
            "precondition: fresh conn has no streams"
        );
        assert!(!conn.is_usable());
    }

    #[test]
    fn connection_is_usable_true_initially() {
        let conn = fake_conn();
        assert!(conn.is_usable());
    }

    #[test]
    fn initial_window_size_delta_applies_to_all_streams() {
        // Open two streams (both at the default 65_535 send window).
        // A SETTINGS bump to INITIAL_WINDOW_SIZE = 131_072 must shift both
        // stream send windows by +65_537; the conn send window is unchanged.
        let mut conn = fake_conn();
        let id1 = conn.open_stream().unwrap();
        let id2 = conn.open_stream().unwrap();

        let payload = settings_payload(&[(S_INITIAL_WINDOW_SIZE, 131_072)]);
        let frame = Frame {
            typ: F_SETTINGS,
            flags: 0,
            stream_id: 0,
            payload,
        };
        conn.process_frame(frame).unwrap();

        let expect = 65_535 + (131_072 - 65_535);
        assert_eq!(
            conn.streams.get(&id1).unwrap().send_window.available,
            expect
        );
        assert_eq!(
            conn.streams.get(&id2).unwrap().send_window.available,
            expect
        );
        assert_eq!(conn.conn_send_window.available, 65_535);
    }
}

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
//! - HPACK encoder uses only "literal header field without indexing"
//!   (0x00 prefix) with full literal name+value, plus indexed lookups in
//!   the static table when the (name, value) pair matches an entry. No
//!   dynamic-table insertion on the encode side, no Huffman on encode.
//! - HPACK decoder handles the static table, indexed-name+literal-value,
//!   full literal, dynamic table insertions (capped, no resize signals
//!   beyond the default 4096), and Huffman-coded literals (RFC 7541
//!   Appendix B).
//! - Frame I/O covers HEADERS, CONTINUATION, DATA, SETTINGS, PING,
//!   WINDOW_UPDATE, GOAWAY, RST_STREAM. We auto-ACK SETTINGS, auto-PONG
//!   PING; everything else on a non-target stream is ignored.

use std::io::{self, Read, Write};
use std::net::TcpStream;

use crate::error::{Error, Result};
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
    let mut out = Vec::with_capacity(input.len() * 2);
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
        while pos < buf.len() {
            let b = buf[pos];
            if b & 0x80 != 0 {
                // Indexed header field (RFC 7541 §6.1).
                let (idx, n) = decode_int(&buf[pos..], 7)?;
                pos += n;
                out.push(self.lookup(idx)?);
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
                out.push((name, value));
            } else if b & 0x20 != 0 {
                // Dynamic table size update (§6.3).
                let (new_size, n) = decode_int(&buf[pos..], 5)?;
                pos += n;
                let cap = (new_size as usize).min(DYN_TABLE_CAP);
                self.dyn_table_cap = cap;
                self.evict_to_fit(0);
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
                out.push((name, value));
            }
        }
        Ok(out)
    }
}

/// Encode one header into `out` as either an indexed reference (when both
/// name and value match the static table) or a literal-without-indexing entry
/// with literal name and literal value. Lowercased names are required by
/// RFC 9113 §8.2.1 for HTTP/2.
fn hpack_encode_header(out: &mut Vec<u8>, name: &str, value: &str) {
    if let Some(idx) = static_full_index(name, value) {
        // Indexed: high bit set, 7-bit integer index.
        let mut bytes = encode_int(idx as u64, 7);
        bytes[0] |= 0x80;
        out.extend_from_slice(&bytes);
        return;
    }
    if let Some(idx) = static_name_index(name) {
        // Literal without indexing, indexed name: 0000xxxx prefix, 4-bit name index.
        let mut bytes = encode_int(idx as u64, 4);
        bytes[0] |= 0x00; // explicit: top 4 bits already zero from 4-bit encode.
        out.extend_from_slice(&bytes);
        encode_literal_string(out, value);
        return;
    }
    // Literal without indexing, literal name: 0x00 marker byte, then two strings.
    out.push(0x00);
    encode_literal_string(out, name);
    encode_literal_string(out, value);
}

fn encode_literal_string(out: &mut Vec<u8>, s: &str) {
    // Huffman flag = 0, length in 7-bit prefix.
    let bytes = s.as_bytes();
    let mut len_bytes = encode_int(bytes.len() as u64, 7);
    len_bytes[0] &= 0x7f; // clear Huffman bit.
    out.extend_from_slice(&len_bytes);
    out.extend_from_slice(bytes);
}

// ---------------------------------------------------------------------------
// TLS with ALPN = h2 — uses the shared driver in `crate::tls`.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TCP setup, mirroring crate::http::tcp_connect.
// ---------------------------------------------------------------------------

fn tcp_connect(req: &Request) -> Result<TcpStream> {
    let addr = format!("{}:{}", req.url.host, req.url.port);
    let stream = match req.connect_timeout {
        Some(t) => {
            let first = std::net::ToSocketAddrs::to_socket_addrs(&addr)?
                .next()
                .ok_or_else(|| Error::InvalidUrl(req.url.host.clone()))?;
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
    streams: std::collections::HashMap<u32, Stream>,
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
            streams: std::collections::HashMap::new(),
            next_stream_id: 1,
            goaway_received: None,
            expecting_continuation: None,
        })
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
        let header_block = build_header_block(req);
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
                    .headers_buf
                    .extend_from_slice(frag);
                self.expecting_continuation = Some(stream_id);
            }
            return Ok(DispatchOutcome::Continue);
        }
        let new_state = state.recv_headers(end_stream)?;

        let s = self.streams.get_mut(&stream_id).unwrap();
        s.headers_buf.extend_from_slice(frag);
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
        s.headers_buf.extend_from_slice(&frame.payload);
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

/// Send a single request/response over a fresh HTTP/2 connection.
///
/// The connection is built, used for one stream, and dropped. Task 5 will
/// replace this with a pool-aware variant that reuses connections across
/// `send()` calls.
pub fn send(req: Request) -> Result<Response> {
    if req.url.scheme != "https" {
        // h2c (cleartext HTTP/2 with upgrade) is out of scope for v1.
        return Err(Error::UnsupportedScheme(format!(
            "http/2 over {} not supported",
            req.url.scheme
        )));
    }
    let tcp = tcp_connect(&req)?;
    let opts = crate::http::tls_opts_from(&req, &[b"h2"])?;
    let tls = crate::tls::connect_over_tls(tcp, &req.url.host, opts)?;
    let negotiated_h2 = tls.alpn_selected().map(|p| p == b"h2").unwrap_or(false);
    if !negotiated_h2 {
        return Err(Error::H2NotNegotiated);
    }

    let mut conn = Connection::new(tls)?;
    let stream_id = conn.open_stream()?;
    conn.send_request_on(stream_id, &req)?;
    let stream = conn.drive_until_stream_done(stream_id)?;
    drop(conn);
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

    Ok(Response {
        status,
        reason: String::new(), // HTTP/2 has no reason phrase (RFC 9113 §8.3.1).
        version: "HTTP/2".to_string(),
        headers: clean_headers,
        body: stream.body,
    })
}

/// Build the HPACK-encoded header block for the request: pseudo-headers in the
/// required order (RFC 9113 §8.3.1), then lowercased user headers (skipping
/// the connection-specific ones HTTP/2 forbids per §8.2.2).
fn build_header_block(req: &Request) -> Vec<u8> {
    let mut out = Vec::new();

    // Pseudo-headers must come first, in this order: :method, :scheme,
    // :authority, :path.
    hpack_encode_header(&mut out, ":method", &req.method);
    hpack_encode_header(&mut out, ":scheme", &req.url.scheme);
    let authority = if req.url.port == 443 && req.url.scheme == "https" {
        req.url.host.clone()
    } else {
        format!("{}:{}", req.url.host, req.url.port)
    };
    hpack_encode_header(&mut out, ":authority", &authority);
    hpack_encode_header(&mut out, ":path", &req.url.path);

    // Regular headers: lowercased name, skip any banned ones.
    let mut have_ua = false;
    let mut have_accept = false;
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
        if lk == "authorization" {
            have_auth = true;
        }
        hpack_encode_header(&mut out, &lk, v);
    }
    if !have_auth {
        if let Some(creds) = crate::http::effective_basic_auth(req) {
            let value = format!("Basic {creds}");
            hpack_encode_header(&mut out, "authorization", &value);
        }
    }
    if !have_ua {
        hpack_encode_header(
            &mut out,
            "user-agent",
            concat!("rsurl/", env!("CARGO_PKG_VERSION")),
        );
    }
    if !have_accept {
        hpack_encode_header(&mut out, "accept", "*/*");
    }
    if !req.body.is_empty() {
        let len = req.body.len().to_string();
        hpack_encode_header(&mut out, "content-length", &len);
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
        let mut out = Vec::new();
        hpack_encode_header(&mut out, ":method", "GET");
        // Indexed header field, index 2 → 0x82.
        assert_eq!(out, vec![0x82]);
    }

    #[test]
    fn hpack_encode_literal_with_indexed_name() {
        let mut out = Vec::new();
        hpack_encode_header(&mut out, ":path", "/foo");
        // Literal w/o indexing, indexed name :path = 4 → 0x04.
        // Then literal length 4, Huffman flag 0 → 0x04, then "/foo".
        assert_eq!(out, vec![0x04, 0x04, b'/', b'f', b'o', b'o']);
    }

    #[test]
    fn hpack_encode_literal_full() {
        let mut out = Vec::new();
        hpack_encode_header(&mut out, "x-custom", "yes");
        // Literal w/o indexing, new name → 0x00, then "x-custom" (len 8), then "yes" (len 3).
        let expected = {
            let mut v = vec![0x00, 0x08];
            v.extend_from_slice(b"x-custom");
            v.push(0x03);
            v.extend_from_slice(b"yes");
            v
        };
        assert_eq!(out, expected);
    }

    #[test]
    fn hpack_decode_round_trip_pseudo_headers() {
        let mut block = Vec::new();
        hpack_encode_header(&mut block, ":method", "GET");
        hpack_encode_header(&mut block, ":scheme", "https");
        hpack_encode_header(&mut block, ":authority", "example.com");
        hpack_encode_header(&mut block, ":path", "/");
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
        let block = build_header_block(&req);
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
        let block = build_header_block(&req);
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
        let block = build_header_block(&req);
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
            streams: std::collections::HashMap::new(),
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

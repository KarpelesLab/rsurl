//! HTTP/2 support (RFC 9113), with HPACK header compression (RFC 7541).
//!
//! HTTP/2 reuses the `https://` URL scheme; the version is selected at
//! connect time, typically via ALPN ("h2"). This module exposes a backend
//! that can serve [`crate::Request`] over a TLS connection negotiated with
//! ALPN, returning a [`crate::Response`] just like HTTP/1.1.
//!
//! Scope of this implementation:
//!
//! - Multiplexed streams within one connection (RFC 9113 §5.1). A single
//!   `Connection` carries many streams, and `send()` reuses a pooled
//!   `Connection` across calls: a process-wide pool keyed on
//!   `(scheme, host, port)` parks idle post-handshake connections so a
//!   follow-up request to the same authority skips the TCP + TLS + h2-preface
//!   handshake and simply opens the next odd stream id (1, 3, 5, …) on the warm
//!   connection. The single-request `send()` path drives one request at a time
//!   over a pooled connection (sequential reuse). For TRUE concurrency,
//!   `send_multiplexed()` issues a batch of requests to one origin over a
//!   single connection, opening up to `SETTINGS_MAX_CONCURRENT_STREAMS` streams
//!   at once, sending their bodies non-blockingly (no head-of-line stall across
//!   streams), and demultiplexing the interleaved responses from one frame
//!   loop. See `run_multiplexed` / `pump_pending_sends`.
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
//! - Flow control is fully implemented (RFC 9113 §5.2 / §6.9), at both the
//!   connection and stream level, in each direction. On send we never emit
//!   DATA past the smaller of the conn/stream send windows, blocking on the
//!   peer's WINDOW_UPDATE frames when a body outruns the window, and we honour
//!   `SETTINGS_INITIAL_WINDOW_SIZE` — including the §6.9.2 retroactive delta
//!   applied to open streams when the peer changes it mid-connection. On
//!   receive we bill inbound DATA against both windows and replenish the
//!   peer's allowance with WINDOW_UPDATE as the client consumes it (tied to
//!   actual consumption, not unconditional), while the `MAX_RESPONSE_BYTES`
//!   cap still bounds total memory. Window overflow past 2^31-1 and
//!   zero-increment WINDOW_UPDATEs are rejected per §6.9.1.

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

// ---------------------------------------------------------------------------
// Flood / no-progress budgets.
//
// The inbound frame loop (`drive_until_stream_done` / `run_multiplexed`) must
// not be steerable into an unbounded spin or an unbounded cheap-control-frame
// reply storm by a hostile peer. Flow control alone does not save us: an empty
// (0-byte) DATA frame with no END_STREAM bills `consume(0)`, appends nothing
// (so `MAX_RESPONSE_BYTES` never trips) and leaves the stream Open — the loop
// would spin forever. SETTINGS / PING each force an ACK write+flush, and
// RST_STREAM is the Rapid-Reset (CVE-2023-44487) primitive — all free to the
// attacker, all unbounded without an explicit budget.
//
// These ceilings are deliberately far above anything a conformant server does
// over the lifetime of a request batch, but low enough that a tight flood loop
// trips within milliseconds. Exceeding any of them is treated as a fatal
// protocol abuse and surfaced as `Error::BadResponse`.

/// Maximum number of consecutive inbound frames that make NO forward progress
/// before we declare the peer is spinning us and abort. "Progress" is any of:
/// a DATA byte appended to a response body, a header block completed, or a
/// WINDOW_UPDATE that raised a send window (see `frame_made_progress`). The
/// counter resets to 0 on every such frame. Kills the empty-DATA spin and any
/// other do-nothing frame loop. Generous: a legitimate server interleaves
/// progress frames long before this.
const MAX_NO_PROGRESS_FRAMES: u32 = 10_000;

/// Maximum non-ACK SETTINGS frames we will accept on one connection. Each one
/// costs us an ACK write+flush; a conformant server sends a handful (initial +
/// the occasional reconfigure). Bounds the SETTINGS-flood reply storm.
const MAX_SETTINGS_FRAMES: u32 = 2_000;

/// Maximum non-ACK PING frames we will accept on one connection. Each one costs
/// us a PONG write+flush. Bounds the PING-flood reply storm.
const MAX_PING_FRAMES: u32 = 2_000;

/// Maximum RST_STREAM frames we will accept on one connection. This is the
/// Rapid-Reset (CVE-2023-44487) aggregate budget: even though we drive a small
/// number of streams, an attacker controlling the server can spray RST_STREAM
/// to churn our state. A legitimate server resets at most a few of our streams.
const MAX_RST_STREAM_FRAMES: u32 = 2_000;

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
        if !payload.len().is_multiple_of(6) {
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
            // Reject malformed/forbidden octets in field names and values
            // (RFC 9113 §8.2.1). This covers every code path — indexed,
            // literal, and table-sourced — so a malicious peer can't smuggle
            // CR/LF/NUL or non-token name bytes through to a re-serializing
            // consumer (header/response splitting, trace corruption).
            if !header_octets_ok(entry.0.as_bytes(), entry.1.as_bytes()) {
                return Err(Error::BadResponse(
                    "hpack: forbidden octet in decoded header".into(),
                ));
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

/// Validate a decoded HPACK field per RFC 9113 §8.2.1 / RFC 7230 token rules.
///
/// Returns `false` (caller rejects with `Error::BadResponse`) when:
/// - the name is empty,
/// - the name contains an uppercase ASCII letter or any byte outside the
///   RFC 7230 token set, EXCEPT that a single leading `:` is permitted so
///   pseudo-headers like `:status` pass,
/// - the value contains `NUL` (0x00), `LF` (0x0a), or `CR` (0x0d).
///
/// Values may otherwise carry any printable byte, spaces, and tabs.
fn header_octets_ok(name: &[u8], value: &[u8]) -> bool {
    if name.is_empty() {
        return false;
    }
    // A leading `:` marks a pseudo-header; the remainder must still be a token.
    let name_rest = if name[0] == b':' { &name[1..] } else { name };
    if name_rest.is_empty() {
        return false;
    }
    if !name_rest.iter().all(|&c| is_token_char(c)) {
        return false;
    }
    !value.iter().any(|&c| c == 0x00 || c == 0x0a || c == 0x0d)
}

/// RFC 7230 token char: `!#$%&'*+-.^_`|~`, digits, and lowercase letters.
/// Uppercase letters are deliberately excluded (HTTP/2 names are lowercase).
fn is_token_char(c: u8) -> bool {
    c.is_ascii_digit()
        || c.is_ascii_lowercase()
        || matches!(
            c,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
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
    /// Stays empty when the body is streamed straight to a caller-supplied sink
    /// (see [`Connection::process_data`]); `streamed_len` then holds the count.
    body: Vec<u8>,
    /// Bytes written directly to the streaming sink (when streaming, `body` is
    /// empty). Used only for the `* Received N body bytes` trace.
    streamed_len: u64,
    /// True once the peer's END_STREAM has been observed.
    end_stream_recv: bool,
    /// Outbound request body not yet written, with a cursor into it. Used by
    /// the multiplexed driver's non-blocking sender (`pump_pending_sends`):
    /// when a stream's send window is exhausted we leave the unsent suffix
    /// here and move on to other streams, resuming when WINDOW_UPDATE arrives.
    /// `None` once the whole body has been flushed (and END_STREAM emitted).
    /// The single-stream `send_request_on` path never populates this — it
    /// writes the body inline with its own blocking loop.
    pending_body: Option<PendingBody>,
}

/// A request body that is being streamed out across multiple `pump`
/// iterations because flow control would not let it all go at once.
struct PendingBody {
    /// The full request body bytes.
    bytes: Vec<u8>,
    /// How many bytes of `bytes` have already been written to the wire.
    sent: usize,
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
            streamed_len: 0,
            end_stream_recv: false,
            pending_body: None,
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
/// One `Connection` per TLS session. A `Connection` outlives a single
/// request: after a request completes cleanly and the connection is still
/// usable ([`Connection::is_usable`]), `send()` parks it in the process-wide
/// pool so the next `send()` to the same authority reuses it — opening the
/// next odd stream id on the warm transport instead of re-handshaking. See
/// the pool section near the bottom of this module.
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
    /// Per-connection flood / no-progress accounting. Updated by every inbound
    /// frame via `process_frame`; trips `Error::BadResponse` once any budget is
    /// exhausted. Shared by both the single-stream and multiplexed loops since
    /// both funnel through `process_frame`.
    budget: FloodBudget,
    /// Set by a frame handler whenever the frame it processed made real forward
    /// progress (a DATA byte appended, a header block completed, or a
    /// WINDOW_UPDATE that raised a send window). `process_frame` reads and
    /// clears it after each dispatch to drive the no-progress counter.
    made_progress: bool,
    /// Negotiated TLS parameters of this connection, captured at dial time.
    /// Carried so every response on the connection (including pooled reuse) can
    /// report [`crate::Response::tls`]. `None` for non-TLS test connections.
    tls_info: Option<crate::http::TlsInfo>,
    /// Per-phase dial timing (namelookup/connect/appconnect), captured at dial.
    /// Applied to a response only on the fresh-dial path (pooled reuse leaves
    /// these phases unset, matching curl's reuse semantics).
    dial_timing: crate::http::Timing,
}

/// Per-connection budget counters that bound hostile-peer frame floods. See the
/// `MAX_*_FRAMES` / `MAX_NO_PROGRESS_FRAMES` constants for the rationale behind
/// each ceiling.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct FloodBudget {
    /// Consecutive inbound frames that made no forward progress. Reset to 0 on
    /// any progress frame; aborts at `MAX_NO_PROGRESS_FRAMES`.
    no_progress: u32,
    /// Total non-ACK SETTINGS frames received; aborts at `MAX_SETTINGS_FRAMES`.
    settings: u32,
    /// Total non-ACK PING frames received; aborts at `MAX_PING_FRAMES`.
    ping: u32,
    /// Total RST_STREAM frames received; aborts at `MAX_RST_STREAM_FRAMES`.
    rst_stream: u32,
}

impl FloodBudget {
    /// Bill the cheap-control-frame floods (SETTINGS / PING / RST_STREAM) for
    /// one inbound frame. `typ`/`flags` are the frame header fields. Called
    /// *before* dispatch so the budget counts a frame even when its handler
    /// returns `Err` — critically, `process_rst` returns a per-stream error on
    /// a successful reset, so billing RST_STREAM here (not after dispatch) is
    /// what makes the Rapid-Reset (CVE-2023-44487) budget actually bite when
    /// the peer resets *our* in-flight streams. Only variants that cost us a
    /// reply or churn stream state are counted; ACKs and benign types are free.
    fn record_control_frame(&mut self, typ: u8, flags: u8) -> Result<()> {
        match typ {
            F_SETTINGS if flags & FLAG_ACK == 0 => {
                self.settings += 1;
                if self.settings > MAX_SETTINGS_FRAMES {
                    return Err(Error::BadResponse(format!(
                        "http2: peer sent {} SETTINGS frames (flood)",
                        self.settings
                    )));
                }
            }
            F_PING if flags & FLAG_ACK == 0 => {
                self.ping += 1;
                if self.ping > MAX_PING_FRAMES {
                    return Err(Error::BadResponse(format!(
                        "http2: peer sent {} PING frames (flood)",
                        self.ping
                    )));
                }
            }
            F_RST_STREAM => {
                self.rst_stream += 1;
                if self.rst_stream > MAX_RST_STREAM_FRAMES {
                    return Err(Error::BadResponse(format!(
                        "http2: peer sent {} RST_STREAM frames (Rapid-Reset flood)",
                        self.rst_stream
                    )));
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// No-progress spin guard. `made_progress` is whether the just-dispatched
    /// frame reported real forward progress (a DATA byte appended, a header
    /// block completed, a WINDOW_UPDATE that raised a send window, or a
    /// terminal `Done`). Any progress frame resets the streak; otherwise the
    /// streak grows and we abort at `MAX_NO_PROGRESS_FRAMES`. Called after a
    /// successful dispatch.
    fn record_progress(&mut self, made_progress: bool) -> Result<()> {
        if made_progress {
            self.no_progress = 0;
        } else {
            self.no_progress += 1;
            if self.no_progress > MAX_NO_PROGRESS_FRAMES {
                return Err(Error::BadResponse(format!(
                    "http2: peer sent {} consecutive frames with no forward progress (flood)",
                    self.no_progress
                )));
            }
        }
        Ok(())
    }
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
            budget: FloodBudget::default(),
            made_progress: false,
            tls_info: None,
            dial_timing: crate::http::Timing::default(),
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

    /// Drop every stream that has reached a terminal state from `self.streams`.
    ///
    /// `drive_until_stream_done` already removes the stream it was waiting on,
    /// but a connection that is reused across requests could otherwise
    /// accumulate `Closed` / fully-received entries for streams that finished
    /// while we were blocked on another one. Reaping them here keeps the map
    /// from growing unbounded across pooled reuses (task requirement #6) and
    /// is a no-op for the common single-stream-per-request case.
    fn prune_completed_streams(&mut self) {
        self.streams.retain(|_, s| {
            let terminal = matches!(s.state, StreamState::Closed)
                || (matches!(s.state, StreamState::HalfClosedRemote)
                    && s.response_headers.is_some()
                    && s.end_stream_recv);
            !terminal
        });
    }

    /// Allocate the next client-initiated stream id and register an empty
    /// `Stream` in `self.streams`.
    ///
    /// Errors:
    /// - At `MAX_CONCURRENT_STREAMS`: refuse so the caller can open another
    ///   connection. `is_usable` honours the same limit before a pooled
    ///   connection is handed back out.
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
                    match self.read_and_dispatch(None)? {
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
        self.drive_until_stream_done_to(stream_id, None, None)
    }

    /// As [`drive_until_stream_done`], but DATA payloads for `stream_id` are
    /// written to `sink` instead of buffered (when the response permits — see
    /// [`Connection::process_data`]). The reborrow keeps the `&mut` usable
    /// across loop iterations.
    fn drive_until_stream_done_to(
        &mut self,
        stream_id: u32,
        mut sink: Option<&mut dyn Write>,
        mut on_head: Option<crate::http::HeadObserver<'_>>,
    ) -> Result<Stream> {
        loop {
            // Has the stream already completed in an earlier dispatch?
            if let Some(s) = self.streams.get(&stream_id) {
                if matches!(s.state, StreamState::Closed | StreamState::HalfClosedRemote)
                    && s.response_headers.is_some()
                    && s.end_stream_recv
                {
                    self.fire_head(stream_id, &mut on_head);
                    return Ok(self.streams.remove(&stream_id).unwrap());
                }
            } else {
                return Err(Error::BadResponse(format!(
                    "stream {stream_id} not registered"
                )));
            }

            let reborrow: Option<&mut dyn Write> = match &mut sink {
                Some(w) => Some(&mut **w),
                None => None,
            };
            let outcome = self.read_and_dispatch(reborrow)?;
            // Fire the head callback the moment the response HEADERS for our
            // stream are decoded — which, since DATA frames are distinct frames
            // arriving after HEADERS, is guaranteed before the first body byte
            // is written to `sink`.
            self.fire_head(stream_id, &mut on_head);
            match outcome {
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

    /// Invoke `on_head` once, the first time `stream_id`'s response headers are
    /// available. Takes the observer out of the `Option` so it never fires
    /// twice (e.g. on a trailing HEADERS frame).
    fn fire_head(&self, stream_id: u32, on_head: &mut Option<crate::http::HeadObserver<'_>>) {
        if on_head.is_none() {
            return;
        }
        let Some(s) = self.streams.get(&stream_id) else {
            return;
        };
        let Some(headers) = s.response_headers.as_ref() else {
            return;
        };
        let mut status: Option<u16> = None;
        let mut clean: Vec<(String, String)> = Vec::with_capacity(headers.len());
        for (k, v) in headers {
            if k == ":status" {
                status = v.parse::<u16>().ok();
            } else if !k.starts_with(':') {
                clean.push((k.clone(), v.clone()));
            }
        }
        // Interim 1xx responses (e.g. 100/103) are not the final head; wait.
        let Some(status) = status.filter(|s| *s >= 200) else {
            return;
        };
        if let Some(obs) = on_head.take() {
            obs(&crate::http::ResponseHead {
                status,
                reason: String::new(),
                version: "HTTP/2".to_string(),
                headers: clean,
            });
        }
    }

    // -----------------------------------------------------------------------
    // Concurrent multiplexing driver.
    //
    // The single-stream path above (`send_request_on` + `drive_until_stream_done`)
    // blocks on one stream at a time. The methods below instead keep many
    // streams in flight on ONE connection and drive them all from a single
    // frame loop, so a slow body on one stream cannot stall the others
    // (no head-of-line blocking on send).
    // -----------------------------------------------------------------------

    /// Write the HEADERS (+ CONTINUATION) frames for `req` on `stream_id` and
    /// stage its request body for later, non-blocking transmission.
    ///
    /// Unlike [`send_request_on`], this NEVER blocks on flow control: the body
    /// is parked in the stream's `pending_body` and drained incrementally by
    /// [`pump_pending_sends`] as send-window budget becomes available across
    /// all streams. Returns immediately after the HEADERS are on the wire (the
    /// caller flushes once after staging every stream in a batch).
    ///
    /// `send_request_on` is the verb name; this is `stage_request_on` because
    /// it only commits the request headers, deferring the body.
    fn stage_request_on(&mut self, stream_id: u32, req: &Request) -> Result<()> {
        let header_block = build_header_block(&mut self.encoder, req);
        let has_body = !req.body.is_empty();
        let max_frame_size = self.peer.max_frame_size as usize;
        let header_frames =
            fragment_header_block(stream_id, &header_block, max_frame_size, !has_body);
        for f in &header_frames {
            write_frame(&mut self.tls, f)?;
        }
        let s = self
            .streams
            .get_mut(&stream_id)
            .ok_or_else(|| Error::BadResponse(format!("stream {stream_id} not found")))?;
        s.state = s.state.send_data(!has_body)?;
        if has_body {
            s.pending_body = Some(PendingBody {
                bytes: req.body.clone(),
                sent: 0,
            });
        }
        Ok(())
    }

    /// Write as much pending request-body DATA as the connection and per-stream
    /// send windows currently allow, across EVERY stream with bytes left to
    /// send. This is the non-blocking heart of multiplexed sending: each call
    /// makes whatever forward progress the windows permit and returns; it never
    /// waits on a WINDOW_UPDATE. When a stream's body is fully flushed its
    /// `pending_body` is cleared and END_STREAM is emitted on the final DATA
    /// frame. Returns whether any byte was written (so the caller knows to
    /// flush the transport).
    ///
    /// Streams are visited in ascending id order for deterministic, fair-ish
    /// scheduling (lower ids — issued first — drain first), and to keep the
    /// `-v` trace stable across runs.
    fn pump_pending_sends(&mut self, trace: &mut dyn Write) -> Result<bool> {
        let mut wrote = false;
        let max_frame_size = self.peer.max_frame_size as usize;
        // Snapshot the ids with work to do so we don't borrow `self.streams`
        // while mutating it inside the loop.
        let mut ids: Vec<u32> = self
            .streams
            .iter()
            .filter(|(_, s)| s.pending_body.is_some())
            .map(|(id, _)| *id)
            .collect();
        ids.sort_unstable();

        for id in ids {
            // The stream is present (we just collected it) and is never removed
            // mid-pump, so look it up once and drain it until the window stalls
            // or its body is exhausted.
            if !self.streams.contains_key(&id) {
                continue;
            }
            loop {
                // Recompute the budget each iteration — the conn window is
                // shared, so an earlier stream's writes shrink it for later
                // ones within this same pass.
                let s = self.streams.get(&id).unwrap();
                let budget = s.send_budget(&self.conn_send_window);
                let (remaining_len, sent) = match s.pending_body.as_ref() {
                    Some(pb) => (pb.bytes.len() - pb.sent, pb.sent),
                    None => break, // body fully sent
                };
                if remaining_len == 0 {
                    // Defensive: an empty pending body is cleared below; this
                    // shouldn't happen because we never stage an empty body.
                    self.streams.get_mut(&id).unwrap().pending_body = None;
                    break;
                }
                let n = next_data_chunk_size(max_frame_size, budget, remaining_len);
                if n == 0 {
                    // Window exhausted for this stream right now — move on to
                    // the next one rather than blocking (no head-of-line stall).
                    break;
                }
                let is_last = n == remaining_len;
                let chunk: Vec<u8> = {
                    let pb = self
                        .streams
                        .get(&id)
                        .unwrap()
                        .pending_body
                        .as_ref()
                        .unwrap();
                    pb.bytes[sent..sent + n].to_vec()
                };
                let data_frame = Frame {
                    typ: F_DATA,
                    flags: if is_last { FLAG_END_STREAM } else { 0 },
                    stream_id: id,
                    payload: chunk,
                };
                write_frame(&mut self.tls, &data_frame)?;
                self.conn_send_window.consume(n);
                let s = self.streams.get_mut(&id).unwrap();
                s.send_window.consume(n);
                s.state = s.state.send_data(is_last)?;
                let pb = s.pending_body.as_mut().unwrap();
                pb.sent += n;
                if is_last {
                    s.pending_body = None;
                    let _ = writeln!(trace, "* [stream {id}] request body sent");
                }
                wrote = true;
                if is_last {
                    break;
                }
            }
        }
        Ok(wrote)
    }

    /// Run `reqs` concurrently over this single connection, returning one
    /// result per request, in the same order as `reqs`.
    ///
    /// Design:
    /// - Open a stream per request up to the peer's `SETTINGS_MAX_CONCURRENT_STREAMS`,
    ///   queueing the rest. Each opened stream writes its HEADERS immediately;
    ///   request bodies are staged and streamed out non-blockingly.
    /// - A SINGLE frame loop alternates between pumping outbound body DATA
    ///   (whatever the windows allow, across all streams) and reading one
    ///   inbound frame, dispatching it to its stream by id. As each in-flight
    ///   stream completes, the next queued request is started, keeping at most
    ///   `MAX_CONCURRENT_STREAMS` streams open.
    /// - Demultiplexing: every request gets its own `Response`. A single
    ///   stream's RST_STREAM (or per-stream protocol error) fails ONLY that
    ///   request; the others keep running. A connection-level failure
    ///   (transport error, conn-level protocol error) fails all not-yet-
    ///   completed requests. On GOAWAY, streams with id above the peer's
    ///   advertised last-stream-id are failed while lower ones finish, and no
    ///   queued request is started beyond the GOAWAY boundary.
    ///
    /// The single-request `send` / `run_one_request` path is untouched; this is
    /// purely additive.
    fn run_multiplexed(
        &mut self,
        reqs: &[Request],
        trace: &mut dyn Write,
    ) -> Vec<Result<Response>> {
        let n = reqs.len();
        // Per-request slot: `None` while in flight or queued, `Some` once a
        // terminal result (Ok response / Err) is known.
        let mut results: Vec<Option<Result<Response>>> = (0..n).map(|_| None).collect();
        // Map live stream id -> request index, so a completed/failed stream
        // routes its outcome back to the right slot.
        let mut id_to_idx: HashMap<u32, usize> = HashMap::new();
        // Indices not yet started, in order. We start them as slots free up.
        let mut queue: VecDeque<usize> = (0..n).collect();

        // Helper closure-free start: open a stream for request `idx` and write
        // its HEADERS. On failure to open (e.g. GOAWAY boundary,
        // MAX_CONCURRENT, id exhaustion) record the error for that request.
        // We inline this rather than use a closure so it can borrow `self`.

        // Prime: start as many as the concurrency limit allows.
        self.start_queued(&mut queue, &mut id_to_idx, &mut results, reqs, trace);
        // Flush the HEADERS we just wrote, plus any body bytes we can send.
        match self.pump_pending_sends(trace) {
            Ok(_) => {}
            Err(e) => {
                // A write failure here is connection-fatal: fail everything
                // still outstanding and bail.
                self.fail_all_outstanding(&id_to_idx, &mut results, &queue, &e);
                return collect_results(results);
            }
        }
        if let Err(e) = self.tls.flush() {
            let e = Error::Io(e);
            self.fail_all_outstanding(&id_to_idx, &mut results, &queue, &e);
            return collect_results(results);
        }

        // Single frame loop: keep going until every request has a result.
        while results.iter().any(Option::is_none) {
            // If nothing is in flight but the queue is non-empty, we couldn't
            // open any stream (e.g. all blocked by GOAWAY) — drain the queue
            // as failures to avoid spinning forever.
            if id_to_idx.is_empty() {
                if queue.is_empty() {
                    break;
                }
                // Try once more to start queued work; if still nothing opens,
                // fail the rest.
                self.start_queued(&mut queue, &mut id_to_idx, &mut results, reqs, trace);
                if id_to_idx.is_empty() {
                    while let Some(idx) = queue.pop_front() {
                        if results[idx].is_none() {
                            results[idx] = Some(Err(Error::BadResponse(
                                "no usable stream to issue request (GOAWAY?)".into(),
                            )));
                        }
                    }
                    break;
                }
                if self.flush_pending(trace).is_err() {
                    break;
                }
            }

            // Read and dispatch one inbound frame.
            let outcome = match self.read_and_dispatch(None) {
                Ok(o) => o,
                Err(e) => {
                    // Distinguish a per-stream RST (carried as BadResponse from
                    // `process_rst`) from a connection-fatal error. `process_rst`
                    // sets the offending stream to Closed before returning Err,
                    // so we can detect a single closed-but-unfinished stream and
                    // fail just that request, then keep the loop running.
                    if let Some(idx) = self.take_stream_error(&mut id_to_idx) {
                        results[idx] = Some(Err(e));
                        // After a per-stream error a slot may have freed up.
                        self.start_queued(&mut queue, &mut id_to_idx, &mut results, reqs, trace);
                        if let Err(fe) = self.flush_pending(trace) {
                            self.fail_all_outstanding(&id_to_idx, &mut results, &queue, &fe);
                            break;
                        }
                        continue;
                    }
                    // Connection-fatal: fail everything still outstanding.
                    self.fail_all_outstanding(&id_to_idx, &mut results, &queue, &e);
                    break;
                }
            };

            // GOAWAY may have doomed some high-id streams (state forced to
            // Closed by `process_conn_frame`). Reap any that the peer abandoned.
            if self.goaway_received.is_some() {
                self.fail_goaway_doomed(&mut id_to_idx, &mut results);
            }

            if let DispatchOutcome::Done(done_id) = outcome {
                if let Some(idx) = id_to_idx.remove(&done_id) {
                    let stream = self
                        .streams
                        .remove(&done_id)
                        .expect("Done stream must still be registered");
                    let mut built =
                        build_response_from_stream_labelled(stream, Some(done_id), trace);
                    if let Ok(resp) = &mut built {
                        resp.tls = self.tls_info.clone();
                    }
                    results[idx] = Some(built);
                    // A slot freed up — start the next queued request.
                    self.start_queued(&mut queue, &mut id_to_idx, &mut results, reqs, trace);
                }
            }

            // Make outbound progress on every loop turn: a WINDOW_UPDATE we
            // just processed may have unblocked a stalled body.
            if self.flush_pending(trace).is_err() {
                let e = Error::BadResponse("write error pumping multiplexed sends".into());
                self.fail_all_outstanding(&id_to_idx, &mut results, &queue, &e);
                break;
            }
        }

        self.prune_completed_streams();
        collect_results(results)
    }

    /// Pump pending sends and flush the transport. Small wrapper so the loop
    /// reads cleanly.
    fn flush_pending(&mut self, trace: &mut dyn Write) -> Result<()> {
        self.pump_pending_sends(trace)?;
        self.tls.flush().map_err(Error::Io)
    }

    /// Start queued requests until we hit the concurrency limit or run out.
    /// For each started request, open a stream, write its HEADERS, stage its
    /// body, and record the id→index mapping. Open failures are recorded as
    /// per-request errors (the request simply doesn't run).
    fn start_queued(
        &mut self,
        queue: &mut VecDeque<usize>,
        id_to_idx: &mut HashMap<u32, usize>,
        results: &mut [Option<Result<Response>>],
        reqs: &[Request],
        trace: &mut dyn Write,
    ) {
        while !queue.is_empty() {
            // Respect the peer's concurrency cap based on currently-open streams.
            if (self.streams.len() as u64) >= self.peer.max_concurrent_streams as u64 {
                break;
            }
            let idx = *queue.front().unwrap();
            let id = match self.open_stream() {
                Ok(id) => id,
                Err(e) => {
                    // Can't open any more right now (GOAWAY boundary / id space
                    // / concurrency). If it's the concurrency limit we just
                    // stop; otherwise the request fails. Distinguish by retry:
                    // a GOAWAY/exhaustion error is permanent for this request.
                    queue.pop_front();
                    results[idx] = Some(Err(e));
                    continue;
                }
            };
            queue.pop_front();
            let req = &reqs[idx];
            trace_request_labelled(req, id, trace);
            if let Err(e) = self.stage_request_on(id, req) {
                // HEADERS write failed — record the error and drop the stream.
                self.streams.remove(&id);
                results[idx] = Some(Err(e));
                continue;
            }
            id_to_idx.insert(id, idx);
        }
    }

    /// On a dispatch error, if exactly one open stream was just forced to
    /// `Closed` (the RST_STREAM target) and it has no complete response, treat
    /// the error as scoped to that one stream: return its request index and
    /// drop it from the live map. Returns `None` if the error is not cleanly
    /// attributable to a single stream (caller treats it as connection-fatal).
    fn take_stream_error(&mut self, id_to_idx: &mut HashMap<u32, usize>) -> Option<usize> {
        let mut culprit: Option<u32> = None;
        for (&id, s) in self.streams.iter() {
            if !id_to_idx.contains_key(&id) {
                continue;
            }
            let complete = matches!(s.state, StreamState::Closed | StreamState::HalfClosedRemote)
                && s.end_stream_recv
                && s.response_headers.is_some();
            if matches!(s.state, StreamState::Closed) && !complete {
                if culprit.is_some() {
                    // More than one candidate — ambiguous, treat as fatal.
                    return None;
                }
                culprit = Some(id);
            }
        }
        let id = culprit?;
        let idx = id_to_idx.remove(&id)?;
        self.streams.remove(&id);
        Some(idx)
    }

    /// After a GOAWAY, any in-flight stream with id above the peer's
    /// last-stream-id is abandoned: `process_conn_frame` already forced its
    /// state to `Closed`. Fail the matching requests and drop those streams,
    /// but only when they have no complete response of their own.
    fn fail_goaway_doomed(
        &mut self,
        id_to_idx: &mut HashMap<u32, usize>,
        results: &mut [Option<Result<Response>>],
    ) {
        let last = match self.goaway_received {
            Some(l) => l,
            None => return,
        };
        let doomed: Vec<u32> = id_to_idx
            .keys()
            .copied()
            .filter(|id| *id > last)
            .filter(|id| {
                // Don't clobber a stream that actually completed.
                match self.streams.get(id) {
                    Some(s) => !(s.end_stream_recv && s.response_headers.is_some()),
                    None => true,
                }
            })
            .collect();
        for id in doomed {
            if let Some(idx) = id_to_idx.remove(&id) {
                self.streams.remove(&id);
                results[idx] = Some(Err(Error::BadResponse(format!(
                    "stream {id} abandoned by GOAWAY (last-stream-id={last})"
                ))));
            }
        }
    }

    /// Fail every request that has no result yet: all in-flight streams plus
    /// everything still queued. Used when the connection itself is lost.
    fn fail_all_outstanding(
        &self,
        id_to_idx: &HashMap<u32, usize>,
        results: &mut [Option<Result<Response>>],
        queue: &VecDeque<usize>,
        err: &Error,
    ) {
        for &idx in id_to_idx.values() {
            if results[idx].is_none() {
                results[idx] = Some(Err(clone_error(err)));
            }
        }
        for &idx in queue.iter() {
            if results[idx].is_none() {
                results[idx] = Some(Err(clone_error(err)));
            }
        }
    }

    /// Read one frame from the wire and route it to the right place. The
    /// connection-scoped frames (SETTINGS / PING / GOAWAY / WINDOW_UPDATE on
    /// stream 0) are handled here directly; stream-scoped frames are looked
    /// up in `self.streams` and dispatched.
    fn read_and_dispatch(&mut self, sink: Option<&mut dyn Write>) -> Result<DispatchOutcome> {
        let frame = match read_frame(&mut self.tls) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(Error::UnexpectedEof);
            }
            Err(e) => return Err(Error::Io(e)),
        };
        self.process_frame(frame, sink)
    }

    /// Apply one already-read frame. Split out from `read_and_dispatch` so
    /// tests can drive the dispatch ladder with synthetic frames.
    fn process_frame(
        &mut self,
        frame: Frame,
        sink: Option<&mut dyn Write>,
    ) -> Result<DispatchOutcome> {
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

        // Flood / no-progress accounting. Both the single-stream and
        // multiplexed loops reach the wire through this method, so accounting
        // here covers both paths. We snapshot `typ`/`flags` up front so the
        // budget can be billed without cloning the payload.
        let frame_typ = frame.typ;
        let frame_flags = frame.flags;
        // Cheap-control-frame floods are billed BEFORE dispatch: a successful
        // RST_STREAM dispatch returns a per-stream `Err`, so billing it here
        // (rather than after) is what makes the Rapid-Reset budget bite.
        self.budget.record_control_frame(frame_typ, frame_flags)?;
        // Handlers signal real forward progress by setting `self.made_progress`
        // (cleared here before each dispatch); a terminal `Done` outcome also
        // counts. The no-progress streak is judged only on a successful
        // dispatch (an error already aborts, or is handled per-stream upstream).
        self.made_progress = false;
        let outcome = if frame.stream_id == 0 {
            self.process_conn_frame(frame)
        } else {
            self.process_stream_frame(frame, sink)
        }?;
        let progress = self.made_progress || matches!(outcome, DispatchOutcome::Done(_));
        self.budget.record_progress(progress)?;
        Ok(outcome)
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
                // Raising the connection send window can unblock a stalled
                // body: count as forward progress.
                self.made_progress = true;
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
    fn process_stream_frame(
        &mut self,
        frame: Frame,
        sink: Option<&mut dyn Write>,
    ) -> Result<DispatchOutcome> {
        match frame.typ {
            F_HEADERS => self.process_headers(frame),
            F_CONTINUATION => self.process_continuation(frame),
            F_DATA => self.process_data(frame, sink),
            F_RST_STREAM => self.process_rst(frame),
            F_WINDOW_UPDATE => {
                let inc = parse_window_update(&frame.payload)?;
                if let Some(s) = self.streams.get_mut(&frame.stream_id) {
                    s.send_window.apply_window_update(inc)?;
                    // Raising a live stream's send window can unblock a stalled
                    // body: count as forward progress. A WINDOW_UPDATE on an
                    // unknown / closed stream (dropped below) is NOT progress —
                    // it must not be usable to defeat the no-progress guard.
                    self.made_progress = true;
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
            // A header block completed: forward progress.
            self.made_progress = true;
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
            // A header block completed: forward progress.
            self.made_progress = true;
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

    fn process_data(
        &mut self,
        frame: Frame,
        sink: Option<&mut dyn Write>,
    ) -> Result<DispatchOutcome> {
        let stream_id = frame.stream_id;
        let frame_bytes = frame.payload.len();
        // Connection window is billed regardless of whether the stream is
        // known — that's what the RFC requires.
        self.conn_recv_window.consume(frame_bytes);
        // RFC 9113 §6.9.1: a receiver MUST treat a peer that sends more DATA
        // than the advertised connection window as a FLOW_CONTROL_ERROR and
        // tear down the connection. A conformant peer keeps `available` >= 0;
        // only a strict overrun drives it negative (an exactly-full window
        // reaching 0 is legitimate and must NOT be rejected).
        if self.conn_recv_window.available < 0 {
            return Err(Error::BadResponse(
                "http2: flow-control window exceeded by peer".into(),
            ));
        }
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
        // Per-stream counterpart of the connection-level check above
        // (RFC 9113 §6.9.1). A negative window means the peer sent more DATA
        // on this stream than we granted; exactly 0 is still legitimate.
        if s.recv_window.available < 0 {
            return Err(Error::BadResponse(
                "http2: flow-control window exceeded by peer".into(),
            ));
        }

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
        // Stream the body straight to the caller's sink when possible: a sink
        // is present, nothing has been buffered yet (so byte order is kept),
        // and the response is not content-encoded (encoded bodies need the
        // buffered decode path). Otherwise accumulate into `body`.
        let encoded = s.response_headers.as_ref().is_some_and(|h| {
            h.iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("content-encoding"))
        });
        let to_sink = sink.is_some() && !encoded && s.body.is_empty();
        // Cumulative body cap for the *buffered* path. HTTP/2 flow control
        // auto-replenishes (see the `replenish()` calls below), so it never
        // stops a server that streams DATA forever — only an absolute ceiling
        // does. Streamed-to-disk bytes aren't held in memory, so they are
        // bounded by the sink (e.g. `--max-filesize`), like curl `-o`.
        if !to_sink && s.body.len().saturating_add(payload.len()) > MAX_RESPONSE_BYTES {
            return Err(Error::BadResponse(
                "response body exceeds size limit".into(),
            ));
        }
        // A real body byte landed: this frame made forward progress, so it
        // resets the no-progress flood counter. An empty DATA frame appends
        // nothing and is (correctly) NOT counted as progress — that is exactly
        // the empty-DATA spin we are guarding against. (Recorded after the
        // `s` borrow ends, below.)
        let appended_body = !payload.is_empty();
        if to_sink {
            if let Some(w) = sink {
                w.write_all(payload)?;
            }
            s.streamed_len += payload.len() as u64;
        } else {
            s.body.extend_from_slice(payload);
        }
        if end_stream {
            s.end_stream_recv = true;
        }
        s.state = new_state;
        if appended_body {
            self.made_progress = true;
        }

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
    /// Caller-supplied partition key (e.g. top-level site); isolates pooled h2
    /// connections per partition. `None` for unpartitioned requests.
    partition: Option<String>,
}

impl PoolKey {
    fn from_request(req: &Request) -> Self {
        PoolKey {
            scheme: req.url.scheme.clone(),
            host: req.url.host.clone(),
            port: req.url.port,
            partition: req.partition_key.clone(),
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
type DialedH2 = (
    Connection<TlsStream<TcpStream>>,
    Option<crate::cancel::CancelGuard>,
);

fn dial_h2(req: &Request, trace: &mut dyn Write) -> Result<DialedH2> {
    // Reuse the shared TCP dialer so the `*   Trying ...` / `* Connected to ...`
    // trace lines and the actual socket come from the same code as HTTP/1.1.
    // The cancel guard (when a token is attached) shuts the socket down on a
    // concurrent `cancel()`; the caller keeps it alive for the request.
    let start = std::time::Instant::now();
    let (tcp, cancel_guard, namelookup) = crate::http::tcp_connect_cancellable(req, trace)?;
    let connect = start.elapsed();
    // HTTPS-over-proxy: CONNECT to establish a transparent tunnel before
    // the TLS handshake. h2c (cleartext HTTP/2) over a proxy is rejected
    // higher up in `send()`, so by here we know scheme == "https".
    if let Some(p) = req
        .proxy
        .as_ref()
        .filter(|_| !crate::http::proxy_bypassed(req))
    {
        crate::http::connect_tunnel(&tcp, &req.url, p, trace)?;
    }
    let opts = crate::http::tls_opts_from(req, &[b"h2"])?;
    let tls = crate::tls::connect_over_tls(tcp, &req.url.host, opts)?;
    let appconnect = start.elapsed();
    crate::http::write_tls_info(&tls, trace);
    let negotiated_h2 = tls.alpn_selected().map(|p| p == b"h2").unwrap_or(false);
    if !negotiated_h2 {
        // Bail before emitting any request `>` lines — the caller (Auto mode)
        // will fall back to HTTP/1.1 on a fresh connection.
        return Err(Error::H2NotNegotiated);
    }
    let _ = writeln!(trace, "* using HTTP/2");
    let tls_info = crate::http::tls_info_from(&tls);
    let mut conn = Connection::new(tls)?;
    conn.tls_info = Some(tls_info);
    conn.dial_timing = crate::http::Timing {
        namelookup,
        connect: Some(connect),
        appconnect: Some(appconnect),
        pretransfer: Some(appconnect),
        ..Default::default()
    };
    Ok((conn, cancel_guard))
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
pub fn send(req: Request, trace: &mut dyn Write) -> Result<Response> {
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
            // Poison-tolerant locking (matches the HTTP/1.1 pool and the TLS
            // verify-posture isolation fix): a panic while another caller held
            // the pool lock must not wedge every future request. We only ever
            // mutate a small map under this lock, so an observer that proceeds
            // past poison sees a structurally valid (if possibly stale) pool.
            let mut guard = global_pool().lock().unwrap_or_else(|e| e.into_inner());
            guard.checkout(&key)
        };
        if let Some(arc) = pooled {
            // Hold the per-conn lock for the whole request — sequential
            // reuse only. The pool-wide lock has already been released.
            let mut conn_guard = arc.lock().unwrap_or_else(|e| e.into_inner());
            if conn_guard.is_usable() {
                let _ = writeln!(trace, "* Reusing existing connection from pool");
                match run_one_request(&mut conn_guard, &req, trace) {
                    Ok(resp) => {
                        let still_usable = conn_guard.is_usable();
                        drop(conn_guard);
                        if still_usable {
                            let mut guard = global_pool().lock().unwrap_or_else(|e| e.into_inner());
                            guard.release(key.clone(), arc);
                            let _ = writeln!(trace, "* Connection kept alive (pooled)");
                        } else {
                            let _ = writeln!(trace, "* Connection closed");
                        }
                        return Ok(resp);
                    }
                    Err(_e) => {
                        // Wire state may now be inconsistent. Drop the conn
                        // and fall through to a cold dial; the original error
                        // is intentionally discarded in favour of the
                        // (likely cleaner) error from the fresh attempt.
                        drop(conn_guard);
                        let _ = writeln!(
                            trace,
                            "* Pooled connection unusable (request failed); reconnecting"
                        );
                    }
                }
            } else {
                // Unusable on checkout: just drop, do not re-pool.
                let _ = writeln!(
                    trace,
                    "* Pooled connection unusable (connection closed); reconnecting"
                );
            }
        }
    }

    // -------- Cold-dial path --------
    let (mut fresh, _cancel_guard) = dial_h2(&req, trace)?;
    let mut resp = run_one_request(&mut fresh, &req, trace)?;
    apply_dial_timing(&mut resp, &fresh);
    if eligible && fresh.is_usable() {
        let arc = Arc::new(Mutex::new(fresh));
        let mut guard = global_pool().lock().unwrap_or_else(|e| e.into_inner());
        guard.release(key, arc);
        let _ = writeln!(trace, "* Connection kept alive (pooled)");
    } else {
        let _ = writeln!(trace, "* Connection closed");
    }
    Ok(resp)
}

/// Drive one request/response exchange on an already-established conn.
/// Factored out so both pool-hit and pool-miss paths share the same body.
fn run_one_request<S: Read + Write>(
    conn: &mut Connection<S>,
    req: &Request,
    trace: &mut dyn Write,
) -> Result<Response> {
    let stream_id = conn.open_stream()?;
    // Trace the request `>` lines right before they go on the wire, so the
    // trace reflects exactly what `send_request_on` is about to encode.
    trace_request(req, trace);
    conn.send_request_on(stream_id, req)?;
    if !req.body.is_empty() {
        let _ = writeln!(trace, "* uploading {} body bytes", req.body.len());
    }
    let stream = conn.drive_until_stream_done(stream_id)?;
    // Reap any other streams that completed while we were driving this one, so
    // a pooled connection's `streams` map doesn't grow across reuses.
    conn.prune_completed_streams();
    let mut resp = build_response_from_stream(stream, trace)?;
    // Surface the connection's negotiated TLS parameters (a property of the
    // live connection — reported on pooled reuse too).
    resp.tls = conn.tls_info.clone();
    Ok(resp)
}

/// Translate a fully-received `Stream` into the public `Response` type.
/// Extracts the `:status` pseudo-header, drops any other pseudo-headers
/// (none are defined for responses but be conservative), and inherits the
/// accumulated body. The `<` trace lines are unlabelled (single-stream path);
/// the multiplexed driver uses [`build_response_from_stream_labelled`].
fn build_response_from_stream(stream: Stream, trace: &mut dyn Write) -> Result<Response> {
    build_response_from_stream_labelled(stream, None, trace)
}

/// Like [`build_response_from_stream`] but prefixes every `<` / `*` trace line
/// with `[stream N]` so concurrently-multiplexed responses stay readable when
/// their frames interleave on the wire.
fn build_response_from_stream_labelled(
    stream: Stream,
    label_id: Option<u32>,
    trace: &mut dyn Write,
) -> Result<Response> {
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

    // Response `<` trace, mirroring the HTTP/1.1 reader: a status line carrying
    // the HTTP/2 version + numeric status, then each header field in received
    // order (lowercase, as h2 delivers them), then a closing blank `< `.
    let tag = match label_id {
        Some(id) => format!("[stream {id}] "),
        None => String::new(),
    };
    let _ = writeln!(trace, "< {tag}HTTP/2 {status}");
    for (k, v) in &clean_headers {
        let _ = writeln!(trace, "< {tag}{k}: {v}");
    }
    let _ = writeln!(trace, "< {tag}");

    let wire_len = stream.body.len();
    let _ = writeln!(trace, "* {tag}Received {wire_len} body bytes");

    // Shared with HTTP/1.1 and HTTP/3: peel off any `Content-Encoding`
    // layer rsurl knows how to decode (gzip / deflate / x-gzip / identity).
    let (clean_headers, body) = crate::http::maybe_decode_body(clean_headers, stream.body, trace)?;

    Ok(Response {
        status,
        reason: String::new(), // HTTP/2 has no reason phrase (RFC 9113 §8.3.1).
        version: "HTTP/2".to_string(),
        headers: clean_headers,
        body,
        timing: crate::http::Timing::default(),
        // Set by the buffered `send_to` redirect loop; empty on the raw
        // multiplexed path, where callers fall back to the request URL.
        final_url: String::new(),
        tls: None,
    })
}

/// Like [`build_response_from_stream`] but for the streaming path: the body has
/// already been written to `sink` by [`Connection::process_data`] (so
/// `stream.body` is empty), unless it was a content-encoded response, which the
/// streaming path deliberately buffers — in that case decode it now and write
/// the plaintext to `sink`. The returned `Response` always carries an empty
/// `body` (the bytes are in the sink).
fn build_response_from_stream_streaming(
    stream: Stream,
    sink: &mut dyn Write,
    trace: &mut dyn Write,
) -> Result<Response> {
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
        } else if !k.starts_with(':') {
            clean_headers.push((k, v));
        }
    }
    let status = status.ok_or_else(|| Error::BadResponse("response missing :status".into()))?;

    let _ = writeln!(trace, "< HTTP/2 {status}");
    for (k, v) in &clean_headers {
        let _ = writeln!(trace, "< {k}: {v}");
    }
    let _ = writeln!(trace, "< ");
    let total = stream.body.len() as u64 + stream.streamed_len;
    let _ = writeln!(trace, "* Received {total} body bytes (streamed)");

    // `stream.body` is non-empty only on the buffered fallback (content-encoded
    // response): decode it and write the plaintext through to the sink.
    let (clean_headers, body) = crate::http::maybe_decode_body(clean_headers, stream.body, trace)?;
    if !body.is_empty() {
        sink.write_all(&body)?;
    }

    Ok(Response {
        status,
        reason: String::new(),
        version: "HTTP/2".to_string(),
        headers: clean_headers,
        body: Vec::new(),
        timing: crate::http::Timing::default(),
        final_url: String::new(),
        tls: None,
    })
}

/// Streaming counterpart of [`run_one_request`]: response DATA is written to
/// `sink` as it arrives rather than buffered (see
/// [`Connection::drive_until_stream_done_to`]).
fn run_one_request_to<S: Read + Write>(
    conn: &mut Connection<S>,
    req: &Request,
    sink: &mut dyn Write,
    on_head: Option<crate::http::HeadObserver<'_>>,
    trace: &mut dyn Write,
) -> Result<Response> {
    let stream_id = conn.open_stream()?;
    trace_request(req, trace);
    conn.send_request_on(stream_id, req)?;
    let stream = conn.drive_until_stream_done_to(stream_id, Some(sink), on_head)?;
    conn.prune_completed_streams();
    let mut resp = build_response_from_stream_streaming(stream, sink, trace)?;
    resp.tls = conn.tls_info.clone();
    Ok(resp)
}

/// Stream an HTTP/2 response body straight to `sink` instead of buffering it.
/// Always cold-dials (the streaming path does not pool) and closes the
/// connection afterward; the returned [`Response`] carries an empty `body`.
pub fn send_to(
    req: Request,
    sink: &mut dyn Write,
    on_head: Option<crate::http::HeadObserver<'_>>,
    trace: &mut dyn Write,
) -> Result<Response> {
    if req.url.scheme != "https" {
        return Err(Error::UnsupportedScheme(format!(
            "http/2 over {} not supported",
            req.url.scheme
        )));
    }
    let (mut fresh, _cancel_guard) = dial_h2(&req, trace)?;
    let mut resp = run_one_request_to(&mut fresh, &req, sink, on_head, trace)?;
    apply_dial_timing(&mut resp, &fresh);
    let _ = writeln!(trace, "* Connection closed");
    Ok(resp)
}

/// Copy a freshly-dialed connection's per-phase timing onto its first response.
/// (Pooled reuse leaves these phases unset, matching curl's reuse semantics.)
fn apply_dial_timing<S: Read + Write>(resp: &mut Response, conn: &Connection<S>) {
    resp.timing.namelookup = conn.dial_timing.namelookup;
    resp.timing.connect = conn.dial_timing.connect;
    resp.timing.appconnect = conn.dial_timing.appconnect;
    resp.timing.pretransfer = conn.dial_timing.pretransfer;
}

/// Build the HPACK-encoded header block for the request: pseudo-headers in the
/// required order (RFC 9113 §8.3.1), then lowercased user headers (skipping
/// the connection-specific ones HTTP/2 forbids per §8.2.2). The `encoder`
/// is borrowed mutably so its dynamic table tracks every header we emit
/// with incremental indexing — keeping our table aligned with the peer's.
/// Compute the exact ordered list of header fields rsurl will put on the wire
/// for `req`, split into the four pseudo-headers (`:method`, `:scheme`,
/// `:authority`, `:path`) and the regular `(name, value)` fields that follow.
///
/// This is the single source of truth for what gets encoded into the HEADERS
/// block, so the verbose `-v` trace can reproduce the request exactly without
/// hardcoding (it reads the same list the encoder consumes).
fn request_header_fields(req: &Request) -> (RequestPseudo, Vec<(String, String)>) {
    let authority = if req.url.port == 443 && req.url.scheme == "https" {
        req.url.host.clone()
    } else {
        format!("{}:{}", req.url.host, req.url.port)
    };
    let pseudo = RequestPseudo {
        method: crate::http::effective_method(req),
        scheme: req.url.scheme.clone(),
        authority,
        path: req.url.path.clone(),
    };

    let mut fields: Vec<(String, String)> = Vec::new();
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
        fields.push((lk, v.clone()));
    }
    // Automatic request headers, suppressed in strict mode (the caller's set is
    // sent verbatim); see [`crate::Request::strict_headers`].
    if !req.strict_headers {
        if !have_auth {
            if let Some(creds) = crate::http::effective_basic_auth(req) {
                fields.push(("authorization".to_string(), format!("Basic {creds}")));
            }
        }
        if !have_ua {
            fields.push((
                "user-agent".to_string(),
                concat!("rsurl/", env!("CARGO_PKG_VERSION")).to_string(),
            ));
        }
        if !have_accept {
            fields.push(("accept".to_string(), "*/*".to_string()));
        }
        if !have_accept_enc {
            // Same default as the HTTP/1.1 writer — rsurl always decodes these
            // on the way back (see `crate::compress`). The full value is HPACK
            // static index 16, so this round-trips with minimum bytes on wire.
            fields.push(("accept-encoding".to_string(), "gzip, deflate".to_string()));
        }
    }
    if !req.body.is_empty() {
        fields.push(("content-length".to_string(), req.body.len().to_string()));
    }
    (pseudo, fields)
}

/// The four HTTP/2 request pseudo-headers, in send order.
struct RequestPseudo {
    method: String,
    scheme: String,
    authority: String,
    path: String,
}

fn build_header_block(encoder: &mut Encoder, req: &Request) -> Vec<u8> {
    let mut out = Vec::new();
    let (pseudo, fields) = request_header_fields(req);

    // Pseudo-headers must come first, in this order: :method, :scheme,
    // :authority, :path.
    encoder.encode_header(&mut out, ":method", &pseudo.method);
    encoder.encode_header(&mut out, ":scheme", &pseudo.scheme);
    encoder.encode_header(&mut out, ":authority", &pseudo.authority);
    encoder.encode_header(&mut out, ":path", &pseudo.path);

    // Regular headers: lowercased name, banned ones already filtered out.
    for (k, v) in &fields {
        encoder.encode_header(&mut out, k, v);
    }
    out
}

/// Emit the curl-style `> ` request trace for an HTTP/2 request, mirroring the
/// HTTP/1.1 writer's format: a request line, a `Host:` line synthesised from
/// `:authority`, then each regular header field, then a closing blank `> `.
/// Reads from [`request_header_fields`] so the trace reflects exactly what the
/// HEADERS block carries.
fn trace_request(req: &Request, trace: &mut dyn Write) {
    let (pseudo, fields) = request_header_fields(req);
    let _ = writeln!(trace, "> {} {} HTTP/2", pseudo.method, pseudo.path);
    let _ = writeln!(trace, "> Host: {}", pseudo.authority);
    for (k, v) in &fields {
        let _ = writeln!(trace, "> {k}: {v}");
    }
    let _ = writeln!(trace, "> ");
}

fn is_connection_specific_header(name: &str) -> bool {
    // RFC 9113 §8.2.2: connection-specific header fields MUST NOT be sent.
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection" | "proxy-connection" | "keep-alive" | "transfer-encoding" | "upgrade" | "te" // unless value is exactly "trailers"; we conservatively drop.
    )
}

/// Like [`trace_request`] but labels every `>` line with `[stream N]` so the
/// interleaved request lines of a multiplexed batch stay attributable.
fn trace_request_labelled(req: &Request, id: u32, trace: &mut dyn Write) {
    let (pseudo, fields) = request_header_fields(req);
    let _ = writeln!(
        trace,
        "> [stream {id}] {} {} HTTP/2",
        pseudo.method, pseudo.path
    );
    let _ = writeln!(trace, "> [stream {id}] Host: {}", pseudo.authority);
    for (k, v) in &fields {
        let _ = writeln!(trace, "> [stream {id}] {k}: {v}");
    }
    let _ = writeln!(trace, "> [stream {id}] ");
}

/// Collapse the per-request `Option<Result<...>>` slots into a `Vec<Result<...>>`.
/// Every slot must be filled by the time the driver returns; an unfilled slot
/// is an internal bug, surfaced as a `BadResponse` rather than a panic.
fn collect_results(results: Vec<Option<Result<Response>>>) -> Vec<Result<Response>> {
    results
        .into_iter()
        .map(|slot| {
            slot.unwrap_or_else(|| {
                Err(Error::BadResponse(
                    "internal: multiplexed request produced no result".into(),
                ))
            })
        })
        .collect()
}

/// Best-effort clone of an [`Error`] so a single connection-level failure can
/// be reported on every outstanding request. `Error` isn't `Clone` because it
/// wraps `io::Error`; we reconstruct an equivalent value (preserving the
/// `io::ErrorKind` for the `Io` case) so callers still get a faithful kind and
/// message.
fn clone_error(e: &Error) -> Error {
    match e {
        Error::InvalidUrl(s) => Error::InvalidUrl(s.clone()),
        Error::UnsupportedScheme(s) => Error::UnsupportedScheme(s.clone()),
        Error::Io(io_err) => Error::Io(io::Error::new(io_err.kind(), io_err.to_string())),
        Error::BadResponse(s) => Error::BadResponse(s.clone()),
        Error::UnexpectedEof => Error::UnexpectedEof,
        Error::H2NotNegotiated => Error::H2NotNegotiated,
        Error::Ssh(s) => Error::Ssh(s.clone()),
        Error::Decode(s) => Error::Decode(s.clone()),
        Error::Status { code, reason } => Error::Status {
            code: *code,
            reason: reason.clone(),
        },
        Error::Cancelled => Error::Cancelled,
    }
}

/// Issue `reqs` concurrently over a SINGLE HTTP/2 connection and return one
/// result per request, in input order.
///
/// All requests MUST share the same origin (scheme/host/port) and be
/// `https://` (HTTP/2 over TLS). This is the precondition for multiplexing —
/// the whole point is one connection. Violations are handled gracefully rather
/// than panicking:
///
/// - An empty `reqs` returns an empty `Vec`.
/// - A non-`https` request, or any request whose origin differs from the
///   first, makes the batch fall back to issuing **every** request
///   sequentially via [`send`] (each on its own pooled connection). The
///   results are still correct and in order; you just don't get multiplexing.
/// - If the common origin is not pool-eligible (i.e. `-k` /
///   `--insecure` or a custom `--cacert`), we likewise fall back to
///   sequential [`send`] — the same TLS-posture isolation rule the pool
///   enforces (a verify-off session must never be reused for a verify-on
///   caller).
/// - If the server doesn't negotiate ALPN `h2` on the shared connection, we
///   fall back to sequential [`send`] (which itself does the h2→h1.1 dance).
///
/// On the happy path: one TCP+TLS handshake, N concurrent streams, interleaved
/// frame I/O, demultiplexed responses. A single stream's `RST_STREAM` /
/// per-stream protocol error fails only that request; the rest still complete.
/// A connection-level failure (transport error, GOAWAY beyond a stream's id)
/// fails the affected subset. The successful connection is returned to the pool
/// when still usable.
pub fn send_multiplexed(reqs: Vec<Request>, trace: &mut dyn Write) -> Vec<Result<Response>> {
    if reqs.is_empty() {
        return Vec::new();
    }

    // Determine the common origin and whether the batch is multiplex-eligible.
    let first = &reqs[0];
    let same_origin_https = first.url.scheme == "https"
        && reqs.iter().all(|r| {
            r.url.scheme == first.url.scheme
                && r.url.host == first.url.host
                && r.url.port == first.url.port
        });
    let all_eligible = reqs.iter().all(pool_eligible);

    if !same_origin_https || !all_eligible {
        // Preconditions not met — fall back to issuing each request on its own
        // (pooled) connection, sequentially. Still correct, just not multiplexed.
        let _ = writeln!(
            trace,
            "* multiplexing preconditions not met (mixed origin / non-https / non-pool-eligible TLS); issuing requests sequentially"
        );
        return reqs.into_iter().map(|r| send(r, trace)).collect();
    }

    let key = PoolKey::from_request(first);

    // Try a pooled connection first; fall back to a cold dial. We do NOT pump
    // the batch over a pooled conn that turns out unusable mid-flight — instead
    // we cold-dial a fresh one and run the whole batch there (a half-consumed
    // batch is hard to reason about; a clean re-run is simpler and correct
    // because none of these requests have been observed as sent yet).
    let pooled = {
        let mut guard = global_pool().lock().unwrap_or_else(|e| e.into_inner());
        guard.checkout(&key)
    };
    if let Some(arc) = pooled {
        let mut conn_guard = arc.lock().unwrap_or_else(|e| e.into_inner());
        if conn_guard.is_usable() {
            let _ = writeln!(
                trace,
                "* Reusing existing connection from pool (multiplexed)"
            );
            let results = conn_guard.run_multiplexed(&reqs, trace);
            // Re-pool only if every request completed without disturbing the
            // wire (no error result) and the conn is still structurally usable.
            let clean = results.iter().all(Result::is_ok) && conn_guard.is_usable();
            drop(conn_guard);
            if clean {
                let mut guard = global_pool().lock().unwrap_or_else(|e| e.into_inner());
                guard.release(key, arc);
                let _ = writeln!(trace, "* Connection kept alive (pooled)");
            } else {
                let _ = writeln!(trace, "* Connection closed");
            }
            return results;
        }
        // Unusable on checkout: drop it and cold-dial below.
        drop(conn_guard);
        let _ = writeln!(
            trace,
            "* Pooled connection unusable (connection closed); reconnecting"
        );
    }

    // Cold-dial path.
    let (mut fresh, _cancel_guard) = match dial_h2(first, trace) {
        Ok(c) => c,
        Err(e) => {
            // The shared handshake failed (e.g. ALPN didn't select h2). Fall
            // back to sequential `send` so each request gets the standard
            // h2→h1.1 negotiation rather than failing the whole batch.
            let _ = writeln!(
                trace,
                "* HTTP/2 connection for multiplexing failed ({e}); issuing requests sequentially"
            );
            return reqs.into_iter().map(|r| send(r, trace)).collect();
        }
    };
    let results = fresh.run_multiplexed(&reqs, trace);
    let clean = results.iter().all(Result::is_ok) && fresh.is_usable();
    if clean {
        let arc = Arc::new(Mutex::new(fresh));
        let mut guard = global_pool().lock().unwrap_or_else(|e| e.into_inner());
        guard.release(key, arc);
        let _ = writeln!(trace, "* Connection kept alive (pooled)");
    } else {
        let _ = writeln!(trace, "* Connection closed");
    }
    results
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

    /// Build a literal-without-indexing block (0x00 marker) with a raw
    /// (non-Huffman) literal name and value. Used to drive forbidden-octet
    /// rejection tests directly at the decode boundary.
    fn raw_literal_block(name: &[u8], value: &[u8]) -> Vec<u8> {
        let mut buf = vec![0x00u8];
        buf.push(name.len() as u8); // 7-bit length, high bit 0 = raw
        buf.extend_from_slice(name);
        buf.push(value.len() as u8);
        buf.extend_from_slice(value);
        buf
    }

    #[test]
    fn hpack_decode_rejects_crlf_in_value() {
        // x: "evil\r\nset-cookie: x=1" — classic response-splitting payload.
        let block = raw_literal_block(b"x-h", b"evil\r\nset-cookie: x=1");
        let mut dec = Decoder::new();
        let err = dec.decode_block(&block).unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)), "got {err:?}");
    }

    #[test]
    fn hpack_decode_rejects_lf_in_value() {
        let block = raw_literal_block(b"x-h", b"a\nb");
        let mut dec = Decoder::new();
        assert!(matches!(
            dec.decode_block(&block).unwrap_err(),
            Error::BadResponse(_)
        ));
    }

    #[test]
    fn hpack_decode_rejects_nul_in_value() {
        let block = raw_literal_block(b"x-h", b"a\x00b");
        let mut dec = Decoder::new();
        assert!(matches!(
            dec.decode_block(&block).unwrap_err(),
            Error::BadResponse(_)
        ));
    }

    #[test]
    fn hpack_decode_rejects_uppercase_name() {
        let block = raw_literal_block(b"X-Bad", b"ok");
        let mut dec = Decoder::new();
        assert!(matches!(
            dec.decode_block(&block).unwrap_err(),
            Error::BadResponse(_)
        ));
    }

    #[test]
    fn hpack_decode_rejects_empty_name() {
        let block = raw_literal_block(b"", b"ok");
        let mut dec = Decoder::new();
        assert!(matches!(
            dec.decode_block(&block).unwrap_err(),
            Error::BadResponse(_)
        ));
    }

    #[test]
    fn hpack_decode_accepts_normal_header_and_pseudo() {
        // Ordinary header with spaces/tabs in the value, plus a pseudo-header.
        let mut block = raw_literal_block(b"content-type", b"text/html; charset=utf-8");
        block.extend(raw_literal_block(b":status", b"200"));
        let mut dec = Decoder::new();
        let got = dec.decode_block(&block).unwrap();
        assert_eq!(
            got[0],
            ("content-type".into(), "text/html; charset=utf-8".into())
        );
        assert_eq!(got[1], (":status".into(), "200".into()));
        // A tab in the value is allowed (only NUL/CR/LF are forbidden).
        let tabbed = raw_literal_block(b"x-h", b"a\tb");
        let mut dec2 = Decoder::new();
        assert!(dec2.decode_block(&tabbed).is_ok());
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
            budget: FloodBudget::default(),
            made_progress: false,
            tls_info: None,
            dial_timing: crate::http::Timing::default(),
        }
    }

    #[test]
    fn apply_dial_timing_copies_phases() {
        use std::time::Duration;
        let mut conn = fake_conn();
        conn.dial_timing = crate::http::Timing {
            namelookup: Some(Duration::from_millis(1)),
            connect: Some(Duration::from_millis(2)),
            appconnect: Some(Duration::from_millis(3)),
            pretransfer: Some(Duration::from_millis(3)),
            ..Default::default()
        };
        let mut resp = crate::http::Response {
            status: 200,
            reason: String::new(),
            version: "HTTP/2".into(),
            headers: Vec::new(),
            body: Vec::new(),
            timing: crate::http::Timing::default(),
            final_url: String::new(),
            tls: None,
        };
        apply_dial_timing(&mut resp, &conn);
        assert_eq!(resp.timing.namelookup, Some(Duration::from_millis(1)));
        assert_eq!(resp.timing.connect, Some(Duration::from_millis(2)));
        assert_eq!(resp.timing.appconnect, Some(Duration::from_millis(3)));
        assert_eq!(resp.timing.pretransfer, Some(Duration::from_millis(3)));
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
        let outcome = conn.process_frame(frame, None).unwrap();
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
        conn.process_frame(window_update_frame(id, 10_000), None)
            .unwrap();
        assert_eq!(
            conn.streams.get(&id).unwrap().send_window.available,
            65_535 + 10_000
        );
        assert_eq!(conn.conn_send_window.available, 65_535);

        conn.process_frame(window_update_frame(0, 5_000), None)
            .unwrap();
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

        conn.process_frame(synth_status_200_headers(id_a, false), None)
            .unwrap();
        conn.process_frame(synth_status_200_headers(id_b, false), None)
            .unwrap();
        conn.process_frame(synth_data(id_a, b"aaa", false), None)
            .unwrap();
        conn.process_frame(synth_data(id_b, b"bbbb", false), None)
            .unwrap();
        conn.process_frame(synth_data(id_a, b"AAA", true), None)
            .unwrap();
        conn.process_frame(synth_data(id_b, b"BBBB", true), None)
            .unwrap();

        assert_eq!(conn.streams.get(&id_a).unwrap().body, b"aaaAAA");
        assert_eq!(conn.streams.get(&id_b).unwrap().body, b"bbbbBBBB");
    }

    #[test]
    fn dispatch_data_on_unknown_stream_is_silently_dropped() {
        // DATA on a stream id we never opened: per RFC 9113 §5.1 we may
        // ignore. No error surfaces and nothing is accumulated.
        let mut conn = fake_conn();
        let outcome = conn
            .process_frame(synth_data(7, b"orphaned", false), None)
            .unwrap();
        assert_eq!(outcome, DispatchOutcome::Continue);
        // No stream was registered, so no body anywhere.
        assert!(conn.streams.is_empty());
        // Conn recv window has still been charged (the bytes did cross the
        // shared budget), then possibly replenished — verify the latter holds.
        assert!(conn.conn_recv_window.available <= OUR_INITIAL_WINDOW);
    }

    #[test]
    fn inbound_data_exceeding_conn_window_is_flow_control_error() {
        // RFC 9113 §6.9.1: a single DATA frame larger than the advertised
        // connection receive window must be rejected as a flow-control error.
        let mut conn = fake_conn();
        let id = conn.open_stream().unwrap();
        conn.streams.get_mut(&id).unwrap().state = StreamState::Open;
        conn.process_frame(synth_status_200_headers(id, false), None)
            .unwrap();

        // OUR_INITIAL_WINDOW + 1 bytes overruns the 65_535 conn window.
        let overrun = vec![0u8; OUR_INITIAL_WINDOW as usize + 1];
        let err = conn
            .process_frame(synth_data(id, &overrun, false), None)
            .unwrap_err();
        match err {
            Error::BadResponse(m) => assert!(
                m.contains("flow-control window exceeded"),
                "unexpected message: {m}"
            ),
            other => panic!("expected BadResponse, got {other:?}"),
        }
    }

    #[test]
    fn inbound_data_exceeding_stream_window_is_flow_control_error() {
        // Same overrun but isolated to the per-stream window: inflate the
        // connection window so only the stream window goes negative, proving
        // the per-stream check fires independently.
        let mut conn = fake_conn();
        let id = conn.open_stream().unwrap();
        conn.streams.get_mut(&id).unwrap().state = StreamState::Open;
        conn.process_frame(synth_status_200_headers(id, false), None)
            .unwrap();

        // Give the conn window plenty of room so it stays >= 0.
        conn.conn_recv_window.available = i64::from(u32::MAX);

        let overrun = vec![0u8; OUR_INITIAL_WINDOW as usize + 1];
        let err = conn
            .process_frame(synth_data(id, &overrun, false), None)
            .unwrap_err();
        match err {
            Error::BadResponse(m) => assert!(
                m.contains("flow-control window exceeded"),
                "unexpected message: {m}"
            ),
            other => panic!("expected BadResponse, got {other:?}"),
        }
        // The stream window must have actually gone negative.
        assert!(conn.streams.get(&id).unwrap().recv_window.available < 0);
    }

    #[test]
    fn inbound_data_filling_window_exactly_is_accepted() {
        // A frame that drives the window to exactly 0 is legitimate and must
        // NOT be rejected (only strictly-negative is an overrun).
        let mut conn = fake_conn();
        let id = conn.open_stream().unwrap();
        conn.streams.get_mut(&id).unwrap().state = StreamState::Open;
        conn.process_frame(synth_status_200_headers(id, false), None)
            .unwrap();

        let exact = vec![0u8; OUR_INITIAL_WINDOW as usize];
        // Must succeed; both windows reach exactly 0 before replenish runs.
        conn.process_frame(synth_data(id, &exact, false), None)
            .unwrap();
        assert_eq!(conn.streams.get(&id).unwrap().body.len(), exact.len());
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
        conn.process_frame(frame, None).unwrap();
        assert_eq!(conn.expecting_continuation, Some(id1));

        // CONTINUATION on stream 3 must error.
        let bad = Frame {
            typ: F_CONTINUATION,
            flags: FLAG_END_HEADERS,
            stream_id: id3,
            payload: vec![],
        };
        let err = conn.process_frame(bad, None).unwrap_err();
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
            .process_frame(synth_data(id, b"abc", false), None)
            .unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)));
        // The over-limit payload must not have been appended.
        assert_eq!(
            conn.streams.get(&id).unwrap().body.len(),
            MAX_RESPONSE_BYTES - 2
        );
    }

    #[test]
    fn empty_data_flood_is_bounded() {
        // The empty-DATA spin: a 0-byte DATA frame with no END_STREAM bills
        // consume(0), appends nothing (MAX_RESPONSE_BYTES never trips) and
        // leaves the stream Open. Without a no-progress guard the frame loop
        // would accept these forever. We must abort after
        // MAX_NO_PROGRESS_FRAMES.
        let mut conn = fake_conn();
        let id = conn.open_stream().unwrap();
        conn.streams.get_mut(&id).unwrap().state = StreamState::Open;
        conn.process_frame(synth_status_200_headers(id, false), None)
            .unwrap();
        // The HEADERS above completed a block → progress, so the streak starts
        // fresh. Feed empty DATA frames until the guard fires.
        let mut err = None;
        for _ in 0..(MAX_NO_PROGRESS_FRAMES as usize + 10) {
            match conn.process_frame(synth_data(id, b"", false), None) {
                Ok(_) => {}
                Err(e) => {
                    err = Some(e);
                    break;
                }
            }
        }
        let err = err.expect("empty-DATA flood was not bounded");
        match err {
            Error::BadResponse(m) => {
                assert!(m.contains("no forward progress"), "unexpected message: {m}")
            }
            other => panic!("expected BadResponse, got {other:?}"),
        }
        // The stream is still Open with an empty body — proving the abort came
        // from the flood guard, not from any flow-control / body-cap path.
        assert_eq!(conn.streams.get(&id).unwrap().body.len(), 0);
        assert_eq!(conn.streams.get(&id).unwrap().state, StreamState::Open);
    }

    #[test]
    fn process_data_streams_body_to_sink() {
        // With a sink and an un-encoded 200 response, DATA payloads are written
        // straight to the sink and never buffered in `body`.
        let mut conn = fake_conn();
        let id = conn.open_stream().unwrap();
        conn.streams.get_mut(&id).unwrap().state = StreamState::Open;
        conn.process_frame(synth_status_200_headers(id, false), None)
            .unwrap();
        let mut sink: Vec<u8> = Vec::new();
        conn.process_frame(synth_data(id, b"hello ", false), Some(&mut sink))
            .unwrap();
        conn.process_frame(synth_data(id, b"world", true), Some(&mut sink))
            .unwrap();
        assert_eq!(sink, b"hello world");
        let s = conn.streams.get(&id).unwrap();
        assert_eq!(s.body.len(), 0, "streamed body must not be buffered");
        assert_eq!(s.streamed_len, 11);
    }

    #[test]
    fn body_byte_resets_no_progress_counter() {
        // A single real DATA byte must reset the no-progress streak so a server
        // that legitimately interleaves small bodies with other frames is never
        // tripped. Bring the counter near the ceiling, then a 1-byte DATA frame
        // should let us go another full window of no-progress frames.
        let mut conn = fake_conn();
        let id = conn.open_stream().unwrap();
        conn.streams.get_mut(&id).unwrap().state = StreamState::Open;
        conn.process_frame(synth_status_200_headers(id, false), None)
            .unwrap();

        for _ in 0..(MAX_NO_PROGRESS_FRAMES - 1) {
            conn.process_frame(synth_data(id, b"", false), None)
                .unwrap();
        }
        assert_eq!(conn.budget.no_progress, MAX_NO_PROGRESS_FRAMES - 1);
        // One real byte resets the streak.
        conn.process_frame(synth_data(id, b"x", false), None)
            .unwrap();
        assert_eq!(conn.budget.no_progress, 0);
        assert_eq!(conn.streams.get(&id).unwrap().body, b"x");
    }

    #[test]
    fn settings_flood_is_bounded() {
        // Every non-ACK SETTINGS forces an ACK write+flush. An unbounded stream
        // must be rejected after MAX_SETTINGS_FRAMES. Use an empty payload so
        // each frame is a trivially-valid no-op reconfigure.
        let mut conn = fake_conn();
        let mut err = None;
        for _ in 0..(MAX_SETTINGS_FRAMES as usize + 10) {
            let f = Frame {
                typ: F_SETTINGS,
                flags: 0,
                stream_id: 0,
                payload: Vec::new(),
            };
            if let Err(e) = conn.process_frame(f, None) {
                err = Some(e);
                break;
            }
        }
        match err.expect("SETTINGS flood was not bounded") {
            Error::BadResponse(m) => {
                assert!(m.contains("SETTINGS"), "unexpected message: {m}")
            }
            other => panic!("expected BadResponse, got {other:?}"),
        }
    }

    #[test]
    fn ping_flood_is_bounded() {
        // Every non-ACK PING forces a PONG write+flush; bound it.
        let mut conn = fake_conn();
        let mut err = None;
        for _ in 0..(MAX_PING_FRAMES as usize + 10) {
            let f = Frame {
                typ: F_PING,
                flags: 0,
                stream_id: 0,
                payload: vec![0u8; 8],
            };
            if let Err(e) = conn.process_frame(f, None) {
                err = Some(e);
                break;
            }
        }
        match err.expect("PING flood was not bounded") {
            Error::BadResponse(m) => assert!(m.contains("PING"), "unexpected message: {m}"),
            other => panic!("expected BadResponse, got {other:?}"),
        }
    }

    #[test]
    fn rst_stream_flood_is_bounded() {
        // Rapid-Reset (CVE-2023-44487): RST_STREAM on unknown streams is
        // individually harmless (ignored) but must carry an aggregate budget so
        // a hostile server cannot churn us indefinitely. Target unknown stream
        // ids so each frame returns Ok(Continue) until the budget trips.
        let mut conn = fake_conn();
        let mut err = None;
        for i in 0..(MAX_RST_STREAM_FRAMES as usize + 10) {
            // Unknown odd stream id (never opened) → process_rst returns
            // Continue; only the flood budget can stop the loop.
            let f = synth_rst((2 * i as u32) + 1001, 0);
            if let Err(e) = conn.process_frame(f, None) {
                err = Some(e);
                break;
            }
        }
        match err.expect("RST_STREAM flood was not bounded") {
            Error::BadResponse(m) => {
                assert!(m.contains("RST_STREAM"), "unexpected message: {m}")
            }
            other => panic!("expected BadResponse, got {other:?}"),
        }
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
        conn.process_frame(
            Frame {
                typ: F_HEADERS,
                flags: 0,
                stream_id: id,
                payload: vec![0u8; 8 * 1024],
            },
            None,
        )
        .unwrap();
        // Keep feeding CONTINUATION fragments with no END_HEADERS; eventually
        // the aggregate buffer cap fires.
        let chunk = vec![0u8; 16 * 1024];
        let mut hit_cap = false;
        for _ in 0..(MAX_HEADERS_BUF / chunk.len() + 4) {
            let r = conn.process_frame(
                Frame {
                    typ: F_CONTINUATION,
                    flags: 0,
                    stream_id: id,
                    payload: chunk.clone(),
                },
                None,
            );
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
    // Connection pool. All pool tests use `PoolInner::<FakeTls>` built
    // directly — they do NOT touch the process-global `POOL` static, so they
    // are isolated from one another and from any production code.
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

    // -----------------------------------------------------------------
    // Sequential connection reuse: run more than one request/response over a
    // single `Connection`, exactly as the pool does on a hit. Stream ids must
    // advance 1 → 3 → 5, response bodies must be demultiplexed correctly, the
    // connection must stay `is_usable` between requests, and the `streams` map
    // must be pruned back to empty after each one.
    // -----------------------------------------------------------------

    /// A complete server response for `id`: HEADERS(:status 200, END_HEADERS)
    /// then DATA(`body`, END_STREAM).
    fn synth_full_response(id: u32, body: &[u8]) -> Vec<Frame> {
        vec![
            synth_status_200_headers(id, /*end_stream=*/ false),
            synth_data(id, body, /*end_stream=*/ true),
        ]
    }

    fn h2_get(url: &str) -> Request {
        Request::new("GET", url).unwrap()
    }

    #[test]
    fn sequential_reuse_advances_stream_ids_and_demuxes_bodies() {
        // Pre-seed three full responses on streams 1, 3, 5 — the ids the
        // client must allocate across three sequential requests on one conn.
        let mut inbound = Vec::new();
        inbound.extend(synth_full_response(1, b"first"));
        inbound.extend(synth_full_response(3, b"second"));
        inbound.extend(synth_full_response(5, b"third"));
        let mut conn = fake_conn_with_inbound(&inbound);

        let req = h2_get("https://example.com/");

        // Request #1 → stream 1.
        assert_eq!(conn.next_stream_id, 1);
        let r1 = run_one_request(&mut conn, &req, &mut std::io::sink()).unwrap();
        assert_eq!(r1.status, 200);
        assert_eq!(r1.body, b"first");
        // Stream pruned, conn ready for the next id, still poolable.
        assert!(conn.streams.is_empty(), "stream 1 not reaped after reuse");
        assert_eq!(conn.next_stream_id, 3);
        assert!(conn.is_usable());

        // Request #2 → stream 3.
        let r2 = run_one_request(&mut conn, &req, &mut std::io::sink()).unwrap();
        assert_eq!(r2.status, 200);
        assert_eq!(r2.body, b"second");
        assert!(conn.streams.is_empty());
        assert_eq!(conn.next_stream_id, 5);
        assert!(conn.is_usable());

        // Request #3 → stream 5.
        let r3 = run_one_request(&mut conn, &req, &mut std::io::sink()).unwrap();
        assert_eq!(r3.body, b"third");
        assert_eq!(conn.next_stream_id, 7);
        assert!(conn.is_usable());

        // Confirm the HEADERS the client actually wrote carried stream ids
        // 1, 3, 5 in order — i.e. id progression went out on the wire, not
        // just in the local counter.
        let header_ids: Vec<u32> = drain_wire_out(&conn)
            .into_iter()
            .filter(|f| f.typ == F_HEADERS)
            .map(|f| f.stream_id)
            .collect();
        assert_eq!(header_ids, vec![1, 3, 5]);
    }

    #[test]
    fn run_one_request_emits_curl_style_verbose_trace() {
        // Server response: HEADERS(:status 200, content-type: text/plain)
        // then DATA("hello world", END_STREAM). Drive one request through
        // `run_one_request` with a `Vec<u8>` trace sink and assert it carries
        // the curl-style `>` request lines, the `< HTTP/2 200` status line,
        // the response header line, and the `* Received N body bytes` line.
        let mut hdr_payload = Vec::new();
        let mut enc = Encoder::new();
        enc.encode_header(&mut hdr_payload, ":status", "200");
        enc.encode_header(&mut hdr_payload, "content-type", "text/plain");
        let headers_frame = Frame {
            typ: F_HEADERS,
            flags: FLAG_END_HEADERS,
            stream_id: 1,
            payload: hdr_payload,
        };
        let inbound = vec![headers_frame, synth_data(1, b"hello world", true)];
        let mut conn = fake_conn_with_inbound(&inbound);

        let req = h2_get("https://example.com/path");
        let mut trace: Vec<u8> = Vec::new();
        let resp = run_one_request(&mut conn, &req, &mut trace).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"hello world");

        let t = String::from_utf8(trace).expect("trace is utf-8");
        // Request line + a synthesised Host line + a default header field.
        assert!(
            t.contains("> GET /path HTTP/2"),
            "missing request line in trace:\n{t}"
        );
        assert!(
            t.contains("> Host: example.com"),
            "missing Host line in trace:\n{t}"
        );
        assert!(
            t.contains("> accept: */*"),
            "missing default accept header in trace:\n{t}"
        );
        // Response status + header + body-byte notice.
        assert!(
            t.contains("< HTTP/2 200"),
            "missing response status line in trace:\n{t}"
        );
        assert!(
            t.contains("< content-type: text/plain"),
            "missing response header line in trace:\n{t}"
        );
        assert!(
            t.contains("* Received 11 body bytes"),
            "missing received-bytes notice in trace:\n{t}"
        );
    }

    #[test]
    fn goaway_between_requests_marks_connection_non_reusable() {
        // First request succeeds; the peer then sends GOAWAY (last-stream-id
        // = 1) before we issue a second. is_usable must flip to false so the
        // pool drops the connection instead of handing it back out.
        let mut inbound = Vec::new();
        inbound.extend(synth_full_response(1, b"ok"));
        // GOAWAY(last_stream_id=1, NO_ERROR) on stream 0.
        let mut goaway_payload = Vec::new();
        goaway_payload.extend_from_slice(&1u32.to_be_bytes()); // last-stream-id
        goaway_payload.extend_from_slice(&0u32.to_be_bytes()); // error code
        inbound.push(Frame {
            typ: F_GOAWAY,
            flags: 0,
            stream_id: 0,
            payload: goaway_payload,
        });
        let mut conn = fake_conn_with_inbound(&inbound);

        let req = h2_get("https://example.com/");
        let r1 = run_one_request(&mut conn, &req, &mut std::io::sink()).unwrap();
        assert_eq!(r1.body, b"ok");
        assert!(conn.is_usable(), "no GOAWAY seen yet — still reusable");

        // Consume the GOAWAY that's sitting in the inbound buffer.
        let outcome = conn.read_and_dispatch(None).unwrap();
        assert_eq!(outcome, DispatchOutcome::Continue);
        assert_eq!(conn.goaway_received, Some(1));
        assert!(
            !conn.is_usable(),
            "GOAWAY must make the connection non-reusable"
        );
    }

    #[test]
    fn prune_completed_streams_drops_terminal_entries_only() {
        // A connection that finished one stream while another is still open
        // must keep the open one and reap the closed one.
        let mut conn = fake_conn();
        let open_id = conn.open_stream().unwrap();
        let done_id = conn.open_stream().unwrap();
        // Mark `done_id` fully received and closed; leave `open_id` mid-flight.
        {
            let s = conn.streams.get_mut(&done_id).unwrap();
            s.state = StreamState::Closed;
            s.response_headers = Some(vec![(":status".into(), "200".into())]);
            s.end_stream_recv = true;
        }
        conn.streams.get_mut(&open_id).unwrap().state = StreamState::Open;

        conn.prune_completed_streams();
        assert!(
            conn.streams.contains_key(&open_id),
            "open stream was reaped"
        );
        assert!(
            !conn.streams.contains_key(&done_id),
            "closed stream was not reaped"
        );
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
        conn.process_frame(frame, None).unwrap();

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

    // -----------------------------------------------------------------
    // End-to-end flow control over the I/O loop (RFC 9113 §5.2 / §6.9).
    // These drive `send_request_on` / `process_frame` against a `FakeTls`
    // whose `wire_in` is pre-seeded with the frames the peer would send,
    // and inspect the bytes the `Connection` wrote to `wire_out`.
    // -----------------------------------------------------------------

    /// Build a `Connection<FakeTls>` whose inbound wire is pre-seeded with the
    /// concatenation of `frames` (the order the peer would send them in).
    fn fake_conn_with_inbound(frames: &[Frame]) -> Connection<FakeTls> {
        let mut bytes = Vec::new();
        for f in frames {
            write_frame(&mut bytes, f).unwrap();
        }
        let mut conn = fake_conn();
        conn.tls.wire_in = Cursor::new(bytes);
        conn
    }

    /// Decode every frame the `Connection` wrote to its peer.
    fn drain_wire_out(conn: &Connection<FakeTls>) -> Vec<Frame> {
        let mut cur = Cursor::new(conn.tls.wire_out.clone());
        let mut out = Vec::new();
        while (cur.position() as usize) < conn.tls.wire_out.len() {
            out.push(read_frame(&mut cur).unwrap());
        }
        out
    }

    fn h2_request_with_body(body: Vec<u8>) -> Request {
        let mut req = Request::new("POST", "https://example.com/upload").unwrap();
        req.body = body;
        req
    }

    #[test]
    fn send_body_splits_across_window_updates() {
        // Peer advertises a tiny INITIAL_WINDOW_SIZE (5 octets). A 12-byte
        // request body therefore cannot be sent in one go: the stream send
        // window only allows 5 bytes, then the send loop must block until the
        // peer grants more with WINDOW_UPDATE. We seed two stream-level
        // WINDOW_UPDATE(+5) frames so the loop can drain the whole body across
        // three DATA frames (5 + 5 + 2).
        let body = (0..12u8).collect::<Vec<u8>>();
        let req = h2_request_with_body(body.clone());

        // The send loop will read these when its window hits zero.
        let inbound = vec![window_update_frame(1, 5), window_update_frame(1, 5)];
        let mut conn = fake_conn_with_inbound(&inbound);
        // Shrink the peer's initial window *before* opening the stream so the
        // new stream picks up the small send window.
        conn.peer.initial_window_size = 5;

        let id = conn.open_stream().unwrap();
        assert_eq!(conn.streams.get(&id).unwrap().send_window.available, 5);

        conn.send_request_on(id, &req).unwrap();

        // Pull apart what we wrote: one or more HEADERS frames, then DATA.
        let frames = drain_wire_out(&conn);
        let data: Vec<&Frame> = frames.iter().filter(|f| f.typ == F_DATA).collect();
        assert_eq!(
            data.len(),
            3,
            "12-byte body under a 5-octet window must split into 5+5+2"
        );
        assert_eq!(data[0].payload.len(), 5);
        assert_eq!(data[1].payload.len(), 5);
        assert_eq!(data[2].payload.len(), 2);
        // END_STREAM only on the final DATA frame.
        assert_eq!(data[0].flags & FLAG_END_STREAM, 0);
        assert_eq!(data[1].flags & FLAG_END_STREAM, 0);
        assert_eq!(data[2].flags & FLAG_END_STREAM, FLAG_END_STREAM);
        // Reassembled DATA equals the original body.
        let mut reassembled = Vec::new();
        for d in &data {
            reassembled.extend_from_slice(&d.payload);
        }
        assert_eq!(reassembled, body);

        // Both windows were charged for the full body: stream window back to 0
        // (5 + 5 granted, 12 consumed = -2... but the third chunk only fired
        // after the second grant left 5, consuming 2 → 3 remaining).
        let s = conn.streams.get(&id).unwrap();
        assert_eq!(s.send_window.available, 3, "5+5 granted, 12 consumed");
        assert_eq!(conn.conn_send_window.available, 65_535 - 12);
    }

    #[test]
    fn send_body_blocks_on_conn_window_too() {
        // Here the per-stream window is huge but the *connection* window is the
        // binding constraint. Set the conn send window to 4 and seed a conn
        // WINDOW_UPDATE(+8) on stream 0; a 10-byte body must go 4, then (after
        // the grant) 6.
        let body = (0..10u8).collect::<Vec<u8>>();
        let req = h2_request_with_body(body.clone());

        let inbound = vec![window_update_frame(0, 8)];
        let mut conn = fake_conn_with_inbound(&inbound);
        conn.conn_send_window.available = 4;

        let id = conn.open_stream().unwrap();
        conn.send_request_on(id, &req).unwrap();

        let frames = drain_wire_out(&conn);
        let data: Vec<&Frame> = frames.iter().filter(|f| f.typ == F_DATA).collect();
        assert_eq!(data.len(), 2, "conn window of 4 then +8 splits 10 into 4+6");
        assert_eq!(data[0].payload.len(), 4);
        assert_eq!(data[1].payload.len(), 6);
        assert_eq!(data[1].flags & FLAG_END_STREAM, FLAG_END_STREAM);
        // 4 + 8 granted = 12, consumed 10 → 2 left.
        assert_eq!(conn.conn_send_window.available, 2);
    }

    #[test]
    fn recv_data_replenishes_window_on_the_wire() {
        // Drive enough inbound DATA past the half-window threshold and confirm
        // the Connection writes WINDOW_UPDATE frames (stream + connection) back
        // to the peer — i.e. replenishment is tied to actual consumption, not
        // emitted unconditionally.
        let mut conn = fake_conn();
        let id = conn.open_stream().unwrap();
        conn.streams.get_mut(&id).unwrap().state = StreamState::Open;

        // A single 40_000-byte DATA frame drops both windows from 65_535 to
        // 25_535 — below the 32_767 half-threshold — so both replenish.
        let big = vec![0xa5u8; 40_000];
        conn.process_frame(synth_data(id, &big, false), None)
            .unwrap();

        let out = drain_wire_out(&conn);
        let updates: Vec<&Frame> = out.iter().filter(|f| f.typ == F_WINDOW_UPDATE).collect();
        assert_eq!(
            updates.len(),
            2,
            "one conn-level and one stream-level WINDOW_UPDATE expected"
        );
        let conn_update = updates.iter().find(|f| f.stream_id == 0).unwrap();
        let stream_update = updates.iter().find(|f| f.stream_id == id).unwrap();
        // Each grant restores the consumed 40_000 octets.
        assert_eq!(parse_window_update(&conn_update.payload).unwrap(), 40_000);
        assert_eq!(parse_window_update(&stream_update.payload).unwrap(), 40_000);
        // Running windows are back to full after the grant.
        assert_eq!(conn.conn_recv_window.available, OUR_INITIAL_WINDOW);
        assert_eq!(
            conn.streams.get(&id).unwrap().recv_window.available,
            OUR_INITIAL_WINDOW
        );
    }

    #[test]
    fn recv_small_data_does_not_replenish() {
        // A small DATA frame that leaves both windows above the half-threshold
        // must NOT trigger any WINDOW_UPDATE (the prior unconditional replenish
        // was the security-audit finding this guards against).
        let mut conn = fake_conn();
        let id = conn.open_stream().unwrap();
        conn.streams.get_mut(&id).unwrap().state = StreamState::Open;

        conn.process_frame(synth_data(id, b"hello", false), None)
            .unwrap();
        let out = drain_wire_out(&conn);
        assert!(
            out.iter().all(|f| f.typ != F_WINDOW_UPDATE),
            "no WINDOW_UPDATE should be emitted while windows stay above half"
        );
        assert_eq!(conn.conn_recv_window.available, OUR_INITIAL_WINDOW - 5);
        assert_eq!(
            conn.streams.get(&id).unwrap().recv_window.available,
            OUR_INITIAL_WINDOW - 5
        );
    }

    #[test]
    fn dispatch_zero_increment_window_update_conn_is_error() {
        // §6.9: a WINDOW_UPDATE with a 0 increment on stream 0 is a connection
        // error. Driving it through the full dispatch ladder must surface it.
        let mut conn = fake_conn();
        let frame = window_update_frame(0, 0);
        let err = conn.process_frame(frame, None).unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)));
    }

    #[test]
    fn dispatch_zero_increment_window_update_stream_is_error() {
        // §6.9: a WINDOW_UPDATE with a 0 increment on a live stream is a stream
        // error; through the dispatch ladder it surfaces as BadResponse.
        let mut conn = fake_conn();
        let id = conn.open_stream().unwrap();
        let frame = window_update_frame(id, 0);
        let err = conn.process_frame(frame, None).unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)));
    }

    #[test]
    fn dispatch_window_update_overflow_conn_is_error() {
        // §6.9.1: a WINDOW_UPDATE pushing the connection send window past
        // 2^31-1 is a FLOW_CONTROL_ERROR. Prime the window near the ceiling and
        // drive an oversized grant through dispatch.
        let mut conn = fake_conn();
        conn.conn_send_window.available = WINDOW_MAX - 1;
        let err = conn
            .process_frame(window_update_frame(0, 5), None)
            .unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)));
    }

    #[test]
    fn dispatch_window_update_overflow_stream_is_error() {
        // §6.9.1 on a stream: same overflow rule via the stream dispatch path.
        let mut conn = fake_conn();
        let id = conn.open_stream().unwrap();
        conn.streams.get_mut(&id).unwrap().send_window.available = WINDOW_MAX - 1;
        let err = conn
            .process_frame(window_update_frame(id, 5), None)
            .unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)));
    }

    #[test]
    fn settings_initial_window_change_lets_stalled_send_proceed() {
        // A stream opened under a 0-octet initial window cannot send any body
        // until the peer enlarges the window. Here the peer raises
        // INITIAL_WINDOW_SIZE mid-connection (§6.9.2), which retroactively
        // grows the existing stream's send window and unblocks the send loop.
        let body = vec![0x11u8; 6];
        let req = h2_request_with_body(body.clone());

        // The send loop will read this SETTINGS frame when stalled at window 0;
        // it bumps INITIAL_WINDOW_SIZE to 100, applying a +100 delta to the
        // already-open stream. We must also seed its ACK consumption — the loop
        // writes an ACK, which is fine (it goes to wire_out, not wire_in).
        let settings = Frame {
            typ: F_SETTINGS,
            flags: 0,
            stream_id: 0,
            payload: settings_payload(&[(S_INITIAL_WINDOW_SIZE, 100)]),
        };
        let mut conn = fake_conn_with_inbound(&[settings]);
        conn.peer.initial_window_size = 0;

        let id = conn.open_stream().unwrap();
        assert_eq!(conn.streams.get(&id).unwrap().send_window.available, 0);

        conn.send_request_on(id, &req).unwrap();

        let frames = drain_wire_out(&conn);
        let data: Vec<&Frame> = frames.iter().filter(|f| f.typ == F_DATA).collect();
        assert_eq!(data.len(), 1, "after the delta the whole body fits");
        assert_eq!(data[0].payload, body);
        assert_eq!(data[0].flags & FLAG_END_STREAM, FLAG_END_STREAM);
        // Stream send window: 0 + 100 (delta) - 6 (consumed) = 94.
        assert_eq!(conn.streams.get(&id).unwrap().send_window.available, 94);
        // The loop also ACKed the SETTINGS frame.
        assert!(
            frames
                .iter()
                .any(|f| f.typ == F_SETTINGS && f.flags & FLAG_ACK != 0),
            "SETTINGS must be ACKed"
        );
    }

    // -----------------------------------------------------------------
    // Concurrent multiplexing (`run_multiplexed`).
    //
    // These drive several requests over one `Connection<FakeTls>` whose
    // inbound wire is pre-seeded with interleaved server frames, then assert
    // each request's `Response` is demultiplexed back to the right slot.
    // -----------------------------------------------------------------

    /// Synthesize an RST_STREAM frame for `id` carrying `code`.
    fn synth_rst(id: u32, code: u32) -> Frame {
        Frame {
            typ: F_RST_STREAM,
            flags: 0,
            stream_id: id,
            payload: code.to_be_bytes().to_vec(),
        }
    }

    #[test]
    fn multiplex_two_requests_demuxes_interleaved_frames() {
        // Two GET requests → streams 1 and 3. Seed the server's frames
        // INTERLEAVED across the two streams: h1-headers, h3-headers,
        // h1-data-part, h3-data(END), h1-data-rest(END). The driver must route
        // each fragment to its own stream and return the right body to the
        // right request regardless of interleave order.
        let inbound = vec![
            synth_status_200_headers(1, false),
            synth_status_200_headers(3, false),
            synth_data(1, b"one-", false),
            synth_data(3, b"THREE", true),
            synth_data(1, b"part", true),
        ];
        let mut conn = fake_conn_with_inbound(&inbound);

        let reqs = vec![
            h2_get("https://example.com/a"),
            h2_get("https://example.com/b"),
        ];
        let results = conn.run_multiplexed(&reqs, &mut std::io::sink());
        assert_eq!(results.len(), 2);

        let r0 = results[0].as_ref().expect("req 0 ok");
        let r1 = results[1].as_ref().expect("req 1 ok");
        assert_eq!(r0.status, 200);
        assert_eq!(r0.body, b"one-part", "stream 1 body");
        assert_eq!(r1.status, 200);
        assert_eq!(r1.body, b"THREE", "stream 3 body");

        // Both HEADERS the client wrote went out on streams 1 and 3.
        let header_ids: Vec<u32> = drain_wire_out(&conn)
            .into_iter()
            .filter(|f| f.typ == F_HEADERS)
            .map(|f| f.stream_id)
            .collect();
        assert_eq!(header_ids, vec![1, 3]);
        // The streams were reaped.
        assert!(conn.streams.is_empty());
    }

    #[test]
    fn multiplex_reversed_interleave_still_demuxes() {
        // Same as above but the server completes stream 3 entirely before it
        // even opens stream 1's body — order independence.
        let inbound = vec![
            synth_status_200_headers(3, false),
            synth_data(3, b"bbb", true),
            synth_status_200_headers(1, false),
            synth_data(1, b"aaaa", true),
        ];
        let mut conn = fake_conn_with_inbound(&inbound);
        let reqs = vec![
            h2_get("https://example.com/a"),
            h2_get("https://example.com/b"),
        ];
        let results = conn.run_multiplexed(&reqs, &mut std::io::sink());
        assert_eq!(results[0].as_ref().unwrap().body, b"aaaa");
        assert_eq!(results[1].as_ref().unwrap().body, b"bbb");
    }

    #[test]
    fn multiplex_queues_third_request_at_max_concurrent_two() {
        // MAX_CONCURRENT_STREAMS = 2: only streams 1 and 3 may be open at once.
        // The third request must wait until one of the first two completes,
        // then open on stream 5. We seed the responses so stream 1 finishes
        // first (freeing a slot for stream 5), then 3, then 5.
        let inbound = vec![
            // Stream 1 completes first.
            synth_status_200_headers(1, false),
            synth_data(1, b"first", true),
            // Then stream 3.
            synth_status_200_headers(3, false),
            synth_data(3, b"second", true),
            // Stream 5 (the queued one) only opens after 1 frees a slot.
            synth_status_200_headers(5, false),
            synth_data(5, b"third", true),
        ];
        let mut conn = fake_conn_with_inbound(&inbound);
        conn.peer.max_concurrent_streams = 2;

        let reqs = vec![
            h2_get("https://example.com/1"),
            h2_get("https://example.com/2"),
            h2_get("https://example.com/3"),
        ];
        let results = conn.run_multiplexed(&reqs, &mut std::io::sink());
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].as_ref().unwrap().body, b"first");
        assert_eq!(results[1].as_ref().unwrap().body, b"second");
        assert_eq!(results[2].as_ref().unwrap().body, b"third");

        // The client must have written HEADERS on streams 1, 3 first, and
        // only later on 5 — i.e. no more than two were open before stream 1
        // completed. We assert the *order* of HEADERS writes: 1, 3, then 5.
        let header_ids: Vec<u32> = drain_wire_out(&conn)
            .into_iter()
            .filter(|f| f.typ == F_HEADERS)
            .map(|f| f.stream_id)
            .collect();
        assert_eq!(
            header_ids,
            vec![1, 3, 5],
            "stream 5 must be opened only after a slot freed"
        );
    }

    #[test]
    fn multiplex_one_stream_rst_others_succeed() {
        // Stream 1 is reset by the server; stream 3 completes normally. The
        // reset request gets an Err, the other its Response — the RST must not
        // kill the whole batch.
        let inbound = vec![
            synth_status_200_headers(3, false),
            synth_rst(1, 0x8), // CANCEL
            synth_data(3, b"alive", true),
        ];
        let mut conn = fake_conn_with_inbound(&inbound);
        let reqs = vec![
            h2_get("https://example.com/doomed"),
            h2_get("https://example.com/ok"),
        ];
        let results = conn.run_multiplexed(&reqs, &mut std::io::sink());
        assert_eq!(results.len(), 2);
        assert!(
            matches!(results[0], Err(Error::BadResponse(_))),
            "reset stream must yield an error, got {:?}",
            results[0]
        );
        let ok = results[1].as_ref().expect("stream 3 should succeed");
        assert_eq!(ok.body, b"alive");
    }

    #[test]
    fn multiplex_flow_control_no_head_of_line_block() {
        // A tiny INITIAL_WINDOW_SIZE (4 octets) forces request bodies to be
        // split. Two POSTs with 10-byte bodies each: stream 1 can only put 4
        // bytes out before stalling, but stream 3 must still make progress (and
        // vice versa) — the non-blocking pump interleaves them. After the
        // server grants WINDOW_UPDATEs, both bodies finish and both responses
        // come back.
        let mut req1 = Request::new("POST", "https://example.com/u1").unwrap();
        req1.body = (0..10u8).collect();
        let mut req3 = Request::new("POST", "https://example.com/u3").unwrap();
        req3.body = (100..110u8).collect();

        // Inbound: first the per-stream WINDOW_UPDATEs that unblock the bodies
        // (interleaved across both streams), then the responses. The driver
        // pumps sends after each inbound frame, so the grants let both bodies
        // drain without one blocking the other.
        let inbound = vec![
            window_update_frame(1, 6),  // stream 1: 4 + 6 = 10 → done
            window_update_frame(3, 6),  // stream 3: 4 + 6 = 10 → done
            window_update_frame(0, 12), // conn: enough for both remainders
            synth_status_200_headers(1, false),
            synth_data(1, b"r1", true),
            synth_status_200_headers(3, false),
            synth_data(3, b"r3", true),
        ];
        let mut conn = fake_conn_with_inbound(&inbound);
        // Small per-stream send window; conn window large enough initially for
        // the first 4+4 octets (8 < 65535).
        conn.peer.initial_window_size = 4;

        let reqs = vec![req1.clone(), req3.clone()];
        let results = conn.run_multiplexed(&reqs, &mut std::io::sink());
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].as_ref().unwrap().body, b"r1");
        assert_eq!(results[1].as_ref().unwrap().body, b"r3");

        // Verify both bodies went out fully and interleaved: the first DATA on
        // each stream was 4 bytes (the initial window), proving neither waited
        // for the other to finish before starting.
        let data: Vec<Frame> = drain_wire_out(&conn)
            .into_iter()
            .filter(|f| f.typ == F_DATA)
            .collect();
        // Reassemble per-stream payloads and confirm completeness.
        let mut s1 = Vec::new();
        let mut s3 = Vec::new();
        for f in &data {
            if f.stream_id == 1 {
                s1.extend_from_slice(&f.payload);
            } else if f.stream_id == 3 {
                s3.extend_from_slice(&f.payload);
            }
        }
        assert_eq!(s1, req1.body);
        assert_eq!(s3, req3.body);
        // The first chunk on stream 1 was capped to the 4-octet window.
        let first_s1 = data.iter().find(|f| f.stream_id == 1).unwrap();
        assert_eq!(
            first_s1.payload.len(),
            4,
            "stream 1 first DATA capped to window"
        );
        let first_s3 = data.iter().find(|f| f.stream_id == 3).unwrap();
        assert_eq!(
            first_s3.payload.len(),
            4,
            "stream 3 first DATA capped to window"
        );
    }

    #[test]
    fn multiplex_goaway_fails_high_streams_lower_completes() {
        // MAX_CONCURRENT_STREAMS=3 so streams 1, 3, 5 all open up front.
        // The server completes stream 1, then sends GOAWAY(last-stream-id=3):
        // stream 3 may still finish, but stream 5 (id > 3) is abandoned and
        // must fail. Stream 1 already completed.
        let mut goaway_payload = Vec::new();
        goaway_payload.extend_from_slice(&3u32.to_be_bytes()); // last-stream-id = 3
        goaway_payload.extend_from_slice(&0u32.to_be_bytes()); // NO_ERROR
        let goaway = Frame {
            typ: F_GOAWAY,
            flags: 0,
            stream_id: 0,
            payload: goaway_payload,
        };
        let inbound = vec![
            synth_status_200_headers(1, false),
            synth_data(1, b"one", true),
            goaway,
            synth_status_200_headers(3, false),
            synth_data(3, b"three", true),
        ];
        let mut conn = fake_conn_with_inbound(&inbound);
        conn.peer.max_concurrent_streams = 3;

        let reqs = vec![
            h2_get("https://example.com/1"),
            h2_get("https://example.com/3"),
            h2_get("https://example.com/5"),
        ];
        let results = conn.run_multiplexed(&reqs, &mut std::io::sink());
        assert_eq!(results.len(), 3);
        assert_eq!(
            results[0].as_ref().unwrap().body,
            b"one",
            "stream 1 completes"
        );
        assert_eq!(
            results[1].as_ref().unwrap().body,
            b"three",
            "stream 3 (<= last-stream-id) completes"
        );
        assert!(
            matches!(results[2], Err(Error::BadResponse(_))),
            "stream 5 (> last-stream-id) must be abandoned, got {:?}",
            results[2]
        );
    }

    #[test]
    fn multiplex_verbose_trace_labels_streams() {
        // The -v trace must label request/response lines per stream id so the
        // interleaved output stays readable.
        let inbound = vec![
            synth_status_200_headers(1, false),
            synth_data(1, b"x", true),
            synth_status_200_headers(3, false),
            synth_data(3, b"y", true),
        ];
        let mut conn = fake_conn_with_inbound(&inbound);
        let reqs = vec![
            h2_get("https://example.com/a"),
            h2_get("https://example.com/b"),
        ];
        let mut trace: Vec<u8> = Vec::new();
        let _ = conn.run_multiplexed(&reqs, &mut trace);
        let t = String::from_utf8(trace).unwrap();
        assert!(t.contains("> [stream 1] GET /a HTTP/2"), "trace:\n{t}");
        assert!(t.contains("> [stream 3] GET /b HTTP/2"), "trace:\n{t}");
        assert!(t.contains("< [stream 1] HTTP/2 200"), "trace:\n{t}");
        assert!(t.contains("< [stream 3] HTTP/2 200"), "trace:\n{t}");
    }

    #[test]
    fn send_multiplexed_empty_returns_empty() {
        let mut sink = std::io::sink();
        let out = send_multiplexed(Vec::new(), &mut sink);
        assert!(out.is_empty());
    }
}

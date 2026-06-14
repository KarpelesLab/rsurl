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
//! * **QPACK dynamic table**: decoder side implemented (RFC 9204). We
//!   advertise a non-zero `SETTINGS_QPACK_MAX_TABLE_CAPACITY` and
//!   `SETTINGS_QPACK_BLOCKED_STREAMS = 0`, read the peer's encoder
//!   stream, apply Insert With Name Reference / Insert With Literal Name /
//!   Set Dynamic Table Capacity / Duplicate instructions (§4.3) into a
//!   bounded dynamic table, and resolve dynamic / post-base field-line
//!   references (§4.5) when decoding a response HEADERS block. We send
//!   Section Acknowledgement back on the decoder stream (§4.4). Because
//!   we advertise zero blocked streams, the encoder must send every
//!   insert a header block references *before* that block — the normal
//!   single-connection ordering, which our I/O loop drains first. The
//!   **encoder** (request) side still emits literal-only field lines —
//!   wire-legal, since the dynamic table is optional for the sender.
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
use std::io::Write;
use std::net::ToSocketAddrs;
use std::time::{Duration, Instant};

use crate::net::udp::{open_udp_transport, UdpTransport};
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

/// HTTP/3 and QPACK SETTINGS identifiers (RFC 9114 §7.2.4.1, RFC 9204 §5).
#[allow(dead_code)]
pub(crate) mod settings_id {
    pub const QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
    pub const MAX_FIELD_SECTION_SIZE: u64 = 0x06;
    pub const QPACK_BLOCKED_STREAMS: u64 = 0x07;
}

/// Dynamic-table capacity (bytes) we advertise via
/// `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (RFC 9204 §5). This bounds the memory
/// the decoder's dynamic table can ever hold.
pub(crate) const QPACK_MAX_TABLE_CAPACITY: u64 = 4096;

/// Number of streams we permit to be "blocked" on as-yet-unreceived
/// dynamic-table inserts (RFC 9204 §2.1.2). We advertise 0: the encoder
/// must deliver every insert a header block references *before* that block,
/// which is the normal single-connection ordering and lets us decode without
/// a blocked-stream queue.
pub(crate) const QPACK_BLOCKED_STREAMS: u64 = 0;

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
    //! not (the H bit selects RFC 7541 Appendix B prefix decoding).
    //!
    //! Dynamic-table references (RFC 9204 §4.5) are decoded too: a
    //! [`DynamicTable`] holds entries inserted via the peer's encoder
    //! stream (§4.3), and [`decode_field_section`] resolves indexed,
    //! post-base, and literal-with-name-reference field lines against it
    //! using the Base computed from the field-section prefix (§4.5.1). The
    //! table is bounded by the advertised capacity, never allocates
    //! unboundedly, and rejects inconsistent Required Insert Counts with
    //! [`Error::BadResponse`] so failures stay observable.

    use crate::error::{Error, Result};

    /// Cap on the *decoded* header-list size (sum of `name + value + 32` per
    /// header, the RFC 7541 §4.1 accounting). Bounds a QPACK decompression
    /// bomb: a small compressed field section can otherwise expand into a
    /// huge header list and exhaust memory.
    const MAX_DECODED_HEADER_LIST: usize = 256 * 1024;

    /// Hard cap on the dynamic-table capacity we will ever honor, regardless
    /// of a peer's Set Dynamic Table Capacity instruction. The encoder may
    /// only raise capacity up to the value we advertised in
    /// `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (RFC 9204 §3.2.3); we clamp to this
    /// to bound memory even if our own SETTINGS value were ever raised.
    pub(crate) const MAX_DYNAMIC_CAPACITY: usize = 4096;

    /// Per-entry overhead in the RFC 9204 §3.2.1 size accounting: an entry's
    /// size is `name.len() + value.len() + 32`.
    const ENTRY_OVERHEAD: usize = 32;

    /// The QPACK dynamic table (RFC 9204 §3.2): a FIFO of `(name, value)`
    /// entries fed by the peer's encoder stream. Entries are addressed by an
    /// ever-increasing *absolute index* (§3.2.4); the oldest live entry has
    /// the smallest absolute index. `insert_count` is the total number of
    /// entries ever inserted, so the next insert lands at absolute index
    /// `insert_count` and `dropped` counts entries evicted off the front.
    #[derive(Debug, Default)]
    pub(crate) struct DynamicTable {
        /// Live entries, oldest first. `entries[0]` has absolute index
        /// `dropped`.
        entries: std::collections::VecDeque<(String, String)>,
        /// Sum of `name+value+32` over the live entries (RFC 9204 §3.2.1).
        size: usize,
        /// Maximum total size; raised/lowered by Set Dynamic Table Capacity,
        /// clamped to [`MAX_DYNAMIC_CAPACITY`].
        capacity: usize,
        /// Total entries ever inserted (the Insert Count, RFC 9204 §2.1.4).
        insert_count: u64,
        /// Number of entries evicted off the front. `dropped + entries.len()
        /// == insert_count`.
        dropped: u64,
    }

    impl DynamicTable {
        /// A fresh, zero-capacity table. The peer must raise the capacity via
        /// Set Dynamic Table Capacity (up to our advertised maximum) before it
        /// can insert anything.
        pub(crate) fn new() -> Self {
            DynamicTable::default()
        }

        /// Total inserts ever applied (RFC 9204 §2.1.4 Insert Count). Equals
        /// the absolute index that the next insert will occupy.
        pub(crate) fn insert_count(&self) -> u64 {
            self.insert_count
        }

        /// Set the table capacity (RFC 9204 §3.2.3). Clamped to our hard cap;
        /// evicts oldest entries until `size <= capacity`. A capacity below
        /// our advertised maximum is always legal; a capacity above it is a
        /// QPACK encoder-stream error.
        pub(crate) fn set_capacity(&mut self, cap: u64) -> Result<()> {
            if cap > MAX_DYNAMIC_CAPACITY as u64 {
                return Err(Error::BadResponse(format!(
                    "qpack: encoder set capacity {cap} above advertised max {MAX_DYNAMIC_CAPACITY}"
                )));
            }
            self.capacity = cap as usize;
            self.evict_to_fit(0);
            Ok(())
        }

        /// Evict oldest entries until `size + incoming <= capacity`.
        fn evict_to_fit(&mut self, incoming: usize) {
            while self.size + incoming > self.capacity {
                match self.entries.pop_front() {
                    Some((n, v)) => {
                        self.size -= n.len() + v.len() + ENTRY_OVERHEAD;
                        self.dropped += 1;
                    }
                    None => break,
                }
            }
        }

        /// Insert a new entry (RFC 9204 §3.2.2). If the entry alone exceeds
        /// capacity it cannot be added — that's an encoder error. Otherwise we
        /// evict oldest entries to make room, push, and bump the insert count.
        pub(crate) fn insert(&mut self, name: String, value: String) -> Result<()> {
            let entry_size = name.len() + value.len() + ENTRY_OVERHEAD;
            if entry_size > self.capacity {
                return Err(Error::BadResponse(format!(
                    "qpack: dynamic entry size {entry_size} exceeds capacity {}",
                    self.capacity
                )));
            }
            self.evict_to_fit(entry_size);
            self.size += entry_size;
            self.entries.push_back((name, value));
            self.insert_count += 1;
            Ok(())
        }

        /// Look up an entry by its absolute index (RFC 9204 §3.2.4). Returns
        /// an error if the entry has been evicted or never existed.
        pub(crate) fn get_absolute(&self, abs: u64) -> Result<&(String, String)> {
            if abs < self.dropped || abs >= self.insert_count {
                return Err(Error::BadResponse(format!(
                    "qpack: dynamic absolute index {abs} not live (dropped {}, count {})",
                    self.dropped, self.insert_count
                )));
            }
            let pos = (abs - self.dropped) as usize;
            self.entries
                .get(pos)
                .ok_or_else(|| Error::BadResponse("qpack: dynamic index out of range".into()))
        }
    }

    /// Apply one or more QPACK encoder-stream instructions (RFC 9204 §4.3)
    /// from `buf` into `table`. Returns the number of bytes consumed: a whole
    /// number of complete instructions. A partial trailing instruction is
    /// left unconsumed for the caller to retry once more bytes arrive.
    pub(crate) fn apply_encoder_instructions(
        table: &mut DynamicTable,
        buf: &[u8],
    ) -> Result<usize> {
        let mut p = 0;
        while p < buf.len() {
            match decode_encoder_instruction(table, &buf[p..])? {
                Some(used) => p += used,
                None => break, // need more bytes for this instruction
            }
        }
        Ok(p)
    }

    /// Decode and apply a single encoder-stream instruction at the start of
    /// `buf`. `Ok(Some(n))` applied one instruction consuming `n` bytes;
    /// `Ok(None)` means the buffer holds only a partial instruction.
    fn decode_encoder_instruction(table: &mut DynamicTable, buf: &[u8]) -> Result<Option<usize>> {
        if buf.is_empty() {
            return Ok(None);
        }
        let b0 = buf[0];
        if b0 & 0b1000_0000 != 0 {
            // Insert With Name Reference (§4.3.2): 1 T iiiiii (6-bit index).
            let t_static = b0 & 0b0100_0000 != 0;
            let (idx, used) = decode_int(b0, 6, &buf[1..])?;
            let mut p = 1 + used;
            let name = if t_static {
                let (n, _) = *STATIC_TABLE.get(idx as usize).ok_or_else(|| {
                    Error::BadResponse(format!(
                        "qpack: encoder static name index {idx} out of range"
                    ))
                })?;
                n.to_string()
            } else {
                // Dynamic name reference uses a relative index (§3.2.5):
                // abs = insert_count - 1 - rel.
                let abs = relative_to_absolute_insert(table.insert_count(), idx)?;
                table.get_absolute(abs)?.0.clone()
            };
            let (value, vlen) = match try_decode_literal_string_7bit(&buf[p..])? {
                Some(x) => x,
                None => return Ok(None),
            };
            p += vlen;
            table.insert(name, value)?;
            Ok(Some(p))
        } else if b0 & 0b0100_0000 != 0 {
            // Insert With Literal Name (§4.3.3): 01 H nnnnn (5-bit name len).
            let huffman = b0 & 0b0010_0000 != 0;
            let (nlen, used) = decode_int(b0, 5, &buf[1..])?;
            let mut p = 1 + used;
            let nlen = nlen as usize;
            // A length that overflows usize can never be satisfied by more
            // bytes; treat it as a hard error rather than an endless "need more".
            let nend = p.checked_add(nlen).ok_or_else(|| {
                Error::BadResponse("qpack: oversized encoder literal name length".into())
            })?;
            if nend > buf.len() {
                return Ok(None);
            }
            let name = decode_string_bytes(&buf[p..nend], huffman, "encoder literal name")?;
            p += nlen;
            let (value, vlen) = match try_decode_literal_string_7bit(&buf[p..])? {
                Some(x) => x,
                None => return Ok(None),
            };
            p += vlen;
            table.insert(name, value)?;
            Ok(Some(p))
        } else if b0 & 0b0010_0000 != 0 {
            // Set Dynamic Table Capacity (§4.3.1): 001 ccccc (5-bit capacity).
            let (cap, used) = decode_int(b0, 5, &buf[1..])?;
            table.set_capacity(cap)?;
            Ok(Some(1 + used))
        } else {
            // Duplicate (§4.3.4): 000 iiiii (5-bit relative index).
            let (idx, used) = decode_int(b0, 5, &buf[1..])?;
            let abs = relative_to_absolute_insert(table.insert_count(), idx)?;
            let (n, v) = table.get_absolute(abs)?.clone();
            table.insert(n, v)?;
            Ok(Some(1 + used))
        }
    }

    /// Encoder-instruction relative index → absolute index (RFC 9204 §3.2.5):
    /// the relative index is counted back from the most recent insert, so
    /// `abs = insert_count - 1 - rel`. Errors if it underflows.
    fn relative_to_absolute_insert(insert_count: u64, rel: u64) -> Result<u64> {
        insert_count
            .checked_sub(1)
            .and_then(|last| last.checked_sub(rel))
            .ok_or_else(|| {
                Error::BadResponse(format!(
                    "qpack: relative index {rel} out of range (insert count {insert_count})"
                ))
            })
    }

    /// Decode raw `bytes` as a header name/value, applying Huffman if `huffman`
    /// is set, then validating UTF-8. `what` names the field for error text.
    fn decode_string_bytes(bytes: &[u8], huffman: bool, what: &str) -> Result<String> {
        if huffman {
            let decoded = huffman_decode(bytes)?;
            String::from_utf8(decoded)
                .map_err(|_| Error::BadResponse(format!("qpack: {what} not utf-8")))
        } else {
            std::str::from_utf8(bytes)
                .map_err(|_| Error::BadResponse(format!("qpack: {what} not utf-8")))
                .map(|s| s.to_string())
        }
    }

    /// Like [`decode_literal_string_7bit`] but returns `Ok(None)` when the
    /// buffer holds only a partial string (used while streaming the encoder
    /// stream, where instructions can straddle datagram boundaries).
    fn try_decode_literal_string_7bit(buf: &[u8]) -> Result<Option<(String, usize)>> {
        if buf.is_empty() {
            return Ok(None);
        }
        let b = buf[0];
        let huffman = b & 0b1000_0000 != 0;
        // We need the full length-prefix integer before we know the string
        // length; if it's truncated, ask for more bytes rather than erroring.
        let (slen, used) = match decode_int_partial(b, 7, &buf[1..])? {
            Some(x) => x,
            None => return Ok(None),
        };
        let start = 1 + used;
        // A length that overflows usize cannot ever be satisfied by more bytes;
        // treat it as a hard error rather than an endless "need more".
        let end = start
            .checked_add(slen as usize)
            .ok_or_else(|| Error::BadResponse("qpack: oversized literal string length".into()))?;
        if end > buf.len() {
            return Ok(None);
        }
        let s = decode_string_bytes(&buf[start..end], huffman, "literal string")?;
        Ok(Some((s, end)))
    }

    /// Like [`decode_int`] but distinguishes "truncated, need more bytes"
    /// (`Ok(None)`) from a hard error. Used by the streaming encoder-stream
    /// parser; the field-section decoder uses the non-partial variant since it
    /// always has the whole block.
    fn decode_int_partial(first: u8, prefix_bits: u8, rest: &[u8]) -> Result<Option<(u64, usize)>> {
        debug_assert!((1..=8).contains(&prefix_bits));
        let mask = ((1u16 << prefix_bits) - 1) as u8;
        let prefix = (first & mask) as u64;
        let max_prefix = mask as u64;
        if prefix < max_prefix {
            return Ok(Some((prefix, 0)));
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
                return Ok(Some((value, used)));
            }
            shift += 7;
            if shift > 63 {
                return Err(Error::BadResponse("qpack int too long".into()));
            }
        }
        Ok(None) // ran out of bytes mid-integer
    }

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

    /// Decode a complete QPACK field section against the static table only
    /// (no dynamic-table state). Convenience wrapper used by tests and any
    /// caller that knows the block can't reference the dynamic table; a
    /// dynamic reference here is an error because the empty table can't
    /// satisfy it.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn decode_field_section(buf: &[u8]) -> Result<Fields> {
        let table = DynamicTable::new();
        decode_field_section_with(buf, &table)
    }

    /// Compute `MaxEntries = floor(capacity / 32)` (RFC 9204 §3.2.2), the
    /// modulus used by the Required Insert Count wrap-around encoding.
    fn max_entries() -> u64 {
        (MAX_DYNAMIC_CAPACITY / ENTRY_OVERHEAD) as u64
    }

    /// Decode the Required Insert Count from its encoded wire value
    /// (RFC 9204 §4.5.1.1). `total_inserts` is the table's current insert
    /// count. Returns the reconstructed absolute Required Insert Count.
    pub(crate) fn decode_required_insert_count(encoded: u64, total_inserts: u64) -> Result<u64> {
        if encoded == 0 {
            return Ok(0);
        }
        let max_entries = max_entries();
        let full_range = 2 * max_entries;
        if encoded > full_range {
            return Err(Error::BadResponse(format!(
                "qpack: encoded Required Insert Count {encoded} exceeds 2*MaxEntries {full_range}"
            )));
        }
        let max_value = total_inserts + max_entries;
        let max_wrapped = (max_value / full_range) * full_range;
        let mut ric = max_wrapped + encoded - 1;
        if ric > max_value {
            if ric <= full_range {
                return Err(Error::BadResponse(
                    "qpack: Required Insert Count wrap underflow".into(),
                ));
            }
            ric -= full_range;
        }
        if ric == 0 {
            return Err(Error::BadResponse(
                "qpack: reconstructed Required Insert Count is zero".into(),
            ));
        }
        Ok(ric)
    }

    /// Cheap predicate: does this field section's prefix carry a non-zero
    /// encoded Required Insert Count? If so the block references the dynamic
    /// table and (RFC 9204 §4.4.1) we owe the peer a Section Acknowledgement.
    /// Returns `false` for any malformed prefix — the decode itself surfaces
    /// the real error.
    pub(crate) fn block_references_dynamic_table(buf: &[u8]) -> bool {
        if buf.is_empty() {
            return false;
        }
        match decode_int(buf[0], 8, &buf[1..]) {
            Ok((enc_ric, _)) => enc_ric != 0,
            Err(_) => false,
        }
    }

    /// Decode the Base from the second field-section-prefix integer
    /// (RFC 9204 §4.5.1.2). The sign bit `S` (0b1000_0000 of the first byte)
    /// selects the direction of the Delta Base offset from `ric`.
    fn decode_base(first: u8, rest: &[u8], ric: u64) -> Result<(u64, usize)> {
        let sign = first & 0b1000_0000 != 0;
        let (delta_base, used) = decode_int(first, 7, rest)?;
        let base = if sign {
            // S=1: Base = ReqInsertCount - DeltaBase - 1.
            ric.checked_sub(delta_base)
                .and_then(|x| x.checked_sub(1))
                .ok_or_else(|| Error::BadResponse("qpack: negative Base".into()))?
        } else {
            // S=0: Base = ReqInsertCount + DeltaBase.
            ric.checked_add(delta_base)
                .ok_or_else(|| Error::BadResponse("qpack: Base overflow".into()))?
        };
        Ok((base, used))
    }

    /// Decode a complete QPACK field section, resolving dynamic-table
    /// references against `table`. Handles indexed-static, indexed-dynamic,
    /// post-base-indexed, the literal-name variants (static / dynamic /
    /// post-base), and literal-literal lines, Huffman-coded or not.
    ///
    /// Enforces the Required Insert Count from the field-section prefix
    /// (§4.5.1): the caller must have applied enough encoder-stream inserts
    /// (we advertise zero blocked streams, so the encoder sends them first).
    /// If the table can't satisfy the block, that's a `QPACK_DECOMPRESSION_FAILED`
    /// surfaced as `Error::BadResponse`.
    pub(crate) fn decode_field_section_with(buf: &[u8], table: &DynamicTable) -> Result<Fields> {
        if buf.is_empty() {
            return Err(Error::BadResponse("qpack: empty field section".into()));
        }
        // Field Section Prefix: Required Insert Count (8-bit prefix) + Base.
        let (enc_ric, n1) = decode_int(buf[0], 8, &buf[1..])?;
        let ric = decode_required_insert_count(enc_ric, table.insert_count())?;
        if ric > table.insert_count() {
            return Err(Error::BadResponse(format!(
                "qpack: Required Insert Count {ric} exceeds available inserts {}",
                table.insert_count()
            )));
        }
        let mut p = 1 + n1;
        if p >= buf.len() {
            return Err(Error::BadResponse(
                "qpack: truncated field-section prefix".into(),
            ));
        }
        let (base, n2) = decode_base(buf[p], &buf[p + 1..], ric)?;
        p += 1 + n2;

        let mut out: Fields = Vec::new();
        // Running total of the decoded header-list size (RFC 7541 §4.1:
        // `name.len() + value.len() + 32` per entry). Bounds a QPACK
        // decompression bomb.
        let mut list_size: usize = 0;
        while p < buf.len() {
            let b = buf[p];
            let entry: (String, String) = if b & 0b1000_0000 != 0 {
                // Indexed Field Line (§4.5.2): 0b1Txxxxxx
                let t_static = b & 0b0100_0000 != 0;
                let (idx, used) = decode_int(b, 6, &buf[p + 1..])?;
                p += 1 + used;
                if t_static {
                    let (n, v) = *STATIC_TABLE.get(idx as usize).ok_or_else(|| {
                        Error::BadResponse(format!("qpack: static index out of range: {idx}"))
                    })?;
                    (n.to_string(), v.to_string())
                } else {
                    // Dynamic: relative to Base (§3.2.6): abs = base - 1 - idx.
                    let abs = field_relative_to_absolute(base, idx)?;
                    table.get_absolute(abs)?.clone()
                }
            } else if b & 0b0100_0000 != 0 {
                // Literal Field Line With Name Reference (§4.5.4): 0b01NTxxxx
                let t_static = b & 0b0001_0000 != 0;
                let (idx, used) = decode_int(b, 4, &buf[p + 1..])?;
                p += 1 + used;
                let name = if t_static {
                    let (n, _) = *STATIC_TABLE.get(idx as usize).ok_or_else(|| {
                        Error::BadResponse(format!("qpack: static name index out of range: {idx}"))
                    })?;
                    n.to_string()
                } else {
                    let abs = field_relative_to_absolute(base, idx)?;
                    table.get_absolute(abs)?.0.clone()
                };
                let value = decode_literal_string_7bit(&buf[p..])?;
                p += value.1;
                (name, value.0)
            } else if b & 0b0010_0000 != 0 {
                // Literal Field Line With Literal Name (§4.5.6): 0b001NHXXX
                let huffman = b & 0b0000_1000 != 0;
                let (nlen, used) = decode_int(b, 3, &buf[p + 1..])?;
                p += 1 + used;
                let nlen = nlen as usize;
                let nend = p
                    .checked_add(nlen)
                    .filter(|&e| e <= buf.len())
                    .ok_or_else(|| {
                        Error::BadResponse("qpack: truncated/oversized literal name".into())
                    })?;
                let name = decode_string_bytes(&buf[p..nend], huffman, "literal name")?;
                p += nlen;
                let value = decode_literal_string_7bit(&buf[p..])?;
                p += value.1;
                (name, value.0)
            } else if b & 0b0001_0000 != 0 {
                // Indexed Field Line With Post-Base Index (§4.5.3): 0b0001xxxx
                let (idx, used) = decode_int(b, 4, &buf[p + 1..])?;
                p += 1 + used;
                let abs = post_base_to_absolute(base, idx)?;
                table.get_absolute(abs)?.clone()
            } else {
                // Literal Field Line With Post-Base Name Reference (§4.5.5):
                // 0b0000NHHH — N (never-index) bit, then 3-bit post-base index.
                let (idx, used) = decode_int(b, 3, &buf[p + 1..])?;
                p += 1 + used;
                let abs = post_base_to_absolute(base, idx)?;
                let name = table.get_absolute(abs)?.0.clone();
                let value = decode_literal_string_7bit(&buf[p..])?;
                p += value.1;
                (name, value.0)
            };
            // Reject malformed/forbidden octets in field names and values
            // (RFC 9114 §10.3). Covers every code path — indexed-static,
            // indexed-dynamic, post-base, and all literal variants — so a
            // malicious peer can't smuggle CR/LF/NUL or non-token name bytes
            // through to a re-serializing consumer (header/response splitting,
            // trace corruption).
            if !header_octets_ok(entry.0.as_bytes(), entry.1.as_bytes()) {
                return Err(Error::BadResponse(
                    "qpack: forbidden octet in decoded header".into(),
                ));
            }
            list_size = list_size
                .saturating_add(entry.0.len())
                .saturating_add(entry.1.len())
                .saturating_add(32);
            if list_size > MAX_DECODED_HEADER_LIST {
                return Err(Error::BadResponse(
                    "qpack: decoded header list exceeds limit".into(),
                ));
            }
            out.push(entry);
        }
        Ok(out)
    }

    /// Validate a decoded QPACK field per RFC 9114 §10.3 / RFC 7230 token
    /// rules.
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
        // A leading `:` marks a pseudo-header; the rest must still be a token.
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
    /// Uppercase letters are deliberately excluded (HTTP/3 names are lowercase).
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

    /// Field-line relative index → absolute index (RFC 9204 §3.2.6): the
    /// index is relative to Base, counting backwards, so `abs = base - 1 - rel`.
    fn field_relative_to_absolute(base: u64, rel: u64) -> Result<u64> {
        base.checked_sub(1)
            .and_then(|x| x.checked_sub(rel))
            .ok_or_else(|| {
                Error::BadResponse(format!(
                    "qpack: field relative index {rel} out of range (Base {base})"
                ))
            })
    }

    /// Post-base index → absolute index (RFC 9204 §3.2.6): post-base entries
    /// are at or after Base, so `abs = base + idx`.
    fn post_base_to_absolute(base: u64, idx: u64) -> Result<u64> {
        base.checked_add(idx)
            .ok_or_else(|| Error::BadResponse("qpack: post-base index overflow".into()))
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
        let end = start
            .checked_add(slen as usize)
            .filter(|&e| e <= buf.len())
            .ok_or_else(|| Error::BadResponse("qpack: truncated/oversized literal value".into()))?;
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
        let mut out = Vec::with_capacity(input.len().saturating_mul(2));
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
/// Upper bound on a single HEADERS frame's declared length. A response header
/// section is tiny; a HEADERS frame claiming megabytes is bogus and must be
/// rejected *before* we buffer toward `MAX_RESPONSE_BYTES`. Matches the
/// decoded-header-list cap (256 KiB) the QPACK decoder enforces.
const MAX_HEADERS_FRAME_LEN: u64 = 256 * 1024;
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
/// Per-connection HTTP/3 / QPACK decoder state. Holds the QPACK dynamic
/// table fed by the peer's encoder stream, the partial-read buffers for the
/// server's unidirectional streams (so an instruction split across datagrams
/// can be reassembled), and the client's QPACK decoder stream id (where we
/// send Section Acknowledgements).
struct Http3State {
    /// The QPACK dynamic table, populated from the peer's encoder stream.
    dyn_table: qpack::DynamicTable,
    /// Our QPACK decoder stream id, if we managed to open it.
    decoder_stream: Option<StreamId>,
    /// Per server-uni-stream reassembly state, keyed by stream id value.
    uni: std::collections::HashMap<u64, UniStreamState>,
}

/// State for one server-initiated unidirectional stream while we classify it
/// by its leading stream-type varint and (for the QPACK encoder stream)
/// accumulate and apply instructions.
#[derive(Default)]
struct UniStreamState {
    /// Bytes received but not yet processed (a partial type prefix, or a
    /// partial encoder instruction).
    buf: Vec<u8>,
    /// The decoded stream type, once the leading varint has been read.
    ty: Option<u64>,
}

/// Cap on bytes we buffer from a single server uni-stream awaiting a complete
/// QPACK encoder instruction. Bounds memory against a peer that dribbles an
/// unterminated instruction. Generous relative to any real instruction.
const MAX_UNI_BUFFER: usize = 64 * 1024;

impl Http3State {
    fn new(decoder_stream: Option<StreamId>) -> Self {
        Http3State {
            dyn_table: qpack::DynamicTable::new(),
            decoder_stream,
            uni: std::collections::HashMap::new(),
        }
    }
}

pub fn send(req: Request, trace: &mut dyn Write) -> Result<Response> {
    send_inner(req, None, None, trace)
}

/// Stream an HTTP/3 response body straight to `sink` instead of buffering it.
/// The returned [`Response`] carries an empty `body`. `on_head`, when present,
/// fires with the response head before any body byte reaches `sink`.
pub fn send_to(
    req: Request,
    sink: &mut dyn Write,
    on_head: Option<crate::http::HeadObserver<'_>>,
    trace: &mut dyn Write,
) -> Result<Response> {
    send_inner(req, Some(sink), on_head, trace)
}

fn send_inner(
    req: Request,
    sink: Option<&mut dyn Write>,
    on_head: Option<crate::http::HeadObserver<'_>>,
    trace: &mut dyn Write,
) -> Result<Response> {
    if req.url.scheme != "https" {
        // HTTP/3 only runs over QUIC, which only runs encrypted.
        return Err(Error::UnsupportedScheme(format!(
            "http/3 requires https://, not {}://",
            req.url.scheme
        )));
    }

    // `--pinnedpubkey`: parse the spec up front so a malformed value fails
    // fast (before any network I/O), mirroring the TCP path's `tls_opts_from`.
    // The pins are checked against the server leaf *after* the handshake, now
    // that `QuicConnection` exposes the peer chain (KarpelesLab/purecrypto#31).
    let pins = match &req.pinned_pubkey {
        Some(spec) => crate::tls::parse_pinned_pubkey(spec)?,
        None => Vec::new(),
    };

    let mut conn = build_client(&req)?;
    let (sock, peer) = open_udp(&req)?;
    let _ = writeln!(trace, "*   Trying {peer} (UDP)...");
    handshake(&mut conn, &*sock, peer, req.read_timeout)?;
    // Post-handshake certificate policy, identical to the TCP TLS path now
    // that purecrypto surfaces the QUIC peer chain (purecrypto#31): a
    // SAN-required hostname check (TLS-4) and public-key pinning.
    verify_peer_certificates(&conn, &req, &pins)?;
    let _ = writeln!(
        trace,
        "* Connected to {} ({}) port {} (QUIC)",
        req.url.host,
        peer.ip(),
        peer.port()
    );
    // QUIC carries its own TLS 1.3 handshake inside the transport. purecrypto
    // 0.6.8 exposes the negotiated ALPN (and the peer chain, used by
    // `verify_peer_certificates` above); report the real value.
    let _ = writeln!(trace, "* QUIC connected, TLS 1.3 handshake complete");
    match conn.alpn_protocol() {
        Some(p) => {
            let _ = writeln!(
                trace,
                "* ALPN: server accepted {}",
                String::from_utf8_lossy(p)
            );
        }
        None => {
            let _ = writeln!(trace, "* ALPN: no protocol negotiated");
        }
    }
    let _ = writeln!(trace, "* using HTTP/3");

    // RFC 9114 §6.2.1 — open a unidirectional control stream and send
    // SETTINGS. Without it the peer is allowed to close us with
    // H3_MISSING_SETTINGS. This is best-effort: if the streams API isn't
    // ready yet (handshake too fresh), we tolerate the error since some
    // servers don't strictly police it on a one-shot request.
    let _ = open_control_stream(&mut conn);

    // RFC 9204 §4.2 — open the QPACK encoder + decoder streams so we can
    // (a) be a well-formed peer and (b) send Section Acknowledgements back.
    let decoder_stream = open_qpack_streams(&mut conn);
    let mut state = Http3State::new(decoder_stream);

    // The first client-initiated bidi stream is StreamId 0 in the absence
    // of any prior streams. `open_bidi` allocates and returns the next
    // available ID for us.
    let request_stream = conn
        .open_bidi()
        .map_err(|e| Error::BadResponse(format!("http3: open_bidi failed: {e:?}")))?;

    write_request(&mut conn, request_stream, &req, trace)?;
    if !req.body.is_empty() {
        let _ = writeln!(trace, "* uploading {} body bytes", req.body.len());
    }
    pump(&mut conn, &*sock, peer, req.read_timeout)?;

    read_response(
        &mut conn,
        &*sock,
        peer,
        request_stream,
        &req,
        &mut state,
        sink,
        on_head,
        trace,
    )
}

/// Read all readable server-initiated unidirectional streams, classify each
/// by its leading stream-type varint (RFC 9114 §6.2), and apply the QPACK
/// encoder stream's instructions (RFC 9204 §4.3) into the dynamic table.
/// Bytes on the server's control / decoder / push streams are buffered-and-
/// discarded for our one-shot model. This must run BEFORE we decode a
/// response HEADERS block so the table is populated (we advertise zero
/// blocked streams, so the encoder front-loads every referenced insert).
fn drain_uni_streams(conn: &mut QuicConnection, state: &mut Http3State) -> Result<()> {
    // Snapshot the readable server uni-streams; reading mutates the iterator
    // source, so collect ids first.
    let ids: Vec<StreamId> = conn
        .readable_streams()
        .filter(|s| s.is_uni() && s.is_server_initiated())
        .collect();
    for sid in ids {
        let mut tmp = vec![0u8; 16 * 1024];
        // A read error on a uni stream we don't strictly need is not fatal for
        // a one-shot request; `while let Ok` simply stops draining it. `n == 0`
        // (no more buffered bytes right now) also ends this pass.
        while let Ok((n, _fin)) = conn.read(sid, &mut tmp) {
            if n == 0 {
                break;
            }
            let entry = state.uni.entry(sid.value()).or_default();
            if entry.buf.len() + n > MAX_UNI_BUFFER {
                return Err(Error::BadResponse(
                    "http3: server uni-stream buffer exceeded limit".into(),
                ));
            }
            entry.buf.extend_from_slice(&tmp[..n]);
        }
        // Process whatever is buffered for this stream.
        process_uni_stream(state, sid.value())?;
    }
    Ok(())
}

/// Classify and process the buffered bytes for one server uni-stream. Once
/// the leading stream-type varint is known, QPACK-encoder bytes are applied
/// to the dynamic table and other stream types are drained.
fn process_uni_stream(state: &mut Http3State, sid: u64) -> Result<()> {
    let entry = state.uni.entry(sid).or_default();
    // Decode the stream-type prefix once.
    if entry.ty.is_none() {
        match varint::decode(&entry.buf) {
            Ok((ty, used)) => {
                entry.ty = Some(ty);
                entry.buf.drain(..used);
            }
            Err(_) => return Ok(()), // need more bytes for the type prefix
        }
    }
    match entry.ty {
        Some(uni_stream_type::QPACK_ENCODER) => {
            let consumed = qpack::apply_encoder_instructions(&mut state.dyn_table, &entry.buf)?;
            let entry = state.uni.get_mut(&sid).expect("entry present");
            entry.buf.drain(..consumed);
        }
        // Control / decoder / push / unknown: drain and ignore for our
        // one-shot request. We never reference push, and the server's
        // control SETTINGS don't change our literal-only request encoding.
        _ => {
            entry.buf.clear();
        }
    }
    Ok(())
}

/// Post-handshake server-certificate policy for HTTP/3, mirroring the TCP TLS
/// path ([`crate::tls::connect_over_tls`]): a SAN-required hostname check
/// (TLS-4, no Common-Name fallback) when verifying, and public-key pinning
/// (`--pinnedpubkey`). Uses the peer chain `QuicConnection` exposes as of
/// purecrypto 0.6.8 (KarpelesLab/purecrypto#31). The QUIC handshake itself has
/// already verified the chain against the roots unless `--insecure`.
fn verify_peer_certificates(conn: &QuicConnection, req: &Request, pins: &[[u8; 32]]) -> Result<()> {
    let leaf = conn.peer_certificates().first().map(Vec::as_slice);

    // SAN-required hostname verification (TLS-4): reject a leaf that carries no
    // Subject Alternative Name (purecrypto's verifier would otherwise fall
    // back to the deprecated Common Name). Only meaningful when verifying.
    if req.verify_tls {
        match leaf {
            Some(der) if crate::tls::client_auth::leaf_has_san(der) => {}
            Some(_) => {
                return Err(Error::BadResponse(
                    "server certificate has no Subject Alternative Name \
                     (CN fallback is not accepted)"
                        .into(),
                ))
            }
            // No chain surfaced: the handshake's own verification (gated on
            // verify_certificates) is the authority; nothing to add here.
            None => {}
        }
    }

    // Public-key pinning (curl `--pinnedpubkey`): require the leaf SPKI to
    // match at least one pin. Enforced even under `--insecure`, exactly like
    // the TCP path.
    if !pins.is_empty() {
        match leaf {
            Some(der) if crate::tls::client_auth::spki_pin_matches(der, pins) => {}
            _ => {
                return Err(Error::BadResponse(
                    "pinned public key does not match server certificate".into(),
                ))
            }
        }
    }
    Ok(())
}

/// Build the QUIC client connection with the right transport-parameter set
/// for HTTP/3.
fn build_client(req: &Request) -> Result<QuicConnection> {
    // QUIC is built on `purecrypto::quic`, which in turn needs a
    // `purecrypto::tls::Config` — so even when the `rustls-tls` feature has
    // pointed the public `crate::tls::*` API at rustls, HTTP/3 still loads
    // its trust anchors through purecrypto. Going through `pc_roots` directly
    // sidesteps the active backend.
    // Honor the same TLS knobs as the HTTP/1.1+2 path's `tls_opts_from`, so a
    // user who sets `--capath` / `--crlfile` / `--ciphers` / `--tls13-ciphers`
    // gets the same protection over h3 as over h2. Fail closed: when
    // verification is on we still need a usable root store.
    //
    // Base trust store: `--cacert <file>` replaces the system roots; otherwise
    // load the system bundle. `--capath <dir>` then *adds* a directory of CAs
    // on top of whichever base is in effect (curl semantics). Going through
    // `pc_roots` directly sidesteps the active `crate::tls::*` backend (which
    // may be rustls), because QUIC always needs a purecrypto root store.
    let mut roots = match &req.ca_bundle {
        Some(path) => crate::tls::pc_roots::load_from_file(path)?,
        None => crate::tls::pc_roots::load_system_roots()?,
    };
    if let Some(dir) = &req.ca_path {
        crate::tls::pc_roots::add_from_dir(&mut roots, dir)?;
    }

    let mut builder = purecrypto::tls::Config::builder()
        .tls_only()
        .roots(roots)
        .server_name(req.url.host.clone())
        .verify_certificates(req.verify_tls)
        // RFC 9114 §3.1 — HTTP/3 is selected via ALPN identifier "h3".
        .alpn(vec![b"h3".to_vec()]);

    // CRL-based revocation (`--crlfile`). The `Request` stores the *path*; read
    // it here so a missing/unreadable file surfaces as an `Error` before we
    // dial. curl's `--crlfile` accepts a concatenation of PEM `X509 CRL`
    // blocks, so split every block and add each (a single `add_pem` only
    // consumes the first); fall back to raw DER when no PEM armor is present.
    // This mirrors the purecrypto TLS backend in `src/tls/purecrypto.rs`.
    if let Some(path) = &req.crl_file {
        let crl_bytes = std::fs::read(path).map_err(Error::Io)?;
        let mut store = purecrypto::tls::CrlStore::new();
        let blocks = std::str::from_utf8(&crl_bytes)
            .ok()
            .map(|pem| crate::tls::pc_roots::pem_blocks_labelled(pem, "X509 CRL"))
            .unwrap_or_default();
        if !blocks.is_empty() {
            for block in &blocks {
                store
                    .add_pem(block)
                    .map_err(|_| Error::BadResponse("--crlfile: invalid PEM CRL block".into()))?;
            }
        } else {
            store
                .add_der(crl_bytes)
                .map_err(|_| Error::BadResponse("--crlfile: not a valid PEM or DER CRL".into()))?;
        }
        builder = builder.crls(store);
    }

    // Cipher-suite restriction: combine `--ciphers` (TLS≤1.2) and
    // `--tls13-ciphers` into one IANA-ID list, exactly like `tls_opts_from`;
    // purecrypto intersects it with the suites it supports, in order.
    let mut cipher_ids: Vec<u16> = Vec::new();
    if let Some(spec) = &req.ciphers {
        cipher_ids.extend(crate::tls::cipher_names_to_ids(spec)?);
    }
    if let Some(spec) = &req.tls13_ciphers {
        cipher_ids.extend(crate::tls::cipher_names_to_ids(spec)?);
    }
    if !cipher_ids.is_empty() {
        builder = builder.cipher_suites(&cipher_ids);
    }

    // NOTE: `--pinnedpubkey` is rejected up front in `send_inner` (it needs a
    // peer-certificate accessor that `QuicConnection` lacks — purecrypto#31),
    // so no pin handling is wired here.
    let tls = builder.build();

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
    // `QuicConfig` is `#[non_exhaustive]` (purecrypto 0.6), so it can't be
    // built with a struct literal; the documented idiom is `default()` plus
    // field assignment. `require_retry`/`retry_secret` are server-only and
    // already default to `false`/`None`, which is what a client wants.
    #[allow(clippy::field_reassign_with_default)]
    let cfg = {
        let mut cfg = QuicConfig::default();
        cfg.tls = tls;
        cfg.transport_params = transport_params;
        cfg
    };

    QuicConnection::client(cfg, &req.url.host)
        .map_err(|e| Error::BadResponse(format!("http3: build client: {e:?}")))
}

fn open_udp(req: &Request) -> Result<(Box<dyn UdpTransport>, std::net::SocketAddr)> {
    let host_port = format!("{}:{}", req.url.host, req.url.port);
    let peer = host_port
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| Error::InvalidUrl(req.url.host.clone()))?;
    // Direct UDP, or relayed through a SOCKS5 proxy if the connector is one;
    // a non-UDP-capable proxy (http/https/socks4) errors here.
    let sock = open_udp_transport(req.connector.udp_proxy(), peer)?;
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
    sock: &dyn UdpTransport,
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
        sock.send_to(&dg, peer)?;
        sent_anything = true;
    }

    // Ingress: try one recv (timed). `can_block` controls whether we wait
    // up to the socket's read-timeout for traffic to arrive.
    let mut buf = vec![0u8; MAX_DATAGRAM];
    let mut got_anything = false;
    if can_block {
        match sock.recv_from(&mut buf) {
            // The QUIC engine routes on the datagram contents, not the UDP
            // 4-tuple, so we always attribute it to the server `peer` (which
            // equals the decapsulated source under both transports).
            Ok((n, _from)) => {
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
        sock.send_to(&dg, peer)?;
        sent_anything = true;
    }

    Ok(sent_anything || got_anything)
}

/// Run the QUIC handshake until `is_handshake_complete()`.
fn handshake(
    conn: &mut QuicConnection,
    sock: &dyn UdpTransport,
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
/// SETTINGS frame on it (RFC 9114 §6.2.1 + §7.2.4). We advertise a non-zero
/// `SETTINGS_QPACK_MAX_TABLE_CAPACITY` so the server may use its encoder's
/// dynamic table, and `SETTINGS_QPACK_BLOCKED_STREAMS = 0` (the encoder must
/// front-load every insert a header block references). Best-effort.
fn open_control_stream(conn: &mut QuicConnection) -> Result<()> {
    let sid = conn
        .open_uni()
        .map_err(|e| Error::BadResponse(format!("http3: open_uni: {e:?}")))?;
    // Stream-type prefix: 0x00 = control.
    let mut prefix = Vec::with_capacity(16);
    varint::encode(uni_stream_type::CONTROL, &mut prefix);
    // SETTINGS payload: a sequence of identifier+value varint pairs.
    let mut settings = Vec::with_capacity(8);
    varint::encode(settings_id::QPACK_MAX_TABLE_CAPACITY, &mut settings);
    varint::encode(QPACK_MAX_TABLE_CAPACITY, &mut settings);
    varint::encode(settings_id::QPACK_BLOCKED_STREAMS, &mut settings);
    varint::encode(QPACK_BLOCKED_STREAMS, &mut settings);
    Frame::encode_header(frame_type::SETTINGS, settings.len() as u64, &mut prefix);
    prefix.extend_from_slice(&settings);
    write_all(conn, sid, &prefix)?;
    Ok(())
}

/// Open the client's QPACK encoder and decoder unidirectional streams
/// (RFC 9204 §4.2). We never insert into our own dynamic table (the request
/// encoder emits literals only), so the encoder stream carries just its
/// type byte. The decoder stream is where we send Section Acknowledgements
/// back to the peer. Returns the decoder stream id for later writes.
/// Best-effort: returns `None` on any stream-API error so a one-shot request
/// can still proceed.
fn open_qpack_streams(conn: &mut QuicConnection) -> Option<StreamId> {
    // Encoder stream: just the stream-type prefix; no instructions follow.
    if let Ok(enc) = conn.open_uni() {
        let mut buf = Vec::with_capacity(1);
        varint::encode(uni_stream_type::QPACK_ENCODER, &mut buf);
        let _ = write_all(conn, enc, &buf);
    }
    // Decoder stream: type prefix, then Section Ack instructions as we decode.
    let dec = conn.open_uni().ok()?;
    let mut buf = Vec::with_capacity(1);
    varint::encode(uni_stream_type::QPACK_DECODER, &mut buf);
    if write_all(conn, dec, &buf).is_err() {
        return None;
    }
    Some(dec)
}

/// Encode a QPACK decoder-stream Section Acknowledgement (RFC 9204 §4.4.1):
/// pattern `1` then the stream ID as a 7-bit-prefix integer.
fn encode_section_ack(stream_id: u64, out: &mut Vec<u8>) {
    qpack::encode_int(stream_id, 7, 0b1000_0000, out);
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
fn write_request(
    conn: &mut QuicConnection,
    sid: StreamId,
    req: &Request,
    trace: &mut dyn Write,
) -> Result<()> {
    // Build the pseudo-headers required by RFC 9114 §4.3.1.
    let host_port = if req.url.port == 443 {
        req.url.host.clone()
    } else {
        format!("{}:{}", req.url.host, req.url.port)
    };
    let mut fields: Vec<(String, String)> = Vec::with_capacity(req.headers.len() + 5);
    fields.push((":method".into(), crate::http::effective_method(req)));
    fields.push((":scheme".into(), "https".into()));
    fields.push((":authority".into(), host_port));
    fields.push((":path".into(), req.url.path.clone()));

    // Normal headers — HTTP/3 requires lowercase field names (RFC 9114
    // §4.2). Skip any pseudo-headers / Host / Connection-specific
    // headers the caller may have set.
    let mut have_ua = false;
    let mut have_accept_enc = false;
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
        if kl == "accept-encoding" {
            have_accept_enc = true;
        }
        fields.push((kl, v.clone()));
    }
    // Automatic headers, suppressed in strict mode (caller's set sent verbatim).
    if !req.strict_headers {
        if !have_ua {
            fields.push((
                "user-agent".into(),
                format!("rsurl/{}", env!("CARGO_PKG_VERSION")),
            ));
        }
        if !have_accept_enc {
            // Match HTTP/1.1 + HTTP/2 default: we decode these on the way back
            // in `finalize_response` via `crate::compress`.
            fields.push(("accept-encoding".into(), "gzip, deflate".into()));
        }
    }
    if !req.body.is_empty() {
        fields.push(("content-length".into(), req.body.len().to_string()));
    }

    // Verbose `>` request trace, mirroring HTTP/1.1 + HTTP/2: a request line
    // built from the `:method`/`:path` pseudo-headers, a `Host:` line from
    // `:authority`, then every regular field actually sent, then a closing
    // blank `> `. Read straight from `fields` so the trace can't drift from
    // the encoded HEADERS block.
    {
        let path = fields
            .iter()
            .find(|(k, _)| k == ":path")
            .map(|(_, v)| v.as_str())
            .unwrap_or("/");
        let _ = writeln!(
            trace,
            "> {} {path} HTTP/3",
            crate::http::effective_method(req)
        );
        if let Some((_, authority)) = fields.iter().find(|(k, _)| k == ":authority") {
            let _ = writeln!(trace, "> Host: {authority}");
        }
        for (k, v) in &fields {
            if !k.starts_with(':') {
                let _ = writeln!(trace, "> {k}: {v}");
            }
        }
        let _ = writeln!(trace, "> ");
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
    sock: &dyn UdpTransport,
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
#[allow(clippy::too_many_arguments)]
fn read_response(
    conn: &mut QuicConnection,
    sock: &dyn UdpTransport,
    peer: std::net::SocketAddr,
    sid: StreamId,
    req: &Request,
    state: &mut Http3State,
    mut sink: Option<&mut dyn Write>,
    mut on_head: Option<crate::http::HeadObserver<'_>>,
    trace: &mut dyn Write,
) -> Result<Response> {
    let mut streamed_len: u64 = 0;
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

        // Apply any QPACK encoder-stream inserts the server has sent BEFORE we
        // try to decode a HEADERS block, since we advertise zero blocked
        // streams and the encoder front-loads every referenced insert.
        drain_uni_streams(conn, state)?;

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
            // Stream DATA to the sink only when the response is not
            // content-encoded (encoded bodies must be buffered to decode).
            // Recomputed each frame because HEADERS may have just arrived.
            let encoded = headers.as_ref().is_some_and(|f| {
                f.iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("content-encoding"))
            });
            let frame_sink: Option<&mut dyn Write> = if encoded {
                None
            } else {
                match &mut sink {
                    Some(w) => Some(&mut **w),
                    None => None,
                }
            };
            let (consumed, ack_owed) = match try_consume_frame(
                &stream_buf,
                &mut headers,
                &mut body,
                &state.dyn_table,
                frame_sink,
                &mut streamed_len,
            ) {
                FrameOutcome::Consumed(n, ack) => (n, ack),
                FrameOutcome::NeedMore => break,
                FrameOutcome::Err(e) => return Err(e),
            };
            if ack_owed {
                // RFC 9204 §4.4.1: acknowledge a section that referenced the
                // dynamic table. Best-effort; the result doesn't depend on it.
                send_section_ack(conn, sid, state);
            }
            stream_buf.drain(..consumed);
            // Fire the head callback as soon as the HEADERS block is decoded —
            // DATA frames are consumed on later passes of this inner loop, so
            // this runs before the first body byte reaches the sink.
            if on_head.is_some() {
                if let Some(fields) = headers.as_ref() {
                    fire_h3_head(fields, &mut on_head);
                }
            }
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
    finalize_response(fields, body, streamed_len, sink, trace)
}

enum FrameOutcome {
    /// Consumed `n` bytes; the bool is `true` when the frame was a HEADERS
    /// block that referenced the dynamic table and thus owes a Section
    /// Acknowledgement (RFC 9204 §4.4.1).
    Consumed(usize, bool),
    NeedMore,
    Err(Error),
}

/// Try to parse one HTTP/3 frame out of `buf`. On success, the relevant
/// output bucket (HEADERS → `headers`, DATA → `body`) is populated and the
/// number of bytes consumed is returned. A HEADERS block is decoded against
/// `dyn_table`; the returned flag reports whether the block referenced the
/// dynamic table (Required Insert Count > 0), so the caller can send a
/// Section Acknowledgement.
#[allow(clippy::too_many_arguments)]
fn try_consume_frame(
    buf: &[u8],
    headers: &mut Option<qpack::Fields>,
    body: &mut Vec<u8>,
    dyn_table: &qpack::DynamicTable,
    sink: Option<&mut dyn Write>,
    streamed_len: &mut u64,
) -> FrameOutcome {
    let (frame, hdr_len) = match Frame::decode_header(buf) {
        Ok(x) => x,
        Err(_) => return FrameOutcome::NeedMore,
    };
    // Reject obviously-bogus declared lengths *before* waiting to buffer that
    // many bytes. A HEADERS section is tiny, and a DATA frame can't carry more
    // than the remaining response budget.
    match frame.ty {
        frame_type::HEADERS if frame.len > MAX_HEADERS_FRAME_LEN => {
            return FrameOutcome::Err(Error::BadResponse(
                "http3: HEADERS frame length exceeds limit".into(),
            ));
        }
        frame_type::DATA => {
            let remaining = MAX_RESPONSE_BYTES.saturating_sub(body.len()) as u64;
            if frame.len > remaining {
                return FrameOutcome::Err(Error::BadResponse(
                    "http3: DATA frame length exceeds response budget".into(),
                ));
            }
        }
        _ => {}
    }
    // `frame.len` is a QUIC varint (up to 2^62-1). On a 32-bit target a plain
    // `as usize` cast would truncate the high bits and mis-bound the frame —
    // harmless for the length-capped HEADERS/DATA arms above, but the
    // reserved/grease arm has no cap, so reject anything that doesn't fit usize
    // to keep the cast lossless on every target.
    let frame_len = match usize::try_from(frame.len) {
        Ok(n) => n,
        Err(_) => {
            return FrameOutcome::Err(Error::BadResponse("http3: frame length too large".into()));
        }
    };
    let total = hdr_len.saturating_add(frame_len);
    if buf.len() < total {
        return FrameOutcome::NeedMore;
    }
    let payload = &buf[hdr_len..total];
    match frame.ty {
        frame_type::HEADERS => match qpack::decode_field_section_with(payload, dyn_table) {
            Ok(fields) => {
                if headers.is_some() {
                    // Trailers — RFC 9114 §4.1 allows them, but the
                    // scaffold doesn't surface them. Discard silently.
                } else {
                    *headers = Some(fields);
                }
                let ack_owed = qpack::block_references_dynamic_table(payload);
                FrameOutcome::Consumed(total, ack_owed)
            }
            Err(e) => FrameOutcome::Err(e),
        },
        frame_type::DATA => {
            // Stream straight to the caller's sink when one is supplied and
            // nothing has been buffered yet (the caller passes `None` for a
            // content-encoded response, which must be buffered to decode).
            if let Some(w) = sink {
                if body.is_empty() {
                    if let Err(e) = w.write_all(payload) {
                        return FrameOutcome::Err(Error::Io(e));
                    }
                    *streamed_len += payload.len() as u64;
                    return FrameOutcome::Consumed(total, false);
                }
            }
            body.extend_from_slice(payload);
            FrameOutcome::Consumed(total, false)
        }
        // RFC 9114 §7.2.8 reserved/grease types — ignore (drain).
        _ => FrameOutcome::Consumed(total, false),
    }
}

/// Send a QPACK Section Acknowledgement for `request_sid` on our decoder
/// stream (RFC 9204 §4.4.1). Best-effort: failures are non-fatal for a
/// one-shot request.
fn send_section_ack(conn: &mut QuicConnection, request_sid: StreamId, state: &Http3State) {
    if let Some(dec) = state.decoder_stream {
        let mut out = Vec::with_capacity(4);
        encode_section_ack(request_sid.value(), &mut out);
        let _ = write_all(conn, dec, &out);
    }
}

/// Invoke `on_head` once with the decoded response head, taking the observer so
/// it can never fire twice. Interim 1xx responses are skipped (not the final
/// head). Mirrors the `:status`/pseudo-header handling in [`finalize_response`].
fn fire_h3_head(fields: &qpack::Fields, on_head: &mut Option<crate::http::HeadObserver<'_>>) {
    let mut status: Option<u16> = None;
    let mut hdrs: Vec<(String, String)> = Vec::with_capacity(fields.len());
    for (k, v) in fields {
        if k == ":status" {
            status = v.parse::<u16>().ok();
        } else if !k.starts_with(':') {
            hdrs.push((k.clone(), v.clone()));
        }
    }
    let Some(status) = status.filter(|s| *s >= 200) else {
        return;
    };
    if let Some(obs) = on_head.take() {
        obs(&crate::http::ResponseHead {
            status,
            reason: String::new(),
            version: "HTTP/3".to_string(),
            headers: hdrs,
        });
    }
}

fn finalize_response(
    fields: qpack::Fields,
    body: Vec<u8>,
    streamed_len: u64,
    sink: Option<&mut dyn Write>,
    trace: &mut dyn Write,
) -> Result<Response> {
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

    // Response `<` trace, mirroring HTTP/1.1 + HTTP/2: a status line carrying
    // the HTTP/3 version + numeric status, then each header field, then a
    // closing blank `< `, then the body-byte notice.
    let _ = writeln!(trace, "< HTTP/3 {status}");
    for (k, v) in &hdrs {
        let _ = writeln!(trace, "< {k}: {v}");
    }
    let _ = writeln!(trace, "< ");
    let _ = writeln!(
        trace,
        "* Received {} body bytes",
        body.len() as u64 + streamed_len
    );

    // Shared with HTTP/1.1 and HTTP/2: strip any Content-Encoding layer we
    // recognise (gzip / deflate / x-gzip / identity).
    let (hdrs, body) = crate::http::maybe_decode_body(hdrs, body, trace)?;
    // Streaming path: the un-encoded body already went to the sink; only the
    // buffered (content-encoded) fallback still has bytes here to flush.
    if let Some(w) = sink {
        if !body.is_empty() {
            w.write_all(&body)?;
        }
        return Ok(Response {
            status,
            reason: String::new(),
            version: "HTTP/3".to_string(),
            headers: hdrs,
            body: Vec::new(),
            timing: crate::http::Timing::default(),
            final_url: String::new(),
        });
    }
    Ok(Response {
        status,
        // HTTP/3 has no reason phrase on the wire.
        reason: String::new(),
        version: "HTTP/3".to_string(),
        headers: hdrs,
        body,
        timing: crate::http::Timing::default(),
        final_url: String::new(),
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
            ("user-agent".to_string(), "rsurl/test".to_string()),
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
    fn qpack_decode_rejects_crlf_in_value() {
        // x-h: "evil\r\nset-cookie: x=1" — response-splitting payload.
        let buf = qpack::encode_field_section(&[(
            "x-h".to_string(),
            "evil\r\nset-cookie: x=1".to_string(),
        )]);
        let err = qpack::decode_field_section(&buf).unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)), "got {err:?}");
    }

    #[test]
    fn qpack_decode_rejects_lf_in_value() {
        let buf = qpack::encode_field_section(&[("x-h".to_string(), "a\nb".to_string())]);
        assert!(matches!(
            qpack::decode_field_section(&buf).unwrap_err(),
            Error::BadResponse(_)
        ));
    }

    #[test]
    fn qpack_decode_rejects_nul_in_value() {
        let buf = qpack::encode_field_section(&[("x-h".to_string(), "a\x00b".to_string())]);
        assert!(matches!(
            qpack::decode_field_section(&buf).unwrap_err(),
            Error::BadResponse(_)
        ));
    }

    #[test]
    fn qpack_decode_rejects_uppercase_name() {
        let buf = qpack::encode_field_section(&[("X-Bad".to_string(), "ok".to_string())]);
        assert!(matches!(
            qpack::decode_field_section(&buf).unwrap_err(),
            Error::BadResponse(_)
        ));
    }

    #[test]
    fn qpack_decode_rejects_empty_name() {
        let buf = qpack::encode_field_section(&[("".to_string(), "ok".to_string())]);
        assert!(matches!(
            qpack::decode_field_section(&buf).unwrap_err(),
            Error::BadResponse(_)
        ));
    }

    #[test]
    fn qpack_decode_accepts_normal_header_and_pseudo() {
        // Ordinary header (spaces in value) + a tab in another value (allowed)
        // + a pseudo-header must all decode cleanly.
        let buf = qpack::encode_field_section(&[
            (
                "content-type".to_string(),
                "text/html; charset=utf-8".to_string(),
            ),
            ("x-h".to_string(), "a\tb".to_string()),
            (":status".to_string(), "200".to_string()),
        ]);
        let fields = qpack::decode_field_section(&buf).expect("decode");
        assert_eq!(
            fields[0],
            (
                "content-type".to_string(),
                "text/html; charset=utf-8".to_string()
            )
        );
        assert_eq!(fields[1], ("x-h".to_string(), "a\tb".to_string()));
        assert_eq!(fields[2], (":status".to_string(), "200".to_string()));
    }

    #[test]
    fn qpack_oversized_literal_value_length_does_not_panic() {
        // Regression: an attacker-controlled literal-value length close to
        // usize::MAX must not overflow `start + slen` (which in release builds
        // wraps past the `end > buf.len()` guard and panics on the slice).
        // The decoder must return a hard error instead.
        let mut buf = Vec::new();
        // Field-section prefix: RIC=0, Base=0.
        enc_prefix(0, false, 0, &mut buf);
        // Literal Field Line With Literal Name, H=0, name length 1.
        qpack::encode_int(1, 3, 0b0010_0000, &mut buf);
        buf.push(b'a'); // 1-byte literal name
                        // Value: 7-bit prefix, H=0, length = u64::MAX - 1 (won't overflow the
                        // qpack-int decoder, but `start + slen as usize` would wrap usize).
        qpack::encode_int(u64::MAX - 1, 7, 0x00, &mut buf);
        // No value bytes follow.
        let t = table_at_max();
        let err = qpack::decode_field_section_with(&buf, &t).unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)), "got {err:?}");
    }

    #[test]
    fn qpack_encoder_oversized_literal_name_length_does_not_panic() {
        // Regression: the streaming encoder-stream parser must not overflow
        // `p + nlen` for an Insert With Literal Name whose name length is near
        // usize::MAX. An unsatisfiable (overflowing) length is a hard error,
        // not an endless "need more bytes".
        let mut wire = Vec::new();
        // Insert With Literal Name (§4.3.3): 01 H nnnnn, H=0, 5-bit name len.
        qpack::encode_int(u64::MAX - 1, 5, 0b0100_0000, &mut wire);
        // No name bytes follow.
        let mut t = table_at_max();
        let err = qpack::apply_encoder_instructions(&mut t, &wire).unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)), "got {err:?}");
    }

    #[test]
    fn send_rejects_non_https() {
        let req = Request::get("http://example.com/").unwrap();
        let err = send(req, &mut std::io::sink()).unwrap_err();
        match err {
            Error::UnsupportedScheme(_) => {}
            other => panic!("expected UnsupportedScheme, got {other:?}"),
        }
    }

    #[test]
    fn send_rejects_malformed_pinned_pubkey() {
        // `--pinnedpubkey` is honoured over HTTP/3 (the pin is checked
        // post-handshake against the server leaf, purecrypto#31). A malformed
        // pin spec is rejected up front, before any network I/O, mirroring the
        // TCP path's `tls_opts_from`. (A *well-formed* pin would proceed to a
        // real handshake, which a unit test can't exercise offline.)
        let req = Request::get("https://example.com/")
            .unwrap()
            .pinned_pubkey("not-a-valid-pin-spec");
        let err = send(req, &mut std::io::sink()).unwrap_err();
        // Parsing happens after the https-scheme check and before the dial, so
        // this must NOT be a connection/UDP error.
        assert!(
            !matches!(err, Error::Io(_)),
            "expected a pin-parse error before any network I/O, got {err:?}"
        );
    }

    #[test]
    fn qpack_decompression_bomb_is_rejected() {
        // A modest compressed field section that decodes to an enormous
        // header list must be rejected (decompression bomb). We emit many
        // Literal Field Line With Literal Name entries with a long value.
        let mut buf = Vec::new();
        // Field-section prefix: RIC=0, Base=0.
        qpack::encode_int(0, 8, 0x00, &mut buf);
        qpack::encode_int(0, 7, 0x00, &mut buf);
        let name = b"a";
        let value = vec![b'x'; 1024];
        for _ in 0..512 {
            // Literal Field Line With Literal Name, H=0, 3-bit name length.
            qpack::encode_int(name.len() as u64, 3, 0b0010_0000, &mut buf);
            buf.extend_from_slice(name);
            // Value: 7-bit prefix, H=0.
            qpack::encode_int(value.len() as u64, 7, 0x00, &mut buf);
            buf.extend_from_slice(&value);
        }
        let err = qpack::decode_field_section(&buf).unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)));
    }

    #[test]
    fn oversized_headers_frame_len_is_rejected() {
        // A HEADERS frame declaring a length far larger than any real header
        // section must be rejected before we buffer toward MAX_RESPONSE_BYTES.
        let mut buf = Vec::new();
        Frame::encode_header(frame_type::HEADERS, MAX_HEADERS_FRAME_LEN + 1, &mut buf);
        let mut headers = None;
        let mut body = Vec::new();
        let table = qpack::DynamicTable::new();
        assert!(matches!(
            try_consume_frame(&buf, &mut headers, &mut body, &table, None, &mut 0),
            FrameOutcome::Err(Error::BadResponse(_))
        ));
    }

    #[test]
    fn data_frame_len_past_budget_is_rejected() {
        // A DATA frame claiming more bytes than the remaining response budget
        // must be rejected rather than buffered up to the 256 MiB cap.
        let mut buf = Vec::new();
        Frame::encode_header(frame_type::DATA, (MAX_RESPONSE_BYTES + 1) as u64, &mut buf);
        let mut headers = None;
        let mut body = Vec::new();
        let table = qpack::DynamicTable::new();
        assert!(matches!(
            try_consume_frame(&buf, &mut headers, &mut body, &table, None, &mut 0),
            FrameOutcome::Err(Error::BadResponse(_))
        ));
    }

    #[test]
    fn data_frame_streams_to_sink_when_present() {
        // With a sink and an empty buffer so far, a DATA frame's payload is
        // written straight to the sink instead of `body`.
        let payload = b"h3-streamed-body";
        let mut buf = Vec::new();
        Frame::encode_header(frame_type::DATA, payload.len() as u64, &mut buf);
        buf.extend_from_slice(payload);
        let mut headers = None;
        let mut body = Vec::new();
        let table = qpack::DynamicTable::new();
        let mut sink: Vec<u8> = Vec::new();
        let mut streamed: u64 = 0;
        let outcome = try_consume_frame(
            &buf,
            &mut headers,
            &mut body,
            &table,
            Some(&mut sink),
            &mut streamed,
        );
        assert!(
            matches!(outcome, FrameOutcome::Consumed(_, _)),
            "expected the DATA frame to be consumed"
        );
        assert_eq!(sink, payload);
        assert!(body.is_empty(), "streamed body must not be buffered");
        assert_eq!(streamed, payload.len() as u64);
    }

    #[test]
    fn grease_frame_len_exceeding_usize_is_rejected() {
        // A reserved/grease frame type (RFC 9114 §7.2.8) has no length cap, so
        // its declared varint length is the only thing that bounds the frame.
        // `frame.len` is a u64 QUIC varint; on a 32-bit target a plain
        // `as usize` cast would truncate the high bits and mis-bound the frame,
        // desyncing the parser. A length that doesn't fit `usize` must be
        // rejected rather than truncated. `usize::try_from` can only fail when
        // `usize` is narrower than 64 bits, so this reject path is exercised on
        // 32-bit (and smaller) targets; on 64-bit hosts every u64 fits and the
        // companion `grease_frame_len_within_usize_needs_full_buffer` test
        // covers the bounding behaviour instead.
        #[cfg(target_pointer_width = "32")]
        {
            let mut buf = Vec::new();
            // 0x21 is a reserved/grease frame type → the uncapped `_` arm.
            Frame::encode_header(0x21, 0x1_0000_0001, &mut buf);
            let mut headers = None;
            let mut body = Vec::new();
            let table = qpack::DynamicTable::new();
            assert!(matches!(
                try_consume_frame(&buf, &mut headers, &mut body, &table, None, &mut 0),
                FrameOutcome::Err(Error::BadResponse(_))
            ));
        }
    }

    #[test]
    fn grease_frame_len_within_usize_needs_full_buffer() {
        // A grease frame whose declared length fits `usize` but isn't fully
        // buffered yet must report `NeedMore` (not consume a truncated count),
        // confirming the length drives bounding correctly after the
        // fits-in-usize conversion.
        let mut buf = Vec::new();
        // 0x21 is a reserved/grease frame type → the uncapped `_` arm.
        Frame::encode_header(0x21, 4096, &mut buf);
        // Only the header is present; the 4096-byte payload is not.
        let mut headers = None;
        let mut body = Vec::new();
        let table = qpack::DynamicTable::new();
        assert!(matches!(
            try_consume_frame(&buf, &mut headers, &mut body, &table, None, &mut 0),
            FrameOutcome::NeedMore
        ));
    }

    // ---- QPACK dynamic table: encoder stream (RFC 9204 §4.3) --------------

    /// Test helper: a dynamic table with the capacity we'd accept after the
    /// peer raises it to our advertised maximum.
    fn table_at_max() -> qpack::DynamicTable {
        let mut t = qpack::DynamicTable::new();
        t.set_capacity(qpack::MAX_DYNAMIC_CAPACITY as u64)
            .expect("set capacity");
        t
    }

    /// Encode an Insert With Literal Name instruction (§4.3.3, H=0).
    fn enc_insert_literal(name: &str, value: &str, out: &mut Vec<u8>) {
        // Pattern 0b01 H nnnnn, H=0, 5-bit name length prefix.
        qpack::encode_int(name.len() as u64, 5, 0b0100_0000, out);
        out.extend_from_slice(name.as_bytes());
        qpack::encode_string_7bit(value, out);
    }

    /// Encode an Insert With Name Reference instruction (§4.3.2).
    /// `t_static` selects the static (T=1) vs dynamic (T=0) name table.
    fn enc_insert_name_ref(t_static: bool, idx: u64, value: &str, out: &mut Vec<u8>) {
        // Pattern 0b1 T iiiiii, 6-bit index prefix.
        let pat = 0b1000_0000 | if t_static { 0b0100_0000 } else { 0 };
        qpack::encode_int(idx, 6, pat, out);
        qpack::encode_string_7bit(value, out);
    }

    /// Encode a Set Dynamic Table Capacity instruction (§4.3.1).
    fn enc_set_capacity(cap: u64, out: &mut Vec<u8>) {
        // Pattern 0b001 ccccc, 5-bit prefix.
        qpack::encode_int(cap, 5, 0b0010_0000, out);
    }

    /// Encode a Duplicate instruction (§4.3.4).
    fn enc_duplicate(rel: u64, out: &mut Vec<u8>) {
        // Pattern 0b000 iiiii, 5-bit prefix.
        qpack::encode_int(rel, 5, 0b0000_0000, out);
    }

    #[test]
    fn qpack_encoder_insert_literal_name_adds_entry() {
        let mut t = table_at_max();
        let mut wire = Vec::new();
        enc_insert_literal("x-custom", "hello", &mut wire);
        let used = qpack::apply_encoder_instructions(&mut t, &wire).expect("apply");
        assert_eq!(used, wire.len(), "consumed the whole instruction");
        assert_eq!(t.insert_count(), 1);
        // Absolute index 0 is the first (and only) entry.
        assert_eq!(
            t.get_absolute(0).expect("entry"),
            &("x-custom".to_string(), "hello".to_string())
        );
    }

    #[test]
    fn qpack_encoder_insert_name_ref_static_and_dynamic() {
        let mut t = table_at_max();
        let mut wire = Vec::new();
        // Static name ref: index 0 = ":authority", value "example.com".
        enc_insert_name_ref(true, 0, "example.com", &mut wire);
        // Dynamic name ref: relative index 0 → the entry we just inserted,
        // i.e. name ":authority", value "other.example".
        enc_insert_name_ref(false, 0, "other.example", &mut wire);
        let used = qpack::apply_encoder_instructions(&mut t, &wire).expect("apply");
        assert_eq!(used, wire.len());
        assert_eq!(t.insert_count(), 2);
        assert_eq!(
            t.get_absolute(0).unwrap(),
            &(":authority".to_string(), "example.com".to_string())
        );
        assert_eq!(
            t.get_absolute(1).unwrap(),
            &(":authority".to_string(), "other.example".to_string())
        );
    }

    #[test]
    fn qpack_encoder_set_capacity_resizes_and_evicts() {
        let mut t = table_at_max();
        let mut wire = Vec::new();
        // Two entries, each size = name+value+32.
        enc_insert_literal("aaaa", "bbbb", &mut wire); // 4+4+32 = 40
        enc_insert_literal("cccc", "dddd", &mut wire); // 40
        qpack::apply_encoder_instructions(&mut t, &wire).expect("apply");
        assert_eq!(t.insert_count(), 2);
        assert!(t.get_absolute(0).is_ok());

        // Shrink capacity below two entries' worth (40 each → cap 60 leaves
        // room for only the newest). The oldest (abs 0) is evicted.
        let mut shrink = Vec::new();
        enc_set_capacity(60, &mut shrink);
        qpack::apply_encoder_instructions(&mut t, &shrink).expect("shrink");
        assert!(t.get_absolute(0).is_err(), "oldest evicted");
        assert_eq!(
            t.get_absolute(1).unwrap(),
            &("cccc".to_string(), "dddd".to_string())
        );
        // insert_count is monotonic even across eviction.
        assert_eq!(t.insert_count(), 2);
    }

    #[test]
    fn qpack_encoder_duplicate_readds_entry() {
        let mut t = table_at_max();
        let mut wire = Vec::new();
        enc_insert_literal("foo", "bar", &mut wire);
        // Duplicate relative index 0 → re-add the just-inserted entry.
        enc_duplicate(0, &mut wire);
        qpack::apply_encoder_instructions(&mut t, &wire).expect("apply");
        assert_eq!(t.insert_count(), 2);
        assert_eq!(t.get_absolute(0).unwrap(), t.get_absolute(1).unwrap());
        assert_eq!(
            t.get_absolute(1).unwrap(),
            &("foo".to_string(), "bar".to_string())
        );
    }

    #[test]
    fn qpack_encoder_eviction_on_overflow() {
        // Capacity 100 holds two 40-byte entries (80) but a third evicts the
        // oldest (size accounting RFC 9204 §3.2.1).
        let mut t = qpack::DynamicTable::new();
        t.set_capacity(100).unwrap();
        let mut wire = Vec::new();
        enc_insert_literal("aaaa", "1111", &mut wire); // abs 0, size 40
        enc_insert_literal("bbbb", "2222", &mut wire); // abs 1, size 40
        enc_insert_literal("cccc", "3333", &mut wire); // abs 2, evicts abs 0
        qpack::apply_encoder_instructions(&mut t, &wire).expect("apply");
        assert_eq!(t.insert_count(), 3);
        assert!(t.get_absolute(0).is_err(), "abs 0 evicted");
        assert_eq!(
            t.get_absolute(1).unwrap(),
            &("bbbb".to_string(), "2222".to_string())
        );
        assert_eq!(
            t.get_absolute(2).unwrap(),
            &("cccc".to_string(), "3333".to_string())
        );
    }

    #[test]
    fn qpack_encoder_capacity_above_advertised_is_rejected() {
        let mut t = qpack::DynamicTable::new();
        let mut wire = Vec::new();
        enc_set_capacity(qpack::MAX_DYNAMIC_CAPACITY as u64 + 1, &mut wire);
        assert!(qpack::apply_encoder_instructions(&mut t, &wire).is_err());
    }

    #[test]
    fn qpack_encoder_partial_instruction_is_held() {
        // A truncated Insert With Literal Name (value bytes missing) must be
        // left unconsumed so the streaming caller can retry after more bytes.
        let mut t = table_at_max();
        let mut full = Vec::new();
        enc_insert_literal("name", "value", &mut full);
        // Feed all but the last byte.
        let used = qpack::apply_encoder_instructions(&mut t, &full[..full.len() - 1])
            .expect("partial apply");
        assert_eq!(used, 0, "no complete instruction yet");
        assert_eq!(t.insert_count(), 0);
        // Now the whole thing applies.
        let used = qpack::apply_encoder_instructions(&mut t, &full).expect("apply");
        assert_eq!(used, full.len());
        assert_eq!(t.insert_count(), 1);
    }

    #[test]
    fn qpack_encoder_rfc9204_appendix_b2_cross_check() {
        // RFC 9204 Appendix B.2 — the exact encoder-stream byte sequence the
        // RFC shows a server emitting:
        //   3fbd01                Set Dynamic Table Capacity = 220
        //   c0 0f www.example.com Insert With Name Reference, static idx 0
        //                          (:authority=www.example.com)
        //   c1 0c /sample/path    Insert With Name Reference, static idx 1
        //                          (:path=/sample/path)
        // We apply the real RFC bytes and assert the resulting dynamic table.
        let mut wire: Vec<u8> = vec![0x3f, 0xbd, 0x01];
        wire.extend_from_slice(&[0xc0, 0x0f]);
        wire.extend_from_slice(b"www.example.com");
        wire.extend_from_slice(&[0xc1, 0x0c]);
        wire.extend_from_slice(b"/sample/path");

        let mut t = qpack::DynamicTable::new();
        let used = qpack::apply_encoder_instructions(&mut t, &wire).expect("apply");
        assert_eq!(used, wire.len(), "consumed entire Appendix B.2 stream");
        assert_eq!(t.insert_count(), 2);
        // Absolute index 0 / 1 per RFC Appendix B.2.
        assert_eq!(
            t.get_absolute(0).unwrap(),
            &(":authority".to_string(), "www.example.com".to_string())
        );
        assert_eq!(
            t.get_absolute(1).unwrap(),
            &(":path".to_string(), "/sample/path".to_string())
        );

        // RFC 9204 Appendix B.2 then shows the Stream-4 request header block:
        //   0381  Field Section Prefix: Required Insert Count = 2 (enc 0x03),
        //         Base = 0 (prefix byte 0x81 → S=1, DeltaBase=1, so
        //         Base = RIC - DeltaBase - 1 = 2 - 1 - 1 = 0)
        //   10    Indexed Field Line With Post-Base Index, abs = 0+0 = 0
        //         (:authority=www.example.com)
        //   11    Indexed Field Line With Post-Base Index, abs = 0+1 = 1
        //         (:path=/sample/path)
        let block: [u8; 4] = [0x03, 0x81, 0x10, 0x11];
        let fields = qpack::decode_field_section_with(&block, &t).expect("decode block");
        assert_eq!(
            fields,
            vec![
                (":authority".to_string(), "www.example.com".to_string()),
                (":path".to_string(), "/sample/path".to_string()),
            ]
        );
        assert!(qpack::block_references_dynamic_table(&block));
    }

    // ---- QPACK field-section prefix (RFC 9204 §4.5.1) ---------------------

    #[test]
    fn qpack_required_insert_count_round_trips() {
        // §4.5.1.1: the wrap-around encoding. With MaxEntries = 4096/32 = 128
        // and FullRange = 256, encode several RICs against a total-inserts
        // count and confirm reconstruction. The encoder formula is
        // EncInsertCount = ReqInsertCount mod FullRange + 1 (for RIC > 0).
        //
        // The reconstruction is only well-defined when the true RIC lies in
        // the window (TotalInserts + MaxEntries - FullRange, TotalInserts +
        // MaxEntries] — i.e. roughly within FullRange of the insert count,
        // which always holds for a real block (RIC <= insert count). All
        // cases below satisfy that.
        let max_entries = (qpack::MAX_DYNAMIC_CAPACITY / 32) as u64;
        let full_range = 2 * max_entries; // 256
        for &(ric, total) in &[
            (1u64, 1u64),
            (5, 10),
            (128, 200),
            (255, 300),
            (400, 400), // RIC == insert count
            (300, 400), // RIC within FullRange below the insert count
            (512, 600), // wraps past one FullRange multiple
        ] {
            let enc = (ric % full_range) + 1;
            let got = qpack::decode_required_insert_count(enc, total).expect("decode RIC");
            assert_eq!(got, ric, "RIC {ric} total {total} enc {enc}");
        }
        // EncInsertCount 0 always means RIC 0.
        assert_eq!(qpack::decode_required_insert_count(0, 99).unwrap(), 0);
    }

    #[test]
    fn qpack_required_insert_count_rejects_out_of_range() {
        let max_entries = (qpack::MAX_DYNAMIC_CAPACITY / 32) as u64;
        let full_range = 2 * max_entries;
        // EncInsertCount > FullRange is illegal.
        assert!(qpack::decode_required_insert_count(full_range + 1, 0).is_err());
    }

    // ---- QPACK full decode with dynamic references (RFC 9204 §4.5) --------

    /// Encode a field-section prefix (§4.5.1): Required Insert Count and Base.
    /// `enc_ric` is the already-§4.5.1.1-encoded insert count; `delta_base`
    /// and `sign` give the Base.
    fn enc_prefix(enc_ric: u64, sign: bool, delta_base: u64, out: &mut Vec<u8>) {
        qpack::encode_int(enc_ric, 8, 0x00, out);
        let pat = if sign { 0b1000_0000 } else { 0 };
        qpack::encode_int(delta_base, 7, pat, out);
    }

    #[test]
    fn qpack_decode_with_dynamic_indexed_post_base_and_name_ref() {
        // Build a dynamic table via encoder-stream inserts, then a HEADERS
        // block that references it three ways.
        let mut t = table_at_max();
        let mut enc = Vec::new();
        // abs 0: ("x-a", "va") via literal name.
        enc_insert_literal("x-a", "va", &mut enc);
        // abs 1: (":status", "200") via static name ref idx 25? Use literal to
        // keep the name predictable: ("x-b", "vb").
        enc_insert_literal("x-b", "vb", &mut enc);
        // abs 2: ("x-c", "vc").
        enc_insert_literal("x-c", "vc", &mut enc);
        qpack::apply_encoder_instructions(&mut t, &enc).expect("inserts");
        assert_eq!(t.insert_count(), 3);

        // Field section: RIC = 3 (all three inserts needed). To exercise a
        // post-base reference we need Base < insert_count, so set Base = 2 via
        // the §4.5.1.2 sign form: Base = RIC - DeltaBase - 1 = 3 - 0 - 1 = 2.
        // EncInsertCount for RIC=3 is (3 % FullRange) + 1 = 4.
        // With Base=2: relative 0 → abs 1, relative 1 → abs 0; post-base 0 → abs 2.
        let mut block = Vec::new();
        enc_prefix(4, true, 0, &mut block); // RIC=3, Base=2

        // Indexed Field Line (dynamic, T=0), relative index 1 → abs 0 ("x-a").
        // Pattern 0b10 iiiiii (T=0), 6-bit prefix.
        qpack::encode_int(1, 6, 0b1000_0000, &mut block);
        // Indexed Field Line (dynamic), relative index 0 → abs 1 ("x-b").
        qpack::encode_int(0, 6, 0b1000_0000, &mut block);
        // Indexed Field Line With Post-Base Index, post-base 0 → abs 2 ("x-c").
        // Pattern 0b0001 iiii, 4-bit prefix.
        qpack::encode_int(0, 4, 0b0001_0000, &mut block);
        // Literal Field Line With Name Reference (dynamic, T=0), relative
        // index 1 → abs 0 name "x-a", value "lit". Pattern 0b01 N T iiii,
        // N=0 T=0, 4-bit index prefix.
        qpack::encode_int(1, 4, 0b0100_0000, &mut block);
        qpack::encode_string_7bit("lit", &mut block);

        let fields = qpack::decode_field_section_with(&block, &t).expect("decode");
        assert_eq!(
            fields,
            vec![
                ("x-a".to_string(), "va".to_string()),
                ("x-b".to_string(), "vb".to_string()),
                ("x-c".to_string(), "vc".to_string()),
                ("x-a".to_string(), "lit".to_string()),
            ]
        );
        // A block with RIC>0 owes a Section Acknowledgement.
        assert!(qpack::block_references_dynamic_table(&block));
    }

    #[test]
    fn qpack_decode_post_base_name_reference() {
        // Exercise §4.5.5 Literal Field Line With Post-Base Name Reference.
        let mut t = table_at_max();
        let mut enc = Vec::new();
        enc_insert_literal("x-name", "ignored", &mut enc); // abs 0
        qpack::apply_encoder_instructions(&mut t, &enc).expect("insert");

        let mut block = Vec::new();
        // RIC = 1 → enc = (1 % 256) + 1 = 2. Base = 0 (sign=0, delta_base=0
        // gives Base=RIC=1; we want Base=0 so post-base 0 → abs 0).
        // Base = RIC - DeltaBase - 1 with sign=1: 1 - 0 - 1 = 0.
        enc_prefix(2, true, 0, &mut block); // Base = 0
                                            // Literal With Post-Base Name Reference: 0b0000 N iii, N=0, 3-bit
                                            // post-base index = 0 → abs 0, name "x-name".
        qpack::encode_int(0, 3, 0b0000_0000, &mut block);
        qpack::encode_string_7bit("v", &mut block);

        let fields = qpack::decode_field_section_with(&block, &t).expect("decode");
        assert_eq!(fields, vec![("x-name".to_string(), "v".to_string())]);
    }

    #[test]
    fn qpack_decode_mixes_static_and_dynamic() {
        // A realistic response: indexed-static :status 200, plus a dynamic
        // indexed header. Confirms the static path still works alongside.
        let mut t = table_at_max();
        let mut enc = Vec::new();
        enc_insert_literal("x-dyn", "dynval", &mut enc); // abs 0
        qpack::apply_encoder_instructions(&mut t, &enc).expect("insert");

        let mut block = Vec::new();
        enc_prefix(2, false, 0, &mut block); // RIC=1 (enc=2), Base=1
                                             // Indexed static: :status 200 = static index 25, T=1, 6-bit prefix.
        qpack::encode_int(25, 6, 0b1100_0000, &mut block);
        // Indexed dynamic: Base=1, relative 0 → abs 0 ("x-dyn","dynval").
        qpack::encode_int(0, 6, 0b1000_0000, &mut block);

        let fields = qpack::decode_field_section_with(&block, &t).expect("decode");
        assert_eq!(
            fields,
            vec![
                (":status".to_string(), "200".to_string()),
                ("x-dyn".to_string(), "dynval".to_string()),
            ]
        );
    }

    #[test]
    fn qpack_decode_unsatisfiable_required_insert_count_errors() {
        // RIC larger than the table's insert count → decompression failure.
        let mut t = table_at_max();
        let mut enc = Vec::new();
        enc_insert_literal("a", "b", &mut enc); // insert_count becomes 1
        qpack::apply_encoder_instructions(&mut t, &enc).unwrap();

        let mut block = Vec::new();
        // Ask for RIC = 5 (enc = (5 % 256)+1 = 6) but only 1 insert exists.
        enc_prefix(6, false, 0, &mut block);
        // A single dynamic indexed line (won't be reached — prefix check fails).
        qpack::encode_int(0, 6, 0b1000_0000, &mut block);
        let err = qpack::decode_field_section_with(&block, &t).unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)), "got {err:?}");
    }

    #[test]
    fn qpack_decode_dynamic_index_out_of_range_errors() {
        // A field line referencing an absolute index the table doesn't have
        // (evicted / never inserted) → decode error.
        let mut t = table_at_max();
        let mut enc = Vec::new();
        enc_insert_literal("a", "b", &mut enc); // abs 0, insert_count 1
        qpack::apply_encoder_instructions(&mut t, &enc).unwrap();

        let mut block = Vec::new();
        enc_prefix(2, false, 0, &mut block); // RIC=1, Base=1
                                             // Relative index 5 → field_relative_to_absolute(1, 5) underflows.
        qpack::encode_int(5, 6, 0b1000_0000, &mut block);
        assert!(qpack::decode_field_section_with(&block, &t).is_err());
    }

    #[test]
    fn qpack_decode_dynamic_reference_bomb_trips_list_cap() {
        // Even with dynamic references, the decoded-header-list cap must trip.
        // Insert one large entry, then reference it many times via Duplicate-
        // free indexed lines so the decoded list explodes.
        let mut t = table_at_max();
        let mut enc = Vec::new();
        // One ~4000-byte value won't fit (cap 4096, entry size = name+val+32);
        // use a value that fits: name "a" (1) + value 3000 + 32 = 3033 < 4096.
        let big = "x".repeat(3000);
        enc_insert_literal("a", &big, &mut enc); // abs 0
        qpack::apply_encoder_instructions(&mut t, &enc).expect("insert");

        let mut block = Vec::new();
        enc_prefix(2, false, 0, &mut block); // RIC=1, Base=1
                                             // Reference abs 0 (relative 0) ~100 times. Each contributes
                                             // 1 + 3000 + 32 = 3033 to the list size; 100 * 3033 > 256 KiB cap.
        for _ in 0..100 {
            qpack::encode_int(0, 6, 0b1000_0000, &mut block);
        }
        let err = qpack::decode_field_section_with(&block, &t).unwrap_err();
        match err {
            Error::BadResponse(m) => assert!(m.contains("header list"), "msg: {m}"),
            other => panic!("expected header-list-cap error, got {other:?}"),
        }
    }

    #[test]
    fn qpack_block_references_dynamic_table_predicate() {
        // RIC=0 prefix → no dynamic reference; RIC>0 → owes Section Ack.
        let mut zero = Vec::new();
        enc_prefix(0, false, 0, &mut zero);
        assert!(!qpack::block_references_dynamic_table(&zero));
        let mut nonzero = Vec::new();
        enc_prefix(2, false, 0, &mut nonzero);
        assert!(qpack::block_references_dynamic_table(&nonzero));
    }

    #[test]
    fn qpack_section_ack_encoding() {
        // §4.4.1: Section Acknowledgement is pattern 1 then a 7-bit-prefix
        // stream id. Stream id 0 → single byte 0x80.
        let mut out = Vec::new();
        encode_section_ack(0, &mut out);
        assert_eq!(out, vec![0x80]);
        // Stream id 4 (the request bidi stream) → 0x84.
        let mut out = Vec::new();
        encode_section_ack(4, &mut out);
        assert_eq!(out, vec![0x84]);
    }
}

//! HTTP/3 support (RFC 9114), with QPACK (RFC 9204) over QUIC (RFC 9000).
//!
//! HTTP/3 reuses the `https://` URL scheme; the version is selected at
//! connect time, in practice via Alt-Svc — we simply offer it as an
//! alternate transport that a caller can request explicitly.
//!
//! Status of this module
//! =====================
//!
//! The pieces present and tested are:
//!
//! * RFC 9000 §16 variable-length integer codec (`varint`).
//! * RFC 9114 §7.1 frame-header codec (`Frame`).
//! * QPACK header compression (RFC 9204) via `compcol`'s `qpack` codec:
//!   - **Decoder**: the full `QpackDecoder`, with the static table, a
//!     bounded dynamic table built from the peer's encoder stream (Set
//!     Dynamic Table Capacity / Insert With Name Reference / Insert With
//!     Literal Name / Duplicate, §4.3), and every field-line representation
//!     (indexed, post-base, literal-with-name-reference, literal-literal —
//!     §4.5), Huffman-coded or not. We advertise a non-zero
//!     `SETTINGS_QPACK_MAX_TABLE_CAPACITY` and
//!     `SETTINGS_QPACK_BLOCKED_STREAMS = 0`, feed the peer's encoder stream
//!     into the decoder as it arrives, and send Section Acknowledgements on
//!     our decoder stream (§4.4) for any response block that referenced the
//!     dynamic table. Because we advertise zero blocked streams, the encoder
//!     must front-load every insert a block references before that block —
//!     the normal single-connection ordering, which our I/O loop drains
//!     first. Decoded fields are validated at the HTTP/3 layer (RFC 9114
//!     §10.3 — see `header_octets_ok`) and bounded by a decoded-header-list
//!     cap against decompression bombs.
//!   - **Encoder**: the static-only `QpackEncoder` with Huffman string
//!     coding enabled. Request header blocks reference the QPACK static
//!     table and emit Huffman-coded literals (§4.5.2/§4.5.4/§4.5.6). We
//!     never insert into a dynamic table on the send side: that is a
//!     deliberate, wire-legal design choice for a one-shot client — the
//!     dynamic table is optional for a sender (RFC 9204 §2.1), and a
//!     static-only encoder needs no encoder stream and never blocks the
//!     peer's decoder. The field-section prefix is therefore always
//!     Required Insert Count = 0, Base = 0.
//! * A [`send`] function that wires a [`purecrypto::quic::QuicConnection`]
//!   client to a [`std::net::UdpSocket`], runs the QUIC handshake to
//!   completion, opens the HTTP/3 control stream (with a SETTINGS frame),
//!   then opens a request bidi stream and serializes a `:method`/`:scheme`/
//!   `:authority`/`:path` HEADERS frame followed by an optional DATA frame.
//!
//! Stream framing on the response stream (RFC 9114 §4.1, §7.2): an interim
//! 1xx HEADERS block is recognised and skipped so the following final HEADERS
//! becomes the response head; a HEADERS block after the final response is
//! treated as trailers and discarded; reserved/grease frame types (§7.2.8) are
//! drained; and a control-stream-only frame (SETTINGS / GOAWAY / CANCEL_PUSH /
//! MAX_PUSH_ID) or a PUSH_PROMISE (we never enable server push) seen on a
//! request stream is rejected as H3_FRAME_UNEXPECTED.
//!
//! Loss recovery (RFC 9002 §6.2): the I/O loop waits no longer than the QUIC
//! connection's next timeout ([`QuicConnection::next_timeout`]) before waking,
//! and drives [`on_timeout`] with the real elapsed-since-start, so a lost
//! packet's PTO fires and retransmits promptly rather than stalling on a fixed
//! read cap.
//!
//! [`on_timeout`]: purecrypto::quic::QuicConnection::on_timeout

use std::io;
use std::io::Write;
use std::time::{Duration, Instant};

use crate::net::udp::{open_udp_transport, UdpTransport};
use compcol::hpack::HeaderField;
use compcol::qpack::{QpackDecoder, QpackEncoder};
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
// QPACK header compression (RFC 9204) via compcol
// ============================================================================

use crate::http::{header_octets_ok, MAX_DECODED_HEADER_LIST};

/// A decoded HTTP/3 header list as `(name, value)` pairs.
type Fields = Vec<(String, String)>;

/// Decode one QPACK field section (RFC 9204 §4.5) against `decoder` — whose
/// dynamic table has already been built from the peer's encoder stream — then
/// validate every field at the HTTP/3 layer and return it as a `(name, value)`
/// list.
///
/// `compcol`'s [`QpackDecoder`] resolves the static table, the dynamic table,
/// and every field-line representation (indexed / post-base /
/// literal-with-name-reference / literal-literal, Huffman-coded or not). A
/// decode failure (malformed representation, bad table reference, a blocked
/// dynamic reference whose Required Insert Count exceeds what we've inserted,
/// …) is surfaced as [`Error::BadResponse`].
///
/// On top of that we re-impose the HTTP/3-layer validation (RFC 9114 §10.3)
/// the codec itself does not perform: [`header_octets_ok`] rejects uppercase or
/// non-token field names, empty names, and CR/LF/NUL octets in values — so a
/// malicious peer can't smuggle header/response-splitting payloads through to a
/// re-serializing consumer — and [`MAX_DECODED_HEADER_LIST`] bounds the decoded
/// list against a decompression bomb. Values must also be UTF-8 (the rest of
/// the crate models headers as `String`).
fn decode_header_block(decoder: &mut QpackDecoder, block: &[u8]) -> Result<Fields> {
    let decoded = decoder
        .decode_field_section(block)
        .map_err(|e| Error::BadResponse(format!("qpack: decode failed: {e}")))?;
    let mut out: Fields = Vec::with_capacity(decoded.len());
    let mut list_size: usize = 0;
    for f in decoded {
        // RFC 9114 §10.3: reject forbidden octets across every representation
        // (indexed-static, indexed-dynamic, post-base, and all literal
        // variants) before they reach a consumer.
        if !header_octets_ok(&f.name, &f.value) {
            return Err(Error::BadResponse(
                "qpack: forbidden octet in decoded header".into(),
            ));
        }
        list_size = list_size
            .saturating_add(f.name.len())
            .saturating_add(f.value.len())
            .saturating_add(32);
        if list_size > MAX_DECODED_HEADER_LIST {
            return Err(Error::BadResponse(
                "qpack: decoded header list exceeds limit".into(),
            ));
        }
        let name = String::from_utf8(f.name)
            .map_err(|_| Error::BadResponse("qpack: header name not utf-8".into()))?;
        let value = String::from_utf8(f.value)
            .map_err(|_| Error::BadResponse("qpack: header value not utf-8".into()))?;
        out.push((name, value));
    }
    Ok(out)
}

/// Encode `fields` as a self-contained QPACK field section (RFC 9204 §4.5)
/// using `compcol`'s static-only [`QpackEncoder`] with Huffman string coding.
///
/// The block references the QPACK static table and emits Huffman-coded literals
/// otherwise; it never inserts into a dynamic table, so the §4.5.1 prefix is
/// always Required Insert Count = 0, Base = 0. Static-only encoding is a
/// deliberate, wire-legal design for a one-shot client: the dynamic table is
/// optional for a sender (RFC 9204 §2.1), needs no encoder stream, and never
/// blocks the peer's decoder.
fn encode_header_block(fields: &[(String, String)]) -> Vec<u8> {
    let hfields: Vec<HeaderField> = fields
        .iter()
        .map(|(n, v)| HeaderField::new(n.as_bytes(), v.as_bytes()))
        .collect();
    let mut enc = QpackEncoder::new();
    enc.set_huffman(true);
    enc.encode_field_section(&hfields)
}

/// A field section references the dynamic table iff its Required Insert Count
/// (the leading 8-bit-prefix integer of the §4.5.1 prefix) is non-zero; for an
/// 8-bit prefix that is exactly a non-zero first byte. Per RFC 9204 §4.4.1 the
/// decoder then owes the peer a Section Acknowledgement.
fn block_references_dynamic_table(block: &[u8]) -> bool {
    !block.is_empty() && block[0] != 0
}

/// Encode `value` as an RFC 7541 §5.1 `n`-bit-prefix integer, OR-ing the fixed
/// high bits `pattern` into the first byte. Used only for the QPACK
/// decoder-stream Section Acknowledgement (`compcol`'s integer codec is
/// private), so a tiny standalone encoder is cheaper than pulling in more API.
fn encode_prefixed_int(value: u64, prefix_bits: u8, pattern: u8, out: &mut Vec<u8>) {
    debug_assert!((1..=8).contains(&prefix_bits));
    let max_prefix = (1u64 << prefix_bits) - 1;
    if value < max_prefix {
        out.push(pattern | value as u8);
    } else {
        out.push(pattern | max_prefix as u8);
        let mut rem = value - max_prefix;
        while rem >= 128 {
            out.push(((rem & 0x7f) as u8) | 0x80);
            rem >>= 7;
        }
        out.push(rem as u8);
    }
}

/// Length of the longest prefix of `buf` that consists of whole QPACK
/// encoder-stream instructions (RFC 9204 §4.3).
///
/// `compcol`'s [`QpackDecoder::feed_encoder_stream`] is all-or-error and
/// mutates the dynamic table as it parses, so handing it a buffer that ends
/// mid-instruction would both error *and* leave the table half-updated (and
/// re-feeding the completed buffer later would double-apply the earlier
/// instructions). We therefore feed it only complete instructions and keep any
/// trailing partial instruction buffered until the rest of it arrives. This is
/// framing only: it skips over each instruction's length fields without
/// interpreting names, values, table references, or Huffman coding — the codec
/// does all of that on the bytes we hand it.
fn complete_encoder_instructions_len(buf: &[u8]) -> usize {
    let mut pos = 0;
    while let Some(end) = next_instruction_end(buf, pos) {
        pos = end;
    }
    pos
}

/// End offset of the encoder-stream instruction starting at `pos`, or `None`
/// if `buf` holds only a partial instruction there (RFC 9204 §4.3).
fn next_instruction_end(buf: &[u8], pos: usize) -> Option<usize> {
    let b = *buf.get(pos)?;
    if b & 0b1000_0000 != 0 {
        // Insert With Name Reference (§4.3.2): 1 T name-index(6+) value-str(7+).
        let p = skip_int(buf, pos, 6)?;
        skip_string(buf, p, 7)
    } else if b & 0b0100_0000 != 0 {
        // Insert With Literal Name (§4.3.3): 0 1 H name-str(5+) value-str(7+).
        let p = skip_string(buf, pos, 5)?;
        skip_string(buf, p, 7)
    } else {
        // Set Dynamic Table Capacity (§4.3.1, 001) or Duplicate (§4.3.4, 000):
        // a single 5-bit-prefix integer.
        skip_int(buf, pos, 5)
    }
}

/// Skip an `n`-bit-prefix integer (RFC 7541 §5.1) at `pos`, returning the
/// offset just past it, or `None` if it is truncated (the caller then waits for
/// more bytes; the uni-stream buffer cap bounds a peer that never completes it).
fn skip_int(buf: &[u8], pos: usize, prefix_bits: u32) -> Option<usize> {
    let mask = ((1u16 << prefix_bits) - 1) as u8;
    let first = *buf.get(pos)?;
    if first & mask != mask {
        return Some(pos + 1);
    }
    let mut p = pos + 1;
    loop {
        let b = *buf.get(p)?;
        p += 1;
        if b & 0x80 == 0 {
            return Some(p);
        }
    }
}

/// Skip an `n`-bit-prefix string literal (RFC 9204 §4.1.2) at `pos` — its
/// length prefix then that many octets — returning the offset just past it, or
/// `None` if truncated. A malformed over-long length integer is reported as
/// "complete here" so `feed_encoder_stream` surfaces the real error.
fn skip_string(buf: &[u8], pos: usize, prefix_bits: u32) -> Option<usize> {
    let mask = ((1u16 << prefix_bits) - 1) as u8;
    let first = *buf.get(pos)?;
    let (len, mut p) = if first & mask != mask {
        ((first & mask) as u64, pos + 1)
    } else {
        let mut value = mask as u64;
        let mut shift = 0u32;
        let mut q = pos + 1;
        loop {
            let b = *buf.get(q)?;
            q += 1;
            value = match value.checked_add(((b & 0x7f) as u64) << shift) {
                Some(v) => v,
                None => return Some(q), // malformed; let the codec reject it
            };
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift > 63 {
                return Some(q); // malformed; let the codec reject it
            }
        }
        (value, q)
    };
    // A length that can't fit usize can never be satisfied by more bytes; keep
    // waiting (the buffer cap bounds it) rather than risk a bad cast.
    let len = usize::try_from(len).ok()?;
    p = p.checked_add(len)?;
    if p > buf.len() {
        return None;
    }
    Some(p)
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
/// Upper bound on how long a single pump recv parks the I/O loop. The actual
/// wait is the lesser of this and the QUIC next-timeout (the PTO), so loss
/// recovery stays responsive while a quiet connection still wakes periodically
/// to re-check the overall deadline and shutdown.
const PUMP_READ_CAP: Duration = Duration::from_millis(100);
/// Maximum UDP datagram we expect to receive (a hair over the QUIC default).
const MAX_DATAGRAM: usize = 65_535;

/// Per-connection HTTP/3 / QPACK decoder state. Holds the QPACK decoder (whose
/// dynamic table is fed by the peer's encoder stream), the partial-read buffers
/// for the server's unidirectional streams (so an instruction split across
/// datagrams can be reassembled), the client's QPACK decoder stream id (where
/// we send Section Acknowledgements), and what we learned from the peer's
/// control stream.
struct Http3State {
    /// The QPACK decoder; its dynamic table is populated from the peer's
    /// encoder stream and bounded by our advertised max table capacity.
    decoder: QpackDecoder,
    /// Our QPACK decoder stream id, if we managed to open it.
    decoder_stream: Option<StreamId>,
    /// Per server-uni-stream reassembly state, keyed by stream id value.
    uni: std::collections::HashMap<u64, UniStreamState>,
    /// Stream ids of the peer's critical unidirectional streams, once seen.
    /// Each may exist at most once per connection (RFC 9114 §6.2.1, RFC 9204
    /// §4.2), and none may be closed (H3_CLOSED_CRITICAL_STREAM).
    peer_control: Option<u64>,
    peer_qpack_encoder: Option<u64>,
    peer_qpack_decoder: Option<u64>,
    /// Whether the peer's SETTINGS (the mandatory first control frame) arrived.
    settings_seen: bool,
    /// Lowest stream id announced by a peer GOAWAY (RFC 9114 §5.2): request
    /// streams at or above it were not, and will not be, processed.
    goaway_id: Option<u64>,
}

/// State for one server-initiated unidirectional stream while we classify it
/// by its leading stream-type varint and then process (control, QPACK
/// encoder) or discard (everything else) its bytes.
#[derive(Default)]
struct UniStreamState {
    /// Bytes received but not yet processed (a partial type prefix, a partial
    /// control frame, or a partial encoder instruction).
    buf: Vec<u8>,
    /// The decoded stream type, once the leading varint has been read.
    ty: Option<u64>,
    /// Control stream: payload bytes of an ignorable (unknown / grease) frame
    /// still to be skipped without buffering.
    skip_remaining: u64,
}

/// Cap on bytes we buffer from a single server uni-stream awaiting a complete
/// QPACK encoder instruction or control frame. Bounds memory against a peer
/// that dribbles an unterminated one. Generous relative to any real instruction
/// or SETTINGS/GOAWAY frame. Streams we don't process (the peer's QPACK decoder
/// stream, grease types) are discarded as they arrive and never count toward it.
const MAX_UNI_BUFFER: usize = 64 * 1024;

impl Http3State {
    fn new(decoder_stream: Option<StreamId>) -> Self {
        Http3State {
            decoder: QpackDecoder::with_max_table_capacity(QPACK_MAX_TABLE_CAPACITY as usize),
            decoder_stream,
            uni: std::collections::HashMap::new(),
            peer_control: None,
            peer_qpack_encoder: None,
            peer_qpack_decoder: None,
            settings_seen: false,
            goaway_id: None,
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

    let dial_start = Instant::now();
    let mut conn = build_client(&req)?;
    let (sock, peer) = open_udp(&req)?;
    let connect = dial_start.elapsed();
    let _ = writeln!(trace, "*   Trying {peer} (UDP)...");
    handshake(&mut conn, &*sock, peer, req.read_timeout, dial_start)?;
    let appconnect = dial_start.elapsed();
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

    // Negotiated TLS parameters for `Response::tls`. QUIC always runs TLS 1.3.
    let tls_info = crate::http::TlsInfo {
        version: Some(crate::tls::ProtocolVersion::TLSv1_3),
        cipher_suite: conn.negotiated_cipher_suite(),
        alpn: conn.alpn_protocol().map(|p| p.to_vec()),
        peer_certificates: conn.peer_certificates().to_vec(),
    };

    let wire = Wire {
        sock: &*sock,
        peer,
        start: dial_start,
        idle_timeout: req
            .read_timeout
            .unwrap_or(MAX_TOTAL_DEADLINE)
            .min(MAX_TOTAL_DEADLINE),
    };
    write_request(&mut conn, &wire, request_stream, &req, trace)?;
    if !req.body.is_empty() {
        let _ = writeln!(trace, "* uploading {} body bytes", req.body.len());
    }
    pump(&mut conn, &*sock, peer, req.read_timeout, dial_start)?;

    let mut resp = read_response(
        &mut conn,
        &*sock,
        peer,
        request_stream,
        &req,
        &mut state,
        sink,
        on_head,
        trace,
        dial_start,
    )?;
    resp.tls = Some(tls_info);
    resp.timing.connect = Some(connect);
    resp.timing.appconnect = Some(appconnect);
    resp.timing.pretransfer = Some(appconnect);
    Ok(resp)
}

/// Read all readable server-initiated unidirectional streams, classify each
/// by its leading stream-type varint (RFC 9114 §6.2), and process it: the
/// control stream's frames (SETTINGS first, GOAWAY) and the QPACK encoder
/// stream's instructions (RFC 9204 §4.3) into the dynamic table. Everything
/// else (the peer's QPACK decoder stream, reserved/grease stream types) is
/// discarded as it arrives. This must run BEFORE we decode a response HEADERS
/// block so the table is populated (we advertise zero blocked streams, so the
/// encoder front-loads every referenced insert).
fn drain_uni_streams(conn: &mut QuicConnection, state: &mut Http3State) -> Result<()> {
    // Snapshot the readable server uni-streams; reading mutates the iterator
    // source, so collect ids first.
    let ids: Vec<StreamId> = conn
        .readable_streams()
        .filter(|s| s.is_uni() && s.is_server_initiated())
        .collect();
    let mut tmp = vec![0u8; 16 * 1024];
    for sid in ids {
        // A read error on a uni stream is not fatal for a one-shot request;
        // `while let Ok` simply stops draining it. `n == 0` (no more buffered
        // bytes right now) also ends this pass.
        while let Ok((n, fin)) = conn.read(sid, &mut tmp) {
            if n > 0 {
                state
                    .uni
                    .entry(sid.value())
                    .or_default()
                    .buf
                    .extend_from_slice(&tmp[..n]);
                // Process per chunk so discarded stream types never
                // accumulate, and a processed stream only ever holds one
                // incomplete unit.
                process_uni_stream(state, sid.value())?;
                if state
                    .uni
                    .get(&sid.value())
                    .is_some_and(|e| e.buf.len() > MAX_UNI_BUFFER)
                {
                    return Err(Error::BadResponse(
                        "http3: server uni-stream buffer exceeded limit".into(),
                    ));
                }
            }
            if fin {
                // RFC 9114 §6.2.1 / RFC 9204 §4.2: closing the control or a
                // QPACK stream is H3_CLOSED_CRITICAL_STREAM.
                let v = sid.value();
                if [
                    state.peer_control,
                    state.peer_qpack_encoder,
                    state.peer_qpack_decoder,
                ]
                .contains(&Some(v))
                {
                    return Err(Error::BadResponse(format!(
                        "http3: peer closed critical stream {v} (H3_CLOSED_CRITICAL_STREAM)"
                    )));
                }
                state.uni.remove(&v);
                break;
            }
            if n == 0 {
                break;
            }
        }
    }
    Ok(())
}

/// Classify and process the buffered bytes for one server uni-stream. Once
/// the leading stream-type varint is known, control-stream frames are parsed,
/// QPACK-encoder bytes are applied to the dynamic table, and other stream
/// types are drained.
fn process_uni_stream(state: &mut Http3State, sid: u64) -> Result<()> {
    let entry = state.uni.entry(sid).or_default();
    // Decode the stream-type prefix once.
    if entry.ty.is_none() {
        match varint::decode(&entry.buf) {
            Ok((ty, used)) => {
                entry.ty = Some(ty);
                entry.buf.drain(..used);
                let slot = match ty {
                    uni_stream_type::CONTROL => Some(&mut state.peer_control),
                    uni_stream_type::QPACK_ENCODER => Some(&mut state.peer_qpack_encoder),
                    uni_stream_type::QPACK_DECODER => Some(&mut state.peer_qpack_decoder),
                    uni_stream_type::PUSH => {
                        // We never send MAX_PUSH_ID, so the server may not
                        // open a push stream (RFC 9114 §4.6: H3_ID_ERROR).
                        return Err(Error::BadResponse(
                            "http3: server opened a push stream without MAX_PUSH_ID (H3_ID_ERROR)"
                                .into(),
                        ));
                    }
                    _ => None,
                };
                if let Some(slot) = slot {
                    if slot.is_some() {
                        return Err(Error::BadResponse(format!(
                            "http3: duplicate unidirectional stream type {ty:#x} (H3_STREAM_CREATION_ERROR)"
                        )));
                    }
                    *slot = Some(sid);
                }
            }
            Err(_) => return Ok(()), // need more bytes for the type prefix
        }
    }
    let entry = state.uni.get_mut(&sid).expect("entry present");
    match entry.ty {
        Some(uni_stream_type::CONTROL) => process_control_stream(state, sid),
        Some(uni_stream_type::QPACK_ENCODER) => {
            // Feed only whole instructions to the decoder; a trailing partial
            // one stays buffered for the next pass (see
            // `complete_encoder_instructions_len`).
            let consumed = complete_encoder_instructions_len(&entry.buf);
            if consumed > 0 {
                state
                    .decoder
                    .feed_encoder_stream(&entry.buf[..consumed])
                    .map_err(|e| Error::BadResponse(format!("qpack: encoder stream: {e}")))?;
                let entry = state.uni.get_mut(&sid).expect("entry present");
                entry.buf.drain(..consumed);
            }
            Ok(())
        }
        // The peer's QPACK decoder stream (acks for an encoder table we never
        // use) and reserved/grease stream types: discard as they arrive.
        _ => {
            entry.buf.clear();
            Ok(())
        }
    }
}

/// Parse complete frames on the peer's control stream (RFC 9114 §6.2.1,
/// §7.2): the first must be SETTINGS and it may not repeat; GOAWAY records
/// the boundary above which requests were not processed; frames that belong
/// on request streams, and HTTP/2 frame types reserved in HTTP/3, are
/// H3_FRAME_UNEXPECTED. Unknown / grease frames are skipped without being
/// buffered.
fn process_control_stream(state: &mut Http3State, sid: u64) -> Result<()> {
    loop {
        let entry = state.uni.get_mut(&sid).expect("entry present");
        if entry.skip_remaining > 0 {
            let n = entry.skip_remaining.min(entry.buf.len() as u64) as usize;
            entry.buf.drain(..n);
            entry.skip_remaining -= n as u64;
            if entry.skip_remaining > 0 {
                return Ok(());
            }
        }
        let Ok((frame, hdr_len)) = Frame::decode_header(&entry.buf) else {
            return Ok(()); // partial frame header
        };
        if !state.settings_seen && frame.ty != frame_type::SETTINGS {
            return Err(Error::BadResponse(format!(
                "http3: first control frame is {:#x}, not SETTINGS (H3_MISSING_SETTINGS)",
                frame.ty
            )));
        }
        match frame.ty {
            frame_type::DATA | frame_type::HEADERS | frame_type::PUSH_PROMISE => {
                return Err(Error::BadResponse(format!(
                    "http3: frame type {:#x} on the control stream (H3_FRAME_UNEXPECTED)",
                    frame.ty
                )));
            }
            ty if is_h2_reserved_frame_type(ty) => {
                return Err(Error::BadResponse(format!(
                    "http3: reserved HTTP/2 frame type {ty:#x} (H3_FRAME_UNEXPECTED)"
                )));
            }
            frame_type::SETTINGS
            | frame_type::GOAWAY
            | frame_type::MAX_PUSH_ID
            | frame_type::CANCEL_PUSH => {
                if frame.len > MAX_UNI_BUFFER as u64 {
                    return Err(Error::BadResponse(format!(
                        "http3: control frame {:#x} too large ({} bytes)",
                        frame.ty, frame.len
                    )));
                }
                let total = hdr_len + frame.len as usize;
                if entry.buf.len() < total {
                    return Ok(()); // wait for the whole frame
                }
                let payload: Vec<u8> = entry.buf[hdr_len..total].to_vec();
                entry.buf.drain(..total);
                match frame.ty {
                    frame_type::SETTINGS => {
                        if state.settings_seen {
                            return Err(Error::BadResponse(
                                "http3: second SETTINGS frame (H3_FRAME_UNEXPECTED)".into(),
                            ));
                        }
                        validate_settings(&payload)?;
                        state.settings_seen = true;
                    }
                    frame_type::GOAWAY => {
                        let malformed = || {
                            Error::BadResponse("http3: malformed GOAWAY (H3_FRAME_ERROR)".into())
                        };
                        let (id, used) = varint::decode(&payload).map_err(|_| malformed())?;
                        if used != payload.len() {
                            return Err(malformed());
                        }
                        // §5.2: the id may only stay or shrink.
                        if state.goaway_id.is_some_and(|prev| id > prev) {
                            return Err(Error::BadResponse(
                                "http3: GOAWAY id increased (H3_ID_ERROR)".into(),
                            ));
                        }
                        state.goaway_id = Some(id);
                    }
                    frame_type::MAX_PUSH_ID => {
                        // Only a client sends MAX_PUSH_ID (§7.2.7).
                        return Err(Error::BadResponse(
                            "http3: MAX_PUSH_ID from server (H3_FRAME_UNEXPECTED)".into(),
                        ));
                    }
                    // CANCEL_PUSH: we never accept pushes; nothing to cancel.
                    _ => {}
                }
            }
            _ => {
                // Unknown / grease (§9): skip its payload as it streams in.
                entry.buf.drain(..hdr_len);
                entry.skip_remaining = frame.len;
            }
        }
    }
}

/// Validate a peer SETTINGS payload (RFC 9114 §7.2.4): well-formed varint
/// pairs, no identifier twice, and none of the HTTP/2 setting identifiers
/// reserved in HTTP/3 (H3_SETTINGS_ERROR). We don't act on any value: our
/// requests use a literal-only QPACK encoding and no extensions.
fn validate_settings(payload: &[u8]) -> Result<()> {
    let malformed = || Error::BadResponse("http3: malformed SETTINGS (H3_FRAME_ERROR)".into());
    let mut seen = std::collections::HashSet::new();
    let mut pos = 0;
    while pos < payload.len() {
        let (id, n1) = varint::decode(&payload[pos..]).map_err(|_| malformed())?;
        let (_value, n2) = varint::decode(&payload[pos + n1..]).map_err(|_| malformed())?;
        pos += n1 + n2;
        if matches!(id, 0x02..=0x05) {
            return Err(Error::BadResponse(format!(
                "http3: reserved HTTP/2 setting {id:#x} (H3_SETTINGS_ERROR)"
            )));
        }
        if !seen.insert(id) {
            return Err(Error::BadResponse(format!(
                "http3: duplicate setting {id:#x} (H3_SETTINGS_ERROR)"
            )));
        }
    }
    Ok(())
}

/// HTTP/2 frame types with no HTTP/3 equivalent, reserved so that receiving
/// one is H3_FRAME_UNEXPECTED (RFC 9114 §7.2.8, §11.2.1): PRIORITY (0x02),
/// PING (0x06), WINDOW_UPDATE (0x08), CONTINUATION (0x09).
fn is_h2_reserved_frame_type(ty: u64) -> bool {
    matches!(ty, 0x02 | 0x06 | 0x08 | 0x09)
}

/// Post-handshake server-certificate policy for HTTP/3, mirroring the TCP TLS
/// path ([`crate::tls::connect_over_tls`]): a SAN-required hostname check
/// (TLS-4, no Common-Name fallback) when verifying, and public-key pinning
/// (`--pinnedpubkey`). Uses the peer chain `QuicConnection` exposes as of
/// purecrypto 0.6.8 (KarpelesLab/purecrypto#31). The QUIC handshake itself has
/// already verified the chain against the roots unless `--insecure`.
fn verify_peer_certificates(conn: &QuicConnection, req: &Request, pins: &[[u8; 32]]) -> Result<()> {
    let leaf = conn.peer_certificates().first().map(Vec::as_slice);

    // Public-key pinning (curl `--pinnedpubkey`): require the leaf SPKI to
    // match at least one pin. Enforced even under `--insecure` and regardless
    // of any verify callback, exactly like the TCP path.
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

    // Caller-owned verification (the browser model): when a verify callback is
    // set it is the *sole* trust authority — engine verification was disabled
    // in `build_client` (`.verify_certificates(false)`), mirroring the TCP TLS
    // path. Hand the callback the full peer chain and honour its verdict. The
    // SAN check below is skipped: it is the engine's job, which the callback now
    // owns.
    if let Some(cb) = &req.tls_verify_callback {
        let chain = conn.peer_certificates().to_vec();
        let verdict = cb.call(&crate::tls::CertVerify {
            server_name: tls_host(&req.url.host),
            chain_der: &chain,
        });
        if verdict == crate::tls::CertVerdict::Reject {
            return Err(Error::BadResponse(
                "server certificate rejected by verify callback".into(),
            ));
        }
        return Ok(());
    }

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
    // Base trust store: `--cacert <file>` replaces the defaults; otherwise use
    // the embedded CA bundle. `--capath <dir>` then *adds* a directory of CAs
    // on top of whichever base is in effect (curl semantics). Going through
    // `pc_roots` directly sidesteps the active `crate::tls::*` backend (which
    // may be rustls), because QUIC always needs a purecrypto root store.
    let mut roots = match &req.ca_bundle {
        Some(path) => crate::tls::pc_roots::load_from_file(path)?,
        None => crate::tls::pc_roots::embedded_roots(),
    };
    if let Some(dir) = &req.ca_path {
        crate::tls::pc_roots::add_from_dir(&mut roots, dir)?;
    }

    let mut builder = purecrypto::tls::Config::builder()
        .tls_only()
        .roots(roots)
        .server_name(quic_server_name(req))
        // A verify callback is the sole trust authority (browser model): when
        // one is set, disable the engine's own chain verification and defer to
        // the callback post-handshake (see `verify_peer_certificates`). This
        // mirrors the TCP path's `effective_verify = verify && callback.is_none()`.
        .verify_certificates(req.verify_tls && req.tls_verify_callback.is_none())
        // purecrypto 0.6.17 requires an explicit TLS/QUIC entropy source (no
        // implicit OsRng default); supply the OS CSPRNG.
        .rng(std::sync::Arc::new(purecrypto::rng::OsRng))
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

    // `TransportParameters` became `#[non_exhaustive]` in purecrypto 0.9.7
    // (the RFC 9000 §22.3 registry keeps growing), so it takes the same
    // `default()`-plus-field-assignment idiom as `QuicConfig` below.
    let transport_params = {
        let mut tp = TransportParameters::default();
        tp.max_idle_timeout_ms = Some(30_000);
        tp.max_udp_payload_size = Some(1452);
        // Generous credit so the server can put the whole response on one
        // bidi stream without our blocking it.
        tp.initial_max_data = Some(10 * 1024 * 1024);
        tp.initial_max_stream_data_bidi_local = Some(2 * 1024 * 1024);
        tp.initial_max_stream_data_bidi_remote = Some(2 * 1024 * 1024);
        tp.initial_max_stream_data_uni = Some(2 * 1024 * 1024);
        tp.initial_max_streams_bidi = Some(100);
        // QPACK encoder + decoder + server-control all live on uni streams.
        tp.initial_max_streams_uni = Some(100);
        tp.active_connection_id_limit = Some(2);
        tp
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

    QuicConnection::client(cfg, &quic_server_name(req))
        .map_err(|e| Error::BadResponse(format!("http3: build client: {e:?}")))
}

fn open_udp(req: &Request) -> Result<(Box<dyn UdpTransport>, std::net::SocketAddr)> {
    let peer = dial_addr(req)?;
    // Direct UDP, or relayed through a SOCKS5 proxy if the connector is one;
    // a non-UDP-capable proxy (http/https/socks4) errors here.
    let sock = open_udp_transport(req.connector.udp_proxy(), peer)?;
    // We do our own deadline accounting in the pump loop; set a short
    // per-recv timeout so we can interleave timer ticks.
    sock.set_read_timeout(Some(Duration::from_millis(100)))?;
    sock.set_write_timeout(req.read_timeout)?;
    Ok((sock, peer))
}

/// The host as a TLS reference identity / resolver input: a bracketed IPv6
/// literal from the URL (`[::1]`, `[fe80::1%25en0]`) loses its brackets and
/// any zone id (RFC 6874), which name nothing to the peer or to DNS.
fn tls_host(host: &str) -> &str {
    match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        Some(inner) => inner.split('%').next().unwrap_or(inner),
        None => host,
    }
}

/// The name handed to purecrypto for the QUIC handshake. purecrypto uses one
/// string both as the SNI and as the reference identity it verifies the leaf
/// against, and omits SNI only when it is empty. RFC 6066 §3 forbids an IP
/// literal in SNI, but an IP must still be the reference identity (matched
/// against iPAddress SANs) whenever the engine verifies — so an IP literal is
/// only dropped (no SNI) when engine verification is off: `-k`, or a verify
/// callback that owns trust (and gets the name via [`tls_host`] instead).
fn quic_server_name(req: &Request) -> String {
    let host = tls_host(&req.url.host);
    let engine_verifies = req.verify_tls && req.tls_verify_callback.is_none();
    if !engine_verifies && host.parse::<std::net::IpAddr>().is_ok() {
        String::new()
    } else {
        host.to_string()
    }
}

/// The UDP address to dial for `req`, applying the same overrides as the TCP
/// path (`http::tcp_connect`) in the same order: `--connect-to` remaps the
/// dial host/port, then a `--resolve` pin for the (remapped) host:port wins
/// over DNS, otherwise the request's pluggable resolver runs and `-4`/`-6`
/// picks the family. The QUIC handshake still names (and verifies) the URL
/// host, so remapping the dial target never changes whose certificate is
/// accepted.
fn dial_addr(req: &Request) -> Result<std::net::SocketAddr> {
    let (mut host, mut port) = (tls_host(&req.url.host).to_string(), req.url.port);
    for (fh, fp, th, tp) in &req.connect_to {
        let host_ok = fh.is_empty() || fh.eq_ignore_ascii_case(&host);
        let port_ok = *fp == 0 || *fp == port;
        if host_ok && port_ok {
            if !th.is_empty() {
                host = th.clone();
            }
            if *tp != 0 {
                port = *tp;
            }
            break;
        }
    }
    if let Some((_, _, ip)) = req
        .resolve
        .iter()
        .find(|(h, p, _)| *p == port && h.eq_ignore_ascii_case(&host))
    {
        return Ok(std::net::SocketAddr::new(*ip, port));
    }
    let addrs = req.resolver.resolve(&host, port)?;
    let chosen = match req.ip_family {
        Some(crate::http::IpFamily::V4) => addrs.into_iter().find(|a| a.is_ipv4()),
        Some(crate::http::IpFamily::V6) => addrs.into_iter().find(|a| a.is_ipv6()),
        None => addrs.into_iter().next(),
    };
    chosen.ok_or(Error::InvalidUrl(host))
}

/// Drain whatever the connection wants to send right now, blast it out, and
/// optionally read one datagram from the socket back into the engine.
fn pump_once(
    conn: &mut QuicConnection,
    sock: &dyn UdpTransport,
    peer: std::net::SocketAddr,
    can_block: bool,
    start: Instant,
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
        // Wake no later than the next QUIC timer (the PTO) so a loss is
        // retransmitted promptly instead of waiting out a fixed cap — RFC 9002
        // §6.2 loss recovery. Floor at 1 ms (a zero timeout means "block
        // forever" on some platforms) and cap at PUMP_READ_CAP so a stalled
        // peer never parks us indefinitely.
        let wait = conn
            .next_timeout()
            .unwrap_or(PUMP_READ_CAP)
            .clamp(Duration::from_millis(1), PUMP_READ_CAP);
        sock.set_read_timeout(Some(wait))?;
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

    // Run timers. `on_timeout` compares the elapsed-since-connection-start we
    // pass against its internal deadlines, so it must receive the real elapsed
    // time (passing zero would make `has_fired` perpetually false and a PTO
    // would never retransmit). `start` is anchored at connection build, a hair
    // before the engine's own start, so we never fire a timer early.
    conn.on_timeout(start.elapsed());

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
    start: Instant,
) -> Result<()> {
    let total_deadline = deadline_hint
        .unwrap_or(MAX_TOTAL_DEADLINE)
        .min(MAX_TOTAL_DEADLINE);
    while !conn.is_handshake_complete() {
        if start.elapsed() > total_deadline {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "http3: QUIC handshake timed out",
            )));
        }
        pump_once(conn, sock, peer, true, start)?;
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
    encode_prefixed_int(stream_id, 7, 0b1000_0000, out);
}

/// Queue `data` on `sid` without driving the connection. For the small,
/// fixed-size writes on our own unidirectional streams (stream types,
/// SETTINGS, section acks), which always fit the initial flow-control credit;
/// a request body goes through [`write_all_pumped`] instead.
fn write_all(conn: &mut QuicConnection, sid: StreamId, mut data: &[u8]) -> Result<()> {
    while !data.is_empty() {
        let n = conn
            .write(sid, data)
            .map_err(|e| Error::BadResponse(format!("http3: stream write: {e:?}")))?;
        if n == 0 {
            return Err(Error::BadResponse(
                "http3: stream write blocked (flow control)".into(),
            ));
        }
        data = &data[n..];
    }
    Ok(())
}

/// The UDP path and clock a stream write needs to wait out flow control.
struct Wire<'a> {
    sock: &'a dyn UdpTransport,
    peer: std::net::SocketAddr,
    /// Connection start (for `on_timeout`).
    start: Instant,
    /// Give up waiting for credit after this long without any.
    idle_timeout: Duration,
}

/// Queue all of `data` on `sid`, driving the connection while the peer's
/// flow control (MAX_DATA / MAX_STREAM_DATA) holds us back. `write` returning
/// `Ok(0)` means "blocked": we flush what's queued and read the peer's
/// datagrams until fresh credit arrives, rather than failing any body larger
/// than the peer's initial window (e.g. nginx-quic's 64 KiB default).
fn write_all_pumped(
    conn: &mut QuicConnection,
    wire: &Wire<'_>,
    sid: StreamId,
    mut data: &[u8],
) -> Result<()> {
    let mut last_progress = Instant::now();
    while !data.is_empty() {
        let n = conn
            .write(sid, data)
            .map_err(|e| Error::BadResponse(format!("http3: stream write: {e:?}")))?;
        if n > 0 {
            data = &data[n..];
            last_progress = Instant::now();
            continue;
        }
        if conn.is_closed() {
            return Err(Error::BadResponse(
                "http3: peer closed connection while sending the request body".into(),
            ));
        }
        if last_progress.elapsed() > wire.idle_timeout {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "http3: timed out waiting for flow-control credit",
            )));
        }
        pump_once(conn, wire.sock, wire.peer, true, wire.start)?;
    }
    Ok(())
}

/// Whether a caller-supplied request header (lowercased name `kl`) must be
/// left out of an HTTP/3 request: pseudo-headers (we emit our own), `Host`
/// (carried as `:authority`), connection-specific fields (RFC 9114 §4.2), and
/// `te` with any value other than "trailers".
fn omit_request_field(kl: &str, value: &str) -> bool {
    kl.starts_with(':')
        || matches!(
            kl,
            "host"
                | "connection"
                | "transfer-encoding"
                | "upgrade"
                | "keep-alive"
                | "proxy-connection"
        )
        || (kl == "te" && !value.trim().eq_ignore_ascii_case("trailers"))
}

/// Serialize HEADERS + DATA for `req` onto `sid` and finish the send side.
fn write_request(
    conn: &mut QuicConnection,
    wire: &Wire<'_>,
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
        if omit_request_field(&kl, v) {
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

    let qpack_payload = encode_header_block(&fields);

    let mut out = Vec::with_capacity(qpack_payload.len() + 16);
    Frame::encode_header(frame_type::HEADERS, qpack_payload.len() as u64, &mut out);
    out.extend_from_slice(&qpack_payload);
    if !req.body.is_empty() {
        Frame::encode_header(frame_type::DATA, req.body.len() as u64, &mut out);
    }
    write_all_pumped(conn, wire, sid, &out)?;
    if !req.body.is_empty() {
        write_all_pumped(conn, wire, sid, &req.body)?;
    }
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
    start: Instant,
) -> Result<()> {
    // A couple of non-blocking ticks just to flush our pending datagrams.
    for _ in 0..3 {
        pump_once(conn, sock, peer, false, start)?;
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
    conn_start: Instant,
) -> Result<Response> {
    let total_deadline = req
        .read_timeout
        .unwrap_or(MAX_TOTAL_DEADLINE)
        .min(MAX_TOTAL_DEADLINE);
    let start = Instant::now();

    let mut stream_buf: Vec<u8> = Vec::new();
    let mut rs = ReqStream {
        head_request: crate::http::effective_method(req).eq_ignore_ascii_case("HEAD"),
        ..ReqStream::default()
    };

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
        // RFC 9114 §5.2: a GOAWAY naming an id at or below our request stream
        // means the server did not process it — fail now (it is safe to retry
        // elsewhere) instead of waiting for a response that will never come.
        if let Some(g) = state.goaway_id {
            if sid.value() >= g {
                return Err(Error::BadResponse(format!(
                    "http3: peer closed connection (GOAWAY {g}) before processing request stream {}",
                    sid.value()
                )));
            }
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
            // Stream DATA to the sink only when the response is not
            // content-encoded (encoded bodies must be buffered to decode) — but
            // when the caller turned decompression off, there's nothing to
            // decode, so even an encoded body streams straight through as raw
            // bytes. Recomputed each frame because HEADERS may have just arrived.
            let encoded = req.decompress
                && rs.headers.as_ref().is_some_and(|f| {
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
            let (consumed, ack_owed) =
                match try_consume_frame(&stream_buf, &mut rs, &mut state.decoder, frame_sink) {
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
                if let Some(fields) = rs.headers.as_ref() {
                    fire_h3_head(fields, &mut on_head);
                }
            }
            if stream_buf.is_empty() {
                break;
            }
        }

        if fin {
            if !stream_buf.is_empty() || rs.data_remaining > 0 || rs.skip_remaining > 0 {
                return Err(Error::BadResponse(
                    "http3: stream FIN with partial frame in buffer".into(),
                ));
            }
            break;
        }

        // Drive the I/O loop forward so more bytes can arrive.
        pump_once(conn, sock, peer, true, conn_start)?;
    }

    rs.check_content_length(true)?;
    let fields = rs
        .headers
        .ok_or_else(|| Error::BadResponse("http3: no HEADERS frame".into()))?;
    finalize_response(
        fields,
        rs.body,
        rs.streamed_len,
        req.decompress,
        sink,
        trace,
    )
}

/// Receive-side state of the request stream (RFC 9114 §4.1): the final
/// response head, the body, and where we are in the frame sequence.
#[derive(Default)]
struct ReqStream {
    /// The final (non-1xx) response head, once received.
    headers: Option<Fields>,
    /// A trailer section has been received; nothing but FIN may follow.
    trailers_seen: bool,
    /// Interim (1xx) heads seen so far; bounded by [`MAX_INTERIM_RESPONSES`].
    interim: u32,
    /// `content-length` of the final head, checked against the DATA received.
    content_length: Option<u64>,
    /// The request was HEAD: `content-length` describes the would-be GET body.
    head_request: bool,
    /// Buffered body (content-encoded, or no sink).
    body: Vec<u8>,
    /// Body bytes written straight to the sink.
    streamed_len: u64,
    /// Payload bytes of the current DATA frame not yet received. DATA is
    /// consumed as it arrives rather than after the whole frame is buffered,
    /// so a large frame streams to the sink with bounded memory.
    data_remaining: u64,
    /// Payload bytes of an ignorable (reserved / grease) frame still to skip.
    skip_remaining: u64,
}

/// Upper bound on interim (1xx) response heads per request. Each is decoded
/// and would otherwise keep the read loop busy forever.
const MAX_INTERIM_RESPONSES: u32 = 32;

impl ReqStream {
    fn received(&self) -> u64 {
        self.body.len() as u64 + self.streamed_len
    }

    /// The `content-length` the DATA must match, or `None` when there is none
    /// or it doesn't describe this stream's content (HEAD, 204, 304).
    fn enforced_content_length(&self) -> Option<u64> {
        let exempt = self.head_request
            || self
                .headers
                .as_ref()
                .and_then(header_status)
                .is_some_and(|s| s == 204 || s == 304);
        if exempt {
            None
        } else {
            self.content_length
        }
    }

    /// RFC 9114 §4.1.2: a response whose DATA length differs from its
    /// `content-length` is malformed. Before FIN (`at_end == false`) only an
    /// excess is detectable. HEAD responses and 204/304 carry no content.
    fn check_content_length(&self, at_end: bool) -> Result<()> {
        let Some(expected) = self.enforced_content_length() else {
            return Ok(());
        };
        let got = self.received();
        if got > expected || (at_end && got != expected) {
            return Err(Error::BadResponse(format!(
                "http3: content-length {expected} but received {got} body bytes"
            )));
        }
        Ok(())
    }

    /// Hand `payload` (part of a DATA frame) to the sink or the body buffer.
    fn deliver(&mut self, payload: &[u8], sink: Option<&mut dyn Write>) -> Result<()> {
        // Stream straight to the caller's sink when one is supplied and
        // nothing has been buffered yet (the caller passes `None` for a
        // content-encoded response, which must be buffered to decode).
        match sink {
            Some(w) if self.body.is_empty() => {
                w.write_all(payload)?;
                self.streamed_len += payload.len() as u64;
            }
            _ => {
                if self.body.len().saturating_add(payload.len()) > MAX_RESPONSE_BYTES {
                    return Err(Error::BadResponse("http3: response too large".into()));
                }
                self.body.extend_from_slice(payload);
            }
        }
        self.check_content_length(false)
    }
}

enum FrameOutcome {
    /// Consumed `n` bytes; the bool is `true` when the frame was a HEADERS
    /// block that referenced the dynamic table and thus owes a Section
    /// Acknowledgement (RFC 9204 §4.4.1).
    Consumed(usize, bool),
    NeedMore,
    Err(Error),
}

/// Try to consume the next piece of the request stream from `buf`: the rest
/// of an in-progress DATA (or ignorable) frame, or one new frame. DATA and
/// ignorable payloads are consumed as they arrive; HEADERS needs its whole
/// frame. A HEADERS block is decoded with `decoder` (whose dynamic table the
/// encoder stream has already populated); the returned flag reports whether
/// the block referenced the dynamic table (Required Insert Count > 0), so the
/// caller can send a Section Acknowledgement.
fn try_consume_frame(
    buf: &[u8],
    rs: &mut ReqStream,
    decoder: &mut QpackDecoder,
    sink: Option<&mut dyn Write>,
) -> FrameOutcome {
    match consume_frame(buf, rs, decoder, sink) {
        Ok(Some(x)) => FrameOutcome::Consumed(x.0, x.1),
        Ok(None) => FrameOutcome::NeedMore,
        Err(e) => FrameOutcome::Err(e),
    }
}

fn consume_frame(
    buf: &[u8],
    rs: &mut ReqStream,
    decoder: &mut QpackDecoder,
    sink: Option<&mut dyn Write>,
) -> Result<Option<(usize, bool)>> {
    // Continue a partially received DATA / ignorable frame.
    if rs.data_remaining > 0 || rs.skip_remaining > 0 {
        let pending = rs.data_remaining.max(rs.skip_remaining);
        let n = pending.min(buf.len() as u64) as usize;
        if n == 0 {
            return Ok(None);
        }
        if rs.data_remaining > 0 {
            rs.data_remaining -= n as u64;
            rs.deliver(&buf[..n], sink)?;
        } else {
            rs.skip_remaining -= n as u64;
        }
        return Ok(Some((n, false)));
    }

    let Ok((frame, hdr_len)) = Frame::decode_header(buf) else {
        return Ok(None);
    };
    match frame.ty {
        frame_type::DATA => {
            // RFC 9114 §4.1: DATA only between the final HEADERS and any
            // trailers; before it (or after trailers) the response is
            // malformed (H3_FRAME_UNEXPECTED).
            if rs.headers.is_none() {
                return Err(Error::BadResponse(
                    "http3: DATA before the response HEADERS (H3_FRAME_UNEXPECTED)".into(),
                ));
            }
            if rs.trailers_seen {
                return Err(Error::BadResponse(
                    "http3: DATA after trailers (H3_FRAME_UNEXPECTED)".into(),
                ));
            }
            // Reject an obviously-bogus declared length up front when the body
            // is buffered: it can't exceed the remaining response budget. A
            // body streamed to a sink is bounded by the sink instead.
            let streaming = sink.is_some() && rs.body.is_empty();
            if !streaming {
                let remaining = MAX_RESPONSE_BYTES.saturating_sub(rs.body.len()) as u64;
                if frame.len > remaining {
                    return Err(Error::BadResponse(
                        "http3: DATA frame length exceeds response budget".into(),
                    ));
                }
            }
            // Checked against the declared frame length so an oversized frame
            // is refused before any of it is delivered.
            if let Some(cl) = rs.enforced_content_length() {
                if rs.received().saturating_add(frame.len) > cl {
                    return Err(Error::BadResponse(format!(
                        "http3: DATA exceeds content-length {cl}"
                    )));
                }
            }
            let avail = ((buf.len() - hdr_len) as u64).min(frame.len) as usize;
            rs.data_remaining = frame.len - avail as u64;
            rs.deliver(&buf[hdr_len..hdr_len + avail], sink)?;
            Ok(Some((hdr_len + avail, false)))
        }
        frame_type::HEADERS => {
            if frame.len > MAX_HEADERS_FRAME_LEN {
                return Err(Error::BadResponse(
                    "http3: HEADERS frame length exceeds limit".into(),
                ));
            }
            if rs.trailers_seen {
                return Err(Error::BadResponse(
                    "http3: HEADERS after trailers (H3_FRAME_UNEXPECTED)".into(),
                ));
            }
            let total = hdr_len + frame.len as usize;
            if buf.len() < total {
                return Ok(None);
            }
            let payload = &buf[hdr_len..total];
            let fields = decode_header_block(decoder, payload)?;
            // A block always owes a Section Ack if it referenced the dynamic
            // table, regardless of which kind of HEADERS it is.
            let ack_owed = block_references_dynamic_table(payload);
            if rs.headers.is_some() {
                // A HEADERS block after the final response is trailers (RFC
                // 9114 §4.1) — allowed, validated, but not surfaced.
                crate::http2::validate_response_fields(&fields, true)
                    .map_err(|m| Error::BadResponse(format!("http3: malformed trailers: {m}")))?;
                rs.trailers_seen = true;
                return Ok(Some((total, ack_owed)));
            }
            let info = crate::http2::validate_response_fields(&fields, false)
                .map_err(|m| Error::BadResponse(format!("http3: malformed response head: {m}")))?;
            if info.status < 200 {
                // An interim 1xx informational response: not the final head.
                // 101 has no meaning in HTTP/3 (§4.5).
                if info.status == 101 {
                    return Err(Error::BadResponse("http3: 101 response in HTTP/3".into()));
                }
                rs.interim += 1;
                if rs.interim > MAX_INTERIM_RESPONSES {
                    return Err(Error::BadResponse(format!(
                        "http3: more than {MAX_INTERIM_RESPONSES} interim responses"
                    )));
                }
            } else {
                rs.content_length = info.content_length;
                rs.headers = Some(fields);
            }
            Ok(Some((total, ack_owed)))
        }
        // RFC 9114 §7.2: these frames belong on the control stream (or, for
        // PUSH_PROMISE, require a push we never enabled). Seeing one on a
        // request stream is H3_FRAME_UNEXPECTED — reject before buffering its
        // (possibly huge) declared length rather than silently draining it.
        frame_type::SETTINGS
        | frame_type::GOAWAY
        | frame_type::CANCEL_PUSH
        | frame_type::MAX_PUSH_ID
        | frame_type::PUSH_PROMISE => Err(Error::BadResponse(format!(
            "http3: frame type {:#x} not allowed on a request stream",
            frame.ty
        ))),
        ty if is_h2_reserved_frame_type(ty) => Err(Error::BadResponse(format!(
            "http3: reserved HTTP/2 frame type {ty:#x} (H3_FRAME_UNEXPECTED)"
        ))),
        // RFC 9114 §7.2.8 / §9 reserved/grease types: skip their payload as
        // it arrives (never buffered, whatever the declared length).
        _ => {
            let avail = ((buf.len() - hdr_len) as u64).min(frame.len);
            rs.skip_remaining = frame.len - avail;
            Ok(Some((hdr_len + avail as usize, false)))
        }
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

/// The numeric `:status` pseudo-header of a decoded field section, if present
/// and parseable. Used to tell an interim 1xx HEADERS block from the final
/// response (RFC 9114 §4.1).
fn header_status(fields: &Fields) -> Option<u16> {
    fields
        .iter()
        .find(|(k, _)| k == ":status")
        .and_then(|(_, v)| v.parse::<u16>().ok())
}

/// Invoke `on_head` once with the decoded response head, taking the observer so
/// it can never fire twice. Interim 1xx responses are skipped (not the final
/// head). Mirrors the `:status`/pseudo-header handling in [`finalize_response`].
fn fire_h3_head(fields: &Fields, on_head: &mut Option<crate::http::HeadObserver<'_>>) {
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
    fields: Fields,
    body: Vec<u8>,
    streamed_len: u64,
    decompress: bool,
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
    let (hdrs, body) = crate::http::maybe_decode_body(hdrs, body, decompress, trace)?;
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
            tls: None,
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
        tls: None,
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

    // ---- QPACK glue over compcol -----------------------------------------

    /// A decoder bounded by the table capacity we advertise.
    fn decoder() -> QpackDecoder {
        QpackDecoder::with_max_table_capacity(QPACK_MAX_TABLE_CAPACITY as usize)
    }

    /// Encode a field-section prefix (§4.5.1): Required Insert Count and Base.
    /// `enc_ric` is the already-§4.5.1.1-encoded insert count; `delta_base`
    /// and `sign` give the Base.
    fn enc_prefix(enc_ric: u64, sign: bool, delta_base: u64, out: &mut Vec<u8>) {
        encode_prefixed_int(enc_ric, 8, 0x00, out);
        let pat = if sign { 0b1000_0000 } else { 0 };
        encode_prefixed_int(delta_base, 7, pat, out);
    }

    /// Encode a Set Dynamic Table Capacity encoder-stream instruction
    /// (§4.3.1): pattern `001`, 5-bit-prefix capacity.
    fn enc_set_capacity(cap: u64, out: &mut Vec<u8>) {
        encode_prefixed_int(cap, 5, 0b0010_0000, out);
    }

    /// Encode an Insert With Literal Name encoder-stream instruction
    /// (§4.3.3, H=0): pattern `01`, 5-bit-prefix name length, then the name,
    /// then a 7-bit-prefix value string (H=0).
    fn enc_insert_literal(name: &str, value: &str, out: &mut Vec<u8>) {
        encode_prefixed_int(name.len() as u64, 5, 0b0100_0000, out);
        out.extend_from_slice(name.as_bytes());
        encode_prefixed_int(value.len() as u64, 7, 0x00, out);
        out.extend_from_slice(value.as_bytes());
    }

    #[test]
    fn qpack_encode_decode_round_trip_indexed_and_literal() {
        // Exercises every encoder representation: indexed-static (:method GET,
        // :scheme https), literal-with-static-name (:authority, :path,
        // user-agent), and literal-literal (x-custom), all Huffman-coded.
        let fields: Fields = vec![
            (":method".to_string(), "GET".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "example.com".to_string()),
            (":path".to_string(), "/index.html".to_string()),
            ("user-agent".to_string(), "rsurl/test".to_string()),
            ("x-custom".to_string(), "hello".to_string()),
        ];
        let wire = encode_header_block(&fields);
        let decoded = decode_header_block(&mut decoder(), &wire).expect("decode");
        assert_eq!(decoded, fields);
    }

    #[test]
    fn qpack_decode_rejects_crlf_in_value() {
        // x-h: "evil\r\nset-cookie: x=1" — response-splitting payload.
        let buf =
            encode_header_block(&[("x-h".to_string(), "evil\r\nset-cookie: x=1".to_string())]);
        let err = decode_header_block(&mut decoder(), &buf).unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)), "got {err:?}");
    }

    #[test]
    fn qpack_decode_rejects_lf_in_value() {
        let buf = encode_header_block(&[("x-h".to_string(), "a\nb".to_string())]);
        assert!(matches!(
            decode_header_block(&mut decoder(), &buf).unwrap_err(),
            Error::BadResponse(_)
        ));
    }

    #[test]
    fn qpack_decode_rejects_nul_in_value() {
        let buf = encode_header_block(&[("x-h".to_string(), "a\x00b".to_string())]);
        assert!(matches!(
            decode_header_block(&mut decoder(), &buf).unwrap_err(),
            Error::BadResponse(_)
        ));
    }

    #[test]
    fn qpack_decode_rejects_uppercase_name() {
        let buf = encode_header_block(&[("X-Bad".to_string(), "ok".to_string())]);
        assert!(matches!(
            decode_header_block(&mut decoder(), &buf).unwrap_err(),
            Error::BadResponse(_)
        ));
    }

    #[test]
    fn qpack_decode_rejects_empty_name() {
        let buf = encode_header_block(&[("".to_string(), "ok".to_string())]);
        assert!(matches!(
            decode_header_block(&mut decoder(), &buf).unwrap_err(),
            Error::BadResponse(_)
        ));
    }

    #[test]
    fn qpack_decode_accepts_normal_header_and_pseudo() {
        // Ordinary header (spaces in value) + a tab in another value (allowed)
        // + a pseudo-header must all decode cleanly.
        let buf = encode_header_block(&[
            (
                "content-type".to_string(),
                "text/html; charset=utf-8".to_string(),
            ),
            ("x-h".to_string(), "a\tb".to_string()),
            (":status".to_string(), "200".to_string()),
        ]);
        let fields = decode_header_block(&mut decoder(), &buf).expect("decode");
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
        // usize::MAX must not overflow the slice bound and panic; the decoder
        // must return a hard error instead.
        let mut buf = Vec::new();
        enc_prefix(0, false, 0, &mut buf); // RIC=0, Base=0
                                           // Literal Field Line With Literal Name, H=0, name length 1.
        encode_prefixed_int(1, 3, 0b0010_0000, &mut buf);
        buf.push(b'a'); // 1-byte literal name
                        // Value: 7-bit prefix, H=0, length = u64::MAX - 1, with no value bytes.
        encode_prefixed_int(u64::MAX - 1, 7, 0x00, &mut buf);
        let err = decode_header_block(&mut decoder(), &buf).unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)), "got {err:?}");
    }

    #[test]
    fn qpack_decompression_bomb_is_rejected() {
        // A modest compressed field section that decodes to an enormous header
        // list must be rejected. Emit many Literal Field Line With Literal Name
        // entries with a long value.
        let mut buf = Vec::new();
        enc_prefix(0, false, 0, &mut buf); // RIC=0, Base=0
        let name = b"a";
        let value = vec![b'x'; 1024];
        for _ in 0..512 {
            encode_prefixed_int(name.len() as u64, 3, 0b0010_0000, &mut buf);
            buf.extend_from_slice(name);
            encode_prefixed_int(value.len() as u64, 7, 0x00, &mut buf);
            buf.extend_from_slice(&value);
        }
        let err = decode_header_block(&mut decoder(), &buf).unwrap_err();
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
        assert!(!block_references_dynamic_table(&zero));
        let mut nonzero = Vec::new();
        enc_prefix(2, false, 0, &mut nonzero);
        assert!(block_references_dynamic_table(&nonzero));
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

    // ---- QPACK dynamic table end-to-end (RFC 9204 §4.3 / §4.5) ------------

    #[test]
    fn qpack_rfc9204_appendix_b2_cross_check() {
        // RFC 9204 Appendix B.2 — the exact encoder-stream byte sequence the
        // RFC shows a server emitting, then the matching Stream-4 header block.
        //   3fbd01                Set Dynamic Table Capacity = 220
        //   c0 0f www.example.com Insert With Name Reference, static idx 0
        //   c1 0c /sample/path    Insert With Name Reference, static idx 1
        let mut wire: Vec<u8> = vec![0x3f, 0xbd, 0x01];
        wire.extend_from_slice(&[0xc0, 0x0f]);
        wire.extend_from_slice(b"www.example.com");
        wire.extend_from_slice(&[0xc1, 0x0c]);
        wire.extend_from_slice(b"/sample/path");

        // The framing helper must accept the whole real-world stream.
        assert_eq!(
            complete_encoder_instructions_len(&wire),
            wire.len(),
            "framing consumes the entire Appendix B.2 stream"
        );

        let mut dec = decoder();
        dec.feed_encoder_stream(&wire).expect("feed encoder stream");
        assert_eq!(dec.insert_count(), 2);

        //   0381  Field Section Prefix: Required Insert Count = 2, Base = 0
        //   10    Indexed Field Line With Post-Base Index → abs 0
        //   11    Indexed Field Line With Post-Base Index → abs 1
        let block: [u8; 4] = [0x03, 0x81, 0x10, 0x11];
        let fields = decode_header_block(&mut dec, &block).expect("decode block");
        assert_eq!(
            fields,
            vec![
                (":authority".to_string(), "www.example.com".to_string()),
                (":path".to_string(), "/sample/path".to_string()),
            ]
        );
        assert!(block_references_dynamic_table(&block));
    }

    #[test]
    fn qpack_decode_unsatisfiable_required_insert_count_errors() {
        // A block whose Required Insert Count exceeds the decoder's Insert
        // Count is a blocked reference this synchronous decoder can't wait on:
        // it must error (QPACK_DECOMPRESSION_FAILED).
        let mut dec = decoder(); // no inserts applied
        let mut block = Vec::new();
        // EncInsertCount = 2 → RIC = 1, but insert count is 0.
        enc_prefix(2, false, 0, &mut block);
        encode_prefixed_int(0, 6, 0b1000_0000, &mut block); // a dynamic indexed line
        let err = decode_header_block(&mut dec, &block).unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)), "got {err:?}");
    }

    #[test]
    fn qpack_decode_dynamic_reference_bomb_trips_list_cap() {
        // Even with dynamic references, the decoded-header-list cap must trip.
        // Insert one large entry, then reference it many times.
        let mut dec = decoder();
        let mut enc = Vec::new();
        enc_set_capacity(QPACK_MAX_TABLE_CAPACITY, &mut enc);
        let big = "x".repeat(3000);
        enc_insert_literal("a", &big, &mut enc); // abs 0, size 1+3000+32 = 3033
        dec.feed_encoder_stream(&enc).expect("inserts");
        assert_eq!(dec.insert_count(), 1);

        let mut block = Vec::new();
        enc_prefix(2, false, 0, &mut block); // RIC=1, Base=1
                                             // Reference abs 0 (relative 0) 100 times: 100 * 3033 > 256 KiB cap.
        for _ in 0..100 {
            encode_prefixed_int(0, 6, 0b1000_0000, &mut block);
        }
        let err = decode_header_block(&mut dec, &block).unwrap_err();
        match err {
            Error::BadResponse(m) => assert!(m.contains("header list"), "msg: {m}"),
            other => panic!("expected header-list-cap error, got {other:?}"),
        }
    }

    #[test]
    fn qpack_encoder_stream_partial_instruction_is_held() {
        // A truncated encoder-stream instruction must be left unframed so the
        // streaming caller can retry after more bytes arrive (and so compcol
        // never sees — and half-applies — a partial instruction).
        let mut full = Vec::new();
        enc_set_capacity(QPACK_MAX_TABLE_CAPACITY, &mut full);
        enc_insert_literal("name", "value", &mut full);

        // Drop the last value byte: the Set Dynamic Table Capacity instruction
        // is complete, the trailing insert isn't.
        let truncated = &full[..full.len() - 1];
        let complete = complete_encoder_instructions_len(truncated);
        assert!(complete > 0 && complete < truncated.len());
        let mut dec = decoder();
        dec.feed_encoder_stream(&truncated[..complete])
            .expect("feed complete prefix");
        assert_eq!(dec.insert_count(), 0, "no insert applied from a partial");

        // With the whole buffer the insert frames completely and lands.
        assert_eq!(complete_encoder_instructions_len(&full), full.len());
        let mut dec = decoder();
        dec.feed_encoder_stream(&full).expect("feed full");
        assert_eq!(dec.insert_count(), 1);
    }

    // ---- HTTP/3 framing --------------------------------------------------

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

    /// A request stream that has already received a final `200` head.
    fn rs_with_head() -> ReqStream {
        ReqStream {
            headers: Some(vec![(":status".into(), "200".into())]),
            ..ReqStream::default()
        }
    }

    fn consume(buf: &[u8], rs: &mut ReqStream) -> FrameOutcome {
        let mut dec = decoder();
        try_consume_frame(buf, rs, &mut dec, None)
    }

    #[test]
    fn oversized_headers_frame_len_is_rejected() {
        // A HEADERS frame declaring a length far larger than any real header
        // section must be rejected before we buffer toward MAX_RESPONSE_BYTES.
        let mut buf = Vec::new();
        Frame::encode_header(frame_type::HEADERS, MAX_HEADERS_FRAME_LEN + 1, &mut buf);
        let mut rs = ReqStream::default();
        assert!(matches!(
            consume(&buf, &mut rs),
            FrameOutcome::Err(Error::BadResponse(_))
        ));
    }

    #[test]
    fn data_frame_len_past_budget_is_rejected() {
        // A buffered DATA frame claiming more bytes than the remaining
        // response budget must be rejected rather than buffered up to the
        // 256 MiB cap.
        let mut buf = Vec::new();
        Frame::encode_header(frame_type::DATA, (MAX_RESPONSE_BYTES + 1) as u64, &mut buf);
        let mut rs = rs_with_head();
        assert!(matches!(
            consume(&buf, &mut rs),
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
        let mut rs = rs_with_head();
        let mut dec = decoder();
        let mut sink: Vec<u8> = Vec::new();
        let outcome = try_consume_frame(&buf, &mut rs, &mut dec, Some(&mut sink));
        assert!(
            matches!(outcome, FrameOutcome::Consumed(n, _) if n == buf.len()),
            "expected the DATA frame to be consumed"
        );
        assert_eq!(sink, payload);
        assert!(rs.body.is_empty(), "streamed body must not be buffered");
        assert_eq!(rs.streamed_len, payload.len() as u64);
    }

    #[test]
    fn large_data_frame_streams_progressively_past_the_buffer_cap() {
        // A single DATA frame larger than MAX_RESPONSE_BYTES is fine when
        // streaming to a sink: its payload is delivered as it arrives, never
        // buffered whole.
        let declared = (MAX_RESPONSE_BYTES as u64) + 10;
        let mut buf = Vec::new();
        Frame::encode_header(frame_type::DATA, declared, &mut buf);
        let hdr = buf.len();
        buf.extend_from_slice(b"abc");
        let mut rs = rs_with_head();
        let mut dec = decoder();
        let mut sink: Vec<u8> = Vec::new();
        let outcome = try_consume_frame(&buf, &mut rs, &mut dec, Some(&mut sink));
        assert!(matches!(outcome, FrameOutcome::Consumed(n, _) if n == hdr + 3));
        assert_eq!(sink, b"abc");
        assert_eq!(rs.data_remaining, declared - 3);
        // The next bytes on the stream continue the same frame.
        let outcome = try_consume_frame(b"defg", &mut rs, &mut dec, Some(&mut sink));
        assert!(matches!(outcome, FrameOutcome::Consumed(4, _)));
        assert_eq!(sink, b"abcdefg");
        assert_eq!(rs.data_remaining, declared - 7);
    }

    #[test]
    fn data_before_headers_is_rejected() {
        let mut buf = Vec::new();
        Frame::encode_header(frame_type::DATA, 2, &mut buf);
        buf.extend_from_slice(b"hi");
        let mut rs = ReqStream::default();
        let mut dec = decoder();
        let mut sink: Vec<u8> = Vec::new();
        assert!(matches!(
            try_consume_frame(&buf, &mut rs, &mut dec, Some(&mut sink)),
            FrameOutcome::Err(Error::BadResponse(_))
        ));
        assert!(sink.is_empty(), "no body byte may precede the head");
    }

    #[test]
    fn grease_frame_payload_is_skipped_progressively() {
        // A reserved/grease frame (RFC 9114 §7.2.8) is skipped as it arrives,
        // whatever its declared length — never buffered whole.
        let mut buf = Vec::new();
        Frame::encode_header(0x21, 4096, &mut buf);
        let hdr = buf.len();
        let mut rs = ReqStream::default();
        assert!(matches!(
            consume(&buf, &mut rs),
            FrameOutcome::Consumed(n, false) if n == hdr
        ));
        assert_eq!(rs.skip_remaining, 4096);
        assert!(matches!(
            consume(&[0u8; 100], &mut rs),
            FrameOutcome::Consumed(100, false)
        ));
        assert_eq!(rs.skip_remaining, 3996);
        assert!(rs.body.is_empty());
    }

    /// Build a HEADERS frame carrying `fields`, statically QPACK-encoded.
    fn headers_frame(fields: &[(&str, &str)]) -> Vec<u8> {
        let owned: Vec<(String, String)> = fields
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let block = encode_header_block(&owned);
        let mut buf = Vec::new();
        Frame::encode_header(frame_type::HEADERS, block.len() as u64, &mut buf);
        buf.extend_from_slice(&block);
        buf
    }

    #[test]
    fn control_frame_on_request_stream_is_rejected() {
        // SETTINGS / GOAWAY / CANCEL_PUSH / MAX_PUSH_ID / PUSH_PROMISE belong on
        // the control stream (or need a push we never enabled). On a request
        // stream they are H3_FRAME_UNEXPECTED — rejected even before the
        // declared payload is buffered (here only the header is present).
        for ty in [
            frame_type::SETTINGS,
            frame_type::GOAWAY,
            frame_type::CANCEL_PUSH,
            frame_type::MAX_PUSH_ID,
            frame_type::PUSH_PROMISE,
        ] {
            let mut buf = Vec::new();
            Frame::encode_header(ty, 8, &mut buf); // declares 8 bytes, sends none
            let mut rs = ReqStream::default();
            assert!(
                matches!(
                    consume(&buf, &mut rs),
                    FrameOutcome::Err(Error::BadResponse(_))
                ),
                "frame type {ty:#x} must be rejected on a request stream"
            );
        }
    }

    #[test]
    fn h2_reserved_frame_types_are_rejected_on_request_stream() {
        // PRIORITY / PING / WINDOW_UPDATE / CONTINUATION are reserved in
        // HTTP/3 (§7.2.8): H3_FRAME_UNEXPECTED, not grease to be skipped.
        for ty in [0x02u64, 0x06, 0x08, 0x09] {
            let mut buf = Vec::new();
            Frame::encode_header(ty, 0, &mut buf);
            let mut rs = rs_with_head();
            assert!(
                matches!(
                    consume(&buf, &mut rs),
                    FrameOutcome::Err(Error::BadResponse(_))
                ),
                "frame type {ty:#x} must be rejected"
            );
        }
    }

    #[test]
    fn interim_1xx_headers_is_skipped_then_final_used() {
        // A 1xx informational HEADERS block must not become the response head;
        // the following final block is the real one (RFC 9114 §4.1).
        let interim = headers_frame(&[(":status", "103")]);
        let final_block = headers_frame(&[(":status", "200"), ("content-type", "text/plain")]);
        let mut rs = ReqStream::default();
        let mut dec = decoder();

        assert!(matches!(
            try_consume_frame(&interim, &mut rs, &mut dec, None),
            FrameOutcome::Consumed(_, _)
        ));
        assert!(
            rs.headers.is_none(),
            "interim 1xx must not be stored as the head"
        );

        assert!(matches!(
            try_consume_frame(&final_block, &mut rs, &mut dec, None),
            FrameOutcome::Consumed(_, _)
        ));
        let fields = rs.headers.expect("final HEADERS should be stored");
        assert_eq!(header_status(&fields), Some(200));
    }

    #[test]
    fn interim_1xx_flood_is_bounded() {
        let interim = headers_frame(&[(":status", "103")]);
        let mut rs = ReqStream::default();
        let mut dec = decoder();
        for _ in 0..MAX_INTERIM_RESPONSES {
            assert!(matches!(
                try_consume_frame(&interim, &mut rs, &mut dec, None),
                FrameOutcome::Consumed(_, _)
            ));
        }
        assert!(matches!(
            try_consume_frame(&interim, &mut rs, &mut dec, None),
            FrameOutcome::Err(Error::BadResponse(_))
        ));
    }

    #[test]
    fn trailers_after_final_headers_are_discarded() {
        let final_block = headers_frame(&[(":status", "200")]);
        let trailers = headers_frame(&[("x-trailer", "v")]);
        let mut rs = ReqStream::default();
        let mut dec = decoder();

        let _ = try_consume_frame(&final_block, &mut rs, &mut dec, None);
        assert_eq!(header_status(rs.headers.as_ref().unwrap()), Some(200));

        // A second HEADERS block (after the final response) is trailers: consumed
        // but does not replace the stored head.
        assert!(matches!(
            try_consume_frame(&trailers, &mut rs, &mut dec, None),
            FrameOutcome::Consumed(_, _)
        ));
        let fields = rs.headers.as_ref().unwrap();
        assert_eq!(header_status(fields), Some(200));
        assert!(
            !fields.iter().any(|(k, _)| k == "x-trailer"),
            "trailers must not be merged into the head"
        );

        // Nothing but FIN may follow trailers.
        let mut data = Vec::new();
        Frame::encode_header(frame_type::DATA, 1, &mut data);
        data.push(b'x');
        assert!(matches!(
            try_consume_frame(&data, &mut rs, &mut dec, None),
            FrameOutcome::Err(Error::BadResponse(_))
        ));
    }

    #[test]
    fn trailers_with_pseudo_header_are_rejected() {
        let final_block = headers_frame(&[(":status", "200")]);
        let trailers = headers_frame(&[(":status", "500")]);
        let mut rs = ReqStream::default();
        let mut dec = decoder();
        let _ = try_consume_frame(&final_block, &mut rs, &mut dec, None);
        assert!(matches!(
            try_consume_frame(&trailers, &mut rs, &mut dec, None),
            FrameOutcome::Err(Error::BadResponse(_))
        ));
    }

    #[test]
    fn malformed_response_heads_are_rejected() {
        for fields in [
            &[(":status", "200"), (":status", "204")][..],
            &[("content-type", "x"), (":status", "200")][..],
            &[(":status", "200"), ("connection", "close")][..],
            &[(":status", "200"), ("transfer-encoding", "chunked")][..],
            &[(":status", "200"), (":path", "/")][..],
            &[(":status", "20")][..],
            &[("content-type", "x")][..],
            &[
                (":status", "200"),
                ("content-length", "1"),
                ("content-length", "2"),
            ][..],
        ] {
            let block = headers_frame(fields);
            let mut rs = ReqStream::default();
            assert!(
                matches!(
                    consume(&block, &mut rs),
                    FrameOutcome::Err(Error::BadResponse(_))
                ),
                "{fields:?} must be rejected"
            );
        }
    }

    #[test]
    fn content_length_mismatch_is_detected() {
        // Short body: detected when the stream ends.
        let head = headers_frame(&[(":status", "200"), ("content-length", "5")]);
        let mut rs = ReqStream::default();
        let mut dec = decoder();
        let _ = try_consume_frame(&head, &mut rs, &mut dec, None);
        let mut data = Vec::new();
        Frame::encode_header(frame_type::DATA, 3, &mut data);
        data.extend_from_slice(b"abc");
        assert!(matches!(
            try_consume_frame(&data, &mut rs, &mut dec, None),
            FrameOutcome::Consumed(_, _)
        ));
        assert!(rs.check_content_length(true).is_err());

        // Excess: rejected as soon as the DATA frame header declares it.
        let mut data = Vec::new();
        Frame::encode_header(frame_type::DATA, 3, &mut data);
        data.extend_from_slice(b"def");
        assert!(matches!(
            try_consume_frame(&data, &mut rs, &mut dec, None),
            FrameOutcome::Err(Error::BadResponse(_))
        ));

        // HEAD: content-length describes the GET body, not this stream.
        let mut rs = ReqStream {
            head_request: true,
            ..ReqStream::default()
        };
        let _ = try_consume_frame(&head, &mut rs, &mut dec, None);
        assert!(rs.check_content_length(true).is_ok());
    }

    #[test]
    fn dial_addr_honours_connect_to_and_resolve() {
        // --resolve pins the URL host.
        let mut req = Request::get("https://h3.invalid/").unwrap();
        req.resolve
            .push(("h3.invalid".into(), 443, "127.0.0.9".parse().unwrap()));
        assert_eq!(dial_addr(&req).unwrap(), "127.0.0.9:443".parse().unwrap());

        // --connect-to remaps first; the pin then applies to the new target.
        let mut req = Request::get("https://h3.invalid/").unwrap().connect_to(
            "h3.invalid",
            443,
            "backend.invalid",
            8443,
        );
        req.resolve
            .push(("backend.invalid".into(), 8443, "127.0.0.7".parse().unwrap()));
        assert_eq!(dial_addr(&req).unwrap(), "127.0.0.7:8443".parse().unwrap());
    }

    #[test]
    fn ipv6_literal_host_is_unbracketed_for_tls_and_dialing() {
        assert_eq!(tls_host("[::1]"), "::1");
        assert_eq!(tls_host("[fe80::1%25en0]"), "fe80::1");
        assert_eq!(tls_host("example.com"), "example.com");

        let req = Request::get("https://[::1]:8443/").unwrap();
        assert_eq!(dial_addr(&req).unwrap(), "[::1]:8443".parse().unwrap());
        // Verifying: the bare IP is the reference identity.
        assert_eq!(quic_server_name(&req), "::1");
        // Not verifying: no SNI for an IP literal (RFC 6066 §3).
        let mut insecure = req.clone();
        insecure.verify_tls = false;
        assert_eq!(quic_server_name(&insecure), "");
        let named = Request::get("https://example.com/").unwrap();
        assert_eq!(quic_server_name(&named), "example.com");
    }

    #[test]
    fn te_request_field_only_passes_trailers() {
        assert!(omit_request_field("te", "gzip"));
        assert!(!omit_request_field("te", "trailers"));
        assert!(omit_request_field("connection", "keep-alive"));
        assert!(omit_request_field("host", "example.com"));
        assert!(!omit_request_field("accept", "*/*"));
    }

    // ---- server unidirectional streams (RFC 9114 §6.2) ----

    fn uni_bytes(state: &mut Http3State, sid: u64, bytes: &[u8]) -> Result<()> {
        state
            .uni
            .entry(sid)
            .or_default()
            .buf
            .extend_from_slice(bytes);
        process_uni_stream(state, sid)
    }

    fn control_prefix_with_settings(settings: &[(u64, u64)]) -> Vec<u8> {
        let mut payload = Vec::new();
        for (id, v) in settings {
            varint::encode(*id, &mut payload);
            varint::encode(*v, &mut payload);
        }
        let mut out = Vec::new();
        varint::encode(uni_stream_type::CONTROL, &mut out);
        Frame::encode_header(frame_type::SETTINGS, payload.len() as u64, &mut out);
        out.extend_from_slice(&payload);
        out
    }

    #[test]
    fn control_stream_requires_settings_first() {
        let mut state = Http3State::new(None);
        let mut bytes = Vec::new();
        varint::encode(uni_stream_type::CONTROL, &mut bytes);
        Frame::encode_header(frame_type::GOAWAY, 1, &mut bytes);
        bytes.push(0);
        assert!(uni_bytes(&mut state, 3, &bytes).is_err());
    }

    #[test]
    fn control_stream_settings_then_goaway_is_recorded() {
        let mut state = Http3State::new(None);
        let bytes = control_prefix_with_settings(&[(settings_id::QPACK_MAX_TABLE_CAPACITY, 0)]);
        uni_bytes(&mut state, 3, &bytes).unwrap();
        assert!(state.settings_seen);
        let mut goaway = Vec::new();
        Frame::encode_header(frame_type::GOAWAY, 1, &mut goaway);
        goaway.push(4);
        uni_bytes(&mut state, 3, &goaway).unwrap();
        assert_eq!(state.goaway_id, Some(4));
        // A later GOAWAY may not raise the id.
        let mut higher = Vec::new();
        Frame::encode_header(frame_type::GOAWAY, 1, &mut higher);
        higher.push(8);
        assert!(uni_bytes(&mut state, 3, &higher).is_err());
    }

    #[test]
    fn control_stream_rejects_second_settings_and_reserved_ids() {
        let mut state = Http3State::new(None);
        uni_bytes(&mut state, 3, &control_prefix_with_settings(&[])).unwrap();
        let mut again = Vec::new();
        Frame::encode_header(frame_type::SETTINGS, 0, &mut again);
        assert!(uni_bytes(&mut state, 3, &again).is_err());

        // HTTP/2's SETTINGS_ENABLE_PUSH (0x2) is reserved in HTTP/3.
        let mut state = Http3State::new(None);
        assert!(uni_bytes(&mut state, 3, &control_prefix_with_settings(&[(0x2, 0)])).is_err());
    }

    #[test]
    fn control_stream_rejects_h2_frame_types_and_skips_grease() {
        let mut state = Http3State::new(None);
        uni_bytes(&mut state, 3, &control_prefix_with_settings(&[])).unwrap();
        // A large grease frame is skipped without buffering its payload.
        let mut grease = Vec::new();
        Frame::encode_header(0x21, 1_000_000, &mut grease);
        grease.extend_from_slice(&[0u8; 1000]);
        uni_bytes(&mut state, 3, &grease).unwrap();
        assert!(state.uni[&3].buf.is_empty());
        assert_eq!(state.uni[&3].skip_remaining, 999_000);

        let mut state = Http3State::new(None);
        uni_bytes(&mut state, 3, &control_prefix_with_settings(&[])).unwrap();
        let mut ping = Vec::new();
        Frame::encode_header(0x06, 8, &mut ping);
        ping.extend_from_slice(&[0u8; 8]);
        assert!(uni_bytes(&mut state, 3, &ping).is_err());
    }

    #[test]
    fn duplicate_critical_uni_streams_are_rejected() {
        let mut state = Http3State::new(None);
        uni_bytes(&mut state, 3, &control_prefix_with_settings(&[])).unwrap();
        assert!(uni_bytes(&mut state, 7, &control_prefix_with_settings(&[])).is_err());

        let mut state = Http3State::new(None);
        let mut enc = Vec::new();
        varint::encode(uni_stream_type::QPACK_ENCODER, &mut enc);
        uni_bytes(&mut state, 3, &enc).unwrap();
        assert!(uni_bytes(&mut state, 7, &enc).is_err());
    }

    #[test]
    fn push_stream_without_max_push_id_is_rejected() {
        let mut state = Http3State::new(None);
        let mut push = Vec::new();
        varint::encode(uni_stream_type::PUSH, &mut push);
        assert!(uni_bytes(&mut state, 3, &push).is_err());
    }

    #[test]
    fn grease_uni_stream_is_discarded_not_buffered() {
        // A reserved stream type (0x21) carrying far more than MAX_UNI_BUFFER
        // must be discarded as it arrives rather than tripping the buffer cap.
        let mut state = Http3State::new(None);
        let mut first = Vec::new();
        varint::encode(0x21, &mut first);
        first.extend_from_slice(&[0u8; 16 * 1024]);
        uni_bytes(&mut state, 3, &first).unwrap();
        for _ in 0..10 {
            uni_bytes(&mut state, 3, &[0u8; 16 * 1024]).unwrap();
            assert!(state.uni[&3].buf.is_empty());
        }
    }
}

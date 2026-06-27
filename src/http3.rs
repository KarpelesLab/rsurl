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
//! Out-of-scope behaviours (HTTP/3 framing and transport, not QPACK):
//!
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

/// Cap on the *decoded* header-list size (sum of `name + value + 32` per
/// header, the RFC 7541 §4.1 accounting). Bounds a QPACK decompression bomb: a
/// small compressed field section can otherwise expand into a huge header list
/// and exhaust memory.
const MAX_DECODED_HEADER_LIST: usize = 256 * 1024;

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

/// Validate a decoded QPACK field per RFC 9114 §10.3 / RFC 7230 token rules.
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
/// Maximum UDP datagram we expect to receive (a hair over the QUIC default).
const MAX_DATAGRAM: usize = 65_535;

/// Per-connection HTTP/3 / QPACK decoder state. Holds the QPACK decoder (whose
/// dynamic table is fed by the peer's encoder stream), the partial-read buffers
/// for the server's unidirectional streams (so an instruction split across
/// datagrams can be reassembled), and the client's QPACK decoder stream id
/// (where we send Section Acknowledgements).
struct Http3State {
    /// The QPACK decoder; its dynamic table is populated from the peer's
    /// encoder stream and bounded by our advertised max table capacity.
    decoder: QpackDecoder,
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
            decoder: QpackDecoder::with_max_table_capacity(QPACK_MAX_TABLE_CAPACITY as usize),
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

    let dial_start = Instant::now();
    let mut conn = build_client(&req)?;
    let (sock, peer) = open_udp(&req)?;
    let connect = dial_start.elapsed();
    let _ = writeln!(trace, "*   Trying {peer} (UDP)...");
    handshake(&mut conn, &*sock, peer, req.read_timeout)?;
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

    write_request(&mut conn, request_stream, &req, trace)?;
    if !req.body.is_empty() {
        let _ = writeln!(trace, "* uploading {} body bytes", req.body.len());
    }
    pump(&mut conn, &*sock, peer, req.read_timeout)?;

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
    )?;
    resp.tls = Some(tls_info);
    resp.timing.connect = Some(connect);
    resp.timing.appconnect = Some(appconnect);
    resp.timing.pretransfer = Some(appconnect);
    Ok(resp)
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
        }
        // Control / decoder / push / unknown: drain and ignore for our
        // one-shot request. We never reference push, and the server's
        // control SETTINGS don't change our static-only request encoding.
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
            server_name: &req.url.host,
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
    encode_prefixed_int(stream_id, 7, 0b1000_0000, out);
}

fn write_all(conn: &mut QuicConnection, sid: StreamId, mut data: &[u8]) -> Result<()> {
    while !data.is_empty() {
        let n = conn
            .write(sid, data)
            .map_err(|e| Error::BadResponse(format!("http3: stream write: {e:?}")))?;
        if n == 0 {
            // Flow control blocked — rather than spin, bail out (a request
            // header section plus a small body fits the initial flow window).
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

    let qpack_payload = encode_header_block(&fields);

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
    let mut headers: Option<Fields> = None;
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
            // content-encoded (encoded bodies must be buffered to decode) — but
            // when the caller turned decompression off, there's nothing to
            // decode, so even an encoded body streams straight through as raw
            // bytes. Recomputed each frame because HEADERS may have just arrived.
            let encoded = req.decompress
                && headers.as_ref().is_some_and(|f| {
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
                &mut state.decoder,
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
    finalize_response(fields, body, streamed_len, req.decompress, sink, trace)
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
/// number of bytes consumed is returned. A HEADERS block is decoded with
/// `decoder` (whose dynamic table the encoder stream has already populated);
/// the returned flag reports whether the block referenced the dynamic table
/// (Required Insert Count > 0), so the caller can send a Section
/// Acknowledgement.
#[allow(clippy::too_many_arguments)]
fn try_consume_frame(
    buf: &[u8],
    headers: &mut Option<Fields>,
    body: &mut Vec<u8>,
    decoder: &mut QpackDecoder,
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
        frame_type::HEADERS => match decode_header_block(decoder, payload) {
            Ok(fields) => {
                if headers.is_some() {
                    // Trailers — RFC 9114 §4.1 allows them, but we don't
                    // surface them. Discard silently.
                } else {
                    *headers = Some(fields);
                }
                let ack_owed = block_references_dynamic_table(payload);
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

    #[test]
    fn oversized_headers_frame_len_is_rejected() {
        // A HEADERS frame declaring a length far larger than any real header
        // section must be rejected before we buffer toward MAX_RESPONSE_BYTES.
        let mut buf = Vec::new();
        Frame::encode_header(frame_type::HEADERS, MAX_HEADERS_FRAME_LEN + 1, &mut buf);
        let mut headers = None;
        let mut body = Vec::new();
        let mut dec = decoder();
        assert!(matches!(
            try_consume_frame(&buf, &mut headers, &mut body, &mut dec, None, &mut 0),
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
        let mut dec = decoder();
        assert!(matches!(
            try_consume_frame(&buf, &mut headers, &mut body, &mut dec, None, &mut 0),
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
        let mut dec = decoder();
        let mut sink: Vec<u8> = Vec::new();
        let mut streamed: u64 = 0;
        let outcome = try_consume_frame(
            &buf,
            &mut headers,
            &mut body,
            &mut dec,
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
            let mut dec = decoder();
            assert!(matches!(
                try_consume_frame(&buf, &mut headers, &mut body, &mut dec, None, &mut 0),
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
        let mut dec = decoder();
        assert!(matches!(
            try_consume_frame(&buf, &mut headers, &mut body, &mut dec, None, &mut 0),
            FrameOutcome::NeedMore
        ));
    }
}

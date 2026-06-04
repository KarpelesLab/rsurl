//! Response-body decompression for `Content-Encoding: gzip | deflate | zstd | br | compress`.
//!
//! `Accept-Encoding: gzip, deflate` is offered by default on every HTTP
//! request rsurl makes; this module is the matching decode side. It is the
//! moral equivalent of curl's `--compressed`, except always-on — without
//! it, a vanilla GET against any modern HTTP server returns a body that
//! looks like binary noise.
//!
//! Scope:
//!
//! * **gzip** (RFC 1952) and **deflate** (RFC 1951) are decoded.
//!   `x-gzip` is accepted as a gzip alias because some legacy servers
//!   still emit it.
//! * **zstd** (RFC 8878), **br** (brotli, RFC 7932) and **compress** /
//!   **x-compress** (the classic Unix `.Z` LZW format defined by the
//!   `compress(1)` utility) are decoded too, all via `compcol`'s pure-Rust
//!   codecs — no C dependency is pulled in.
//! * **identity** is a no-op pass-through.
//!
//! With LZW wired in, every common HTTP content coding is now supported. Any
//! other unknown encoding is returned verbatim and the encoding token is
//! reported so the caller can decide what to do (today, we leave the header in
//! place and ship the bytes through unchanged — matching what curl does when it
//! doesn't know an encoding).
//!
//! `Content-Encoding` is a list. RFC 9110 §8.4.1 says encodings are applied
//! in the order listed, so decoding walks the list **right-to-left**.

use std::io::Read;

use compcol::brotli::Brotli;
use compcol::deflate::Deflate;
use compcol::gzip::Gzip;
use compcol::io::DecoderReader;
use compcol::limit::LimitedDecoder;
use compcol::lzw::Lzw;
use compcol::zlib::Zlib;
use compcol::zstd::Zstd;
use compcol::Algorithm;

use crate::error::{Error, Result};
use crate::http::MAX_BODY_BYTES;

/// Maximum number of `Content-Encoding` layers we will decode for a single
/// response. Stacked encodings are a decompression-amplification vector: each
/// layer can expand its input, so N layers multiply both the work performed
/// and the peak resident memory. Real servers send at most one (occasionally
/// two) layers; curl and browsers reject deeply-nested chains. Cap at a small
/// number and surface anything beyond it as a bad response.
const MAX_ENCODING_LAYERS: usize = 3;

/// Result of trying to decode a body against a `Content-Encoding` header.
#[derive(Debug)]
pub(crate) struct Decoded {
    /// The decoded bytes (or the original bytes, if no decoding happened).
    pub body: Vec<u8>,
    /// `true` if at least one encoding layer was successfully stripped.
    /// Drives whether the caller rewrites `Content-Encoding` /
    /// `Content-Length` on the [`crate::Response`].
    pub decoded: bool,
}

/// Walk a comma-separated `Content-Encoding` value right-to-left and peel
/// off each layer we recognise. Stops at the first unknown token so we
/// don't claim a body is plaintext when an outer brotli wrapper still hides it.
///
/// `body` is consumed; on success returns the (possibly-decoded) bytes.
/// On a decode error mid-stream, returns the error — a truncated or
/// corrupt gzip frame is a real problem worth surfacing.
pub(crate) fn decode_body(body: Vec<u8>, content_encoding: &str) -> Result<Decoded> {
    // Split, normalise, drop empty entries (Some servers emit
    // "gzip,,deflate" or trailing commas — be permissive on input).
    let layers: Vec<&str> = content_encoding
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if layers.is_empty() {
        return Ok(Decoded {
            body,
            decoded: false,
        });
    }

    // Bound the number of stacked encodings: a deeply-nested chain is a
    // decompression-amplification vector with no legitimate use.
    if layers.len() > MAX_ENCODING_LAYERS {
        return Err(Error::BadResponse(format!(
            "too many Content-Encoding layers ({}, max {MAX_ENCODING_LAYERS})",
            layers.len()
        )));
    }

    let mut current = body;
    let mut peeled = false;
    // Single cumulative output budget shared across every layer, so N stacked
    // encodings can't each claim a fresh MAX_BODY_BYTES allowance. Each layer
    // may expand the running total only up to what remains.
    let mut budget = MAX_BODY_BYTES as u64;
    for token in layers.iter().rev() {
        match Layer::parse(token) {
            Some(Layer::Identity) => {
                // No-op; counts as recognised so the loop keeps going if
                // there are inner layers we can still strip.
                peeled = true;
            }
            Some(Layer::Gzip) => {
                current = gunzip(&current, budget)?;
                budget = budget.saturating_sub(current.len() as u64);
                peeled = true;
            }
            Some(Layer::Deflate) => {
                current = inflate_zlib(&current, budget)?;
                budget = budget.saturating_sub(current.len() as u64);
                peeled = true;
            }
            Some(Layer::Zstd) => {
                current = unzstd(&current, budget)?;
                budget = budget.saturating_sub(current.len() as u64);
                peeled = true;
            }
            Some(Layer::Brotli) => {
                current = unbrotli(&current, budget)?;
                budget = budget.saturating_sub(current.len() as u64);
                peeled = true;
            }
            Some(Layer::Compress) => {
                current = uncompress(&current, budget)?;
                budget = budget.saturating_sub(current.len() as u64);
                peeled = true;
            }
            None => {
                // Unknown outer layer — return what we have so far with the
                // body untouched from this point in. We can't safely strip
                // any inner layers since they're behind a wrapper we can't
                // read. Caller will leave the Content-Encoding header alone.
                return Ok(Decoded {
                    body: current,
                    decoded: peeled,
                });
            }
        }
    }
    Ok(Decoded {
        body: current,
        decoded: peeled,
    })
}

enum Layer {
    Gzip,
    Deflate,
    Zstd,
    Brotli,
    Compress,
    Identity,
}

impl Layer {
    fn parse(token: &str) -> Option<Self> {
        // Tokens are case-insensitive per RFC 9110.
        if token.eq_ignore_ascii_case("gzip") || token.eq_ignore_ascii_case("x-gzip") {
            Some(Layer::Gzip)
        } else if token.eq_ignore_ascii_case("deflate") {
            Some(Layer::Deflate)
        } else if token.eq_ignore_ascii_case("zstd") {
            Some(Layer::Zstd)
        } else if token.eq_ignore_ascii_case("br") {
            Some(Layer::Brotli)
        } else if token.eq_ignore_ascii_case("compress") || token.eq_ignore_ascii_case("x-compress")
        {
            Some(Layer::Compress)
        } else if token.eq_ignore_ascii_case("identity") {
            Some(Layer::Identity)
        } else {
            None
        }
    }
}

/// One-shot decode of `src` with algorithm `A`, capping the decompressed
/// output at `budget` bytes via compcol's [`LimitedDecoder`]. `budget` is the
/// portion of the response-wide [`MAX_BODY_BYTES`] allowance still unspent by
/// earlier layers, so a stack of encodings can't exceed the single cap. The
/// streaming `DecoderReader` adapter exposes a `std::io::Read` so we can
/// reuse the standard `read_to_end` machinery.
fn decode_with<A: Algorithm>(src: &[u8], budget: u64) -> std::io::Result<Vec<u8>> {
    // Pre-allocate against the remaining budget, not a blind 3x of the input,
    // so a tiny highly-compressible frame can't pre-reserve hundreds of MiB.
    let cap = (src.len() as u64).saturating_mul(3).min(budget) as usize;
    let mut out = Vec::with_capacity(cap);
    let dec = LimitedDecoder::new(A::decoder(), budget);
    let mut reader = DecoderReader::new(src, dec);
    reader.read_to_end(&mut out)?;
    Ok(out)
}

fn gunzip(src: &[u8], budget: u64) -> Result<Vec<u8>> {
    decode_with::<Gzip>(src, budget)
        .map_err(|e| Error::BadResponse(format!("gzip decode failed: {e}")))
}

/// Decode a `deflate`-encoded body. RFC 9110 says HTTP `deflate` is **zlib**
/// (RFC 1950) wrapping raw deflate (RFC 1951), but many real-world servers
/// emit raw deflate without the zlib header. Try the zlib framing first;
/// if it fails, retry as raw deflate so we interoperate with both camps.
fn inflate_zlib(src: &[u8], budget: u64) -> Result<Vec<u8>> {
    let zlib_err = match decode_with::<Zlib>(src, budget) {
        Ok(out) => return Ok(out),
        Err(e) => e,
    };
    decode_with::<Deflate>(src, budget)
        .map_err(|_| Error::BadResponse(format!("deflate decode failed: {zlib_err}")))
}

/// Decode a `zstd`-encoded (RFC 8878) body. Routes through the same
/// budget-bounded streaming path as gzip/deflate; compcol's zstd decoder is
/// pure Rust and plugs into the generic `decode_with` via its `Algorithm` impl.
fn unzstd(src: &[u8], budget: u64) -> Result<Vec<u8>> {
    decode_with::<Zstd>(src, budget)
        .map_err(|e| Error::BadResponse(format!("zstd decode failed: {e}")))
}

/// Decode a `br`-encoded (brotli, RFC 7932) body. Same budget-bounded
/// streaming path as the other codecs.
fn unbrotli(src: &[u8], budget: u64) -> Result<Vec<u8>> {
    decode_with::<Brotli>(src, budget)
        .map_err(|e| Error::BadResponse(format!("brotli decode failed: {e}")))
}

/// Decode a `compress` / `x-compress`-encoded body — the classic Unix `.Z`
/// LZW format (magic `0x1F 0x9D`, block mode, early-change width growth and
/// group padding) defined by `compress(1)`. Routes through the same
/// budget-bounded streaming path as the other codecs; compcol's LZW decoder is
/// pure Rust and plugs into the generic `decode_with` via its `Algorithm` impl,
/// so no bespoke bit-banging lives here.
fn uncompress(src: &[u8], budget: u64) -> Result<Vec<u8>> {
    decode_with::<Lzw>(src, budget)
        .map_err(|e| Error::BadResponse(format!("compress decode failed: {e}")))
}

/// A single content coding that can be decoded directly off a byte stream
/// (no buffered retry). Excludes `deflate` (its zlib-vs-raw ambiguity needs a
/// buffered fallback) and `compress`/multi-layer/unknown encodings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StreamCodec {
    Gzip,
    Zstd,
    Brotli,
}

/// If `content_encoding` is exactly one streamable layer (gzip / zstd / br,
/// case-insensitive, with optional surrounding whitespace), return its codec so
/// the caller can decode straight off the wire. Anything else — `deflate`,
/// `compress`, `identity`, an unknown token, or more than one layer — returns
/// `None`, and the caller should fall back to the buffered [`decode_body`].
pub(crate) fn single_streamable_layer(content_encoding: &str) -> Option<StreamCodec> {
    let mut layers = content_encoding
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let only = layers.next()?;
    if layers.next().is_some() {
        return None; // more than one layer
    }
    if only.eq_ignore_ascii_case("gzip") || only.eq_ignore_ascii_case("x-gzip") {
        Some(StreamCodec::Gzip)
    } else if only.eq_ignore_ascii_case("zstd") {
        Some(StreamCodec::Zstd)
    } else if only.eq_ignore_ascii_case("br") {
        Some(StreamCodec::Brotli)
    } else {
        None
    }
}

/// Decode a single-codec stream from `reader` to `sink`, capping the
/// decompressed output at `budget` bytes via compcol's [`LimitedDecoder`] (the
/// decompression-bomb guard). Returns the number of plaintext bytes written.
pub(crate) fn stream_decode<R: Read, W: std::io::Write + ?Sized>(
    reader: R,
    codec: StreamCodec,
    sink: &mut W,
    budget: u64,
) -> Result<u64> {
    fn copy<A: Algorithm, R: Read, W: std::io::Write + ?Sized>(
        reader: R,
        sink: &mut W,
        budget: u64,
    ) -> std::io::Result<u64> {
        let dec = LimitedDecoder::new(A::decoder(), budget);
        let mut r = DecoderReader::new(reader, dec);
        std::io::copy(&mut r, sink)
    }
    let res = match codec {
        StreamCodec::Gzip => copy::<Gzip, _, _>(reader, sink, budget),
        StreamCodec::Zstd => copy::<Zstd, _, _>(reader, sink, budget),
        StreamCodec::Brotli => copy::<Brotli, _, _>(reader, sink, budget),
    };
    res.map_err(|e| Error::BadResponse(format!("{codec:?} stream decode failed: {e}")))
}

/// Strip `Content-Encoding` and `Content-Length` from a response header
/// list after a successful in-place body decode. Returns the new headers.
///
/// `Content-Length` is removed (not rewritten) because the decoded length
/// is trivially `body.len()` and consumers who care can read that off the
/// body directly; leaving a stale length would be worse than silence.
pub(crate) fn strip_after_decode(headers: Vec<(String, String)>) -> Vec<(String, String)> {
    headers
        .into_iter()
        .filter(|(k, _)| {
            !k.eq_ignore_ascii_case("content-encoding") && !k.eq_ignore_ascii_case("content-length")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use compcol::vec::compress_to_vec;

    fn gz(data: &[u8]) -> Vec<u8> {
        compress_to_vec::<Gzip>(data).expect("gzip encode")
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        compress_to_vec::<Zlib>(data).expect("zlib encode")
    }

    fn raw_deflate(data: &[u8]) -> Vec<u8> {
        compress_to_vec::<Deflate>(data).expect("deflate encode")
    }

    fn zstd(data: &[u8]) -> Vec<u8> {
        compress_to_vec::<Zstd>(data).expect("zstd encode")
    }

    fn brotli(data: &[u8]) -> Vec<u8> {
        compress_to_vec::<Brotli>(data).expect("brotli encode")
    }

    fn lzw(data: &[u8]) -> Vec<u8> {
        compress_to_vec::<Lzw>(data).expect("lzw encode")
    }

    #[test]
    fn decodes_gzip() {
        let out = decode_body(gz(b"hello world"), "gzip").unwrap();
        assert_eq!(out.body, b"hello world");
        assert!(out.decoded);
    }

    #[test]
    fn decodes_x_gzip_alias() {
        let out = decode_body(gz(b"abc"), "x-gzip").unwrap();
        assert_eq!(out.body, b"abc");
    }

    #[test]
    fn decodes_zlib_wrapped_deflate() {
        let out = decode_body(zlib(b"payload"), "deflate").unwrap();
        assert_eq!(out.body, b"payload");
    }

    #[test]
    fn decodes_raw_deflate_for_buggy_servers() {
        let out = decode_body(raw_deflate(b"payload"), "deflate").unwrap();
        assert_eq!(out.body, b"payload");
    }

    #[test]
    fn case_insensitive_token() {
        let out = decode_body(gz(b"x"), "GZIP").unwrap();
        assert_eq!(out.body, b"x");
    }

    #[test]
    fn identity_passes_through() {
        let out = decode_body(b"raw".to_vec(), "identity").unwrap();
        assert_eq!(out.body, b"raw");
        assert!(out.decoded); // identity is recognised, just a no-op
    }

    #[test]
    fn empty_encoding_is_noop() {
        let out = decode_body(b"raw".to_vec(), "").unwrap();
        assert_eq!(out.body, b"raw");
        assert!(!out.decoded);
    }

    #[test]
    fn nested_gzip_then_identity() {
        // Server says "Content-Encoding: identity, gzip" — applied in
        // order, so the body is identity(gzip(plain)) == gzip(plain).
        // Decoder walks right-to-left: first strip gzip, then identity.
        let out = decode_body(gz(b"nested"), "identity, gzip").unwrap();
        assert_eq!(out.body, b"nested");
    }

    #[test]
    fn unknown_outer_layer_returns_undecoded() {
        // An unrecognised outer layer (`snappy` is not a coding we decode)
        // means we can't reach the gzip layer underneath, so the body is
        // returned verbatim with nothing peeled.
        let payload = gz(b"inner");
        let out = decode_body(payload.clone(), "gzip, snappy").unwrap();
        assert_eq!(out.body, payload);
        assert!(!out.decoded);
    }

    #[test]
    fn decodes_zstd() {
        let out = decode_body(zstd(b"hello zstd world"), "zstd").unwrap();
        assert_eq!(out.body, b"hello zstd world");
        assert!(out.decoded);
    }

    #[test]
    fn decodes_brotli() {
        let out = decode_body(brotli(b"hello brotli world"), "br").unwrap();
        assert_eq!(out.body, b"hello brotli world");
        assert!(out.decoded);
    }

    #[test]
    fn zstd_token_is_case_insensitive() {
        let out = decode_body(zstd(b"Z"), "ZSTD").unwrap();
        assert_eq!(out.body, b"Z");
    }

    #[test]
    fn brotli_token_is_case_insensitive() {
        let out = decode_body(brotli(b"B"), "BR").unwrap();
        assert_eq!(out.body, b"B");
    }

    #[test]
    fn corrupt_zstd_reports_error() {
        let mut bad = zstd(b"valid payload");
        // Truncate the frame so the decoder can't reach the end-of-stream.
        bad.truncate(bad.len() / 2);
        let err = decode_body(bad, "zstd").unwrap_err();
        match err {
            Error::BadResponse(msg) => assert!(msg.contains("zstd"), "got {msg:?}"),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn decodes_compress() {
        let out = decode_body(lzw(b"hello compress world"), "compress").unwrap();
        assert_eq!(out.body, b"hello compress world");
        assert!(out.decoded);
    }

    #[test]
    fn compress_token_is_case_insensitive() {
        // Both the canonical token and the `x-compress` legacy alias, in
        // assorted casings, must route to the LZW decoder.
        let out = decode_body(lzw(b"C"), "COMPRESS").unwrap();
        assert_eq!(out.body, b"C");

        let out = decode_body(lzw(b"x"), "x-compress").unwrap();
        assert_eq!(out.body, b"x");

        let out = decode_body(lzw(b"X"), "X-Compress").unwrap();
        assert_eq!(out.body, b"X");
    }

    #[test]
    fn decodes_compress_across_code_width_boundary() {
        // A few KB of mixed repetitive + varied data forces the encoder past
        // the 9->10-bit code-width bump (and likely further), and across at
        // least one group-padding realignment — exercising the parts of the
        // `.Z` format a trivial decoder gets wrong. Round-trip must be exact.
        let mut payload = Vec::with_capacity(8192);
        for i in 0u32..2048 {
            payload.extend_from_slice(b"the quick brown fox ");
            payload.push((i & 0xFF) as u8);
            payload.push((i.wrapping_mul(31) & 0xFF) as u8);
        }
        let encoded = lzw(&payload);
        assert!(
            encoded.len() < payload.len(),
            "fixture should actually be compressed"
        );
        let out = decode_body(encoded, "compress").unwrap();
        assert_eq!(out.body, payload);
        assert!(out.decoded);
    }

    #[test]
    fn corrupt_compress_reports_error() {
        // Wrong magic bytes: not a `.Z` stream at all.
        let err = decode_body(b"not a dot-Z stream at all".to_vec(), "compress").unwrap_err();
        match err {
            Error::BadResponse(msg) => assert!(msg.contains("compress"), "got {msg:?}"),
            other => panic!("unexpected error variant: {other:?}"),
        }

        // Valid header + codestream chopped mid-stream must also surface as a
        // decode error rather than a silently-truncated body.
        let mut truncated = lzw(b"a reasonably long compress payload to truncate hard");
        truncated.truncate(truncated.len() / 2 + 1);
        // Truncation may or may not error depending on where the cut lands;
        // if it decodes, it must not equal the original (data was lost).
        match decode_body(truncated, "compress") {
            Ok(out) => assert_ne!(
                out.body, b"a reasonably long compress payload to truncate hard",
                "truncated stream should not reproduce the full original"
            ),
            Err(Error::BadResponse(msg)) => assert!(msg.contains("compress"), "got {msg:?}"),
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn compress_bomb_rejected_by_budget_cap() {
        // A large zero-fill compresses to a tiny `.Z` frame but expands past
        // MAX_BODY_BYTES; the cumulative budget must reject it instead of
        // materialising the full expansion.
        let huge = vec![0u8; MAX_BODY_BYTES + (1 << 20)];
        let bomb = lzw(&huge);
        assert!(
            bomb.len() < huge.len(),
            "fixture should actually be compressed"
        );
        let err = decode_body(bomb, "compress").unwrap_err();
        match err {
            Error::BadResponse(msg) => assert!(msg.contains("compress"), "got {msg:?}"),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn corrupt_brotli_reports_error() {
        // A valid brotli frame chopped in half mid-stream must surface as a
        // decode error rather than silently producing a truncated body.
        let mut bad = brotli(b"a reasonably long brotli payload to truncate");
        bad.truncate(bad.len() / 2);
        let err = decode_body(bad, "br").unwrap_err();
        match err {
            Error::BadResponse(msg) => assert!(msg.contains("brotli"), "got {msg:?}"),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn zstd_then_gzip_share_one_budget() {
        // Mixed stack within the layer cap: gzip(zstd(plain)), labelled
        // "zstd, gzip" (applied in order zstd-then-gzip, peeled right-to-left).
        let inner = zstd(b"mixed payload");
        let outer = gz(&inner);
        let out = decode_body(outer, "zstd, gzip").unwrap();
        assert_eq!(out.body, b"mixed payload");
        assert!(out.decoded);
    }

    #[test]
    fn zstd_bomb_rejected_by_budget_cap() {
        // Compress far more than MAX_BODY_BYTES of highly-compressible input;
        // the cumulative budget must reject it instead of materialising the
        // full expansion. The compressed frame itself is tiny.
        let huge = vec![0u8; MAX_BODY_BYTES + (1 << 20)];
        let bomb = zstd(&huge);
        assert!(
            bomb.len() < huge.len(),
            "fixture should actually be compressed"
        );
        let err = decode_body(bomb, "zstd").unwrap_err();
        match err {
            Error::BadResponse(msg) => assert!(msg.contains("zstd"), "got {msg:?}"),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn corrupt_gzip_reports_error() {
        let mut bad = gz(b"valid");
        bad.pop(); // chop the trailing CRC32 byte
        bad.pop();
        let err = decode_body(bad, "gzip").unwrap_err();
        match err {
            Error::BadResponse(msg) => assert!(msg.contains("gzip"), "got {msg:?}"),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn rejects_too_many_encoding_layers() {
        // Four stacked encodings exceed MAX_ENCODING_LAYERS (3). The body
        // contents don't matter — the chain length is rejected up front.
        let err = decode_body(gz(b"x"), "gzip, gzip, gzip, gzip").unwrap_err();
        match err {
            Error::BadResponse(msg) => {
                assert!(msg.contains("Content-Encoding layers"), "got {msg:?}")
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn accepts_max_encoding_layers() {
        // Exactly MAX_ENCODING_LAYERS gzip wrappers must still decode. Build
        // gzip(gzip(gzip(plain))) and label it with three gzip tokens.
        let inner = gz(b"deep");
        let mid = gz(&inner);
        let outer = gz(&mid);
        let out = decode_body(outer, "gzip, gzip, gzip").unwrap();
        assert_eq!(out.body, b"deep");
        assert!(out.decoded);
    }

    #[test]
    fn nested_layers_share_one_budget() {
        // Two stacked layers (within the cap) decode to the original; this
        // exercises the cumulative-budget path without tripping the limit.
        let inner = gz(b"payload");
        let outer = gz(&inner);
        let out = decode_body(outer, "gzip, gzip").unwrap();
        assert_eq!(out.body, b"payload");
    }

    #[test]
    fn strip_after_decode_removes_both_headers() {
        let h = vec![
            ("Content-Type".into(), "text/html".into()),
            ("Content-Encoding".into(), "gzip".into()),
            ("Content-Length".into(), "123".into()),
            ("Server".into(), "test".into()),
        ];
        let out = strip_after_decode(h);
        let names: Vec<&str> = out.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(names, ["Content-Type", "Server"]);
    }

    #[test]
    fn single_streamable_layer_matches_only_single_known_codecs() {
        assert_eq!(single_streamable_layer("gzip"), Some(StreamCodec::Gzip));
        assert_eq!(single_streamable_layer(" X-Gzip "), Some(StreamCodec::Gzip));
        assert_eq!(single_streamable_layer("zstd"), Some(StreamCodec::Zstd));
        assert_eq!(single_streamable_layer("br"), Some(StreamCodec::Brotli));
        // deflate is excluded (zlib/raw ambiguity needs a buffered retry).
        assert_eq!(single_streamable_layer("deflate"), None);
        // compress, identity, unknown, and multi-layer are not streamable.
        assert_eq!(single_streamable_layer("compress"), None);
        assert_eq!(single_streamable_layer("identity"), None);
        assert_eq!(single_streamable_layer("snappy"), None);
        assert_eq!(single_streamable_layer("gzip, br"), None);
    }

    #[test]
    fn stream_decode_roundtrips_each_codec() {
        let payload = b"the quick brown fox jumps over the lazy dog, twice over.";
        for (codec, blob) in [
            (StreamCodec::Gzip, gz(payload)),
            (StreamCodec::Zstd, zstd(payload)),
            (StreamCodec::Brotli, brotli(payload)),
        ] {
            let mut out = Vec::new();
            let n = stream_decode(
                blob.as_slice(),
                codec,
                &mut out,
                crate::http::MAX_BODY_BYTES as u64,
            )
            .expect("stream decode");
            assert_eq!(out, payload, "{codec:?}");
            assert_eq!(n, payload.len() as u64, "{codec:?}");
        }
    }

    #[test]
    fn stream_decode_enforces_budget() {
        // A tiny gzip frame that expands past a 4-byte budget must error rather
        // than write an unbounded amount (decompression-bomb guard).
        let blob = gz(&[b'A'; 4096]);
        let mut out = Vec::new();
        let err = stream_decode(blob.as_slice(), StreamCodec::Gzip, &mut out, 4);
        assert!(err.is_err(), "decode past budget must fail");
    }
}

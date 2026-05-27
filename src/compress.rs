//! Response-body decompression for `Content-Encoding: gzip | deflate`.
//!
//! `Accept-Encoding: gzip, deflate` is offered by default on every HTTP
//! request rsurl makes; this module is the matching decode side. It is the
//! moral equivalent of curl's `--compressed`, except always-on — without
//! it, a vanilla GET against any modern HTTP server returns a body that
//! looks like binary noise.
//!
//! Scope is deliberately narrow:
//!
//! * **gzip** (RFC 1952) and **deflate** (RFC 1951) are decoded.
//!   `x-gzip` is accepted as a gzip alias because some legacy servers
//!   still emit it.
//! * **identity** is a no-op pass-through.
//! * **brotli**, **zstd**, and **compress** are not implemented; a body
//!   labelled with one of those is returned verbatim and the encoding
//!   token is reported so the caller can decide what to do (today, we
//!   leave the header in place and ship the bytes through unchanged —
//!   matching what curl does when it doesn't know an encoding).
//!
//! `Content-Encoding` is a list. RFC 9110 §8.4.1 says encodings are applied
//! in the order listed, so decoding walks the list **right-to-left**.

use std::io::Read;

use flate2::read::{GzDecoder, ZlibDecoder};

use crate::error::{Error, Result};
use crate::http::MAX_BODY_BYTES;

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

    let mut current = body;
    let mut peeled = false;
    for token in layers.iter().rev() {
        match Layer::parse(token) {
            Some(Layer::Identity) => {
                // No-op; counts as recognised so the loop keeps going if
                // there are inner layers we can still strip.
                peeled = true;
            }
            Some(Layer::Gzip) => {
                current = gunzip(&current)?;
                peeled = true;
            }
            Some(Layer::Deflate) => {
                current = inflate_zlib(&current)?;
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
    Identity,
}

impl Layer {
    fn parse(token: &str) -> Option<Self> {
        // Tokens are case-insensitive per RFC 9110.
        if token.eq_ignore_ascii_case("gzip") || token.eq_ignore_ascii_case("x-gzip") {
            Some(Layer::Gzip)
        } else if token.eq_ignore_ascii_case("deflate") {
            Some(Layer::Deflate)
        } else if token.eq_ignore_ascii_case("identity") {
            Some(Layer::Identity)
        } else {
            None
        }
    }
}

fn gunzip(src: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(src.len().saturating_mul(3));
    GzDecoder::new(src)
        .take(MAX_BODY_BYTES as u64)
        .read_to_end(&mut out)
        .map_err(|e| Error::BadResponse(format!("gzip decode failed: {e}")))?;
    Ok(out)
}

/// Decode a `deflate`-encoded body. RFC 9110 says HTTP `deflate` is **zlib**
/// (RFC 1950) wrapping raw deflate (RFC 1951), but many real-world servers
/// emit raw deflate without the zlib header. Try the zlib framing first;
/// if it fails, retry as raw deflate so we interoperate with both camps.
fn inflate_zlib(src: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(src.len().saturating_mul(3));
    let zlib_err = match ZlibDecoder::new(src)
        .take(MAX_BODY_BYTES as u64)
        .read_to_end(&mut out)
    {
        Ok(_) => return Ok(out),
        Err(e) => e,
    };
    out.clear();
    flate2::read::DeflateDecoder::new(src)
        .take(MAX_BODY_BYTES as u64)
        .read_to_end(&mut out)
        .map_err(|_| Error::BadResponse(format!("deflate decode failed: {zlib_err}")))?;
    Ok(out)
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
    use flate2::write::{DeflateEncoder, GzEncoder, ZlibEncoder};
    use flate2::Compression;
    use std::io::Write;

    fn gz(data: &[u8]) -> Vec<u8> {
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn raw_deflate(data: &[u8]) -> Vec<u8> {
        let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
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
        // br first means we can't reach the gzip layer underneath.
        let payload = gz(b"inner");
        let out = decode_body(payload.clone(), "gzip, br").unwrap();
        assert_eq!(out.body, payload);
        assert!(!out.decoded);
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
}

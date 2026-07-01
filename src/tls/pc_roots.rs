//! Purecrypto root-store loading, available regardless of the active TLS
//! backend.
//!
//! HTTP/3 (`src/http3.rs`) is built on `purecrypto::quic`, which in turn is
//! built on `purecrypto::tls` — so HTTP/3 always needs a
//! `purecrypto::tls::RootCertStore` even when the `rustls-tls` feature is
//! active. This module keeps the purecrypto-flavoured trust anchors
//! ([`embedded_roots`]) unconditionally compiled so HTTP/3 has a source of
//! trust regardless of which TLS backend is selected.
//!
//! The `purecrypto-tls` backend re-exports the loaders here as its public API
//! surface; nothing else uses them.

use std::sync::OnceLock;

use purecrypto::tls::RootCertStore;

use crate::error::{Error, Result};

/// The default trust anchors when the caller supplies neither `--cacert` nor
/// `--capath`: the embedded [`cacrt`](https://crates.io/crates/cacrt) CA bundle
/// (curated Mozilla-derived roots as static DER), loaded once on first use and
/// cached. Deliberately does NOT read the OS trust store, so verification works
/// identically on every platform — no `/etc/ssl/...` needed (which is why the
/// old system-path loader failed on Windows).
pub(crate) fn embedded_roots() -> RootCertStore {
    static CACHE: OnceLock<RootCertStore> = OnceLock::new();
    CACHE
        .get_or_init(RootCertStore::with_embedded_roots)
        .clone()
}

/// Load CA certificates from a user-supplied PEM bundle (curl's
/// `--cacert <file>`). Empty bundle is an error.
///
/// Only the purecrypto TLS backend wires this in today (the rustls backend
/// has its own loader); kept always-compiled and `allow(dead_code)` so any
/// future HTTP/3-side `--cacert` plumbing can use it without surgery.
#[allow(dead_code)]
pub(crate) fn load_from_file(path: &str) -> Result<RootCertStore> {
    let pem = std::fs::read_to_string(path).map_err(Error::Io)?;
    parse_into_store(&pem, path)
}

/// Add every CA certificate found in the files under `dir` to `roots` (curl's
/// `--capath <dir>`). Each regular file in the directory is read as PEM and any
/// `CERTIFICATE` blocks it contains are added; non-PEM / unreadable files are
/// skipped. An empty directory (no usable certs found anywhere) is an error so
/// the user knows the flag had no effect.
///
/// Only the purecrypto TLS backend wires this in (the rustls backend has its
/// own dir loader); kept always-compiled (HTTP/3 is bound to purecrypto) and
/// `allow(dead_code)` so the rustls-only build doesn't warn.
#[allow(dead_code)]
pub(crate) fn add_from_dir(roots: &mut RootCertStore, dir: &str) -> Result<()> {
    let entries = std::fs::read_dir(dir).map_err(Error::Io)?;
    let mut loaded = 0usize;
    for entry in entries {
        let entry = entry.map_err(Error::Io)?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Ok(pem) = std::fs::read_to_string(&path) else {
            continue; // binary/unreadable file in the dir — skip like curl/OpenSSL
        };
        for block in pem_blocks(&pem) {
            if roots.add_pem(&block).is_ok() {
                loaded += 1;
            }
        }
    }
    if loaded == 0 {
        return Err(Error::BadResponse(format!(
            "--capath {dir}: no usable CA certificates found"
        )));
    }
    Ok(())
}

fn parse_into_store(pem: &str, path: &str) -> Result<RootCertStore> {
    let mut roots = RootCertStore::new();
    let mut loaded = 0usize;
    for block in pem_blocks(pem) {
        if roots.add_pem(&block).is_ok() {
            loaded += 1;
        }
    }
    if loaded == 0 {
        return Err(Error::BadResponse(format!(
            "no usable CA certificates parsed from {path}"
        )));
    }
    Ok(roots)
}

/// Yield each `-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----`
/// block from a PEM string as its own string.
pub(crate) fn pem_blocks(pem: &str) -> Vec<String> {
    pem_blocks_labelled(pem, "CERTIFICATE")
}

/// Like [`pem_blocks`] but for an arbitrary RFC 7468 `label` (e.g. `X509 CRL`).
/// Yields each `-----BEGIN <label>-----...-----END <label>-----` block as its
/// own string, tolerating junk between blocks and unterminated/stray headers.
pub(crate) fn pem_blocks_labelled(pem: &str, label: &str) -> Vec<String> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let (begin, end): (&str, &str) = (&begin, &end);
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(start) = rest.find(begin) {
        let after_begin = &rest[start..];
        // Body of this candidate block is everything past its own header.
        let body = &after_begin[begin.len()..];
        let Some(end_rel) = body.find(end) else {
            // This BEGIN has no matching END anywhere after it. Don't abort the
            // whole scan and discard every later block — skip just past this
            // BEGIN and keep looking for the next well-formed block.
            rest = body;
            continue;
        };
        // If another BEGIN appears before that END, this BEGIN is unterminated
        // (its body is garbage and the END belongs to a later block). Skip past
        // this BEGIN and re-scan, so the later block isn't swallowed whole.
        if let Some(next_begin) = body.find(begin) {
            if next_begin < end_rel {
                rest = body;
                continue;
            }
        }
        // `add_pem` remains the authority on what's actually trusted; we only
        // slice candidate blocks here.
        let end_abs = start + begin.len() + end_rel + end.len();
        out.push(rest[start..end_abs].to_string());
        rest = &rest[end_abs..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_roots_are_populated() {
        // The default trust store is the embedded cacrt bundle (a full curated
        // root set), available on every platform without reading the OS store.
        assert!(
            embedded_roots().len() > 100,
            "embedded CA bundle should be populated"
        );
    }

    #[test]
    fn pem_blocks_splits() {
        let pem = "junk\n\
            -----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n\
            noise\n\
            -----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n";
        let blocks = pem_blocks(pem);
        assert_eq!(blocks.len(), 2);
        assert!(blocks[0].contains("AAA"));
        assert!(blocks[1].contains("BBB"));
    }

    #[test]
    fn pem_blocks_skips_unterminated_begin() {
        // [valid][unterminated BEGIN][valid] must still yield BOTH valid blocks
        // rather than dropping everything after the malformed one.
        let pem = "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n\
            -----BEGIN CERTIFICATE-----\nTRUNCATED never terminated\n\
            -----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n";
        let blocks = pem_blocks(pem);
        assert_eq!(blocks.len(), 2);
        assert!(blocks[0].contains("AAA"));
        assert!(blocks[1].contains("BBB"));
        // The unterminated block's body must not leak into a kept block.
        assert!(!blocks[0].contains("TRUNCATED"));
        assert!(!blocks[1].contains("TRUNCATED"));
    }

    #[test]
    fn pem_blocks_stray_end_does_not_corrupt() {
        // A stray END before any real block must not be mistaken for part of a
        // block; the following well-formed block still parses cleanly.
        let pem = "-----END CERTIFICATE-----\njunk\n\
            -----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n";
        let blocks = pem_blocks(pem);
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].contains("AAA"));
        assert!(blocks[0].starts_with("-----BEGIN CERTIFICATE-----"));
    }
}

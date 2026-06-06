//! Purecrypto root-store loading, available regardless of the active TLS
//! backend.
//!
//! HTTP/3 (`src/http3.rs`) is built on `purecrypto::quic`, which in turn is
//! built on `purecrypto::tls` — so HTTP/3 always needs a
//! `purecrypto::tls::RootCertStore`, even when the `rustls-tls` feature has
//! redirected [`crate::tls::load_system_roots`] to rustls. This module keeps
//! the purecrypto-flavoured loader unconditionally compiled so HTTP/3 has a
//! source of trust anchors regardless of which TLS backend is active.
//!
//! The `purecrypto-tls` backend just re-exports the two `load_*` functions
//! here as its public API surface; nothing else uses them.

use std::io;

use purecrypto::tls::RootCertStore;

use crate::error::{Error, Result};

/// Search paths for a system-wide CA bundle, in order of preference.
/// Mirrors what curl/OpenSSL look at on common Unix distros.
pub(crate) const SYSTEM_CA_PATHS: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu/Gentoo
    "/etc/pki/tls/certs/ca-bundle.crt",   // Fedora/RHEL
    "/etc/ssl/cert.pem",                  // Alpine, OpenBSD, macOS (via brew)
    "/etc/ssl/ca-bundle.pem",             // openSUSE
    "/etc/ca-certificates/extracted/tls-ca-bundle.pem", // Arch
];

/// Load every CA found in the first existing bundle on disk into a
/// `purecrypto::tls::RootCertStore`. PEM blocks that purecrypto cannot
/// parse (e.g. unsupported key types) are silently skipped, matching what
/// other pure-Rust TLS stacks do.
pub(crate) fn load_system_roots() -> Result<RootCertStore> {
    for path in SYSTEM_CA_PATHS {
        let pem = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(Error::Io(e)),
        };
        return parse_into_store(&pem, path);
    }
    Err(Error::BadResponse(
        "no system CA bundle found; tried common Unix paths".into(),
    ))
}

/// Load CA certificates from a user-supplied PEM bundle (curl's
/// `--cacert <file>`). Same parser as [`load_system_roots`]; empty bundle
/// is an error.
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
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(start) = rest.find(BEGIN) {
        let after_begin = &rest[start..];
        // Body of this candidate block is everything past its own header.
        let body = &after_begin[BEGIN.len()..];
        let Some(end_rel) = body.find(END) else {
            // This BEGIN has no matching END anywhere after it. Don't abort the
            // whole scan and discard every later block — skip just past this
            // BEGIN and keep looking for the next well-formed block.
            rest = body;
            continue;
        };
        // If another BEGIN appears before that END, this BEGIN is unterminated
        // (its body is garbage and the END belongs to a later block). Skip past
        // this BEGIN and re-scan, so the later block isn't swallowed whole.
        if let Some(next_begin) = body.find(BEGIN) {
            if next_begin < end_rel {
                rest = body;
                continue;
            }
        }
        // `add_pem` remains the authority on what's actually trusted; we only
        // slice candidate blocks here.
        let end_abs = start + BEGIN.len() + end_rel + END.len();
        out.push(rest[start..end_abs].to_string());
        rest = &rest[end_abs..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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

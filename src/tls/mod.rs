//! TLS support, with a pluggable backend.
//!
//! Two backends are available via Cargo features:
//!
//! * `purecrypto-tls` (default) — `purecrypto::tls`, the pure-Rust stack
//!   that ships with the rest of `rsurl`'s crypto.
//! * `rustls-tls` — rustls 0.23 with the `ring` crypto provider.
//!
//! When both features are enabled, `rustls-tls` wins. This makes
//! `cargo build --features rustls-tls` (without `--no-default-features`)
//! still do what users expect, instead of failing on a feature clash.
//!
//! The public surface (`TlsStream`, `TlsOpts`, `connect_over*`,
//! `load_*_roots`, and the methods called on `TlsStream`) is identical
//! between backends — [`ProtocolVersion`] is the one type that had to be
//! unified into a backend-neutral enum so callers don't link against
//! either crypto crate.
//!
//! Note: HTTP/3 (`src/http3.rs`) always uses purecrypto's TLS, regardless
//! of this feature, because it is built on `purecrypto::quic` which is
//! itself built on `purecrypto::tls`.

mod common;
pub use common::{CertVerdict, CertVerify, ProtocolVersion, VerifyCallback};

// Purecrypto-flavoured root-store loaders, always compiled because HTTP/3
// is bound to purecrypto's QUIC stack regardless of which TLS backend is
// active. The active backend's `load_*_roots` functions may or may not use
// these — the purecrypto backend re-exports them as its public API, the
// rustls backend has its own.
pub(crate) mod pc_roots;

// Backend-neutral client-auth (`-E`/`--key`/`--pass`) and public-key pinning
// (`--pinnedpubkey`) helpers. The SPKI/pin logic uses purecrypto's x509
// parser, which is always linked regardless of the active TLS backend.
pub(crate) mod client_auth;
pub(crate) use client_auth::{cipher_names_to_ids, parse_pinned_pubkey};

// curl-flag TLS settings (paths, pin specs) → backend `TlsOpts`, shared by
// HTTP and the non-HTTP protocols.
#[cfg(any(feature = "purecrypto-tls", feature = "rustls-tls"))]
mod settings;
#[cfg(any(feature = "purecrypto-tls", feature = "rustls-tls"))]
pub(crate) use settings::TlsSettings;

#[cfg(feature = "rustls-tls")]
mod rustls;
#[cfg(feature = "rustls-tls")]
use rustls as backend;

#[cfg(all(feature = "purecrypto-tls", not(feature = "rustls-tls")))]
mod purecrypto;
#[cfg(all(feature = "purecrypto-tls", not(feature = "rustls-tls")))]
use purecrypto as backend;

#[cfg(not(any(feature = "purecrypto-tls", feature = "rustls-tls")))]
compile_error!(
    "rsurl: no TLS backend enabled. Enable either `purecrypto-tls` \
     (default) or `rustls-tls`."
);

// Gated on a backend being present so the no-backend build prints only the
// compile_error! above, not a confusing follow-on "unresolved import".
#[cfg(any(feature = "purecrypto-tls", feature = "rustls-tls"))]
pub use backend::{
    connect_over, connect_over_tls, connect_over_with_alpn, load_roots_from_dir,
    load_roots_from_file, RootCertStore, TlsConn, TlsOpts, TlsStream,
};

/// The TLS reference identity for a URL host: an IPv6 literal loses its URL
/// brackets and zone ID (`[fe80::1%25en0]` → `fe80::1`) so both backends parse
/// it as an IP (matched against iPAddress SANs, and — on rustls — never sent as
/// SNI); DNS names pass through unchanged.
pub(crate) fn server_name(host: &str) -> &str {
    let h = crate::url::unbracket(host);
    match h.find('%') {
        Some(i) if h.contains(':') => &h[..i],
        _ => h,
    }
}

/// CVE-2011-0411-class STARTTLS plaintext-injection guard, shared by the mail
/// protocols (imap/smtp/pop3). After the server's STARTTLS/STLS `OK` and
/// *before* the TLS handshake ([`connect_over`]), the client's read buffer must
/// be empty. Any bytes already buffered were pipelined by a MITM as plaintext
/// in the same flight; trusting them as server responses once TLS is up is the
/// vulnerability, and discarding them is also unsafe — so we abort. The reader
/// buffer type differs per protocol, so the caller passes its emptiness as
/// `buffer_empty`; `proto` names the scheme for the error.
pub(crate) fn reject_pipelined_plaintext(
    proto: &str,
    buffer_empty: bool,
) -> crate::error::Result<()> {
    if buffer_empty {
        Ok(())
    } else {
        Err(crate::error::Error::BadResponse(format!(
            "{proto}: server pipelined plaintext before the TLS handshake (STARTTLS injection)"
        )))
    }
}

/// Build a socket-free sans-IO TLS client engine for the active backend,
/// configured from `sni` and `opts`. The blocking/async drivers drive the
/// returned engine via [`crate::proto::tls::TlsClient`]; this is the
/// connect-construction half of the sans-IO request stack, used by
/// `http::run_https_core`. Post-handshake checks (verify callback, public-key
/// pinning) remain the driver's responsibility — they need the peer chain,
/// available only after the handshake (see `http::verify_core_peer_certificates`).
/// Returns the active backend's concrete engine type (exactly one backend
/// compiles, so this is a single type per build).
#[cfg(feature = "rustls-tls")]
pub(crate) fn build_client_engine(
    sni: &str,
    opts: &mut TlsOpts,
) -> crate::error::Result<crate::proto::tls::RustlsEngine> {
    Ok(crate::proto::tls::RustlsEngine::new(
        backend::build_client_conn(sni, opts)?,
    ))
}

#[cfg(all(feature = "purecrypto-tls", not(feature = "rustls-tls")))]
pub(crate) fn build_client_engine(
    sni: &str,
    opts: &mut TlsOpts,
) -> crate::error::Result<crate::proto::tls::PurecryptoEngine> {
    crate::proto::tls::PurecryptoEngine::new(backend::build_client_conn(sni, opts)?)
}

/// The concrete [`TlsEngine`](crate::proto::tls::TlsEngine) type
/// [`build_client_engine`] returns for the active backend — exactly one backend
/// compiles per build, so this is a single type. Lets callers that must *name*
/// the engine (e.g. the async TLS stream behind `wss://`) avoid a generic
/// parameter or a `Box<dyn TlsEngine>`.
#[cfg(feature = "rustls-tls")]
pub(crate) type ClientEngine = crate::proto::tls::RustlsEngine;
#[cfg(all(feature = "purecrypto-tls", not(feature = "rustls-tls")))]
pub(crate) type ClientEngine = crate::proto::tls::PurecryptoEngine;

#[cfg(test)]
mod tests {
    use super::{reject_pipelined_plaintext, server_name};
    use crate::error::Error;

    #[test]
    fn server_name_unbrackets_ipv6_and_drops_zone() {
        assert_eq!(server_name("[::1]"), "::1");
        assert_eq!(server_name("[fe80::1%25en0]"), "fe80::1");
        assert_eq!(server_name("127.0.0.1"), "127.0.0.1");
        assert_eq!(server_name("example.com"), "example.com");
    }

    /// A URL-form IPv6 host (`[::1]`) must build a client engine on the active
    /// backend — rustls used to reject it as an invalid DNS name, and
    /// purecrypto could never match it against an iPAddress SAN.
    #[test]
    fn client_engine_accepts_bracketed_ipv6_host() {
        for verify in [true, false] {
            let mut opts = super::TlsOpts::verifying();
            opts.verify = verify;
            assert!(
                super::build_client_engine("[::1]", &mut opts).is_ok(),
                "verify={verify}"
            );
        }
    }

    #[test]
    fn pipelined_guard_passes_on_empty_buffer() {
        assert!(reject_pipelined_plaintext("imap", true).is_ok());
    }

    #[test]
    fn pipelined_guard_rejects_buffered_plaintext() {
        match reject_pipelined_plaintext("pop3", false) {
            Err(Error::BadResponse(m)) => {
                assert!(m.contains("pop3"));
                assert!(m.contains("STARTTLS injection"));
            }
            other => panic!("expected BadResponse, got {other:?}"),
        }
    }
}

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
    load_roots_from_file, load_system_roots, RootCertStore, TlsConn, TlsOpts, TlsStream,
};

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
    Ok(crate::proto::tls::RustlsEngine(backend::build_client_conn(
        sni, opts,
    )?))
}

#[cfg(all(feature = "purecrypto-tls", not(feature = "rustls-tls")))]
pub(crate) fn build_client_engine(
    sni: &str,
    opts: &mut TlsOpts,
) -> crate::error::Result<crate::proto::tls::PurecryptoEngine> {
    crate::proto::tls::PurecryptoEngine::new(backend::build_client_conn(sni, opts)?)
}

//! Types shared by every TLS backend (currently `purecrypto` and `rustls`).
//!
//! Keeping a small backend-neutral surface here means consumer code never
//! has to name a crate-specific TLS type, so flipping the `rustls-tls`
//! feature switches the implementation transparently.

/// Negotiated TLS protocol version, mapped from whichever backend ran the
/// handshake. The `Debug` derive prints `TLSv1_3` / `TLSv1_2`, which is the
/// form the verbose trace in `src/http.rs` already shows via `{v:?}`.
///
/// `Other(u16)` is used for anything outside the two TLS 1.x versions we
/// currently advertise — its `u16` is the on-wire two-byte version code
/// (e.g. `0x0301` for TLS 1.0) so a diagnostic still has something to print.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[allow(non_camel_case_types)]
pub enum ProtocolVersion {
    TLSv1_2,
    TLSv1_3,
    Other(u16),
}

/// The peer certificate chain presented at handshake, handed to a caller's
/// [`VerifyCallback`] so it can make the trust decision itself (the browser
/// security model: rsurl moves bytes, the embedder owns trust).
pub struct CertVerify<'a> {
    /// The SNI / expected server name for this connection.
    pub server_name: &'a str,
    /// Peer chain in wire order (leaf first), each entry DER-encoded.
    pub chain_der: &'a [Vec<u8>],
}

/// A caller's verdict on a presented certificate chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertVerdict {
    /// Accept the chain and proceed with the connection.
    Accept,
    /// Reject the chain; the connection fails with a certificate error.
    Reject,
}

/// A caller-supplied certificate-validation hook. When set on [`super::TlsOpts`]
/// it becomes the **sole** trust authority: rsurl performs the handshake without
/// its own chain validation and defers the accept/reject decision to this
/// callback, passing the full peer chain. This lets `argus-security` own trust
/// (custom roots, error→override UX) instead of rsurl.
///
/// A cheap clonable handle (an `Arc` inside) with an opaque `Debug` so it can
/// live on `Request`/`TlsOpts` without those needing to format the closure.
#[derive(Clone)]
pub struct VerifyCallback(std::sync::Arc<dyn Fn(&CertVerify<'_>) -> CertVerdict + Send + Sync>);

impl VerifyCallback {
    /// Wrap a closure as a verify callback.
    pub fn new(f: impl Fn(&CertVerify<'_>) -> CertVerdict + Send + Sync + 'static) -> Self {
        VerifyCallback(std::sync::Arc::new(f))
    }

    /// Invoke the callback on a presented chain.
    pub fn call(&self, v: &CertVerify<'_>) -> CertVerdict {
        (self.0)(v)
    }
}

impl std::fmt::Debug for VerifyCallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifyCallback(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_callback_invokes_closure_with_chain() {
        let leaf = vec![1u8, 2, 3];
        let chain = vec![leaf.clone()];
        // Accept only when the leaf matches and the server name is as expected.
        let cb = VerifyCallback::new(|v: &CertVerify<'_>| {
            if v.server_name == "example.com" && v.chain_der.first() == Some(&vec![1u8, 2, 3]) {
                CertVerdict::Accept
            } else {
                CertVerdict::Reject
            }
        });
        assert_eq!(
            cb.call(&CertVerify {
                server_name: "example.com",
                chain_der: &chain,
            }),
            CertVerdict::Accept
        );
        assert_eq!(
            cb.call(&CertVerify {
                server_name: "evil.com",
                chain_der: &chain,
            }),
            CertVerdict::Reject
        );
        // Debug is opaque (doesn't try to format the closure).
        assert_eq!(format!("{cb:?}"), "VerifyCallback(..)");
    }
}

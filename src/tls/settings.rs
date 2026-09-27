//! Backend-neutral TLS *settings*: the curl-flag view of TLS configuration
//! (file paths, pin specs, cipher lists), as carried by an HTTP
//! [`Request`](crate::Request) and by the non-HTTP protocols' `NetConfig`.
//!
//! [`TlsSettings::to_opts`] is the single place these settings become a
//! backend [`TlsOpts`] (reading the CA / cert / key / CRL files and parsing
//! pins and cipher names), so HTTP and ftps/imaps/smtps/... can't drift apart.

use super::{ProtocolVersion, TlsOpts, VerifyCallback};
use crate::error::{Error, Result};

/// TLS configuration as set by curl-style options. `Default` verifies against
/// the system trust store with no client certificate, pins, CRL or cipher
/// restriction — the same as [`TlsOpts::verifying`].
#[derive(Clone)]
pub(crate) struct TlsSettings {
    /// Verify the server chain and hostname (cleared by `-k`/`--insecure`).
    pub(crate) verify: bool,
    /// `--cacert`: a CA bundle replacing the system roots.
    pub(crate) ca_bundle: Option<String>,
    /// `--capath`: a directory of extra CAs added on top of the base roots.
    pub(crate) ca_path: Option<String>,
    /// `-E`/`--cert`: client certificate file.
    pub(crate) client_cert: Option<String>,
    /// `--key`: client key file (else read from the cert file).
    pub(crate) client_key: Option<String>,
    /// `--pass`: passphrase for an encrypted client key.
    pub(crate) client_key_pass: Option<String>,
    /// `--cert-type DER`.
    pub(crate) cert_is_der: bool,
    /// `--key-type DER`.
    pub(crate) key_is_der: bool,
    /// `--pinnedpubkey` spec (`sha256//BASE64[;...]`).
    pub(crate) pinned_pubkey: Option<String>,
    /// `--crlfile`.
    pub(crate) crl_file: Option<String>,
    /// `--ciphers` (TLS ≤ 1.2 names).
    pub(crate) ciphers: Option<String>,
    /// `--tls13-ciphers`.
    pub(crate) tls13_ciphers: Option<String>,
    /// `--tlsv1.x` floor.
    pub(crate) min_version: Option<ProtocolVersion>,
    /// `--tls-max` ceiling.
    pub(crate) max_version: Option<ProtocolVersion>,
    /// Caller-owned certificate-validation hook (replaces built-in checks).
    pub(crate) verify_callback: Option<VerifyCallback>,
}

impl Default for TlsSettings {
    fn default() -> Self {
        TlsSettings {
            verify: true,
            ca_bundle: None,
            ca_path: None,
            client_cert: None,
            client_key: None,
            client_key_pass: None,
            cert_is_der: false,
            key_is_der: false,
            pinned_pubkey: None,
            crl_file: None,
            ciphers: None,
            tls13_ciphers: None,
            min_version: None,
            max_version: None,
            verify_callback: None,
        }
    }
}

impl std::fmt::Debug for TlsSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The key passphrase is redacted so a `{:?}` of a request can't leak it.
        f.debug_struct("TlsSettings")
            .field("verify", &self.verify)
            .field("ca_bundle", &self.ca_bundle)
            .field("ca_path", &self.ca_path)
            .field("client_cert", &self.client_cert)
            .field("client_key", &self.client_key)
            .field(
                "client_key_pass",
                &self.client_key_pass.as_ref().map(|_| "<redacted>"),
            )
            .field("cert_is_der", &self.cert_is_der)
            .field("key_is_der", &self.key_is_der)
            .field("pinned_pubkey", &self.pinned_pubkey)
            .field("crl_file", &self.crl_file)
            .field("ciphers", &self.ciphers)
            .field("tls13_ciphers", &self.tls13_ciphers)
            .field("min_version", &self.min_version)
            .field("max_version", &self.max_version)
            .field("verify_callback", &self.verify_callback)
            .finish()
    }
}

/// Builder methods for the TLS session *to an `https://` proxy* (curl's
/// `--proxy-*` TLS family), shared by `Client` and `Request`; both keep these
/// settings in a `proxy_tls` field, independent of the origin's TLS settings.
macro_rules! proxy_tls_builder_methods {
    () => {
        /// Verify the certificate of an `https://` proxy (default `true`).
        /// `false` is curl's `--proxy-insecure`. Independent of
        /// [`verify_tls`](Self::verify_tls): `-k` does not relax proxy
        /// verification, and this does not relax origin verification.
        pub fn proxy_verify_tls(mut self, on: bool) -> Self {
            self.proxy_tls.verify = on;
            self
        }

        /// Trust the CA bundle (PEM) at `path` instead of the system roots
        /// when verifying an `https://` proxy (curl `--proxy-cacert`).
        pub fn proxy_ca_bundle(mut self, path: &str) -> Self {
            self.proxy_tls.ca_bundle = Some(path.to_string());
            self
        }

        /// Additionally trust every CA certificate in `dir` when verifying an
        /// `https://` proxy (curl `--proxy-capath`).
        pub fn proxy_ca_path(mut self, dir: &str) -> Self {
            self.proxy_tls.ca_path = Some(dir.to_string());
            self
        }

        /// Check the `https://` proxy's chain against the CRL in `path` (curl
        /// `--proxy-crlfile`).
        pub fn proxy_crl_file(mut self, path: &str) -> Self {
            self.proxy_tls.crl_file = Some(path.to_string());
            self
        }

        /// Present the client certificate at `path` to an `https://` proxy
        /// (curl `--proxy-cert`).
        pub fn proxy_client_cert(mut self, path: &str) -> Self {
            self.proxy_tls.client_cert = Some(path.to_string());
            self
        }

        /// Client private key at `path` for the proxy client certificate
        /// (curl `--proxy-key`).
        pub fn proxy_client_key(mut self, path: &str) -> Self {
            self.proxy_tls.client_key = Some(path.to_string());
            self
        }

        /// Passphrase for an encrypted proxy client key (curl `--proxy-pass`).
        pub fn proxy_client_key_pass(mut self, pass: &str) -> Self {
            self.proxy_tls.client_key_pass = Some(pass.to_string());
            self
        }

        /// Treat the proxy client certificate as DER (curl
        /// `--proxy-cert-type DER`).
        pub fn proxy_cert_type_der(mut self, der: bool) -> Self {
            self.proxy_tls.cert_is_der = der;
            self
        }

        /// Treat the proxy client key as DER (curl `--proxy-key-type DER`).
        pub fn proxy_key_type_der(mut self, der: bool) -> Self {
            self.proxy_tls.key_is_der = der;
            self
        }

        /// Pin the `https://` proxy's public key (curl `--proxy-pinnedpubkey`,
        /// `sha256//BASE64[;...]`); a mismatch fails the proxy handshake.
        pub fn proxy_pinned_pubkey(mut self, spec: &str) -> Self {
            self.proxy_tls.pinned_pubkey = Some(spec.to_string());
            self
        }

        /// Restrict the TLS ≤ 1.2 cipher suites offered to the proxy (curl
        /// `--proxy-ciphers`).
        pub fn proxy_ciphers(mut self, list: &str) -> Self {
            self.proxy_tls.ciphers = Some(list.to_string());
            self
        }

        /// Restrict the TLS 1.3 cipher suites offered to the proxy (curl
        /// `--proxy-tls13-ciphers`).
        pub fn proxy_tls13_ciphers(mut self, list: &str) -> Self {
            self.proxy_tls.tls13_ciphers = Some(list.to_string());
            self
        }

        /// Minimum TLS version for the proxy connection (curl
        /// `--proxy-tlsv1.x`).
        pub fn proxy_tls_min_version(mut self, v: crate::tls::ProtocolVersion) -> Self {
            self.proxy_tls.min_version = Some(v);
            self
        }

        /// Maximum TLS version for the proxy connection (curl
        /// `--proxy-tls-max`).
        pub fn proxy_tls_max_version(mut self, v: crate::tls::ProtocolVersion) -> Self {
            self.proxy_tls.max_version = Some(v);
            self
        }
    };
}
pub(crate) use proxy_tls_builder_methods;

impl TlsSettings {
    /// Build backend [`TlsOpts`] offering `alpn`. Files are read here, so a
    /// missing or unreadable one surfaces as an [`Error`] before any
    /// handshake.
    pub(crate) fn to_opts(&self, alpn: &[&[u8]]) -> Result<TlsOpts> {
        let mut opts = TlsOpts::verifying();
        opts.alpn = alpn.iter().map(|p| p.to_vec()).collect();
        opts.verify = self.verify;
        opts.min_version = self.min_version;
        opts.max_version = self.max_version;
        // Base trust store: `--cacert` replaces the system roots; otherwise
        // leave `None` so the backend loads its default bundle. `--capath`
        // *adds* a directory of CAs on top of whichever base is in effect.
        if let Some(path) = &self.ca_bundle {
            opts.roots = Some(super::load_roots_from_file(path)?);
        }
        if let Some(dir) = &self.ca_path {
            opts.roots = Some(super::load_roots_from_dir(opts.roots.take(), dir)?);
        }
        if let Some(cert_path) = &self.client_cert {
            opts.client_cert = Some(std::fs::read(cert_path).map_err(Error::Io)?);
            opts.cert_is_der = self.cert_is_der;
            opts.key_is_der = self.key_is_der;
            opts.client_key_pass = self.client_key_pass.clone();
            if let Some(key_path) = &self.client_key {
                opts.client_key = Some(std::fs::read(key_path).map_err(Error::Io)?);
            }
        }
        if let Some(spec) = &self.pinned_pubkey {
            opts.pinned_spki_sha256 = super::parse_pinned_pubkey(spec)?;
        }
        if let Some(path) = &self.crl_file {
            opts.crl_pem = Some(std::fs::read(path).map_err(Error::Io)?);
        }
        // Combine --ciphers and --tls13-ciphers into one IANA-ID list; the
        // backend intersects it per TLS version.
        if let Some(spec) = &self.ciphers {
            opts.cipher_suites.extend(super::cipher_names_to_ids(spec)?);
        }
        if let Some(spec) = &self.tls13_ciphers {
            opts.cipher_suites.extend(super::cipher_names_to_ids(spec)?);
        }
        opts.verify_callback = self.verify_callback.clone();
        Ok(opts)
    }

    /// TLS-handshake `transport` for `host` with these settings, enforcing
    /// public-key pins and the verify callback like the HTTP path does.
    pub(crate) fn connect<S: std::io::Read + std::io::Write>(
        &self,
        transport: S,
        host: &str,
    ) -> Result<super::TlsStream<S>> {
        super::connect_over_tls(transport, host, self.to_opts(&[])?)
    }
}

#[cfg(test)]
mod tests {
    use super::TlsSettings;

    #[test]
    fn default_matches_verifying_opts() {
        let o = TlsSettings::default().to_opts(&[b"h2"]).unwrap();
        assert!(o.verify);
        assert!(o.roots.is_none());
        assert!(o.pinned_spki_sha256.is_empty());
        assert_eq!(o.alpn, vec![b"h2".to_vec()]);
    }

    #[test]
    fn insecure_and_bad_pin_are_carried() {
        let s = TlsSettings {
            verify: false,
            ..TlsSettings::default()
        };
        assert!(!s.to_opts(&[]).unwrap().verify);
        let s = TlsSettings {
            pinned_pubkey: Some("not-a-pin".into()),
            ..TlsSettings::default()
        };
        assert!(s.to_opts(&[]).is_err(), "malformed pin must fail closed");
    }

    #[test]
    fn missing_ca_file_is_an_error_before_connecting() {
        let s = TlsSettings {
            ca_bundle: Some("/nonexistent/rsurl-ca.pem".into()),
            ..TlsSettings::default()
        };
        assert!(s.to_opts(&[]).is_err());
    }
}

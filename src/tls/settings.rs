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

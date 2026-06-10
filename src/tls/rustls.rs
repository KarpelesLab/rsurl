//! TLS backend layered on rustls 0.23 + the `ring` crypto provider.
//!
//! Exposes [`TlsStream`], a blocking `Read + Write` adapter that runs the
//! TLS handshake on construction and then transparently encrypts/decrypts
//! application bytes on every read/write. Selected by the `rustls-tls`
//! Cargo feature; see [`crate::tls`] for the cfg cascade.
//!
//! Driving rustls manually (`read_tls`, `write_tls`, `process_new_packets`,
//! `reader`, `writer`) instead of leaning on `rustls::Stream<'_>` lets the
//! adapter own the underlying transport and stay generic over any
//! `S: Read + Write` (TCP, FTPS data sockets, `TlsStream<TlsStream<...>>`,
//! anything the rest of the crate already uses).

use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring as crypto, CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};

use super::client_auth;
use super::common::ProtocolVersion;
use crate::error::{Error, Result};

pub use rustls::RootCertStore;

/// Search paths for a system-wide CA bundle, in order of preference.
/// Same list and rationale as the purecrypto backend — see comments there.
const SYSTEM_CA_PATHS: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
    "/etc/ssl/ca-bundle.pem",
    "/etc/ca-certificates/extracted/tls-ca-bundle.pem",
];

/// Knobs the caller can flip on a single TLS handshake. Same shape as the
/// purecrypto backend so consumer code compiles against both unchanged.
#[derive(Clone)]
pub struct TlsOpts {
    pub alpn: Vec<Vec<u8>>,
    pub verify: bool,
    pub roots: Option<RootCertStore>,
    /// Minimum / maximum acceptable TLS version (curl `--tlsv1.x`/`--tls-max`).
    pub min_version: Option<ProtocolVersion>,
    pub max_version: Option<ProtocolVersion>,
    /// Raw bytes of the client certificate file (curl `-E`/`--cert`).
    pub client_cert: Option<Vec<u8>>,
    /// Raw bytes of the client private-key file (curl `--key`). When `None`
    /// and `client_cert` is set, the key is looked for inside the cert file.
    pub client_key: Option<Vec<u8>>,
    /// Passphrase for an encrypted client key (curl `--pass`). rustls-pemfile
    /// cannot decrypt keys; a set passphrase with an encrypted key is an error.
    pub client_key_pass: Option<String>,
    /// The client cert file is DER, not PEM (curl `--cert-type DER`).
    pub cert_is_der: bool,
    /// The client key file is DER, not PEM (curl `--key-type DER`).
    pub key_is_der: bool,
    /// SHA-256 pins of the server leaf SPKI (curl `--pinnedpubkey`). Empty
    /// means no pinning; non-empty requires the leaf to match at least one.
    pub pinned_spki_sha256: Vec<[u8; 32]>,
    /// Raw bytes of a CRL file (curl `--crlfile`). The rustls backend does not
    /// wire CRL checking; a non-`None` value is reported as unsupported (use
    /// the default purecrypto-tls backend, which honors it).
    pub crl_pem: Option<Vec<u8>>,
    /// IANA cipher-suite IDs (curl `--ciphers`/`--tls13-ciphers`). The rustls
    /// backend does not wire suite restriction; a non-empty value errors.
    pub cipher_suites: Vec<u16>,
}

impl TlsOpts {
    pub fn verifying() -> Self {
        TlsOpts {
            alpn: Vec::new(),
            verify: true,
            roots: None,
            min_version: None,
            max_version: None,
            client_cert: None,
            client_key: None,
            client_key_pass: None,
            cert_is_der: false,
            key_is_der: false,
            pinned_spki_sha256: Vec::new(),
            crl_pem: None,
            cipher_suites: Vec::new(),
        }
    }
}

/// `TlsOpts` is public API with public fields, so `..Default::default()` in a
/// downstream struct-update must NOT silently disable certificate verification
/// (a `bool` derive would default `verify` to `false`). The safe default is the
/// verifying configuration; opting out of verification must be explicit (`-k`).
impl Default for TlsOpts {
    fn default() -> Self {
        TlsOpts::verifying()
    }
}

/// Load every CA found in the first existing bundle on disk. Mirrors the
/// purecrypto backend's behaviour (skip-the-broken, error on empty).
pub fn load_system_roots() -> Result<RootCertStore> {
    for path in SYSTEM_CA_PATHS {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(Error::Io(e)),
        };
        return parse_roots(BufReader::new(file), path);
    }
    Err(Error::BadResponse(
        "no system CA bundle found; tried common Unix paths".into(),
    ))
}

/// Load CA certificates from a user-supplied PEM bundle (curl's
/// `--cacert <file>` flag). Empty/unparseable bundle is an error so the
/// caller knows verification would always fail.
pub fn load_roots_from_file(path: &str) -> Result<RootCertStore> {
    let file = File::open(path).map_err(Error::Io)?;
    parse_roots(BufReader::new(file), path)
}

/// Add every CA in `dir` to a base root store and return it (curl `--capath`,
/// which *adds* to the trust set). When `base` is `None` the system bundle is
/// loaded first, so `--capath` alone augments the default roots; when `base`
/// is `Some` (e.g. a `--cacert` bundle) the directory's CAs are added on top.
/// Files that don't parse as PEM certs are skipped, matching curl/OpenSSL.
pub fn load_roots_from_dir(base: Option<RootCertStore>, dir: &str) -> Result<RootCertStore> {
    let mut roots = match base {
        Some(r) => r,
        None => load_system_roots()?,
    };
    let mut added = 0usize;
    for entry in std::fs::read_dir(dir).map_err(Error::Io)? {
        let entry = entry.map_err(Error::Io)?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Ok(file) = File::open(&path) else {
            continue;
        };
        let mut reader = BufReader::new(file);
        let Ok(certs) =
            rustls_pemfile::certs(&mut reader).collect::<std::result::Result<Vec<_>, _>>()
        else {
            continue; // unreadable / non-PEM file in the dir — skip it
        };
        let (n, _ignored) = roots.add_parsable_certificates(certs);
        added += n;
    }
    if added == 0 {
        return Err(Error::BadResponse(format!(
            "--capath {dir}: no usable CA certificates found"
        )));
    }
    Ok(roots)
}

fn parse_roots<R: io::BufRead>(mut reader: R, path: &str) -> Result<RootCertStore> {
    // rustls-pemfile yields the DER bytes of every certificate it can extract;
    // anything else (private keys, unknown PEM tags) is skipped. We then hand
    // the whole batch to add_parsable_certificates, which drops anything that
    // webpki cannot ingest (e.g. unsupported curve) — matching purecrypto's
    // "broken certs are skipped silently" semantics.
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::BadResponse(format!("PEM parse error in {path}: {e}")))?;
    let mut roots = RootCertStore::empty();
    let (added, _ignored) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err(Error::BadResponse(format!(
            "no usable CA certificates parsed from {path}"
        )));
    }
    Ok(roots)
}

/// A blocking TLS adapter around a transport `S: Read + Write` plus a
/// rustls `ClientConnection`. The handshake runs in [`connect_over_tls`];
/// after that, `Read`/`Write` work like an ordinary stream.
pub struct TlsStream<S: Read + Write> {
    conn: ClientConnection,
    sock: S,
    /// Snapshot of the negotiated TLS version, captured at handshake
    /// completion (post-handshake rustls returns `None` once the connection
    /// is shutting down, which would surprise the verbose trace).
    version: Option<ProtocolVersion>,
    /// Snapshot of the server-selected ALPN protocol, for the same reason.
    alpn: Option<Vec<u8>>,
    /// Snapshot of the peer certificate chain, leaf first, each DER-encoded.
    /// Owned so [`TlsStream::peer_certificates`] can return a borrow into it.
    peer_certs_der: Vec<Vec<u8>>,
}

/// Establish a TLS 1.2/1.3 connection over an existing transport. Peer name
/// is verified against `sni`. ALPN is not offered.
pub fn connect_over<S: Read + Write>(transport: S, sni: &str) -> Result<TlsStream<S>> {
    connect_over_tls(transport, sni, TlsOpts::verifying())
}

/// Like [`connect_over`], but offers `alpn` as the ALPN protocol list. Pass
/// an empty slice to disable ALPN (same as [`connect_over`]).
pub fn connect_over_with_alpn<S: Read + Write>(
    transport: S,
    sni: &str,
    alpn: &[&[u8]],
) -> Result<TlsStream<S>> {
    let mut opts = TlsOpts::verifying();
    opts.alpn = alpn.iter().map(|p| p.to_vec()).collect();
    connect_over_tls(transport, sni, opts)
}

/// Like [`connect_over_with_alpn`], but takes the full [`TlsOpts`] so
/// callers can disable verification (`-k`) or supply a custom root store
/// (`--cacert`).
pub fn connect_over_tls<S: Read + Write>(
    transport: S,
    sni: &str,
    opts: TlsOpts,
) -> Result<TlsStream<S>> {
    // CRL checking (curl `--crlfile`) is only wired on the purecrypto-tls
    // backend; refuse it here rather than silently skip revocation.
    if opts.crl_pem.is_some() {
        return Err(Error::BadResponse(
            "--crlfile is not supported by the rustls-tls backend; \
             build with the default purecrypto-tls backend for CRL checking"
                .into(),
        ));
    }
    if !opts.cipher_suites.is_empty() {
        return Err(Error::BadResponse(
            "--ciphers/--tls13-ciphers is not supported by the rustls-tls backend; \
             build with the default purecrypto-tls backend"
                .into(),
        ));
    }
    let roots = match opts.roots {
        Some(r) => r,
        None => load_system_roots()?,
    };

    // Build the ClientConfig. Two paths: the standard webpki verifier
    // (verify=true) or a "trust everything" verifier (verify=false), the
    // latter delegating signature math to the ring CryptoProvider so the
    // handshake still validates the cryptographic binding between the
    // presented cert and the server's signed handshake — only chain trust
    // is skipped. This is what curl's -k does.
    // Restrict the offered TLS versions if --tlsv1.x/--tls-max were given.
    let rank = |v: ProtocolVersion| match v {
        ProtocolVersion::TLSv1_3 => 3u8,
        _ => 2u8,
    };
    let min = opts.min_version.map(rank).unwrap_or(0);
    let max = opts.max_version.map(rank).unwrap_or(u8::MAX);
    let versions: Vec<&'static rustls::SupportedProtocolVersion> =
        if opts.min_version.is_none() && opts.max_version.is_none() {
            rustls::ALL_VERSIONS.to_vec()
        } else {
            [&rustls::version::TLS12, &rustls::version::TLS13]
                .into_iter()
                .filter(|v| {
                    let r = match v.version {
                        rustls::ProtocolVersion::TLSv1_3 => 3u8,
                        _ => 2u8,
                    };
                    r >= min && r <= max
                })
                .collect()
        };
    let builder = ClientConfig::builder_with_protocol_versions(&versions);
    // Parse the client identity (curl `-E`/`--key`/`--pass`), if any, before
    // choosing the verifier branch so both branches share it.
    let identity = if let Some(cert_bytes) = &opts.client_cert {
        Some(build_identity(
            cert_bytes,
            opts.client_key.as_deref(),
            opts.client_key_pass.as_deref(),
            opts.cert_is_der,
            opts.key_is_der,
        )?)
    } else {
        None
    };
    let verified = builder.with_root_certificates(roots);
    let dangerous = ClientConfig::builder_with_protocol_versions(&versions)
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify::new()));
    let mut config = match (opts.verify, identity) {
        (true, Some((chain, key))) => verified
            .with_client_auth_cert(chain, key)
            .map_err(rustls_err)?,
        (true, None) => verified.with_no_client_auth(),
        (false, Some((chain, key))) => dangerous
            .with_client_auth_cert(chain, key)
            .map_err(rustls_err)?,
        (false, None) => dangerous.with_no_client_auth(),
    };
    config.alpn_protocols = opts.alpn;

    let server_name: ServerName<'static> = ServerName::try_from(sni.to_string())
        .map_err(|e| Error::BadResponse(format!("invalid SNI {sni:?}: {e}")))?;
    let conn = ClientConnection::new(Arc::new(config), server_name).map_err(rustls_err)?;

    let mut s = TlsStream {
        conn,
        sock: transport,
        version: None,
        alpn: None,
        peer_certs_der: Vec::new(),
    };
    s.run_handshake()?;
    s.snapshot_post_handshake();
    // Public-key pinning (curl `--pinnedpubkey`): hash the leaf cert SPKI and
    // require a match against at least one pin. SPKI extraction uses
    // purecrypto's x509 parser (always linked), shared with the other backend.
    if !opts.pinned_spki_sha256.is_empty() {
        let leaf = s.peer_certificates().first().map(Vec::as_slice);
        match leaf {
            Some(der) if client_auth::spki_pin_matches(der, &opts.pinned_spki_sha256) => {}
            _ => {
                return Err(Error::BadResponse(
                    "pinned public key does not match server certificate".into(),
                ))
            }
        }
    }
    Ok(s)
}

/// Parse the client cert chain + private key from raw file bytes into the
/// rustls owned-DER types, honouring the PEM/DER cert/key type flags.
///
/// rustls-pemfile cannot decrypt encrypted keys, so a `--pass` is only usable
/// to confirm the key is *not* encrypted; an actually-encrypted key is reported
/// as unsupported on this backend.
fn build_identity(
    cert_bytes: &[u8],
    key_bytes: Option<&[u8]>,
    pass: Option<&str>,
    cert_is_der: bool,
    key_is_der: bool,
) -> Result<(
    Vec<CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    use rustls::pki_types::PrivateKeyDer;

    // Certificate chain.
    let chain: Vec<CertificateDer<'static>> = if cert_is_der {
        vec![CertificateDer::from(cert_bytes.to_vec())]
    } else {
        let mut reader = BufReader::new(cert_bytes);
        let certs = rustls_pemfile::certs(&mut reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::BadResponse(format!("client cert: PEM parse error: {e}")))?;
        if certs.is_empty() {
            return Err(Error::BadResponse(
                "client cert: file contains no CERTIFICATE blocks".into(),
            ));
        }
        certs
    };

    // Private key: from `--key` file, or embedded in the cert PEM.
    let key: PrivateKeyDer<'static> = if key_is_der {
        let kb = key_bytes.ok_or_else(|| {
            Error::BadResponse("client cert: a DER key needs --key (no embedded key)".into())
        })?;
        PrivateKeyDer::try_from(kb.to_vec())
            .map_err(|e| Error::BadResponse(format!("client key (DER): {e}")))?
    } else {
        // Look in the key file if given, else fall back to the cert file.
        let src = key_bytes.unwrap_or(cert_bytes);
        let mut reader = BufReader::new(src);
        match rustls_pemfile::private_key(&mut reader) {
            Ok(Some(k)) => k,
            Ok(None) => {
                return Err(Error::BadResponse(
                    "client key: no private key found in the PEM \
                     (encrypted keys are not supported by the rustls backend)"
                        .into(),
                ))
            }
            Err(e) => {
                return Err(Error::BadResponse(format!(
                    "client key: PEM parse error: {e}"
                )))
            }
        }
    };

    // An explicit passphrase can't be applied (rustls-pemfile won't decrypt).
    // If the key parsed anyway it was unencrypted; warn-by-error only when we
    // failed above. Nothing to do here on success, but reject a `--pass` that
    // the user clearly expected to matter for a key we *couldn't* decrypt is
    // already handled by the parse failure above.
    let _ = pass;

    Ok((chain, key))
}

impl<S: Read + Write> TlsStream<S> {
    pub fn negotiated_version(&self) -> Option<ProtocolVersion> {
        self.version
    }

    pub fn alpn_selected(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        &self.peer_certs_der
    }

    fn run_handshake(&mut self) -> Result<()> {
        // Standard rustls drive-loop: keep stepping while the SM still
        // wants I/O, until is_handshaking() flips to false. Identical in
        // spirit to the purecrypto backend's loop.
        while self.conn.is_handshaking() {
            let mut did_something = false;
            if self.conn.wants_write() {
                self.conn.write_tls(&mut self.sock).map_err(Error::Io)?;
                did_something = true;
            }
            if self.conn.is_handshaking() && self.conn.wants_read() {
                let n = self.conn.read_tls(&mut self.sock).map_err(Error::Io)?;
                if n == 0 {
                    return Err(Error::UnexpectedEof);
                }
                self.conn.process_new_packets().map_err(rustls_err)?;
                did_something = true;
            }
            if !did_something {
                // The SM wants neither read nor write but says we're still
                // handshaking — drive one process_new_packets to unstick.
                self.conn.process_new_packets().map_err(rustls_err)?;
            }
        }
        // Flush any final handshake bytes the SM produced after the last
        // process_new_packets but before transitioning out of handshaking.
        while self.conn.wants_write() {
            self.conn.write_tls(&mut self.sock).map_err(Error::Io)?;
        }
        Ok(())
    }

    fn snapshot_post_handshake(&mut self) {
        self.version = self.conn.protocol_version().map(map_rustls_version);
        self.alpn = self.conn.alpn_protocol().map(|p| p.to_vec());
        self.peer_certs_der = self
            .conn
            .peer_certificates()
            .map(|certs| certs.iter().map(|c| c.to_vec()).collect())
            .unwrap_or_default();
    }
}

impl<S: Read + Write> Write for TlsStream<S> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let n = self.conn.writer().write(data)?;
        // Flush the freshly encrypted record(s) immediately so a request
        // that the caller wrote with write_all() actually leaves the host.
        while self.conn.wants_write() {
            self.conn.write_tls(&mut self.sock)?;
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        while self.conn.wants_write() {
            self.conn.write_tls(&mut self.sock)?;
        }
        self.sock.flush()
    }
}

impl<S: Read + Write> Read for TlsStream<S> {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        if dst.is_empty() {
            return Ok(0);
        }
        loop {
            // Try to serve from already-decrypted plaintext sitting in
            // the SM's internal buffer.
            match self.conn.reader().read(dst) {
                Ok(0) => return Ok(0), // clean close (close_notify)
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                // Many real servers close the TCP connection without sending
                // close_notify. Map that to a clean EOF for parity with the
                // purecrypto backend, which has the same behaviour.
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(0),
                Err(e) => return Err(e),
            }
            // No buffered plaintext — flush any pending output (post-handshake
            // tickets, key updates) and pull more bytes off the wire.
            while self.conn.wants_write() {
                self.conn.write_tls(&mut self.sock)?;
            }
            if !self.conn.wants_read() {
                return Ok(0);
            }
            let n = self.conn.read_tls(&mut self.sock)?;
            if n == 0 {
                // TCP EOF. Drain anything left in the SM, otherwise EOF up.
                return match self.conn.reader().read(dst) {
                    Ok(n) => Ok(n),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(0),
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(0),
                    Err(e) => Err(e),
                };
            }
            // Will surface a decryption / protocol error if the record we
            // just read is malformed.
            self.conn
                .process_new_packets()
                .map_err(|e| io::Error::other(format!("tls: {e}")))?;
        }
    }
}

/// `ServerCertVerifier` that returns success for any chain. Cryptographic
/// signature verification on the handshake itself is still performed via the
/// ring `CryptoProvider`, so a real TLS handshake (just not one that proves
/// the server's identity via the PKI) is what actually completes — matching
/// what curl's `-k` does.
#[derive(Debug)]
struct NoVerify {
    sig_algs: WebPkiSupportedAlgorithms,
}

impl NoVerify {
    fn new() -> Self {
        let provider: CryptoProvider = crypto::default_provider();
        Self {
            sig_algs: provider.signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.sig_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.sig_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.sig_algs.supported_schemes()
    }
}

fn map_rustls_version(v: rustls::ProtocolVersion) -> ProtocolVersion {
    use rustls::ProtocolVersion as R;
    match v {
        R::TLSv1_2 => ProtocolVersion::TLSv1_2,
        R::TLSv1_3 => ProtocolVersion::TLSv1_3,
        // SSLv2/3, TLSv1_0/1_1, DTLS, or Unknown(u16) — surface the
        // on-wire code via the From<ProtocolVersion> for u16 impl that
        // rustls's enum_builder! macro generates.
        other => ProtocolVersion::Other(u16::from(other)),
    }
}

fn rustls_err(e: rustls::Error) -> Error {
    Error::BadResponse(format!("tls: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_enables_verification() {
        // TLS-2: a `#[derive(Default)]` would leave `verify == false`, silently
        // disabling certificate verification for `..Default::default()` callers.
        assert!(TlsOpts::default().verify);
        assert!(TlsOpts::verifying().verify);
    }
}

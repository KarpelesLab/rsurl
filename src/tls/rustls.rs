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
#[derive(Default, Clone)]
pub struct TlsOpts {
    pub alpn: Vec<Vec<u8>>,
    pub verify: bool,
    pub roots: Option<RootCertStore>,
    /// Minimum / maximum acceptable TLS version (curl `--tlsv1.x`/`--tls-max`).
    pub min_version: Option<ProtocolVersion>,
    pub max_version: Option<ProtocolVersion>,
}

impl TlsOpts {
    pub fn verifying() -> Self {
        TlsOpts {
            alpn: Vec::new(),
            verify: true,
            roots: None,
            min_version: None,
            max_version: None,
        }
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
    let mut config = if opts.verify {
        builder.with_root_certificates(roots).with_no_client_auth()
    } else {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify::new()))
            .with_no_client_auth()
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
    Ok(s)
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

//! Test-only in-process TLS server, built on the same stack as the active
//! client backend (purecrypto, or rustls under `rustls-tls`), and the TLS
//! session-resumption tests that run against it.
//!
//! Every [`TestServer`] shares one resumption state (a fixed purecrypto ticket
//! key, or one rustls session store), so a server resumes sessions minted by
//! another. A server built with `rogue = true` presents a self-signed
//! certificate the test CA does not vouch for: a verifying client can only
//! complete a handshake with it by *resuming* a session (a resumed handshake
//! carries no certificate), which lets a test enforce resumption the way
//! vsftpd's `require_ssl_reuse` does.

use std::io::{self, Read, Write};
use std::net::TcpStream;

use crate::tls::ProtocolVersion;

/// A test CA and a `localhost` leaf (P-256) signed by it.
pub(crate) const CA_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBhzCCAS2gAwIBAgIUEJAJGguFhUu6Wi64F9FYb6oJ9bkwCgYIKoZIzj0EAwIw
GDEWMBQGA1UEAwwNcnN1cmwtdGVzdC1jYTAgFw0yNjA2MjEyMzI2MjFaGA8yMTI2
MDUyODIzMjYyMVowGDEWMBQGA1UEAwwNcnN1cmwtdGVzdC1jYTBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABGvezLhNMu/DJw3ClBkhcK571eQz/QctqGAf1whkMiXf
Sj46b9bBymWIV706DP/x2nXzSJgiXTv9rnTli35el0CjUzBRMB0GA1UdDgQWBBQU
AOFhWcYfxuM+R86kRFZWr/KATzAfBgNVHSMEGDAWgBQUAOFhWcYfxuM+R86kRFZW
r/KATzAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIBWUfubWKWST
arQvZPn0jqXOwKG0x+xYs5UtcjVf3vOiAiEAlxoTAAh0nVLMrmTsnJXD131iPHz7
Uk3Wt1xw1blCE/8=
-----END CERTIFICATE-----
";

const LEAF_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBuDCCAV2gAwIBAgIUcMudt8JBWAsDX8h+3CC46SiY14EwCgYIKoZIzj0EAwIw
GDEWMBQGA1UEAwwNcnN1cmwtdGVzdC1jYTAgFw0yNjA2MjEyMzI2MjFaGA8yMTI2
MDUyODIzMjYyMVowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEuBVdUYNtZqpWDO9h4nw0HF9sTKT3R7p/WJYsNgIfeO4hi/AM
9x+n7MP1tYi6zPlfR6qG/ZbEJLFDzZShfHPc/KOBhjCBgzAUBgNVHREEDTALggls
b2NhbGhvc3QwCQYDVR0TBAIwADALBgNVHQ8EBAMCB4AwEwYDVR0lBAwwCgYIKwYB
BQUHAwEwHQYDVR0OBBYEFAAZvjmK2EXoiEDqFV3wFGMS8GBJMB8GA1UdIwQYMBaA
FBQA4WFZxh/G4z5HzqREVlav8oBPMAoGCCqGSM49BAMCA0kAMEYCIQCPQPF3G07F
EhDmMDPLFGbF/ZdfuDFfBN6Sjs3DuIgSXAIhAMGqymq6vFwXRbvrhbGljFfJQjtz
98VOQz3xfzdRnPC2
-----END CERTIFICATE-----
";

const LEAF_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg8mp/gpytQtzNMwlE
fXfhylHGgcKzHtmkPeil9MKfoSyhRANCAAS4FV1Rg21mqlYM72HifDQcX2xMpPdH
un9Yliw2Ah947iGL8Az3H6fsw/W1iLrM+V9Hqob9lsQksUPNlKF8c9z8
-----END PRIVATE KEY-----
";

/// A self-signed `localhost` certificate the test CA did not issue.
const ROGUE_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBkjCCATigAwIBAgIUIm38IgOEUocdIqWMEc9ToO7oD3cwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MDkyNzE0MjUzN1oYDzIxMjYwOTAz
MTQyNTM3WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAATZY6oxnvr5uNQHGRpsa8W250AYXhoEibnMYTKNbM5EfrLYw9tuLrOl
cVEKQ+KXPew+gv3kh0amIpNiHoSWlHI5o2YwZDAdBgNVHQ4EFgQUKFFO6A1dLQ8z
as1PujWfVjWuywQwHwYDVR0jBBgwFoAUKFFO6A1dLQ8zas1PujWfVjWuywQwFAYD
VR0RBA0wC4IJbG9jYWxob3N0MAwGA1UdEwEB/wQCMAAwCgYIKoZIzj0EAwIDSAAw
RQIhAIZYOXCC71o4EvaFHxm2/UREcK1qCwbsKoARyIl1wBvdAiAt+/VHIJeeVZ5O
DZAkX0WdipQlVvFt3tggbLfMqyFjDA==
-----END CERTIFICATE-----
";

const ROGUE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgeBOZYuNwvEXY6AcM
JxqyfPs9oAP8iW0OtInuDXUImIOhRANCAATZY6oxnvr5uNQHGRpsa8W250AYXhoE
ibnMYTKNbM5EfrLYw9tuLrOlcVEKQ+KXPew+gv3kh0amIpNiHoSWlHI5
-----END PRIVATE KEY-----
";

/// The DER leaf the trusted (non-rogue) server presents.
pub(crate) fn leaf_der() -> Vec<u8> {
    super::client_auth::load_cert_chain(LEAF_CERT_PEM).unwrap()[0].clone()
}

/// Write the test CA to a unique temp file (for `--cacert`); the caller
/// removes it.
pub(crate) fn ca_file() -> std::path::PathBuf {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "rsurl-test-ca-{}-{}.pem",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::write(&path, CA_CERT_PEM).unwrap();
    path
}

/// An accepted, handshaken server-side TLS connection.
pub(crate) trait ServerTls: Read + Write + Send {
    /// Send `close_notify`.
    fn close(&mut self) -> io::Result<()>;
    /// Whether the handshake resumed a session, when the server stack can
    /// tell (rustls can; purecrypto's `Connection` does not expose it).
    fn resumed(&self) -> Option<bool>;
}

/// A TLS server configuration accepting `min..=max`.
pub(crate) struct TestServer {
    #[cfg(feature = "rustls-tls")]
    cfg: std::sync::Arc<rustls::ServerConfig>,
    #[cfg(not(feature = "rustls-tls"))]
    cfg: purecrypto::tls::Config,
}

impl TestServer {
    pub(crate) fn new(min: ProtocolVersion, max: ProtocolVersion, rogue: bool) -> Self {
        let (cert, key) = if rogue {
            (ROGUE_CERT_PEM, ROGUE_KEY_PEM)
        } else {
            (LEAF_CERT_PEM, LEAF_KEY_PEM)
        };
        TestServer {
            cfg: Self::build(min, max, cert, key),
        }
    }

    #[cfg(feature = "rustls-tls")]
    fn build(
        min: ProtocolVersion,
        max: ProtocolVersion,
        cert: &str,
        key: &str,
    ) -> std::sync::Arc<rustls::ServerConfig> {
        use std::sync::{Arc, OnceLock};
        static STORE: OnceLock<Arc<rustls::server::ServerSessionMemoryCache>> = OnceLock::new();
        let store = STORE.get_or_init(|| rustls::server::ServerSessionMemoryCache::new(256));
        let rank = |v: ProtocolVersion| u8::from(v == ProtocolVersion::TLSv1_3);
        let versions: Vec<&'static rustls::SupportedProtocolVersion> = [
            (ProtocolVersion::TLSv1_2, &rustls::version::TLS12),
            (ProtocolVersion::TLSv1_3, &rustls::version::TLS13),
        ]
        .into_iter()
        .filter(|(v, _)| rank(min) <= rank(*v) && rank(*v) <= rank(max))
        .map(|(_, rv)| rv)
        .collect();
        let certs = rustls_pemfile::certs(&mut cert.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        let key = rustls_pemfile::private_key(&mut key.as_bytes())
            .unwrap()
            .unwrap();
        let mut cfg = rustls::ServerConfig::builder_with_protocol_versions(&versions)
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        // One store for every test server: TLS 1.2 session IDs and TLS 1.3
        // (stateful) tickets minted by one are resumable on another.
        cfg.session_storage = store.clone();
        Arc::new(cfg)
    }

    #[cfg(not(feature = "rustls-tls"))]
    fn build(
        min: ProtocolVersion,
        max: ProtocolVersion,
        cert: &str,
        key: &str,
    ) -> purecrypto::tls::Config {
        let pc = |v: ProtocolVersion| match v {
            ProtocolVersion::TLSv1_3 => purecrypto::tls::ProtocolVersion::TLSv1_3,
            _ => purecrypto::tls::ProtocolVersion::TLSv1_2,
        };
        let chain = super::client_auth::load_cert_chain(cert).unwrap();
        let key = super::client_auth::parse_signing_key(key, None).unwrap();
        purecrypto::tls::Config::builder()
            .tls_only()
            .versions(pc(min), pc(max))
            .identity(chain, key)
            // One ticket key for every test server, so any of them resumes.
            .ticket_key([0x5a; 32])
            .rng(std::sync::Arc::new(purecrypto::rng::OsRng))
            .build()
    }

    /// Run the server handshake over `sock`.
    #[cfg(feature = "rustls-tls")]
    pub(crate) fn accept(&self, mut sock: TcpStream) -> io::Result<Box<dyn ServerTls>> {
        let mut conn = rustls::ServerConnection::new(self.cfg.clone()).map_err(io::Error::other)?;
        while conn.is_handshaking() {
            conn.complete_io(&mut sock)?;
        }
        // Flush what followed the handshake (TLS 1.3 NewSessionTicket).
        while conn.wants_write() {
            conn.write_tls(&mut sock)?;
        }
        Ok(Box::new(rustls::StreamOwned::new(conn, sock)))
    }

    /// Run the server handshake over `sock`.
    #[cfg(not(feature = "rustls-tls"))]
    pub(crate) fn accept(&self, sock: TcpStream) -> io::Result<Box<dyn ServerTls>> {
        Ok(Box::new(pc_server::ServerStream::accept(sock, &self.cfg)?))
    }
}

#[cfg(feature = "rustls-tls")]
impl ServerTls for rustls::StreamOwned<rustls::ServerConnection, TcpStream> {
    fn close(&mut self) -> io::Result<()> {
        self.conn.send_close_notify();
        while self.conn.wants_write() {
            self.conn.write_tls(&mut self.sock)?;
        }
        Ok(())
    }

    fn resumed(&self) -> Option<bool> {
        Some(self.conn.handshake_kind() == Some(rustls::HandshakeKind::Resumed))
    }
}

/// A blocking server-side stream over purecrypto's sans-I/O `Connection`.
#[cfg(not(feature = "rustls-tls"))]
mod pc_server {
    use std::io::{self, Read, Write};
    use std::net::TcpStream;

    use purecrypto::tls::{Config, Connection, HandshakeStatus};

    pub(crate) struct ServerStream {
        conn: Connection,
        sock: TcpStream,
        plaintext: Vec<u8>,
        eof: bool,
    }

    impl ServerStream {
        /// Run the server handshake, then flush whatever the engine queued
        /// after it (TLS 1.3 NewSessionTicket).
        pub(crate) fn accept(sock: TcpStream, cfg: &Config) -> io::Result<Self> {
            let mut s = ServerStream {
                conn: Connection::server(cfg).map_err(other)?,
                sock,
                plaintext: Vec::new(),
                eof: false,
            };
            let mut buf = [0u8; 16 * 1024];
            loop {
                s.flush_tls()?;
                match s.conn.handshake().map_err(other)? {
                    HandshakeStatus::Complete => break,
                    HandshakeStatus::WantWrite => continue,
                    HandshakeStatus::WantRead => {
                        let n = s.sock.read(&mut buf)?;
                        if n == 0 {
                            return Err(io::ErrorKind::UnexpectedEof.into());
                        }
                        s.feed(&buf[..n])?;
                    }
                }
            }
            s.flush_tls()?;
            Ok(s)
        }

        fn feed(&mut self, mut wire: &[u8]) -> io::Result<()> {
            while !wire.is_empty() {
                let n = self.conn.feed(wire).map_err(other)?;
                if n == 0 {
                    return Err(io::Error::other("server engine refused input"));
                }
                wire = &wire[n..];
            }
            Ok(())
        }

        fn flush_tls(&mut self) -> io::Result<()> {
            loop {
                let out = self.conn.pop().map_err(other)?;
                if out.is_empty() {
                    return self.sock.flush();
                }
                self.sock.write_all(&out)?;
            }
        }
    }

    impl super::ServerTls for ServerStream {
        fn close(&mut self) -> io::Result<()> {
            self.conn.close().map_err(other)?;
            self.flush_tls()
        }

        fn resumed(&self) -> Option<bool> {
            None
        }
    }

    impl Read for ServerStream {
        fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
            let mut buf = [0u8; 16 * 1024];
            while self.plaintext.is_empty() {
                let app = self.conn.recv().map_err(other)?;
                if !app.is_empty() {
                    self.plaintext = app;
                    break;
                }
                if self.eof || self.conn.received_close_notify() {
                    return Ok(0);
                }
                let n = self.sock.read(&mut buf)?;
                if n == 0 {
                    self.eof = true;
                    continue;
                }
                self.feed(&buf[..n])?;
                self.flush_tls()?;
            }
            let n = dst.len().min(self.plaintext.len());
            dst[..n].copy_from_slice(&self.plaintext[..n]);
            self.plaintext.drain(..n);
            Ok(n)
        }
    }

    impl Write for ServerStream {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.conn.send(data).map_err(other)?;
            self.flush_tls()?;
            Ok(data.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flush_tls()
        }
    }

    fn other(e: purecrypto::tls::Error) -> io::Error {
        io::Error::other(format!("tls server: {e:?}"))
    }
}

/// Client-side resumption tests on the active backend.
mod resumption {
    use std::net::TcpListener;

    use super::*;
    use crate::tls::{connect_over_tls, TlsOpts, TlsSessionCache, TlsStream};

    /// Serve one connection: send `greeting`, then `close_notify`. The handle
    /// yields `None` if the handshake failed, else whether it resumed (when
    /// the server stack can tell).
    fn serve_once(
        server: TestServer,
        greeting: &'static [u8],
    ) -> (u16, std::thread::JoinHandle<Option<Option<bool>>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let (sock, _) = l.accept().unwrap();
            let mut s = server.accept(sock).ok()?;
            s.write_all(greeting).unwrap();
            // close_notify, then drop the socket: the client reads to EOF.
            let _ = s.close();
            Some(s.resumed())
        });
        (port, h)
    }

    fn connect(
        port: u16,
        cache: Option<&TlsSessionCache>,
        max: Option<ProtocolVersion>,
    ) -> crate::error::Result<(TlsStream<TcpStream>, Vec<u8>)> {
        let ca = ca_file();
        let mut opts = TlsOpts::verifying();
        opts.roots = Some(crate::tls::load_roots_from_file(ca.to_str().unwrap()).unwrap());
        let _ = std::fs::remove_file(&ca);
        opts.max_version = max;
        opts.session_cache = cache.cloned();
        let sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mut s = connect_over_tls(sock, "localhost", opts)?;
        let mut got = Vec::new();
        s.read_to_end(&mut got).map_err(crate::error::Error::Io)?;
        Ok((s, got))
    }

    /// First connection fills the cache; the second, against a server whose
    /// own certificate the client would reject, can only succeed by resuming.
    fn assert_second_connection_resumes(v: ProtocolVersion, client_max: Option<ProtocolVersion>) {
        let cache = TlsSessionCache::new();

        let (port, h) = serve_once(TestServer::new(v, v, false), b"control");
        let (first, got) = connect(port, Some(&cache), client_max).unwrap();
        assert_ne!(h.join().unwrap(), None);
        assert_eq!(got, b"control");
        assert!(!first.resumed(), "the first handshake is a full one");
        drop(first);

        // Without the session, the rogue server's certificate is rejected.
        let (port, h) = serve_once(TestServer::new(v, v, true), b"x");
        assert!(connect(port, None, client_max).is_err());
        let _ = h.join();

        let (port, h) = serve_once(TestServer::new(v, v, true), b"data");
        let (second, got) = connect(port, Some(&cache), client_max)
            .expect("the second connection must resume the cached session");
        let server_resumed = h.join().unwrap().expect("server handshake");
        assert_ne!(server_resumed, Some(false), "server saw a full handshake");
        assert_eq!(got, b"data");
        assert!(second.resumed(), "the second handshake must resume");
        // The resumed connection reports the originating (verified) chain, so
        // pinning / verify callbacks still see the real server leaf.
        assert_eq!(second.peer_certificates().first(), Some(&leaf_der()));
    }

    #[test]
    fn tls13_second_connection_resumes() {
        assert_second_connection_resumes(ProtocolVersion::TLSv1_3, None);
    }

    #[test]
    fn tls12_second_connection_resumes() {
        // purecrypto's version-spanning ClientHello does not ask for a TLS 1.2
        // ticket, so the client caps at TLS 1.2 here (curl `--tls-max 1.2`).
        assert_second_connection_resumes(ProtocolVersion::TLSv1_2, Some(ProtocolVersion::TLSv1_2));
    }

    #[test]
    fn session_cache_debug_is_redacted() {
        let cache = TlsSessionCache::new();
        let v = ProtocolVersion::TLSv1_3;
        let (port, h) = serve_once(TestServer::new(v, v, false), b"hi");
        connect(port, Some(&cache), None).unwrap();
        h.join().unwrap();
        let dbg = format!("{cache:?}");
        assert!(dbg.starts_with("TlsSessionCache"), "{dbg}");
        assert!(!dbg.contains("psk") && !dbg.contains("ticket"), "{dbg}");
    }
}

//! Sans-IO TLS as a *layered* [`Machine`]: [`TlsClient`] wraps an inner
//! application machine and a sans-IO TLS engine, and presents itself as a
//! `Machine` whose wire bytes are ciphertext. A driver pumps it exactly like any
//! other machine — TLS is invisible to the driver, and the same `TlsClient`
//! works under both the blocking and async drivers.
//!
//! This is the composition the sans-IO pattern buys us: rustls
//! (`ClientConnection`) and purecrypto's TLS are themselves buffer state
//! machines, so a thin [`TlsEngine`] adapter over the active backend lets TLS
//! carry HTTP/1, HTTP/2, WebSocket, etc., with no socket logic of its own.
//!
//! This module lands the composition (proven through the real blocking driver
//! with a deterministic mock engine) plus the real [`RustlsEngine`] and
//! [`PurecryptoEngine`] adapters — proven with full in-memory handshakes
//! (rustls client↔server, and purecrypto client↔rustls server cross-backend)
//! carrying an HTTP/1.1 exchange. Wiring these into the connect path (so a
//! configured engine is built without a socket) is the next increment.

use std::time::Instant;

use crate::error::Result;
use crate::io::Machine;

/// Negotiated TLS parameters a [`TlsEngine`] surfaces after the handshake, so a
/// frontend can populate its own TLS-info type ([`crate::http::TlsInfo`])
/// without depending on the active backend. All fields hold their default
/// ("unknown"/empty) value until the handshake completes.
#[derive(Debug, Clone, Default)]
pub(crate) struct TlsParams {
    /// Negotiated protocol version (e.g. TLS 1.3).
    pub version: Option<crate::tls::ProtocolVersion>,
    /// Negotiated cipher suite (IANA id).
    pub cipher_suite: Option<u16>,
    /// Server-selected ALPN protocol (e.g. `b"h2"`), if any.
    pub alpn: Option<Vec<u8>>,
    /// Peer certificate chain, leaf first, each entry DER-encoded.
    pub peer_certificates: Vec<Vec<u8>>,
}

/// The sans-IO half of a TLS connection: a pure in-memory state machine that
/// converts between ciphertext (on the wire) and plaintext (the application).
///
/// Both supported backends expose exactly these operations — rustls via
/// `read_tls`/`process_new_packets`/`writer`/`reader`/`write_tls`, purecrypto
/// via its `Connection` equivalents. The outbound (encrypt) path is in-memory
/// buffering and therefore infallible, so it composes with the infallible
/// [`Machine::poll_transmit`]; only the inbound (decrypt) path, which can see a
/// malformed record, returns a `Result`.
pub(crate) trait TlsEngine {
    /// Whether the handshake is still in progress. While `true`, application
    /// data is neither sent nor expected.
    fn is_handshaking(&self) -> bool;

    /// Feed inbound ciphertext and advance the handshake/record state machine.
    /// Errors on a malformed or undecryptable record.
    fn feed_incoming(&mut self, ciphertext: &[u8]) -> Result<()>;

    /// Append any outbound ciphertext the engine wants to send — handshake
    /// flights, encrypted application data, alerts — to `out`. In-memory and
    /// infallible.
    fn drain_outgoing(&mut self, out: &mut Vec<u8>);

    /// Move up to `dst.len()` bytes of decrypted application plaintext into
    /// `dst`, returning the count (`0` when none is buffered).
    fn read_plaintext(&mut self, dst: &mut [u8]) -> Result<usize>;

    /// Queue application plaintext for encryption; the ciphertext is emitted by
    /// the next [`drain_outgoing`](TlsEngine::drain_outgoing). In-memory and
    /// infallible.
    fn write_plaintext(&mut self, plaintext: &[u8]);

    /// The negotiated TLS parameters once the handshake has completed (version,
    /// cipher suite, ALPN, peer certificate chain). Returns defaults while
    /// still handshaking.
    fn tls_params(&self) -> TlsParams;
}

/// A TLS-wrapped application exchange: drives the handshake, then carries the
/// inner machine `M`'s bytes as encrypted records. Itself a [`Machine`], so a
/// driver pumps `TlsClient<E, M>` the same way it pumps a bare `M`.
pub(crate) struct TlsClient<E, M> {
    tls: E,
    inner: M,
    /// Scratch buffer for pulling plaintext out of the engine.
    scratch: Vec<u8>,
}

impl<E: TlsEngine, M: Machine> TlsClient<E, M> {
    pub(crate) fn new(tls: E, inner: M) -> TlsClient<E, M> {
        TlsClient {
            tls,
            inner,
            scratch: vec![0u8; 16 * 1024],
        }
    }

    /// The negotiated TLS parameters of the wrapped connection (valid after the
    /// driver has run the handshake to completion).
    pub(crate) fn tls_params(&self) -> TlsParams {
        self.tls.tls_params()
    }

    /// Drain all currently-available decrypted plaintext into the inner machine.
    fn pump_inner_input(&mut self) -> Result<()> {
        loop {
            let n = self.tls.read_plaintext(&mut self.scratch)?;
            if n == 0 {
                return Ok(());
            }
            let chunk = self.scratch[..n].to_vec();
            self.inner.handle_input(&chunk)?;
        }
    }
}

impl<E: TlsEngine, M: Machine> Machine for TlsClient<E, M> {
    type Event = M::Event;

    fn handle_input(&mut self, wire: &[u8]) -> Result<usize> {
        self.tls.feed_incoming(wire)?;
        if !self.tls.is_handshaking() {
            self.pump_inner_input()?;
        }
        Ok(wire.len())
    }

    fn handle_eof(&mut self) -> Result<()> {
        // Surface any last decrypted bytes before telling the inner machine the
        // transport closed.
        if !self.tls.is_handshaking() {
            self.pump_inner_input()?;
        }
        self.inner.handle_eof()
    }

    fn poll_transmit(&mut self, out: &mut Vec<u8>) -> bool {
        // Once the handshake completes, hand the inner machine's outbound bytes
        // (e.g. the HTTP request) to TLS for encryption. During the handshake we
        // only forward the engine's own flights.
        if !self.tls.is_handshaking() {
            let mut plaintext = Vec::new();
            while self.inner.poll_transmit(&mut plaintext) {}
            if !plaintext.is_empty() {
                self.tls.write_plaintext(&plaintext);
            }
        }
        let before = out.len();
        self.tls.drain_outgoing(out);
        out.len() > before
    }

    fn poll_event(&mut self) -> Option<M::Event> {
        self.inner.poll_event()
    }

    fn handle_timeout(&mut self, now: Instant) {
        self.inner.handle_timeout(now);
    }

    fn next_timeout(&self) -> Option<Instant> {
        self.inner.next_timeout()
    }

    fn is_finished(&self) -> bool {
        // The exchange is done when the inner application machine is done; a TLS
        // close_notify is best-effort and not required for completeness.
        self.inner.is_finished()
    }
}

/// The real [`TlsEngine`] over rustls's `ClientConnection`, which is itself a
/// sans-IO buffer state machine (`read_tls`/`process_new_packets`/`write_tls`/
/// `reader`/`writer`). Available with the `rustls-tls` backend. Construction of
/// a configured `ClientConnection` (verification, SNI, ALPN, client auth) is
/// factored out of the connect path in the wiring increment; this adapter only
/// drives an already-built engine.
#[cfg(feature = "rustls-tls")]
pub(crate) struct RustlsEngine(pub(crate) rustls::ClientConnection);

#[cfg(feature = "rustls-tls")]
impl TlsEngine for RustlsEngine {
    fn is_handshaking(&self) -> bool {
        self.0.is_handshaking()
    }

    fn feed_incoming(&mut self, mut ciphertext: &[u8]) -> Result<()> {
        // Read ciphertext records into the engine and process them. `read_tls`
        // may take less than offered when its internal buffer fills, so loop.
        while !ciphertext.is_empty() {
            let used = self
                .0
                .read_tls(&mut ciphertext)
                .map_err(crate::error::Error::Io)?;
            if used == 0 {
                break;
            }
            self.0
                .process_new_packets()
                .map_err(|e| crate::error::Error::Io(std::io::Error::other(format!("tls: {e}"))))?;
        }
        Ok(())
    }

    fn drain_outgoing(&mut self, out: &mut Vec<u8>) {
        // Writing pending ciphertext into a Vec never fails.
        while self.0.wants_write() {
            let _ = self.0.write_tls(out);
        }
    }

    fn read_plaintext(&mut self, dst: &mut [u8]) -> Result<usize> {
        use std::io::Read;
        match self.0.reader().read(dst) {
            Ok(n) => Ok(n),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(crate::error::Error::Io(e)),
        }
    }

    fn write_plaintext(&mut self, plaintext: &[u8]) {
        use std::io::Write;
        // Buffered into the engine; emitted as ciphertext by `drain_outgoing`.
        let _ = self.0.writer().write_all(plaintext);
    }

    fn tls_params(&self) -> TlsParams {
        use crate::tls::ProtocolVersion;
        TlsParams {
            version: self.0.protocol_version().map(|v| match v {
                rustls::ProtocolVersion::TLSv1_2 => ProtocolVersion::TLSv1_2,
                rustls::ProtocolVersion::TLSv1_3 => ProtocolVersion::TLSv1_3,
                other => ProtocolVersion::Other(u16::from(other)),
            }),
            cipher_suite: self
                .0
                .negotiated_cipher_suite()
                .map(|cs| u16::from(cs.suite())),
            alpn: self.0.alpn_protocol().map(|p| p.to_vec()),
            peer_certificates: self
                .0
                .peer_certificates()
                .map(|certs| certs.iter().map(|c| c.to_vec()).collect())
                .unwrap_or_default(),
        }
    }
}

/// The real [`TlsEngine`] over purecrypto's sans-IO `Connection`. Available with
/// the `purecrypto-tls` backend (the default). Unlike rustls, purecrypto's
/// handshake is *advanced* by `feed` (which runs `process_new_packets` and
/// queues the next flight) and *reported* by `handshake()` — so we feed, then
/// refresh a cached completion flag, and never loop on `handshake()` (which
/// would spin on `WantWrite` since it only reports queued output).
#[cfg(feature = "purecrypto-tls")]
pub(crate) struct PurecryptoEngine {
    conn: purecrypto::tls::Connection,
    /// Inbound wire that `feed` did not consume yet (it takes only a prefix).
    pending_wire: Vec<u8>,
    /// Decrypted plaintext pulled from `recv` but not yet handed out.
    plaintext: Vec<u8>,
    done: bool,
}

#[cfg(feature = "purecrypto-tls")]
fn pc_err(e: impl std::fmt::Debug) -> crate::error::Error {
    crate::error::Error::Io(std::io::Error::other(format!("tls: {e:?}")))
}

#[cfg(feature = "purecrypto-tls")]
impl PurecryptoEngine {
    pub(crate) fn new(conn: purecrypto::tls::Connection) -> Result<PurecryptoEngine> {
        // `Connection::client` already queues the ClientHello, popped by the
        // first `drain_outgoing`; nothing to pump here.
        let mut e = PurecryptoEngine {
            conn,
            pending_wire: Vec::new(),
            plaintext: Vec::new(),
            done: false,
        };
        e.refresh_done()?;
        Ok(e)
    }

    /// Update the cached handshake-completion flag from the engine's status.
    fn refresh_done(&mut self) -> Result<()> {
        if matches!(
            self.conn.handshake().map_err(pc_err)?,
            purecrypto::tls::HandshakeStatus::Complete
        ) {
            self.done = true;
        }
        Ok(())
    }
}

#[cfg(feature = "purecrypto-tls")]
impl TlsEngine for PurecryptoEngine {
    fn is_handshaking(&self) -> bool {
        !self.done
    }

    fn feed_incoming(&mut self, ciphertext: &[u8]) -> Result<()> {
        // `feed` consumes only a prefix per call; buffer any unconsumed tail and
        // retry it (prepended) on the next inbound bytes.
        self.pending_wire.extend_from_slice(ciphertext);
        let mut taken = 0;
        while taken < self.pending_wire.len() {
            let n = self
                .conn
                .feed(&self.pending_wire[taken..])
                .map_err(pc_err)?;
            if n == 0 {
                break;
            }
            taken += n;
        }
        self.pending_wire.drain(..taken);
        // `feed` advanced the handshake and may have queued our next flight.
        self.refresh_done()?;
        Ok(())
    }

    fn drain_outgoing(&mut self, out: &mut Vec<u8>) {
        loop {
            match self.conn.pop() {
                Ok(rec) if rec.is_empty() => break,
                Ok(rec) => out.extend_from_slice(&rec),
                // A pop error means the engine is broken; the next fallible call
                // (feed/recv) surfaces the real error.
                Err(_) => break,
            }
        }
    }

    fn read_plaintext(&mut self, dst: &mut [u8]) -> Result<usize> {
        if self.plaintext.is_empty() {
            let app = self.conn.recv().map_err(pc_err)?;
            self.plaintext.extend_from_slice(&app);
        }
        let n = dst.len().min(self.plaintext.len());
        dst[..n].copy_from_slice(&self.plaintext[..n]);
        self.plaintext.drain(..n);
        Ok(n)
    }

    fn write_plaintext(&mut self, plaintext: &[u8]) {
        let _ = self.conn.send(plaintext);
    }

    fn tls_params(&self) -> TlsParams {
        use crate::tls::ProtocolVersion;
        TlsParams {
            version: self.conn.negotiated_version().map(|v| match v {
                purecrypto::tls::ProtocolVersion::TLSv1_2 => ProtocolVersion::TLSv1_2,
                purecrypto::tls::ProtocolVersion::TLSv1_3 => ProtocolVersion::TLSv1_3,
                other => ProtocolVersion::Other(other.as_u16()),
            }),
            cipher_suite: self.conn.negotiated_cipher_suite(),
            alpn: self.conn.alpn_selected().map(|p| p.to_vec()),
            peer_certificates: self.conn.peer_certificates().to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::http1::{ClientExchange, Event};

    /// A deterministic stand-in for a real TLS engine used to prove the
    /// *layering* logic without a crypto handshake. "Encryption" is identity:
    /// ciphertext == plaintext. The handshake is a single round trip: the client
    /// emits `CHLO`, and becomes established once it has seen `SHLO`.
    #[derive(Default)]
    struct MockTls {
        sent_hello: bool,
        established: bool,
        outbox: Vec<u8>,
        plaintext_in: Vec<u8>,
    }

    impl TlsEngine for MockTls {
        fn is_handshaking(&self) -> bool {
            !self.established
        }

        fn feed_incoming(&mut self, ciphertext: &[u8]) -> Result<()> {
            if !self.established {
                // The handshake reply (possibly with trailing app data).
                if let Some(rest) = strip_prefix(ciphertext, b"SHLO") {
                    self.established = true;
                    self.plaintext_in.extend_from_slice(rest);
                }
            } else {
                self.plaintext_in.extend_from_slice(ciphertext);
            }
            Ok(())
        }

        fn drain_outgoing(&mut self, out: &mut Vec<u8>) {
            if !self.sent_hello {
                out.extend_from_slice(b"CHLO");
                self.sent_hello = true;
            }
            out.append(&mut self.outbox);
        }

        fn read_plaintext(&mut self, dst: &mut [u8]) -> Result<usize> {
            let n = dst.len().min(self.plaintext_in.len());
            dst[..n].copy_from_slice(&self.plaintext_in[..n]);
            self.plaintext_in.drain(..n);
            Ok(n)
        }

        fn write_plaintext(&mut self, plaintext: &[u8]) {
            self.outbox.extend_from_slice(plaintext); // identity "encryption"
        }

        fn tls_params(&self) -> TlsParams {
            TlsParams::default() // the mock negotiates nothing
        }
    }

    fn strip_prefix<'a>(buf: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
        buf.starts_with(prefix).then(|| &buf[prefix.len()..])
    }

    fn request() -> Vec<u8> {
        ClientExchange::encode_request("GET", "/", &[("Host".into(), "x".into())], b"")
    }

    #[test]
    fn layered_handshake_then_request_then_response() {
        let mut tls = TlsClient::new(MockTls::default(), ClientExchange::new("GET", request()));

        // 1. First transmit: the handshake ClientHello, no request yet.
        let mut out = Vec::new();
        assert!(tls.poll_transmit(&mut out));
        assert_eq!(out, b"CHLO");

        // 2. Server responds to the handshake; now established.
        tls.handle_input(b"SHLO").unwrap();

        // 3. Next transmit carries the (identity-"encrypted") HTTP request.
        out.clear();
        assert!(tls.poll_transmit(&mut out));
        assert_eq!(out, request());

        // 4. Feed the encrypted HTTP response; the inner machine decodes it.
        tls.handle_input(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
            .unwrap();
        let Event::Response { head, body } = tls.poll_event().expect("response");
        assert_eq!(head.status, 200);
        assert_eq!(body, b"hi");
        assert!(tls.is_finished());
    }

    #[test]
    fn handshake_reply_may_carry_app_data() {
        // A server that flights its response together with the handshake reply.
        let mut tls = TlsClient::new(MockTls::default(), ClientExchange::new("GET", request()));
        let mut out = Vec::new();
        tls.poll_transmit(&mut out); // CHLO
        tls.handle_input(b"SHLOHTTP/1.1 204 No Content\r\n\r\n")
            .unwrap();
        let Event::Response { head, .. } = tls.poll_event().expect("response");
        assert_eq!(head.status, 204);
    }

    #[test]
    fn drives_through_the_real_blocking_driver() {
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};
        use std::thread;

        // A server speaking the mock "TLS" handshake then a plain HTTP reply.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let Ok((mut sock, _)) = listener.accept() else {
                return;
            };
            // Expect CHLO, answer SHLO.
            let mut hello = [0u8; 4];
            if sock.read_exact(&mut hello).is_err() || &hello != b"CHLO" {
                return;
            }
            let _ = sock.write_all(b"SHLO");
            // Read the (identity-encrypted) request head, then reply.
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            while sock.read(&mut byte).map(|n| n == 1).unwrap_or(false) {
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
        });

        let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mut tls = TlsClient::new(MockTls::default(), ClientExchange::new("GET", request()));
        let events = crate::io::blocking::drive(&mut tls, &mut sock).unwrap();

        assert_eq!(events.len(), 1);
        let Event::Response { head, body } = &events[0];
        assert_eq!(head.status, 200);
        assert_eq!(body, b"hello");
    }
}

/// Real-crypto proof for [`RustlsEngine`]: a full in-memory rustls handshake
/// (client engine ↔ server engine, no socket) carrying an HTTP/1.1 exchange
/// through the layered [`TlsClient`]. The test cert/key are an `openssl`-
/// generated self-signed pair valid until 2126 (embedded, so no cert-gen
/// dependency and no C toolchain — respecting the crate's no-C guarantee).
#[cfg(all(test, feature = "rustls-tls"))]
pub(crate) mod rustls_tests {
    use std::io::{Read, Write};
    use std::sync::Arc;

    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};

    use super::*;
    use crate::proto::http1::{ClientExchange, Event};

    // A test CA (trusted by the client) and a `localhost` leaf signed by it
    // (presented by the server). Using the CA cert itself as an end-entity is
    // rejected by webpki (`CaUsedAsEndEntity`), so a real chain is required.
    pub(super) const CA_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
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

    pub(crate) fn server_config() -> Arc<ServerConfig> {
        let certs = rustls_pemfile::certs(&mut LEAF_CERT_PEM.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        let key = rustls_pemfile::private_key(&mut LEAF_KEY_PEM.as_bytes())
            .unwrap()
            .unwrap();
        Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap(),
        )
    }

    fn client_conn() -> ClientConnection {
        let mut roots = RootCertStore::empty();
        for c in rustls_pemfile::certs(&mut CA_CERT_PEM.as_bytes()) {
            roots.add(c.unwrap()).unwrap();
        }
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = ServerName::try_from("localhost").unwrap();
        ClientConnection::new(Arc::new(config), name).unwrap()
    }

    #[test]
    fn real_rustls_handshake_carries_http_exchange() {
        let req =
            ClientExchange::encode_request("GET", "/", &[("Host".into(), "localhost".into())], b"");
        let mut client =
            TlsClient::new(RustlsEngine(client_conn()), ClientExchange::new("GET", req));
        let mut server = ServerConnection::new(server_config()).unwrap();

        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nhello rustls";
        let mut server_req = Vec::new();
        let mut replied = false;

        // Shuttle ciphertext both ways until the client decodes the response.
        for _ in 0..64 {
            // client -> server
            let mut c2s = Vec::new();
            while client.poll_transmit(&mut c2s) {}
            let mut cur = &c2s[..];
            while !cur.is_empty() {
                let used = server.read_tls(&mut cur).unwrap();
                if used == 0 {
                    break;
                }
                server.process_new_packets().unwrap();
            }

            // Server app logic: collect the request, reply once it's complete.
            if !server.is_handshaking() {
                let mut tmp = [0u8; 4096];
                loop {
                    match server.reader().read(&mut tmp) {
                        Ok(0) => break,
                        Ok(n) => server_req.extend_from_slice(&tmp[..n]),
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => panic!("server read: {e}"),
                    }
                }
                if !replied && server_req.windows(4).any(|w| w == b"\r\n\r\n") {
                    server.writer().write_all(response).unwrap();
                    replied = true;
                }
            }

            // server -> client
            let mut s2c = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut s2c).unwrap();
            }
            if !s2c.is_empty() {
                client.handle_input(&s2c).unwrap();
            }

            if let Some(Event::Response { head, body }) = client.poll_event() {
                assert_eq!(head.status, 200);
                assert_eq!(body, b"hello rustls");
                return;
            }
        }
        panic!("TLS exchange did not complete within the iteration budget");
    }
}

/// Real-engine proof for [`PurecryptoEngine`] that needs no peer: a genuine
/// purecrypto client emits a well-formed TLS ClientHello through the adapter.
/// Covers the purecrypto-only lanes (http-only / default); the full handshake
/// is proven cross-backend against a rustls server when both backends are on.
#[cfg(all(test, feature = "purecrypto-tls"))]
mod purecrypto_tests {
    use super::*;

    #[test]
    fn purecrypto_adapter_emits_client_hello() {
        let cfg = purecrypto::tls::Config::builder()
            .roots(purecrypto::tls::RootCertStore::new())
            .server_name("localhost")
            .rng(std::sync::Arc::new(purecrypto::rng::OsRng))
            .build();
        let conn = purecrypto::tls::Connection::client(&cfg).unwrap();
        let mut eng = PurecryptoEngine::new(conn).unwrap();

        assert!(eng.is_handshaking());
        let mut out = Vec::new();
        eng.drain_outgoing(&mut out);
        // TLS record: content type 0x16 (handshake); first handshake message
        // (byte 5, after the 5-byte record header) is 0x01 (ClientHello).
        assert!(out.len() > 5, "expected a ClientHello record");
        assert_eq!(out[0], 0x16, "record content type should be handshake");
        assert_eq!(out[5], 0x01, "handshake message type should be ClientHello");
    }
}

/// Cross-backend interop proof: a real purecrypto **client** ([`PurecryptoEngine`])
/// completes a full TLS handshake against a real rustls **server** and carries an
/// HTTP/1.1 exchange through the layered [`TlsClient`] — entirely in memory.
/// Runs only when both backends are compiled (the `--all-features` CI lane), and
/// doubles as a cross-stack interoperability check.
#[cfg(all(test, feature = "purecrypto-tls", feature = "rustls-tls"))]
mod cross_backend_tests {
    use std::io::{Read, Write};

    use rustls::ServerConnection;

    use super::*;
    use crate::proto::http1::{ClientExchange, Event};

    #[test]
    fn purecrypto_client_against_rustls_server() {
        // purecrypto client trusting the test CA.
        let mut roots = purecrypto::tls::RootCertStore::new();
        roots.add_pem(super::rustls_tests::CA_CERT_PEM).unwrap();
        let cfg = purecrypto::tls::Config::builder()
            .roots(roots)
            .server_name("localhost")
            .rng(std::sync::Arc::new(purecrypto::rng::OsRng))
            .build();
        let client_conn = purecrypto::tls::Connection::client(&cfg).unwrap();

        let req =
            ClientExchange::encode_request("GET", "/", &[("Host".into(), "localhost".into())], b"");
        let mut client = TlsClient::new(
            PurecryptoEngine::new(client_conn).unwrap(),
            ClientExchange::new("GET", req),
        );
        let mut server = ServerConnection::new(super::rustls_tests::server_config()).unwrap();

        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\ninterop ok";
        let mut server_req = Vec::new();
        let mut replied = false;

        for _ in 0..64 {
            // client -> server
            let mut c2s = Vec::new();
            while client.poll_transmit(&mut c2s) {}
            let mut cur = &c2s[..];
            while !cur.is_empty() {
                let used = server.read_tls(&mut cur).unwrap();
                if used == 0 {
                    break;
                }
                server.process_new_packets().unwrap();
            }

            if !server.is_handshaking() {
                let mut tmp = [0u8; 4096];
                loop {
                    match server.reader().read(&mut tmp) {
                        Ok(0) => break,
                        Ok(n) => server_req.extend_from_slice(&tmp[..n]),
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => panic!("server read: {e}"),
                    }
                }
                if !replied && server_req.windows(4).any(|w| w == b"\r\n\r\n") {
                    server.writer().write_all(response).unwrap();
                    replied = true;
                }
            }

            // server -> client
            let mut s2c = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut s2c).unwrap();
            }
            if !s2c.is_empty() {
                client.handle_input(&s2c).unwrap();
            }

            if let Some(Event::Response { head, body }) = client.poll_event() {
                assert_eq!(head.status, 200);
                assert_eq!(body, b"interop ok");
                return;
            }
        }
        panic!("cross-backend TLS exchange did not complete");
    }
}

/// Connect-wiring proof: the real backend config path
/// (`crate::tls::build_client_engine`) yields a working sans-IO engine that
/// completes a TLS handshake and carries an HTTP/1.1 exchange through
/// [`TlsClient`] against an in-memory rustls server. Under `--all-features` the
/// active backend is rustls, so this exercises [`RustlsEngine`] end to end from
/// the crate's own configuration code.
#[cfg(all(test, feature = "rustls-tls"))]
mod connect_wiring_tests {
    use std::io::{Read, Write};

    use rustls::ServerConnection;

    use super::*;
    use crate::proto::http1::{ClientExchange, Event};

    #[test]
    fn engine_from_build_client_engine_completes_handshake() {
        // `-k`-style: skip chain validation so the test need not thread the test
        // CA into TlsOpts roots; we are proving construction + drive, not the
        // (separately tested) verifier. Supply an explicit (empty) root store so
        // construction does not fall back to `load_system_roots()`, which is
        // Unix-only in the rustls backend and would fail on Windows CI.
        let mut opts = crate::tls::TlsOpts::verifying();
        opts.verify = false;
        opts.roots = Some(rustls::RootCertStore::empty());
        let engine = crate::tls::build_client_engine("localhost", &mut opts).unwrap();

        let req =
            ClientExchange::encode_request("GET", "/", &[("Host".into(), "localhost".into())], b"");
        let mut client = TlsClient::new(engine, ClientExchange::new("GET", req));
        let mut server = ServerConnection::new(super::rustls_tests::server_config()).unwrap();

        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nwired";
        let mut server_req = Vec::new();
        let mut replied = false;
        for _ in 0..64 {
            let mut c2s = Vec::new();
            while client.poll_transmit(&mut c2s) {}
            let mut cur = &c2s[..];
            while !cur.is_empty() {
                let used = server.read_tls(&mut cur).unwrap();
                if used == 0 {
                    break;
                }
                server.process_new_packets().unwrap();
            }
            if !server.is_handshaking() {
                let mut tmp = [0u8; 4096];
                loop {
                    match server.reader().read(&mut tmp) {
                        Ok(0) => break,
                        Ok(n) => server_req.extend_from_slice(&tmp[..n]),
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => panic!("server read: {e}"),
                    }
                }
                if !replied && server_req.windows(4).any(|w| w == b"\r\n\r\n") {
                    server.writer().write_all(response).unwrap();
                    replied = true;
                }
            }
            let mut s2c = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut s2c).unwrap();
            }
            if !s2c.is_empty() {
                client.handle_input(&s2c).unwrap();
            }
            if let Some(Event::Response { head, body }) = client.poll_event() {
                assert_eq!(head.status, 200);
                assert_eq!(body, b"wired");
                return;
            }
        }
        panic!("handshake/exchange did not complete");
    }
}

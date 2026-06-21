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
//! This module lands the composition and proves it end-to-end (including
//! through the real blocking driver) with a deterministic mock engine. The
//! rustls/purecrypto [`TlsEngine`] adapters and the wiring into the connect path
//! are the next increment.

use std::time::Instant;

use crate::error::Result;
use crate::io::Machine;

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

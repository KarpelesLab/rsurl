//! A persistent async TLS stream: plaintext [`AsyncConn`] over an encrypted one.
//!
//! The [`asyncio`](super::asyncio) driver runs a [`Machine`](super::Machine) to
//! *completion* (one request/response), which is the right shape for HTTP but
//! not for a long-lived duplex like a WebSocket. This wraps the same sans-IO TLS
//! engine ([`TlsEngine`]) the [`TlsClient`](crate::proto::tls::TlsClient) machine
//! uses, but exposes it as a *persistent* [`AsyncConn`]: run the handshake once,
//! then read/write application plaintext for as long as the connection lives.
//!
//! It is itself an [`AsyncConn`], so anything that speaks that trait (the async
//! WebSocket in `crate::aio`) can run over `wss://` exactly as it runs over a
//! plain socket.

use std::io;

use crate::error::Result;
use crate::io::runtime::AsyncConn;
use crate::proto::tls::TlsEngine;
use crate::tls::ClientEngine;

/// Map a crate error surfaced by the TLS engine into an [`io::Error`], so the
/// [`AsyncConn`] surface stays `io`-typed like a real socket.
fn to_io(e: crate::error::Error) -> io::Error {
    io::Error::other(e.to_string())
}

/// An async, plaintext byte stream layered on the encrypted `conn`.
pub(crate) struct AsyncTlsStream<C> {
    conn: C,
    engine: ClientEngine,
    /// Scratch for inbound ciphertext reads.
    inbuf: Vec<u8>,
}

impl<C: AsyncConn> AsyncTlsStream<C> {
    /// Wrap `conn`, driving the TLS handshake for server name `sni` to
    /// completion before returning. `opts` carries verification settings.
    pub(crate) async fn connect(
        mut conn: C,
        sni: &str,
        opts: &mut crate::tls::TlsOpts,
    ) -> Result<AsyncTlsStream<C>> {
        let mut engine = crate::tls::build_client_engine(sni, opts)?;
        let mut inbuf = vec![0u8; 16 * 1024];

        // Standard sans-IO handshake pump: flush whatever the engine wants to
        // send, stop once it is no longer handshaking, otherwise feed it the
        // next inbound flight.
        loop {
            let mut out = Vec::new();
            engine.drain_outgoing(&mut out);
            if !out.is_empty() {
                conn.write_all(&out).await?;
                conn.flush().await?;
            }
            if !engine.is_handshaking() {
                break;
            }
            let n = conn.read(&mut inbuf).await?;
            if n == 0 {
                return Err(crate::error::Error::UnexpectedEof);
            }
            engine.feed_incoming(&inbuf[..n])?;
        }

        Ok(AsyncTlsStream {
            conn,
            engine,
            inbuf,
        })
    }
}

impl<C: AsyncConn> AsyncConn for AsyncTlsStream<C> {
    async fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        loop {
            // Drain already-decrypted plaintext first.
            let n = self.engine.read_plaintext(dst).map_err(to_io)?;
            if n > 0 {
                return Ok(n);
            }
            // None buffered — pull more ciphertext and decrypt it.
            let m = self.conn.read(&mut self.inbuf).await?;
            if m == 0 {
                return Ok(0); // peer closed the underlying connection
            }
            let chunk = self.inbuf[..m].to_vec();
            self.engine.feed_incoming(&chunk).map_err(to_io)?;
            // Feeding may have produced records to send (e.g. a TLS 1.3
            // post-handshake message or key update) — flush them.
            let mut out = Vec::new();
            self.engine.drain_outgoing(&mut out);
            if !out.is_empty() {
                self.conn.write_all(&out).await?;
                self.conn.flush().await?;
            }
        }
    }

    async fn write_all(&mut self, src: &[u8]) -> io::Result<()> {
        self.engine.write_plaintext(src);
        let mut out = Vec::new();
        self.engine.drain_outgoing(&mut out);
        if !out.is_empty() {
            self.conn.write_all(&out).await?;
        }
        Ok(())
    }

    async fn flush(&mut self) -> io::Result<()> {
        let mut out = Vec::new();
        self.engine.drain_outgoing(&mut out);
        if !out.is_empty() {
            self.conn.write_all(&out).await?;
        }
        self.conn.flush().await
    }
}

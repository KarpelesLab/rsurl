//! Native async WebSocket for [`crate::aio`], the counterpart of the browser
//! [`wasm`](super::wasm) one.
//!
//! It runs over any [`AsyncConn`] a [`Runtime`] hands back: `ws://` directly, and
//! `wss://` through the persistent [`AsyncTlsStream`](crate::io::asynctls) TLS
//! duplex. The RFC 6455 frame codec (masking, parsing, control-frame rules) and
//! the handshake-response validation are shared with the blocking
//! [`crate::websocket`] implementation — this module only supplies the async I/O
//! loop around them.
//!
//! Scope of this cut: text/binary messages (fragmented or whole), automatic
//! ping→pong and close handling, arbitrary subprotocols. It deliberately does
//! **not** offer permessage-deflate (RFC 7692), so messages are uncompressed —
//! matching the browser path, where compression is the browser's business. The
//! thread-split reader/writer of the blocking API (`WsReader`/`WsWriter`) is not
//! reproduced here; a single [`WebSocket`] owns the connection.
//!
//! # Cancellation
//!
//! [`recv`](WebSocket::recv) is cancel-safe provided the connection's own
//! `read` is (as Tokio's is): a partly reassembled message lives on the
//! `WebSocket`, not in the future, so dropping a `recv` (a `select!` branch
//! losing, a timeout) loses nothing and the next `recv` carries on. Writes are
//! not resumable — [`AsyncConn::write_all`] cannot report how much of a frame
//! reached the wire — so a send (or the automatic pong/close echo inside
//! `recv`) that is dropped mid-write, or that fails, leaves the connection
//! unusable: every later operation returns an error rather than risk putting a
//! half frame on the wire.

use std::fmt;
use std::io;

use crate::error::{Error, Result};
use crate::io::runtime::{AsyncConn, Runtime};
use crate::url::Url;
use crate::websocket::{
    accumulate, bad_close_error, base64_encode, build_client_frame, check_handshake_response,
    close_echo_payload, close_payload, parse_close_payload, random_16, subprotocol_header,
    try_parse_frame, validate_control_frame, Frame, CLOSE_INVALID_DATA, HANDSHAKE_DEADLINE,
    OPCODE_BINARY, OPCODE_CLOSE, OPCODE_CONT, OPCODE_PING, OPCODE_PONG, OPCODE_TEXT,
};

use super::WsMessage;

#[cfg(any(feature = "rustls-tls", feature = "purecrypto-tls"))]
use crate::io::asynctls::AsyncTlsStream;

/// Cap on the handshake response header block, to bound memory on a hostile or
/// broken server that never terminates the headers.
const MAX_HANDSHAKE_HEAD: usize = 64 * 1024;

/// The plaintext transport under the WebSocket framing: a bare async socket for
/// `ws://`, or an async TLS stream for `wss://`. Both are [`AsyncConn`], and so
/// is this enum, so the frame loop is transport-agnostic.
enum Transport<C> {
    Plain(C),
    // Boxed: the TLS engine is far larger than a bare socket, so an unboxed
    // variant would bloat every `Plain` connection too (clippy::large_enum_variant).
    #[cfg(any(feature = "rustls-tls", feature = "purecrypto-tls"))]
    Tls(Box<AsyncTlsStream<C>>),
}

impl<C: AsyncConn> AsyncConn for Transport<C> {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Transport::Plain(c) => c.read(buf).await,
            #[cfg(any(feature = "rustls-tls", feature = "purecrypto-tls"))]
            Transport::Tls(t) => t.read(buf).await,
        }
    }

    async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        match self {
            Transport::Plain(c) => c.write_all(buf).await,
            #[cfg(any(feature = "rustls-tls", feature = "purecrypto-tls"))]
            Transport::Tls(t) => t.write_all(buf).await,
        }
    }

    async fn flush(&mut self) -> io::Result<()> {
        match self {
            Transport::Plain(c) => c.flush().await,
            #[cfg(any(feature = "rustls-tls", feature = "purecrypto-tls"))]
            Transport::Tls(t) => t.flush().await,
        }
    }
}

/// A fragmented data message whose FIN frame has not arrived yet.
struct Partial {
    opcode: u8,
    buf: Vec<u8>,
}

/// An async WebSocket client over a [`Runtime`]'s connection. The native
/// counterpart of the browser WebSocket (the wasm build's `aio::WebSocket`):
/// the same `send`/`send_text`/`send_binary`/`recv`/`close`/`close_with`/
/// `subprotocol`/`is_closed` surface, with the same `async`-ness and receivers,
/// so only the [`connect`](WebSocket::connect) call — which takes a `Runtime`,
/// since there is no implicit event loop natively — differs between targets.
///
/// # Cancellation
///
/// [`recv`](WebSocket::recv) is cancel-safe provided the connection's own
/// `read` is (as Tokio's is): a partly reassembled message lives on the
/// `WebSocket`, not in the future, so dropping a `recv` (a `select!` branch
/// losing, a timeout) loses nothing and the next `recv` carries on. Writes are
/// not resumable, so a send (or the automatic pong/close echo inside `recv`)
/// that is dropped mid-write, or that fails, leaves the connection unusable:
/// every later operation returns an error rather than risk putting a half
/// frame on the wire.
///
/// Dropping the socket drops the underlying connection without a close
/// handshake; call [`close`](Self::close) for a polite shutdown.
pub struct WebSocket<C> {
    transport: Transport<C>,
    /// Unparsed inbound bytes carried between reads (frames are only consumed
    /// once whole — see [`try_parse_frame`]).
    rxbuf: Vec<u8>,
    /// The message being reassembled, kept here (not in a `recv` future) so a
    /// cancelled `recv` does not lose fragments.
    partial: Option<Partial>,
    closed: bool,
    /// Set while a frame write is in flight and left set if it fails or its
    /// future is dropped: the wire may then hold a partial frame, so the
    /// connection must not be written again.
    write_poisoned: bool,
    subprotocol: Option<String>,
}

impl<C> fmt::Debug for WebSocket<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebSocket")
            .field("closed", &self.closed)
            .field("subprotocol", &self.subprotocol)
            .field("buffered", &self.rxbuf.len())
            .finish_non_exhaustive()
    }
}

impl<C: AsyncConn> WebSocket<C> {
    /// Open a WebSocket to `url` (`ws://` or `wss://`) over `rt`, running the
    /// HTTP/1.1 Upgrade handshake before returning.
    pub async fn connect<R>(rt: &R, url: &str) -> Result<WebSocket<C>>
    where
        R: Runtime<Conn = C>,
    {
        Self::connect_with_subprotocols(rt, url, &[]).await
    }

    /// Open a WebSocket requesting the given `subprotocols` (sent as
    /// `Sec-WebSocket-Protocol`, preference order). See [`connect`](Self::connect).
    ///
    /// Each subprotocol must be an HTTP token. The connection fails if the
    /// server selects a subprotocol that was not offered. Connecting,
    /// including the TLS and upgrade handshakes, is bounded by a 60 s
    /// deadline so a server that trickles its response cannot stall forever.
    pub async fn connect_with_subprotocols<R>(
        rt: &R,
        url: &str,
        subprotocols: &[&str],
    ) -> Result<WebSocket<C>>
    where
        R: Runtime<Conn = C>,
    {
        let u = Url::parse(url)?;
        let subs: Vec<String> = subprotocols.iter().map(|s| s.to_string()).collect();
        // Validate before touching the network.
        let proto_header = subprotocol_header(&subs)?;

        super::native::with_timeout(rt, Some(HANDSHAKE_DEADLINE), async {
            let conn = super::native::connect(rt, &u.host, u.port).await?;

            let transport = match u.scheme.as_str() {
                "ws" => Transport::Plain(conn),
                "wss" => {
                    #[cfg(any(feature = "rustls-tls", feature = "purecrypto-tls"))]
                    {
                        let mut opts = crate::tls::TlsOpts::verifying();
                        let tls = AsyncTlsStream::connect(conn, &u.host, &mut opts).await?;
                        Transport::Tls(Box::new(tls))
                    }
                    #[cfg(not(any(feature = "rustls-tls", feature = "purecrypto-tls")))]
                    {
                        let _ = conn;
                        return Err(Error::UnsupportedScheme(
                            "wss (no TLS backend compiled)".into(),
                        ));
                    }
                }
                other => return Err(Error::UnsupportedScheme(other.to_string())),
            };

            let mut ws = WebSocket::new(transport);
            ws.handshake(&u, &subs, &proto_header).await?;
            Ok(ws)
        })
        .await
    }

    fn new(transport: Transport<C>) -> WebSocket<C> {
        WebSocket {
            transport,
            rxbuf: Vec::new(),
            partial: None,
            closed: false,
            write_poisoned: false,
            subprotocol: None,
        }
    }

    /// The subprotocol the server selected, or `None`.
    pub fn subprotocol(&self) -> Option<&str> {
        self.subprotocol.as_deref()
    }

    /// Whether a close has been observed or sent (or the peer hung up).
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Receive the next message, or `None` once the connection has closed
    /// cleanly. A protocol/IO error is returned as `Some(Err(..))`.
    ///
    /// Cancel-safe (see [`WebSocket`]'s *Cancellation* notes).
    pub async fn recv(&mut self) -> Option<Result<WsMessage>> {
        match self.recv_inner().await {
            Ok(Some(m)) => Some(Ok(m)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }

    /// Send a text message.
    pub async fn send_text(&mut self, text: &str) -> Result<()> {
        self.send_data(OPCODE_TEXT, text.as_bytes()).await
    }

    /// Send a binary message.
    pub async fn send_binary(&mut self, data: &[u8]) -> Result<()> {
        self.send_data(OPCODE_BINARY, data).await
    }

    /// Send a [`WsMessage`].
    pub async fn send(&mut self, msg: &WsMessage) -> Result<()> {
        match msg {
            WsMessage::Text(t) => self.send_text(t).await,
            WsMessage::Binary(b) => self.send_binary(b).await,
        }
    }

    /// Send a close frame (no status code) and mark the socket closed.
    /// Idempotent: closing an already-closed socket is a no-op.
    pub async fn close(&mut self) -> Result<()> {
        self.send_close(&[]).await
    }

    /// Send a close frame carrying a status code and reason (RFC 6455 §5.5.1),
    /// then mark the socket closed. Idempotent. `code` is typically 1000
    /// (normal closure) and must be one that may appear on the wire
    /// (1000-1003, 1007-1014, 3000-4999); the reason plus the 2-byte code must
    /// fit in a control frame (≤ 125 bytes).
    pub async fn close_with(&mut self, code: u16, reason: &str) -> Result<()> {
        let payload = close_payload(code, reason)?;
        self.send_close(&payload).await
    }

    // ── internals ────────────────────────────────────────────────────────────

    /// Write one whole frame and flush it. Poisons the connection for the
    /// duration, so a failed or cancelled write leaves it unusable (see
    /// [`write_poisoned`](Self::write_poisoned)).
    async fn write_frame(&mut self, frame: &[u8]) -> Result<()> {
        if self.write_poisoned {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "websocket: connection unusable after an interrupted or failed write",
            )));
        }
        self.write_poisoned = true;
        self.transport.write_all(frame).await.map_err(Error::Io)?;
        self.transport.flush().await.map_err(Error::Io)?;
        self.write_poisoned = false;
        Ok(())
    }

    async fn send_close(&mut self, payload: &[u8]) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        // Mark closed up front: a write failure still means this socket is done,
        // and a retry would only send a second CLOSE.
        self.closed = true;
        let frame = build_client_frame(OPCODE_CLOSE, payload)?;
        self.write_frame(&frame).await
    }

    async fn send_data(&mut self, opcode: u8, payload: &[u8]) -> Result<()> {
        // Nothing may follow a close frame on the wire (RFC 6455 §5.5.1).
        if self.closed {
            return Err(Error::BadResponse(
                "websocket: the connection is closed".into(),
            ));
        }
        let frame = build_client_frame(opcode, payload)?;
        self.write_frame(&frame).await
    }

    /// _Fail the WebSocket Connection_ (RFC 6455 §7.1.7): mark it closed and
    /// send a close frame with `status`, best-effort.
    async fn fail(&mut self, status: u16) {
        if self.closed {
            return;
        }
        self.closed = true;
        if let Ok(frame) =
            close_payload(status, "").and_then(|p| build_client_frame(OPCODE_CLOSE, &p))
        {
            let _ = self.write_frame(&frame).await;
        }
    }

    /// Reassemble one application message, answering pings and honouring close.
    async fn recv_inner(&mut self) -> Result<Option<WsMessage>> {
        if self.closed {
            return Ok(None);
        }
        loop {
            let frame = self.next_frame().await?;
            match frame.opcode {
                OPCODE_PING => {
                    validate_control_frame(&frame)?;
                    let pong = build_client_frame(OPCODE_PONG, &frame.payload)?;
                    self.write_frame(&pong).await?;
                }
                OPCODE_PONG => validate_control_frame(&frame)?,
                OPCODE_CLOSE => {
                    validate_control_frame(&frame)?;
                    return match parse_close_payload(&frame.payload) {
                        Ok(close) => {
                            // Echo the peer's status code; ignore failure, we're
                            // closing anyway.
                            self.closed = true;
                            let echo = close_echo_payload(close.as_ref());
                            if let Ok(frame) = build_client_frame(OPCODE_CLOSE, &echo) {
                                let _ = self.write_frame(&frame).await;
                            }
                            Ok(None)
                        }
                        Err(status) => {
                            self.fail(status).await;
                            Err(bad_close_error(status))
                        }
                    };
                }
                OPCODE_TEXT | OPCODE_BINARY => {
                    if self.partial.is_some() {
                        return Err(Error::BadResponse(
                            "new data frame began before the previous message finished".into(),
                        ));
                    }
                    if frame.rsv1 {
                        return Err(Error::BadResponse(
                            "RSV1 set but permessage-deflate was not negotiated".into(),
                        ));
                    }
                    if frame.fin {
                        return self.finish(frame.opcode, frame.payload).await.map(Some);
                    }
                    self.partial = Some(Partial {
                        opcode: frame.opcode,
                        buf: frame.payload,
                    });
                }
                OPCODE_CONT => {
                    let Some(partial) = self.partial.as_mut() else {
                        return Err(Error::BadResponse(
                            "CONTINUATION frame without a start frame".into(),
                        ));
                    };
                    if frame.rsv1 {
                        return Err(Error::BadResponse(
                            "RSV1 set on a WS continuation frame".into(),
                        ));
                    }
                    // Bound the reassembled message like the blocking client.
                    accumulate(&mut partial.buf, &frame.payload)?;
                    if frame.fin {
                        let done = self.partial.take().expect("checked above");
                        return self.finish(done.opcode, done.buf).await.map(Some);
                    }
                }
                other => return Err(Error::BadResponse(format!("unknown WS opcode 0x{other:x}"))),
            }
        }
    }

    /// Turn a complete message into a [`WsMessage`], failing the connection
    /// with 1007 on invalid UTF-8 text (RFC 6455 §8.1).
    async fn finish(&mut self, opcode: u8, payload: Vec<u8>) -> Result<WsMessage> {
        match build_message(opcode, payload) {
            Ok(m) => Ok(m),
            Err(e) => {
                self.fail(CLOSE_INVALID_DATA).await;
                Err(e)
            }
        }
    }

    /// Pull bytes until a whole frame is buffered, then return it. A transport
    /// EOF marks the socket closed before surfacing as an error.
    async fn next_frame(&mut self) -> Result<Frame> {
        let mut tmp = [0u8; 16 * 1024];
        loop {
            if let Some((frame, consumed)) = try_parse_frame(&self.rxbuf)? {
                self.rxbuf.drain(..consumed);
                return Ok(frame);
            }
            let n = self.transport.read(&mut tmp).await.map_err(Error::Io)?;
            if n == 0 {
                self.closed = true;
                return Err(Error::UnexpectedEof);
            }
            self.rxbuf.extend_from_slice(&tmp[..n]);
        }
    }

    /// Send the HTTP/1.1 Upgrade request and validate the `101` response.
    async fn handshake(
        &mut self,
        u: &Url,
        subprotocols: &[String],
        proto_header: &str,
    ) -> Result<()> {
        let key_b64 = base64_encode(&random_16()?);

        let host_header =
            if (u.scheme == "ws" && u.port == 80) || (u.scheme == "wss" && u.port == 443) {
                u.host.clone()
            } else {
                format!("{}:{}", u.host, u.port)
            };
        let path = if u.path.is_empty() {
            "/"
        } else {
            u.path.as_str()
        };

        // No `Sec-WebSocket-Extensions`: we do not offer permessage-deflate.
        let req = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {host_header}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {key_b64}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             {proto_header}\
             \r\n"
        );
        self.write_frame(req.as_bytes()).await?;

        let head = self.read_handshake_head().await?;
        let resp = check_handshake_response(&head, &key_b64, subprotocols)?;
        // We offered no extension, so a server that names one is misbehaving.
        if resp.extensions.is_some() {
            return Err(Error::BadResponse(
                "server negotiated a permessage extension that was not offered".into(),
            ));
        }
        self.subprotocol = resp.subprotocol;
        Ok(())
    }

    /// Read response bytes up to and including the `\r\n\r\n` header terminator,
    /// leaving any trailing frame bytes in `rxbuf`.
    async fn read_handshake_head(&mut self) -> Result<Vec<u8>> {
        let mut tmp = [0u8; 4096];
        // Where the terminator search resumes: only the bytes that arrived since
        // the last scan (plus 3 of overlap) are examined, so a server that
        // trickles its headers costs linear rather than quadratic work.
        let mut scanned = 0usize;
        loop {
            if let Some(end) = find_double_crlf(&self.rxbuf, scanned) {
                return Ok(self.rxbuf.drain(..end).collect());
            }
            scanned = self.rxbuf.len();
            let n = self.transport.read(&mut tmp).await.map_err(Error::Io)?;
            if n == 0 {
                return Err(Error::UnexpectedEof);
            }
            self.rxbuf.extend_from_slice(&tmp[..n]);
            if self.rxbuf.len() > MAX_HANDSHAKE_HEAD {
                return Err(Error::BadResponse(
                    "websocket handshake response headers too large".into(),
                ));
            }
        }
    }
}

/// A text opcode yields a UTF-8-validated [`WsMessage::Text`]; anything else a
/// [`WsMessage::Binary`].
fn build_message(opcode: u8, payload: Vec<u8>) -> Result<WsMessage> {
    if opcode == OPCODE_TEXT {
        let s = String::from_utf8(payload)
            .map_err(|_| Error::BadResponse("invalid UTF-8 in text message".into()))?;
        Ok(WsMessage::Text(s))
    } else {
        Ok(WsMessage::Binary(payload))
    }
}

/// Index just past the first `\r\n\r\n` in `buf`, or `None` if absent. Bytes
/// before `from` were already searched, so the scan restarts 3 bytes earlier
/// (a terminator may straddle the old end) instead of from the start.
fn find_double_crlf(buf: &[u8], from: usize) -> Option<usize> {
    let start = from.saturating_sub(3);
    buf.get(start..)?
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| start + i + 4)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::future::Future;
    use std::net::SocketAddr;
    use std::pin::pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};
    use std::time::{Duration, Instant};

    use super::*;
    use crate::websocket::{derive_accept, MAX_PAYLOAD_BYTES};

    /// Builds a reply from everything the client has written so far.
    type Responder = Box<dyn FnMut(&[u8]) -> Vec<u8> + Send>;

    /// Scripted in-memory connection. Reads hand out `inbound` chunks in order;
    /// once they run out a read either reports EOF (`eof`) or stays pending
    /// forever (modelling a quiet peer), which lets a test drop a `recv` future
    /// mid-message. Writes land in the shared `sent` buffer, or pend forever
    /// when `stall_writes` is set.
    #[derive(Default)]
    struct MockConn {
        inbound: VecDeque<Vec<u8>>,
        eof: bool,
        stall_writes: bool,
        sent: Arc<Mutex<Vec<u8>>>,
        /// Called with everything written so far when a read finds `inbound`
        /// empty; its reply is queued (lets a test answer the random key).
        responder: Option<Responder>,
    }

    impl AsyncConn for MockConn {
        async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.inbound.is_empty() {
                if let Some(mut respond) = self.responder.take() {
                    let sent = self.sent.lock().unwrap().clone();
                    self.inbound.push_back(respond(&sent));
                }
            }
            if let Some(mut chunk) = self.inbound.pop_front() {
                let n = chunk.len().min(buf.len());
                buf[..n].copy_from_slice(&chunk[..n]);
                if n < chunk.len() {
                    self.inbound.push_front(chunk.split_off(n));
                }
                return Ok(n);
            }
            if self.eof {
                return Ok(0);
            }
            std::future::pending().await
        }

        async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
            if self.stall_writes {
                std::future::pending::<()>().await;
            }
            self.sent.lock().unwrap().extend_from_slice(buf);
            Ok(())
        }

        async fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Poll `fut` once with a no-op waker.
    fn poll_once<F: Future>(fut: std::pin::Pin<&mut F>) -> Poll<F::Output> {
        fut.poll(&mut Context::from_waker(Waker::noop()))
    }

    /// Run a future that the mock never leaves pending.
    fn block_on<F: Future>(fut: F) -> F::Output {
        match poll_once(pin!(fut)) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("future unexpectedly pending"),
        }
    }

    fn ws_over(conn: MockConn) -> WebSocket<MockConn> {
        WebSocket::new(Transport::Plain(conn))
    }

    /// An unmasked server frame.
    fn server_frame(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![if fin { 0x80 } else { 0 } | opcode];
        if payload.len() < 126 {
            f.push(payload.len() as u8);
        } else if payload.len() <= u16::MAX as usize {
            f.push(126);
            f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        } else {
            f.push(127);
            f.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
        f.extend_from_slice(payload);
        f
    }

    /// Decode the masked client frames in `sent` as (opcode, unmasked payload).
    fn client_frames(sent: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut out = Vec::new();
        let mut i = 0;
        while i + 2 <= sent.len() {
            let opcode = sent[i] & 0x0F;
            let mut len = (sent[i + 1] & 0x7F) as usize;
            i += 2;
            if len == 126 {
                len = u16::from_be_bytes([sent[i], sent[i + 1]]) as usize;
                i += 2;
            } else if len == 127 {
                len = u64::from_be_bytes(sent[i..i + 8].try_into().unwrap()) as usize;
                i += 8;
            }
            let mask = [sent[i], sent[i + 1], sent[i + 2], sent[i + 3]];
            i += 4;
            let payload = sent[i..i + len]
                .iter()
                .enumerate()
                .map(|(j, b)| b ^ mask[j & 3])
                .collect();
            i += len;
            out.push((opcode, payload));
        }
        out
    }

    #[test]
    fn fragmented_message_with_interleaved_ping_is_reassembled() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut inbound = server_frame(false, OPCODE_TEXT, b"hel");
        inbound.extend(server_frame(true, OPCODE_PING, b"p"));
        inbound.extend(server_frame(true, OPCODE_CONT, b"lo"));
        let mut ws = ws_over(MockConn {
            inbound: VecDeque::from([inbound]),
            sent: Arc::clone(&sent),
            ..Default::default()
        });
        let msg = block_on(ws.recv()).unwrap().unwrap();
        assert_eq!(msg, WsMessage::Text("hello".into()));
        assert_eq!(
            client_frames(&sent.lock().unwrap()),
            vec![(OPCODE_PONG, b"p".to_vec())]
        );
    }

    #[test]
    fn cancelled_recv_keeps_fragments_for_the_next_recv() {
        let mut ws = ws_over(MockConn {
            inbound: VecDeque::from([server_frame(false, OPCODE_BINARY, b"ab")]),
            ..Default::default()
        });
        {
            // The first fragment arrives, then the peer goes quiet: drop the
            // pending recv as a `select!`/timeout would.
            let mut fut = pin!(ws.recv());
            assert!(poll_once(fut.as_mut()).is_pending());
        }
        if let Transport::Plain(c) = &mut ws.transport {
            c.inbound.push_back(server_frame(true, OPCODE_CONT, b"cd"));
        }
        let msg = block_on(ws.recv()).unwrap().unwrap();
        assert_eq!(msg, WsMessage::Binary(b"abcd".to_vec()));
    }

    #[test]
    fn server_close_is_echoed_with_its_code() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut payload = 1001u16.to_be_bytes().to_vec();
        payload.extend_from_slice(b"going");
        let mut ws = ws_over(MockConn {
            inbound: VecDeque::from([server_frame(true, OPCODE_CLOSE, &payload)]),
            sent: Arc::clone(&sent),
            ..Default::default()
        });
        assert!(block_on(ws.recv()).is_none());
        assert!(ws.is_closed());
        assert_eq!(
            client_frames(&sent.lock().unwrap()),
            vec![(OPCODE_CLOSE, 1001u16.to_be_bytes().to_vec())]
        );
        // Nothing may be sent after the close.
        assert!(block_on(ws.send_text("late")).is_err());
    }

    #[test]
    fn malformed_close_fails_the_connection() {
        for (payload, status) in [
            (vec![0x03], 1002u16),                  // 1-byte payload
            (1005u16.to_be_bytes().to_vec(), 1002), // local-only code
            (vec![0x03, 0xE8, 0xFF, 0xFE], 1007),   // 1000 + invalid UTF-8
        ] {
            let sent = Arc::new(Mutex::new(Vec::new()));
            let mut ws = ws_over(MockConn {
                inbound: VecDeque::from([server_frame(true, OPCODE_CLOSE, &payload)]),
                sent: Arc::clone(&sent),
                ..Default::default()
            });
            assert!(block_on(ws.recv()).unwrap().is_err(), "{payload:?}");
            assert_eq!(
                client_frames(&sent.lock().unwrap()),
                vec![(OPCODE_CLOSE, status.to_be_bytes().to_vec())],
                "{payload:?}"
            );
        }
    }

    #[test]
    fn invalid_utf8_text_fails_with_1007() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut ws = ws_over(MockConn {
            inbound: VecDeque::from([server_frame(true, OPCODE_TEXT, &[0xC3])]),
            sent: Arc::clone(&sent),
            ..Default::default()
        });
        assert!(block_on(ws.recv()).unwrap().is_err());
        assert_eq!(
            client_frames(&sent.lock().unwrap()),
            vec![(OPCODE_CLOSE, 1007u16.to_be_bytes().to_vec())]
        );
    }

    #[test]
    fn endless_continuation_frames_hit_the_message_cap() {
        // 64 MiB of continuation payload pushes the reassembled message past
        // MAX_PAYLOAD_BYTES; the async client must refuse rather than grow.
        let chunk = vec![0u8; 8 * 1024 * 1024];
        let mut inbound = VecDeque::from([server_frame(false, OPCODE_BINARY, &chunk)]);
        let frames = (MAX_PAYLOAD_BYTES as usize) / chunk.len();
        for _ in 0..frames {
            inbound.push_back(server_frame(false, OPCODE_CONT, &chunk));
        }
        let mut ws = ws_over(MockConn {
            inbound,
            ..Default::default()
        });
        let err = block_on(ws.recv()).unwrap().unwrap_err();
        assert!(err.to_string().contains("too large"), "{err}");
    }

    #[test]
    fn rsv1_on_continuation_is_rejected() {
        let mut inbound = server_frame(false, OPCODE_TEXT, b"a");
        let mut cont = server_frame(true, OPCODE_CONT, b"b");
        cont[0] |= 0x40;
        inbound.extend(cont);
        let mut ws = ws_over(MockConn {
            inbound: VecDeque::from([inbound]),
            ..Default::default()
        });
        assert!(block_on(ws.recv()).unwrap().is_err());
    }

    #[test]
    fn eof_marks_socket_closed() {
        let mut ws = ws_over(MockConn {
            eof: true,
            ..Default::default()
        });
        assert!(matches!(
            block_on(ws.recv()),
            Some(Err(Error::UnexpectedEof))
        ));
        assert!(ws.is_closed());
    }

    #[test]
    fn cancelled_write_poisons_the_connection() {
        let mut ws = ws_over(MockConn {
            stall_writes: true,
            ..Default::default()
        });
        {
            let mut fut = pin!(ws.send_text("hi"));
            assert!(poll_once(fut.as_mut()).is_pending());
        }
        // The frame may be half on the wire: later sends must refuse.
        if let Transport::Plain(c) = &mut ws.transport {
            c.stall_writes = false;
        }
        assert!(block_on(ws.send_text("again")).is_err());
    }

    #[test]
    fn find_double_crlf_resumes_across_chunk_boundary() {
        assert_eq!(find_double_crlf(b"ab\r\n\r\nx", 0), Some(6));
        // Terminator straddles the previously-scanned end.
        assert_eq!(find_double_crlf(b"ab\r\n\r\nx", 4), Some(6));
        assert_eq!(find_double_crlf(b"ab\r\n", 4), None);
        assert_eq!(find_double_crlf(b"", 0), None);
    }

    /// A handshake mock that answers with `extra` headers added to a valid
    /// 101 for whatever key the client sent, on `status` line.
    fn handshake_conn(status: &'static str, extra: &'static str) -> MockConn {
        MockConn {
            responder: Some(Box::new(move |sent: &[u8]| {
                let req = String::from_utf8_lossy(sent);
                let key = req
                    .lines()
                    .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: "))
                    .unwrap()
                    .to_string();
                format!(
                    "{status}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                     Sec-WebSocket-Accept: {}\r\n{extra}\r\n",
                    derive_accept(&key)
                )
                .into_bytes()
            })),
            ..Default::default()
        }
    }

    fn run_handshake(conn: MockConn, offered: &[&str]) -> Result<Option<String>> {
        let offered: Vec<String> = offered.iter().map(|s| s.to_string()).collect();
        let header = subprotocol_header(&offered)?;
        let url = Url::parse("ws://example.com/").unwrap();
        let mut ws = ws_over(conn);
        block_on(ws.handshake(&url, &offered, &header))?;
        Ok(ws.subprotocol)
    }

    #[test]
    fn handshake_accepts_offered_subprotocol() {
        let conn = handshake_conn(
            "HTTP/1.1 101 Switching Protocols",
            "Sec-WebSocket-Protocol: chat\r\n",
        );
        assert_eq!(
            run_handshake(conn, &["superchat", "chat"]).unwrap(),
            Some("chat".into())
        );
    }

    #[test]
    fn handshake_rejects_unoffered_subprotocol() {
        let conn = handshake_conn(
            "HTTP/1.1 101 Switching Protocols",
            "Sec-WebSocket-Protocol: evil\r\n",
        );
        assert!(run_handshake(conn, &["chat"]).is_err());
        let conn = handshake_conn(
            "HTTP/1.1 101 Switching Protocols",
            "Sec-WebSocket-Protocol: chat\r\n",
        );
        assert!(run_handshake(conn, &[]).is_err(), "none offered");
    }

    #[test]
    fn handshake_rejects_http10_101() {
        let conn = handshake_conn("HTTP/1.0 101 Switching Protocols", "");
        assert!(run_handshake(conn, &[]).is_err());
    }

    #[test]
    fn subprotocol_with_crlf_is_rejected_before_sending() {
        let conn = handshake_conn("HTTP/1.1 101 Switching Protocols", "");
        let err = run_handshake(conn, &["chat\r\nX-Injected: 1"]).unwrap_err();
        assert!(matches!(err, Error::InvalidUrl(_)), "{err:?}");
    }

    /// A runtime whose timer fires immediately and whose connections never
    /// answer: the handshake deadline must trip instead of waiting forever.
    struct StalledRuntime;

    impl Runtime for StalledRuntime {
        type Conn = MockConn;

        async fn connect(&self, _addr: SocketAddr) -> io::Result<MockConn> {
            Ok(MockConn::default())
        }

        async fn sleep(&self, _dur: Duration) {}

        fn now(&self) -> Instant {
            Instant::now()
        }
    }

    #[test]
    fn stalled_handshake_hits_the_deadline() {
        let err = block_on(WebSocket::connect(&StalledRuntime, "ws://127.0.0.1:9/"))
            .expect_err("deadline");
        match err {
            Error::Io(e) => assert_eq!(e.kind(), io::ErrorKind::TimedOut),
            other => panic!("expected a timeout, got {other:?}"),
        }
    }
}

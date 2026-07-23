//! Native async WebSocket for [`crate::aio`], the counterpart of the browser
//! [`wasm`](super::wasm) one.
//!
//! It runs over any [`AsyncConn`] a [`Runtime`] hands back: `ws://` directly, and
//! `wss://` through the persistent [`AsyncTlsStream`](crate::io::asynctls) TLS
//! duplex. The RFC 6455 frame codec (masking, parsing, control-frame rules) is
//! shared with the blocking [`crate::websocket`] implementation — this module
//! only supplies the async I/O loop around it.
//!
//! Scope of this cut: text/binary messages (fragmented or whole), automatic
//! ping→pong and close handling, arbitrary subprotocols. It deliberately does
//! **not** offer permessage-deflate (RFC 7692), so messages are uncompressed —
//! matching the browser path, where compression is the browser's business. The
//! thread-split reader/writer of the blocking API (`WsReader`/`WsWriter`) is not
//! reproduced here; a single [`WebSocket`] owns the connection.

use std::future::Future;
use std::io;

use crate::error::{Error, Result};
use crate::io::runtime::{AsyncConn, Runtime};
use crate::url::Url;
use crate::websocket::{
    base64_encode, build_client_frame, derive_accept, parse_close_payload, random_16,
    try_parse_frame, validate_control_frame, Frame, OPCODE_BINARY, OPCODE_CLOSE, OPCODE_CONT,
    OPCODE_PING, OPCODE_PONG, OPCODE_TEXT,
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
    #[cfg(any(feature = "rustls-tls", feature = "purecrypto-tls"))]
    Tls(AsyncTlsStream<C>),
}

impl<C: AsyncConn> AsyncConn for Transport<C> {
    fn read(&mut self, buf: &mut [u8]) -> impl Future<Output = io::Result<usize>> + Send {
        async move {
            match self {
                Transport::Plain(c) => c.read(buf).await,
                #[cfg(any(feature = "rustls-tls", feature = "purecrypto-tls"))]
                Transport::Tls(t) => t.read(buf).await,
            }
        }
    }

    fn write_all(&mut self, buf: &[u8]) -> impl Future<Output = io::Result<()>> + Send {
        async move {
            match self {
                Transport::Plain(c) => c.write_all(buf).await,
                #[cfg(any(feature = "rustls-tls", feature = "purecrypto-tls"))]
                Transport::Tls(t) => t.write_all(buf).await,
            }
        }
    }

    fn flush(&mut self) -> impl Future<Output = io::Result<()>> + Send {
        async move {
            match self {
                Transport::Plain(c) => c.flush().await,
                #[cfg(any(feature = "rustls-tls", feature = "purecrypto-tls"))]
                Transport::Tls(t) => t.flush().await,
            }
        }
    }
}

/// An async WebSocket client over a [`Runtime`]'s connection. The native
/// counterpart of the browser [`WebSocket`](super::wasm::WebSocket): same
/// [`connect`](WebSocket::connect)/[`recv`](WebSocket::recv)/`send`/`close`
/// surface, but taking a `Runtime` (there is no implicit event loop natively).
pub struct WebSocket<C> {
    transport: Transport<C>,
    /// Unparsed inbound bytes carried between reads (frames are only consumed
    /// once whole — see [`try_parse_frame`]).
    rxbuf: Vec<u8>,
    closed: bool,
    subprotocol: Option<String>,
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
    pub async fn connect_with_subprotocols<R>(
        rt: &R,
        url: &str,
        subprotocols: &[&str],
    ) -> Result<WebSocket<C>>
    where
        R: Runtime<Conn = C>,
    {
        let u = Url::parse(url)?;
        let addr = super::resolve(&u.host, u.port)?;
        let conn = rt.connect(addr).await.map_err(Error::Io)?;

        let transport = match u.scheme.as_str() {
            "ws" => Transport::Plain(conn),
            "wss" => {
                #[cfg(any(feature = "rustls-tls", feature = "purecrypto-tls"))]
                {
                    let mut opts = crate::tls::TlsOpts::verifying();
                    let tls = AsyncTlsStream::connect(conn, &u.host, &mut opts).await?;
                    Transport::Tls(tls)
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

        let subs: Vec<String> = subprotocols.iter().map(|s| s.to_string()).collect();
        let mut ws = WebSocket {
            transport,
            rxbuf: Vec::new(),
            closed: false,
            subprotocol: None,
        };
        ws.handshake(&u, &subs).await?;
        Ok(ws)
    }

    /// The subprotocol the server selected, or `None`.
    pub fn subprotocol(&self) -> Option<&str> {
        self.subprotocol.as_deref()
    }

    /// Whether a close has been observed or sent.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Receive the next message, or `None` once the connection has closed
    /// cleanly. A protocol/IO error is returned as `Some(Err(..))`.
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

    /// Send a close frame (code 1000) and mark the socket closed.
    pub async fn close(&mut self) -> Result<()> {
        let frame = build_client_frame(OPCODE_CLOSE, &[])?;
        self.transport.write_all(&frame).await.map_err(Error::Io)?;
        self.transport.flush().await.map_err(Error::Io)?;
        self.closed = true;
        Ok(())
    }

    // ── internals ────────────────────────────────────────────────────────────

    async fn send_data(&mut self, opcode: u8, payload: &[u8]) -> Result<()> {
        let frame = build_client_frame(opcode, payload)?;
        self.transport.write_all(&frame).await.map_err(Error::Io)?;
        self.transport.flush().await.map_err(Error::Io)?;
        Ok(())
    }

    /// Reassemble one application message, answering pings and honouring close.
    async fn recv_inner(&mut self) -> Result<Option<WsMessage>> {
        if self.closed {
            return Ok(None);
        }
        let mut assembled: Vec<u8> = Vec::new();
        let mut msg_opcode: Option<u8> = None;
        loop {
            let frame = self.next_frame().await?;
            match frame.opcode {
                OPCODE_PING => {
                    validate_control_frame(&frame)?;
                    let pong = build_client_frame(OPCODE_PONG, &frame.payload)?;
                    self.transport.write_all(&pong).await.map_err(Error::Io)?;
                    self.transport.flush().await.map_err(Error::Io)?;
                }
                OPCODE_PONG => validate_control_frame(&frame)?,
                OPCODE_CLOSE => {
                    validate_control_frame(&frame)?;
                    let _ = parse_close_payload(&frame.payload); // code/reason available if needed
                                                                 // Polite close echo; ignore failure, we're closing anyway.
                    if let Ok(close) = build_client_frame(OPCODE_CLOSE, &[]) {
                        let _ = self.transport.write_all(&close).await;
                        let _ = self.transport.flush().await;
                    }
                    self.closed = true;
                    return Ok(None);
                }
                OPCODE_TEXT | OPCODE_BINARY => {
                    if msg_opcode.is_some() {
                        return Err(Error::BadResponse(
                            "new data frame began before the previous message finished".into(),
                        ));
                    }
                    if frame.rsv1 {
                        return Err(Error::BadResponse(
                            "RSV1 set but permessage-deflate was not negotiated".into(),
                        ));
                    }
                    msg_opcode = Some(frame.opcode);
                    assembled.extend_from_slice(&frame.payload);
                    if frame.fin {
                        return Ok(Some(build_message(frame.opcode, assembled)?));
                    }
                }
                OPCODE_CONT => {
                    let op = msg_opcode.ok_or_else(|| {
                        Error::BadResponse("CONTINUATION frame without a start frame".into())
                    })?;
                    assembled.extend_from_slice(&frame.payload);
                    if frame.fin {
                        return Ok(Some(build_message(op, assembled)?));
                    }
                }
                other => return Err(Error::BadResponse(format!("unknown WS opcode 0x{other:x}"))),
            }
        }
    }

    /// Pull bytes until a whole frame is buffered, then return it.
    async fn next_frame(&mut self) -> Result<Frame> {
        let mut tmp = [0u8; 16 * 1024];
        loop {
            if let Some((frame, consumed)) = try_parse_frame(&self.rxbuf)? {
                self.rxbuf.drain(..consumed);
                return Ok(frame);
            }
            let n = self.transport.read(&mut tmp).await.map_err(Error::Io)?;
            if n == 0 {
                return Err(Error::UnexpectedEof);
            }
            self.rxbuf.extend_from_slice(&tmp[..n]);
        }
    }

    /// Send the HTTP/1.1 Upgrade request and validate the `101` response.
    async fn handshake(&mut self, u: &Url, subprotocols: &[String]) -> Result<()> {
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
        let proto_header = if subprotocols.is_empty() {
            String::new()
        } else {
            format!("Sec-WebSocket-Protocol: {}\r\n", subprotocols.join(", "))
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
        self.transport
            .write_all(req.as_bytes())
            .await
            .map_err(Error::Io)?;
        self.transport.flush().await.map_err(Error::Io)?;

        let head = self.read_handshake_head().await?;
        self.interpret_handshake(&head, &key_b64)
    }

    /// Read response bytes up to and including the `\r\n\r\n` header terminator,
    /// leaving any trailing frame bytes in `rxbuf`.
    async fn read_handshake_head(&mut self) -> Result<Vec<u8>> {
        let mut tmp = [0u8; 4096];
        loop {
            if let Some(end) = find_double_crlf(&self.rxbuf) {
                return Ok(self.rxbuf.drain(..end).collect());
            }
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

    /// Validate a `101 Switching Protocols` handshake response.
    fn interpret_handshake(&mut self, head: &[u8], key_b64: &str) -> Result<()> {
        let text = std::str::from_utf8(head)
            .map_err(|_| Error::BadResponse("non-utf8 handshake response".into()))?;
        let mut lines = text.split("\r\n");
        let status = lines
            .next()
            .ok_or_else(|| Error::BadResponse("empty handshake response".into()))?;
        if !(status.starts_with("HTTP/1.1 101") || status.starts_with("HTTP/1.0 101")) {
            return Err(Error::BadResponse(format!(
                "expected 101 Switching Protocols, got: {status:?}"
            )));
        }

        let mut upgrade_ok = false;
        let mut connection_ok = false;
        let mut accept_value: Option<String> = None;
        let mut subprotocol_value: Option<String> = None;
        let mut had_extension = false;
        for line in lines {
            if line.is_empty() {
                break;
            }
            let (k, v) = match line.split_once(':') {
                Some((k, v)) => (k.trim(), v.trim()),
                None => continue,
            };
            if k.eq_ignore_ascii_case("upgrade") {
                if v.eq_ignore_ascii_case("websocket") {
                    upgrade_ok = true;
                }
            } else if k.eq_ignore_ascii_case("connection") {
                if v.split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
                {
                    connection_ok = true;
                }
            } else if k.eq_ignore_ascii_case("sec-websocket-accept") {
                accept_value = Some(v.to_string());
            } else if k.eq_ignore_ascii_case("sec-websocket-protocol") {
                subprotocol_value = Some(v.to_string());
            } else if k.eq_ignore_ascii_case("sec-websocket-extensions") && !v.is_empty() {
                had_extension = true;
            }
        }

        if !upgrade_ok {
            return Err(Error::BadResponse(
                "missing or wrong Upgrade header in handshake response".into(),
            ));
        }
        if !connection_ok {
            return Err(Error::BadResponse(
                "missing or wrong Connection header in handshake response".into(),
            ));
        }
        let accept = accept_value
            .ok_or_else(|| Error::BadResponse("missing Sec-WebSocket-Accept header".into()))?;
        if accept != derive_accept(key_b64) {
            return Err(Error::BadResponse("Sec-WebSocket-Accept mismatch".into()));
        }
        // We offered no extension, so a server that names one is misbehaving.
        if had_extension {
            return Err(Error::BadResponse(
                "server negotiated a permessage extension that was not offered".into(),
            ));
        }
        self.subprotocol = subprotocol_value;
        Ok(())
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

/// Index just past the first `\r\n\r\n` in `buf`, or `None` if absent.
fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

//! WebSocket support (RFC 6455).
//!
//! Two entry points:
//!   * [`WebSocket`] — a **persistent** connection: open it once with
//!     [`WebSocket::connect`] (or [`Client::websocket`](crate::net::Client::websocket)
//!     for proxy/timeout/TLS control) and exchange many messages over its
//!     lifetime via `send_text`/`send_binary`/`recv`/`ping`/`close`.
//!   * [`fetch`] — a one-shot: open, read a single message, close.
//!
//! WS handshakes are HTTP/1.1 `Upgrade: websocket` requests followed by
//! binary/text frames. We perform the handshake by hand (so we can sit on the
//! raw stream without buffered-reader leftovers eating into the frame
//! channel), then drive a proper frame loop. For `wss://`, the TCP stream is
//! wrapped with [`crate::tls::connect_over`] before sending the upgrade.
//!
//! What this module does:
//!   * Send-side data frames: `send_message` writes a masked client
//!     text/binary frame (client frames MUST be masked, RFC 6455 §5.3).
//!   * Receive-side reassembly: `read_message` runs a frame loop that
//!     stitches an initial data frame (FIN=0) and its CONTINUATION frames
//!     (opcode 0x0) back into one message, enforcing the
//!     `MAX_PAYLOAD_BYTES` cap on the *cumulative* reassembled size so a
//!     fragmented bomb can't slip past it.
//!   * Control frames inline: a PING is answered with a PONG echoing its
//!     application data, an unsolicited PONG is ignored, and a CLOSE is
//!     answered with a CLOSE before returning cleanly. Control frames are
//!     handled both while waiting for the first data frame and in between
//!     fragments. Per §5.4/§5.5 control frames must not be fragmented and
//!     carry at most 125 bytes; violations are rejected as protocol errors.
//!   * permessage-deflate (RFC 7692): the upgrade request offers the
//!     extension (with `client_no_context_takeover` /
//!     `server_no_context_takeover` and `client_max_window_bits`). If the
//!     server agrees, data messages whose first frame has RSV1 set are
//!     per-message DEFLATE-compressed (RFC 1951 raw deflate) — we append the
//!     `00 00 FF FF` empty-block terminator the sender strips and inflate,
//!     bounding the inflated size against `MAX_PAYLOAD_BYTES` so a
//!     compression bomb can't bypass the cap. Outgoing messages are deflated
//!     and flagged with RSV1 when compression is negotiated. RSV1 is rejected
//!     when compression was *not* negotiated, RSV2/RSV3 are always rejected,
//!     and RSV1 on a control frame is rejected. See `Pmd` for the
//!     context-takeover decision.
//!
//! Limitations of this scaffold (intentionally deferred):
//!   * Streaming/large payloads — the whole message is buffered in memory.
//!   * Ping *intervals* / timer-driven keepalive; we react to peer pings but
//!     do not proactively send our own on a schedule.

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use compcol::deflate::Deflate;
use compcol::limit::LimitedDecoder;
use compcol::vec::compress_to_vec;
use compcol::{Algorithm, Decoder, Status};
use purecrypto::hash::{Digest, Sha1};

use crate::error::{Error, Result};
use crate::tls::TlsStream;
use crate::url::Url;

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The empty-block terminator a permessage-deflate sender strips from the
/// tail of each deflated message (RFC 7692 §7.2.1) and the receiver appends
/// back before inflating (§7.2.2).
const DEFLATE_TAIL: [u8; 4] = [0x00, 0x00, 0xFF, 0xFF];

const OPCODE_CONT: u8 = 0x0;
const OPCODE_TEXT: u8 = 0x1;
const OPCODE_BINARY: u8 = 0x2;
const OPCODE_CLOSE: u8 = 0x8;
const OPCODE_PING: u8 = 0x9;
const OPCODE_PONG: u8 = 0xA;

const MAX_PAYLOAD_BYTES: u64 = 64 * 1024 * 1024;

/// Wall-clock budget for reading the *entire* HTTP/1.1 upgrade-handshake
/// response header. The per-`read` socket timeout (`set_read_timeout`, ~60 s)
/// only bounds an individual syscall, so a server that dribbles one byte just
/// under that timeout could otherwise hold the connection for up to the 64 KiB
/// header cap × ~60 s — a slowloris-style hold. This deadline caps the whole
/// header read regardless of how the bytes are paced.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(60);

/// The permessage-deflate offer we put in the upgrade request. We advertise
/// `client_no_context_takeover` and `server_no_context_takeover` so each
/// message inflates/deflates independently (no sliding window carried across
/// messages), which keeps state bounded and the implementation simple. We
/// also offer `client_max_window_bits` so a server that wants to shrink our
/// (notional) window can; we don't carry context anyway, so any value it
/// echoes is fine.
const PMD_OFFER: &str =
    "permessage-deflate; client_no_context_takeover; server_no_context_takeover; client_max_window_bits";

/// Negotiated permessage-deflate (RFC 7692) state for a connection.
///
/// ## Context-takeover decision
///
/// We always operate our **send** side in no-context-takeover mode: every
/// outgoing message is an independent raw-DEFLATE stream produced by a fresh
/// encoder. That is why we offer `client_no_context_takeover` — it lets the
/// peer reset its inflater per message to match.
///
/// On the **receive** side we honour what the server negotiated. The
/// underlying `compcol` raw-deflate decoder keeps a 32 KiB sliding window and
/// can carry it across separate `decode` calls, so a persistent inflate
/// context across messages is supported: we keep one decoder and only
/// [`reset`](Decoder::reset) it per message when `server_no_context_takeover`
/// was agreed. Since our offer always includes `server_no_context_takeover`,
/// a compliant server typically agrees to it and we reset each message; but
/// if it declines, the persistent-window path keeps us correct.
struct Pmd {
    /// `client_no_context_takeover` was agreed: our encoder is fresh per
    /// message (always true for us — we never carry send context). Recorded
    /// for completeness/observability; our send path is unconditionally
    /// no-context-takeover, so we don't branch on it.
    #[allow(dead_code)]
    client_no_context_takeover: bool,
    /// `server_no_context_takeover` was agreed: reset the inflate decoder
    /// before each incoming message rather than carrying its window.
    server_no_context_takeover: bool,
    /// Persistent inflate context, reused across messages when the server
    /// did not agree `server_no_context_takeover`.
    decoder: <Deflate as Algorithm>::Decoder,
}

impl Pmd {
    /// Inflate one full (reassembled) compressed message payload. Appends the
    /// stripped `00 00 FF FF` terminator (RFC 7692 §7.2.2) and runs raw
    /// DEFLATE, bounding the inflated output at `MAX_PAYLOAD_BYTES` so a
    /// compression bomb can't slip past the cap. The decoder's sliding window
    /// is carried across messages unless `server_no_context_takeover` was
    /// negotiated, in which case it is reset first.
    fn inflate_message(&mut self, compressed: &[u8]) -> Result<Vec<u8>> {
        if self.server_no_context_takeover {
            self.decoder.reset();
        }
        // RFC 7692 §7.2.2: append the empty-block terminator the sender
        // stripped, then inflate.
        let mut input = Vec::with_capacity(compressed.len() + DEFLATE_TAIL.len());
        input.extend_from_slice(compressed);
        input.extend_from_slice(&DEFLATE_TAIL);

        // Bound the inflated output against the cap, exactly like compress.rs's
        // LimitedDecoder path, so a compressed bomb can't expand past
        // MAX_PAYLOAD_BYTES. `LimitedDecoder` takes the decoder by value, so we
        // move our persistent decoder into it, run, then recover it via
        // `into_inner` — preserving its 32 KiB window for the next message
        // (the context-takeover path).
        let taken = std::mem::replace(&mut self.decoder, Deflate::decoder());
        let mut limited = LimitedDecoder::new(taken, MAX_PAYLOAD_BYTES);

        let result = Self::run_inflate(&mut limited, &input);
        // Restore the (now advanced) decoder regardless of outcome.
        self.decoder = limited.into_inner();
        result
    }

    /// Drive the bounded decoder over `input`, collecting all inflated output.
    /// Stops at stream end (our own BFINAL=1 messages) or when the input is
    /// exhausted with no further progress (a peer's sync-flushed message,
    /// whose final empty block leaves the decoder parked in `InputEmpty`).
    fn run_inflate(
        limited: &mut LimitedDecoder<<Deflate as Algorithm>::Decoder>,
        input: &[u8],
    ) -> Result<Vec<u8>> {
        let mut out: Vec<u8> = Vec::new();
        let mut scratch = vec![0u8; 64 * 1024];
        let mut consumed = 0usize;
        loop {
            let before_consumed = consumed;
            let before_written = out.len();
            let (p, status) = limited
                .decode(&input[consumed..], &mut scratch)
                .map_err(|e| {
                    Error::BadResponse(format!("permessage-deflate inflate failed: {e}"))
                })?;
            out.extend_from_slice(&scratch[..p.written]);
            consumed += p.consumed;
            match status {
                Status::StreamEnd => break,
                Status::OutputFull => continue,
                Status::InputEmpty => {
                    if consumed >= input.len()
                        || (consumed == before_consumed && out.len() == before_written)
                    {
                        break;
                    }
                }
            }
        }
        Ok(out)
    }
}

/// Deflate one application message for sending (RFC 7692 §7.2.1). Produces a
/// fresh raw-DEFLATE stream (no context carried — we always operate the send
/// side in no-context-takeover mode). `compcol`'s encoder terminates the
/// stream with a BFINAL=1 block rather than a `Z_SYNC_FLUSH`, so there is no
/// trailing `00 00 FF FF` to strip; the receiver appends its own terminator
/// and, on hitting our final block, recovers the exact payload (the appended
/// tail is then harmlessly ignored). This is spec-legal and, paired with our
/// `client_no_context_takeover` offer, lets the peer reset its inflater each
/// message.
fn deflate_message(payload: &[u8]) -> Result<Vec<u8>> {
    let mut out = compress_to_vec::<Deflate>(payload)
        .map_err(|e| Error::BadResponse(format!("permessage-deflate deflate failed: {e}")))?;
    // If the encoder ever did emit the sync-flush terminator, strip it per
    // §7.2.1. compcol terminates with a final block today, so this is a
    // forward-compatible no-op, but it keeps us correct if that changes.
    if out.ends_with(&DEFLATE_TAIL) {
        out.truncate(out.len() - DEFLATE_TAIL.len());
    }
    Ok(out)
}

/// Open a WS connection, read one full text or binary message (reassembling
/// fragments and answering any interleaved ping/close control frames), send a
/// close, and return that message's payload.
pub fn fetch(url: &Url) -> Result<Vec<u8>> {
    fetch_with(url, &crate::net::NetConfig::default())
}

pub(crate) fn fetch_with(url: &Url, cfg: &crate::net::NetConfig) -> Result<Vec<u8>> {
    match url.scheme.as_str() {
        "ws" => {
            let mut sock = tcp_connect(url, cfg)?;
            let (mut pmd, _proto) = handshake(&mut sock, url, &[])?;
            read_data_and_close(&mut sock, pmd.as_mut())
        }
        "wss" => {
            let tcp = tcp_connect(url, cfg)?;
            let mut tls = crate::tls::connect_over(tcp, &url.host)?;
            let (mut pmd, _proto) = handshake(&mut tls, url, &[])?;
            read_data_and_close(&mut tls, pmd.as_mut())
        }
        other => Err(Error::UnsupportedScheme(other.to_string())),
    }
}

fn tcp_connect(url: &Url, cfg: &crate::net::NetConfig) -> Result<Box<dyn crate::net::NetStream>> {
    let stream = cfg.connect(&url.host, url.port)?;
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    stream.set_write_timeout(Some(Duration::from_secs(60)))?;
    Ok(stream)
}

// ===========================================================================
// Persistent client API
// ===========================================================================

/// Bounded write timeout for a persistent connection's outgoing frames, so a
/// stuck send can't hang forever. The *read* timeout is configurable (see
/// [`WebSocket::set_read_timeout`]) because a long-lived client legitimately
/// waits on sparse server pushes.
const SEND_TIMEOUT: Duration = Duration::from_secs(60);

/// A message exchanged over a [`WebSocket`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsMessage {
    /// A UTF-8 text message (RFC 6455 opcode 0x1). On receive, the payload has
    /// already been validated as UTF-8 (§8.1).
    Text(String),
    /// A binary message (opcode 0x2); opaque bytes.
    Binary(Vec<u8>),
}

impl WsMessage {
    /// The payload as bytes (the UTF-8 bytes for a text message).
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            WsMessage::Text(s) => s.as_bytes(),
            WsMessage::Binary(b) => b,
        }
    }

    /// The text, if this is a [`WsMessage::Text`].
    pub fn as_text(&self) -> Option<&str> {
        match self {
            WsMessage::Text(s) => Some(s),
            WsMessage::Binary(_) => None,
        }
    }

    /// Consume the message into its raw payload bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            WsMessage::Text(s) => s.into_bytes(),
            WsMessage::Binary(b) => b,
        }
    }
}

/// A close frame's status code and reason (RFC 6455 §5.5.1 / §7.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsClose {
    /// Status code (e.g. 1000 normal, 1001 going away).
    pub code: u16,
    /// Optional human-readable reason; empty if none was sent.
    pub reason: String,
}

/// A WebSocket frame opcode (RFC 6455 §5.2), for the low-level
/// [`WebSocket::send_frame`] / [`WebSocket::recv_frame`] API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsOpcode {
    /// Continuation of a fragmented message (0x0).
    Continuation,
    /// Text data (0x1).
    Text,
    /// Binary data (0x2).
    Binary,
    /// Connection close (0x8).
    Close,
    /// Ping (0x9).
    Ping,
    /// Pong (0xA).
    Pong,
}

impl WsOpcode {
    fn to_u8(self) -> u8 {
        match self {
            WsOpcode::Continuation => OPCODE_CONT,
            WsOpcode::Text => OPCODE_TEXT,
            WsOpcode::Binary => OPCODE_BINARY,
            WsOpcode::Close => OPCODE_CLOSE,
            WsOpcode::Ping => OPCODE_PING,
            WsOpcode::Pong => OPCODE_PONG,
        }
    }
    fn from_u8(op: u8) -> Result<WsOpcode> {
        Ok(match op {
            OPCODE_CONT => WsOpcode::Continuation,
            OPCODE_TEXT => WsOpcode::Text,
            OPCODE_BINARY => WsOpcode::Binary,
            OPCODE_CLOSE => WsOpcode::Close,
            OPCODE_PING => WsOpcode::Ping,
            OPCODE_PONG => WsOpcode::Pong,
            other => return Err(Error::BadResponse(format!("unknown WS opcode 0x{other:x}"))),
        })
    }
    fn is_control(self) -> bool {
        matches!(self, WsOpcode::Close | WsOpcode::Ping | WsOpcode::Pong)
    }
}

/// An event from [`WebSocket::recv_event`] — every frame type, including the
/// control frames that [`WebSocket::recv`] handles for you silently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsEvent {
    /// A reassembled UTF-8 text message.
    Text(String),
    /// A reassembled binary message.
    Binary(Vec<u8>),
    /// A ping from the peer (already answered with a pong unless auto-pong was
    /// disabled via [`WebSocket::set_auto_pong`]); carries its application data.
    Ping(Vec<u8>),
    /// An unsolicited or solicited pong from the peer; carries its data.
    Pong(Vec<u8>),
    /// The peer closed the connection (already echoed). Carries the close code
    /// and reason when the peer supplied them.
    Close(Option<WsClose>),
}

/// A single raw frame from [`WebSocket::recv_frame`] — no reassembly, no
/// decompression, no automatic control handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsFrame {
    /// The FIN bit: `false` means more fragments of this message follow.
    pub fin: bool,
    /// The frame opcode.
    pub opcode: WsOpcode,
    /// The frame's (still-compressed, if permessage-deflate) payload bytes.
    pub payload: Vec<u8>,
}

/// Object-safe `Read + Write + Send` for the WS data path, so a [`WebSocket`]
/// can hold a plaintext (`ws://`) or TLS-wrapped (`wss://`) connection behind
/// one boxed type. Blanket-implemented for every such stream.
trait ReadWrite: Read + Write + Send {}
impl<T: Read + Write + Send + ?Sized> ReadWrite for T {}

/// A live, persistent WebSocket connection (RFC 6455).
///
/// Open one with [`WebSocket::connect`] for the common case, or
/// [`Client::websocket`](crate::net::Client::websocket) to control the
/// transport (proxy, timeouts, TLS verification). Then exchange messages over
/// the connection's lifetime:
///
/// ```no_run
/// use rsurl::websocket::{WebSocket, WsMessage};
/// let mut ws = WebSocket::connect("wss://example.com/socket")?;
/// ws.send_text("hello")?;
/// while let Some(msg) = ws.recv()? {
///     match msg {
///         WsMessage::Text(t) => println!("text: {t}"),
///         WsMessage::Binary(b) => println!("{} binary bytes", b.len()),
///     }
/// }
/// ws.close()?;
/// # Ok::<(), rsurl::Error>(())
/// ```
///
/// Incoming **ping** frames are answered with pongs and unsolicited **pongs**
/// are ignored automatically inside [`recv`](WebSocket::recv); a peer
/// **close** is surfaced as `recv` returning `Ok(None)`. permessage-deflate
/// (RFC 7692) is negotiated transparently when the server supports it.
///
/// The API is single-threaded: drive `send`/`recv` from one thread. (The type
/// is `Send`, so you may move the whole connection between threads; just don't
/// call it from two at once.)
pub struct WebSocket {
    stream: Box<dyn ReadWrite>,
    /// A cloned handle to the underlying socket (same OS fd) kept only to
    /// adjust the read timeout — the data path may be TLS-wrapped and own the
    /// socket, so this side-channel reaches it. `None` if the transport does
    /// not support cloning (e.g. some custom connectors).
    ctl: Option<Box<dyn crate::net::NetStream>>,
    pmd: Option<Pmd>,
    /// We have sent a close frame; no more data frames may be sent. We may
    /// still `recv` to drain the peer's replies and its own close (RFC 6455
    /// §5.5.1 closing handshake).
    send_closed: bool,
    /// The peer has closed (a close frame was received, or the transport hit
    /// EOF); `recv` yields nothing further.
    recv_closed: bool,
    compression: bool,
    /// Auto-reply to incoming pings with a pong (default `true`). When `false`,
    /// [`recv_event`](WebSocket::recv_event) surfaces pings without answering
    /// them (curl's `CURLWS_NOAUTOPONG`). [`recv`](WebSocket::recv) always
    /// auto-pongs regardless, since it hides control frames.
    auto_pong: bool,
    /// The negotiated subprotocol (`Sec-WebSocket-Protocol`), if any.
    subprotocol: Option<String>,
}

impl WebSocket {
    /// Open a WebSocket to `url` (`ws://` or `wss://`) with default settings
    /// (direct transport, TLS verification on, 60 s read timeout). For proxy,
    /// timeout, or `-k`/insecure control, use
    /// [`Client::websocket`](crate::net::Client::websocket).
    pub fn connect(url: &str) -> Result<WebSocket> {
        crate::net::Client::new().websocket(url)
    }

    /// Open a WebSocket offering `subprotocols` in the handshake
    /// `Sec-WebSocket-Protocol` header. Read the server's choice with
    /// [`subprotocol`](Self::subprotocol).
    pub fn connect_with_subprotocols(url: &str, subprotocols: &[&str]) -> Result<WebSocket> {
        crate::net::Client::new().websocket_with_subprotocols(url, subprotocols)
    }

    /// Open a connection using an already-built [`NetConfig`] and the caller's
    /// persistent read timeout. Used by [`Client::websocket`].
    pub(crate) fn open(
        url: &Url,
        cfg: &crate::net::NetConfig,
        read_timeout: Option<Duration>,
        subprotocols: &[String],
    ) -> Result<WebSocket> {
        let (stream, ctl, pmd, subprotocol): (Box<dyn ReadWrite>, _, _, _) =
            match url.scheme.as_str() {
                "ws" => {
                    let mut data = cfg.connect(&url.host, url.port)?;
                    data.set_write_timeout(Some(SEND_TIMEOUT))
                        .map_err(Error::Io)?;
                    // Bound each handshake read; the wall-clock HANDSHAKE_DEADLINE
                    // inside `handshake` defeats a slow drip on top of this.
                    data.set_read_timeout(Some(SEND_TIMEOUT))
                        .map_err(Error::Io)?;
                    let ctl = data.try_clone_box().ok();
                    let (pmd, proto) = handshake(&mut data, url, subprotocols)?;
                    (Box::new(data), ctl, pmd, proto)
                }
                "wss" => {
                    let data = cfg.connect(&url.host, url.port)?;
                    data.set_write_timeout(Some(SEND_TIMEOUT))
                        .map_err(Error::Io)?;
                    data.set_read_timeout(Some(SEND_TIMEOUT))
                        .map_err(Error::Io)?;
                    // Clone the raw socket for timeout control *before* the TLS
                    // layer takes ownership of it.
                    let ctl = data.try_clone_box().ok();
                    // Honour the client's verification setting (`-k` => verify off);
                    // wss otherwise verifies against the system roots like `fetch`.
                    let mut opts = crate::tls::TlsOpts::verifying();
                    opts.verify = cfg.verify;
                    let mut tls = crate::tls::connect_over_tls(data, &url.host, opts)?;
                    let (pmd, proto) = handshake(&mut tls, url, subprotocols)?;
                    (Box::new(tls), ctl, pmd, proto)
                }
                other => return Err(Error::UnsupportedScheme(other.to_string())),
            };

        // The handshake is done; switch to the caller's persistent read timeout
        // (which may be `None` to block indefinitely on a quiet connection).
        if let Some(c) = &ctl {
            let _ = c.set_read_timeout(read_timeout);
        }

        let compression = pmd.is_some();
        Ok(WebSocket {
            stream,
            ctl,
            pmd,
            send_closed: false,
            recv_closed: false,
            compression,
            auto_pong: true,
            subprotocol,
        })
    }

    /// The subprotocol the server selected from the offered
    /// `Sec-WebSocket-Protocol` list, or `None` if none was negotiated.
    pub fn subprotocol(&self) -> Option<&str> {
        self.subprotocol.as_deref()
    }

    /// Whether permessage-deflate (RFC 7692) was negotiated for this
    /// connection.
    pub fn compression_enabled(&self) -> bool {
        self.compression
    }

    /// Whether the connection is closed or closing — either we sent a close
    /// frame ([`close`](Self::close)) or the peer closed (observed in
    /// [`recv`](Self::recv)).
    pub fn is_closed(&self) -> bool {
        self.send_closed || self.recv_closed
    }

    /// Set the per-read inactivity timeout for [`recv`](Self::recv). `None`
    /// blocks indefinitely (suitable for a connection that waits on sparse
    /// server pushes). Errors if the transport does not support a cloned socket
    /// control handle (e.g. some custom connectors).
    pub fn set_read_timeout(&self, dur: Option<Duration>) -> Result<()> {
        match &self.ctl {
            Some(c) => c.set_read_timeout(dur).map_err(Error::Io),
            None => Err(Error::BadResponse(
                "websocket: this transport does not support changing the read timeout".into(),
            )),
        }
    }

    /// Send a UTF-8 text message (opcode 0x1).
    pub fn send_text(&mut self, text: &str) -> Result<()> {
        self.ensure_open()?;
        send_message(
            &mut self.stream,
            OPCODE_TEXT,
            text.as_bytes(),
            self.pmd.as_mut(),
        )
    }

    /// Send a binary message (opcode 0x2).
    pub fn send_binary(&mut self, data: &[u8]) -> Result<()> {
        self.ensure_open()?;
        send_message(&mut self.stream, OPCODE_BINARY, data, self.pmd.as_mut())
    }

    /// Send a [`WsMessage`].
    pub fn send(&mut self, msg: &WsMessage) -> Result<()> {
        match msg {
            WsMessage::Text(s) => self.send_text(s),
            WsMessage::Binary(b) => self.send_binary(b),
        }
    }

    /// Send a ping with `payload` (≤ 125 bytes per RFC 6455 §5.5). The peer's
    /// pong is consumed silently by the next [`recv`](Self::recv).
    pub fn ping(&mut self, payload: &[u8]) -> Result<()> {
        self.ensure_open()?;
        if payload.len() > MAX_CONTROL_PAYLOAD {
            return Err(Error::BadResponse(format!(
                "websocket: ping payload too large: {} bytes (max {MAX_CONTROL_PAYLOAD})",
                payload.len()
            )));
        }
        let frame = build_client_frame(OPCODE_PING, payload)?;
        self.stream.write_all(&frame).map_err(Error::Io)?;
        self.stream.flush().map_err(Error::Io)?;
        Ok(())
    }

    /// Block until the next data message arrives, answering any interleaved
    /// ping/pong control frames automatically. Returns `Ok(None)` when the
    /// peer closes the connection (a close is also answered automatically);
    /// every subsequent call then returns `Ok(None)`.
    pub fn recv(&mut self) -> Result<Option<WsMessage>> {
        loop {
            match self.recv_event()? {
                WsEvent::Text(s) => return Ok(Some(WsMessage::Text(s))),
                WsEvent::Binary(b) => return Ok(Some(WsMessage::Binary(b))),
                // Control frames are handled inside `recv_event`; skip them and
                // keep waiting for the next data message.
                WsEvent::Ping(_) | WsEvent::Pong(_) => continue,
                WsEvent::Close(_) => return Ok(None),
            }
        }
    }

    /// Enable or disable automatic PONG replies to incoming pings (default
    /// enabled). The analogue of curl's `CURLWS_NOAUTOPONG`. Only affects
    /// [`recv_event`](Self::recv_event); [`recv`](Self::recv) always auto-pongs
    /// because it never surfaces control frames.
    pub fn set_auto_pong(&mut self, on: bool) {
        self.auto_pong = on;
    }

    /// Receive the next frame as a [`WsEvent`], surfacing control frames
    /// (`Ping`/`Pong`/`Close`) in addition to data messages — unlike
    /// [`recv`](Self::recv), which hides them. Data messages are still
    /// reassembled from fragments and decompressed. Returns `Close(..)` once
    /// the peer has closed (and on every later call). A ping is answered with a
    /// pong before being surfaced, unless auto-pong is off
    /// ([`set_auto_pong`](Self::set_auto_pong)).
    ///
    /// Note: a control frame interleaved *between fragments* of a partially
    /// received message is always handled internally (pings answered) and is
    /// not surfaced, so reassembly is never interrupted.
    pub fn recv_event(&mut self) -> Result<WsEvent> {
        if self.recv_closed {
            return Ok(WsEvent::Close(None));
        }
        let mut frag_opcode: Option<u8> = None;
        let mut compressed = false;
        let mut buf: Vec<u8> = Vec::new();

        loop {
            let frame = read_frame(&mut self.stream)?;

            if frame.opcode >= 0x8 {
                validate_control_frame(&frame)?;
                let mid_message = frag_opcode.is_some();
                match frame.opcode {
                    OPCODE_PING => {
                        if self.auto_pong {
                            let pong = build_client_frame(OPCODE_PONG, &frame.payload)?;
                            self.stream.write_all(&pong).map_err(Error::Io)?;
                            self.stream.flush().map_err(Error::Io)?;
                        }
                        // Don't break a half-reassembled message: only surface a
                        // ping that arrived between messages.
                        if mid_message {
                            continue;
                        }
                        return Ok(WsEvent::Ping(frame.payload));
                    }
                    OPCODE_PONG => {
                        if mid_message {
                            continue;
                        }
                        return Ok(WsEvent::Pong(frame.payload));
                    }
                    OPCODE_CLOSE => {
                        // Echo the close (masked, best-effort) unless we already
                        // sent one — then this frame is the peer's echo of ours.
                        if !self.send_closed {
                            if let Ok(close) = build_client_frame(OPCODE_CLOSE, &[]) {
                                let _ = self.stream.write_all(&close);
                                let _ = self.stream.flush();
                            }
                            self.send_closed = true;
                        }
                        self.recv_closed = true;
                        return Ok(WsEvent::Close(parse_close_payload(&frame.payload)));
                    }
                    other => {
                        return Err(Error::BadResponse(format!(
                            "unknown WS control opcode 0x{other:x}"
                        )));
                    }
                }
            }

            // Data / continuation frames — reassemble exactly like
            // `read_message` (kept in sync; that path backs the one-shot
            // `fetch`).
            match frame.opcode {
                OPCODE_TEXT | OPCODE_BINARY => {
                    if frag_opcode.is_some() {
                        return Err(Error::BadResponse(
                            "new data frame began while a fragmented message was in progress"
                                .into(),
                        ));
                    }
                    if frame.rsv1 {
                        if self.pmd.is_none() {
                            return Err(Error::BadResponse(
                                "RSV1 set on a WS frame but permessage-deflate was not negotiated"
                                    .into(),
                            ));
                        }
                        compressed = true;
                    }
                    accumulate(&mut buf, &frame.payload)?;
                    if frame.fin {
                        return self.finish_event(frame.opcode, buf, compressed);
                    }
                    frag_opcode = Some(frame.opcode);
                }
                OPCODE_CONT => {
                    let opcode = frag_opcode.ok_or_else(|| {
                        Error::BadResponse("continuation frame with no message in progress".into())
                    })?;
                    if frame.rsv1 {
                        return Err(Error::BadResponse(
                            "RSV1 set on a WS continuation frame".into(),
                        ));
                    }
                    accumulate(&mut buf, &frame.payload)?;
                    if frame.fin {
                        return self.finish_event(opcode, buf, compressed);
                    }
                }
                other => {
                    return Err(Error::BadResponse(format!("unknown WS opcode 0x{other:x}")));
                }
            }
        }
    }

    /// Inflate (if compressed) and turn a reassembled data message into a
    /// [`WsEvent`], reusing the shared [`finish_data_message`] validation.
    fn finish_event(&mut self, opcode: u8, payload: Vec<u8>, compressed: bool) -> Result<WsEvent> {
        match finish_data_message(opcode, payload, compressed, self.pmd.as_mut())? {
            Message::Data { opcode, payload } if opcode == OPCODE_TEXT => {
                let s = String::from_utf8(payload).map_err(|_| {
                    Error::BadResponse("WS TEXT message payload is not valid UTF-8".into())
                })?;
                Ok(WsEvent::Text(s))
            }
            Message::Data { payload, .. } => Ok(WsEvent::Binary(payload)),
            // finish_data_message only ever yields Data.
            Message::Closed => Ok(WsEvent::Close(None)),
        }
    }

    /// Send a pong frame with `payload` (≤ 125 bytes). Normally unnecessary —
    /// pings are auto-ponged — but available when [`set_auto_pong`](Self::set_auto_pong)
    /// is off or for an unsolicited keepalive pong (RFC 6455 §5.5.3).
    pub fn send_pong(&mut self, payload: &[u8]) -> Result<()> {
        self.ensure_open()?;
        self.send_control(OPCODE_PONG, payload)
    }

    /// Send a low-level frame, bypassing reassembly and permessage-deflate
    /// (the analogue of curl's raw mode). Use this to fragment a message
    /// manually (`fin = false` on all but the last frame, opcode
    /// [`WsOpcode::Continuation`] after the first) or to send an arbitrary
    /// control frame. Payloads are masked per §5.3. No compression is applied,
    /// so do not set this on a permessage-deflate-only path expecting RSV1.
    pub fn send_frame(&mut self, fin: bool, opcode: WsOpcode, payload: &[u8]) -> Result<()> {
        self.ensure_open()?;
        if opcode.is_control() {
            if !fin {
                return Err(Error::BadResponse(
                    "websocket: control frames cannot be fragmented (fin must be true)".into(),
                ));
            }
            if payload.len() > MAX_CONTROL_PAYLOAD {
                return Err(Error::BadResponse(format!(
                    "websocket: control frame payload too large: {} bytes (max {MAX_CONTROL_PAYLOAD})",
                    payload.len()
                )));
            }
        }
        let frame = build_client_frame_inner(fin, opcode.to_u8(), payload, false)?;
        self.stream.write_all(&frame).map_err(Error::Io)?;
        self.stream.flush().map_err(Error::Io)?;
        Ok(())
    }

    /// Receive a single raw frame with no reassembly, decompression, or
    /// automatic control handling (curl's raw mode). Most callers want
    /// [`recv`](Self::recv) or [`recv_event`](Self::recv_event); use this only
    /// to drive the framing yourself.
    pub fn recv_frame(&mut self) -> Result<WsFrame> {
        let frame = read_frame(&mut self.stream)?;
        Ok(WsFrame {
            fin: frame.fin,
            opcode: WsOpcode::from_u8(frame.opcode)?,
            payload: frame.payload,
        })
    }

    fn send_control(&mut self, opcode: u8, payload: &[u8]) -> Result<()> {
        if payload.len() > MAX_CONTROL_PAYLOAD {
            return Err(Error::BadResponse(format!(
                "websocket: control frame payload too large: {} bytes (max {MAX_CONTROL_PAYLOAD})",
                payload.len()
            )));
        }
        let frame = build_client_frame(opcode, payload)?;
        self.stream.write_all(&frame).map_err(Error::Io)?;
        self.stream.flush().map_err(Error::Io)?;
        Ok(())
    }

    /// Send a close frame (masked, per §5.3) and mark the connection closed.
    /// Idempotent. Drain the peer's close echo with a final [`recv`](Self::recv)
    /// if you need a clean shutdown handshake.
    pub fn close(&mut self) -> Result<()> {
        if self.send_closed {
            return Ok(());
        }
        self.send_closed = true;
        let frame = build_client_frame(OPCODE_CLOSE, &[])?;
        self.stream.write_all(&frame).map_err(Error::Io)?;
        self.stream.flush().map_err(Error::Io)?;
        Ok(())
    }

    /// Send a close frame carrying a status code and reason (RFC 6455 §5.5.1 /
    /// §7.4), then mark the connection closed. Idempotent. `code` is typically
    /// 1000 (normal closure); the reason (UTF-8) plus the 2-byte code must fit
    /// in a control frame (≤ 125 bytes).
    pub fn close_with(&mut self, code: u16, reason: &str) -> Result<()> {
        if self.send_closed {
            return Ok(());
        }
        let mut payload = Vec::with_capacity(2 + reason.len());
        payload.extend_from_slice(&code.to_be_bytes());
        payload.extend_from_slice(reason.as_bytes());
        if payload.len() > MAX_CONTROL_PAYLOAD {
            return Err(Error::BadResponse(format!(
                "websocket: close reason too long: {} bytes (max {})",
                payload.len(),
                MAX_CONTROL_PAYLOAD - 2
            )));
        }
        self.send_closed = true;
        let frame = build_client_frame(OPCODE_CLOSE, &payload)?;
        self.stream.write_all(&frame).map_err(Error::Io)?;
        self.stream.flush().map_err(Error::Io)?;
        Ok(())
    }

    fn ensure_open(&self) -> Result<()> {
        if self.send_closed {
            return Err(Error::BadResponse(
                "websocket: the connection is closed".into(),
            ));
        }
        Ok(())
    }
}

/// Drive the HTTP/1.1 upgrade handshake on `stream`. After this returns, the
/// stream sits at the first byte of the first WS frame.
///
/// Returns `Some(Pmd)` if the server agreed to permessage-deflate (RFC 7692),
/// `None` otherwise (in which case the connection operates uncompressed,
/// exactly as before).
fn handshake<S: Read + Write>(
    stream: &mut S,
    url: &Url,
    subprotocols: &[String],
) -> Result<(Option<Pmd>, Option<String>)> {
    let key_bytes: [u8; 16] = random_16()?;
    let key_b64 = base64_encode(&key_bytes);

    let host_header =
        if (url.scheme == "ws" && url.port == 80) || (url.scheme == "wss" && url.port == 443) {
            url.host.clone()
        } else {
            format!("{}:{}", url.host, url.port)
        };

    let path = if url.path.is_empty() {
        "/"
    } else {
        url.path.as_str()
    };

    // Sec-WebSocket-Protocol: comma-separated subprotocols in preference order.
    let proto_header = if subprotocols.is_empty() {
        String::new()
    } else {
        format!("Sec-WebSocket-Protocol: {}\r\n", subprotocols.join(", "))
    };

    let req = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {key_b64}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Extensions: {PMD_OFFER}\r\n\
         {proto_header}\
         \r\n"
    );
    stream.write_all(req.as_bytes())?;
    stream.flush()?;

    // Read the response headers byte-by-byte so we don't over-read into the
    // post-handshake WS frame stream. RFC 6455 requires the response end at
    // \r\n\r\n with no extra data, so this is fine.
    let buf = read_handshake_head(stream, HANDSHAKE_DEADLINE)?;

    let head = std::str::from_utf8(&buf)
        .map_err(|_| Error::BadResponse("non-utf8 handshake response".into()))?;
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| Error::BadResponse("empty handshake response".into()))?;
    if !(status_line.starts_with("HTTP/1.1 101") || status_line.starts_with("HTTP/1.0 101")) {
        return Err(Error::BadResponse(format!(
            "expected 101 Switching Protocols, got: {status_line:?}"
        )));
    }

    let mut upgrade_ok = false;
    let mut connection_ok = false;
    let mut accept_value: Option<String> = None;
    let mut extensions_value: Option<String> = None;
    let mut subprotocol_value: Option<String> = None;
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
            // Connection can be a comma-separated list of tokens.
            if v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
            {
                connection_ok = true;
            }
        } else if k.eq_ignore_ascii_case("sec-websocket-accept") {
            accept_value = Some(v.to_string());
        } else if k.eq_ignore_ascii_case("sec-websocket-protocol") {
            subprotocol_value = Some(v.to_string());
        } else if k.eq_ignore_ascii_case("sec-websocket-extensions") {
            // A server may repeat the header; concatenate as the spec allows
            // a comma-joined list to be split across lines.
            match &mut extensions_value {
                Some(existing) => {
                    existing.push_str(", ");
                    existing.push_str(v);
                }
                None => extensions_value = Some(v.to_string()),
            }
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
    let expected = derive_accept(&key_b64);
    if accept != expected {
        return Err(Error::BadResponse(format!(
            "Sec-WebSocket-Accept mismatch: got {accept:?}, expected {expected:?}"
        )));
    }

    // If the server accepted permessage-deflate, enable compression and record
    // the negotiated context-takeover parameters. Otherwise operate
    // uncompressed exactly as before.
    let pmd = extensions_value.as_deref().and_then(parse_pmd_response);

    Ok((pmd, subprotocol_value))
}

/// Read the HTTP/1.1 upgrade-handshake response header off `stream`, one byte
/// at a time, stopping at the `\r\n\r\n` terminator. Reading byte-by-byte is
/// deliberate: it must not consume any byte past the terminator, since those
/// bytes are the start of the first WS frame and would be lost.
///
/// Three independent limits bound the read:
///   * the per-`read` socket timeout (set on the stream), which caps a single
///     syscall;
///   * a 64 KiB size cap, which bounds memory; and
///   * `deadline`, a wall-clock budget for the *whole* header read, which
///     defeats a slowloris-style drip (one byte just under the socket timeout,
///     repeated up to the size cap) that the other two limits do not catch.
fn read_handshake_head<S: Read>(stream: &mut S, deadline: Duration) -> Result<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let start = Instant::now();
    loop {
        let mut b = [0u8; 1];
        let n = stream.read(&mut b)?;
        if n == 0 {
            return Err(Error::UnexpectedEof);
        }
        buf.push(b[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            break;
        }
        if buf.len() > 64 * 1024 {
            return Err(Error::BadResponse("handshake response too large".into()));
        }
        if start.elapsed() > deadline {
            return Err(Error::BadResponse(
                "handshake response timed out (header read exceeded deadline)".into(),
            ));
        }
    }
    Ok(buf)
}

/// Parse a `Sec-WebSocket-Extensions` response value and, if it selects
/// `permessage-deflate`, return the negotiated `Pmd` state. Returns `None`
/// if permessage-deflate was not selected.
///
/// The header is a comma-separated list of extensions, each a semicolon-
/// separated list of `token[=value]` parameters (RFC 7692 §7 / RFC 6455 §9.1).
/// We look only at the first `permessage-deflate` offer the server returned
/// (a compliant server returns at most one) and read the two
/// context-takeover flags; `*_max_window_bits` values are accepted but, since
/// we never carry a window on our side and bound the inflate output by byte
/// count regardless, they don't change our behaviour.
fn parse_pmd_response(value: &str) -> Option<Pmd> {
    for ext in value.split(',') {
        let mut params = ext.split(';').map(str::trim);
        let name = params.next()?;
        if !name.eq_ignore_ascii_case("permessage-deflate") {
            continue;
        }
        let mut client_no_context_takeover = false;
        let mut server_no_context_takeover = false;
        for param in params {
            if param.is_empty() {
                continue;
            }
            // A parameter may be `token` or `token=value`; we only key off the
            // token names here.
            let token = param.split('=').next().unwrap_or(param).trim();
            if token.eq_ignore_ascii_case("client_no_context_takeover") {
                client_no_context_takeover = true;
            } else if token.eq_ignore_ascii_case("server_no_context_takeover") {
                server_no_context_takeover = true;
            }
            // client_max_window_bits / server_max_window_bits are accepted but
            // intentionally ignored (see the doc comment).
        }
        return Some(Pmd {
            client_no_context_takeover,
            server_no_context_takeover,
            decoder: Deflate::decoder(),
        });
    }
    None
}

/// What `read_message` produced for the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Message {
    /// A reassembled text or binary message.
    Data { opcode: u8, payload: Vec<u8> },
    /// The peer initiated a close; we have already answered it.
    Closed,
}

/// Max payload of a control frame (RFC 6455 §5.5).
const MAX_CONTROL_PAYLOAD: usize = 125;

/// Run the receive frame loop until one full data message is reassembled or
/// the peer closes. Control frames (ping/pong/close) are handled inline:
///
///   * PING → reply with a PONG echoing the application data.
///   * PONG → ignored (unsolicited keepalive response).
///   * CLOSE → reply with a CLOSE and return [`Message::Closed`].
///
/// Control frames are honored both before the first data frame and in between
/// fragments. Data fragments (initial frame with FIN=0 followed by
/// CONTINUATION frames until FIN=1) are stitched together, with the
/// cumulative size enforced against `MAX_PAYLOAD_BYTES` so a fragmented
/// payload cannot exceed the cap that a single frame would be held to.
///
/// permessage-deflate (RFC 7692 §7.2.2): if `pmd` is `Some` (the extension
/// was negotiated) and the FIRST frame of a data message has RSV1 set, the
/// reassembled payload is raw-DEFLATE-compressed and is inflated before
/// returning, with the cumulative cap enforced on the *inflated* size. RSV1 is
/// rejected when compression was not negotiated; RSV1 on a control frame is
/// rejected; RSV1 only carries meaning on the first frame of a message (it
/// must be 0 on continuation frames).
fn read_message<S: Read + Write>(stream: &mut S, mut pmd: Option<&mut Pmd>) -> Result<Message> {
    // State for an in-progress fragmented data message. `None` means we are
    // not currently inside a fragmentation chain.
    let mut frag_opcode: Option<u8> = None;
    // Whether the in-progress message is permessage-deflate compressed (RSV1
    // was set on its first frame).
    let mut compressed = false;
    let mut buf: Vec<u8> = Vec::new();

    loop {
        let frame = read_frame(stream)?;

        // Control frames (opcode >= 0x8) may be interleaved between fragments
        // but MUST NOT themselves be fragmented and MUST have payload <= 125.
        if frame.opcode >= 0x8 {
            if frame.rsv1 {
                return Err(Error::BadResponse("RSV1 set on a WS control frame".into()));
            }
            if !frame.fin {
                return Err(Error::BadResponse(
                    "fragmented control frame (FIN=0 on a control opcode)".into(),
                ));
            }
            if frame.payload.len() > MAX_CONTROL_PAYLOAD {
                return Err(Error::BadResponse(format!(
                    "control frame payload too large: {} bytes (max {MAX_CONTROL_PAYLOAD})",
                    frame.payload.len()
                )));
            }
            match frame.opcode {
                OPCODE_PING => {
                    let pong = build_client_frame(OPCODE_PONG, &frame.payload)?;
                    stream.write_all(&pong)?;
                    stream.flush()?;
                    continue;
                }
                OPCODE_PONG => continue,
                OPCODE_CLOSE => {
                    // Echo the close (masked, per §5.3). Best-effort: if we
                    // can't build it we still report a clean close.
                    if let Ok(close) = build_client_frame(OPCODE_CLOSE, &[]) {
                        let _ = stream.write_all(&close);
                        let _ = stream.flush();
                    }
                    return Ok(Message::Closed);
                }
                other => {
                    return Err(Error::BadResponse(format!(
                        "unknown WS control opcode 0x{other:x}"
                    )));
                }
            }
        }

        // Data / continuation frames.
        match frame.opcode {
            OPCODE_TEXT | OPCODE_BINARY => {
                if frag_opcode.is_some() {
                    return Err(Error::BadResponse(
                        "new data frame began while a fragmented message was in progress".into(),
                    ));
                }
                // RSV1 on the first data frame means a compressed message — but
                // only if permessage-deflate was negotiated. Reject otherwise.
                if frame.rsv1 {
                    if pmd.is_none() {
                        return Err(Error::BadResponse(
                            "RSV1 set on a WS frame but permessage-deflate was not negotiated"
                                .into(),
                        ));
                    }
                    compressed = true;
                }
                accumulate(&mut buf, &frame.payload)?;
                if frame.fin {
                    return finish_data_message(frame.opcode, buf, compressed, pmd.as_deref_mut());
                }
                frag_opcode = Some(frame.opcode);
            }
            OPCODE_CONT => {
                let opcode = frag_opcode.ok_or_else(|| {
                    Error::BadResponse("continuation frame with no message in progress".into())
                })?;
                // RSV1 is only meaningful on the first frame of a message; a
                // continuation frame must clear it (RFC 7692 §7.2.2).
                if frame.rsv1 {
                    return Err(Error::BadResponse(
                        "RSV1 set on a WS continuation frame".into(),
                    ));
                }
                accumulate(&mut buf, &frame.payload)?;
                if frame.fin {
                    return finish_data_message(opcode, buf, compressed, pmd.as_deref_mut());
                }
            }
            other => {
                return Err(Error::BadResponse(format!("unknown WS opcode 0x{other:x}")));
            }
        }
    }
}

/// Finalise a reassembled data message: inflate it if it was permessage-
/// deflate compressed, then hand it back as a [`Message::Data`]. When
/// `compressed` is set, `pmd` must be `Some` (the read loop only sets
/// `compressed` after confirming negotiation).
fn finish_data_message(
    opcode: u8,
    payload: Vec<u8>,
    compressed: bool,
    pmd: Option<&mut Pmd>,
) -> Result<Message> {
    let payload = if compressed {
        let pmd = pmd.ok_or_else(|| {
            Error::BadResponse("compressed WS message without negotiated permessage-deflate".into())
        })?;
        pmd.inflate_message(&payload)?
    } else {
        payload
    };
    // RFC 6455 §8.1: a TEXT message MUST carry valid UTF-8; a receiver fails
    // the connection on invalid UTF-8. We validate the fully reassembled
    // (and, if applicable, inflated) buffer so a multibyte sequence split
    // across fragments still validates correctly. BINARY frames are opaque
    // and are never validated.
    if opcode == OPCODE_TEXT && std::str::from_utf8(&payload).is_err() {
        return Err(Error::BadResponse(
            "WS TEXT message payload is not valid UTF-8".into(),
        ));
    }
    Ok(Message::Data { opcode, payload })
}

/// Append `chunk` to the reassembly buffer, enforcing the cumulative cap.
/// `read_frame` already bounds a single frame; this guards against many
/// small fragments adding up past `MAX_PAYLOAD_BYTES`.
fn accumulate(buf: &mut Vec<u8>, chunk: &[u8]) -> Result<()> {
    let total = buf.len() as u64 + chunk.len() as u64;
    if total > MAX_PAYLOAD_BYTES {
        return Err(Error::BadResponse(format!(
            "reassembled WS message too large: {total} bytes (max {MAX_PAYLOAD_BYTES})"
        )));
    }
    buf.extend_from_slice(chunk);
    Ok(())
}

/// Validate an incoming control frame (opcode ≥ 0x8): RSV1 clear, not
/// fragmented, payload ≤ 125 bytes (RFC 6455 §5.4/§5.5). Mirrors the inline
/// checks in [`read_message`]; both must stay in agreement.
fn validate_control_frame(frame: &Frame) -> Result<()> {
    if frame.rsv1 {
        return Err(Error::BadResponse("RSV1 set on a WS control frame".into()));
    }
    if !frame.fin {
        return Err(Error::BadResponse(
            "fragmented control frame (FIN=0 on a control opcode)".into(),
        ));
    }
    if frame.payload.len() > MAX_CONTROL_PAYLOAD {
        return Err(Error::BadResponse(format!(
            "control frame payload too large: {} bytes (max {MAX_CONTROL_PAYLOAD})",
            frame.payload.len()
        )));
    }
    Ok(())
}

/// Parse a CLOSE frame's payload into a [`WsClose`] (RFC 6455 §5.5.1): a 2-byte
/// big-endian status code optionally followed by a UTF-8 reason. An empty
/// payload (no code) yields `None`; a 1-byte payload is malformed and also
/// yields `None` rather than erroring (we are closing regardless).
fn parse_close_payload(payload: &[u8]) -> Option<WsClose> {
    if payload.len() < 2 {
        return None;
    }
    let code = u16::from_be_bytes([payload[0], payload[1]]);
    let reason = String::from_utf8_lossy(&payload[2..]).into_owned();
    Some(WsClose { code, reason })
}

/// Send a masked client data frame. `opcode` must be [`OPCODE_TEXT`] or
/// [`OPCODE_BINARY`]; the payload is masked per RFC 6455 §5.3 using the
/// crate's CSPRNG. Drives the send side of the persistent [`WebSocket`] API.
///
/// When `pmd` is `Some` (permessage-deflate was negotiated), the payload is
/// raw-DEFLATE-compressed (RFC 7692 §7.2.1) and the frame's RSV1 bit is set.
/// We always compress and never carry encoder context across messages, so
/// each message is an independent stream (consistent with our
/// `client_no_context_takeover` offer).
fn send_message<S: Write>(
    stream: &mut S,
    opcode: u8,
    payload: &[u8],
    pmd: Option<&mut Pmd>,
) -> Result<()> {
    if opcode != OPCODE_TEXT && opcode != OPCODE_BINARY {
        return Err(Error::BadResponse(format!(
            "send_message expects a data opcode (text/binary), got 0x{opcode:x}"
        )));
    }
    let frame = if pmd.is_some() {
        let compressed = deflate_message(payload)?;
        build_client_frame_rsv1(opcode, &compressed)?
    } else {
        build_client_frame(opcode, payload)?
    };
    stream.write_all(&frame)?;
    stream.flush()?;
    Ok(())
}

/// Read frames until a full data message is reassembled, then send a close
/// frame and return that message's payload. Interleaved pings are answered
/// with pongs; a close from the server short-circuits to returning whatever
/// (likely empty) payload we have collected.
fn read_data_and_close<S: Read + Write>(stream: &mut S, pmd: Option<&mut Pmd>) -> Result<Vec<u8>> {
    let payload = match read_message(stream, pmd)? {
        Message::Data { payload, .. } => payload,
        // Peer closed before sending data; read_message already replied.
        Message::Closed => return Ok(Vec::new()),
    };

    // Polite close. Client→server frames must be masked (RFC 6455 §5.3),
    // including close frames; with a zero-length payload there's nothing to
    // mask, but we send the properly masked variant anyway to stay
    // spec-clean. A failure to obtain entropy for the close frame is
    // non-fatal: we've already captured the payload, so just skip the polite
    // close in that (extremely unlikely) case rather than discarding a good
    // result.
    if let Ok(close) = build_client_frame(OPCODE_CLOSE, &[]) {
        let _ = stream.write_all(&close);
        let _ = stream.flush();
    }
    Ok(payload)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Frame {
    fin: bool,
    /// RSV1 bit. For data messages this signals a permessage-deflate
    /// compressed payload (RFC 7692 §7.2.2) when set on the first frame.
    rsv1: bool,
    opcode: u8,
    payload: Vec<u8>,
}

/// Parse a single frame off the wire. Server-to-client frames must NOT be
/// masked per RFC 6455 §5.1; a masked frame is rejected as a protocol error.
///
/// RSV2 and RSV3 are always rejected (no extension that uses them is
/// negotiated). RSV1 is surfaced via [`Frame::rsv1`]; whether it is legal
/// depends on context (permessage-deflate negotiation + frame type), which is
/// enforced by the caller in `read_message`.
fn read_frame<S: Read>(stream: &mut S) -> Result<Frame> {
    let mut header = [0u8; 2];
    read_exact(stream, &mut header)?;
    let fin = (header[0] & 0x80) != 0;
    let rsv1 = (header[0] & 0x40) != 0;
    // RSV2/RSV3 must always be zero — no extension using them is negotiated.
    if (header[0] & 0x30) != 0 {
        return Err(Error::BadResponse(
            "non-zero RSV2/RSV3 bits on incoming WS frame".into(),
        ));
    }
    let opcode = header[0] & 0x0F;
    let masked = (header[1] & 0x80) != 0;
    if masked {
        return Err(Error::BadResponse(
            "server-to-client frame is masked".into(),
        ));
    }
    let len7 = header[1] & 0x7F;
    let payload_len: u64 = match len7 {
        0..=125 => len7 as u64,
        126 => {
            let mut ext = [0u8; 2];
            read_exact(stream, &mut ext)?;
            u16::from_be_bytes(ext) as u64
        }
        127 => {
            let mut ext = [0u8; 8];
            read_exact(stream, &mut ext)?;
            u64::from_be_bytes(ext)
        }
        _ => unreachable!(),
    };
    if payload_len > MAX_PAYLOAD_BYTES {
        return Err(Error::BadResponse(format!(
            "WS payload too large: {payload_len} bytes"
        )));
    }
    let mut payload = vec![0u8; payload_len as usize];
    if payload_len > 0 {
        read_exact(stream, &mut payload)?;
    }
    Ok(Frame {
        fin,
        rsv1,
        opcode,
        payload,
    })
}

/// Build an unfragmented client-to-server frame with the given opcode and
/// payload. Client frames must be masked (RFC 6455 §5.3), and the mask must
/// be unpredictable, so this fails if no secure entropy source is available.
fn build_client_frame(opcode: u8, payload: &[u8]) -> Result<Vec<u8>> {
    build_client_frame_inner(true, opcode, payload, false)
}

/// Like [`build_client_frame`] but with the RSV1 bit set, marking the payload
/// as permessage-deflate compressed (RFC 7692 §7.2.1). Only valid on a data
/// frame; callers guarantee that.
fn build_client_frame_rsv1(opcode: u8, payload: &[u8]) -> Result<Vec<u8>> {
    build_client_frame_inner(true, opcode, payload, true)
}

/// Build a masked client-to-server frame. `fin` controls the FIN bit (clear it
/// to start/continue a fragmented message); `rsv1` marks a permessage-deflate
/// payload. Client frames must be masked (RFC 6455 §5.3) with an unpredictable
/// mask, so this fails if no secure entropy source is available.
fn build_client_frame_inner(fin: bool, opcode: u8, payload: &[u8], rsv1: bool) -> Result<Vec<u8>> {
    let mask: [u8; 4] = {
        let r = random_16()?;
        [r[0], r[1], r[2], r[3]]
    };
    let mut out = Vec::with_capacity(2 + 8 + 4 + payload.len());
    let fin_bit = if fin { 0x80 } else { 0x00 };
    let rsv1_bit = if rsv1 { 0x40 } else { 0x00 };
    out.push(fin_bit | rsv1_bit | (opcode & 0x0F)); // FIN + RSV1 + opcode
    let n = payload.len();
    if n < 126 {
        out.push(0x80 | (n as u8));
    } else if n <= u16::MAX as usize {
        out.push(0x80 | 126);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        out.push(0x80 | 127);
        out.extend_from_slice(&(n as u64).to_be_bytes());
    }
    out.extend_from_slice(&mask);
    let start = out.len();
    out.extend_from_slice(payload);
    for (i, b) in out[start..].iter_mut().enumerate() {
        *b ^= mask[i & 3];
    }
    Ok(out)
}

fn read_exact<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<()> {
    let mut got = 0;
    while got < buf.len() {
        let n = r.read(&mut buf[got..])?;
        if n == 0 {
            return Err(Error::UnexpectedEof);
        }
        got += n;
    }
    Ok(())
}

/// `base64(sha1(key + WS_GUID))`. Used by both sides of the handshake to
/// prove the response was generated specifically for this request.
fn derive_accept(key_b64: &str) -> String {
    let mut h = Sha1::new();
    h.update(key_b64.as_bytes());
    h.update(WS_GUID.as_bytes());
    let digest = h.finalize();
    base64_encode(digest.as_ref())
}

/// 16 cryptographically-random bytes for the `Sec-WebSocket-Key` and frame
/// masks, sourced from the crate's vetted CSPRNG ([`purecrypto::rng::OsRng`],
/// the same source used by `mqtt.rs`).
///
/// `OsRng::fill_bytes` panics if it cannot read OS entropy (e.g. a missing
/// `/dev/urandom` in a locked-down sandbox). We catch that and surface it as
/// a connection error rather than either crashing the process or — worse —
/// falling back to predictable time/PID entropy: a guessable mask weakens the
/// masking the spec relies on, so failing closed is the secure choice.
fn random_16() -> Result<[u8; 16]> {
    use purecrypto::rng::{OsRng, RngCore};
    let mut out = [0u8; 16];
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        OsRng.fill_bytes(&mut out);
    }))
    .map_err(|_| Error::BadResponse("websocket: no secure entropy source available".into()))?;
    Ok(out)
}

/// Standard base64 (RFC 4648 §4) with `=` padding. Hand-rolled so we don't
/// pull in another dependency for ~30 lines of work. (Also reused by HTTP
/// Basic auth in `crate::http`.)
pub(crate) fn base64_encode(input: &[u8]) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= input.len() {
        let b0 = input[i];
        let b1 = input[i + 1];
        let b2 = input[i + 2];
        out.push(ALPHA[(b0 >> 2) as usize] as char);
        out.push(ALPHA[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(ALPHA[(((b1 & 0x0F) << 2) | (b2 >> 6)) as usize] as char);
        out.push(ALPHA[(b2 & 0x3F) as usize] as char);
        i += 3;
    }
    let rem = input.len() - i;
    if rem == 1 {
        let b0 = input[i];
        out.push(ALPHA[(b0 >> 2) as usize] as char);
        out.push(ALPHA[((b0 & 0x03) << 4) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let b0 = input[i];
        let b1 = input[i + 1];
        out.push(ALPHA[(b0 >> 2) as usize] as char);
        out.push(ALPHA[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(ALPHA[((b1 & 0x0F) << 2) as usize] as char);
        out.push('=');
    }
    out
}

// Silence unused-import warning in builds that take only the `ws://` path
// — `TlsStream` is referenced in docs but not directly in this module
// (we call `crate::tls::connect_over` instead).
#[allow(dead_code)]
fn _tlsstream_in_scope_for_docs<S: Read + Write>(_: TlsStream<S>) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// In-memory duplex stream: `inbound` is what the "server" sends to us
    /// (drained by `read`), `sent` captures what we write back. Lets us drive
    /// the full read/control-frame loop without a socket.
    struct MockStream {
        inbound: Cursor<Vec<u8>>,
        sent: Vec<u8>,
    }

    impl MockStream {
        fn new(inbound: Vec<u8>) -> Self {
            MockStream {
                inbound: Cursor::new(inbound),
                sent: Vec::new(),
            }
        }
    }

    impl Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.inbound.read(buf)
        }
    }

    impl Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.sent.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Build an unmasked server-to-client frame (server frames must not be
    /// masked) for feeding into the mock stream.
    fn server_frame(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let b0 = if fin { 0x80 } else { 0x00 } | (opcode & 0x0F);
        out.push(b0);
        let n = payload.len();
        if n < 126 {
            out.push(n as u8);
        } else if n <= u16::MAX as usize {
            out.push(126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        } else {
            out.push(127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
        out.extend_from_slice(payload);
        out
    }

    /// Like [`server_frame`] but with the RSV1 bit set on the header — used to
    /// feed permessage-deflate compressed frames into the mock stream.
    fn server_frame_rsv1(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = server_frame(fin, opcode, payload);
        out[0] |= 0x40; // set RSV1
        out
    }

    /// Raw-DEFLATE-compress `data` with compcol and strip the trailing
    /// `00 00 FF FF` terminator if present, producing a permessage-deflate
    /// message payload (RFC 7692 §7.2.1).
    fn pmd_compress(data: &[u8]) -> Vec<u8> {
        let mut out = compress_to_vec::<Deflate>(data).expect("deflate encode");
        if out.ends_with(&DEFLATE_TAIL) {
            out.truncate(out.len() - DEFLATE_TAIL.len());
        }
        out
    }

    /// A negotiated `Pmd` in `server_no_context_takeover` mode (the common
    /// case for our offer), for driving the receive path in tests.
    fn test_pmd() -> Pmd {
        Pmd {
            client_no_context_takeover: true,
            server_no_context_takeover: true,
            decoder: Deflate::decoder(),
        }
    }

    /// Decode every frame the client wrote into `sent`, returning
    /// `(opcode, unmasked_payload)` pairs. Asserts each is masked, as client
    /// frames must be (RFC 6455 §5.3).
    fn decode_sent(sent: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut frames = Vec::new();
        let mut i = 0;
        while i < sent.len() {
            let opcode = sent[i] & 0x0F;
            let masked = (sent[i + 1] & 0x80) != 0;
            assert!(masked, "client frame must be masked");
            let len7 = sent[i + 1] & 0x7F;
            i += 2;
            let len = match len7 {
                0..=125 => len7 as usize,
                126 => {
                    let l = u16::from_be_bytes([sent[i], sent[i + 1]]) as usize;
                    i += 2;
                    l
                }
                127 => {
                    let mut b = [0u8; 8];
                    b.copy_from_slice(&sent[i..i + 8]);
                    i += 8;
                    u64::from_be_bytes(b) as usize
                }
                _ => unreachable!(),
            };
            let mask = [sent[i], sent[i + 1], sent[i + 2], sent[i + 3]];
            i += 4;
            let mut payload = sent[i..i + len].to_vec();
            i += len;
            for (j, b) in payload.iter_mut().enumerate() {
                *b ^= mask[j & 3];
            }
            frames.push((opcode, payload));
        }
        frames
    }

    /// A stream that drips one byte per `read`, sleeping `per_read` first, and
    /// never emits the `\r\n\r\n` terminator — modelling a slowloris server.
    /// Used to exercise the wall-clock handshake deadline without a socket.
    struct DripStream {
        per_read: Duration,
    }

    impl Read for DripStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            std::thread::sleep(self.per_read);
            if buf.is_empty() {
                return Ok(0);
            }
            buf[0] = b'X'; // never completes "\r\n\r\n"
            Ok(1)
        }
    }

    #[test]
    fn handshake_head_reads_up_to_terminator_without_overreading() {
        // Response header followed by the first WS frame's bytes. The reader
        // must stop exactly at \r\n\r\n and leave the frame bytes unread.
        let head = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n";
        let frame = [0x81u8, 0x02, b'h', b'i'];
        let mut inbound = head.to_vec();
        inbound.extend_from_slice(&frame);
        let mut s = MockStream::new(inbound);

        let got = read_handshake_head(&mut s, Duration::from_secs(60)).expect("reads header");
        assert_eq!(
            &got, head,
            "must capture exactly the header, no frame bytes"
        );

        // The frame bytes must remain in the stream for the frame reader.
        let mut rest = Vec::new();
        s.read_to_end(&mut rest).expect("drain remainder");
        assert_eq!(rest, frame, "first-frame bytes must not be consumed");
    }

    #[test]
    fn handshake_head_deadline_trips_on_slow_drip() {
        // ~5 ms per byte against a 20 ms deadline: the wall-clock budget must
        // fire well before the 64 KiB size cap (which would need 64Ki reads).
        let mut s = DripStream {
            per_read: Duration::from_millis(5),
        };
        let err = read_handshake_head(&mut s, Duration::from_millis(20))
            .expect_err("slow drip must hit the deadline");
        match err {
            Error::BadResponse(m) => assert!(m.contains("timed out"), "unexpected message: {m}"),
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn base64_encode_hello() {
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
    }

    #[test]
    fn base64_encode_rfc4648_vectors() {
        // Classic RFC 4648 §10 vectors.
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn rfc6455_accept_derivation() {
        // The example from RFC 6455 §1.3.
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let expected = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
        assert_eq!(derive_accept(key), expected);
    }

    #[test]
    fn parse_short_text_frame() {
        // 0x81 = FIN + opcode 1 (text), 0x05 = unmasked length 5, "hello"
        let bytes = [0x81, 0x05, b'h', b'e', b'l', b'l', b'o'];
        let mut cur = Cursor::new(&bytes[..]);
        let f = read_frame(&mut cur).expect("frame parses");
        assert!(f.fin);
        assert_eq!(f.opcode, OPCODE_TEXT);
        assert_eq!(f.payload, b"hello");
    }

    #[test]
    fn parse_16bit_length_frame() {
        // 200-byte binary payload of 0x41 ('A'), length encoded as 126 + u16.
        let mut bytes: Vec<u8> = vec![0x82, 126, 0x00, 200];
        bytes.extend(std::iter::repeat_n(b'A', 200));
        let mut cur = Cursor::new(bytes);
        let f = read_frame(&mut cur).expect("frame parses");
        assert_eq!(f.opcode, OPCODE_BINARY);
        assert_eq!(f.payload.len(), 200);
        assert!(f.payload.iter().all(|&b| b == b'A'));
    }

    #[test]
    fn reject_masked_server_frame() {
        // MASK bit set, length 0 — server is not allowed to mask.
        let bytes = [0x81, 0x80, 0, 0, 0, 0];
        let mut cur = Cursor::new(&bytes[..]);
        let err = read_frame(&mut cur).expect_err("masked server frame must be rejected");
        match err {
            Error::BadResponse(_) => {}
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn build_close_frame_short_payload() {
        // Empty close frame: header byte 0x88 (FIN + opcode 8), len byte has
        // MASK bit set + payload-len 0, plus a 4-byte mask. Total: 6 bytes.
        let frame = build_client_frame(OPCODE_CLOSE, &[]).unwrap();
        assert_eq!(frame.len(), 6);
        assert_eq!(frame[0], 0x88);
        assert_eq!(frame[1], 0x80); // mask flag set, length 0
    }

    #[test]
    fn build_text_frame_masks_payload() {
        let payload = b"hi";
        let frame = build_client_frame(OPCODE_TEXT, payload).unwrap();
        // Header (2) + mask (4) + payload (2) = 8.
        assert_eq!(frame.len(), 8);
        assert_eq!(frame[0], 0x81);
        assert_eq!(frame[1], 0x82);
        let mask = [frame[2], frame[3], frame[4], frame[5]];
        let unmasked: Vec<u8> = frame[6..]
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ mask[i & 3])
            .collect();
        assert_eq!(unmasked, payload);
    }

    #[test]
    fn build_frame_uses_16bit_length_for_medium_payload() {
        let payload = vec![0u8; 200];
        let frame = build_client_frame(OPCODE_BINARY, &payload).unwrap();
        assert_eq!(frame[0], 0x82);
        assert_eq!(frame[1], 0x80 | 126);
        let len = u16::from_be_bytes([frame[2], frame[3]]);
        assert_eq!(len, 200);
        // 2 (header) + 2 (ext len) + 4 (mask) + 200 (payload).
        assert_eq!(frame.len(), 208);
    }

    #[test]
    fn build_frame_uses_64bit_length_for_large_payload() {
        let payload = vec![0u8; 70_000];
        let frame = build_client_frame(OPCODE_BINARY, &payload).unwrap();
        assert_eq!(frame[1], 0x80 | 127);
        let len = u64::from_be_bytes([
            frame[2], frame[3], frame[4], frame[5], frame[6], frame[7], frame[8], frame[9],
        ]);
        assert_eq!(len, 70_000);
    }

    #[test]
    fn random_16_is_nonzero() {
        // Astronomically unlikely the CSPRNG returns all zeros.
        let r = random_16().expect("OS entropy available in the test environment");
        assert_ne!(r, [0u8; 16]);
    }

    #[test]
    fn random_16_is_not_constant() {
        // Two draws should differ — a sanity check that we're pulling fresh
        // entropy, not a fixed seed.
        let a = random_16().unwrap();
        let b = random_16().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn reassembles_fragmented_text_message() {
        // "Hel" (text, FIN=0) + "lo " (cont, FIN=0) + "world" (cont, FIN=1).
        let mut inbound = server_frame(false, OPCODE_TEXT, b"Hel");
        inbound.extend(server_frame(false, OPCODE_CONT, b"lo "));
        inbound.extend(server_frame(true, OPCODE_CONT, b"world"));
        let mut s = MockStream::new(inbound);
        let msg = read_message(&mut s, None).expect("reassembles");
        assert_eq!(
            msg,
            Message::Data {
                opcode: OPCODE_TEXT,
                payload: b"Hello world".to_vec(),
            }
        );
    }

    #[test]
    fn invalid_utf8_text_message_is_rejected() {
        // 0xff is never valid UTF-8; a TEXT message carrying it must fail the
        // connection per RFC 6455 §8.1.
        let inbound = server_frame(true, OPCODE_TEXT, &[0xff, 0xfe]);
        let mut s = MockStream::new(inbound);
        let err = read_message(&mut s, None).expect_err("invalid utf-8 TEXT must be rejected");
        match err {
            Error::BadResponse(m) => assert!(m.contains("UTF-8"), "unexpected message: {m}"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn invalid_utf8_binary_message_is_accepted() {
        // The same bytes in a BINARY message are fine — BINARY is opaque.
        let inbound = server_frame(true, OPCODE_BINARY, &[0xff, 0xfe]);
        let mut s = MockStream::new(inbound);
        let msg = read_message(&mut s, None).expect("binary is not utf-8 validated");
        assert_eq!(
            msg,
            Message::Data {
                opcode: OPCODE_BINARY,
                payload: vec![0xff, 0xfe],
            }
        );
    }

    #[test]
    fn valid_utf8_text_message_passes() {
        // Multibyte UTF-8 (é = 0xc3 0xa9) split across two fragments still
        // validates because we check the reassembled buffer.
        let mut inbound = server_frame(false, OPCODE_TEXT, &[0xc3]);
        inbound.extend(server_frame(true, OPCODE_CONT, &[0xa9]));
        let mut s = MockStream::new(inbound);
        let msg = read_message(&mut s, None).expect("valid utf-8 across fragments");
        assert_eq!(
            msg,
            Message::Data {
                opcode: OPCODE_TEXT,
                payload: "é".as_bytes().to_vec(),
            }
        );
    }

    #[test]
    fn ping_between_fragments_gets_pong_and_message_completes() {
        // "foo" (text, FIN=0), a PING with "pingdata", then "bar" (cont,
        // FIN=1). The message must still reassemble and a PONG echoing the
        // ping data must have been sent.
        let mut inbound = server_frame(false, OPCODE_TEXT, b"foo");
        inbound.extend(server_frame(true, OPCODE_PING, b"pingdata"));
        inbound.extend(server_frame(true, OPCODE_CONT, b"bar"));
        let mut s = MockStream::new(inbound);
        let msg = read_message(&mut s, None).expect("completes despite ping");
        assert_eq!(
            msg,
            Message::Data {
                opcode: OPCODE_TEXT,
                payload: b"foobar".to_vec(),
            }
        );
        let sent = decode_sent(&s.sent);
        assert_eq!(sent.len(), 1, "exactly one pong expected");
        assert_eq!(sent[0].0, OPCODE_PONG);
        assert_eq!(sent[0].1, b"pingdata");
    }

    #[test]
    fn close_is_answered_and_returns_closed() {
        let inbound = server_frame(true, OPCODE_CLOSE, &[]);
        let mut s = MockStream::new(inbound);
        let msg = read_message(&mut s, None).expect("handles close");
        assert_eq!(msg, Message::Closed);
        let sent = decode_sent(&s.sent);
        assert_eq!(sent.len(), 1, "exactly one close reply expected");
        assert_eq!(sent[0].0, OPCODE_CLOSE);
    }

    #[test]
    fn unsolicited_pong_is_ignored_then_data_returns() {
        let mut inbound = server_frame(true, OPCODE_PONG, b"x");
        inbound.extend(server_frame(true, OPCODE_TEXT, b"hi"));
        let mut s = MockStream::new(inbound);
        let msg = read_message(&mut s, None).expect("ignores pong");
        assert_eq!(
            msg,
            Message::Data {
                opcode: OPCODE_TEXT,
                payload: b"hi".to_vec(),
            }
        );
        // Nothing should have been written for the pong.
        assert!(s.sent.is_empty(), "unsolicited pong must not be answered");
    }

    #[test]
    fn send_message_produces_masked_frame() {
        let mut s = MockStream::new(Vec::new());
        send_message(&mut s, OPCODE_TEXT, b"hello", None).expect("sends");
        // Raw bytes: FIN+text, MASK+len, 4-byte mask, 5 masked bytes.
        assert_eq!(s.sent[0], 0x81);
        assert_eq!(s.sent[1], 0x80 | 5);
        assert_eq!(s.sent.len(), 2 + 4 + 5);
        let decoded = decode_sent(&s.sent);
        assert_eq!(decoded, vec![(OPCODE_TEXT, b"hello".to_vec())]);
    }

    #[test]
    fn send_message_rejects_control_opcode() {
        let mut s = MockStream::new(Vec::new());
        let err = send_message(&mut s, OPCODE_PING, b"x", None)
            .expect_err("control opcode must be rejected for send_message");
        match err {
            Error::BadResponse(_) => {}
            other => panic!("wrong error: {other:?}"),
        }
        assert!(s.sent.is_empty());
    }

    #[test]
    fn oversized_cumulative_fragmented_payload_is_rejected() {
        // Two frames whose individual sizes are fine, but whose sum exceeds
        // MAX_PAYLOAD_BYTES — the cumulative cap must catch it. We forge the
        // header to claim a huge length without actually allocating the bytes
        // would still trip read_frame's per-frame cap, so instead we lower the
        // bar by checking `accumulate` directly against the cap boundary.
        let mut buf = vec![0u8; (MAX_PAYLOAD_BYTES - 1) as usize];
        // One more byte is exactly at the cap: allowed.
        accumulate(&mut buf, &[0u8]).expect("exactly at the cap is allowed");
        // The next byte pushes over the cap: rejected.
        let err = accumulate(&mut buf, &[0u8]).expect_err("over the cap must be rejected");
        match err {
            Error::BadResponse(_) => {}
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn fragmented_control_frame_is_rejected() {
        // A PING with FIN=0 is illegal: control frames must not be fragmented.
        let inbound = server_frame(false, OPCODE_PING, b"x");
        let mut s = MockStream::new(inbound);
        let err = read_message(&mut s, None).expect_err("fragmented control must be rejected");
        match err {
            Error::BadResponse(_) => {}
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn oversized_control_frame_is_rejected() {
        // A PING with a 126-byte payload exceeds the 125-byte control cap.
        let inbound = server_frame(true, OPCODE_PING, &[0u8; 126]);
        let mut s = MockStream::new(inbound);
        let err = read_message(&mut s, None).expect_err("oversized control must be rejected");
        match err {
            Error::BadResponse(_) => {}
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn new_data_frame_during_fragmentation_is_rejected() {
        // text(FIN=0) then a second text(FIN=1) without a continuation: the
        // peer must use opcode 0x0 to continue, so this is a protocol error.
        let mut inbound = server_frame(false, OPCODE_TEXT, b"a");
        inbound.extend(server_frame(true, OPCODE_TEXT, b"b"));
        let mut s = MockStream::new(inbound);
        let err =
            read_message(&mut s, None).expect_err("interleaved new data frame must be rejected");
        match err {
            Error::BadResponse(_) => {}
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn lone_continuation_frame_is_rejected() {
        // A continuation frame with no message in progress is illegal.
        let inbound = server_frame(true, OPCODE_CONT, b"x");
        let mut s = MockStream::new(inbound);
        let err = read_message(&mut s, None).expect_err("lone continuation must be rejected");
        match err {
            Error::BadResponse(_) => {}
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn read_data_and_close_returns_reassembled_payload_and_sends_close() {
        let mut inbound = server_frame(false, OPCODE_BINARY, &[1, 2, 3]);
        inbound.extend(server_frame(true, OPCODE_CONT, &[4, 5]));
        let mut s = MockStream::new(inbound);
        let payload = read_data_and_close(&mut s, None).expect("reads message");
        assert_eq!(payload, vec![1, 2, 3, 4, 5]);
        // A polite close should have been written.
        let sent = decode_sent(&s.sent);
        assert_eq!(sent.last().map(|f| f.0), Some(OPCODE_CLOSE));
    }

    // ─── permessage-deflate (RFC 7692) ──────────────────────────────────────

    /// Decode one client frame including its RSV1 bit: `(opcode, rsv1, payload)`.
    fn decode_first_frame_with_rsv1(sent: &[u8]) -> (u8, bool, Vec<u8>) {
        let opcode = sent[0] & 0x0F;
        let rsv1 = (sent[0] & 0x40) != 0;
        let masked = (sent[1] & 0x80) != 0;
        assert!(masked, "client frame must be masked");
        let len7 = sent[1] & 0x7F;
        let mut i = 2;
        let len = match len7 {
            0..=125 => len7 as usize,
            126 => {
                let l = u16::from_be_bytes([sent[i], sent[i + 1]]) as usize;
                i += 2;
                l
            }
            127 => {
                let mut b = [0u8; 8];
                b.copy_from_slice(&sent[i..i + 8]);
                i += 8;
                u64::from_be_bytes(b) as usize
            }
            _ => unreachable!(),
        };
        let mask = [sent[i], sent[i + 1], sent[i + 2], sent[i + 3]];
        i += 4;
        let mut payload = sent[i..i + len].to_vec();
        for (j, b) in payload.iter_mut().enumerate() {
            *b ^= mask[j & 3];
        }
        (opcode, rsv1, payload)
    }

    /// Inflate a permessage-deflate payload the way a server would: append the
    /// stripped terminator and run raw deflate.
    fn pmd_inflate(compressed: &[u8]) -> Vec<u8> {
        let mut input = compressed.to_vec();
        input.extend_from_slice(&DEFLATE_TAIL);
        let mut dec = Deflate::decoder();
        let mut out = Vec::new();
        let mut scratch = vec![0u8; 32 * 1024];
        let mut consumed = 0usize;
        loop {
            let before_c = consumed;
            let before_w = out.len();
            let (p, status) = dec
                .decode(&input[consumed..], &mut scratch)
                .expect("inflate");
            out.extend_from_slice(&scratch[..p.written]);
            consumed += p.consumed;
            match status {
                Status::StreamEnd => break,
                Status::OutputFull => continue,
                Status::InputEmpty => {
                    if consumed >= input.len() || (consumed == before_c && out.len() == before_w) {
                        break;
                    }
                }
            }
        }
        out
    }

    #[test]
    fn handshake_offers_permessage_deflate() {
        // The upgrade request must advertise a permessage-deflate offer. Drive
        // a handshake against a mock server that returns a valid 101 and see
        // what we wrote.
        struct Recorder {
            request: Vec<u8>,
            response: Cursor<Vec<u8>>,
        }
        impl Read for Recorder {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.response.read(buf)
            }
        }
        impl Write for Recorder {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.request.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        // We can't predict the random key, so we can't precompute Accept; build
        // the response after observing the request. Easiest: run handshake
        // twice isn't possible on one stream, so instead capture the request
        // by sending a deliberately-wrong response and asserting on the bytes
        // we wrote before the Accept check fails.
        let resp = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: wrong\r\n\r\n".to_vec();
        let mut rec = Recorder {
            request: Vec::new(),
            response: Cursor::new(resp),
        };
        let url = Url::parse("ws://example.com/chat").expect("url");
        let _ = handshake(&mut rec, &url, &[]); // Accept mismatch is fine here.
        let req = String::from_utf8(rec.request).expect("utf8 request");
        assert!(
            req.contains("Sec-WebSocket-Extensions: permessage-deflate"),
            "request must offer permessage-deflate, got:\n{req}"
        );
        assert!(req.contains("client_no_context_takeover"));
        assert!(req.contains("server_no_context_takeover"));
    }

    #[test]
    fn parse_pmd_response_enables_compression() {
        let pmd = parse_pmd_response("permessage-deflate; server_no_context_takeover")
            .expect("permessage-deflate accepted");
        assert!(pmd.server_no_context_takeover);
        assert!(!pmd.client_no_context_takeover);

        let pmd2 = parse_pmd_response(
            "permessage-deflate; client_no_context_takeover; server_no_context_takeover",
        )
        .expect("accepted with both flags");
        assert!(pmd2.client_no_context_takeover);
        assert!(pmd2.server_no_context_takeover);
    }

    #[test]
    fn parse_pmd_response_without_extension_is_none() {
        // No permessage-deflate token at all → compression stays off.
        assert!(parse_pmd_response("some-other-extension").is_none());
        assert!(parse_pmd_response("").is_none());
        // A different (unrelated) extension alongside is still no PMD.
        assert!(parse_pmd_response("foo; bar=1").is_none());
    }

    #[test]
    fn inflate_compressed_message_decodes_to_original() {
        // A known raw-DEFLATE payload (built with compcol, terminator stripped)
        // framed with RSV1 set must decode back to the original string.
        let original = b"the quick brown fox jumps over the lazy dog, the quick brown fox";
        let compressed = pmd_compress(original);
        assert!(
            compressed.len() < original.len(),
            "fixture should actually compress"
        );
        let inbound = server_frame_rsv1(true, OPCODE_TEXT, &compressed);
        let mut s = MockStream::new(inbound);
        let mut pmd = test_pmd();
        let msg = read_message(&mut s, Some(&mut pmd)).expect("decodes compressed message");
        assert_eq!(
            msg,
            Message::Data {
                opcode: OPCODE_TEXT,
                payload: original.to_vec(),
            }
        );
    }

    #[test]
    fn send_message_compressed_round_trips() {
        // send_message with compression on must produce an RSV1 frame whose
        // payload, once the terminator is appended and inflated, equals input.
        let input = b"hello hello hello permessage-deflate round trip";
        let mut s = MockStream::new(Vec::new());
        let mut pmd = test_pmd();
        send_message(&mut s, OPCODE_TEXT, input, Some(&mut pmd)).expect("sends compressed");
        let (opcode, rsv1, payload) = decode_first_frame_with_rsv1(&s.sent);
        assert_eq!(opcode, OPCODE_TEXT);
        assert!(rsv1, "compressed frame must have RSV1 set");
        assert_ne!(payload, input, "payload should be compressed, not raw");
        assert_eq!(pmd_inflate(&payload), input);
    }

    #[test]
    fn rsv1_without_negotiation_is_rejected() {
        // RSV1 set on a data frame but compression was never negotiated (pmd
        // is None) must be rejected as a protocol error.
        let inbound = server_frame_rsv1(true, OPCODE_TEXT, b"whatever");
        let mut s = MockStream::new(inbound);
        let err = read_message(&mut s, None).expect_err("RSV1 without PMD must be rejected");
        match err {
            Error::BadResponse(_) => {}
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn rsv2_or_rsv3_always_rejected() {
        // RSV2 set (0x20) — always illegal, even with PMD negotiated.
        let mut inbound = server_frame(true, OPCODE_TEXT, b"x");
        inbound[0] |= 0x20;
        let mut s = MockStream::new(inbound);
        let mut pmd = test_pmd();
        let err = read_message(&mut s, Some(&mut pmd)).expect_err("RSV2 must be rejected");
        assert!(matches!(err, Error::BadResponse(_)));

        // RSV3 set (0x10) — likewise.
        let mut inbound = server_frame(true, OPCODE_TEXT, b"x");
        inbound[0] |= 0x10;
        let mut s = MockStream::new(inbound);
        let mut pmd = test_pmd();
        let err = read_message(&mut s, Some(&mut pmd)).expect_err("RSV3 must be rejected");
        assert!(matches!(err, Error::BadResponse(_)));
    }

    #[test]
    fn rsv1_on_control_frame_is_rejected() {
        // A PING with RSV1 set is illegal even when PMD is negotiated —
        // compression applies to data messages only.
        let inbound = server_frame_rsv1(true, OPCODE_PING, b"x");
        let mut s = MockStream::new(inbound);
        let mut pmd = test_pmd();
        let err =
            read_message(&mut s, Some(&mut pmd)).expect_err("RSV1 on control must be rejected");
        assert!(matches!(err, Error::BadResponse(_)));
    }

    #[test]
    fn compressed_bomb_exceeding_cap_is_rejected() {
        // A highly-compressible payload that inflates beyond MAX_PAYLOAD_BYTES
        // must be rejected by the bounded inflate, not materialised.
        let huge = vec![0u8; (MAX_PAYLOAD_BYTES + (1 << 20)) as usize];
        let compressed = pmd_compress(&huge);
        assert!(
            (compressed.len() as u64) < MAX_PAYLOAD_BYTES,
            "fixture must be much smaller than the cap"
        );
        let inbound = server_frame_rsv1(true, OPCODE_BINARY, &compressed);
        let mut s = MockStream::new(inbound);
        let mut pmd = test_pmd();
        let err =
            read_message(&mut s, Some(&mut pmd)).expect_err("compression bomb must be rejected");
        match err {
            Error::BadResponse(msg) => {
                assert!(msg.contains("permessage-deflate"), "got {msg:?}")
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn fragmented_compressed_message_reassembles_and_inflates() {
        // RSV1 on the first frame, payload split across a TEXT(FIN=0) +
        // CONTINUATION(FIN=1). The whole compressed blob is reassembled, then
        // inflated as one unit.
        let original = b"fragmented compressed payload, split across two frames on the wire";
        let compressed = pmd_compress(original);
        assert!(compressed.len() >= 4, "need enough bytes to split");
        let mid = compressed.len() / 2;
        let mut inbound = server_frame_rsv1(false, OPCODE_TEXT, &compressed[..mid]);
        inbound.extend(server_frame(true, OPCODE_CONT, &compressed[mid..]));
        let mut s = MockStream::new(inbound);
        let mut pmd = test_pmd();
        let msg = read_message(&mut s, Some(&mut pmd)).expect("reassembles + inflates");
        assert_eq!(
            msg,
            Message::Data {
                opcode: OPCODE_TEXT,
                payload: original.to_vec(),
            }
        );
    }

    #[test]
    fn rsv1_on_continuation_frame_is_rejected() {
        // RSV1 is only meaningful on a message's first frame; setting it on a
        // continuation is a protocol error.
        let original = b"continuation rsv1 should be rejected here";
        let compressed = pmd_compress(original);
        let mid = compressed.len() / 2;
        let mut inbound = server_frame_rsv1(false, OPCODE_TEXT, &compressed[..mid]);
        inbound.extend(server_frame_rsv1(true, OPCODE_CONT, &compressed[mid..]));
        let mut s = MockStream::new(inbound);
        let mut pmd = test_pmd();
        let err = read_message(&mut s, Some(&mut pmd))
            .expect_err("RSV1 on continuation must be rejected");
        assert!(matches!(err, Error::BadResponse(_)));
    }

    #[test]
    fn uncompressed_message_passes_through_when_pmd_negotiated() {
        // Even with PMD negotiated, a server may send an uncompressed message
        // (RSV1 clear). It must be returned verbatim, not run through inflate.
        let inbound = server_frame(true, OPCODE_TEXT, b"plain text, no rsv1");
        let mut s = MockStream::new(inbound);
        let mut pmd = test_pmd();
        let msg = read_message(&mut s, Some(&mut pmd)).expect("plain message");
        assert_eq!(
            msg,
            Message::Data {
                opcode: OPCODE_TEXT,
                payload: b"plain text, no rsv1".to_vec(),
            }
        );
    }

    // ---- Persistent WebSocket API ----

    use std::sync::{Arc, Mutex};

    /// A `Send` in-memory duplex usable as a [`WebSocket`] data path: `inbound`
    /// is the server→client byte stream (drained by `read`); `sent` captures
    /// client→server bytes. `Clone` shares both, so a test can keep a handle to
    /// inspect `sent` after moving a clone into the `WebSocket`.
    #[derive(Clone)]
    struct SharedMock {
        inbound: Arc<Mutex<Cursor<Vec<u8>>>>,
        sent: Arc<Mutex<Vec<u8>>>,
    }

    impl SharedMock {
        fn new(inbound: Vec<u8>) -> Self {
            SharedMock {
                inbound: Arc::new(Mutex::new(Cursor::new(inbound))),
                sent: Arc::new(Mutex::new(Vec::new())),
            }
        }
        fn sent(&self) -> Vec<u8> {
            self.sent.lock().unwrap().clone()
        }
    }

    impl Read for SharedMock {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.inbound.lock().unwrap().read(buf)
        }
    }

    impl Write for SharedMock {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.sent.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Build a [`WebSocket`] driven by an in-memory `mock` (no real socket, so
    /// no control handle / timeouts).
    fn ws_over(mock: SharedMock, pmd: Option<Pmd>) -> WebSocket {
        let compression = pmd.is_some();
        WebSocket {
            stream: Box::new(mock),
            ctl: None,
            pmd,
            send_closed: false,
            recv_closed: false,
            compression,
            auto_pong: true,
            subprotocol: None,
        }
    }

    #[test]
    fn websocket_recv_maps_text_binary_and_close() {
        let mut inbound = Vec::new();
        inbound.extend(server_frame(true, OPCODE_TEXT, b"hello"));
        inbound.extend(server_frame(true, OPCODE_BINARY, &[1, 2, 3]));
        inbound.extend(server_frame(true, OPCODE_CLOSE, &[]));
        let mut ws = ws_over(SharedMock::new(inbound), None);

        assert_eq!(ws.recv().unwrap(), Some(WsMessage::Text("hello".into())));
        assert_eq!(ws.recv().unwrap(), Some(WsMessage::Binary(vec![1, 2, 3])));
        // Peer close → Ok(None), and the connection is now closed for good.
        assert_eq!(ws.recv().unwrap(), None);
        assert!(ws.is_closed());
        assert_eq!(ws.recv().unwrap(), None);
    }

    #[test]
    fn websocket_send_text_writes_one_masked_text_frame() {
        let mock = SharedMock::new(Vec::new());
        let mut ws = ws_over(mock.clone(), None);
        ws.send_text("hi there").unwrap();
        let frames = decode_sent(&mock.sent());
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0, OPCODE_TEXT);
        assert_eq!(frames[0].1, b"hi there");
    }

    #[test]
    fn websocket_close_sends_close_frame_and_blocks_further_sends() {
        let mock = SharedMock::new(Vec::new());
        let mut ws = ws_over(mock.clone(), None);
        ws.close().unwrap();
        let frames = decode_sent(&mock.sent());
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0, OPCODE_CLOSE);
        assert!(ws.is_closed());
        // Sending after close is an error; close is idempotent.
        assert!(ws.send_text("nope").is_err());
        ws.close().unwrap();
    }

    #[test]
    fn websocket_recv_autoresponds_ping_with_pong() {
        let mut inbound = Vec::new();
        inbound.extend(server_frame(true, OPCODE_PING, b"pingdata"));
        inbound.extend(server_frame(true, OPCODE_TEXT, b"after ping"));
        let mock = SharedMock::new(inbound);
        let mut ws = ws_over(mock.clone(), None);

        assert_eq!(
            ws.recv().unwrap(),
            Some(WsMessage::Text("after ping".into()))
        );
        // The interleaved ping must have been answered with a pong echoing its
        // application data, before the text message was returned.
        let frames = decode_sent(&mock.sent());
        assert!(
            frames
                .iter()
                .any(|(op, pl)| *op == OPCODE_PONG && pl.as_slice() == b"pingdata"),
            "expected an automatic PONG echoing the ping data, got {frames:?}"
        );
    }

    #[test]
    fn websocket_recv_inflates_compressed_message() {
        let payload = "compress me ".repeat(8);
        let inbound = server_frame_rsv1(true, OPCODE_TEXT, &pmd_compress(payload.as_bytes()));
        let mut ws = ws_over(SharedMock::new(inbound), Some(test_pmd()));
        assert!(ws.compression_enabled());
        assert_eq!(ws.recv().unwrap(), Some(WsMessage::Text(payload)));
    }

    #[test]
    fn websocket_recv_event_surfaces_ping_pong_and_close_code() {
        let mut inbound = Vec::new();
        inbound.extend(server_frame(true, OPCODE_PING, b"pp"));
        inbound.extend(server_frame(true, OPCODE_PONG, b"qq"));
        let mut close_payload = 1001u16.to_be_bytes().to_vec();
        close_payload.extend_from_slice(b"bye");
        inbound.extend(server_frame(true, OPCODE_CLOSE, &close_payload));

        let mock = SharedMock::new(inbound);
        let mut ws = ws_over(mock.clone(), None);

        assert_eq!(ws.recv_event().unwrap(), WsEvent::Ping(b"pp".to_vec()));
        assert_eq!(ws.recv_event().unwrap(), WsEvent::Pong(b"qq".to_vec()));
        assert_eq!(
            ws.recv_event().unwrap(),
            WsEvent::Close(Some(WsClose {
                code: 1001,
                reason: "bye".to_string(),
            }))
        );
        assert!(ws.is_closed());
        // The surfaced ping was still auto-answered with a pong.
        let frames = decode_sent(&mock.sent());
        assert!(frames
            .iter()
            .any(|(op, pl)| *op == OPCODE_PONG && pl == b"pp"));
    }

    #[test]
    fn websocket_no_autopong_when_disabled() {
        let inbound = server_frame(true, OPCODE_PING, b"hi");
        let mock = SharedMock::new(inbound);
        let mut ws = ws_over(mock.clone(), None);
        ws.set_auto_pong(false);
        assert_eq!(ws.recv_event().unwrap(), WsEvent::Ping(b"hi".to_vec()));
        // No pong should have been written.
        let frames = decode_sent(&mock.sent());
        assert!(
            !frames.iter().any(|(op, _)| *op == OPCODE_PONG),
            "auto-pong was disabled but a PONG was sent: {frames:?}"
        );
    }

    #[test]
    fn websocket_send_pong_and_close_with_write_expected_frames() {
        let mock = SharedMock::new(Vec::new());
        let mut ws = ws_over(mock.clone(), None);
        ws.send_pong(b"keepalive").unwrap();
        ws.close_with(1000, "done").unwrap();
        let frames = decode_sent(&mock.sent());
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].0, OPCODE_PONG);
        assert_eq!(frames[0].1, b"keepalive");
        assert_eq!(frames[1].0, OPCODE_CLOSE);
        let mut expected = 1000u16.to_be_bytes().to_vec();
        expected.extend_from_slice(b"done");
        assert_eq!(frames[1].1, expected);
        assert!(ws.is_closed());
    }

    #[test]
    fn websocket_send_frame_fragments_a_message() {
        let mock = SharedMock::new(Vec::new());
        let mut ws = ws_over(mock.clone(), None);
        // Manual fragmentation: first frame TEXT/FIN=0, then a CONT/FIN=1.
        ws.send_frame(false, WsOpcode::Text, b"ab").unwrap();
        ws.send_frame(true, WsOpcode::Continuation, b"cd").unwrap();
        let raw = mock.sent();
        // FIN bit clear on the first frame, set on the second.
        assert_eq!(raw[0] & 0x80, 0x00, "first fragment must have FIN=0");
        let frames = decode_sent(&raw);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].0, OPCODE_TEXT);
        assert_eq!(frames[0].1, b"ab");
        assert_eq!(frames[1].0, OPCODE_CONT);
        assert_eq!(frames[1].1, b"cd");
        // A control frame may not be fragmented.
        assert!(ws.send_frame(false, WsOpcode::Ping, b"x").is_err());
    }

    #[test]
    fn websocket_recv_frame_returns_raw_frame() {
        let inbound = server_frame(true, OPCODE_TEXT, b"raw");
        let mut ws = ws_over(SharedMock::new(inbound), None);
        let f = ws.recv_frame().unwrap();
        assert_eq!(
            f,
            WsFrame {
                fin: true,
                opcode: WsOpcode::Text,
                payload: b"raw".to_vec(),
            }
        );
    }
}

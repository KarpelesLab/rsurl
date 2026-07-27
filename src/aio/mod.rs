//! Experimental **async** HTTP + WebSocket client that compiles for both native
//! targets and the browser.
//!
//! On native targets this is the public entry point onto the runtime-agnostic
//! sans-IO engine: a protocol state machine driven over an async connection
//! supplied by a [`Runtime`] you provide (or the built-in [`TokioRuntime`],
//! behind the `tokio-rt` feature). Unlike the blocking API, it composes with
//! `async`/`await` and idiomatic concurrency — fan many [`get`] futures out with
//! `FuturesUnordered` / `JoinSet` instead of a curl-style multi handle.
//!
//! ```no_run
//! # #[cfg(all(feature = "tokio-rt", not(target_arch = "wasm32")))]
//! # async fn ex() -> Result<(), rsurl::Error> {
//! let rt = rsurl::aio::TokioRuntime;
//! let resp = rsurl::aio::get(&rt, "https://example.com/").await?;
//! println!("{} {} bytes", resp.status, resp.body.len());
//! # Ok(()) }
//! ```
//!
//! Scope (current cut): HTTP/1.1 over `http`/`https` with an arbitrary method,
//! request body, and caller headers (see [`Request`]); optional redirect
//! following, automatic response decompression, and a whole-request
//! [`timeout`](Request::timeout); buffered response. Each request uses a fresh
//! `Connection: close` socket — connection pooling and streaming (non-buffered)
//! bodies are part of the ongoing sans-IO cutover and are not yet wired on this
//! async path.
//!
//! # On wasm32 (browser)
//!
//! `wasm32-unknown-unknown` has no sockets, no threads, and cannot block, so the
//! native sans-IO/socket path above does not compile there. Instead this module
//! routes [`request`] through the browser **Fetch API** and offers
//! [`WebSocket`] over the browser's native `WebSocket` object.
//!
//! ## What is portable, and what is not
//!
//! Portable **without any `cfg`** — the shared vocabulary of this module:
//!
//!   * [`Request`] and every builder on it, [`Response`] and every accessor on
//!     it ([`header`](Response::header), [`text`](Response::text),
//!     [`error_for_status`](Response::error_for_status), …), [`WsMessage`], and
//!     [`crate::Error`] / [`crate::Result`].
//!   * Every WebSocket *method*: `send` / `send_text` / `send_binary` / `recv` /
//!     `close` / `close_with` / `subprotocol` / `is_closed` has the same name,
//!     the same `&mut self` receiver, the same `async`-ness, and the same return
//!     type on both targets, so the body of a transfer loop needs no `cfg`.
//!
//! Needs a **`cfg` at the seam** — the two places a runtime is named:
//!
//!   * The entry points take a [`Runtime`] natively and nothing on wasm:
//!     `get(&rt, url)` vs `get(url)`, `WebSocket::connect(&rt, url)` vs
//!     `WebSocket::connect(url)`. The browser event loop *is* the runtime.
//!   * The native [`WebSocket`] is generic over the runtime's connection
//!     ([`TokioWebSocket`] names the `tokio-rt` one); the browser one is not
//!     generic. Write the `connect` behind a `cfg` and pass the value on:
//!
//! ```no_run
//! # use rsurl::aio::{Result, WsMessage};
//! # #[cfg(all(feature = "tokio-rt", not(target_arch = "wasm32")))]
//! # type Sock = rsurl::aio::TokioWebSocket;
//! # #[cfg(target_arch = "wasm32")]
//! # type Sock = rsurl::aio::WebSocket;
//! // The connect is target-specific…
//! # #[cfg(all(feature = "tokio-rt", not(target_arch = "wasm32")))]
//! async fn open(url: &str) -> Result<Sock> {
//!     Sock::connect(&rsurl::aio::TokioRuntime, url).await
//! }
//! # #[cfg(target_arch = "wasm32")]
//! # async fn open(url: &str) -> Result<Sock> { Sock::connect(url).await }
//!
//! // …everything after it is not.
//! # #[cfg(any(target_arch = "wasm32", all(feature = "tokio-rt", not(target_arch = "wasm32"))))]
//! async fn echo(ws: &mut Sock) -> Result<()> {
//!     ws.send_text("ping").await?;
//!     while let Some(msg) = ws.recv().await {
//!         if let WsMessage::Text(t) = msg? {
//!             println!("{t}");
//!             break;
//!         }
//!     }
//!     ws.close().await
//! }
//! ```
//!
//! Browser-imposed limits you inherit on wasm (none are rsurl bugs):
//!   * **Forbidden request headers** — the browser silently drops `Host`,
//!     `Connection`, `Content-Length`, and parts of `User-Agent`; rsurl does not
//!     synthesise them (fetch sets them itself).
//!   * **CORS** — cross-origin requests need server opt-in; a `no-cors` fetch
//!     yields an opaque, unreadable response.
//!   * **No TLS control**, **redirects/cookies are browser-managed**, and the
//!     response body arrives already decompressed (its `Content-Encoding` is
//!     stripped by the browser), so [`Request::decompress`] is a no-op here.
//!   * **No custom WebSocket handshake headers** (no `Authorization`); only
//!     subprotocols, via
//!     [`connect_with_subprotocols`](WebSocket::connect_with_subprotocols).
//!     Ping/pong control frames are the browser's business and are not visible.
//!   * The wasm-only `WebSocket::split` has no native counterpart: natively a
//!     single `WebSocket` owns the connection (use the blocking
//!     [`crate::WebSocket::split`] if you need two threads).

use std::time::Duration;

use crate::error::Error;
pub use crate::error::Result;

// ─── Native (socket) backend ────────────────────────────────────────────────
#[cfg(not(target_arch = "wasm32"))]
mod native;
// Same `WebSocket` name/surface as the browser one, but generic over the
// runtime's connection and taking a `Runtime` at connect (there is no implicit
// event loop natively).
#[cfg(not(target_arch = "wasm32"))]
mod ws;

#[cfg(not(target_arch = "wasm32"))]
pub use crate::io::runtime::{AsyncConn, Runtime};
#[cfg(all(feature = "tokio-rt", not(target_arch = "wasm32")))]
pub use crate::io::tokio::{TokioConn, TokioRuntime};
#[cfg(not(target_arch = "wasm32"))]
pub use native::{get, post, request};
#[cfg(not(target_arch = "wasm32"))]
pub use ws::WebSocket;

/// The [`WebSocket`] type produced by [`TokioRuntime`] — the name to write down
/// when storing one in a struct, since `WebSocket` is generic over the runtime's
/// connection type.
#[cfg(all(feature = "tokio-rt", not(target_arch = "wasm32")))]
pub type TokioWebSocket = WebSocket<TokioConn>;

// ─── Browser (fetch / WebSocket) backend ────────────────────────────────────
#[cfg(target_arch = "wasm32")]
mod wasm;
#[cfg(target_arch = "wasm32")]
pub use wasm::{get, post, request, WebSocket, WsSink, WsStream};

/// A buffered HTTP response from [`request`] (or [`get`] / [`post`]).
///
/// Non-exhaustive: it is constructed only by this module, and matching on it
/// needs a `..` rest pattern — fields may be added in a future release.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Response {
    /// HTTP status code (e.g. 200).
    pub status: u16,
    /// Reason phrase (may be empty on HTTP/2-style status lines).
    pub reason: String,
    /// Response headers, in received order.
    pub headers: Vec<(String, String)>,
    /// The response body. Decoded by default when the server applied a
    /// `Content-Encoding` (gzip / deflate / zstd / br); the
    /// `Content-Encoding`/`Content-Length` headers are stripped to match. Set
    /// [`Request::decompress(false)`](Request::decompress) to receive the raw
    /// encoded bytes instead.
    ///
    /// On wasm the browser applies any content coding before rsurl sees the
    /// bytes, so this is always the plaintext.
    pub body: Vec<u8>,
}

impl Response {
    /// The first value of header `name`, matched case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Whether the status is a `2xx` success.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Decode the body to a `String` using the `Content-Type` charset.
    ///
    /// UTF-8 (the default when no charset is declared) is decoded lossily —
    /// invalid sequences become `U+FFFD`, like [`crate::Response::text`];
    /// ISO-8859-1 / Latin-1 is mapped directly. A declared charset rsurl cannot
    /// decode returns [`Error::Decode`] (use [`body`](Self::body) for the raw
    /// bytes).
    pub fn text(&self) -> Result<String> {
        match self.charset().as_deref() {
            None | Some("utf-8") | Some("utf8") | Some("us-ascii") | Some("ascii") => {
                Ok(String::from_utf8_lossy(&self.body).into_owned())
            }
            // Latin-1 code points are exactly Unicode U+00..=U+FF, so a byte→char
            // map is a faithful decode (unlike windows-1252, which differs in
            // 0x80–0x9F and is therefore rejected rather than mis-decoded).
            Some("iso-8859-1") | Some("iso8859-1") | Some("latin1") => {
                Ok(self.body.iter().map(|&b| b as char).collect())
            }
            Some(other) => Err(Error::Decode(format!(
                "unsupported Content-Type charset {other:?}; \
                 use Response::body for the raw {} bytes",
                self.body.len()
            ))),
        }
    }

    /// Deserialize the body as JSON into `T`. Requires the `json` Cargo feature
    /// (pure-Rust `serde_json`, off by default).
    #[cfg(feature = "json")]
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body).map_err(|e| Error::Decode(format!("json: {e}")))
    }

    /// Consume the response, returning it unchanged for a 1xx–3xx status or
    /// [`Error::Status`] for a 4xx/5xx one — the reqwest-style "turn an HTTP
    /// error status into a `Result` error" convenience. The async counterpart of
    /// [`crate::Response::error_for_status`].
    pub fn error_for_status(self) -> Result<Self> {
        if self.status >= 400 {
            Err(Error::Status {
                code: self.status,
                reason: self.reason.clone(),
            })
        } else {
            Ok(self)
        }
    }

    /// Consume the response and return just the body bytes.
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }

    /// The lowercased `charset=` parameter of `Content-Type`, if declared.
    fn charset(&self) -> Option<String> {
        let ct = self.header("content-type")?;
        ct.split(';').skip(1).find_map(|param| {
            let (k, v) = param.split_once('=')?;
            if !k.trim().eq_ignore_ascii_case("charset") {
                return None;
            }
            Some(v.trim().trim_matches('"').to_ascii_lowercase())
        })
    }
}

/// An async HTTP request: a method, a URL, caller headers, and a body.
///
/// Build one with [`Request::new`] (or the [`Request::get`] / [`Request::post`]
/// shortcuts) and send it with [`request`].
///
/// On native targets rsurl fills in the mandatory framing headers the caller did
/// not set — `Host`, `User-Agent`, `Accept`, `Connection: close`, and a
/// `Content-Length` matching the body — but never overrides or de-duplicates a
/// header the caller supplied, so passing any of those yourself takes
/// precedence. On wasm the browser owns those headers instead.
///
/// Non-exhaustive: build one through [`Request::new`] rather than a struct
/// literal — fields may be added in a future release.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Request {
    /// HTTP method (e.g. `GET`, `POST`). Sent verbatim.
    pub method: String,
    /// Absolute request URL (`http`/`https`).
    pub url: String,
    /// Caller headers, sent in order after rsurl's defaults.
    pub headers: Vec<(String, String)>,
    /// Request body. An empty body sends no payload.
    pub body: Vec<u8>,
    /// Follow `3xx` redirects (default `false`, matching the blocking API). On
    /// 301/302/303 a non-GET/HEAD request becomes a bodyless `GET`; 307/308
    /// preserve method and body. Capped at [`MAX_REDIRECTS`] hops.
    pub follow_redirects: bool,
    /// Decode the response body per its `Content-Encoding` (default `true`).
    pub decompress: bool,
    /// Whole-request deadline, redirects included (default `None`, i.e. no
    /// limit). See [`Request::timeout`].
    pub timeout: Option<Duration>,
}

/// Maximum number of redirects [`request`] follows when
/// [`Request::follow_redirects`] is on, before failing with an
/// [`Error::BadResponse`].
///
/// Native only: on wasm the browser applies its own redirect limit.
pub const MAX_REDIRECTS: usize = 10;

impl Request {
    /// A request with the given method and URL, no extra headers, an empty
    /// body, redirects off, response decompression on, and no timeout.
    pub fn new(method: impl Into<String>, url: impl Into<String>) -> Self {
        Request {
            method: method.into(),
            url: url.into(),
            headers: Vec::new(),
            body: Vec::new(),
            follow_redirects: false,
            decompress: true,
            timeout: None,
        }
    }

    /// A `GET` request for `url`.
    pub fn get(url: impl Into<String>) -> Self {
        Request::new("GET", url)
    }

    /// A `POST` request for `url` carrying `body`.
    pub fn post(url: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        Request::new("POST", url).body(body)
    }

    /// Append a header. Call repeatedly to set several; order is preserved.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Set the request body. Named to match [`crate::Request::body`] on the
    /// blocking API.
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// Set the request body.
    #[deprecated(since = "0.1.8", note = "renamed to `body`, matching the blocking API")]
    pub fn with_body(self, body: impl Into<Vec<u8>>) -> Self {
        self.body(body)
    }

    /// Follow `3xx` redirects (off by default). See
    /// [`follow_redirects`](Self::follow_redirects).
    pub fn follow_redirects(mut self, on: bool) -> Self {
        self.follow_redirects = on;
        self
    }

    /// Decode the response body per its `Content-Encoding` (on by default).
    /// A no-op on wasm, where the browser has already decoded the body.
    pub fn decompress(mut self, on: bool) -> Self {
        self.decompress = on;
        self
    }

    /// Fail the request if it has not completed within `dur` (redirect hops
    /// included). `None`, the default, means no deadline.
    ///
    /// Natively the deadline is raced against the transfer using
    /// [`Runtime::sleep`], and expiry yields [`Error::Io`] with
    /// [`std::io::ErrorKind::TimedOut`]. On wasm it becomes an
    /// `AbortSignal.timeout()` on the underlying fetch, so expiry surfaces as
    /// the browser's `AbortError` in [`Error::BadResponse`].
    pub fn timeout(mut self, dur: impl Into<Option<Duration>>) -> Self {
        self.timeout = dur.into();
        self
    }
}

/// A message sent or received over an [`aio::WebSocket`](WebSocket): either a
/// UTF-8 text frame or a binary frame. The async, cross-target analogue of
/// [`crate::WsMessage`] (which is the native, blocking WebSocket's type).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsMessage {
    /// A UTF-8 text message.
    Text(String),
    /// A binary message.
    Binary(Vec<u8>),
}

impl WsMessage {
    /// The message payload as bytes (the UTF-8 bytes for [`WsMessage::Text`]).
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

    /// Whether this is a [`WsMessage::Text`].
    pub fn is_text(&self) -> bool {
        matches!(self, WsMessage::Text(_))
    }

    /// Whether this is a [`WsMessage::Binary`].
    pub fn is_binary(&self) -> bool {
        matches!(self, WsMessage::Binary(_))
    }

    /// Consume the message and return its payload bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            WsMessage::Text(s) => s.into_bytes(),
            WsMessage::Binary(b) => b,
        }
    }
}

impl From<String> for WsMessage {
    fn from(s: String) -> Self {
        WsMessage::Text(s)
    }
}

impl From<&str> for WsMessage {
    fn from(s: &str) -> Self {
        WsMessage::Text(s.to_string())
    }
}

impl From<Vec<u8>> for WsMessage {
    fn from(b: Vec<u8>) -> Self {
        WsMessage::Binary(b)
    }
}

impl From<&[u8]> for WsMessage {
    fn from(b: &[u8]) -> Self {
        WsMessage::Binary(b.to_vec())
    }
}

#[cfg(test)]
mod shared_tests {
    use super::*;

    fn resp(headers: Vec<(String, String)>, body: Vec<u8>) -> Response {
        Response {
            status: 200,
            reason: "OK".into(),
            headers,
            body,
        }
    }

    #[test]
    fn response_header_lookup_is_case_insensitive() {
        let r = resp(
            vec![("Content-Type".into(), "text/plain".into())],
            Vec::new(),
        );
        assert_eq!(r.header("content-TYPE"), Some("text/plain"));
        assert_eq!(r.header("missing"), None);
        assert!(r.is_success());
    }

    #[test]
    fn text_honours_declared_charset() {
        let latin1 = resp(
            vec![(
                "Content-Type".into(),
                "text/plain; charset=ISO-8859-1".into(),
            )],
            vec![0xE9], // Latin-1 'é'
        );
        assert_eq!(latin1.text().unwrap(), "é");

        // No charset ⇒ UTF-8, lossily: a lone 0xE9 is not valid UTF-8.
        let utf8 = resp(
            vec![("Content-Type".into(), "text/plain".into())],
            vec![0xE9],
        );
        assert_eq!(utf8.text().unwrap(), "\u{fffd}");

        let unknown = resp(
            vec![(
                "Content-Type".into(),
                "text/plain; charset=shift_jis".into(),
            )],
            vec![0xE9],
        );
        assert!(matches!(unknown.text(), Err(Error::Decode(_))));
    }

    #[test]
    fn error_for_status_maps_4xx_to_err() {
        let mut bad = resp(Vec::new(), Vec::new());
        bad.status = 404;
        bad.reason = "Not Found".into();
        assert!(!bad.is_success());
        assert!(matches!(
            bad.error_for_status(),
            Err(Error::Status { code: 404, .. })
        ));
    }

    #[test]
    fn request_builder_defaults_and_overrides() {
        let req = Request::get("http://x/")
            .header("A", "1")
            .body(b"hi".to_vec())
            .follow_redirects(true)
            .decompress(false)
            .timeout(Duration::from_secs(5));
        assert_eq!(req.method, "GET");
        assert_eq!(req.headers, vec![("A".to_string(), "1".to_string())]);
        assert_eq!(req.body, b"hi");
        assert!(req.follow_redirects);
        assert!(!req.decompress);
        assert_eq!(req.timeout, Some(Duration::from_secs(5)));
        // `impl Into<Option<Duration>>` also accepts an explicit `None`.
        assert_eq!(Request::get("http://x/").timeout(None).timeout, None);
    }

    #[test]
    fn ws_message_conversions() {
        assert_eq!(WsMessage::from("hi"), WsMessage::Text("hi".into()));
        assert_eq!(WsMessage::from(vec![1u8, 2]), WsMessage::Binary(vec![1, 2]));
        assert!(WsMessage::from("hi").is_text());
        assert!(WsMessage::from(&b"x"[..]).is_binary());
        assert_eq!(WsMessage::Text("hi".into()).into_bytes(), b"hi");
    }
}

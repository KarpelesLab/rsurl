//! Experimental **async** HTTP client over the sans-IO stack.
//!
//! This is the first public entry point onto the runtime-agnostic sans-IO
//! engine: a protocol state machine driven over an async connection
//! supplied by a [`Runtime`] you provide (or the built-in [`TokioRuntime`],
//! behind the `tokio-rt` feature). Unlike the blocking API, this composes with
//! `async`/`await` and idiomatic concurrency — fan many [`get`] futures out with
//! `FuturesUnordered` / `JoinSet` instead of a curl-style multi handle.
//!
//! ```no_run
//! # #[cfg(feature = "tokio-rt")]
//! # async fn ex() -> Result<(), rsurl::Error> {
//! let rt = rsurl::aio::TokioRuntime;
//! let resp = rsurl::aio::get(&rt, "https://example.com/").await?;
//! println!("{} {} bytes", resp.status, resp.body.len());
//! # Ok(()) }
//! ```
//!
//! Scope (current cut): HTTP/1.1 over `http`/`https` with an arbitrary method,
//! request body, and caller headers (see [`Request`]); optional redirect
//! following and automatic response decompression; buffered response. DNS is
//! resolved synchronously and each request uses a fresh `Connection: close`
//! socket — connection pooling and streaming (non-buffered) bodies are part of
//! the ongoing sans-IO cutover and are not yet wired on this async path.
//!
//! # On wasm32 (browser)
//!
//! `wasm32-unknown-unknown` has no sockets, no threads, and cannot block, so the
//! native sans-IO/socket path above does not compile there. Instead this module
//! routes [`request`] through the browser **Fetch API** and offers
//! [`WebSocket`] over the browser's native `WebSocket` object. The [`Request`] /
//! [`Response`] types and the `get`/`post`/`request` names are the same on both
//! targets; the only signature difference is that the wasm entry points take no
//! [`Runtime`] argument — the browser event loop *is* the runtime.
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

// ─── Native (socket) backend ────────────────────────────────────────────────
#[cfg(not(target_arch = "wasm32"))]
use std::net::{SocketAddr, ToSocketAddrs};

#[cfg(not(target_arch = "wasm32"))]
pub use crate::io::runtime::{AsyncConn, Runtime};
#[cfg(all(feature = "tokio-rt", not(target_arch = "wasm32")))]
pub use crate::io::tokio::TokioRuntime;

#[cfg(not(target_arch = "wasm32"))]
use crate::io::asyncio;
#[cfg(not(target_arch = "wasm32"))]
use crate::proto::http1::{ClientExchange, Event};
#[cfg(not(target_arch = "wasm32"))]
use crate::proto::tls::TlsClient;

#[cfg(not(target_arch = "wasm32"))]
use crate::error::Error;
use crate::error::Result;
#[cfg(not(target_arch = "wasm32"))]
use crate::url::Url;

// ─── Browser (fetch / WebSocket) backend ────────────────────────────────────
#[cfg(target_arch = "wasm32")]
mod wasm;
#[cfg(target_arch = "wasm32")]
pub use wasm::{WebSocket, WsSink, WsStream};

// ─── Native async WebSocket ─────────────────────────────────────────────────
// Same `WebSocket` name/surface as the wasm one, but generic over the runtime's
// connection and taking a `Runtime` at connect (there is no implicit event loop
// natively). The thread-split `WsReader`/`WsWriter` of the blocking API is not
// mirrored here, so there is no `WsSink`/`WsStream` on this target.
#[cfg(not(target_arch = "wasm32"))]
mod ws;
#[cfg(not(target_arch = "wasm32"))]
pub use ws::WebSocket;

/// A buffered HTTP response from [`get`].
#[derive(Debug, Clone)]
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
    pub body: Vec<u8>,
}

/// An async HTTP request: a method, a URL, caller headers, and a body.
///
/// Build one with [`Request::new`] (or the [`Request::get`] / [`Request::post`]
/// shortcuts) and send it with [`request`]. rsurl fills in the mandatory
/// framing headers the caller did not set — `Host`, `User-Agent`, `Accept`,
/// `Connection: close`, and a `Content-Length` matching the body — but never
/// overrides or de-duplicates a header the caller supplied, so passing any of
/// those yourself takes precedence.
#[derive(Debug, Clone)]
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
}

/// Maximum number of redirects [`request`] follows when
/// [`Request::follow_redirects`] is on, before failing with an
/// [`Error::BadResponse`].
pub const MAX_REDIRECTS: usize = 10;

impl Request {
    /// A request with the given method and URL, no extra headers, an empty
    /// body, redirects off, and response decompression on.
    pub fn new(method: impl Into<String>, url: impl Into<String>) -> Request {
        Request {
            method: method.into(),
            url: url.into(),
            headers: Vec::new(),
            body: Vec::new(),
            follow_redirects: false,
            decompress: true,
        }
    }

    /// A `GET` request for `url`.
    pub fn get(url: impl Into<String>) -> Request {
        Request::new("GET", url)
    }

    /// A `POST` request for `url` carrying `body`.
    pub fn post(url: impl Into<String>, body: impl Into<Vec<u8>>) -> Request {
        Request::new("POST", url).with_body(body)
    }

    /// Append a header. Call repeatedly to set several; order is preserved.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Request {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Set the request body.
    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Request {
        self.body = body.into();
        self
    }

    /// Follow `3xx` redirects (off by default). See
    /// [`follow_redirects`](Self::follow_redirects).
    pub fn follow_redirects(mut self, on: bool) -> Request {
        self.follow_redirects = on;
        self
    }

    /// Decode the response body per its `Content-Encoding` (on by default).
    pub fn decompress(mut self, on: bool) -> Request {
        self.decompress = on;
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
}

/// Perform an HTTP/1.1 `GET` of `url` over `rt`, returning the buffered
/// [`Response`]. Convenience wrapper over [`request`].
#[cfg(not(target_arch = "wasm32"))]
pub async fn get<R: Runtime>(rt: &R, url: &str) -> Result<Response> {
    request(rt, &Request::get(url)).await
}

/// Perform an HTTP/1.1 `POST` of `body` to `url` over `rt`, returning the
/// buffered [`Response`]. Convenience wrapper over [`request`].
#[cfg(not(target_arch = "wasm32"))]
pub async fn post<R: Runtime>(rt: &R, url: &str, body: impl Into<Vec<u8>>) -> Result<Response> {
    request(rt, &Request::post(url, body)).await
}

/// Perform a `GET` of `url` via the browser Fetch API. The wasm counterpart of
/// [`get`] — no [`Runtime`] argument, since the browser event loop is implicit.
#[cfg(target_arch = "wasm32")]
pub async fn get(url: &str) -> Result<Response> {
    request(&Request::get(url)).await
}

/// Perform a `POST` of `body` to `url` via the browser Fetch API. The wasm
/// counterpart of [`post`].
#[cfg(target_arch = "wasm32")]
pub async fn post(url: &str, body: impl Into<Vec<u8>>) -> Result<Response> {
    request(&Request::post(url, body)).await
}

/// Send `req` over `rt`, returning the buffered [`Response`]. `https` builds the
/// active TLS backend's engine via [`crate::tls`] and carries the exchange
/// through the sans-IO TLS layer; `http` drives the request directly. Each
/// connection is closed after its response (`Connection: close`).
///
/// When [`Request::follow_redirects`] is set, `3xx` responses with a `Location`
/// are followed (up to [`MAX_REDIRECTS`] hops, rewriting method/body per the
/// status). When [`Request::decompress`] is set (the default), the final
/// response body is decoded per its `Content-Encoding`.
#[cfg(not(target_arch = "wasm32"))]
pub async fn request<R: Runtime>(rt: &R, req: &Request) -> Result<Response> {
    let mut url = Url::parse(&req.url)?;
    let mut method = req.method.to_ascii_uppercase();
    let mut body = req.body.clone();
    let mut hops = 0usize;

    loop {
        let resp = send_once(rt, &url, &method, &req.headers, &body).await?;

        // Follow a redirect, or fall through to return this response.
        if req.follow_redirects && is_redirect(resp.status) {
            if let Some(location) = header_value(&resp.headers, "location") {
                if hops >= MAX_REDIRECTS {
                    return Err(Error::BadResponse(format!(
                        "aio: maximum ({MAX_REDIRECTS}) redirects followed"
                    )));
                }
                hops += 1;
                url = crate::url::resolve(&url, &location)?;
                // 301/302/303 turn a non-idempotent request into a bodyless GET;
                // 307/308 preserve method and body (RFC 9110 §15.4).
                if (301..=303).contains(&resp.status) && method != "GET" && method != "HEAD" {
                    method = "GET".to_string();
                    body.clear();
                }
                continue;
            }
        }

        return finish_response(resp, req.decompress);
    }
}

/// Send `req` via the browser Fetch API, returning the buffered [`Response`].
/// The wasm counterpart of [`request`] — no [`Runtime`] argument.
///
/// The browser performs DNS, TLS, redirect following, and response
/// decompression itself, so [`Request::decompress`] is ignored and
/// [`Request::follow_redirects`] maps to fetch's redirect mode: `true` →
/// `follow` (the default), `false` → `manual` (a redirect yields an opaque
/// response you cannot read). Forbidden headers set on `req` are dropped by the
/// browser, and cross-origin requests are subject to CORS.
#[cfg(target_arch = "wasm32")]
pub async fn request(req: &Request) -> Result<Response> {
    wasm::fetch(req).await
}

/// One request/response round-trip over a fresh `Connection: close` connection,
/// with no redirect or decompression handling.
#[cfg(not(target_arch = "wasm32"))]
async fn send_once<R: Runtime>(
    rt: &R,
    u: &Url,
    method: &str,
    caller_headers: &[(String, String)],
    body: &[u8],
) -> Result<Response> {
    let addr = resolve(&u.host, u.port)?;
    let mut conn = rt.connect(addr).await.map_err(Error::Io)?;

    let target = if u.path.is_empty() {
        "/".to_string()
    } else {
        u.path.clone()
    };
    let headers = build_headers(u, caller_headers, body.len());
    let bytes = ClientExchange::encode_request(method, &target, &headers, body);

    let events: Vec<Event> = match u.scheme.as_str() {
        "http" => {
            let mut exchange = ClientExchange::new(method, bytes);
            asyncio::drive(&mut exchange, &mut conn).await?
        }
        "https" => {
            let exchange = ClientExchange::new(method, bytes);
            let mut opts = crate::tls::TlsOpts::verifying();
            let engine = crate::tls::build_client_engine(&u.host, &mut opts)?;
            let mut tls = TlsClient::new(engine, exchange);
            asyncio::drive(&mut tls, &mut conn).await?
        }
        other => return Err(Error::UnsupportedScheme(other.to_string())),
    };

    let Some(Event::Response { head, body }) = events.into_iter().next() else {
        return Err(Error::UnexpectedEof);
    };
    Ok(Response {
        status: head.status,
        reason: head.reason,
        headers: head.headers,
        body,
    })
}

/// Status codes [`request`] follows when redirects are enabled.
#[cfg(not(target_arch = "wasm32"))]
fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// First value for header `name` (case-insensitive), if present.
#[cfg(not(target_arch = "wasm32"))]
fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

/// Apply response decompression when requested: decode the body per its
/// `Content-Encoding` and strip the now-stale `Content-Encoding`/`Content-Length`
/// headers. A decode failure (truncated/corrupt stream) is surfaced as an error
/// rather than returning a partial body.
#[cfg(not(target_arch = "wasm32"))]
fn finish_response(mut resp: Response, decompress: bool) -> Result<Response> {
    if !decompress {
        return Ok(resp);
    }
    let Some(encoding) = header_value(&resp.headers, "content-encoding") else {
        return Ok(resp);
    };
    let decoded = crate::compress::decode_body(resp.body, &encoding)?;
    if decoded.decoded {
        resp.headers = crate::compress::strip_after_decode(resp.headers);
    }
    resp.body = decoded.body;
    Ok(resp)
}

/// Merge rsurl's mandatory framing headers with the caller's. Each default is
/// emitted only when the caller did not already supply a header of that name
/// (case-insensitively); `Content-Length` is added for a non-empty body unless
/// the caller set `Content-Length` or `Transfer-Encoding`. Caller headers are
/// then appended verbatim, in order.
#[cfg(not(target_arch = "wasm32"))]
fn build_headers(u: &Url, caller: &[(String, String)], body_len: usize) -> Vec<(String, String)> {
    let has = |name: &str| caller.iter().any(|(k, _)| k.eq_ignore_ascii_case(name));

    let mut headers = Vec::with_capacity(caller.len() + 5);
    if !has("Host") {
        headers.push(("Host".to_string(), host_header(u)));
    }
    if !has("User-Agent") {
        headers.push(("User-Agent".to_string(), "rsurl".to_string()));
    }
    if !has("Accept") {
        headers.push(("Accept".to_string(), "*/*".to_string()));
    }
    if !has("Connection") {
        headers.push(("Connection".to_string(), "close".to_string()));
    }
    if body_len > 0 && !has("Content-Length") && !has("Transfer-Encoding") {
        headers.push(("Content-Length".to_string(), body_len.to_string()));
    }
    headers.extend(caller.iter().cloned());
    headers
}

/// Resolve `host:port` to a socket address (synchronous DNS for now).
#[cfg(not(target_arch = "wasm32"))]
fn resolve(host: &str, port: u16) -> Result<SocketAddr> {
    (host, port)
        .to_socket_addrs()
        .map_err(Error::Io)?
        .next()
        .ok_or_else(|| Error::BadResponse(format!("could not resolve {host}:{port}")))
}

/// The `Host` header value: bare host on the default port, `host:port` otherwise.
#[cfg(not(target_arch = "wasm32"))]
fn host_header(u: &Url) -> String {
    let default = match u.scheme.as_str() {
        "https" => 443,
        _ => 80,
    };
    if u.port == default {
        u.host.clone()
    } else {
        format!("{}:{}", u.host, u.port)
    }
}

#[cfg(all(test, feature = "tokio-rt", not(target_arch = "wasm32")))]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    use super::*;

    fn serve(body: &'static [u8]) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut sock) = conn else { continue };
                let mut buf = Vec::new();
                let mut byte = [0u8; 1];
                while sock.read(&mut byte).map(|n| n == 1).unwrap_or(false) {
                    buf.push(byte[0]);
                    if buf.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes());
                let _ = sock.write_all(body);
            }
        });
        port
    }

    #[tokio::test]
    async fn async_get_http_over_real_socket() {
        let port = serve(b"hello aio");
        let rt = TokioRuntime;
        let resp = get(&rt, &format!("http://127.0.0.1:{port}/"))
            .await
            .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"hello aio");
    }

    #[tokio::test]
    async fn async_get_sends_host_header() {
        // The server echoes back whether it saw the expected Host header.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = Vec::new();
                let mut byte = [0u8; 1];
                while sock.read(&mut byte).map(|n| n == 1).unwrap_or(false) {
                    buf.push(byte[0]);
                    if buf.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&buf).to_lowercase();
                let ok = head.contains(&format!("host: 127.0.0.1:{port}"));
                let body = if ok { "yes" } else { "no" };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes());
            }
        });
        let rt = TokioRuntime;
        let resp = get(&rt, &format!("http://127.0.0.1:{port}/"))
            .await
            .unwrap();
        assert_eq!(resp.body, b"yes");
    }

    /// Capture the full raw request the server received, then reply 200.
    fn echo_request() -> (u16, std::sync::mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = std::sync::mpsc::channel();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 1024];
                // Read headers, then any declared Content-Length body.
                loop {
                    let n = sock.read(&mut tmp).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    let head_end = buf.windows(4).position(|w| w == b"\r\n\r\n");
                    if let Some(end) = head_end {
                        let head = String::from_utf8_lossy(&buf[..end]).to_lowercase();
                        let want = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if buf.len() >= end + 4 + want {
                            break;
                        }
                    }
                }
                let _ = sock.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
                let _ = tx.send(buf);
            }
        });
        (port, rx)
    }

    #[tokio::test]
    async fn async_post_sends_body_and_length() {
        let (port, rx) = echo_request();
        let rt = TokioRuntime;
        let resp = post(
            &rt,
            &format!("http://127.0.0.1:{port}/sub"),
            b"name=value".to_vec(),
        )
        .await
        .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"ok");

        let raw = String::from_utf8(rx.recv().unwrap()).unwrap();
        assert!(
            raw.starts_with("POST /sub HTTP/1.1\r\n"),
            "request line: {raw:?}"
        );
        assert!(
            raw.to_lowercase().contains("content-length: 10\r\n"),
            "missing content-length: {raw:?}"
        );
        assert!(raw.ends_with("\r\n\r\nname=value"), "missing body: {raw:?}");
    }

    #[tokio::test]
    async fn async_request_sends_caller_headers_without_duplicating_defaults() {
        let (port, rx) = echo_request();
        let rt = TokioRuntime;
        let req = Request::new("PUT", format!("http://127.0.0.1:{port}/x"))
            .header("X-Custom", "abc")
            .header("User-Agent", "mine/1.0")
            .with_body(b"hi".to_vec());
        let resp = request(&rt, &req).await.unwrap();
        assert_eq!(resp.status, 200);

        let raw = String::from_utf8(rx.recv().unwrap()).unwrap();
        let lower = raw.to_lowercase();
        assert!(
            raw.starts_with("PUT /x HTTP/1.1\r\n"),
            "request line: {raw:?}"
        );
        assert!(
            raw.contains("X-Custom: abc\r\n"),
            "missing custom header: {raw:?}"
        );
        // Caller's User-Agent wins; rsurl's default is suppressed.
        assert!(lower.contains("user-agent: mine/1.0\r\n"), "ua: {raw:?}");
        assert_eq!(
            lower.matches("user-agent:").count(),
            1,
            "duplicate UA: {raw:?}"
        );
    }

    /// Serve `/final` with 200 "done" and everything else with a `status`
    /// redirect to `/final`. Handles sequential `Connection: close` sockets,
    /// so one listener covers both the redirect hop and the final request.
    fn serve_redirect(status: u16, reason: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut sock) = conn else { continue };
                let mut buf = Vec::new();
                let mut byte = [0u8; 1];
                while sock.read(&mut byte).map(|n| n == 1).unwrap_or(false) {
                    buf.push(byte[0]);
                    if buf.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&buf);
                if head.starts_with("GET /final ") {
                    let _ = sock.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndone",
                    );
                } else {
                    let resp = format!(
                        "HTTP/1.1 {status} {reason}\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                    let _ = sock.write_all(resp.as_bytes());
                }
                // We only read the request head, so a POST body still sits unread
                // in the kernel buffer; dropping the socket would RST it on
                // Windows/macOS and fail the client mid-read. Close gracefully.
                crate::test_support::graceful_close(&mut sock);
            }
        });
        port
    }

    #[tokio::test]
    async fn async_follows_redirect_when_enabled() {
        let port = serve_redirect(302, "Found");
        let rt = TokioRuntime;
        let req = Request::get(format!("http://127.0.0.1:{port}/start")).follow_redirects(true);
        let resp = request(&rt, &req).await.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"done");
    }

    #[tokio::test]
    async fn async_redirect_not_followed_by_default() {
        let port = serve_redirect(302, "Found");
        let rt = TokioRuntime;
        let resp = get(&rt, &format!("http://127.0.0.1:{port}/start"))
            .await
            .unwrap();
        assert_eq!(resp.status, 302);
    }

    #[tokio::test]
    async fn async_303_downgrades_post_to_get() {
        // The server only answers 200 for `GET /final`, so a 200 proves the
        // POST was rewritten to a bodyless GET on the redirect hop.
        let port = serve_redirect(303, "See Other");
        let rt = TokioRuntime;
        let req = Request::post(format!("http://127.0.0.1:{port}/start"), b"x=1".to_vec())
            .follow_redirects(true);
        let resp = request(&rt, &req).await.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"done");
    }

    #[tokio::test]
    async fn async_decompresses_gzip_body() {
        let plain = b"hello gzip world, hello gzip world";
        let gz = compcol::vec::compress_to_vec::<compcol::gzip::Gzip>(plain).expect("gzip encode");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = Vec::new();
                let mut byte = [0u8; 1];
                while sock.read(&mut byte).map(|n| n == 1).unwrap_or(false) {
                    buf.push(byte[0]);
                    if buf.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    gz.len()
                );
                let _ = sock.write_all(head.as_bytes());
                let _ = sock.write_all(&gz);
            }
        });
        let rt = TokioRuntime;
        let resp = get(&rt, &format!("http://127.0.0.1:{port}/"))
            .await
            .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, plain);
        // The stale Content-Encoding header is stripped after decoding.
        assert!(
            !resp
                .headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("content-encoding")),
            "content-encoding should be stripped after decode"
        );
    }

    #[tokio::test]
    async fn async_decompress_disabled_returns_raw_gzip() {
        let plain = b"raw bytes please";
        let gz = compcol::vec::compress_to_vec::<compcol::gzip::Gzip>(plain).expect("gzip encode");
        let gz_for_server = gz.clone();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = Vec::new();
                let mut byte = [0u8; 1];
                while sock.read(&mut byte).map(|n| n == 1).unwrap_or(false) {
                    buf.push(byte[0]);
                    if buf.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    gz_for_server.len()
                );
                let _ = sock.write_all(head.as_bytes());
                let _ = sock.write_all(&gz_for_server);
            }
        });
        let rt = TokioRuntime;
        let req = Request::get(format!("http://127.0.0.1:{port}/")).decompress(false);
        let resp = request(&rt, &req).await.unwrap();
        assert_eq!(resp.body, gz, "raw encoded bytes when decompress is off");
    }

    /// A minimal in-process `ws://` echo server: completes the RFC 6455
    /// handshake (reusing the crate's own `derive_accept`), then reads one masked
    /// client frame, unmasks it, and echoes it back as an unmasked server frame.
    /// Enough to exercise the async client's handshake + masked send + recv.
    fn ws_echo_once() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let Ok((mut sock, _)) = listener.accept() else {
                return;
            };
            // Read handshake head.
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            let key = loop {
                let n = sock.read(&mut tmp).unwrap_or(0);
                if n == 0 {
                    return;
                }
                buf.extend_from_slice(&tmp[..n]);
                if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..end]).to_string();
                    let key = head
                        .lines()
                        .find_map(|l| {
                            l.split_once(':').and_then(|(k, v)| {
                                k.trim()
                                    .eq_ignore_ascii_case("sec-websocket-key")
                                    .then(|| v.trim().to_string())
                            })
                        })
                        .unwrap_or_default();
                    break key;
                }
            };
            let accept = crate::websocket::derive_accept(&key);
            let resp = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                 Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            );
            sock.write_all(resp.as_bytes()).unwrap();

            // Read one masked client frame (small payload; len < 126).
            let mut f = Vec::new();
            while f.len() < 2 {
                let n = sock.read(&mut tmp).unwrap_or(0);
                if n == 0 {
                    return;
                }
                f.extend_from_slice(&tmp[..n]);
            }
            let opcode = f[0] & 0x0F;
            let len = (f[1] & 0x7F) as usize;
            let need = 2 + 4 + len; // header + mask + payload
            while f.len() < need {
                let n = sock.read(&mut tmp).unwrap_or(0);
                if n == 0 {
                    return;
                }
                f.extend_from_slice(&tmp[..n]);
            }
            let mask = [f[2], f[3], f[4], f[5]];
            let mut payload = f[6..6 + len].to_vec();
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i & 3];
            }
            // Echo back unmasked (server frames must not be masked).
            let mut out = vec![0x80 | opcode, len as u8];
            out.extend_from_slice(&payload);
            sock.write_all(&out).unwrap();
            // Keep the socket open briefly so the client can read the echo.
            thread::sleep(std::time::Duration::from_millis(200));
        });
        port
    }

    #[tokio::test]
    async fn async_websocket_handshake_and_echo() {
        let port = ws_echo_once();
        let rt = TokioRuntime;
        let mut ws = WebSocket::connect(&rt, &format!("ws://127.0.0.1:{port}/"))
            .await
            .expect("ws connect");
        ws.send_text("hello ws").await.expect("send");
        let msg = ws.recv().await.expect("stream open").expect("recv ok");
        assert_eq!(msg, WsMessage::Text("hello ws".to_string()));
    }
}

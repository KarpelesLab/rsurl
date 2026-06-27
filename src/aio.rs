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

use std::net::{SocketAddr, ToSocketAddrs};

pub use crate::io::runtime::{AsyncConn, Runtime};
#[cfg(feature = "tokio-rt")]
pub use crate::io::tokio::TokioRuntime;

use crate::error::{Error, Result};
use crate::io::asyncio;
use crate::proto::http1::{ClientExchange, Event};
use crate::proto::tls::TlsClient;
use crate::url::Url;

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

/// Perform an HTTP/1.1 `GET` of `url` over `rt`, returning the buffered
/// [`Response`]. Convenience wrapper over [`request`].
pub async fn get<R: Runtime>(rt: &R, url: &str) -> Result<Response> {
    request(rt, &Request::get(url)).await
}

/// Perform an HTTP/1.1 `POST` of `body` to `url` over `rt`, returning the
/// buffered [`Response`]. Convenience wrapper over [`request`].
pub async fn post<R: Runtime>(rt: &R, url: &str, body: impl Into<Vec<u8>>) -> Result<Response> {
    request(rt, &Request::post(url, body)).await
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

/// One request/response round-trip over a fresh `Connection: close` connection,
/// with no redirect or decompression handling.
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
fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// First value for header `name` (case-insensitive), if present.
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
fn resolve(host: &str, port: u16) -> Result<SocketAddr> {
    (host, port)
        .to_socket_addrs()
        .map_err(Error::Io)?
        .next()
        .ok_or_else(|| Error::BadResponse(format!("could not resolve {host}:{port}")))
}

/// The `Host` header value: bare host on the default port, `host:port` otherwise.
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

#[cfg(all(test, feature = "tokio-rt"))]
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
}

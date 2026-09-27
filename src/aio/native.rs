//! Native (socket) backend for [`crate::aio`]: HTTP/1.1 over the sans-IO stack,
//! driven by a caller-supplied [`Runtime`].
//!
//! This module only compiles off `wasm32-unknown-unknown`; the browser
//! counterpart is [`wasm`](super::wasm). [`request`] is the entry point,
//! [`connect`] the shared resolve-and-dial helper the async
//! [`WebSocket`](super::ws::WebSocket) uses too.

use std::future::{poll_fn, Future};
use std::io;
use std::pin::pin;
use std::task::Poll;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::io::asyncio;
use crate::io::runtime::Runtime;
use crate::proto::http1::{ClientExchange, Event};
use crate::proto::tls::TlsClient;
use crate::url::Url;

use super::{Request, Response, MAX_REDIRECTS};

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
/// through the sans-IO TLS layer, configured from the request's TLS settings
/// ([`Request::verify_tls`], [`Request::ca_bundle`], [`Request::tls`], ...);
/// `http` drives the request directly. Each connection is closed after its
/// response (`Connection: close`).
///
/// When [`Request::follow_redirects`] is set, `3xx` responses with a `Location`
/// are followed (up to [`MAX_REDIRECTS`] hops, rewriting method/body per the
/// status). When [`Request::decompress`] is set (the default), the final
/// response body is decoded per its `Content-Encoding`. [`Request::timeout`]
/// bounds the whole thing, redirect hops included.
pub async fn request<R: Runtime>(rt: &R, req: &Request) -> Result<Response> {
    with_timeout(rt, req.timeout, exchange(rt, req)).await
}

/// [`request`] without the timeout wrapper: the redirect loop itself.
async fn exchange<R: Runtime>(rt: &R, req: &Request) -> Result<Response> {
    let mut url = Url::parse(&req.url)?;
    let mut method = req.method.to_ascii_uppercase();
    // Borrowed from the caller until a redirect drops it — no per-request copy.
    let mut body: &[u8] = &req.body;
    let mut hops = 0usize;

    loop {
        let resp = send_once(rt, &url, &method, &req.headers, body, &req.tls.settings).await?;

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
                    body = &[];
                }
                continue;
            }
        }

        return finish_response(resp, req.decompress);
    }
}

/// Race `fut` against `rt`'s timer, failing with [`std::io::ErrorKind::TimedOut`]
/// if `dur` elapses first. `None` runs `fut` unbounded.
///
/// Hand-rolled rather than pulled from `futures-util`: the async core
/// deliberately depends on no async-ecosystem crate (see
/// [`crate::io::runtime`]), and a two-way select is a dozen lines of safe,
/// stable `poll_fn`.
pub(super) async fn with_timeout<R, F, T>(rt: &R, dur: Option<Duration>, fut: F) -> Result<T>
where
    R: Runtime,
    F: Future<Output = Result<T>>,
{
    let Some(dur) = dur else { return fut.await };

    let mut fut = pin!(fut);
    let mut timer = pin!(rt.sleep(dur));
    poll_fn(move |cx| {
        // Poll the transfer first: a future that is already done wins a tie
        // against a timer that expired in the same wakeup.
        if let Poll::Ready(out) = fut.as_mut().poll(cx) {
            return Poll::Ready(out);
        }
        if timer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(Error::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("aio: request timed out after {dur:?}"),
            ))));
        }
        Poll::Pending
    })
    .await
}

/// Resolve `host:port` through `rt` and dial the addresses in turn, returning
/// the first connection that comes up.
///
/// Trying every address (not just the first) is what makes a dual-stack host
/// with an unreachable AAAA record work, and matches what `TcpStream::connect`
/// does for the blocking path.
pub(super) async fn connect<R: Runtime>(rt: &R, host: &str, port: u16) -> Result<R::Conn> {
    // A URL IPv6 literal keeps its brackets (`[::1]`); the resolver wants the
    // bare address.
    let addrs = rt
        .resolve(crate::url::unbracket(host), port)
        .await
        .map_err(Error::Io)?;
    let mut last: Option<io::Error> = None;
    for addr in addrs {
        match rt.connect(addr).await {
            Ok(conn) => return Ok(conn),
            Err(e) => last = Some(e),
        }
    }
    Err(Error::Io(last.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("could not resolve {host}:{port}"),
        )
    })))
}

/// One request/response round-trip over a fresh `Connection: close` connection,
/// with no redirect or decompression handling.
async fn send_once<R: Runtime>(
    rt: &R,
    u: &Url,
    method: &str,
    caller_headers: &[(String, String)],
    body: &[u8],
    tls_settings: &crate::tls::TlsSettings,
) -> Result<Response> {
    let mut conn = connect(rt, &u.host, u.port).await?;

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
            // Handshake and run the post-handshake trust checks (pins, verify
            // callback, SAN) *before* the request is encrypted and sent.
            let engine = crate::io::asynctls::handshake(&mut conn, &u.host, tls_settings).await?;
            let exchange = ClientExchange::new(method, bytes);
            let mut tls = TlsClient::new(engine, exchange);
            let events = asyncio::drive(&mut tls, &mut conn).await?;
            // A body framed by the connection close is only complete if the
            // close was authenticated with `close_notify`; a bare TCP FIN may
            // be an attacker truncating it (same rule as the blocking path).
            if let Some(Event::Response { head, .. }) = events.first() {
                if crate::http::body_is_close_delimited(method, head.status, &head.headers)
                    && !tls.received_close_notify()
                {
                    return Err(Error::UnexpectedEof);
                }
            }
            events
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
        // Keep advertising any layers that were not peeled (`foo, gzip` →
        // `Content-Encoding: foo`) so the caller can tell the body is still
        // encoded.
        resp.headers = crate::compress::headers_after_decode(resp.headers, &decoded);
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

#[cfg(test)]
mod decode_tests {
    use super::*;

    fn resp(ce: &str, body: Vec<u8>) -> Response {
        Response {
            status: 200,
            reason: "OK".into(),
            headers: vec![
                ("Content-Encoding".into(), ce.into()),
                ("Content-Length".into(), body.len().to_string()),
            ],
            body,
        }
    }

    /// A partial peel (`x-unknown, gzip`: gzip removed, `x-unknown` left) must
    /// keep advertising the remaining layer, like the blocking path.
    #[test]
    fn partial_peel_keeps_remaining_content_encoding() {
        use compcol::{gzip::Gzip, vec::compress_to_vec};
        let gz = compress_to_vec::<Gzip>(b"inner").unwrap();
        let out = finish_response(resp("x-unknown, gzip", gz), true).unwrap();
        assert_eq!(out.body, b"inner");
        assert_eq!(out.header("content-encoding"), Some("x-unknown"));
        assert_eq!(out.header("content-length"), None);
    }

    #[test]
    fn full_peel_drops_content_encoding() {
        use compcol::{gzip::Gzip, vec::compress_to_vec};
        let gz = compress_to_vec::<Gzip>(b"plain").unwrap();
        let out = finish_response(resp("gzip", gz), true).unwrap();
        assert_eq!(out.body, b"plain");
        assert_eq!(out.header("content-encoding"), None);
    }
}

#[cfg(all(test, feature = "tokio-rt"))]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    use super::super::{WebSocket, WsMessage};
    use super::*;
    use crate::io::tokio::TokioRuntime;

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

    /// A bracketed IPv6 literal URL resolves (the resolver gets `::1`, not
    /// `[::1]`).
    #[tokio::test]
    async fn async_get_ipv6_literal() {
        let Ok(listener) = TcpListener::bind("[::1]:0") else {
            return; // no IPv6 loopback here
        };
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let Ok((mut sock, _)) = listener.accept() else {
                return;
            };
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            while sock.read(&mut byte).map(|n| n == 1).unwrap_or(false) {
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nv6");
        });
        let resp = get(&TokioRuntime, &format!("http://[::1]:{port}/"))
            .await
            .unwrap();
        assert_eq!(resp.body, b"v6");
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
            .body(b"hi".to_vec());
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

    #[tokio::test]
    async fn async_request_times_out() {
        // A listener that accepts but never answers: only the timeout can end
        // this request.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let held = listener.accept();
            thread::sleep(std::time::Duration::from_secs(30));
            drop(held);
        });
        let rt = TokioRuntime;
        let req =
            Request::get(format!("http://127.0.0.1:{port}/")).timeout(Duration::from_millis(150));
        let err = request(&rt, &req).await.expect_err("should time out");
        match err {
            Error::Io(e) => assert_eq!(e.kind(), io::ErrorKind::TimedOut, "{e}"),
            other => panic!("expected a TimedOut io error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn async_timeout_not_hit_when_request_is_fast() {
        let port = serve(b"quick");
        let rt = TokioRuntime;
        let req =
            Request::get(format!("http://127.0.0.1:{port}/")).timeout(Duration::from_secs(30));
        let resp = request(&rt, &req).await.unwrap();
        assert_eq!(resp.body, b"quick");
    }

    #[tokio::test]
    async fn connect_reports_unresolvable_host() {
        let rt = TokioRuntime;
        let err = get(&rt, "http://no-such-host.invalid./")
            .await
            .expect_err("should not resolve");
        assert!(matches!(err, Error::Io(_)), "got {err:?}");
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
        assert!(!ws.is_closed());
        assert_eq!(ws.subprotocol(), None);
        ws.send_text("hello ws").await.expect("send");
        let msg = ws.recv().await.expect("stream open").expect("recv ok");
        assert_eq!(msg, WsMessage::Text("hello ws".to_string()));
    }

    #[tokio::test]
    async fn async_websocket_close_with_is_idempotent() {
        let port = ws_echo_once();
        let rt = TokioRuntime;
        let mut ws = WebSocket::connect(&rt, &format!("ws://127.0.0.1:{port}/"))
            .await
            .expect("ws connect");
        ws.close_with(1000, "bye").await.expect("close");
        assert!(ws.is_closed());
        // A second close sends nothing and still succeeds.
        ws.close().await.expect("second close is a no-op");
        // Receiving on a closed socket ends the stream rather than reading on.
        assert!(ws.recv().await.is_none());
    }

    #[tokio::test]
    async fn async_websocket_close_reason_must_fit_a_control_frame() {
        let port = ws_echo_once();
        let rt = TokioRuntime;
        let mut ws = WebSocket::connect(&rt, &format!("ws://127.0.0.1:{port}/"))
            .await
            .expect("ws connect");
        let err = ws
            .close_with(1000, &"x".repeat(200))
            .await
            .expect_err("reason too long");
        assert!(matches!(err, Error::BadResponse(_)), "got {err:?}");
        // The rejected close must not have marked the socket closed.
        assert!(!ws.is_closed());
    }
}

/// Async `https://` / `wss://` against an in-process rustls server presenting a
/// `localhost` leaf signed by a private test CA: the TLS options of
/// [`Request`] / [`TlsOptions`](super::TlsOptions) must actually reach the
/// handshake (they used to be ignored: every async connection hard-coded
/// default verification).
///
/// Driven by a tiny blocking [`Runtime`] (each future completes on its first
/// poll), so these run without `tokio-rt`, under any feature set that has the
/// rustls backend the test server needs.
#[cfg(all(test, feature = "rustls-tls"))]
mod tls_tests {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Waker};
    use std::thread;
    use std::time::Instant;

    use super::super::{TlsOptions, WebSocket, WsMessage};
    use super::*;
    use crate::io::runtime::AsyncConn;
    use crate::proto::tls::rustls_tests::{server_config, CA_CERT_PEM, LEAF_CERT_PEM};

    /// A [`Runtime`] over blocking std sockets: every operation finishes
    /// synchronously, so its futures are ready on the first poll.
    struct BlockingRuntime;

    struct BlockingConn(TcpStream);

    impl AsyncConn for BlockingConn {
        async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }

        async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
            self.0.write_all(buf)
        }

        async fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }

    impl Runtime for BlockingRuntime {
        type Conn = BlockingConn;

        async fn connect(&self, addr: SocketAddr) -> io::Result<BlockingConn> {
            let s = TcpStream::connect(addr)?;
            s.set_read_timeout(Some(Duration::from_secs(10)))?;
            Ok(BlockingConn(s))
        }

        async fn sleep(&self, dur: Duration) {
            thread::sleep(dur);
        }

        fn now(&self) -> Instant {
            Instant::now()
        }
    }

    /// Run a [`BlockingRuntime`] future to completion.
    fn block_on<F: Future>(fut: F) -> F::Output {
        let mut fut = pin!(fut);
        match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("blocking-runtime future unexpectedly pending"),
        }
    }

    /// Read one HTTP head (through `\r\n\r\n`) from `s`.
    fn read_head<S: Read>(s: &mut S) -> Option<String> {
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        while s.read(&mut byte).ok()? == 1 {
            buf.push(byte[0]);
            if buf.ends_with(b"\r\n\r\n") {
                return Some(String::from_utf8_lossy(&buf).into_owned());
            }
        }
        None
    }

    trait ReadWrite: Read + Write {}
    impl<T: Read + Write> ReadWrite for T {}

    /// Log of the request heads a test server actually received.
    type Seen = Arc<Mutex<Vec<String>>>;

    /// Accept connections forever, terminating TLS with the test `localhost`
    /// certificate and handing each decrypted stream (and its request head) to
    /// `serve`. Returns the port and the log of request heads received, so a
    /// test can prove a rejected connection never sent its request.
    fn tls_server<F>(serve: F) -> (u16, Seen)
    where
        F: Fn(&mut dyn ReadWrite, &str) + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Seen::default();
        let log = Arc::clone(&seen);
        thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut sock) = conn else { continue };
                let _ = sock.set_read_timeout(Some(Duration::from_secs(10)));
                let mut server = rustls::ServerConnection::new(server_config()).unwrap();
                {
                    let mut tls = rustls::Stream::new(&mut server, &mut sock);
                    // A client that rejects the certificate aborts the
                    // handshake, so no head ever arrives.
                    if let Some(head) = read_head(&mut tls) {
                        log.lock().unwrap().push(head.clone());
                        serve(&mut tls, &head);
                    }
                    tls.conn.send_close_notify();
                    let _ = tls.flush();
                }
                crate::test_support::graceful_close(&mut sock);
            }
        });
        (port, seen)
    }

    /// An HTTPS server answering every request with `200 hello`.
    fn https_server() -> (u16, Seen) {
        tls_server(|s, _head| {
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
        })
    }

    /// A WSS server: completes the upgrade, then echoes one small masked
    /// client frame back unmasked.
    fn wss_server() -> (u16, Seen) {
        tls_server(|s, head| {
            let key = head
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.trim()
                        .eq_ignore_ascii_case("sec-websocket-key")
                        .then(|| v.trim().to_string())
                })
                .unwrap_or_default();
            let accept = crate::websocket::derive_accept(&key);
            let resp = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                 Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            );
            if s.write_all(resp.as_bytes()).is_err() || s.flush().is_err() {
                return;
            }
            let mut hdr = [0u8; 6];
            if s.read_exact(&mut hdr).is_err() {
                return;
            }
            let len = (hdr[1] & 0x7F) as usize; // tests send < 126 bytes
            let mut payload = vec![0u8; len];
            if s.read_exact(&mut payload).is_err() {
                return;
            }
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= hdr[2 + (i & 3)];
            }
            let mut out = vec![0x80 | (hdr[0] & 0x0F), len as u8];
            out.extend_from_slice(&payload);
            let _ = s.write_all(&out);
            let _ = s.flush();
        })
    }

    /// Write the test CA to a per-test temp file, returning (dir, path).
    fn ca_file(tag: &str) -> (std::path::PathBuf, String) {
        let dir = std::env::temp_dir().join(format!("rsurl-aio-ca-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ca = dir.join("ca.pem");
        std::fs::write(&ca, CA_CERT_PEM).unwrap();
        (dir, ca.to_str().unwrap().to_string())
    }

    /// The server leaf's real `sha256//` pin.
    fn right_pin() -> String {
        let leaf = rustls_pemfile::certs(&mut LEAF_CERT_PEM.as_bytes())
            .next()
            .unwrap()
            .unwrap();
        let spki = crate::tls::client_auth::leaf_spki_sha256(&leaf).unwrap();
        format!("sha256//{}", crate::websocket::base64_encode(&spki))
    }

    const WRONG_PIN: &str = "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[test]
    fn async_https_honours_tls_options() {
        let (port, seen) = https_server();
        let url = format!("https://localhost:{port}/");
        let send = |req: Request| block_on(request(&BlockingRuntime, &req));

        // Default: the private test CA is not in the system trust store.
        send(Request::get(&url)).expect_err("untrusted CA must be rejected by default");

        // `-k` accepts it.
        let resp = send(Request::get(&url).verify_tls(false)).expect("verify off");
        assert_eq!((resp.status, resp.body.as_slice()), (200, &b"hello"[..]));

        // `--cacert` with the test CA accepts it, verification on.
        let (dir, ca) = ca_file("https");
        let resp = send(Request::get(&url).ca_bundle(&ca)).expect("custom CA");
        assert_eq!(resp.body, b"hello");
        // ...and so does the same setting handed over as a `TlsOptions`,
        // together with the correct pin.
        let opts = TlsOptions::new().ca_bundle(&ca).pinned_pubkey(&right_pin());
        let resp = send(Request::get(&url).tls(opts)).expect("custom CA + right pin");
        assert_eq!(resp.body, b"hello");

        // A wrong pin fails even with verification off.
        let err = send(
            Request::get(&url)
                .verify_tls(false)
                .pinned_pubkey(WRONG_PIN),
        )
        .expect_err("pin mismatch must fail even with -k");
        assert!(err.to_string().contains("pinned public key"), "{err}");

        // A missing CA file fails before connecting.
        send(Request::get(&url).ca_bundle("/nonexistent/rsurl-ca.pem"))
            .expect_err("missing CA file");

        // One more success so every earlier connection has been fully handled
        // by the (sequential) server, then check what actually reached it: the
        // rejected connections (untrusted CA, wrong pin) sent no request.
        send(Request::get(&url).verify_tls(false)).expect("verify off");
        assert_eq!(seen.lock().unwrap().len(), 4, "{:?}", seen.lock().unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The options apply on every redirect hop, not just the first.
    #[test]
    fn async_https_tls_options_apply_to_redirect_hops() {
        let (port, _seen) = tls_server(|s, head| {
            let resp: &[u8] = if head.starts_with("GET /final ") {
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone"
            } else {
                b"HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\n\r\n"
            };
            let _ = s.write_all(resp);
        });
        let req = Request::get(format!("https://localhost:{port}/start"))
            .verify_tls(false)
            .follow_redirects(true);
        let resp = block_on(request(&BlockingRuntime, &req)).expect("redirected");
        assert_eq!(resp.body, b"done");
    }

    #[test]
    fn async_wss_honours_tls_options() {
        let (port, seen) = wss_server();
        let url = format!("wss://localhost:{port}/");
        let rt = BlockingRuntime;
        let connect =
            |opts: &TlsOptions| block_on(WebSocket::connect_with_tls(&rt, &url, &[], opts));
        let echo = |mut ws: WebSocket<BlockingConn>| {
            block_on(ws.send_text("hi")).expect("send");
            let msg = block_on(ws.recv()).expect("open").expect("recv");
            assert_eq!(msg, WsMessage::Text("hi".into()));
        };

        // Default options reject the private CA.
        block_on(WebSocket::connect(&rt, &url)).expect_err("untrusted CA, plain connect");
        connect(&TlsOptions::new()).expect_err("untrusted CA, default options");

        echo(connect(&TlsOptions::new().verify_tls(false)).expect("verify off"));

        let (dir, ca) = ca_file("wss");
        echo(connect(&TlsOptions::new().ca_bundle(&ca)).expect("custom CA"));

        let err = connect(&TlsOptions::new().verify_tls(false).pinned_pubkey(WRONG_PIN))
            .expect_err("pin mismatch must fail even with -k");
        assert!(err.to_string().contains("pinned public key"), "{err}");

        echo(connect(&TlsOptions::new().verify_tls(false)).expect("verify off"));
        // The rejected connections never sent their upgrade request.
        assert_eq!(seen.lock().unwrap().len(), 3, "{:?}", seen.lock().unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tls_options_debug_redacts_the_key_passphrase() {
        let req = Request::get("https://x/")
            .verify_tls(false)
            .client_key_pass("hunter2");
        let dbg = format!("{req:?}");
        assert!(dbg.contains("verify: false"), "{dbg}");
        assert!(!dbg.contains("hunter2"), "{dbg}");
    }
}

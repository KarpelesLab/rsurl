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
/// through the sans-IO TLS layer; `http` drives the request directly. Each
/// connection is closed after its response (`Connection: close`).
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
        let resp = send_once(rt, &url, &method, &req.headers, body).await?;

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
async fn with_timeout<R, F, T>(rt: &R, dur: Option<Duration>, fut: F) -> Result<T>
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
    let addrs = rt.resolve(host, port).await.map_err(Error::Io)?;
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

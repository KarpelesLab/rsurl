//! Tiny in-process HTTP/1.1 test server for rsurl integration tests.
//!
//! Design notes:
//!
//! * **Threading.** One acceptor thread, one worker thread per accepted
//!   connection. By default the worker handles a single request and closes;
//!   tests that exercise the client-side connection pool can opt in to
//!   keep-alive via [`TestServer::start_keepalive`], which loops on the
//!   socket until the peer closes it.
//!
//! * **Shutdown.** The acceptor sits on a non-blocking [`TcpListener`] with
//!   a 50 ms poll loop driven by an [`AtomicBool`]. Drop of [`TestServer`]
//!   flips the flag and the acceptor exits on its next tick. This is a
//!   little more code than the "connect-to-yourself" trick, but it avoids
//!   the race where the kernel accepts but the loop has already noticed
//!   the stop flag.
//!
//! * **Framing.** The handler returns a [`Response`] whose [`BodyMode`]
//!   tells the server how to put the body on the wire — either
//!   `Content-Length`, chunked transfer-encoding (with an optional trailer),
//!   or close-delimited (no length, just close the socket after the body).
//!   The header section is rendered from `headers` verbatim plus whatever
//!   framing header is implied; nothing else is auto-added.
//!
//! * **Parser.** Inline, ~50 LOC: reads up to a blank line, splits on CRLF,
//!   handles `Content-Length` request bodies but not chunked uploads
//!   (rsurl does not chunked-upload). Independent of rsurl's parser so a
//!   bug on one side doesn't hide a bug on the other.
//!
//! Public API: [`TestServer::start`], the [`Request`] passed to the handler,
//! [`Response`] with `ok` / `status` / etc. constructors, and `url(path)`
//! which yields a `http://127.0.0.1:<port><path>` string ready for
//! [`rsurl::Request::get`] et al.

#![allow(dead_code)] // not every test exercises every helper

use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// One parsed HTTP request as seen by the test server.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    /// Case-insensitive header lookup (first match).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// How the response body should be framed on the wire.
#[derive(Debug, Clone)]
pub enum BodyMode {
    /// Send `Content-Length: <body.len()>` and the body verbatim.
    ContentLength,
    /// Send `Transfer-Encoding: chunked`, splitting the body into the
    /// given chunks. An empty `chunks` vec means a single zero-length
    /// chunk (legal but degenerate). Each entry is one chunk; the
    /// terminating `0\r\n` is added automatically. If `trailers` is
    /// non-empty, each `Name: value\r\n` line is sent before the final
    /// CRLF that closes the message.
    Chunked {
        chunks: Vec<Vec<u8>>,
        trailers: Vec<(String, String)>,
    },
    /// Send no framing headers and close the socket after the body.
    CloseDelimited,
    /// Send the declared Content-Length, then only `actual_len` body
    /// bytes, then close. Used to simulate a truncated response.
    ContentLengthShort { declared: usize, actual_len: usize },
}

/// One response the handler wants the server to send.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub mode: BodyMode,
}

impl Response {
    /// 200 OK with a `Content-Length`-framed body.
    pub fn ok(body: impl Into<Vec<u8>>) -> Self {
        Response {
            status: 200,
            reason: "OK".into(),
            headers: Vec::new(),
            body: body.into(),
            mode: BodyMode::ContentLength,
        }
    }

    /// Bare status response with no body, no framing.
    pub fn status(code: u16) -> Self {
        Response {
            status: code,
            reason: default_reason(code).into(),
            headers: Vec::new(),
            body: Vec::new(),
            mode: BodyMode::ContentLength,
        }
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    pub fn mode(mut self, mode: BodyMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = reason.into();
        self
    }
}

fn default_reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "Status",
    }
}

type Handler = dyn Fn(Request) -> Response + Send + Sync + 'static;

/// Single-shot HTTP/1.1 test server. Drop it to shut down.
pub struct TestServer {
    pub addr: SocketAddr,
    pub accept_count: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
}

impl TestServer {
    /// Bind to 127.0.0.1:0 and start the acceptor. `handler` is invoked
    /// once per accepted connection in a worker thread; the worker closes
    /// the socket after writing the response.
    pub fn start<F>(handler: F) -> Self
    where
        F: Fn(Request) -> Response + Send + Sync + 'static,
    {
        Self::start_inner(handler, false)
    }

    /// Same as [`Self::start`] but the worker loops on the socket, parsing
    /// each successive request and invoking the handler again, until the
    /// peer closes the connection (or sends `Connection: close`). This is
    /// what's needed to exercise rsurl's client-side connection pool.
    pub fn start_keepalive<F>(handler: F) -> Self
    where
        F: Fn(Request) -> Response + Send + Sync + 'static,
    {
        Self::start_inner(handler, true)
    }

    fn start_inner<F>(handler: F, keep_alive: bool) -> Self
    where
        F: Fn(Request) -> Response + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("local_addr");
        listener
            .set_nonblocking(true)
            .expect("set_nonblocking on listener");

        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_loop = Arc::clone(&stop);
        let accept_count = Arc::new(AtomicUsize::new(0));
        let accept_count_for_loop = Arc::clone(&accept_count);
        let handler: Arc<Handler> = Arc::new(handler);

        let accept = thread::Builder::new()
            .name("rsurl-testserver-accept".into())
            .spawn(move || {
                accept_loop(
                    listener,
                    stop_for_loop,
                    handler,
                    keep_alive,
                    accept_count_for_loop,
                );
            })
            .expect("spawn acceptor");

        TestServer {
            addr,
            accept_count,
            stop,
            accept: Some(accept),
        }
    }

    /// Build a `http://127.0.0.1:<port><path>` URL pointing at this server.
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }

    /// Stop the acceptor and join its thread. Idempotent; called from
    /// [`Drop`] if not invoked explicitly.
    pub fn shutdown(mut self) {
        self.stop_and_join();
    }

    fn stop_and_join(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.accept.take() {
            let _ = h.join();
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

fn accept_loop(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    handler: Arc<Handler>,
    keep_alive: bool,
    accept_count: Arc<AtomicUsize>,
) {
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _peer)) => {
                accept_count.fetch_add(1, Ordering::SeqCst);
                let handler = Arc::clone(&handler);
                // Each connection gets its own worker thread so a slow
                // handler can't block the acceptor.
                let _ = thread::Builder::new()
                    .name("rsurl-testserver-worker".into())
                    .spawn(move || {
                        handle_conn(stream, &*handler, keep_alive);
                    });
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(_) => break,
        }
    }
}

fn handle_conn(mut stream: TcpStream, handler: &Handler, keep_alive: bool) {
    // Generous-ish timeouts: tests should be fast; if we hit one of these
    // something is genuinely wrong with the client.
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    loop {
        let req = match parse_request(&mut stream) {
            Ok(r) => r,
            Err(_) => {
                let _ = stream.shutdown(Shutdown::Both);
                return;
            }
        };

        let resp = handler(req);
        let resp_says_close = resp
            .headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("connection") && v.eq_ignore_ascii_case("close"));
        let close_delimited = matches!(resp.mode, BodyMode::CloseDelimited);

        if write_response(&mut stream, &resp).is_err() {
            // Client may have already closed; that's fine.
            break;
        }

        if !keep_alive || resp_says_close || close_delimited {
            break;
        }
        // In keep-alive mode the loop falls through to parse the next
        // request; if the client closes, the next parse_request returns
        // Err and we exit cleanly.
    }

    // Graceful close. Calling `shutdown(Both)` on macOS sends a TCP RST when
    // there's any data still in the kernel receive buffer (BSD behavior),
    // and the client's in-flight read of our response then surfaces as
    // `ECONNRESET`. Instead: half-close the write side (sends FIN), briefly
    // drain anything the client wrote after the headers (CI hits Linux's
    // forgiving path and ignores this; macOS does not), and let `stream`
    // drop to close the read side.
    let _ = stream.shutdown(Shutdown::Write);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let mut sink = [0u8; 256];
    loop {
        match stream.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(_) => continue,
        }
    }
}

/// Parse one HTTP/1.x request. Returns `Err(())` on any malformed input —
/// callers just drop the connection.
fn parse_request(stream: &mut TcpStream) -> Result<Request, ()> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    let header_end;

    // Read until we see CRLF CRLF, capping at 64 KiB so a misbehaving
    // client can't OOM us.
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => return Err(()),
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if let Some(pos) = find_header_end(&buf) {
                    header_end = pos;
                    break;
                }
                if buf.len() > 64 * 1024 {
                    return Err(());
                }
            }
            Err(_) => return Err(()),
        }
    }

    let header_bytes = &buf[..header_end];
    let header_str = std::str::from_utf8(header_bytes).map_err(|_| ())?;
    let mut lines = header_str.split("\r\n");

    let request_line = lines.next().ok_or(())?;
    let mut parts = request_line.splitn(3, ' ');
    let method = parts.next().ok_or(())?.to_string();
    let path = parts.next().ok_or(())?.to_string();
    let _version = parts.next().ok_or(())?;

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (k, v) = line.split_once(':').ok_or(())?;
        headers.push((k.trim().to_string(), v.trim().to_string()));
    }

    // The header terminator is `\r\n\r\n`; body bytes start right after.
    let body_start = header_end + 4;
    let already_read = buf.len().saturating_sub(body_start);
    let content_length = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(0);

    let mut body = Vec::with_capacity(content_length);
    if already_read > 0 {
        body.extend_from_slice(&buf[body_start..body_start + already_read.min(content_length)]);
    }
    while body.len() < content_length {
        match stream.read(&mut tmp) {
            Ok(0) => return Err(()),
            Ok(n) => {
                let need = content_length - body.len();
                body.extend_from_slice(&tmp[..n.min(need)]);
            }
            Err(_) => return Err(()),
        }
    }

    Ok(Request {
        method,
        path,
        headers,
        body,
    })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn write_response(stream: &mut TcpStream, resp: &Response) -> std::io::Result<()> {
    let mut head = Vec::with_capacity(256);
    write!(&mut head, "HTTP/1.1 {} {}\r\n", resp.status, resp.reason)?;

    let mut have_clen = false;
    let mut have_te = false;
    for (k, v) in &resp.headers {
        if k.eq_ignore_ascii_case("content-length") {
            have_clen = true;
        }
        if k.eq_ignore_ascii_case("transfer-encoding") {
            have_te = true;
        }
        write!(&mut head, "{k}: {v}\r\n")?;
    }

    match &resp.mode {
        BodyMode::ContentLength => {
            if !have_clen {
                write!(&mut head, "Content-Length: {}\r\n", resp.body.len())?;
            }
            head.extend_from_slice(b"\r\n");
            stream.write_all(&head)?;
            stream.write_all(&resp.body)?;
        }
        BodyMode::ContentLengthShort {
            declared,
            actual_len,
        } => {
            if !have_clen {
                write!(&mut head, "Content-Length: {}\r\n", declared)?;
            }
            head.extend_from_slice(b"\r\n");
            stream.write_all(&head)?;
            let n = (*actual_len).min(resp.body.len());
            stream.write_all(&resp.body[..n])?;
        }
        BodyMode::Chunked { chunks, trailers } => {
            if !have_te {
                head.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
            }
            head.extend_from_slice(b"\r\n");
            stream.write_all(&head)?;
            for chunk in chunks {
                write!(stream, "{:x}\r\n", chunk.len())?;
                stream.write_all(chunk)?;
                stream.write_all(b"\r\n")?;
            }
            stream.write_all(b"0\r\n")?;
            for (k, v) in trailers {
                write!(stream, "{k}: {v}\r\n")?;
            }
            stream.write_all(b"\r\n")?;
        }
        BodyMode::CloseDelimited => {
            head.extend_from_slice(b"\r\n");
            stream.write_all(&head)?;
            stream.write_all(&resp.body)?;
        }
    }

    stream.flush()?;
    Ok(())
}

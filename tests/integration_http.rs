//! Live HTTP/1.1 integration tests for rsurl.
//!
//! Each test spins up a single-shot [`TestServer`] in `common/`, points a
//! [`rsurl::Request`] at it, and asserts both directions of the wire.
//! No external network is touched.

mod common;

use std::time::Duration;

use common::{BodyMode, Request as SReq, Response as SResp, TestServer};

use rsurl::{CancelToken, CookieJar, Error, Request, ResponseHead};

/// 200 OK with a Content-Length-framed body — the cheapest possible
/// round-trip.
#[test]
fn get_returns_body() {
    let server = TestServer::start(|_req: SReq| SResp::ok("hello"));
    let resp = Request::get(&server.url("/")).unwrap().send().unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.reason, "OK");
    assert_eq!(resp.body, b"hello");
}

/// HEAD must never carry a body even when the server advertises a length.
/// The presence of `Content-Length: 5` is the temptation; the client side
/// (`read_body`) is responsible for not reading those five bytes.
#[test]
fn head_has_no_body() {
    let server = TestServer::start(|_req: SReq| {
        // Lie about the body length: we send no body bytes, but
        // advertise 5. A HEAD-aware client must ignore the count.
        SResp {
            status: 200,
            reason: "OK".into(),
            headers: vec![("Content-Length".into(), "5".into())],
            body: Vec::new(),
            mode: BodyMode::CloseDelimited, // skip the auto-clen path
        }
    });
    let resp = Request::new("HEAD", &server.url("/"))
        .unwrap()
        .send()
        .unwrap();
    assert_eq!(resp.status, 200);
    assert!(resp.body.is_empty(), "HEAD body must be empty");
}

/// Three concrete chunks, no trailers — exercises the basic chunked
/// reader.
#[test]
fn chunked_encoding() {
    let server = TestServer::start(|_req: SReq| {
        SResp::ok(Vec::new()).mode(BodyMode::Chunked {
            chunks: vec![b"abc".to_vec(), b"defg".to_vec(), b"hi".to_vec()],
            trailers: vec![],
        })
    });
    let resp = Request::get(&server.url("/")).unwrap().send().unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"abcdefghi");
}

/// Chunked body with a trailer field after the terminator. Curl's reader
/// is supposed to drain trailers and not surface them as part of the
/// body or as an error.
#[test]
fn chunked_with_trailers() {
    let server = TestServer::start(|_req: SReq| {
        SResp::ok(Vec::new()).mode(BodyMode::Chunked {
            chunks: vec![b"hello ".to_vec(), b"world".to_vec()],
            trailers: vec![("X-Trailer".into(), "ignored".into())],
        })
    });
    let resp = Request::get(&server.url("/")).unwrap().send().unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"hello world");
}

/// Server advertises 100 bytes, sends 50, then closes. This must surface
/// as `Error::UnexpectedEof` — the client cannot silently truncate.
#[test]
fn content_length_mismatch_short() {
    let server = TestServer::start(|_req: SReq| SResp {
        status: 200,
        reason: "OK".into(),
        headers: vec![],
        body: vec![b'a'; 100],
        mode: BodyMode::ContentLengthShort {
            declared: 100,
            actual_len: 50,
        },
    });
    let err = Request::get(&server.url("/")).unwrap().send().unwrap_err();
    assert!(
        matches!(err, Error::UnexpectedEof),
        "expected UnexpectedEof, got {err:?}",
    );
}

/// No Content-Length, no Transfer-Encoding — the body runs until EOF
/// (Connection: close). rsurl has to read to EOF.
#[test]
fn close_delimited_body() {
    let server = TestServer::start(|_req: SReq| SResp {
        status: 200,
        reason: "OK".into(),
        headers: vec![],
        body: b"hello".to_vec(),
        mode: BodyMode::CloseDelimited,
    });
    let resp = Request::get(&server.url("/")).unwrap().send().unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"hello");
}

/// Round-trip a megabyte of pseudo-random bytes byte-for-byte. Uses a
/// fixed LCG so the test is deterministic and the failure message is
/// useful (no need for a checksum hash).
#[test]
fn large_body_1mb() {
    let payload: Vec<u8> = {
        let mut v = Vec::with_capacity(1 << 20);
        let mut state: u32 = 0x1234_5678;
        for _ in 0..(1 << 20) {
            // Numerical Recipes LCG — cheap and good enough for "is it
            // the same bytes I sent" tests.
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            v.push((state >> 24) as u8);
        }
        v
    };

    let payload_clone = payload.clone();
    let server = TestServer::start(move |_req: SReq| SResp::ok(payload_clone.clone()));
    let resp = Request::get(&server.url("/")).unwrap().send().unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body.len(), payload.len());
    assert!(resp.body == payload, "1 MiB body did not round-trip");
}

/// 204 No Content must complete cleanly with an empty body and no error
/// even though there is no `Content-Length` and no `Transfer-Encoding`.
#[test]
fn status_204_no_body() {
    let server = TestServer::start(|_req: SReq| SResp {
        status: 204,
        reason: "No Content".into(),
        headers: vec![],
        body: Vec::new(),
        mode: BodyMode::CloseDelimited,
    });
    let resp = Request::get(&server.url("/")).unwrap().send().unwrap();
    assert_eq!(resp.status, 204);
    assert_eq!(resp.reason, "No Content");
    assert!(resp.body.is_empty());
}

/// The server reflects every received request header back in the body
/// so the client side can inspect what was actually put on the wire.
/// Locks in: User-Agent default, Accept: */*, Host, and the *absence* of
/// `Connection: close` (HTTP/1.1's default is keep-alive — see the
/// connection-pool work in `src/pool.rs`).
#[test]
fn request_headers_propagate() {
    let server = TestServer::start(|req: SReq| {
        let mut body = Vec::new();
        for (k, v) in &req.headers {
            body.extend_from_slice(k.as_bytes());
            body.extend_from_slice(b": ");
            body.extend_from_slice(v.as_bytes());
            body.push(b'\n');
        }
        SResp::ok(body)
    });
    let resp = Request::get(&server.url("/probe")).unwrap().send().unwrap();
    let text = String::from_utf8(resp.body).expect("ascii reflected headers");

    let expected_ua = concat!("User-Agent: rsurl/", env!("CARGO_PKG_VERSION"));
    assert!(text.contains(expected_ua), "missing default UA in: {text}");
    assert!(text.contains("Accept: */*\n"), "missing Accept in: {text}");
    let expected_host = format!("Host: {}\n", server.addr);
    assert!(
        text.contains(&expected_host),
        "missing/wrong Host in: {text}",
    );
    assert!(
        !text.to_ascii_lowercase().contains("connection: close"),
        "must not advertise Connection: close (keep-alive is the HTTP/1.1 default): {text}",
    );
}

/// A caller-supplied User-Agent overrides the default, but does not
/// duplicate it on the wire.
#[test]
fn custom_user_agent_overrides() {
    let server = TestServer::start(|req: SReq| {
        let ua = req.header("User-Agent").unwrap_or("").to_string();
        SResp::ok(ua)
    });
    let resp = Request::get(&server.url("/"))
        .unwrap()
        .header("User-Agent", "test/1")
        .send()
        .unwrap();
    assert_eq!(resp.body, b"test/1");
    // And the default must not also appear (write_request has an
    // `have_ua` guard — this locks it in).
    let default_ua = concat!("rsurl/", env!("CARGO_PKG_VERSION"));
    assert!(
        !resp
            .body
            .windows(default_ua.len())
            .any(|w| w == default_ua.as_bytes()),
        "default UA leaked alongside the override",
    );
}

/// POST with a body must auto-set Content-Length and the server must
/// receive the exact bytes.
#[test]
fn post_with_body_sets_content_length() {
    let server = TestServer::start(|req: SReq| {
        assert_eq!(req.method, "POST");
        assert_eq!(req.header("Content-Length"), Some("5"));
        assert_eq!(req.body, b"hello");
        SResp::ok("ack")
    });
    let resp = Request::new("POST", &server.url("/echo"))
        .unwrap()
        .body("hello".as_bytes().to_vec())
        .send()
        .unwrap();
    assert_eq!(resp.body, b"ack");
}

/// Lock in the curl-style `-v` trace format produced by `send_traced`:
/// `> ` lines for the request bytes actually put on the wire, `< ` lines
/// for the response status & headers, and a connection-state epilogue
/// (either "Connection kept alive (pooled)" when the response is reusable
/// or "Connection closed" when it isn't).
#[test]
fn verbose_trace_format() {
    let server = TestServer::start(|_req: SReq| SResp::ok("hi"));

    let mut trace = Vec::new();
    let resp = Request::get(&server.url("/"))
        .unwrap()
        .send_traced(&mut trace)
        .unwrap();
    assert_eq!(resp.body, b"hi");

    let t = String::from_utf8(trace).expect("trace should be utf-8");
    assert!(
        t.contains("> GET / HTTP/1.1"),
        "missing request line in:\n{t}"
    );
    assert!(
        t.contains("< HTTP/1.1 200"),
        "missing response status in:\n{t}",
    );
    assert!(
        t.contains("* Connection kept alive (pooled)") || t.contains("* Connection closed"),
        "missing connection-state epilogue in:\n{t}",
    );
}

/// rsurl sends `Accept-Encoding: gzip, deflate` by default and must
/// transparently decode a `Content-Encoding: gzip` response. The header
/// is also expected to be **stripped** from the returned `Response`, so
/// downstream consumers don't think the body is still compressed.
#[test]
fn gzip_response_is_decoded() {
    let plain = b"hello compressed world".to_vec();
    let gz = compcol::vec::compress_to_vec::<compcol::gzip::Gzip>(&plain).unwrap();

    let plain_for_server = plain.clone();
    let gz_for_server = gz.clone();
    let server = TestServer::start(move |req: SReq| {
        // Confirm the client actually advertised compression — we are
        // exercising the default-on Accept-Encoding writer too.
        let ae = req.header("Accept-Encoding").unwrap_or("");
        assert!(ae.contains("gzip"), "Accept-Encoding missing gzip: {ae:?}");
        let _ = plain_for_server; // captured for clarity; not used here
        SResp::ok(gz_for_server.clone()).header("Content-Encoding", "gzip")
    });

    let resp = Request::get(&server.url("/")).unwrap().send().unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, plain, "body should be the decoded plaintext");
    // Stale framing headers must be gone after decode.
    assert!(
        !resp
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-encoding")),
        "Content-Encoding leaked through: {:?}",
        resp.headers,
    );
    assert!(
        !resp
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-length")),
        "stale Content-Length leaked through: {:?}",
        resp.headers,
    );
}

/// `Request::decompress(false)` must leave the body as the raw wire bytes and
/// keep the `Content-Encoding` header intact, so a caller can run its own
/// content-coding policy on exactly what the server sent.
#[test]
fn gzip_response_not_decoded_when_decompress_off() {
    let plain = b"hello compressed world".to_vec();
    let gz = compcol::vec::compress_to_vec::<compcol::gzip::Gzip>(&plain).unwrap();

    let gz_for_server = gz.clone();
    let server = TestServer::start(move |_req: SReq| {
        SResp::ok(gz_for_server.clone()).header("Content-Encoding", "gzip")
    });

    let resp = Request::get(&server.url("/"))
        .unwrap()
        .decompress(false)
        .send()
        .unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(
        resp.body, gz,
        "body should be the undecoded gzip wire bytes"
    );
    assert_eq!(
        resp.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-encoding"))
            .map(|(_, v)| v.as_str()),
        Some("gzip"),
        "Content-Encoding must be preserved when decompression is off",
    );
}

/// `send_reader` streams a `Content-Length` body straight off the socket and
/// returns the raw, undecoded bytes (here a gzip body) with the head — and
/// `Content-Encoding` — available up front.
#[test]
fn send_reader_streams_raw_content_length_body() {
    use std::io::Read;

    let plain = b"streamed raw body content".to_vec();
    let gz = compcol::vec::compress_to_vec::<compcol::gzip::Gzip>(&plain).unwrap();
    let gz_for_server = gz.clone();
    let server = TestServer::start(move |_req: SReq| {
        SResp::ok(gz_for_server.clone()).header("Content-Encoding", "gzip")
    });

    let mut reader = Request::get(&server.url("/"))
        .unwrap()
        .send_reader()
        .unwrap();
    assert_eq!(reader.status(), 200);
    assert_eq!(
        reader.header("content-encoding"),
        Some("gzip"),
        "Content-Encoding must be visible and preserved on the streaming reader",
    );

    let mut got = Vec::new();
    reader.read_to_end(&mut got).unwrap();
    assert_eq!(got, gz, "streamed bytes must be the raw undecoded body");
}

/// `send_reader` over a chunked body buffers and de-chunks (transfer framing is
/// removed) but still leaves the content bytes raw.
#[test]
fn send_reader_handles_chunked_body() {
    use std::io::Read;

    let server = TestServer::start(|_req: SReq| {
        SResp::ok(Vec::new())
            .body(b"hello world".to_vec())
            .mode(BodyMode::Chunked {
                chunks: vec![b"hello ".to_vec(), b"world".to_vec()],
                trailers: Vec::new(),
            })
    });

    let mut reader = Request::get(&server.url("/"))
        .unwrap()
        .send_reader()
        .unwrap();
    assert_eq!(reader.status(), 200);
    let mut got = String::new();
    reader.read_to_string(&mut got).unwrap();
    assert_eq!(got, "hello world");
}

/// A premature close before the declared `Content-Length` surfaces as an I/O
/// error from the streaming reader rather than a silent short read.
#[test]
fn send_reader_errors_on_truncated_length_body() {
    use std::io::Read;

    let server = TestServer::start(|_req: SReq| {
        SResp::ok(vec![b'x'; 100]).mode(BodyMode::ContentLengthShort {
            declared: 100,
            actual_len: 10,
        })
    });

    let mut reader = Request::get(&server.url("/"))
        .unwrap()
        .send_reader()
        .unwrap();
    let mut got = Vec::new();
    let err = reader.read_to_end(&mut got).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
}

/// `Response::into_reader` yields a `Read` + `Seek` cursor over the body; with
/// `decompress(false)` those are the raw undecoded wire bytes.
#[test]
fn into_reader_is_read_and_seek() {
    use std::io::{Read, Seek, SeekFrom};

    let plain = b"abcdefghij".to_vec();
    let gz = compcol::vec::compress_to_vec::<compcol::gzip::Gzip>(&plain).unwrap();
    let gz_for_server = gz.clone();
    let server = TestServer::start(move |_req: SReq| {
        SResp::ok(gz_for_server.clone()).header("Content-Encoding", "gzip")
    });

    let resp = Request::get(&server.url("/"))
        .unwrap()
        .decompress(false)
        .send()
        .unwrap();
    let mut reader = resp.into_reader();
    let mut got = Vec::new();
    reader.read_to_end(&mut got).unwrap();
    assert_eq!(got, gz, "cursor must yield the raw undecoded bytes");

    // Seekable: rewind and re-read the first byte.
    reader.seek(SeekFrom::Start(0)).unwrap();
    let mut first = [0u8; 1];
    reader.read_exact(&mut first).unwrap();
    assert_eq!(first[0], gz[0]);
}

/// Same wire shape but with `deflate` (zlib-wrapped, RFC 9110 form).
#[test]
fn deflate_response_is_decoded() {
    let plain = b"deflate body".to_vec();
    let z = compcol::vec::compress_to_vec::<compcol::zlib::Zlib>(&plain).unwrap();

    let z_for_server = z.clone();
    let server = TestServer::start(move |_req: SReq| {
        SResp::ok(z_for_server.clone()).header("Content-Encoding", "deflate")
    });

    let resp = Request::get(&server.url("/")).unwrap().send().unwrap();
    assert_eq!(resp.body, plain);
}

// ---------------------------------------------------------------------------
// Streaming, cancellation, and strict-header control (Argus browser controls).
// ---------------------------------------------------------------------------

/// `send_streaming` must deliver the head once, before any body chunk, and the
/// concatenated chunks must equal the body (requirements #1 and #3).
#[test]
fn streaming_delivers_head_before_body() {
    let server = TestServer::start(|_req: SReq| SResp::ok("hello streaming world"));

    #[derive(PartialEq, Debug)]
    enum Ev {
        Head(u16),
        Chunk,
    }
    let events = std::cell::RefCell::new(Vec::new());
    let body = std::cell::RefCell::new(Vec::new());
    let resp = Request::get(&server.url("/"))
        .unwrap()
        .send_streaming(
            |h: &ResponseHead| events.borrow_mut().push(Ev::Head(h.status)),
            |chunk: &[u8]| {
                events.borrow_mut().push(Ev::Chunk);
                body.borrow_mut().extend_from_slice(chunk);
                Ok(())
            },
        )
        .unwrap();
    let events = events.into_inner();
    let body = body.into_inner();

    assert_eq!(resp.status, 200);
    assert!(resp.body.is_empty(), "streamed body must not be buffered");
    assert_eq!(body, b"hello streaming world");
    // Head is the first event and appears exactly once, before any chunk.
    assert_eq!(events[0], Ev::Head(200));
    assert_eq!(
        events.iter().filter(|e| matches!(e, Ev::Head(_))).count(),
        1
    );
    let first_chunk = events.iter().position(|e| *e == Ev::Chunk);
    if let Some(idx) = first_chunk {
        assert!(idx > 0, "a chunk arrived before the head");
    }
}

/// A streamed gzip body is decompressed incrementally: the chunk callback sees
/// plaintext, and the head still precedes it.
#[test]
fn streaming_decodes_gzip_incrementally() {
    let plain = b"the quick brown fox jumps over the lazy dog".repeat(50);
    let gz = compcol::vec::compress_to_vec::<compcol::gzip::Gzip>(&plain).unwrap();
    let gz_for_server = gz.clone();
    let server = TestServer::start(move |_req: SReq| {
        SResp::ok(gz_for_server.clone()).header("Content-Encoding", "gzip")
    });

    let got_head = std::cell::Cell::new(false);
    let head_before_body = std::cell::Cell::new(true);
    let body = std::cell::RefCell::new(Vec::new());
    Request::get(&server.url("/"))
        .unwrap()
        .send_streaming(
            |_h: &ResponseHead| got_head.set(true),
            |chunk: &[u8]| {
                if !got_head.get() {
                    head_before_body.set(false);
                }
                body.borrow_mut().extend_from_slice(chunk);
                Ok(())
            },
        )
        .unwrap();
    assert!(got_head.get(), "head callback never fired");
    assert!(head_before_body.get(), "body chunk arrived before the head");
    assert_eq!(
        body.into_inner(),
        plain,
        "streamed body should be decoded plaintext"
    );
}

/// An error returned from the chunk callback aborts the transfer and surfaces.
#[test]
fn streaming_chunk_error_aborts() {
    let server = TestServer::start(|_req: SReq| SResp::ok("abcdefgh"));
    let err = Request::get(&server.url("/"))
        .unwrap()
        .send_streaming(
            |_h: &ResponseHead| {},
            |_chunk: &[u8]| Err(Error::BadResponse("stop".into())),
        )
        .unwrap_err();
    assert!(matches!(err, Error::BadResponse(m) if m == "stop"));
}

/// `strict_headers` suppresses rsurl's automatic User-Agent / Accept /
/// Accept-Encoding while sending the caller's headers verbatim (requirement #4).
/// `Host` is still emitted for HTTP/1.1 correctness.
#[test]
fn strict_headers_suppress_auto_injection() {
    let server = TestServer::start(|req: SReq| {
        let mut body = Vec::new();
        for (k, v) in &req.headers {
            body.extend_from_slice(format!("{k}: {v}\n").as_bytes());
        }
        SResp::ok(body)
    });
    let resp = Request::get(&server.url("/"))
        .unwrap()
        .strict_headers(true)
        .header("X-Custom", "yes")
        .send()
        .unwrap();
    let text = String::from_utf8(resp.body).unwrap().to_ascii_lowercase();
    assert!(
        text.contains("x-custom: yes"),
        "custom header missing: {text}"
    );
    assert!(text.contains("host: "), "Host must still be sent: {text}");
    assert!(
        !text.contains("user-agent:"),
        "UA should be suppressed: {text}"
    );
    assert!(
        !text.contains("accept:"),
        "Accept should be suppressed: {text}"
    );
    assert!(
        !text.contains("accept-encoding:"),
        "Accept-Encoding should be suppressed: {text}"
    );
}

/// `keep_method_case` sends the method verbatim; the default upper-cases it.
#[test]
fn keep_method_case_controls_wire_method() {
    let server = TestServer::start(|req: SReq| SResp::ok(req.method.clone()));
    let upper = Request::new("query", &server.url("/"))
        .unwrap()
        .send()
        .unwrap();
    assert_eq!(upper.body, b"QUERY", "default should upper-case the method");

    let server2 = TestServer::start(|req: SReq| SResp::ok(req.method.clone()));
    let exact = Request::new("query", &server2.url("/"))
        .unwrap()
        .keep_method_case(true)
        .send()
        .unwrap();
    assert_eq!(
        exact.body, b"query",
        "keep_method_case should preserve case"
    );
}

/// Cancelling a token from another thread tears down an in-flight streaming
/// download and surfaces [`Error::Cancelled`] (requirement #2). The server
/// sends the head plus a few body bytes, then stalls forever.
#[test]
fn cancel_token_aborts_streaming_download() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            // Drain the request head.
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf);
            // Advertise a large body, send a little, then stall.
            let _ =
                sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\nstart-of-body");
            let _ = sock.flush();
            // Hold the connection open without finishing the body.
            std::thread::sleep(Duration::from_secs(5));
            drop(sock);
        }
    });

    let token = CancelToken::new();
    let canceller = token.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        canceller.cancel();
    });

    let url = format!("http://{addr}/");
    let err = Request::get(&url)
        .unwrap()
        .cancel_token(token)
        .send_streaming(|_h: &ResponseHead| {}, |_chunk: &[u8]| Ok(()))
        .unwrap_err();
    assert!(
        matches!(err, Error::Cancelled),
        "expected Error::Cancelled, got {err:?}"
    );
    let _ = server.join();
}

/// Sanity: a request to a closed port surfaces as an I/O error rather
/// than panicking. Picks a non-privileged port that's almost certainly
/// closed by getting one from the kernel and immediately releasing it.
#[test]
fn connect_refused_is_io_error() {
    // Bind, capture the port, then drop the listener so the port is
    // (almost certainly) free. Race-prone in theory, fine in practice
    // for a test that just needs *some* port nothing is listening on.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to grab a free port");
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let url = format!("http://{addr}/");
    // Tighten the connect timeout so a stray accept in CI can't make
    // this test wait 30 s.
    let err = Request::get(&url)
        .unwrap()
        .connect_timeout(Duration::from_secs(2))
        .send()
        .unwrap_err();
    assert!(
        matches!(err, Error::Io(_)),
        "expected Error::Io, got {err:?}",
    );
}

/// Set-Cookie on a 200 response populates the jar.
#[test]
fn set_cookie_lands_in_jar() {
    let server =
        TestServer::start(|_req: SReq| SResp::ok("ok").header("Set-Cookie", "sid=abc; Path=/"));
    let mut jar = CookieJar::new();
    let resp = Request::get(&server.url("/"))
        .unwrap()
        .send_with_jar(&mut jar)
        .unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(jar.len(), 1, "expected one cookie, jar={jar:?}");
    let url = rsurl::Url::parse(&server.url("/")).unwrap();
    assert_eq!(jar.cookie_header(&url).as_deref(), Some("sid=abc"));
}

/// A 302 with Set-Cookie sets a cookie, and the chased follow-up GET must
/// carry that cookie in its request header.
#[test]
fn cookie_traverses_redirect_chain() {
    use std::sync::{Arc, Mutex};
    // Shared slot the /home handler writes the Cookie header value into,
    // so the test body can assert what was sent on hop #2.
    let observed: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let obs_for_handler = Arc::clone(&observed);

    let server = TestServer::start(move |req: SReq| {
        if req.path == "/start" {
            // Issue a cookie and redirect.
            SResp::status(302)
                .header("Set-Cookie", "sid=abc; Path=/")
                .header("Location", "/home")
        } else if req.path == "/home" {
            // Capture whatever Cookie: header arrived on the second hop.
            let got = req
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("cookie"))
                .map(|(_, v)| v.clone());
            *obs_for_handler.lock().unwrap() = got;
            SResp::ok("welcome")
        } else {
            SResp::status(404)
        }
    });

    let mut jar = CookieJar::new();
    let resp = Request::get(&server.url("/start"))
        .unwrap()
        .follow_redirects(true)
        .send_with_jar(&mut jar)
        .unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"welcome");
    let cookie_seen = observed.lock().unwrap().clone();
    assert_eq!(
        cookie_seen.as_deref(),
        Some("sid=abc"),
        "expected sid=abc on the redirected hop, got {cookie_seen:?}",
    );
}

/// `cookies_through_redirects(false)` confines jar use to the first request:
/// a cookie set on the redirecting hop is NOT replayed on the followed hop,
/// so a browser can drive its own per-hop cookie policy (requirement #5).
#[test]
fn cookies_not_carried_across_redirects_when_disabled() {
    use std::sync::{Arc, Mutex};
    let observed: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let obs_for_handler = Arc::clone(&observed);
    let server = TestServer::start(move |req: SReq| {
        if req.path == "/start" {
            SResp::status(302)
                .header("Set-Cookie", "sid=abc; Path=/")
                .header("Location", "/home")
        } else {
            *obs_for_handler.lock().unwrap() = req
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("cookie"))
                .map(|(_, v)| v.clone());
            SResp::ok("welcome")
        }
    });

    let mut jar = CookieJar::new();
    let resp = Request::get(&server.url("/start"))
        .unwrap()
        .follow_redirects(true)
        .cookies_through_redirects(false)
        .send_with_jar(&mut jar)
        .unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(
        observed.lock().unwrap().clone(),
        None,
        "no cookie should be sent on the redirected hop when disabled"
    );
}

/// #9: a successful request reports total wall-clock and DNS-lookup timings.
#[test]
fn timing_total_and_namelookup_populated() {
    let server = TestServer::start(|_req: SReq| SResp::ok("ok"));
    let resp = Request::get(&server.url("/")).unwrap().send().unwrap();
    assert!(resp.timing.total.is_some(), "total time should be set");
    assert!(
        resp.timing.namelookup.is_some(),
        "DNS namelookup time should be set on a fresh dial"
    );
}

/// #14: a custom `Resolver` is consulted for the dial address.
#[test]
fn custom_resolver_reaches_server() {
    let server = TestServer::start(|_req: SReq| SResp::ok("via-resolver"));
    let server_addr = server.addr;

    #[derive(Debug)]
    struct PinResolver(std::net::SocketAddr);
    impl rsurl::net::Resolver for PinResolver {
        fn resolve(&self, _host: &str, _port: u16) -> rsurl::Result<Vec<std::net::SocketAddr>> {
            Ok(vec![self.0])
        }
    }

    // A host that does not resolve normally; the resolver pins it to the server.
    let url = format!("http://made-up-host.invalid:{}/", server_addr.port());
    let resp = Request::get(&url)
        .unwrap()
        .resolver(std::sync::Arc::new(PinResolver(server_addr)))
        .send()
        .unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"via-resolver");
}

/// #15: two requests to the same authority with different partition keys must
/// NOT share a pooled connection (two accepts), unlike the default (one).
#[test]
fn partition_key_isolates_pool() {
    use std::sync::atomic::Ordering;
    let server = TestServer::start_keepalive(|_req: SReq| SResp::ok("ok"));

    let r1 = Request::get(&server.url("/a"))
        .unwrap()
        .partition("siteA")
        .send()
        .unwrap();
    assert_eq!(r1.status, 200);
    std::thread::sleep(Duration::from_millis(30));
    let r2 = Request::get(&server.url("/b"))
        .unwrap()
        .partition("siteB")
        .send()
        .unwrap();
    assert_eq!(r2.status, 200);

    let accepted = server.accept_count.load(Ordering::SeqCst);
    assert_eq!(
        accepted, 2,
        "different partition keys must not reuse the pooled connection, got {accepted}",
    );
}

/// #12: a `ProxyResolver` returning `Direct` leaves the request on a direct dial.
#[test]
fn proxy_resolver_direct_connects_normally() {
    let server = TestServer::start(|_req: SReq| SResp::ok("direct"));

    #[derive(Debug)]
    struct AlwaysDirect;
    impl rsurl::net::ProxyResolver for AlwaysDirect {
        fn resolve(&self, _url: &rsurl::Url) -> rsurl::net::ProxyChoice {
            rsurl::net::ProxyChoice::Direct
        }
    }

    let resp = Request::get(&server.url("/"))
        .unwrap()
        .proxy_resolver(std::sync::Arc::new(AlwaysDirect))
        .send()
        .unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"direct");
}

/// #12: a `ProxyResolver` returning a proxy URL routes through it (the proxy
/// sees an absolute-form request line for plain HTTP).
#[test]
fn proxy_resolver_routes_via_proxy() {
    use std::sync::{Arc, Mutex};
    let seen_line: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let seen_for_handler = Arc::clone(&seen_line);
    // The "proxy" is just a TestServer that records the request line it saw.
    let proxy = TestServer::start(move |req: SReq| {
        *seen_for_handler.lock().unwrap() = Some(req.path.clone());
        SResp::ok("via-proxy")
    });
    let proxy_addr = proxy.addr;

    #[derive(Debug)]
    struct ToProxy(String);
    impl rsurl::net::ProxyResolver for ToProxy {
        fn resolve(&self, _url: &rsurl::Url) -> rsurl::net::ProxyChoice {
            rsurl::net::ProxyChoice::Proxy(self.0.clone())
        }
    }

    let resp = Request::get("http://example.com/page")
        .unwrap()
        .proxy_resolver(Arc::new(ToProxy(format!("http://{proxy_addr}"))))
        .send()
        .unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"via-proxy");
    // Plain HTTP via proxy uses absolute-form: the proxy sees the full URL.
    let line = seen_line.lock().unwrap().clone().unwrap_or_default();
    assert!(
        line.contains("http://example.com/page"),
        "proxy should receive absolute-form target, got {line:?}"
    );
}

/// `Response::final_url` reports the effective URL after a redirect (the value
/// behind curl's `CURLINFO_EFFECTIVE_URL`); without a redirect it is the
/// requested URL.
#[test]
fn final_url_reflects_redirect_target() {
    let server = TestServer::start(move |req: SReq| {
        if req.path == "/start" {
            SResp::status(302).header("Location", "/dest")
        } else {
            SResp::ok("here")
        }
    });

    let resp = Request::get(&server.url("/start"))
        .unwrap()
        .follow_redirects(true)
        .send()
        .unwrap();
    assert_eq!(resp.body, b"here");
    assert!(
        resp.final_url.ends_with("/dest"),
        "final_url should be the redirect target, got {:?}",
        resp.final_url
    );

    // No redirect: final_url is the requested URL.
    let direct = Request::get(&server.url("/dest")).unwrap().send().unwrap();
    assert!(
        direct.final_url.ends_with("/dest"),
        "{:?}",
        direct.final_url
    );
}

/// `send_with_jar` without any Set-Cookie response leaves the jar empty
/// and never inserts a stray `Cookie:` request header.
#[test]
fn jar_is_empty_when_server_sets_no_cookie() {
    use std::sync::{Arc, Mutex};
    let observed: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let obs = Arc::clone(&observed);
    let server = TestServer::start(move |req: SReq| {
        let got = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("cookie"))
            .map(|(_, v)| v.clone());
        *obs.lock().unwrap() = got;
        SResp::ok("ok")
    });
    let mut jar = CookieJar::new();
    let resp = Request::get(&server.url("/"))
        .unwrap()
        .send_with_jar(&mut jar)
        .unwrap();
    assert_eq!(resp.status, 200);
    assert!(jar.is_empty(), "jar should be empty");
    assert!(
        observed.lock().unwrap().is_none(),
        "should not have sent any Cookie: header"
    );
}

/// When `-x` is set against a plain-HTTP URL, rsurl must:
///   * connect to the proxy address, not the origin,
///   * send the request line in absolute-URI form per RFC 9112 §3.2.2,
///   * preserve `Host:` as the origin authority.
#[test]
fn plain_http_via_proxy_uses_absolute_form() {
    let proxy = TestServer::start(|req: SReq| {
        // Echo the request line (built from method + path) and the Host
        // header so the test can assert exactly what hit the wire.
        let host = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let body = format!("{} {}\nHost: {host}\n", req.method, req.path);
        SResp::ok(body)
    });
    // Origin URL — we never actually connect to it; the proxy claims to
    // be the intermediary, so the test's TestServer (the proxy) gets the
    // bytes. Use a host name DNS will not resolve so a regression that
    // skips the proxy fails loudly rather than silently hitting the
    // network.
    let origin = "http://origin.invalid/some/path?q=1";
    let resp = Request::get(origin)
        .unwrap()
        .proxy(proxy.url("").trim_end_matches('/'))
        .unwrap()
        .send()
        .unwrap();
    let text = String::from_utf8(resp.body).unwrap();
    assert!(
        text.contains("GET http://origin.invalid/some/path?q=1\n"),
        "absolute-form request line missing: {text}",
    );
    assert!(
        text.contains("Host: origin.invalid\n"),
        "Host should be the origin's authority, not the proxy's: {text}",
    );
}

/// `--proxy-user` (or credentials in the proxy URL) must land in a
/// `Proxy-Authorization: Basic <b64>` header for plain HTTP proxying.
#[test]
fn plain_http_via_proxy_with_creds() {
    use std::sync::{Arc, Mutex};
    let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let cap2 = Arc::clone(&captured);
    let proxy = TestServer::start(move |req: SReq| {
        let pa = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("proxy-authorization"))
            .map(|(_, v)| v.clone());
        *cap2.lock().unwrap() = pa;
        SResp::ok("ok")
    });
    let proxy_url = format!("http://alice:hunter2@{}", proxy.addr);
    Request::get("http://origin.invalid/")
        .unwrap()
        .proxy(&proxy_url)
        .unwrap()
        .send()
        .unwrap();
    let got = captured.lock().unwrap().clone();
    // base64("alice:hunter2") = "YWxpY2U6aHVudGVyMg=="
    assert_eq!(got.as_deref(), Some("Basic YWxpY2U6aHVudGVyMg=="));
}

/// `--noproxy` matches the target host → connection goes direct.
/// We assert this by pointing `proxy()` at a *closed* port and verifying
/// the request still succeeds: only a direct connection to the real
/// origin (the TestServer) can have served it.
#[test]
fn noproxy_bypasses_proxy() {
    let origin = TestServer::start(|_req| SResp::ok("direct"));
    // Reserve a port and immediately release it so the proxy "endpoint"
    // is almost certainly closed; the same trick used by
    // `connect_refused_is_io_error`.
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let closed = l.local_addr().unwrap();
    drop(l);

    let resp = Request::get(&origin.url("/"))
        .unwrap()
        .proxy(&format!("http://{closed}"))
        .unwrap()
        .no_proxy(["127.0.0.1"])
        .connect_timeout(Duration::from_secs(2))
        .send()
        .unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"direct");
}

/// Two consecutive plain-HTTP requests to the same authority share a single
/// TCP connection via the pool. We assert this with the server's
/// `accept_count` — the second request must NOT trigger another accept.
#[test]
fn pool_reuses_plain_http_connection() {
    use std::sync::atomic::Ordering;
    let server = TestServer::start_keepalive(|_req: SReq| SResp::ok("ok"));

    let r1 = Request::get(&server.url("/first")).unwrap().send().unwrap();
    assert_eq!(r1.status, 200);

    // Give the worker a beat to park the bufreader before the second call.
    std::thread::sleep(Duration::from_millis(30));

    let r2 = Request::get(&server.url("/second"))
        .unwrap()
        .send()
        .unwrap();
    assert_eq!(r2.status, 200);

    let accepted = server.accept_count.load(Ordering::SeqCst);
    assert_eq!(
        accepted, 1,
        "second request should have reused the pooled connection, got {accepted} accepts",
    );
}

/// If a server sends `Connection: close`, the connection must NOT be parked.
/// The next request goes out on a fresh socket.
#[test]
fn pool_skips_when_response_says_close() {
    use std::sync::atomic::Ordering;
    let server =
        TestServer::start_keepalive(|_req: SReq| SResp::ok("ok").header("Connection", "close"));

    let _ = Request::get(&server.url("/a")).unwrap().send().unwrap();
    std::thread::sleep(Duration::from_millis(30));
    let _ = Request::get(&server.url("/b")).unwrap().send().unwrap();

    let accepted = server.accept_count.load(Ordering::SeqCst);
    assert_eq!(
        accepted, 2,
        "Connection: close should disable reuse, got {accepted} accepts",
    );
}

/// Close-delimited responses (no Content-Length, no chunked, server closes
/// the socket to signal end of body) must also NOT be parked: by definition
/// the connection is gone.
#[test]
fn pool_skips_close_delimited_response() {
    use std::sync::atomic::Ordering;
    let server = TestServer::start_keepalive(|_req: SReq| {
        SResp::ok("body-bytes").mode(BodyMode::CloseDelimited)
    });
    let _ = Request::get(&server.url("/a")).unwrap().send().unwrap();
    std::thread::sleep(Duration::from_millis(30));
    let _ = Request::get(&server.url("/b")).unwrap().send().unwrap();
    assert_eq!(server.accept_count.load(Ordering::SeqCst), 2);
}

/// If the server kills a parked connection between requests, the client
/// must silently dial a fresh socket — not surface a stale-connection EOF.
/// We simulate this by giving the server a tiny idle timeout and ensuring
/// the second request still succeeds.
#[test]
fn pool_retries_when_pooled_connection_is_stale() {
    use std::sync::atomic::Ordering;
    // start_keepalive's worker loops until parse_request fails. We make it
    // fail by closing our end after the first response — but we control
    // both endpoints. Trick: have the handler return a body, then the
    // worker stays in keep-alive loop waiting on read with a 5s timeout.
    // Instead we use a dedicated server that drops the socket after one
    // response (the default `start`). The client pools the bufreader,
    // server has gone away, second request hits EOF → retries fresh.
    let server = TestServer::start(|_req: SReq| SResp::ok("once"));

    let r1 = Request::get(&server.url("/")).unwrap().send().unwrap();
    assert_eq!(r1.body, b"once");
    // The pool has the now-dead bufreader.
    std::thread::sleep(Duration::from_millis(30));

    // Second request: must NOT fail. The pool entry is stale, the client
    // detects this on first read and reconnects transparently.
    let r2 = Request::get(&server.url("/"))
        .unwrap()
        .connect_timeout(Duration::from_secs(2))
        .send()
        .unwrap();
    assert_eq!(r2.body, b"once");
    // Two TCP accepts — one per request — because the single-shot server
    // closes after the first response, so the pool's parked entry was dead
    // by the time the second request tried to reuse it.
    assert_eq!(server.accept_count.load(Ordering::SeqCst), 2);
}

// ---------------------------------------------------------------------------
// CLI subprocess tests for the curl-parity body flags
// ---------------------------------------------------------------------------
//
// These spawn the actual `rsurl` binary against an in-process test server.
// The binary path comes from `CARGO_BIN_EXE_rsurl`, set automatically by
// Cargo for integration tests on a crate that declares a `[[bin]]` target.
// We need a subprocess (rather than calling code directly) because the CLI
// flag-parsing layer is the unit under test here.

/// A unique temp path for `-o` in CLI tests. `/dev/null` is Unix-only, so tests
/// that only need a discard sink use this cross-platform path instead. rsurl
/// creates/overwrites it; callers should remove it when done.
fn tmp_out_path(tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("rsurl-{tag}-{}.out", std::process::id()));
    p
}

/// `(method, content_type, body_bytes)` captured from one request.
type CapturedRequest = (String, Option<String>, Vec<u8>);
type CapturedSlot = std::sync::Arc<std::sync::Mutex<Option<CapturedRequest>>>;

/// Helper: take ownership of the next captured request body sent by the
/// in-process server. Blocks until the handler has run.
fn capture_one_request() -> (TestServer, CapturedSlot) {
    use std::sync::{Arc, Mutex};
    let slot: CapturedSlot = Arc::new(Mutex::new(None));
    let slot2 = Arc::clone(&slot);
    let server = TestServer::start(move |req: SReq| {
        let ct = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.clone());
        *slot2.lock().unwrap() = Some((req.method.clone(), ct, req.body.clone()));
        SResp::ok("ok")
    });
    (server, slot)
}

/// `rsurl --data-binary @file` must transmit the file bytes verbatim,
/// including CRLF and bare LF — those are the bytes curl preserves under
/// `--data-binary` (and would strip under `-d`).
#[test]
fn cli_data_binary_at_file_keeps_newlines() {
    use std::io::Write;
    use std::process::Command;
    let (server, slot) = capture_one_request();

    let mut tmp = std::env::temp_dir();
    tmp.push(format!("rsurl-data-binary-{}.bin", std::process::id()));
    {
        let mut f = std::fs::File::create(&tmp).unwrap();
        f.write_all(b"a\r\nb\n").unwrap();
    }

    let arg = format!("@{}", tmp.display());
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args(["--data-binary", &arg, &server.url("/post")])
        .output()
        .expect("spawn rsurl");
    let _ = std::fs::remove_file(&tmp);
    assert!(
        out.status.success(),
        "rsurl exited non-zero: {:?}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    let got = slot.lock().unwrap().clone().expect("handler ran");
    assert_eq!(got.0, "POST");
    assert_eq!(
        got.1.as_deref(),
        Some("application/x-www-form-urlencoded"),
        "default Content-Type for --data-binary should match -d"
    );
    assert_eq!(got.2, b"a\r\nb\n", "CRLF/LF must survive --data-binary");
}

/// Drive every documented sub-form of `--data-urlencode` and assert the
/// joined body is exactly what curl would emit: `content` and `=content`
/// percent-encode the bytes; `name=content` keeps the name plain and
/// encodes only the value; `@file` / `name@file` read the file then encode.
#[test]
fn cli_data_urlencode_all_five_forms() {
    use std::io::Write;
    use std::process::Command;
    let (server, slot) = capture_one_request();

    let mut tmp = std::env::temp_dir();
    tmp.push(format!("rsurl-urlencode-{}.txt", std::process::id()));
    {
        let mut f = std::fs::File::create(&tmp).unwrap();
        // Bytes that exercise the encoder: space → '+', '&' → "%26".
        f.write_all(b"x y&z").unwrap();
    }
    let at = format!("@{}", tmp.display());
    let name_at = format!("g@{}", tmp.display());

    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args([
            "--data-urlencode",
            "hello world",
            "--data-urlencode",
            "=raw value",
            "--data-urlencode",
            "k=v with space",
            "--data-urlencode",
            &at,
            "--data-urlencode",
            &name_at,
            &server.url("/post"),
        ])
        .output()
        .expect("spawn rsurl");
    let _ = std::fs::remove_file(&tmp);
    assert!(
        out.status.success(),
        "rsurl exited non-zero: {:?}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    let got = slot.lock().unwrap().clone().expect("handler ran");
    assert_eq!(got.0, "POST");
    let body = String::from_utf8(got.2).expect("ascii body");
    // Joined left-to-right with '&', each part the curl-canonical encoding.
    // file content "x y&z" → "x+y%26z".
    assert_eq!(
        body, "hello+world&raw+value&k=v+with+space&x+y%26z&g=x+y%26z",
        "every --data-urlencode sub-form must match curl's encoding"
    );
}

/// `-d a=1 -d b=2 -d c=3` concatenates with `&` exactly the way curl does;
/// each repetition appends one more form value. This is the canonical
/// "I'd rather repeat the flag than escape an ampersand on the shell line"
/// idiom.
#[test]
fn cli_multiple_d_join_with_ampersand() {
    use std::process::Command;
    let (server, slot) = capture_one_request();

    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args(["-d", "a=1", "-d", "b=2", "-d", "c=3", &server.url("/post")])
        .output()
        .expect("spawn rsurl");
    assert!(
        out.status.success(),
        "rsurl exited non-zero: {:?}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    let got = slot.lock().unwrap().clone().expect("handler ran");
    assert_eq!(got.0, "POST");
    assert_eq!(got.2, b"a=1&b=2&c=3");
}

// ---------------------------------------------------------------------------
// CLI subprocess tests for -F / --form, --form-string, -T / --upload-file
// ---------------------------------------------------------------------------

/// Pull the boundary string out of `multipart/form-data; boundary=…`.
fn extract_boundary(ct: &str) -> String {
    let lc = ct.to_ascii_lowercase();
    let prefix = "boundary=";
    let i = lc.find(prefix).expect("boundary= in Content-Type");
    let mut rest = &ct[i + prefix.len()..];
    if let Some(stripped) = rest.strip_prefix('"') {
        rest = stripped;
        let end = rest.find('"').expect("closing quote on boundary");
        rest[..end].to_string()
    } else {
        // Boundary runs until the next ';' or end-of-line.
        let end = rest.find(';').unwrap_or(rest.len());
        rest[..end].trim().to_string()
    }
}

/// Locate one multipart part by `name="<name>"` and return the slice from
/// after that line's CRLF through the part's terminating CRLF (excluding the
/// trailing `--<boundary>` glue). Tests then split header / body inside that.
fn find_part<'a>(body: &'a [u8], boundary: &str, needle: &str) -> &'a [u8] {
    let sep = format!("--{boundary}\r\n");
    let term = format!("--{boundary}--");
    let body_str =
        std::str::from_utf8(body).expect("multipart body should be UTF-8 in these tests");
    // Find the right part by scanning. Split on the leading boundary; each
    // chunk is one part (the first chunk is empty, before the first boundary).
    let mut chunks = body_str.split(&sep);
    let _ = chunks.next(); // skip the empty preamble
    for chunk in chunks {
        if chunk.contains(needle) {
            // Strip everything from the terminating boundary onward.
            let end = chunk.find(&term).unwrap_or(chunk.len());
            // Also strip the trailing CRLF before the boundary.
            let mut end_no_crlf = end;
            if end_no_crlf >= 2 && &chunk[end_no_crlf - 2..end_no_crlf] == "\r\n" {
                end_no_crlf -= 2;
            }
            // Also handle "--boundary" form (no leading \r\n separator
            // because we split on "--boundary\r\n" already). The actual
            // close marker for an interior part is "\r\n--boundary".
            return &chunk.as_bytes()[..end_no_crlf];
        }
    }
    panic!("no part matched: {needle:?}");
}

/// `-F name=@path` uploads the file's bytes as a multipart part, with
/// `Content-Disposition` carrying the basename as `filename=` and a
/// default `Content-Type: application/octet-stream`.
#[test]
fn cli_form_part_with_at_file_uploads_bytes() {
    use std::io::Write;
    use std::process::Command;
    let (server, slot) = capture_one_request();

    let mut tmp = std::env::temp_dir();
    tmp.push(format!("rsurl-form-{}.bin", std::process::id()));
    {
        let mut f = std::fs::File::create(&tmp).unwrap();
        f.write_all(b"PAYLOAD-BYTES").unwrap();
    }
    let basename = tmp.file_name().unwrap().to_string_lossy().into_owned();
    let arg = format!("upload=@{}", tmp.display());

    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args(["-F", &arg, &server.url("/post")])
        .output()
        .expect("spawn rsurl");
    let _ = std::fs::remove_file(&tmp);
    assert!(
        out.status.success(),
        "rsurl exited non-zero: {:?}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    let got = slot.lock().unwrap().clone().expect("handler ran");
    assert_eq!(got.0, "POST");
    let ct = got.1.expect("Content-Type set");
    assert!(
        ct.starts_with("multipart/form-data; boundary="),
        "got Content-Type: {ct}"
    );
    let boundary = extract_boundary(&ct);
    let part = find_part(&got.2, &boundary, "name=\"upload\"");
    let part_str = std::str::from_utf8(part).expect("ascii part headers");
    let expected_disposition =
        format!("Content-Disposition: form-data; name=\"upload\"; filename=\"{basename}\"\r\n");
    assert!(
        part_str.contains(&expected_disposition),
        "missing disposition in part: {part_str}"
    );
    assert!(
        part_str.contains("Content-Type: application/octet-stream\r\n"),
        "missing default Content-Type in part: {part_str}"
    );
    assert!(
        part.ends_with(b"\r\n\r\nPAYLOAD-BYTES"),
        "part body should end with the uploaded bytes; got: {part_str}"
    );
}

/// `--form-string name=@notafile` must put the literal string `@notafile`
/// in the part value — no file read, no `@` magic, no `;modifier` parsing.
#[test]
fn cli_form_string_treats_at_as_literal() {
    use std::process::Command;
    let (server, slot) = capture_one_request();

    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args([
            "--form-string",
            "field=@notafile;type=ignored",
            &server.url("/post"),
        ])
        .output()
        .expect("spawn rsurl");
    assert!(
        out.status.success(),
        "rsurl exited non-zero: {:?}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    let got = slot.lock().unwrap().clone().expect("handler ran");
    let ct = got.1.expect("Content-Type set");
    let boundary = extract_boundary(&ct);
    let part = find_part(&got.2, &boundary, "name=\"field\"");
    let s = std::str::from_utf8(part).unwrap();
    // No filename promotion, no Content-Type defaulting, value is the
    // literal — `;type=ignored` is part of the bytes, not a modifier.
    assert!(
        !s.contains("filename="),
        "literal form-string must not become an upload: {s}"
    );
    assert!(!s.contains("Content-Type:"), "no auto Content-Type: {s}");
    assert!(
        s.ends_with("\r\n\r\n@notafile;type=ignored"),
        "literal value must appear verbatim: {s}"
    );
}

/// All three modifiers should pass through to the part: `;type=` sets the
/// Content-Type, `;filename=` overrides the basename, `;headers=@file`
/// injects extra header lines.
#[test]
fn cli_form_extras_type_filename_headers() {
    use std::io::Write;
    use std::process::Command;
    let (server, slot) = capture_one_request();

    let mut payload = std::env::temp_dir();
    payload.push(format!("rsurl-form-payload-{}.txt", std::process::id()));
    std::fs::write(&payload, b"DATA").unwrap();

    let mut hdrs = std::env::temp_dir();
    hdrs.push(format!("rsurl-form-hdrs-{}.txt", std::process::id()));
    {
        let mut f = std::fs::File::create(&hdrs).unwrap();
        f.write_all(b"X-Custom: yes\r\nX-Other: 42\r\n").unwrap();
    }

    let arg = format!(
        "f=@{};type=application/json;filename=other.json;headers=@{}",
        payload.display(),
        hdrs.display()
    );
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args(["-F", &arg, &server.url("/post")])
        .output()
        .expect("spawn rsurl");
    let _ = std::fs::remove_file(&payload);
    let _ = std::fs::remove_file(&hdrs);
    assert!(
        out.status.success(),
        "rsurl exited non-zero: {:?}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    let got = slot.lock().unwrap().clone().expect("handler ran");
    let ct = got.1.expect("Content-Type set");
    let boundary = extract_boundary(&ct);
    let part = find_part(&got.2, &boundary, "name=\"f\"");
    let s = std::str::from_utf8(part).unwrap();
    assert!(
        s.contains("name=\"f\"; filename=\"other.json\"\r\n"),
        "filename override missing: {s}"
    );
    assert!(
        s.contains("Content-Type: application/json\r\n"),
        "type modifier missing: {s}"
    );
    assert!(
        s.contains("X-Custom: yes\r\n"),
        "header injection missing: {s}"
    );
    assert!(
        s.contains("X-Other: 42\r\n"),
        "header injection missing: {s}"
    );
    assert!(s.ends_with("\r\n\r\nDATA"), "body bytes wrong: {s}");
}

/// `-T file` PUTs the file's bytes as the request body with
/// `Content-Type: application/octet-stream`.
#[test]
fn cli_upload_file_uses_put_and_octet_stream() {
    use std::io::Write;
    use std::process::Command;
    let (server, slot) = capture_one_request();

    let mut tmp = std::env::temp_dir();
    tmp.push(format!("rsurl-upload-{}.bin", std::process::id()));
    {
        let mut f = std::fs::File::create(&tmp).unwrap();
        // Bytes that include CR/LF/NUL to prove no stripping happens.
        f.write_all(b"AAA\r\nBBB\n\0CCC").unwrap();
    }
    let path = tmp.to_string_lossy().into_owned();
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args(["-T", &path, &server.url("/put")])
        .output()
        .expect("spawn rsurl");
    let _ = std::fs::remove_file(&tmp);
    assert!(
        out.status.success(),
        "rsurl exited non-zero: {:?}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    let got = slot.lock().unwrap().clone().expect("handler ran");
    assert_eq!(got.0, "PUT");
    assert_eq!(got.1.as_deref(), Some("application/octet-stream"));
    assert_eq!(got.2, b"AAA\r\nBBB\n\0CCC");
}

/// `-T` plus a non-HTTP, non-FTP URL is a usage error (exit code 2) and
/// mentions the flag in the message so the user knows what to fix. (FTP/FTPS
/// uploads are supported and exercised separately.)
#[test]
fn cli_upload_file_rejects_unsupported_scheme() {
    use std::process::Command;
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args([
            "-T",
            concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
            "dict://example.invalid/foo",
        ])
        .output()
        .expect("spawn rsurl");
    let code = out.status.code();
    assert_eq!(code, Some(2), "expected exit code 2, got {code:?}");
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(err.contains("-T"), "stderr should mention -T: {err}");
}

/// `-T` with an `ftp://` URL is now a supported upload, not a usage error.
/// Against an unresolvable host it fails at the resolve/connect step, proving
/// the FTP-upload path is reached rather than rejected as a usage error. The
/// exact transfer code (6 couldn't-resolve vs 7 connect) is resolver-dependent,
/// so we only require a non-usage transfer failure.
#[test]
fn cli_upload_file_ftp_attempts_transfer() {
    use std::process::Command;
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args([
            "-T",
            concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
            "ftp://host.invalid/foo",
        ])
        .output()
        .expect("spawn rsurl");
    let code = out.status.code();
    assert!(
        matches!(code, Some(6) | Some(7)),
        "expected a transfer error (6/7), got {code:?}"
    );
}

/// `-a`/`--append` with an `ftp://` URL routes to the FTP upload path (APPE).
/// Against an unresolvable host it fails at the resolve/connect step, proving
/// the append branch is reached rather than rejected as a usage error.
#[test]
fn cli_append_ftp_attempts_transfer() {
    use std::process::Command;
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args([
            "-a",
            "-T",
            concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
            "ftp://host.invalid/foo",
        ])
        .output()
        .expect("spawn rsurl");
    let code = out.status.code();
    assert!(
        matches!(code, Some(6) | Some(7)),
        "expected a transfer error (6/7), got {code:?}"
    );
}

/// `-a` combined with `-C <offset>` for an FTP upload is accepted: APPE takes
/// precedence over REST, so the offset is ignored rather than causing an error.
/// Still reaches the FTP transfer path (resolve/connect failure, not usage).
#[test]
fn cli_append_with_continue_at_prefers_appe() {
    use std::process::Command;
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args([
            "-a",
            "-C",
            "10",
            "-T",
            concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
            "ftp://host.invalid/foo",
        ])
        .output()
        .expect("spawn rsurl");
    let code = out.status.code();
    assert!(
        matches!(code, Some(6) | Some(7)),
        "expected a transfer error (6/7, APPE ignores -C), got {code:?}"
    );
}

/// `-C -` (curl's automatic-resume form) is accepted. It drives HTTP-download
/// resume; for an FTP upload it is a no-op, so the transfer simply proceeds and
/// fails on the unreachable host rather than producing a usage error.
#[test]
fn cli_continue_at_dash_is_accepted() {
    use std::process::Command;
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args([
            "-C",
            "-",
            "-T",
            concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
            "ftp://host.invalid/foo",
        ])
        .output()
        .expect("spawn rsurl");
    let code = out.status.code();
    assert!(
        matches!(code, Some(6) | Some(7)),
        "expected a transfer error (6/7), not a usage error, got {code:?}"
    );
}

/// Combining `-F` and `-d` (or `-T` and either) must be rejected with a
/// usage error rather than silently building something nonsensical.
#[test]
fn cli_form_and_data_are_mutually_exclusive() {
    use std::process::Command;
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args(["-d", "a=1", "-F", "b=2", "http://127.0.0.1:1/post"])
        .output()
        .expect("spawn rsurl");
    assert_eq!(out.status.code(), Some(2), "expected exit 2");
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        err.contains("mutually exclusive"),
        "stderr should explain conflict: {err}"
    );
}

/// `-d` and `-T` are mutually exclusive too — same exit-2 path.
#[test]
fn cli_data_and_upload_are_mutually_exclusive() {
    use std::process::Command;
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args([
            "-d",
            "a=1",
            "-T",
            concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
            "http://127.0.0.1:1/x",
        ])
        .output()
        .expect("spawn rsurl");
    assert_eq!(out.status.code(), Some(2), "expected exit 2");
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        err.contains("mutually exclusive"),
        "stderr should explain conflict: {err}"
    );
}

/// `-F` and `-T` are mutually exclusive too — same exit-2 path.
#[test]
fn cli_form_and_upload_are_mutually_exclusive() {
    use std::process::Command;
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args([
            "-F",
            "x=y",
            "-T",
            concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
            "http://127.0.0.1:1/x",
        ])
        .output()
        .expect("spawn rsurl");
    assert_eq!(out.status.code(), Some(2), "expected exit 2");
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        err.contains("mutually exclusive"),
        "stderr should explain conflict: {err}"
    );
}

/// `-F name=<file` reads the file but emits it as a **form field**, not a
/// file upload: the part carries the file bytes as its value but has no
/// `filename=` attribute and no auto-defaulted `Content-Type`. This is the
/// behavioural distinction from `@file` and the reason `<` exists at all.
#[test]
fn cli_form_field_from_file_has_no_filename() {
    use std::io::Write;
    use std::process::Command;
    let (server, slot) = capture_one_request();

    let mut tmp = std::env::temp_dir();
    tmp.push(format!("rsurl-lt-{}.txt", std::process::id()));
    {
        let mut f = std::fs::File::create(&tmp).unwrap();
        f.write_all(b"FIELD-VALUE").unwrap();
    }
    let arg = format!("note=<{}", tmp.display());
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args(["-F", &arg, &server.url("/post")])
        .output()
        .expect("spawn rsurl");
    let _ = std::fs::remove_file(&tmp);
    assert!(
        out.status.success(),
        "rsurl exited non-zero: {:?}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    let got = slot.lock().unwrap().clone().expect("handler ran");
    let ct = got.1.expect("Content-Type set");
    let boundary = extract_boundary(&ct);
    let part = find_part(&got.2, &boundary, "name=\"note\"");
    let s = std::str::from_utf8(part).unwrap();
    assert!(
        !s.contains("filename="),
        "FileAsField must not add filename=: {s}"
    );
    assert!(
        !s.contains("Content-Type:"),
        "FileAsField must not auto-set Content-Type: {s}"
    );
    assert!(
        s.ends_with("\r\n\r\nFIELD-VALUE"),
        "file bytes must arrive verbatim as field value: {s}"
    );
}

/// `--form-escape` switches name/filename encoding from backslash-escape
/// (the curl-historical default we already test) to RFC 7578 §4.2
/// percent-encoding, so `"` becomes `%22` on the wire.
#[test]
fn cli_form_escape_percent_encodes_name() {
    use std::process::Command;
    let (server, slot) = capture_one_request();

    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args(["--form-escape", "-F", "weird\"name=v", &server.url("/post")])
        .output()
        .expect("spawn rsurl");
    assert!(
        out.status.success(),
        "rsurl exited non-zero: {:?}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    let got = slot.lock().unwrap().clone().expect("handler ran");
    let ct = got.1.expect("Content-Type set");
    let boundary = extract_boundary(&ct);
    // Match on the percent-encoded form because the raw `"` no longer
    // appears in the part header line.
    let part = find_part(&got.2, &boundary, "name=\"weird%22name\"");
    let s = std::str::from_utf8(part).unwrap();
    assert!(
        s.contains("name=\"weird%22name\""),
        "expected RFC 7578 %22 encoding, got: {s}"
    );
    assert!(
        !s.contains("\\\""),
        "must not also backslash-escape when --form-escape is on: {s}"
    );
}

/// Setting `;filename=` on an otherwise-literal `-F` part promotes it to
/// an upload shape: the wire part gains `filename="…"` *and* the default
/// `Content-Type: application/octet-stream`, matching curl's behaviour of
/// "this string is a tiny file, treat it as such".
#[test]
fn cli_form_literal_with_filename_modifier_becomes_upload() {
    use std::process::Command;
    let (server, slot) = capture_one_request();

    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args(["-F", "blob=hello;filename=hi.txt", &server.url("/post")])
        .output()
        .expect("spawn rsurl");
    assert!(
        out.status.success(),
        "rsurl exited non-zero: {:?}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    let got = slot.lock().unwrap().clone().expect("handler ran");
    let ct = got.1.expect("Content-Type set");
    let boundary = extract_boundary(&ct);
    let part = find_part(&got.2, &boundary, "name=\"blob\"");
    let s = std::str::from_utf8(part).unwrap();
    assert!(
        s.contains("name=\"blob\"; filename=\"hi.txt\"\r\n"),
        ";filename= must promote literal to upload shape: {s}"
    );
    assert!(
        s.contains("Content-Type: application/octet-stream\r\n"),
        "promoted literal needs default octet-stream Content-Type: {s}"
    );
    assert!(
        s.ends_with("\r\n\r\nhello"),
        "promoted literal body must be the literal text: {s}"
    );
}

/// `--data-raw @notafile` must put the literal bytes `@notafile` on the
/// wire — no file read, no error. This is the whole point of `--data-raw`
/// vs `-d` (which would try to open `notafile` and fail).
#[test]
fn cli_data_raw_leaves_at_literal_on_wire() {
    use std::process::Command;
    let (server, slot) = capture_one_request();

    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args(["--data-raw", "@notafile", &server.url("/post")])
        .output()
        .expect("spawn rsurl");
    assert!(
        out.status.success(),
        "rsurl exited non-zero: {:?}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    let got = slot.lock().unwrap().clone().expect("handler ran");
    assert_eq!(got.0, "POST");
    assert_eq!(
        got.1.as_deref(),
        Some("application/x-www-form-urlencoded"),
        "--data-raw still defaults to form-urlencoded"
    );
    assert_eq!(
        got.2, b"@notafile",
        "--data-raw must put the literal `@` text on the wire"
    );
}

/// A user-supplied `Content-Type:` via `-H` must override the per-body
/// default (`application/x-www-form-urlencoded` for `-d`, `multipart/…`
/// for `-F`, `application/octet-stream` for `-T`). We check the `-d`
/// path because it's the most common; the same code path serves all
/// three, so this locks in the contract for everyone.
#[test]
fn cli_custom_content_type_header_overrides_default() {
    use std::process::Command;
    let (server, slot) = capture_one_request();

    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args([
            "-H",
            "Content-Type: application/json",
            "-d",
            r#"{"k":"v"}"#,
            &server.url("/post"),
        ])
        .output()
        .expect("spawn rsurl");
    assert!(
        out.status.success(),
        "rsurl exited non-zero: {:?}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    let got = slot.lock().unwrap().clone().expect("handler ran");
    assert_eq!(got.0, "POST");
    assert_eq!(
        got.1.as_deref(),
        Some("application/json"),
        "explicit -H Content-Type must win over the per-flag default"
    );
    assert_eq!(got.2, br#"{"k":"v"}"#);
}

/// `--http3-only` against an unresolvable host must fail cleanly: a non-zero
/// transfer exit (7), no panic, and no fallback to TCP. We use an `.invalid`
/// host (RFC 6761 guarantees it never resolves) so the QUIC path bails at the
/// UDP-address-resolution step on every platform — no UDP egress required, so
/// the test is hermetic and deterministic in CI.
#[test]
fn cli_http3_only_unresolvable_fails_cleanly() {
    use std::process::Command;
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args(["--http3-only", "https://host.invalid/"])
        .output()
        .expect("spawn rsurl");
    // The exact code is environment-dependent: a resolver that returns NXDOMAIN
    // yields 6 (couldn't resolve), but a runner whose resolver maps the bogus
    // host to an address makes the QUIC attempt fail instead (a different
    // non-zero code). What must hold everywhere: a clean non-zero exit, no panic.
    assert!(
        !out.status.success(),
        "unresolvable host must fail, got {:?}",
        out.status
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!err.contains("panicked"), "must not panic; stderr: {err}");
}

/// `--http3-only` on a plaintext `http://` URL is a hard error — HTTP/3 needs
/// QUIC, which is encrypted by construction. Exit non-zero, no panic.
#[test]
fn cli_http3_only_rejects_plaintext_http() {
    use std::process::Command;
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args(["--http3-only", "http://host.invalid/"])
        .output()
        .expect("spawn rsurl");
    assert!(
        !out.status.success(),
        "http:// + --http3-only must fail, got {:?}",
        out.status
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!err.contains("panicked"), "must not panic; stderr: {err}");
}

/// `--http3` (with fallback) against an unresolvable host fails cleanly too:
/// the QUIC attempt fails, falls through to the Auto h2/1.1 path, and that
/// fails as well — so the whole thing exits non-zero without panicking. (The
/// exact code is environment-dependent; see the `--http3-only` test.)
#[test]
fn cli_http3_with_fallback_unresolvable_fails_cleanly() {
    use std::process::Command;
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args(["--http3", "https://host.invalid/"])
        .output()
        .expect("spawn rsurl");
    assert!(
        !out.status.success(),
        "unresolvable host must fail, got {:?}",
        out.status
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!err.contains("panicked"), "must not panic; stderr: {err}");
}

// ---------------------------------------------------------------------------
// Pluggable connectors / SOCKS proxy (phase 2)
// ---------------------------------------------------------------------------

/// A caller-supplied [`rsurl::net::Connector`] that ignores the requested
/// host:port and always dials a fixed address. Proves the request rode the
/// custom transport (the URL host `origin.invalid` would never resolve).
#[test]
fn custom_connector_overrides_transport() {
    use std::net::{SocketAddr, TcpStream};
    use std::sync::Arc;

    #[derive(Debug)]
    struct FixedConnector {
        addr: SocketAddr,
    }
    impl rsurl::net::Connector for FixedConnector {
        fn connect(
            &self,
            _host: &str,
            _port: u16,
            _timeout: Option<Duration>,
        ) -> rsurl::Result<Box<dyn rsurl::net::NetStream>> {
            Ok(Box::new(TcpStream::connect(self.addr)?))
        }
    }

    let server = TestServer::start(|_req: SReq| SResp::ok("via-connector"));
    let resp = Request::get("http://origin.invalid/")
        .unwrap()
        .connector(Arc::new(FixedConnector { addr: server.addr }))
        .send()
        .unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"via-connector");
}

/// End-to-end plain HTTP through a mock SOCKS5h proxy: the proxy performs the
/// RFC 1928 no-auth handshake, accepts the domain-form CONNECT, then serves a
/// canned HTTP/1.1 response. `socks5h://` keeps DNS on the proxy so the
/// unresolvable `origin.invalid` host works.
#[test]
fn http_via_socks5h_proxy() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind socks mock");
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        // Greeting: VER, NMETHODS, METHODS...
        let mut head = [0u8; 2];
        s.read_exact(&mut head).unwrap();
        let mut methods = vec![0u8; head[1] as usize];
        s.read_exact(&mut methods).unwrap();
        s.write_all(&[0x05, 0x00]).unwrap(); // select NO-AUTH
                                             // CONNECT request: VER CMD RSV ATYP DST.ADDR DST.PORT
        let mut req = [0u8; 4];
        s.read_exact(&mut req).unwrap();
        assert_eq!(req[3], 0x03, "socks5h should send a domain ATYP");
        let mut dlen = [0u8; 1];
        s.read_exact(&mut dlen).unwrap();
        let mut domain = vec![0u8; dlen[0] as usize];
        s.read_exact(&mut domain).unwrap();
        assert_eq!(&domain, b"origin.invalid");
        let mut port = [0u8; 2];
        s.read_exact(&mut port).unwrap();
        // Success reply with BND 0.0.0.0:0.
        s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .unwrap();
        // Drain the HTTP request, then serve a canned response.
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            if s.read(&mut byte).unwrap() == 0 {
                break;
            }
            buf.push(byte[0]);
            if buf.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
            .unwrap();
        s.flush().unwrap();
    });

    let resp = Request::get("http://origin.invalid/")
        .unwrap()
        .proxy(&format!("socks5h://{addr}"))
        .unwrap()
        .connect_timeout(Duration::from_secs(2))
        .send()
        .unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"hello");
    handle.join().unwrap();
}

/// A non-HTTP scheme (gopher) routed through `Client` + a custom connector.
/// Proves the phase-3 wiring threads the connector into the protocol backends.
#[test]
fn client_custom_connector_drives_gopher() {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::Arc;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind gopher mock");
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        // Read the gopher request line (selector + CRLF).
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            if s.read(&mut byte).unwrap() == 0 {
                break;
            }
            buf.push(byte[0]);
            if buf.ends_with(b"\r\n") {
                break;
            }
        }
        s.write_all(b"1Welcome\tfake\texample.com\t70\r\n.\r\n")
            .unwrap();
        // gopher is close-delimited; drop the socket to signal EOF.
    });

    #[derive(Debug)]
    struct Fixed {
        addr: SocketAddr,
    }
    impl rsurl::net::Connector for Fixed {
        fn connect(
            &self,
            _host: &str,
            _port: u16,
            _t: Option<Duration>,
        ) -> rsurl::Result<Box<dyn rsurl::net::NetStream>> {
            Ok(Box::new(TcpStream::connect(self.addr)?))
        }
    }

    let body = rsurl::Client::new()
        .connector(Arc::new(Fixed { addr }))
        .transfer("gopher://origin.invalid/1sel")
        .unwrap();
    assert!(body.starts_with(b"1Welcome"));
    handle.join().unwrap();
}

// ---------------------------------------------------------------------------
// Tier A CLI flags
// ---------------------------------------------------------------------------

/// `-f` makes an HTTP >= 400 exit 22 with no body; without it, exit is 0.
#[test]
fn cli_fail_flag_controls_exit_and_body() {
    use std::process::Command;
    let server = TestServer::start(|_req: SReq| SResp::status(404).body("nope"));
    let url = server.url("/missing");

    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args(["-f", "-s", &url])
        .output()
        .expect("spawn rsurl");
    assert_eq!(out.status.code(), Some(22), "-f on 404 should exit 22");
    assert!(out.stdout.is_empty(), "-f must suppress the body");

    let out2 = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args(["-s", &url])
        .output()
        .expect("spawn rsurl");
    assert_eq!(out2.status.code(), Some(0), "no -f on 404 should exit 0");
    assert_eq!(out2.stdout, b"nope");
}

/// `-G` folds `-d` data into the URL query and switches to GET.
#[test]
fn cli_get_moves_data_to_query() {
    use std::process::Command;
    // Echo the request line so we can see method + path+query.
    let server = TestServer::start(|req: SReq| SResp::ok(format!("{} {}", req.method, req.path)));
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args(["-s", "-G", "-d", "a=1", "-d", "b=2", &server.url("/q")])
        .output()
        .expect("spawn rsurl");
    let body = String::from_utf8_lossy(&out.stdout);
    assert_eq!(body, "GET /q?a=1&b=2", "got: {body}");
}

/// `-w` expands `%{...}` variables to stdout after the body.
#[test]
fn cli_write_out_expands_vars() {
    use std::process::Command;
    let server = TestServer::start(|_req: SReq| SResp::ok("hello"));
    let out_path = tmp_out_path("wo-vars");
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args([
            "-s",
            "-o",
            out_path.to_str().unwrap(),
            "-w",
            "%{http_code} %{size_download}",
            &server.url("/"),
        ])
        .output()
        .expect("spawn rsurl");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "200 5");
    let _ = std::fs::remove_file(&out_path);
}

/// `-n`/`--netrc-file` supplies Basic credentials for the host when `-u` and
/// URL userinfo are absent.
#[test]
fn cli_netrc_supplies_basic_auth() {
    use std::io::Write;
    use std::process::Command;
    use std::sync::{Arc, Mutex};

    let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let cap2 = Arc::clone(&captured);
    let server = TestServer::start(move |req: SReq| {
        *cap2.lock().unwrap() = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .map(|(_, v)| v.clone());
        SResp::ok("ok")
    });

    let mut netrc = std::env::temp_dir();
    netrc.push(format!("rsurl-netrc-{}", std::process::id()));
    {
        let mut f = std::fs::File::create(&netrc).unwrap();
        writeln!(f, "machine 127.0.0.1 login alice password s3cret").unwrap();
    }
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args([
            "-s",
            "--netrc-file",
            netrc.to_str().unwrap(),
            &server.url("/"),
        ])
        .output()
        .expect("spawn rsurl");
    let _ = std::fs::remove_file(&netrc);
    assert!(out.status.success());
    // base64("alice:s3cret") = "YWxpY2U6czNjcmV0"
    assert_eq!(
        captured.lock().unwrap().as_deref(),
        Some("Basic YWxpY2U6czNjcmV0")
    );
}

/// `-O -J` names the saved file from a sanitized Content-Disposition filename.
#[test]
fn cli_remote_header_name_uses_content_disposition() {
    use std::process::Command;
    let server = TestServer::start(|_req: SReq| {
        let mut r = SResp::ok("payload");
        r.headers.push((
            "Content-Disposition".into(),
            // include a path component to prove it's stripped to a basename
            "attachment; filename=\"/etc/cd-name.txt\"".into(),
        ));
        r
    });
    let dir = std::env::temp_dir().join(format!("rsurl-cd-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .current_dir(&dir)
        .args(["-s", "-O", "-J", &server.url("/file")])
        .output()
        .expect("spawn rsurl");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let saved = std::fs::read(dir.join("cd-name.txt")).expect("file named from CD basename");
    assert_eq!(saved, b"payload");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--resolve host:port:127.0.0.1` makes an otherwise-unresolvable host reach
/// the local test server.
#[test]
fn cli_resolve_overrides_dns() {
    use std::process::Command;
    let server = TestServer::start(|_req: SReq| SResp::ok("resolved"));
    let port = server.addr.port();
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args([
            "-s",
            "--resolve",
            &format!("origin.invalid:{port}:127.0.0.1"),
            &format!("http://origin.invalid:{port}/"),
        ])
        .output()
        .expect("spawn rsurl");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"resolved");
}

/// `--next` runs a second request with its own options; both bodies are output.
#[test]
fn cli_next_runs_multiple_operations() {
    use std::process::Command;
    let a = TestServer::start(|_r: SReq| SResp::ok("AAA"));
    let b = TestServer::start(|_r: SReq| SResp::ok("BBB"));
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args(["-s", &a.url("/"), "--next", "-s", &b.url("/")])
        .output()
        .expect("spawn rsurl");
    assert!(out.status.success());
    assert_eq!(out.stdout, b"AAABBB");
}

/// `-K/--config` reads options (incl. the URL) from a curl-style config file.
#[test]
fn cli_config_file_supplies_options() {
    use std::io::Write;
    use std::process::Command;
    let server = TestServer::start(|_r: SReq| SResp::ok("from-config"));
    let mut cfg = std::env::temp_dir();
    cfg.push(format!("rsurl-cfg-{}", std::process::id()));
    {
        let mut f = std::fs::File::create(&cfg).unwrap();
        writeln!(f, "# a comment").unwrap();
        writeln!(f, "silent").unwrap();
        writeln!(f, "url = \"{}\"", server.url("/")).unwrap();
    }
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args(["-K", cfg.to_str().unwrap()])
        .output()
        .expect("spawn rsurl");
    let _ = std::fs::remove_file(&cfg);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"from-config");
}

/// Bundled short flags and attached values: `-sSo FILE` = `-s -S -o FILE`.
#[test]
fn cli_bundled_short_flags() {
    use std::process::Command;
    let server = TestServer::start(|_r: SReq| SResp::ok("bundled"));
    let dir = std::env::temp_dir().join(format!("rsurl-bundle-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let outfile = dir.join("o.txt");
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .arg(format!("-sSo{}", outfile.display()))
        .arg(server.url("/"))
        .output()
        .expect("spawn rsurl");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stdout.is_empty(), "-s should silence stdout");
    assert_eq!(std::fs::read(&outfile).unwrap(), b"bundled");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--fail-with-body` exits 22 on an HTTP error but still writes the body.
#[test]
fn cli_fail_with_body() {
    use std::process::Command;
    let server = TestServer::start(|_r: SReq| SResp::status(404).body("err-body"));
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args(["-s", "--fail-with-body", &server.url("/x")])
        .output()
        .expect("spawn rsurl");
    assert_eq!(out.status.code(), Some(22));
    assert_eq!(out.stdout, b"err-body");
}

/// `--proto =https` rejects an http:// URL (exit 1) before connecting.
#[test]
fn cli_proto_restricts_scheme() {
    use std::process::Command;
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args(["-s", "--proto", "=https", "http://example.invalid/"])
        .output()
        .expect("spawn rsurl");
    assert_eq!(out.status.code(), Some(1));
}

/// A scheme-less URL defaults to http; combined with --resolve it reaches the
/// local server.
#[test]
fn cli_schemeless_url_defaults_to_http() {
    use std::process::Command;
    let server = TestServer::start(|_r: SReq| SResp::ok("defaulted"));
    let port = server.addr.port();
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args([
            "-s",
            "--resolve",
            &format!("h.invalid:{port}:127.0.0.1"),
            &format!("h.invalid:{port}/"),
        ])
        .output()
        .expect("spawn rsurl");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"defaulted");
}

/// `-z` sends an If-Modified-Since header carrying the given date.
#[test]
fn cli_time_cond_sends_if_modified_since() {
    use std::process::Command;
    use std::sync::{Arc, Mutex};
    let cap: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let c2 = Arc::clone(&cap);
    let server = TestServer::start(move |req: SReq| {
        *c2.lock().unwrap() = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("if-modified-since"))
            .map(|(_, v)| v.clone());
        SResp::ok("ok")
    });
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args([
            "-s",
            "-z",
            "Sun, 06 Nov 1994 08:49:37 GMT",
            &server.url("/"),
        ])
        .output()
        .expect("spawn rsurl");
    assert!(out.status.success());
    assert_eq!(
        cap.lock().unwrap().as_deref(),
        Some("Sun, 06 Nov 1994 08:49:37 GMT")
    );
}

/// URL globbing: `[1-3]` expands into three transfers.
#[test]
fn cli_url_globbing_expands_range() {
    use std::process::Command;
    let server = TestServer::start(|req: SReq| SResp::ok(req.path.clone()));
    let url = format!("{}[1-3]", server.url("/p"));
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args(["-s", &url])
        .output()
        .expect("spawn rsurl");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"/p1/p2/p3");
}

/// `-g/--globoff` disables globbing — the brackets reach the server literally.
#[test]
fn cli_globoff_keeps_brackets() {
    use std::process::Command;
    let server = TestServer::start(|req: SReq| SResp::ok(req.path.clone()));
    let url = format!("{}[1-3]", server.url("/p"));
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args(["-s", "-g", &url])
        .output()
        .expect("spawn rsurl");
    assert!(out.status.success());
    assert_eq!(out.stdout, b"/p[1-3]");
}

/// `--post302` keeps the POST method across a 302 (curl downgrades to GET
/// without it).
#[test]
fn cli_post302_preserves_method() {
    use std::process::Command;
    let server = TestServer::start(|req: SReq| {
        if req.path == "/a" {
            let mut r = SResp::status(302);
            r.headers.push(("Location".into(), "/b".into()));
            r
        } else {
            SResp::ok(req.method.clone())
        }
    });
    // With --post302: method preserved → /b sees POST.
    let kept = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args(["-s", "-L", "--post302", "-d", "x=1", &server.url("/a")])
        .output()
        .expect("spawn");
    assert_eq!(
        kept.stdout,
        b"POST",
        "stderr: {}",
        String::from_utf8_lossy(&kept.stderr)
    );
    // Without it: curl-default downgrade → /b sees GET.
    let downgraded = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args(["-s", "-L", "-d", "x=1", &server.url("/a")])
        .output()
        .expect("spawn");
    assert_eq!(downgraded.stdout, b"GET");
}

/// `--connect-to` dials a different address while keeping the original Host:.
#[test]
fn cli_connect_to_redirects_dial_keeps_host() {
    use std::process::Command;
    let server = TestServer::start(|req: SReq| {
        let host = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        SResp::ok(host)
    });
    let port = server.addr.port();
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args([
            "-s",
            "--connect-to",
            &format!("origin.invalid:80:127.0.0.1:{port}"),
            "http://origin.invalid/",
        ])
        .output()
        .expect("spawn rsurl");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"origin.invalid");
}

/// `--unix-socket` routes the HTTP request through a Unix-domain socket.
#[cfg(unix)]
#[test]
fn cli_unix_socket_transport() {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::process::Command;

    let dir = std::env::temp_dir().join(format!("rsurl-uds-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("s.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let handle = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut buf = Vec::new();
        let mut b = [0u8; 1];
        loop {
            if s.read(&mut b).unwrap() == 0 {
                break;
            }
            buf.push(b[0]);
            if buf.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nUDS!")
            .unwrap();
    });
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args([
            "-s",
            "--unix-socket",
            sock.to_str().unwrap(),
            "http://localhost/",
        ])
        .output()
        .expect("spawn rsurl");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"UDS!");
    handle.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// End-to-end SMTP send against a minimal mock server: EHLO → MAIL → RCPT →
/// DATA → body → QUIT. Asserts the envelope and dot-unstuffed body.
#[test]
fn cli_smtp_send() {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::process::Command;
    use std::sync::{Arc, Mutex};

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let cap = Arc::clone(&captured);
    let handle = std::thread::spawn(move || {
        fn line(r: &mut BufReader<std::net::TcpStream>) -> String {
            let mut l = String::new();
            r.read_line(&mut l).unwrap();
            l.trim_end().to_string()
        }
        let (s, _) = listener.accept().unwrap();
        let mut w = s.try_clone().unwrap();
        let mut r = BufReader::new(s);
        w.write_all(b"220 mock ESMTP\r\n").unwrap();
        let ehlo = line(&mut r);
        cap.lock().unwrap().push(ehlo);
        w.write_all(b"250-mock\r\n250 AUTH PLAIN\r\n").unwrap();
        let mf = line(&mut r);
        cap.lock().unwrap().push(mf);
        w.write_all(b"250 ok\r\n").unwrap();
        let rcpt = line(&mut r);
        cap.lock().unwrap().push(rcpt);
        w.write_all(b"250 ok\r\n").unwrap();
        let _data = line(&mut r); // DATA
        w.write_all(b"354 go ahead\r\n").unwrap();
        // Read body until the lone "." line.
        let mut body = String::new();
        loop {
            let mut l = String::new();
            r.read_line(&mut l).unwrap();
            if l == ".\r\n" || l == ".\n" {
                break;
            }
            body.push_str(&l);
        }
        cap.lock()
            .unwrap()
            .push(format!("BODY:{}", body.trim_end()));
        w.write_all(b"250 queued\r\n").unwrap();
        let _ = line(&mut r); // QUIT
        w.write_all(b"221 bye\r\n").unwrap();
        let _ = r.read(&mut [0u8; 1]);
    });

    let mut msg = std::env::temp_dir();
    msg.push(format!("rsurl-smtp-{}.txt", std::process::id()));
    std::fs::write(&msg, b"Subject: hi\r\n\r\nHello over SMTP\r\n").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args([
            "-s",
            "--mail-from",
            "alice@example.com",
            "--mail-rcpt",
            "bob@example.com",
            "-T",
            msg.to_str().unwrap(),
            &format!("smtp://127.0.0.1:{}", addr.port()),
        ])
        .output()
        .expect("spawn rsurl");
    let _ = std::fs::remove_file(&msg);
    handle.join().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let c = captured.lock().unwrap();
    assert!(c.iter().any(|l| l.starts_with("EHLO ")), "got: {c:?}");
    assert!(
        c.iter().any(|l| l == "MAIL FROM:<alice@example.com>"),
        "got: {c:?}"
    );
    assert!(
        c.iter().any(|l| l == "RCPT TO:<bob@example.com>"),
        "got: {c:?}"
    );
    assert!(
        c.iter().any(|l| l.contains("Hello over SMTP")),
        "got: {c:?}"
    );
}

/// TELNET: server negotiates an option and sends a banner; rsurl strips the
/// IAC bytes from output and refuses the option.
#[test]
fn cli_telnet_strips_iac_and_refuses() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::process::Command;
    use std::sync::{Arc, Mutex};

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let got = Arc::new(Mutex::new(Vec::<u8>::new()));
    let g2 = Arc::clone(&got);
    let handle = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        // IAC WILL ECHO(1), then "banner\r\n".
        s.write_all(&[255, 251, 1]).unwrap();
        s.write_all(b"banner\r\n").unwrap();
        s.flush().unwrap();
        // Read the client's refusal (IAC DONT 1) then close.
        let mut buf = [0u8; 16];
        if let Ok(n) = s.read(&mut buf) {
            g2.lock().unwrap().extend_from_slice(&buf[..n]);
        }
    });
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args(["-s", &format!("telnet://127.0.0.1:{}", addr.port())])
        .output()
        .expect("spawn rsurl");
    handle.join().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.stdout, b"banner\r\n",
        "IAC should be stripped from output"
    );
    assert_eq!(
        &*got.lock().unwrap(),
        &[255, 254, 1],
        "should refuse with IAC DONT 1"
    );
}

/// A download to a file is streamed (chunked) to disk and the bytes match.
#[test]
fn cli_streamed_download_to_file() {
    use std::process::Command;
    // 100 KiB across several chunks.
    let chunk = vec![b'z'; 16 * 1024];
    let chunks: Vec<Vec<u8>> = (0..7).map(|_| chunk.clone()).collect();
    let total: usize = chunks.iter().map(|c| c.len()).sum();
    let server = TestServer::start(move |_r: SReq| {
        SResp::ok(Vec::new()).mode(BodyMode::Chunked {
            chunks: chunks.clone(),
            trailers: vec![],
        })
    });
    let dir = std::env::temp_dir().join(format!("rsurl-dl-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out_path = dir.join("big.bin");
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args(["-s", "-o", out_path.to_str().unwrap(), &server.url("/big")])
        .output()
        .expect("spawn rsurl");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let saved = std::fs::read(&out_path).unwrap();
    assert_eq!(saved.len(), total);
    assert!(saved.iter().all(|&b| b == b'z'));
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--max-filesize` aborts a streamed download that exceeds the cap (exit 63).
#[test]
fn cli_max_filesize_aborts_stream() {
    use std::process::Command;
    let server = TestServer::start(|_r: SReq| SResp::ok(vec![b'x'; 50_000]));
    let dir = std::env::temp_dir().join(format!("rsurl-mfs-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out_path = dir.join("capped.bin");
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args([
            "-s",
            "--max-filesize",
            "1000",
            "-o",
            out_path.to_str().unwrap(),
            &server.url("/big"),
        ])
        .output()
        .expect("spawn rsurl");
    assert_eq!(
        out.status.code(),
        Some(63),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--digest`: first request is unauthenticated, gets a 401 Digest challenge,
/// then resends with a computed Digest Authorization and succeeds.
#[test]
fn cli_digest_auth() {
    use std::process::Command;
    use std::sync::{Arc, Mutex};
    let auth_seen: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let a2 = Arc::clone(&auth_seen);
    let server = TestServer::start(move |req: SReq| {
        let auth = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .map(|(_, v)| v.clone());
        match auth {
            Some(a) if a.starts_with("Digest") => {
                *a2.lock().unwrap() = Some(a);
                SResp::ok("authed")
            }
            _ => {
                let mut r = SResp::status(401);
                r.headers.push((
                    "WWW-Authenticate".into(),
                    "Digest realm=\"test\", nonce=\"abc123\", qop=\"auth\"".into(),
                ));
                r
            }
        }
    });
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args(["-s", "--digest", "-u", "alice:secret", &server.url("/")])
        .output()
        .expect("spawn rsurl");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"authed");
    let a = auth_seen
        .lock()
        .unwrap()
        .clone()
        .expect("digest header sent");
    assert!(a.contains("username=\"alice\""), "got: {a}");
    assert!(a.contains("realm=\"test\""), "got: {a}");
    assert!(a.contains("qop=auth"), "got: {a}");
    assert!(a.contains("response=\""), "got: {a}");
}

/// `--oauth2-bearer` sends `Authorization: Bearer <token>`.
#[test]
fn cli_oauth2_bearer() {
    use std::process::Command;
    use std::sync::{Arc, Mutex};
    let cap: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let c2 = Arc::clone(&cap);
    let server = TestServer::start(move |req: SReq| {
        *c2.lock().unwrap() = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .map(|(_, v)| v.clone());
        SResp::ok("ok")
    });
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args(["-s", "--oauth2-bearer", "tok123", &server.url("/")])
        .output()
        .expect("spawn rsurl");
    assert!(out.status.success());
    assert_eq!(cap.lock().unwrap().as_deref(), Some("Bearer tok123"));
}

/// `-Z/--parallel` runs globbed transfers concurrently; each writes its file.
#[test]
fn cli_parallel_glob_downloads() {
    use std::process::Command;
    let server = TestServer::start_keepalive(|req: SReq| SResp::ok(req.path.clone()));
    let dir = std::env::temp_dir().join(format!("rsurl-par-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let url = format!("{}[1-4]", server.url("/p"));
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .current_dir(&dir)
        .args(["-s", "-Z", "-o", "#1.out", &url])
        .output()
        .expect("spawn rsurl");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    for n in 1..=4 {
        let got = std::fs::read(dir.join(format!("{n}.out"))).expect("file present");
        assert_eq!(got, format!("/p{n}").into_bytes());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--aws-sigv4` adds an AWS4-HMAC-SHA256 Authorization plus x-amz-* headers.
#[test]
fn cli_aws_sigv4_signs() {
    use std::process::Command;
    use std::sync::{Arc, Mutex};
    let hdrs: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let h2 = Arc::clone(&hdrs);
    let server = TestServer::start(move |req: SReq| {
        *h2.lock().unwrap() = req.headers.clone();
        SResp::ok("ok")
    });
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args([
            "-s",
            "--aws-sigv4",
            "aws:amz:us-east-1:s3",
            "-u",
            "AKID:SECRET",
            &server.url("/bucket/key"),
        ])
        .output()
        .expect("spawn rsurl");
    assert!(out.status.success());
    let h = hdrs.lock().unwrap();
    let get = |n: &str| {
        h.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(n))
            .map(|(_, v)| v.clone())
    };
    let auth = get("authorization").expect("authorization header");
    assert!(auth.starts_with("AWS4-HMAC-SHA256 "), "got: {auth}");
    assert!(auth.contains("Credential=AKID/"));
    assert!(auth.contains("/us-east-1/s3/aws4_request"));
    assert!(get("x-amz-date").is_some());
    assert!(get("x-amz-content-sha256").is_some());
}

/// `-Y <limit> -y 1` aborts a download whose average rate stays below the
/// limit for the window, exiting 28 (curl's CURLE_OPERATION_TIMEDOUT). A raw
/// listener trickles a few bytes across >1s so the low-speed check arms.
#[test]
fn cli_low_speed_abort_exits_28() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::process::Command;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        // Drain the request head.
        let mut buf = [0u8; 1024];
        let _ = sock.read(&mut buf);
        // Promise 100 bytes, then trickle 10 across >1s and stall.
        let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n");
        let _ = sock.flush();
        let _ = sock.write_all(b"01234");
        let _ = sock.flush();
        std::thread::sleep(Duration::from_millis(1300));
        let _ = sock.write_all(b"56789");
        let _ = sock.flush();
        std::thread::sleep(Duration::from_millis(1300));
        // Let the client decide; drop the socket.
    });

    let mut out_path = std::env::temp_dir();
    out_path.push(format!("rsurl-lowspeed-{}.bin", std::process::id()));
    let status = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args([
            "-s",
            "-Y",
            "1000000", // 1 MB/s minimum
            "-y",
            "1", // measured over a 1s window
            "-o",
            out_path.to_str().unwrap(),
            &format!("http://{addr}/slow"),
        ])
        .status()
        .expect("spawn rsurl");
    assert_eq!(status.code(), Some(28), "expected low-speed exit code 28");
    let _ = handle.join();
    let _ = std::fs::remove_file(&out_path);
}

/// curl-compat no-op flags (`-q`, `--no-progress-meter`, `-N`,
/// `--styled-output`) are accepted without error.
#[test]
fn cli_compat_noop_flags_accepted() {
    use std::process::Command;
    let server = TestServer::start(|_req: SReq| SResp::ok("ok"));
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args([
            "-q",
            "--no-progress-meter",
            "-N",
            "--styled-output",
            "--no-styled-output",
            "--basic",
            "--ftp-skip-pasv-ip",
            "--ftp-pasv",
            "-s",
            &server.url("/"),
        ])
        .output()
        .expect("spawn rsurl");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"ok");
}

/// `-w` phase timers are populated (non-zero, well-formed floats) on the
/// direct HTTP/1.1 path.
#[test]
fn cli_write_out_phase_timers() {
    use std::process::Command;
    let server = TestServer::start(|_req: SReq| SResp::ok("hello"));
    let out_path = tmp_out_path("wo-timers");
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args([
            "-s",
            "-o",
            out_path.to_str().unwrap(),
            "-w",
            "%{time_connect} %{time_starttransfer} %{time_total}",
            &server.url("/"),
        ])
        .output()
        .expect("spawn rsurl");
    assert!(out.status.success());
    let line = String::from_utf8_lossy(&out.stdout);
    let nums: Vec<f64> = line
        .split_whitespace()
        .map(|s| s.parse::<f64>().expect("write-out timer is a float"))
        .collect();
    assert_eq!(nums.len(), 3, "got: {line:?}");
    // connect <= starttransfer <= total, and starttransfer was measured (> 0).
    assert!(nums[1] > 0.0, "starttransfer should be measured: {line:?}");
    assert!(
        nums[0] <= nums[1] + 1e-6,
        "connect<=starttransfer: {line:?}"
    );
    assert!(nums[1] <= nums[2] + 1e-6, "starttransfer<=total: {line:?}");
    let _ = std::fs::remove_file(&out_path);
}

/// `-w %header{Name}` emits a named response header; `%{ssl_verify_result}`
/// reports 0 after a successful transfer.
#[test]
fn cli_write_out_header_var() {
    use std::process::Command;
    let server = TestServer::start(|_req: SReq| SResp::ok("body").header("X-Test", "abc123"));
    let out_path = tmp_out_path("wo-header");
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args([
            "-s",
            "-o",
            out_path.to_str().unwrap(),
            "-w",
            "[%header{X-Test}|%{ssl_verify_result}]",
            &server.url("/"),
        ])
        .output()
        .expect("spawn rsurl");
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout), "[abc123|0]");
    let _ = std::fs::remove_file(&out_path);
}

/// A connection refused on an HTTP URL exits 7 (CURLE_COULDNT_CONNECT), and a
/// malformed URL exits 3 (CURLE_URL_MALFORMAT) — the centralized exit-code map.
#[test]
fn cli_exit_codes_connect_and_url() {
    use std::process::Command;
    // Port 1 is privileged and almost certainly not listening → connect fails.
    let refused = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args(["-s", "http://127.0.0.1:1/"])
        .status()
        .expect("spawn rsurl");
    assert_eq!(refused.code(), Some(7), "connection refused should exit 7");

    let bad = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args(["-s", "http://"])
        .status()
        .expect("spawn rsurl");
    assert_eq!(bad.code(), Some(3), "malformed URL should exit 3");
}

/// `--json` sends the body as application/json, sets Accept: application/json,
/// and defaults the method to POST.
#[test]
fn cli_json_flag_sets_content_type_and_accept() {
    use std::process::Command;
    use std::sync::{Arc, Mutex};
    // (method, headers, body) — aliased so clippy::type_complexity is happy.
    type Cap = Arc<Mutex<Option<(String, Vec<(String, String)>, Vec<u8>)>>>;
    let cap: Cap = Arc::new(Mutex::new(None));
    let c2 = Arc::clone(&cap);
    let server = TestServer::start(move |req: SReq| {
        *c2.lock().unwrap() = Some((req.method.clone(), req.headers.clone(), req.body.clone()));
        SResp::ok("ok")
    });
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args(["-s", "--json", r#"{"a":1}"#, &server.url("/")])
        .output()
        .expect("spawn rsurl");
    assert!(out.status.success());
    let g = cap.lock().unwrap();
    let (method, headers, body) = g.as_ref().expect("request captured");
    assert_eq!(method, "POST");
    assert_eq!(body, br#"{"a":1}"#);
    let hv = |n: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(n))
            .map(|(_, v)| v.as_str())
    };
    assert_eq!(hv("content-type"), Some("application/json"));
    assert_eq!(hv("accept"), Some("application/json"));
}

/// `--no-clobber` never overwrites an existing -o target; it picks `.1`.
#[test]
fn cli_no_clobber_picks_suffix() {
    use std::process::Command;
    let server = TestServer::start(|_req: SReq| SResp::ok("fresh"));
    let base = tmp_out_path("noclobber");
    std::fs::write(&base, b"original").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args([
            "-s",
            "--no-clobber",
            "-o",
            base.to_str().unwrap(),
            &server.url("/"),
        ])
        .output()
        .expect("spawn rsurl");
    assert!(out.status.success());
    // The original file is untouched; the download landed in "<base>.1".
    assert_eq!(std::fs::read(&base).unwrap(), b"original");
    let alt = std::path::PathBuf::from(format!("{}.1", base.to_str().unwrap()));
    assert_eq!(std::fs::read(&alt).unwrap(), b"fresh");
    let _ = std::fs::remove_file(&base);
    let _ = std::fs::remove_file(&alt);
}

/// `--remove-on-error` deletes the partial file when a download fails mid-body.
#[test]
fn cli_remove_on_error_deletes_partial() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::process::Command;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let mut buf = [0u8; 1024];
        let _ = sock.read(&mut buf);
        // Promise 100 bytes, send 10, then drop the connection mid-body.
        let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n0123456789");
        let _ = sock.flush();
        // socket closes here → client sees a short/truncated body → error.
    });
    let out_path = tmp_out_path("removeonerr");
    let status = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args([
            "-s",
            "--remove-on-error",
            "-o",
            out_path.to_str().unwrap(),
            &format!("http://{addr}/x"),
        ])
        .status()
        .expect("spawn rsurl");
    let _ = handle.join();
    assert!(!status.success(), "truncated body should fail");
    assert!(
        !out_path.exists(),
        "--remove-on-error must delete the partial file"
    );
    let _ = std::fs::remove_file(&out_path);
}

/// End-to-end FTP download streams the data channel to a file. A minimal mock
/// FTP server scripts the control dialogue (banner, USER/PASS, TYPE I, EPSV,
/// RETR) and serves the file body on the passive data connection.
#[test]
fn cli_ftp_download_streams_to_file() {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::process::Command;

    let ctrl = TcpListener::bind("127.0.0.1:0").unwrap();
    let ctrl_port = ctrl.local_addr().unwrap().port();
    let data = TcpListener::bind("127.0.0.1:0").unwrap();
    let data_port = data.local_addr().unwrap().port();

    let handle = std::thread::spawn(move || {
        let (sock, _) = ctrl.accept().unwrap();
        let mut w = sock.try_clone().unwrap();
        let mut r = BufReader::new(sock);
        w.write_all(b"220 mock ready\r\n").unwrap();
        loop {
            let mut line = String::new();
            if r.read_line(&mut line).unwrap() == 0 {
                break;
            }
            let cmd = line.trim_end();
            if cmd.starts_with("USER") {
                w.write_all(b"331 need password\r\n").unwrap();
            } else if cmd.starts_with("PASS") {
                w.write_all(b"230 logged in\r\n").unwrap();
            } else if cmd.starts_with("EPSV") {
                w.write_all(
                    format!("229 Entering Extended Passive Mode (|||{data_port}|)\r\n").as_bytes(),
                )
                .unwrap();
            } else if cmd.starts_with("RETR") {
                w.write_all(b"150 opening data connection\r\n").unwrap();
                let (mut d, _) = data.accept().unwrap();
                d.write_all(b"FTP-STREAMED-BODY").unwrap();
                drop(d); // EOF closes the data channel
                w.write_all(b"226 transfer complete\r\n").unwrap();
            } else if cmd.starts_with("QUIT") {
                w.write_all(b"221 bye\r\n").unwrap();
                break;
            } else {
                // TYPE I and anything else.
                w.write_all(b"200 ok\r\n").unwrap();
            }
        }
    });

    let out_path = tmp_out_path("ftp-dl");
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args([
            "-s",
            "-o",
            out_path.to_str().unwrap(),
            "-w",
            "%{size_download}",
            &format!("ftp://127.0.0.1:{ctrl_port}/file.txt"),
        ])
        .output()
        .expect("spawn rsurl");
    let _ = handle.join();
    assert!(out.status.success(), "ftp download should succeed");
    assert_eq!(std::fs::read(&out_path).unwrap(), b"FTP-STREAMED-BODY");
    // -w works for FTP too: size_download is the streamed byte count (17).
    assert_eq!(String::from_utf8_lossy(&out.stdout), "17");
    let _ = std::fs::remove_file(&out_path);
}

/// `--ftp-create-dirs` issues MKD for each directory prefix before STOR, and
/// the upload body is delivered. A mock FTP server records the MKD commands and
/// the stored bytes.
#[test]
fn cli_ftp_create_dirs_upload() {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::process::Command;
    use std::sync::{Arc, Mutex};

    let ctrl = TcpListener::bind("127.0.0.1:0").unwrap();
    let ctrl_port = ctrl.local_addr().unwrap().port();
    let data = TcpListener::bind("127.0.0.1:0").unwrap();
    let data_port = data.local_addr().unwrap().port();
    let seen: Arc<Mutex<(Vec<String>, Vec<u8>)>> = Arc::new(Mutex::new((Vec::new(), Vec::new())));
    let seen2 = Arc::clone(&seen);

    let handle = std::thread::spawn(move || {
        let (sock, _) = ctrl.accept().unwrap();
        let mut w = sock.try_clone().unwrap();
        let mut r = BufReader::new(sock);
        w.write_all(b"220 mock\r\n").unwrap();
        loop {
            let mut line = String::new();
            if r.read_line(&mut line).unwrap() == 0 {
                break;
            }
            let cmd = line.trim_end();
            if cmd.starts_with("USER") {
                w.write_all(b"331 pw\r\n").unwrap();
            } else if cmd.starts_with("PASS") {
                w.write_all(b"230 ok\r\n").unwrap();
            } else if let Some(dir) = cmd.strip_prefix("MKD ") {
                seen2.lock().unwrap().0.push(dir.to_string());
                w.write_all(b"257 created\r\n").unwrap();
            } else if cmd.starts_with("EPSV") {
                w.write_all(
                    format!("229 Entering Extended Passive Mode (|||{data_port}|)\r\n").as_bytes(),
                )
                .unwrap();
            } else if cmd.starts_with("STOR") {
                w.write_all(b"150 send it\r\n").unwrap();
                let (mut d, _) = data.accept().unwrap();
                let mut body = Vec::new();
                d.read_to_end(&mut body).unwrap();
                seen2.lock().unwrap().1 = body;
                w.write_all(b"226 stored\r\n").unwrap();
            } else if cmd.starts_with("QUIT") {
                w.write_all(b"221 bye\r\n").unwrap();
                break;
            } else {
                w.write_all(b"200 ok\r\n").unwrap();
            }
        }
    });

    let mut tmp = std::env::temp_dir();
    tmp.push(format!("rsurl-ftp-up-{}.bin", std::process::id()));
    std::fs::write(&tmp, b"UPLOAD-PAYLOAD").unwrap();
    let status = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args([
            "-s",
            "--ftp-create-dirs",
            "-T",
            tmp.to_str().unwrap(),
            &format!("ftp://127.0.0.1:{ctrl_port}/a/b/file.bin"),
        ])
        .status()
        .expect("spawn rsurl");
    let _ = handle.join();
    assert!(status.success(), "ftp upload should succeed");
    let g = seen.lock().unwrap();
    assert_eq!(
        g.0,
        vec!["a".to_string(), "a/b".to_string()],
        "MKD prefixes"
    );
    assert_eq!(g.1, b"UPLOAD-PAYLOAD");
    let _ = std::fs::remove_file(&tmp);
}

/// `file://` download to a file streams the local file through the sink and -w
/// reports the byte count. Unix-only: building a `file://` URL from a Windows
/// path (drive letter + backslashes) isn't portable, and the feature is the
/// same code path on every platform — this just exercises it via the CLI.
#[test]
#[cfg(unix)]
fn cli_file_scheme_download_to_file() {
    use std::process::Command;
    let mut src = std::env::temp_dir();
    src.push(format!("rsurl-file-src-{}.txt", std::process::id()));
    std::fs::write(&src, b"LOCAL-FILE-CONTENTS").unwrap();
    let out_path = tmp_out_path("file-dl");
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args([
            "-s",
            "-o",
            out_path.to_str().unwrap(),
            "-w",
            "%{size_download}",
            &format!("file://{}", src.to_str().unwrap()),
        ])
        .output()
        .expect("spawn rsurl");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(&out_path).unwrap(), b"LOCAL-FILE-CONTENTS");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "19");
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&out_path);
}

/// A gzip-encoded, Content-Length-framed download decodes straight off the wire
/// (streaming decompression), writing the plaintext to the output file.
#[test]
fn cli_streaming_gzip_decode_to_file() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::process::Command;
    // gzip("STREAM-GZIP-DECODE-OK") — 41 bytes, generated with `gzip -c`.
    let gz: [u8; 41] = [
        31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 11, 14, 9, 114, 117, 244, 213, 117, 143, 242, 12, 208,
        117, 113, 117, 246, 119, 113, 213, 245, 247, 6, 0, 182, 187, 1, 85, 21, 0, 0, 0,
    ];
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let mut buf = [0u8; 1024];
        let _ = sock.read(&mut buf);
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
            gz.len()
        );
        let _ = sock.write_all(head.as_bytes());
        let _ = sock.write_all(&gz);
        let _ = sock.flush();
    });
    let out_path = tmp_out_path("gz-stream");
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args([
            "-s",
            "-o",
            out_path.to_str().unwrap(),
            "-w",
            "%{size_download}",
            &format!("http://{addr}/g"),
        ])
        .output()
        .expect("spawn rsurl");
    let _ = handle.join();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(&out_path).unwrap(), b"STREAM-GZIP-DECODE-OK");
    // size_download is the decoded byte count (21).
    assert_eq!(String::from_utf8_lossy(&out.stdout), "21");
    let _ = std::fs::remove_file(&out_path);
}

/// End-to-end active-mode FTP download (`-P`): the client sends EPRT and
/// listens; the mock server parses the advertised port, dials back, and streams
/// the file over that data connection.
#[test]
fn cli_ftp_active_mode_download() {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpStream;
    use std::process::Command;

    let ctrl = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let ctrl_port = ctrl.local_addr().unwrap().port();

    let handle = std::thread::spawn(move || {
        let (sock, _) = ctrl.accept().unwrap();
        let mut w = sock.try_clone().unwrap();
        let mut r = BufReader::new(sock);
        w.write_all(b"220 mock\r\n").unwrap();
        let mut data_port: u16 = 0;
        loop {
            let mut line = String::new();
            if r.read_line(&mut line).unwrap() == 0 {
                break;
            }
            let cmd = line.trim_end();
            if cmd.starts_with("USER") {
                w.write_all(b"331 pw\r\n").unwrap();
            } else if cmd.starts_with("PASS") {
                w.write_all(b"230 ok\r\n").unwrap();
            } else if let Some(rest) = cmd.strip_prefix("EPRT ") {
                // EPRT |1|127.0.0.1|PORT|
                let parts: Vec<&str> = rest.trim_matches('|').split('|').collect();
                data_port = parts.get(2).and_then(|p| p.parse().ok()).unwrap_or(0);
                w.write_all(b"200 EPRT ok\r\n").unwrap();
            } else if cmd.starts_with("RETR") {
                w.write_all(b"150 opening\r\n").unwrap();
                // Active mode: WE dial back to the client's advertised port.
                let mut d = TcpStream::connect(("127.0.0.1", data_port)).unwrap();
                d.write_all(b"ACTIVE-MODE-BODY").unwrap();
                drop(d);
                w.write_all(b"226 done\r\n").unwrap();
            } else if cmd.starts_with("QUIT") {
                w.write_all(b"221 bye\r\n").unwrap();
                break;
            } else {
                w.write_all(b"200 ok\r\n").unwrap();
            }
        }
    });

    let out_path = tmp_out_path("ftp-active");
    let status = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args([
            "-s",
            "-P",
            "-",
            "-o",
            out_path.to_str().unwrap(),
            &format!("ftp://127.0.0.1:{ctrl_port}/file.txt"),
        ])
        .status()
        .expect("spawn rsurl");
    let _ = handle.join();
    assert!(status.success(), "active-mode ftp download should succeed");
    assert_eq!(std::fs::read(&out_path).unwrap(), b"ACTIVE-MODE-BODY");
    let _ = std::fs::remove_file(&out_path);
}

/// The C ABI honors the newer options: RSURLOPT_USERPWD (Basic auth),
/// RSURLOPT_FOLLOWLOCATION, and RSURLOPT_REFERER. Driven through the real
/// extern "C" entry points against a loopback server.
#[test]
fn ffi_easy_extended_options() {
    use rsurl::ffi::{
        rsurl_easy_cleanup, rsurl_easy_init, rsurl_easy_perform, rsurl_easy_response_body,
        rsurl_easy_response_status, rsurl_easy_setopt_long, rsurl_easy_setopt_str,
    };
    use std::ffi::CString;
    use std::sync::{Arc, Mutex};

    let seen: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let s2 = Arc::clone(&seen);
    let server = TestServer::start(move |req: SReq| {
        *s2.lock().unwrap() = req.headers.clone();
        SResp::ok("ffi-ok")
    });
    let url = CString::new(server.url("/")).unwrap();
    let userpwd = CString::new("alice:s3cret").unwrap();
    let referer = CString::new("https://ref.example/").unwrap();

    unsafe {
        let h = rsurl_easy_init();
        assert!(!h.is_null());
        // 1=URL, 11=USERPWD, 14=REFERER, 9=FOLLOWLOCATION, 12=SSL_VERIFYPEER.
        assert_eq!(rsurl_easy_setopt_str(h, 1, url.as_ptr()) as i32, 0);
        assert_eq!(rsurl_easy_setopt_str(h, 11, userpwd.as_ptr()) as i32, 0);
        assert_eq!(rsurl_easy_setopt_str(h, 14, referer.as_ptr()) as i32, 0);
        assert_eq!(rsurl_easy_setopt_long(h, 9, 1) as i32, 0);
        assert_eq!(rsurl_easy_setopt_long(h, 12, 1) as i32, 0);
        assert_eq!(rsurl_easy_perform(h) as i32, 0);
        assert_eq!(rsurl_easy_response_status(h), 200);

        let mut ptr: *const u8 = std::ptr::null();
        let mut len: usize = 0;
        assert_eq!(rsurl_easy_response_body(h, &mut ptr, &mut len) as i32, 0);
        let body = std::slice::from_raw_parts(ptr, len);
        assert_eq!(body, b"ffi-ok");
        rsurl_easy_cleanup(h);
    }

    let h = seen.lock().unwrap();
    let get = |n: &str| {
        h.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(n))
            .map(|(_, v)| v.clone())
    };
    // USERPWD → Basic base64("alice:s3cret"); REFERER → Referer header.
    assert_eq!(
        get("authorization").as_deref(),
        Some("Basic YWxpY2U6czNjcmV0")
    );
    assert_eq!(get("referer").as_deref(), Some("https://ref.example/"));
}

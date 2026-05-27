//! Live HTTP/1.1 integration tests for rsurl.
//!
//! Each test spins up a single-shot [`TestServer`] in `common/`, points a
//! [`rsurl::Request`] at it, and asserts both directions of the wire.
//! No external network is touched.

mod common;

use std::time::Duration;

use common::{BodyMode, Request as SReq, Response as SResp, TestServer};

use rsurl::{Error, Request};

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
/// Locks in: User-Agent default, Accept: */*, Host, Connection: close.
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
        text.contains("Connection: close\n"),
        "missing Connection: close in: {text}",
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
/// for the response status & headers, and a `* Connection closed` epilogue.
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
        t.contains("* Connection closed"),
        "missing close epilogue in:\n{t}",
    );
}

/// rsurl sends `Accept-Encoding: gzip, deflate` by default and must
/// transparently decode a `Content-Encoding: gzip` response. The header
/// is also expected to be **stripped** from the returned `Response`, so
/// downstream consumers don't think the body is still compressed.
#[test]
fn gzip_response_is_decoded() {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    let plain = b"hello compressed world".to_vec();
    let gz = {
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(&plain).unwrap();
        e.finish().unwrap()
    };

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

/// Same wire shape but with `deflate` (zlib-wrapped, RFC 9110 form).
#[test]
fn deflate_response_is_decoded() {
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    let plain = b"deflate body".to_vec();
    let z = {
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(&plain).unwrap();
        e.finish().unwrap()
    };

    let z_for_server = z.clone();
    let server = TestServer::start(move |_req: SReq| {
        SResp::ok(z_for_server.clone()).header("Content-Encoding", "deflate")
    });

    let resp = Request::get(&server.url("/")).unwrap().send().unwrap();
    assert_eq!(resp.body, plain);
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

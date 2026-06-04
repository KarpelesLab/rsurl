//! Live HTTP/1.1 integration tests for rsurl.
//!
//! Each test spins up a single-shot [`TestServer`] in `common/`, points a
//! [`rsurl::Request`] at it, and asserts both directions of the wire.
//! No external network is touched.

mod common;

use std::time::Duration;

use common::{BodyMode, Request as SReq, Response as SResp, TestServer};

use rsurl::{CookieJar, Error, Request};

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
/// With an unresolvable host it fails at the connect step (exit 7), proving
/// the FTP-upload path is reached rather than rejected as a usage error.
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
    assert_eq!(
        code,
        Some(7),
        "expected transfer error exit 7, got {code:?}"
    );
}

/// `-a`/`--append` with an `ftp://` URL routes to the FTP upload path (APPE).
/// With an unresolvable host it fails at the connect step (exit 7), proving the
/// append branch is reached rather than rejected as a usage error.
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
    assert_eq!(
        code,
        Some(7),
        "expected transfer error exit 7, got {code:?}"
    );
}

/// `-a` combined with `-C <offset>` for an FTP upload is accepted: APPE takes
/// precedence over REST, so the offset is ignored rather than causing an error.
/// Still reaches the FTP transfer path (exit 7 against an unresolvable host).
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
    assert_eq!(
        code,
        Some(7),
        "expected transfer error exit 7 (APPE ignores -C), got {code:?}"
    );
}

/// `-C -` (curl's automatic-resume form) is rejected at parse time with a
/// clear usage error, since automatic resume isn't implemented.
#[test]
fn cli_continue_at_dash_is_rejected() {
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
    assert_eq!(code, Some(2), "expected usage error exit 2, got {code:?}");
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
    let code = out.status.code();
    assert_eq!(
        code,
        Some(7),
        "expected transfer error exit 7, got {code:?}"
    );
    // It must not have crashed (a panic yields no exit code on unix, or a
    // SIGABRT/SIGSEGV-derived code), and the error must be a clean message.
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
/// the QUIC attempt can't resolve, falls through to the Auto h2/1.1 path, and
/// that also can't resolve — so the whole thing exits 7 without panicking.
#[test]
fn cli_http3_with_fallback_unresolvable_fails_cleanly() {
    use std::process::Command;
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args(["--http3", "https://host.invalid/"])
        .output()
        .expect("spawn rsurl");
    let code = out.status.code();
    assert_eq!(
        code,
        Some(7),
        "expected transfer error exit 7, got {code:?}"
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
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args([
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code} %{size_download}",
            &server.url("/"),
        ])
        .output()
        .expect("spawn rsurl");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "200 5");
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
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args([
            "-s",
            "-o",
            "/dev/null",
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
}

/// `-w %header{Name}` emits a named response header; `%{ssl_verify_result}`
/// reports 0 after a successful transfer.
#[test]
fn cli_write_out_header_var() {
    use std::process::Command;
    let server = TestServer::start(|_req: SReq| SResp::ok("body").header("X-Test", "abc123"));
    let out = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .args([
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "[%header{X-Test}|%{ssl_verify_result}]",
            &server.url("/"),
        ])
        .output()
        .expect("spawn rsurl");
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout), "[abc123|0]");
}

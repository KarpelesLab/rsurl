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

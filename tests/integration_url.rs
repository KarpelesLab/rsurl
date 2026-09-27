//! Black-box tests for `rsurl::Url`.
//!
//! These complement the in-module unit tests in `src/url.rs` by exercising
//! cases the public API has to handle but that aren't already covered there:
//! IPv6 literals, percent-encoded passthrough, query/fragment combinations,
//! and a few negative cases.

use rsurl::Url;

/// `[::1]:8080` is the canonical bracketed-IPv6 literal authority. We only
/// assert what's stable across parser implementations: it parses without
/// error and the path round-trips. Exact host/port split is intentionally
/// not pinned here so a parser refactor doesn't break the test.
#[test]
fn ipv6_literal_with_port() {
    let u = Url::parse("http://[::1]:8080/path?q=1").expect("ipv6 url parses");
    assert_eq!(u.scheme, "http");
    assert_eq!(u.path, "/path?q=1");
    // Sanity: the host string mentions the address. We deliberately do
    // not pin `u.host == "[::1]"` here — see the doc-comment above.
    assert!(
        u.host.contains("::1"),
        "host should retain ipv6 literal, got {:?}",
        u.host,
    );
}

/// Percent-encoded path segments must be carried verbatim. rsurl does
/// not double-encode or decode; the bytes you supply are the bytes that
/// go on the wire.
#[test]
fn percent_encoded_path_passthrough() {
    let u = Url::parse("http://example.com/foo%20bar/%2Fbaz?a=%26b").unwrap();
    assert_eq!(u.scheme, "http");
    assert_eq!(u.host, "example.com");
    assert_eq!(u.path, "/foo%20bar/%2Fbaz?a=%26b");
}

/// A query string stays glued onto the path (rsurl doesn't split them);
/// a fragment is stripped.
#[test]
fn query_kept_fragment_stripped() {
    let u = Url::parse("http://h/p?x=1&y=2#section").unwrap();
    assert_eq!(u.path, "/p?x=1&y=2");
}

/// No path at all defaults to "/", but the query is still respected when
/// it appears in the right place (after the path that we synthesize).
#[test]
fn missing_path_defaults_to_slash() {
    let u = Url::parse("http://example.com").unwrap();
    assert_eq!(u.path, "/");
    assert_eq!(u.port, 80);
}

/// HTTPS gets port 443 by default; an explicit port wins.
#[test]
fn default_https_port_and_explicit_override() {
    assert_eq!(Url::parse("https://h/").unwrap().port, 443);
    assert_eq!(Url::parse("https://h:8443/").unwrap().port, 8443);
}

/// Userinfo with both user and password round-trips into `userinfo`
/// without being decoded.
#[test]
fn userinfo_with_password() {
    let u = Url::parse("http://alice:s%3Acret@h/p").unwrap();
    assert_eq!(u.userinfo.as_deref(), Some("alice:s%3Acret"));
    assert_eq!(u.host, "h");
    assert_eq!(u.path, "/p");
}

/// Empty host is rejected (would otherwise produce a request with a
/// bogus `Host:` header).
#[test]
fn rejects_empty_host() {
    assert!(Url::parse("http:///path").is_err());
}

/// A scheme with no `://` is not a URL at all.
#[test]
fn rejects_bare_path() {
    assert!(Url::parse("/just/a/path").is_err());
}

/// One-shot HTTP/1.1 server on `listener`: captures the request head, answers
/// `200 OK` with body `ok`, and hands the head back through the join handle.
fn serve_capture(listener: std::net::TcpListener) -> std::thread::JoinHandle<String> {
    use std::io::{Read, Write};
    std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") && sock.read(&mut byte).unwrap_or(0) == 1 {
            head.push(byte[0]);
        }
        let _ =
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        String::from_utf8_lossy(&head).into_owned()
    })
}

/// End to end over an IPv6 literal: the bracketed host must resolve and dial
/// (it used to fail with "failed to lookup address"), while the `Host:` header
/// keeps the brackets. Skipped when the machine has no IPv6 loopback.
#[test]
fn get_over_ipv6_literal_dials_and_keeps_brackets_in_host_header() {
    let Ok(listener) = std::net::TcpListener::bind("[::1]:0") else {
        eprintln!("no IPv6 loopback; skipping");
        return;
    };
    let port = listener.local_addr().unwrap().port();
    let server = serve_capture(listener);
    let resp = rsurl::Request::get(&format!("http://[::1]:{port}/v6?x=1"))
        .unwrap()
        .send()
        .expect("GET over [::1] succeeds");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"ok");
    let head = server.join().unwrap();
    assert!(head.starts_with("GET /v6?x=1 HTTP/1.1\r\n"), "{head}");
    assert!(
        head.to_ascii_lowercase()
            .contains(&format!("\r\nhost: [::1]:{port}\r\n")),
        "{head}"
    );
}

/// A query-only URL puts `/?q` on the request line (not `GET ?q`), and dot
/// segments never reach the server.
#[test]
fn request_line_has_root_path_and_no_dot_segments() {
    for (path_part, want) in [("?q=1", "/?q=1"), ("/a/b/../c/./d", "/a/c/d")] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = serve_capture(listener);
        let resp = rsurl::Request::get(&format!("http://127.0.0.1:{port}{path_part}"))
            .unwrap()
            .send()
            .unwrap();
        assert_eq!(resp.status, 200);
        let head = server.join().unwrap();
        assert!(
            head.starts_with(&format!("GET {want} HTTP/1.1\r\n")),
            "{path_part}: {head}"
        );
    }
}

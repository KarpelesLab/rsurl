//! Multi-interface C smoke test: two concurrent GETs via `curl_multi_*` against
//! a small in-process server that serves multiple connections. Skips if no C
//! compiler / the shared library isn't built.

#![cfg(unix)]

mod support;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

const BODY: &str = "multi-body";

/// HTTP/1.1 server that serves `BODY` on every connection (until the process
/// exits).
fn start_http() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    BODY.len(),
                    BODY
                );
                let _ = s.write_all(resp.as_bytes());
            });
        }
    });
    port
}

#[test]
fn multi_two_concurrent_gets() {
    let Some((exe, libdir)) = support::compile("tests/multi.c", "multi") else {
        return;
    };
    let port = start_http();
    let url = format!("http://127.0.0.1:{port}/x");
    let run = support::run(&exe, &libdir, &[&url, &url]);
    let stdout = String::from_utf8_lossy(&run.stdout);
    let stderr = String::from_utf8_lossy(&run.stderr);

    assert!(
        run.status.success(),
        "multi program failed: stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.contains("MULTI_OK done=2 c1=200 c2=200"),
        "unexpected multi result: {stdout:?}"
    );
    assert!(
        stdout.contains(&format!("b1={BODY}")) && stdout.contains(&format!("b2={BODY}")),
        "body mismatch: {stdout:?}"
    );
}

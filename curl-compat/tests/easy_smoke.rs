//! Easy-interface C smoke tests: real C programs built against the drop-in
//! (through `curl/curl.h`'s *variadic* prototypes) run transfers against a tiny
//! in-process server. Skips if no C compiler / the shared library isn't built.

#![cfg(unix)]

mod support;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

const BODY: &str = "hello from server";

/// One-shot HTTP/1.1 server: serves `BODY` once, then exits.
fn start_http() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf); // consume the request head; we don't parse it
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                BODY.len(),
                BODY
            );
            let _ = s.write_all(resp.as_bytes());
        }
    });
    port
}

/// Echo server: every request is answered with a body describing it —
/// `M=<method> R=<Range header> L=<body length>` —
/// so the C program can check what actually went on the wire.
fn start_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            thread::spawn(move || {
                let mut req = Vec::new();
                let mut buf = [0u8; 4096];
                let head_end = loop {
                    let Ok(n) = s.read(&mut buf) else { return };
                    if n == 0 {
                        return;
                    }
                    req.extend_from_slice(&buf[..n]);
                    if let Some(p) = req.windows(4).position(|w| w == b"\r\n\r\n") {
                        break p + 4;
                    }
                };
                let head = String::from_utf8_lossy(&req[..head_end]).to_string();
                let header = |name: &str| {
                    head.lines()
                        .filter_map(|l| l.split_once(':'))
                        .find(|(k, _)| k.trim().eq_ignore_ascii_case(name))
                        .map(|(_, v)| v.trim().to_string())
                        .unwrap_or_else(|| "-".into())
                };
                let clen: usize = header("content-length").parse().unwrap_or(0);
                while req.len() < head_end + clen {
                    let Ok(n) = s.read(&mut buf) else { return };
                    if n == 0 {
                        break;
                    }
                    req.extend_from_slice(&buf[..n]);
                }
                let method = head.split(' ').next().unwrap_or("").to_string();
                let body = format!("M={method} R={} L={clen}", header("range"));
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes());
            });
        }
    });
    port
}

#[test]
fn easy_get_against_local_server() {
    let Some((exe, libdir)) = support::compile("tests/easy.c", "easy") else {
        return;
    };
    let port = start_http();
    let url = format!("http://127.0.0.1:{port}/hello");
    let run = support::run(&exe, &libdir, &[&url]);
    let stdout = String::from_utf8_lossy(&run.stdout);
    let stderr = String::from_utf8_lossy(&run.stderr);

    assert!(
        run.status.success(),
        "easy program failed: stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.contains("EASY_OK code=200"),
        "bad status line: {stdout:?}"
    );
    assert!(
        stdout.contains(&format!("body={BODY}")),
        "body mismatch: {stdout:?}"
    );
    assert!(
        stdout.contains("ct=text/plain"),
        "content-type missing: {stdout:?}"
    );
    assert!(
        stdout.contains(&format!("eu={url}")),
        "effective-url mismatch: {stdout:?}"
    );
}

/// Option semantics a libcurl program relies on: the default `fwrite` write
/// callback into a `WRITEDATA`/`HEADERDATA` `FILE*`, `CURLOPT_PRIVATE`
/// round-trip, `TIMEOUT 0` = no timeout, `HTTPGET` dropping an earlier POST
/// body, `RANGE` gaining its `bytes=` unit, and `HEADER_SIZE`. Every call goes
/// through the variadic prototypes, so on Apple arm64 this also exercises the
/// stack-slot trampolines.
#[test]
fn easy_option_semantics() {
    let Some((exe, libdir)) = support::compile("tests/options.c", "options") else {
        return;
    };
    let port = start_echo();
    let url = format!("http://127.0.0.1:{port}/o");
    let dir = std::env::temp_dir().join(format!("rsurl_curl_opts_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let body_path = dir.join("body.txt");
    let head_path = dir.join("head.txt");
    let run = support::run(
        &exe,
        &libdir,
        &[
            &url,
            body_path.to_str().unwrap(),
            head_path.to_str().unwrap(),
        ],
    );
    let stdout = String::from_utf8_lossy(&run.stdout).to_string();
    let stderr = String::from_utf8_lossy(&run.stderr);
    let body = std::fs::read_to_string(&body_path).unwrap_or_default();
    let head = std::fs::read_to_string(&head_path).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        run.status.success(),
        "options program failed: stdout={stdout:?} stderr={stderr:?}"
    );
    // WRITEDATA FILE* without a WRITEFUNCTION: body lands in the file, not stdout.
    assert_eq!(
        body, "M=GET R=- L=0",
        "body file: {body:?} stdout={stdout:?}"
    );
    assert!(
        !stdout.lines().any(|l| l.starts_with("M=")),
        "body leaked to stdout: {stdout:?}"
    );
    // HEADERDATA FILE* without a HEADERFUNCTION: headers land in their file.
    assert!(
        head.starts_with("HTTP/1.1 200") && head.contains("Content-Type: text/plain\r\n"),
        "header file: {head:?}"
    );
    for want in [
        "private=ok",
        "timeout0=0",
        "httpget=M=GET R=- L=0",
        "range=M=GET R=bytes=0-3 L=0",
        "post=M=POST R=- L=5",
        "header_size_ok=1",
        "unknown_opt=48",
    ] {
        assert!(stdout.contains(want), "missing {want:?} in {stdout:?}");
    }
}

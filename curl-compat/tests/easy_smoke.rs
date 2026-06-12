//! Easy-interface C smoke test: a real C program built against the drop-in
//! does an HTTP GET (with a write callback, custom header, follow-location)
//! against a tiny in-process server, then reads response info. Skips if no C
//! compiler / the shared library isn't built.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;

const BODY: &str = "hello from server";

fn find_cc() -> Option<&'static str> {
    ["cc", "gcc", "clang"].into_iter().find(|cc| {
        Command::new(cc)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

fn libdir_with_so() -> Option<PathBuf> {
    let base = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("target")
        });
    ["debug", "release"]
        .into_iter()
        .map(|p| base.join(p))
        .find(|d| d.join("libcurl.so").exists())
}

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

#[test]
fn easy_get_against_local_server() {
    let Some(cc) = find_cc() else {
        eprintln!("skipping easy_smoke: no C compiler");
        return;
    };
    let Some(libdir) = libdir_with_so() else {
        eprintln!("skipping easy_smoke: libcurl.so not built — run `cargo build -p curl-compat`");
        return;
    };
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let so4 = libdir.join("libcurl.so.4");
    if !so4.exists() {
        let _ = std::os::unix::fs::symlink(Path::new("libcurl.so"), &so4);
    }

    let exe = std::env::temp_dir().join(format!("rsurl_curl_easy_{}", std::process::id()));
    let compile = Command::new(cc)
        .arg(manifest.join("tests/easy.c"))
        .arg("-I")
        .arg(manifest.join("include"))
        .arg("-L")
        .arg(&libdir)
        .arg("-lcurl")
        .arg("-o")
        .arg(&exe)
        .output()
        .expect("cc");
    assert!(
        compile.status.success(),
        "compile failed:\n{}",
        String::from_utf8_lossy(&compile.stderr)
    );

    let port = start_http();
    let url = format!("http://127.0.0.1:{port}/hello");
    let run = Command::new(&exe)
        .arg(&url)
        .env("LD_LIBRARY_PATH", &libdir)
        .output()
        .expect("run easy");
    let _ = std::fs::remove_file(&exe);
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

//! Multi-interface C smoke test: two concurrent GETs via `curl_multi_*` against
//! a small in-process server that serves multiple connections. Skips if no C
//! compiler / the shared library isn't built.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;

const BODY: &str = "multi-body";

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
    let Some(cc) = find_cc() else {
        eprintln!("skipping multi_smoke: no C compiler");
        return;
    };
    let Some(libdir) = libdir_with_so() else {
        eprintln!("skipping multi_smoke: libcurl.so not built — run `cargo build -p curl-compat`");
        return;
    };
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let so4 = libdir.join("libcurl.so.4");
    if !so4.exists() {
        let _ = std::os::unix::fs::symlink(Path::new("libcurl.so"), &so4);
    }

    let exe = std::env::temp_dir().join(format!("rsurl_curl_multi_{}", std::process::id()));
    let compile = Command::new(cc)
        .arg(manifest.join("tests/multi.c"))
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
    let url = format!("http://127.0.0.1:{port}/x");
    let run = Command::new(&exe)
        .arg(&url)
        .arg(&url)
        .env("LD_LIBRARY_PATH", &libdir)
        .output()
        .expect("run multi");
    let _ = std::fs::remove_file(&exe);
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

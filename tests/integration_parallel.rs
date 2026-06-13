//! End-to-end test for `--parallel-segments`: the `rsurl` binary downloads a
//! single file over several concurrent HTTP range requests and reassembles it
//! correctly. A small in-process server supports HEAD (Content-Length +
//! Accept-Ranges) and ranged GET (206), and counts the range requests it
//! serves so the test can confirm the download was actually segmented.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

/// 4 MiB of a deterministic pattern.
fn payload() -> Vec<u8> {
    (0..4 * 1024 * 1024).map(|i| (i % 251) as u8).collect()
}

struct Server {
    port: u16,
    range_gets: Arc<AtomicUsize>,
    accept_ranges: bool,
}

/// Spawn a server. When `accept_ranges` is false it advertises no range support
/// (and ignores Range), so the client must fall back to a single stream.
fn start(accept_ranges: bool) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let body = Arc::new(payload());
    let range_gets = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&range_gets);

    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let body = Arc::clone(&body);
            let counter = Arc::clone(&counter);
            thread::spawn(move || {
                // Read request head.
                let mut buf = Vec::new();
                let mut tmp = [0u8; 1024];
                loop {
                    let n = match s.read(&mut tmp) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                    if buf.len() > 64 * 1024 {
                        return;
                    }
                }
                let head = String::from_utf8_lossy(&buf);
                let method = head.split_whitespace().next().unwrap_or("");
                let range = head.lines().find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    if k.eq_ignore_ascii_case("range") {
                        Some(v.trim().to_string())
                    } else {
                        None
                    }
                });
                let total = body.len();

                if method == "HEAD" {
                    let ar = if accept_ranges {
                        "Accept-Ranges: bytes\r\n"
                    } else {
                        ""
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {total}\r\n{ar}Connection: close\r\n\r\n"
                    );
                    let _ = s.write_all(resp.as_bytes());
                    return;
                }

                // GET
                if accept_ranges {
                    if let Some(r) = range.as_deref().and_then(|r| r.strip_prefix("bytes=")) {
                        if let Some((a, b)) = r.split_once('-') {
                            let a: usize = a.parse().unwrap_or(0);
                            let b: usize = b.parse().unwrap_or(total - 1);
                            let b = b.min(total - 1);
                            counter.fetch_add(1, Ordering::SeqCst);
                            let slice = &body[a..=b];
                            let hdr = format!(
                                "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {a}-{b}/{total}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                slice.len()
                            );
                            let _ = s.write_all(hdr.as_bytes());
                            let _ = s.write_all(slice);
                            return;
                        }
                    }
                }
                // Full body (no range / ranges unsupported).
                let hdr = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {total}\r\nConnection: close\r\n\r\n"
                );
                let _ = s.write_all(hdr.as_bytes());
                let _ = s.write_all(&body);
            });
        }
    });

    Server {
        port,
        range_gets,
        accept_ranges,
    }
}

static OUT_SEQ: AtomicUsize = AtomicUsize::new(0);

fn run_download(url: &str, segments: u32) -> (Vec<u8>, bool) {
    let bin = env!("CARGO_BIN_EXE_rsurl");
    // Unique per call so concurrently-run tests don't collide on the path.
    let uniq = OUT_SEQ.fetch_add(1, Ordering::SeqCst);
    let out = std::env::temp_dir().join(format!(
        "rsurl_par_{}_{}_{}",
        std::process::id(),
        segments,
        uniq
    ));
    let status = Command::new(bin)
        .arg("--parallel-segments")
        .arg(segments.to_string())
        .arg("-o")
        .arg(&out)
        .arg(url)
        .status()
        .expect("spawn rsurl");
    let data = std::fs::read(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    (data, status.success())
}

#[test]
fn parallel_segments_reassembles_file() {
    let server = start(true);
    let url = format!("http://127.0.0.1:{}/big", server.port);
    let (data, ok) = run_download(&url, 4);
    assert!(ok, "rsurl exited non-zero");
    assert_eq!(data, payload(), "downloaded file does not match");
    // It actually used multiple range requests (not a single stream).
    assert!(
        server.range_gets.load(Ordering::SeqCst) >= 2,
        "expected >=2 range GETs, saw {}",
        server.range_gets.load(Ordering::SeqCst)
    );
}

#[test]
fn falls_back_to_single_stream_without_range_support() {
    let server = start(false);
    let url = format!("http://127.0.0.1:{}/big", server.port);
    let (data, ok) = run_download(&url, 4);
    assert!(ok, "rsurl exited non-zero");
    assert_eq!(data, payload(), "fallback download does not match");
    assert!(!server.accept_ranges);
    assert_eq!(
        server.range_gets.load(Ordering::SeqCst),
        0,
        "no range GETs expected on the fallback path"
    );
}

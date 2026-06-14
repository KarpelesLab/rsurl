//! End-to-end tests for HTTP resume (`-C -`): the `rsurl` binary continues a
//! partially-downloaded `<name>.rsurlpart` via a Range request and finalises it
//! on completion. A small in-process server supports HEAD (Content-Length +
//! Accept-Ranges + ETag) and ranged GET (206), recording the range starts it
//! sees so the test can confirm the download actually resumed.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

const ETAG: &str = "\"v1-test\"";

fn payload() -> Vec<u8> {
    (0..200_000u32)
        .map(|i| (i.wrapping_mul(7) % 251) as u8)
        .collect()
}

struct Server {
    port: u16,
    /// Starting offsets of every ranged GET served.
    range_starts: Arc<Mutex<Vec<u64>>>,
}

/// Spawn an HTTP server. With `accept_ranges == false` it advertises no range
/// support and always returns the full body, forcing the client to fall back.
fn start(accept_ranges: bool) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let body = Arc::new(payload());
    let range_starts = Arc::new(Mutex::new(Vec::new()));
    let starts = Arc::clone(&range_starts);

    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let body = Arc::clone(&body);
            let starts = Arc::clone(&starts);
            thread::spawn(move || {
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
                    k.eq_ignore_ascii_case("range")
                        .then(|| v.trim().to_string())
                });
                let total = body.len();

                if method == "HEAD" {
                    let ar = if accept_ranges {
                        "Accept-Ranges: bytes\r\n"
                    } else {
                        ""
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {total}\r\nETag: {ETAG}\r\n{ar}Connection: close\r\n\r\n"
                    );
                    let _ = s.write_all(resp.as_bytes());
                    return;
                }

                if accept_ranges {
                    if let Some(r) = range.as_deref().and_then(|r| r.strip_prefix("bytes=")) {
                        if let Some((a, b)) = r.split_once('-') {
                            let a: usize = a.parse().unwrap_or(0);
                            let b: usize = b.parse().unwrap_or(total - 1);
                            let b = b.min(total - 1);
                            starts.lock().unwrap().push(a as u64);
                            let slice = &body[a..=b];
                            let hdr = format!(
                                "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {a}-{b}/{total}\r\nContent-Length: {}\r\nETag: {ETAG}\r\nConnection: close\r\n\r\n",
                                slice.len()
                            );
                            let _ = s.write_all(hdr.as_bytes());
                            let _ = s.write_all(slice);
                            return;
                        }
                    }
                }
                let hdr = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {total}\r\nETag: {ETAG}\r\nConnection: close\r\n\r\n"
                );
                let _ = s.write_all(hdr.as_bytes());
                let _ = s.write_all(&body);
            });
        }
    });

    Server { port, range_starts }
}

static SEQ: AtomicUsize = AtomicUsize::new(0);

fn out_path() -> std::path::PathBuf {
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!("rsurl_resume_it_{}_{}.bin", std::process::id(), n))
}

/// Encode the rsurl `http-stream` resume meta block (must match the binary's
/// layout): `[total:u64][done:u64]` then length-prefixed url/etag/last-modified.
fn http_meta(total: u64, done: u64, url: &str, etag: &str, last_mod: &str) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&total.to_le_bytes());
    m.extend_from_slice(&done.to_le_bytes());
    for s in [url, etag, last_mod] {
        let b = s.as_bytes();
        m.extend_from_slice(&(b.len() as u16).to_le_bytes());
        m.extend_from_slice(b);
    }
    m
}

#[test]
fn resume_continues_from_partial() {
    let data = payload();
    let srv = start(true);
    let url = format!("http://127.0.0.1:{}/file", srv.port);

    let out = out_path();
    let part = std::path::PathBuf::from(format!("{}.rsurlpart", out.display()));
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&part);

    // Pre-seed the first half into the .rsurlpart with a valid resume trailer.
    let half = (data.len() / 2) as u64;
    std::fs::write(&part, &data[..half as usize]).unwrap();
    let meta = http_meta(data.len() as u64, half, &url, ETAG, "");
    rsurl::resume::write_state(
        &part,
        data.len() as u64,
        rsurl::resume::Kind::HttpStream,
        &meta,
    )
    .unwrap();

    let status = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .arg("-C")
        .arg("-")
        .arg("-s")
        .arg("-o")
        .arg(&out)
        .arg(&url)
        .status()
        .expect("spawn rsurl");
    assert!(status.success(), "rsurl exit: {status}");

    assert_eq!(std::fs::read(&out).unwrap(), data, "resumed file mismatch");
    assert!(!part.exists(), ".rsurlpart should be finalized away");
    // The single ranged GET must have started at the resume offset, proving it
    // continued rather than restarting.
    let starts = srv.range_starts.lock().unwrap();
    assert_eq!(&*starts, &[half], "expected one ranged GET from the offset");

    let _ = std::fs::remove_file(&out);
}

#[test]
fn fresh_resume_download_completes() {
    let data = payload();
    let srv = start(true);
    let url = format!("http://127.0.0.1:{}/file", srv.port);
    let out = out_path();
    let part = std::path::PathBuf::from(format!("{}.rsurlpart", out.display()));
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&part);

    // No prior partial: -C - still downloads cleanly and finalizes.
    let status = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .arg("-C")
        .arg("-")
        .arg("-s")
        .arg("-o")
        .arg(&out)
        .arg(&url)
        .status()
        .expect("spawn rsurl");
    assert!(status.success(), "rsurl exit: {status}");
    assert_eq!(std::fs::read(&out).unwrap(), data);
    assert!(!part.exists());
    let _ = std::fs::remove_file(&out);
}

#[test]
fn no_range_support_falls_back_to_plain_download() {
    let data = payload();
    let srv = start(false); // server advertises no Accept-Ranges
    let url = format!("http://127.0.0.1:{}/file", srv.port);
    let out = out_path();
    let part = std::path::PathBuf::from(format!("{}.rsurlpart", out.display()));
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&part);

    let status = Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .arg("-C")
        .arg("-")
        .arg("-s")
        .arg("-o")
        .arg(&out)
        .arg(&url)
        .status()
        .expect("spawn rsurl");
    assert!(status.success(), "rsurl exit: {status}");
    // Falls back to a normal in-place download (no .rsurlpart involved).
    assert_eq!(std::fs::read(&out).unwrap(), data);
    assert!(srv.range_starts.lock().unwrap().is_empty());
    let _ = std::fs::remove_file(&out);
}

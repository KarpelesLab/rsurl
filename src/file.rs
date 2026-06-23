//! `file://` URL support (RFC 8089, formerly RFC 1738).
//!
//! `file:///etc/hosts` reads the local file at `/etc/hosts`. Hosts other
//! than the empty string or `localhost` are rejected per RFC 8089 §2.

use std::fs;
use std::path::Path;

use crate::error::{Error, Result};
use crate::url::Url;

/// Read the file at `url.path` and return its contents.
pub fn fetch(url: &Url) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    fetch_to(url, &mut buf)?;
    Ok(buf)
}

/// Stream the file at `url.path` to `sink`, returning the byte count. Avoids
/// buffering a large local file in memory (the streaming core of [`fetch`]).
pub(crate) fn fetch_to(url: &Url, sink: &mut dyn std::io::Write) -> Result<u64> {
    // RFC 8089 §2: only empty host or "localhost" refer to the local machine.
    if !url.host.is_empty() && !url.host.eq_ignore_ascii_case("localhost") {
        return Err(Error::BadResponse(format!(
            "file:// URLs with non-local host are not supported: {}",
            url.host
        )));
    }

    let path = Path::new(&url.path);

    // Require a regular file. `fs::metadata` follows symlinks, so this also
    // covers a symlink pointing at a directory, FIFO, or device. Rejecting
    // non-regular files closes an unbounded read on e.g. /dev/zero or a FIFO,
    // which would otherwise stream forever into `sink` (there's no size cap
    // here). Directories are reported with their original, clearer message.
    let meta = fs::metadata(path)?;
    if meta.is_dir() {
        return Err(Error::BadResponse(format!(
            "path is a directory, not a file: {}",
            url.path
        )));
    }
    if !meta.is_file() {
        return Err(Error::BadResponse(format!(
            "path is not a regular file: {}",
            url.path
        )));
    }

    let mut f = fs::File::open(path)?;
    Ok(std::io::copy(&mut f, sink)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Build a unique scratch path under the OS temp dir without bringing in
    /// the `tempfile` crate.
    fn unique_temp_path(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        std::env::temp_dir().join(format!("rsurl-file-{label}-{pid}-{nanos}-{n}"))
    }

    fn url_for(path: &str, host: &str) -> Url {
        Url {
            scheme: "file".into(),
            userinfo: None,
            host: host.into(),
            port: 0,
            path: path.into(),
        }
    }

    #[test]
    fn reads_existing_file() {
        let p = unique_temp_path("read");
        let payload = b"hello, file://!\n\x00binary\xffbytes";
        {
            let mut f = fs::File::create(&p).expect("create temp file");
            f.write_all(payload).expect("write payload");
        }

        let url = url_for(p.to_str().expect("utf-8 temp path"), "");
        let got = fetch(&url).expect("fetch should succeed");
        assert_eq!(got, payload);

        // localhost host should also work.
        let url_local = url_for(p.to_str().unwrap(), "localhost");
        let got_local = fetch(&url_local).expect("localhost should be accepted");
        assert_eq!(got_local, payload);

        // LOCALHOST (case-insensitive) should also work.
        let url_caps = url_for(p.to_str().unwrap(), "LocalHost");
        let got_caps = fetch(&url_caps).expect("case-insensitive localhost");
        assert_eq!(got_caps, payload);

        let _ = fs::remove_file(&p);
    }

    #[test]
    fn rejects_non_local_host() {
        let url = url_for("/etc/hosts", "example.com");
        match fetch(&url) {
            Err(Error::BadResponse(msg)) => {
                assert!(msg.contains("example.com"), "msg = {msg}");
            }
            other => panic!("expected BadResponse, got {other:?}"),
        }
    }

    #[test]
    fn missing_file_returns_io_error() {
        let p = unique_temp_path("missing");
        assert!(!p.exists(), "test setup: path should not exist");
        let url = url_for(p.to_str().unwrap(), "");
        match fetch(&url) {
            Err(Error::Io(_)) => {}
            other => panic!("expected Io error, got {other:?}"),
        }
    }

    /// A non-regular file (here the character device /dev/zero) must be
    /// rejected rather than streamed unbounded into the sink.
    #[cfg(unix)]
    #[test]
    fn non_regular_file_is_rejected() {
        let url = url_for("/dev/zero", "");
        match fetch(&url) {
            Err(Error::BadResponse(msg)) => {
                assert!(msg.contains("not a regular file"), "msg = {msg}");
            }
            other => panic!("expected BadResponse, got {other:?}"),
        }
    }

    #[test]
    fn directory_path_is_rejected() {
        let dir = unique_temp_path("dir");
        fs::create_dir(&dir).expect("create dir");
        let url = url_for(dir.to_str().unwrap(), "");
        let res = fetch(&url);
        let _ = fs::remove_dir(&dir);
        match res {
            Err(Error::BadResponse(msg)) => {
                assert!(msg.contains("directory"), "msg = {msg}");
            }
            other => panic!("expected BadResponse, got {other:?}"),
        }
    }
}

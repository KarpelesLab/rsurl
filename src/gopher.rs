//! Gopher and Gopher-over-TLS support (RFC 1436 + the TLS extension).
//!
//! Gopher URLs are `gopher://host[:70]/<type><selector>` where `<type>` is a
//! single character item type (e.g. `1` directory, `0` text file). For TLS
//! use [`crate::tls::connect_over`].
//!
//! Gopher has no length framing: the server writes the response and then
//! closes the connection, so the client reads to EOF.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::url::Url;

/// I/O timeout for the Gopher control connection. Gopher has no length
/// framing, so a stalled server could otherwise hang the read forever;
/// match the generous timeouts used by `dict.rs`/`rtsp.rs`.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Upper bound on a Gopher response. Gopher signals end-of-response by
/// closing the connection, with no length header, so without a cap a
/// hostile or runaway server could stream unbounded data into memory.
/// 64 MiB matches the body caps elsewhere in the crate (see `rtsp.rs`).
const MAX_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;

/// Send the selector from `url.path` and read the server's response until
/// the connection is closed (gopher has no length framing).
pub fn fetch(url: &Url) -> Result<Vec<u8>> {
    let selector = selector_from_path(&url.path)?;

    let addr = format!("{}:{}", url.host, url.port);
    let tcp = TcpStream::connect(&addr)?;
    tcp.set_read_timeout(Some(IO_TIMEOUT))?;
    tcp.set_write_timeout(Some(IO_TIMEOUT))?;

    let mut request = Vec::with_capacity(selector.len() + 2);
    request.extend_from_slice(selector.as_bytes());
    request.extend_from_slice(b"\r\n");

    if url.is_tls() {
        let mut tls = crate::tls::connect_over(tcp, &url.host)?;
        tls.write_all(&request)?;
        tls.flush()?;
        read_capped(&mut tls)
    } else {
        let mut sock = tcp;
        sock.write_all(&request)?;
        sock.flush()?;
        read_capped(&mut sock)
    }
}

/// Read the response, refusing to buffer more than [`MAX_RESPONSE_BYTES`].
/// If the server tries to send more than the cap, the excess is treated as
/// a protocol error rather than silently truncated or buffered unbounded.
fn read_capped<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    // `take` caps at exactly MAX_RESPONSE_BYTES; read one extra byte's worth
    // of headroom so we can distinguish "exactly at the cap" from "over it".
    let n = reader.take(MAX_RESPONSE_BYTES + 1).read_to_end(&mut buf)?;
    if n as u64 > MAX_RESPONSE_BYTES {
        return Err(Error::BadResponse(format!(
            "gopher: response exceeds {MAX_RESPONSE_BYTES} bytes"
        )));
    }
    Ok(buf)
}

/// Extract the wire selector from a Gopher URL path.
///
/// A Gopher URL path is `/<itemtype><selector>` where `<itemtype>` is a single
/// byte and the selector is everything after it. The item-type byte is *not*
/// part of the wire selector; it's only a hint to the client about how to
/// render the response.
///
/// * `""` or `"/"` → empty selector (root menu, defaults to type `1`).
/// * `"/1"` → empty selector (root menu, explicit directory type).
/// * `"/0foo"` → `"foo"` (text file selector).
/// * `"/1docs/index"` → `"docs/index"` (directory selector).
///
/// The selector is written verbatim into a `\r\n`-terminated request line,
/// so a raw CR, LF, NUL, or other control byte in the URL would let an
/// attacker inject a second request or otherwise corrupt the wire framing.
/// Such selectors are rejected with [`Error::InvalidUrl`].
fn selector_from_path(path: &str) -> Result<&str> {
    // Strip leading slash if present.
    let without_slash = path.strip_prefix('/').unwrap_or(path);
    // Drop the item-type byte (first char), if any.
    let mut chars = without_slash.chars();
    let selector = match chars.next() {
        Some(_) => chars.as_str(),
        None => "",
    };
    if selector.bytes().any(|b| b.is_ascii_control()) {
        return Err(Error::InvalidUrl(format!(
            "gopher: control byte in selector of path '{path}'"
        )));
    }
    Ok(selector)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_root_slash() {
        assert_eq!(selector_from_path("/").unwrap(), "");
    }

    #[test]
    fn selector_empty() {
        assert_eq!(selector_from_path("").unwrap(), "");
    }

    #[test]
    fn selector_just_item_type() {
        assert_eq!(selector_from_path("/1").unwrap(), "");
    }

    #[test]
    fn selector_text_file() {
        assert_eq!(selector_from_path("/0foo").unwrap(), "foo");
    }

    #[test]
    fn selector_directory_with_subpath() {
        assert_eq!(selector_from_path("/1docs/index").unwrap(), "docs/index");
    }

    #[test]
    fn selector_rejects_crlf_injection() {
        // A raw CR/LF in the selector would inject a second request line.
        assert!(selector_from_path("/0foo\r\nbar").is_err());
        assert!(selector_from_path("/0foo\nbar").is_err());
        assert!(selector_from_path("/0foo\rbar").is_err());
    }

    #[test]
    fn selector_rejects_nul_and_control_bytes() {
        assert!(selector_from_path("/0foo\0bar").is_err());
        assert!(selector_from_path("/0foo\x07bar").is_err());
    }

    #[test]
    fn read_capped_accepts_response_at_limit() {
        let data = vec![b'x'; 1024];
        let mut cur = std::io::Cursor::new(data.clone());
        assert_eq!(read_capped(&mut cur).unwrap(), data);
    }

    #[test]
    fn read_capped_rejects_oversized_response() {
        // A reader that yields just over the cap must be refused, not buffered.
        let oversized = MAX_RESPONSE_BYTES as usize + 1;
        let mut cur = std::io::Cursor::new(vec![0u8; oversized]);
        let err = read_capped(&mut cur).unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)));
    }
}

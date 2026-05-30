//! Gopher and Gopher-over-TLS support (RFC 1436 + the TLS extension).
//!
//! Gopher URLs are `gopher://host[:70]/<type><selector>` where `<type>` is a
//! single character item type (e.g. `1` directory, `0` text file). For TLS
//! use [`crate::tls::connect_over`].
//!
//! Gopher has no length framing: the server writes the response and then
//! closes the connection, so the client reads to EOF.
//!
//! Item-type `7` (search) is supported: a query supplied as the URL's
//! `?<words>` component is appended to the selector with a TAB separator, so
//! `gopher://host/7<selector>?<words>` sends `<selector>\t<words>\r\n` on the
//! wire (RFC 1436 §3.4). This matches curl's behaviour of carrying the search
//! string in the URL. A literal TAB cannot reach here because the URL parser
//! rejects control bytes, so the `?<words>` convention is the supported one.

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

/// Build the wire selector line from a Gopher URL path.
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
/// # Item-type 7 (search)
///
/// For a search item the client sends `<selector>\t<search-words>` (RFC 1436
/// §3.4). curl carries the search words in the URL, so we treat the URL's
/// query component (everything after the first `?`) as the search words and
/// join them to the selector with a TAB:
///
/// * `"/7find?cats"` → `"find\tcats"`.
/// * `"/7?cats"` → `"\tcats"` (empty selector, just a query).
///
/// The split on `?` happens regardless of item type, so `?` is reserved as the
/// search separator for every Gopher URL. A non-search selector with no `?`
/// gets no trailing TAB. A literal TAB cannot reach here — the URL parser
/// rejects control bytes — so `?<words>` is the only supported convention.
///
/// The result is written verbatim into a `\r\n`-terminated request line, so a
/// raw CR, LF, NUL, or other control byte in the selector or search words
/// would let an attacker inject a second request or corrupt the wire framing.
/// The TAB we insert as the separator is allowed; any other control byte
/// (including a CR/LF/NUL inside the search words) is rejected with
/// [`Error::InvalidUrl`]. The item-type byte is not validated because it is
/// dropped before it can reach the wire.
fn selector_from_path(path: &str) -> Result<String> {
    // Strip leading slash if present.
    let without_slash = path.strip_prefix('/').unwrap_or(path);
    // Drop the item-type byte (first char), if any.
    let mut chars = without_slash.chars();
    let after_type = match chars.next() {
        Some(_) => chars.as_str(),
        None => "",
    };

    // Determine the selector and an optional search query.
    //
    // A `?` is the curl-style separator: everything after the first `?` is the
    // search words. As a fallback we also accept a selector that already
    // carries a literal TAB separator (`<selector>\t<words>`) — the TAB is then
    // the separator that is already in place. The `?` form takes precedence so
    // a `?` always wins when both are present.
    let (selector, query) = match after_type.split_once('?') {
        Some((sel, q)) => (sel, Some(q)),
        None => match after_type.split_once('\t') {
            Some((sel, q)) => (sel, Some(q)),
            None => (after_type, None),
        },
    };

    if selector.bytes().any(|b| b.is_ascii_control()) {
        return Err(Error::InvalidUrl(format!(
            "gopher: control byte in selector of path '{path}'"
        )));
    }

    match query {
        Some(q) => {
            // The query is joined back with a single TAB separator, so embedded
            // CR/LF/NUL/etc. would still corrupt framing or inject a second
            // request line — reject them. A further TAB inside the query is a
            // control byte and is likewise rejected; only the one separator TAB
            // we insert is permitted.
            if q.bytes().any(|b| b.is_ascii_control()) {
                return Err(Error::InvalidUrl(format!(
                    "gopher: control byte in search query of path '{path}'"
                )));
            }
            let mut line = String::with_capacity(selector.len() + 1 + q.len());
            line.push_str(selector);
            line.push('\t');
            line.push_str(q);
            Ok(line)
        }
        None => Ok(selector.to_string()),
    }
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
    fn search_type7_joins_selector_and_query_with_tab() {
        // The canonical curl convention: `/7<selector>?<words>` →
        // `<selector>\t<words>` on the wire.
        assert_eq!(selector_from_path("/7find?cats").unwrap(), "find\tcats");
    }

    #[test]
    fn search_query_with_empty_selector() {
        // `/7?cats` → empty selector, just `\tcats`.
        assert_eq!(selector_from_path("/7?cats").unwrap(), "\tcats");
    }

    #[test]
    fn search_query_works_for_any_item_type() {
        // The `?` separator is honoured regardless of item type.
        assert_eq!(selector_from_path("/1dir?term").unwrap(), "dir\tterm");
    }

    #[test]
    fn search_query_with_multiple_words() {
        // The query is taken verbatim (no percent-decoding), spaces and all are
        // already rejected by the URL parser, but `+`-joined words pass through.
        assert_eq!(
            selector_from_path("/7find?big+cats").unwrap(),
            "find\tbig+cats"
        );
    }

    #[test]
    fn non_search_selector_has_no_trailing_tab() {
        // A selector with no `?` must not gain a TAB.
        let line = selector_from_path("/0foo").unwrap();
        assert_eq!(line, "foo");
        assert!(!line.contains('\t'));
    }

    #[test]
    fn search_only_first_question_mark_is_the_separator() {
        // A second `?` is part of the query, not a new separator.
        assert_eq!(selector_from_path("/7a?b?c").unwrap(), "a\tb?c");
    }

    #[test]
    fn search_literal_tab_selector_still_works() {
        // A selector that already carries the TAB separator (`<sel>\t<words>`)
        // is preserved as a valid search line — the TAB is the separator.
        assert_eq!(selector_from_path("/7find\tcats").unwrap(), "find\tcats");
    }

    #[test]
    fn search_query_rejects_crlf_and_nul() {
        // Control bytes in the search words would inject a second request line
        // or corrupt framing just like in the selector.
        assert!(selector_from_path("/7find?a\r\nb").is_err());
        assert!(selector_from_path("/7find?a\nb").is_err());
        assert!(selector_from_path("/7find?a\rb").is_err());
        assert!(selector_from_path("/7find?a\0b").is_err());
    }

    #[test]
    fn search_query_rejects_embedded_tab() {
        // Only the separator TAB we insert is allowed; a TAB inside the query
        // is a control byte and is rejected.
        assert!(selector_from_path("/7find?a\tb").is_err());
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

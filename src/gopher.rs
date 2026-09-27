//! Gopher and Gopher-over-TLS support (RFC 1436 + the TLS extension).
//!
//! Gopher URLs are `gopher://host[:70]/<type><selector>` where `<type>` is a
//! single character item type (e.g. `1` directory, `0` text file). For TLS
//! use [`crate::tls::connect_over`].
//!
//! Gopher has no length framing: the server writes the response and then
//! closes the connection, so the client reads to EOF.
//!
//! The selector is percent-decoded, as curl does, so a search item is sent the
//! curl way as `gopher://host/7<selector>%09<words>` → `<selector>\t<words>`
//! (RFC 1436 §3.4). For item type `7` only, `?<words>` is accepted as a
//! convenient alternative; for every other type a `?` is an ordinary selector
//! character.

use std::io::{Read, Write};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::url::percent_decode;
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
    fetch_with(url, &crate::net::NetConfig::default())
}

pub(crate) fn fetch_with(url: &Url, cfg: &crate::net::NetConfig) -> Result<Vec<u8>> {
    let selector = selector_from_path(&url.path)?;

    let tcp = cfg.connect(&url.host, url.port)?;
    tcp.set_read_timeout(cfg.io_timeout())?;
    tcp.set_write_timeout(Some(IO_TIMEOUT))?;

    let mut request = Vec::with_capacity(selector.len() + 2);
    request.extend_from_slice(selector.as_bytes());
    request.extend_from_slice(b"\r\n");

    if url.is_tls() {
        let mut tls = cfg.tls_connect(tcp, &url.host)?;
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
/// render the response. The rest is percent-decoded, as curl does (RFC 4266
/// §2.1), so a search string can be sent the curl way as `%09<words>`.
///
/// * `""` or `"/"` → empty selector (root menu, defaults to type `1`).
/// * `"/1"` → empty selector (root menu, explicit directory type).
/// * `"/0foo"` → `"foo"` (text file selector).
/// * `"/1docs/my%20index"` → `"docs/my index"`.
/// * `"/0cgi?x=1"` → `"cgi?x=1"` (a `?` is part of an ordinary selector).
///
/// # Item-type 7 (search)
///
/// For a search item the client sends `<selector>\t<search-words>` (RFC 1436
/// §3.4). Besides curl's `%09` form, a type-7 URL may carry the words after
/// the first `?`, which is joined to the selector with a TAB:
///
/// * `"/7find?cats"` → `"find\tcats"`.
/// * `"/7find%09cats"` → `"find\tcats"`.
///
/// The result is written verbatim into a `\r\n`-terminated request line, so a
/// CR, LF, NUL, or other control byte — raw or percent-encoded — would let an
/// attacker inject a second request or corrupt the wire framing; those are
/// rejected with [`Error::InvalidUrl`]. TAB is the Gopher field separator and
/// is allowed.
fn selector_from_path(path: &str) -> Result<String> {
    // Strip leading slash if present.
    let without_slash = path.strip_prefix('/').unwrap_or(path);
    // Drop the item-type byte (first char), if any.
    let mut chars = without_slash.chars();
    let item_type = chars.next();
    let after_type = chars.as_str();

    let line = match (item_type, after_type.split_once('?')) {
        (Some('7'), Some((sel, words))) => {
            format!("{}\t{}", percent_decode(sel), percent_decode(words))
        }
        _ => percent_decode(after_type),
    };

    if line.bytes().any(|b| b.is_ascii_control() && b != b'\t') {
        return Err(Error::InvalidUrl(format!(
            "gopher: control byte in selector of path '{path}'"
        )));
    }
    Ok(line)
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
    fn question_mark_is_literal_outside_search_items() {
        // Only a type-7 search treats `?` as the words separator; elsewhere it
        // is part of the selector (CGI-style gopher selectors), as in curl.
        assert_eq!(selector_from_path("/1dir?term").unwrap(), "dir?term");
        assert_eq!(selector_from_path("/0cgi?x=1").unwrap(), "cgi?x=1");
    }

    #[test]
    fn selector_is_percent_decoded() {
        assert_eq!(selector_from_path("/0my%20file").unwrap(), "my file");
        // curl's search form: an encoded TAB separates selector and words.
        assert_eq!(selector_from_path("/7find%09cats").unwrap(), "find\tcats");
        // Encoded CR/LF/NUL are still rejected after decoding.
        assert!(selector_from_path("/0a%0d%0ab").is_err());
        assert!(selector_from_path("/0a%00").is_err());
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
    fn search_query_allows_further_tabs() {
        // TAB is Gopher's field separator (Gopher+ appends more fields); it
        // cannot break the CRLF framing, so it is allowed.
        assert_eq!(selector_from_path("/7find?a\tb").unwrap(), "find\ta\tb");
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

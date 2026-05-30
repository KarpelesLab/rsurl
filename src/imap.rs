//! IMAP and IMAPS support.
//!
//! Specs: RFC 9051 (IMAP4rev2), RFC 3501 (IMAP4rev1), RFC 8314 (implicit TLS
//! on port 993 for IMAPS), RFC 5092 (`imap:` URL scheme).
//!
//! IMAP URLs look like `imap://user@host/INBOX;UID=42` — the path/parameters
//! select a mailbox and optionally a single message to FETCH. For IMAPS,
//! wrap the TCP stream with [`crate::tls::connect_over`] before LOGIN.
//!
//! This is a deliberately small subset of the spec, enough to support the
//! "give me bytes" URL semantics curl exposes:
//!
//!   * `imap[s]://[user[:pass]@]host[:port]/`          → LIST "" "*"
//!   * `imap[s]://[user[:pass]@]host[:port]/MAILBOX`   → SELECT, FETCH 1:* (UID)
//!   * `imap[s]://[user[:pass]@]host[:port]/MAILBOX;UID=N` → SELECT, UID FETCH N BODY[]
//!
//! Deferred: STARTTLS, CAPABILITY-based feature switching, SASL/AUTHENTICATE,
//! IDLE, search/sort, message sets beyond a single UID, namespace handling,
//! literal+ on the client side, mailbox name encoding (UTF-7/UTF-8 quoted
//! string promotion), multi-line continuation requests.

use std::io::{self, Read, Write};
use std::net::TcpStream;

use crate::error::{Error, Result};
use crate::tls::{connect_over, TlsStream};
use crate::url::Url;

/// Upper bound on a single server-declared IMAP literal (`{N}`). The size is
/// chosen by the server, and `read_exact` would otherwise `Vec::with_capacity`
/// and read that many bytes — an unbounded allocation / DoS vector. 64 MiB
/// matches the crate's other body caps (e.g. `rtsp`, `websocket`).
const MAX_LITERAL_BYTES: usize = 64 * 1024 * 1024;

/// LOGIN (using userinfo or fall back to anonymous), SELECT the mailbox from
/// `url.path`, then either LIST mailboxes or FETCH a specific message and
/// return the raw RFC 5322 message bytes (or the LIST output).
pub fn fetch(url: &Url) -> Result<Vec<u8>> {
    match url.scheme.as_str() {
        "imap" => {
            let sock = TcpStream::connect((url.host.as_str(), url.port))?;
            run(PlainStream(sock), url)
        }
        "imaps" => {
            let sock = TcpStream::connect((url.host.as_str(), url.port))?;
            let tls = connect_over(sock, &url.host)?;
            run(TlsRw(tls), url)
        }
        other => Err(Error::UnsupportedScheme(other.to_string())),
    }
}

/// Tiny trait shim so we can write one `run<S: ImapIo>(...)` and use it for
/// both `TcpStream` and `TlsStream<TcpStream>` without dragging in a bunch of
/// trait-object machinery. Both are blocking `Read + Write`.
trait ImapIo: Read + Write {}

struct PlainStream(TcpStream);
impl Read for PlainStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}
impl Write for PlainStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
impl ImapIo for PlainStream {}

struct TlsRw(TlsStream<TcpStream>);
impl Read for TlsRw {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}
impl Write for TlsRw {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
impl ImapIo for TlsRw {}

fn run<S: ImapIo>(mut sock: S, url: &Url) -> Result<Vec<u8>> {
    let mut buf = LineReader::new();

    // Read the unsolicited greeting. Must start with `* OK`.
    let greeting = buf.read_response(&mut sock, "*")?;
    let first = greeting.lines().next().unwrap_or("");
    if !first.starts_with("* OK") && !first.starts_with("* PREAUTH") {
        return Err(Error::BadResponse(format!(
            "imap greeting was not OK: {first}"
        )));
    }

    let mut tagger = Tagger::new();

    // LOGIN, if we have credentials.
    if let Some(userinfo) = url.userinfo.as_deref() {
        let (user, pass) = split_userinfo(userinfo);
        let tag = tagger.next();
        let cmd = format!(
            "{tag} LOGIN {} {}\r\n",
            quote_imap_string(user),
            quote_imap_string(pass)
        );
        sock.write_all(cmd.as_bytes())?;
        sock.flush()?;
        let resp = buf.read_response(&mut sock, &tag)?;
        require_ok(&resp, &tag, "LOGIN")?;
    }

    let (mailbox, uid) = parse_path(&url.path);

    let body = match (mailbox.as_deref(), uid) {
        // Plain `/` (or empty) and no UID: list mailboxes.
        (None, None) => {
            let tag = tagger.next();
            let cmd = format!("{tag} LIST \"\" \"*\"\r\n");
            sock.write_all(cmd.as_bytes())?;
            sock.flush()?;
            let resp = buf.read_response(&mut sock, &tag)?;
            require_ok(&resp, &tag, "LIST")?;
            collect_untagged(&resp, "LIST").into_bytes()
        }

        // Mailbox, no UID: SELECT and dump UIDs of every message.
        (Some(mbox), None) => {
            select_mailbox(&mut sock, &mut buf, &mut tagger, mbox)?;
            let tag = tagger.next();
            let cmd = format!("{tag} FETCH 1:* (UID)\r\n");
            sock.write_all(cmd.as_bytes())?;
            sock.flush()?;
            let resp = buf.read_response(&mut sock, &tag)?;
            require_ok(&resp, &tag, "FETCH")?;
            collect_untagged(&resp, "FETCH").into_bytes()
        }

        // Mailbox + UID: pull just that message body.
        (Some(mbox), Some(n)) => {
            select_mailbox(&mut sock, &mut buf, &mut tagger, mbox)?;
            let tag = tagger.next();
            let cmd = format!("{tag} UID FETCH {n} BODY[]\r\n");
            sock.write_all(cmd.as_bytes())?;
            sock.flush()?;
            let (resp, literals) = buf.read_response_with_literals(&mut sock, &tag)?;
            require_ok(&resp, &tag, "UID FETCH")?;
            // Per RFC 5092, the URL targets a single message: return that
            // message's literal verbatim, or empty bytes if the server gave
            // us nothing back (UID didn't exist).
            literals.into_iter().next().unwrap_or_default()
        }

        // Path of the form `/;UID=N` (no mailbox). RFC 5092 doesn't really
        // allow this — fall through to "list mailboxes" as a safe default.
        (None, Some(_)) => {
            let tag = tagger.next();
            let cmd = format!("{tag} LIST \"\" \"*\"\r\n");
            sock.write_all(cmd.as_bytes())?;
            sock.flush()?;
            let resp = buf.read_response(&mut sock, &tag)?;
            require_ok(&resp, &tag, "LIST")?;
            collect_untagged(&resp, "LIST").into_bytes()
        }
    };

    // Be polite — LOGOUT and ignore any error (we already have the bytes).
    let tag = tagger.next();
    let _ = sock.write_all(format!("{tag} LOGOUT\r\n").as_bytes());
    let _ = sock.flush();
    // Best-effort drain; a server may or may not reply before tearing down.
    let _ = buf.read_response(&mut sock, &tag);

    Ok(body)
}

fn select_mailbox<S: ImapIo>(
    sock: &mut S,
    buf: &mut LineReader,
    tagger: &mut Tagger,
    mbox: &str,
) -> Result<()> {
    let tag = tagger.next();
    let cmd = format!("{tag} SELECT {}\r\n", quote_imap_string(mbox));
    sock.write_all(cmd.as_bytes())?;
    sock.flush()?;
    let resp = buf.read_response(sock, &tag)?;
    require_ok(&resp, &tag, "SELECT")
}

fn require_ok(resp: &str, tag: &str, what: &str) -> Result<()> {
    // The tagged response is the last non-empty line. Status word follows the tag.
    let last = resp.lines().rev().find(|l| !l.is_empty()).unwrap_or("");
    let rest = last.strip_prefix(tag).unwrap_or("").trim_start();
    let status = rest.split_whitespace().next().unwrap_or("");
    if status.eq_ignore_ascii_case("OK") {
        Ok(())
    } else {
        Err(Error::BadResponse(format!("imap {what} failed: {last}")))
    }
}

/// Return every untagged response line whose data item matches `kind`
/// (`LIST`, `FETCH`, ...) joined with `\r\n`. The lines are returned verbatim
/// (including the leading `* `).
fn collect_untagged(resp: &str, kind: &str) -> String {
    let mut out = String::new();
    for line in resp.lines() {
        if let Some(rest) = line.strip_prefix("* ") {
            // The first whitespace-separated word after `* ` is either a
            // number (for FETCH/EXPUNGE/EXISTS/...) or the response code
            // itself (for LIST/LSUB/STATUS/...). Look at the next token too.
            let mut toks = rest.split_whitespace();
            let first = toks.next().unwrap_or("");
            let second = toks.next().unwrap_or("");
            if first.eq_ignore_ascii_case(kind) || second.eq_ignore_ascii_case(kind) {
                out.push_str(line);
                out.push_str("\r\n");
            }
        }
    }
    out
}

/// Quote an IMAP "string" per RFC 3501 §4.3 — wrap in double quotes and
/// backslash-escape any `\` or `"` already in it. For arbitrary bytes IMAP
/// would want a literal `{n}\r\n...`, but for user/pass and mailbox names
/// (which we expect to be 7-bit ASCII text) a quoted string is fine and a lot
/// simpler.
fn quote_imap_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        if c == '\\' || c == '"' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// Split `user[:pass]` into `(user, pass)`. Missing password is empty string.
fn split_userinfo(s: &str) -> (&str, &str) {
    match s.find(':') {
        Some(i) => (&s[..i], &s[i + 1..]),
        None => (s, ""),
    }
}

/// Parse the IMAP URL path (RFC 5092 subset) into `(mailbox, uid)`.
///
/// Accepts:
///   * `""` or `"/"`                  → `(None, None)`
///   * `"/INBOX"`                     → `(Some("INBOX"), None)`
///   * `"/INBOX;UID=42"`              → `(Some("INBOX"), Some(42))`
///   * `"/Stuff/Sub;UID=7"`           → `(Some("Stuff/Sub"), Some(7))`
fn parse_path(path: &str) -> (Option<String>, Option<u32>) {
    let trimmed = path.strip_prefix('/').unwrap_or(path);
    if trimmed.is_empty() {
        return (None, None);
    }
    // Pull off the first `;`-delimited parameter that matches `UID=<n>`.
    let (mbox_part, params) = match trimmed.find(';') {
        Some(i) => (&trimmed[..i], &trimmed[i + 1..]),
        None => (trimmed, ""),
    };
    let mut uid = None;
    for param in params.split(';') {
        if let Some(v) = param
            .strip_prefix("UID=")
            .or_else(|| param.strip_prefix("uid="))
        {
            if let Ok(n) = v.parse::<u32>() {
                uid = Some(n);
            }
        }
    }
    let mbox = if mbox_part.is_empty() {
        None
    } else {
        Some(percent_decode(mbox_part))
    };
    (mbox, uid)
}

/// Minimal percent-decoder for mailbox names in URL paths. Invalid escapes
/// pass through unchanged — IMAP URL escaping is the producer's job.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|e| {
        // Fall back to lossy UTF-8 if the decoded bytes aren't valid UTF-8.
        String::from_utf8_lossy(&e.into_bytes()).into_owned()
    })
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + b - b'a'),
        b'A'..=b'F' => Some(10 + b - b'A'),
        _ => None,
    }
}

/// If `line` ends in an IMAP literal length specifier (`{<n>}` right before
/// the trailing CRLF), return `n`. Whitespace inside the braces is rejected.
fn extract_literal_size(line: &str) -> Option<usize> {
    // RFC 3501: the literal octet count is always the last token on the line.
    // We allow an optional `+` (literal8 / RFC 7888 LITERAL+) just in case.
    let trimmed = line.trim_end_matches(['\r', '\n']);
    let trimmed = trimmed.trim_end();
    let rest = trimmed.strip_suffix('}')?;
    let open = rest.rfind('{')?;
    let inside = &rest[open + 1..];
    let inside = inside.strip_suffix('+').unwrap_or(inside);
    if inside.is_empty() || inside.chars().any(|c| !c.is_ascii_digit()) {
        return None;
    }
    inside.parse().ok()
}

/// Increments tag IDs as `a001`, `a002`, ...
struct Tagger {
    n: u32,
}
impl Tagger {
    fn new() -> Self {
        Self { n: 0 }
    }
    fn next(&mut self) -> String {
        self.n += 1;
        format!("a{:03}", self.n)
    }
}

/// Line-oriented buffered reader that understands IMAP literals: when a server
/// line ends in `{<n>}\r\n`, the next `n` bytes are raw and must be read
/// before resuming line parsing.
struct LineReader {
    /// Bytes read from the socket that we haven't returned to the caller yet.
    buf: Vec<u8>,
}

impl LineReader {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Read raw bytes until we have at least one complete CRLF-terminated
    /// line in `self.buf`, then pop it (without the trailing CRLF). Returns
    /// an empty string + error if the socket closes mid-line.
    fn read_line<S: Read>(&mut self, sock: &mut S) -> Result<String> {
        let mut tmp = [0u8; 4096];
        loop {
            if let Some(pos) = find_crlf(&self.buf) {
                let line_bytes: Vec<u8> = self.buf.drain(..pos + 2).collect();
                let without_crlf = &line_bytes[..line_bytes.len() - 2];
                return Ok(String::from_utf8_lossy(without_crlf).into_owned());
            }
            let n = sock.read(&mut tmp)?;
            if n == 0 {
                if self.buf.is_empty() {
                    return Err(Error::UnexpectedEof);
                }
                // Server hung up without a trailing CRLF; return what we have.
                let line_bytes = std::mem::take(&mut self.buf);
                return Ok(String::from_utf8_lossy(&line_bytes).into_owned());
            }
            self.buf.extend_from_slice(&tmp[..n]);
        }
    }

    /// Read exactly `n` bytes from the socket (drawing from the internal
    /// buffer first), as required after a `{<n>}` literal marker.
    fn read_exact<S: Read>(&mut self, sock: &mut S, n: usize) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(n);
        if !self.buf.is_empty() {
            let take = self.buf.len().min(n);
            out.extend_from_slice(&self.buf[..take]);
            self.buf.drain(..take);
        }
        let mut tmp = [0u8; 4096];
        while out.len() < n {
            let want = (n - out.len()).min(tmp.len());
            let got = sock.read(&mut tmp[..want])?;
            if got == 0 {
                return Err(Error::UnexpectedEof);
            }
            out.extend_from_slice(&tmp[..got]);
        }
        Ok(out)
    }

    /// Read everything up to (and including) the tagged response line that
    /// starts with `tag `, returning the whole thing as a single string with
    /// CRLF preserved between lines (and literals inlined).
    fn read_response<S: Read>(&mut self, sock: &mut S, tag: &str) -> Result<String> {
        let (text, _literals) = self.read_response_with_literals(sock, tag)?;
        Ok(text)
    }

    /// Like [`read_response`], but also returns each literal block we saw, in
    /// the order they were sent. Used for `UID FETCH BODY[]` so we can hand
    /// the raw message bytes back without re-parsing the merged text.
    fn read_response_with_literals<S: Read>(
        &mut self,
        sock: &mut S,
        tag: &str,
    ) -> Result<(String, Vec<Vec<u8>>)> {
        let mut text = String::new();
        let mut literals: Vec<Vec<u8>> = Vec::new();
        loop {
            let line = self.read_line(sock)?;
            text.push_str(&line);
            text.push_str("\r\n");

            // If this line ends with a literal marker, slurp that many bytes
            // verbatim and treat them as a continuation of the same logical
            // response (so the tagged-line check below doesn't trip on them).
            if let Some(n) = extract_literal_size(&line) {
                if n > MAX_LITERAL_BYTES {
                    return Err(Error::BadResponse(format!(
                        "imap: literal size {n} exceeds maximum {MAX_LITERAL_BYTES}"
                    )));
                }
                let bytes = self.read_exact(sock, n)?;
                text.push_str(&String::from_utf8_lossy(&bytes));
                literals.push(bytes);
                // After a literal there's always more on the same logical
                // line — keep reading until we hit a real CRLF terminator.
                continue;
            }

            // Tagged response? Continuation request (`+ ...`)? Untagged? Only
            // a line that starts with our tag plus a space (or is exactly the
            // tag) ends the response.
            let trimmed = line.trim_end();
            if trimmed.starts_with(&format!("{tag} ")) || trimmed == tag {
                return Ok((text, literals));
            }
        }
    }
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- string quoting ----------------------------------------------------

    #[test]
    fn quote_plain_ascii() {
        assert_eq!(quote_imap_string("alice"), "\"alice\"");
        assert_eq!(quote_imap_string(""), "\"\"");
    }

    #[test]
    fn quote_escapes_backslash_and_quote() {
        // `say "hi"` → `"say \"hi\""`
        assert_eq!(quote_imap_string("say \"hi\""), "\"say \\\"hi\\\"\"");
        // `a\b`     → `"a\\b"`
        assert_eq!(quote_imap_string("a\\b"), "\"a\\\\b\"");
        // mixed
        assert_eq!(quote_imap_string("p\\a\"ss"), "\"p\\\\a\\\"ss\"");
    }

    #[test]
    fn quote_passes_other_chars_through() {
        assert_eq!(quote_imap_string("INBOX/Sent"), "\"INBOX/Sent\"");
        assert_eq!(quote_imap_string("a b c"), "\"a b c\"");
    }

    // -- userinfo split ----------------------------------------------------

    #[test]
    fn userinfo_with_and_without_password() {
        assert_eq!(split_userinfo("alice:secret"), ("alice", "secret"));
        assert_eq!(split_userinfo("alice"), ("alice", ""));
        assert_eq!(split_userinfo("alice:"), ("alice", ""));
        assert_eq!(split_userinfo(":only-pass"), ("", "only-pass"));
    }

    // -- path parsing ------------------------------------------------------

    #[test]
    fn parse_path_root() {
        assert_eq!(parse_path("/"), (None, None));
        assert_eq!(parse_path(""), (None, None));
    }

    #[test]
    fn parse_path_mailbox_only() {
        assert_eq!(parse_path("/INBOX"), (Some("INBOX".into()), None));
        assert_eq!(parse_path("/Stuff/Sub"), (Some("Stuff/Sub".into()), None));
    }

    #[test]
    fn parse_path_mailbox_with_uid() {
        assert_eq!(
            parse_path("/INBOX;UID=42"),
            (Some("INBOX".into()), Some(42))
        );
        assert_eq!(
            parse_path("/Drafts;uid=7"),
            (Some("Drafts".into()), Some(7))
        );
        assert_eq!(
            parse_path("/Stuff/Sub;UID=999"),
            (Some("Stuff/Sub".into()), Some(999))
        );
    }

    #[test]
    fn parse_path_ignores_unknown_params() {
        assert_eq!(
            parse_path("/INBOX;TYPE=LIST;UID=5"),
            (Some("INBOX".into()), Some(5))
        );
    }

    #[test]
    fn parse_path_percent_decodes_mailbox() {
        // `%20` → space, `%2F` → `/`
        assert_eq!(parse_path("/My%20Mail"), (Some("My Mail".into()), None));
        assert_eq!(parse_path("/a%2Fb;UID=1"), (Some("a/b".into()), Some(1)));
    }

    // -- literal-length detection -----------------------------------------

    #[test]
    fn literal_size_basic() {
        assert_eq!(extract_literal_size("* 1 FETCH (BODY[] {42}\r\n"), Some(42));
        assert_eq!(extract_literal_size("* 1 FETCH (BODY[] {42}"), Some(42));
        assert_eq!(extract_literal_size("foo {0}\r\n"), Some(0));
    }

    #[test]
    fn literal_size_with_plus() {
        // RFC 7888 LITERAL+ marker — still a valid octet count.
        assert_eq!(extract_literal_size("foo {123+}\r\n"), Some(123));
    }

    #[test]
    fn literal_size_rejects_non_literal() {
        assert_eq!(extract_literal_size("a001 OK FETCH completed\r\n"), None);
        assert_eq!(extract_literal_size("plain line"), None);
        assert_eq!(extract_literal_size("{}"), None);
        assert_eq!(extract_literal_size("{abc}"), None);
        assert_eq!(extract_literal_size("{12 34}"), None);
    }

    // -- response helpers --------------------------------------------------

    #[test]
    fn collect_untagged_filters_by_kind() {
        let resp = "* LIST () \"/\" INBOX\r\n\
                    * LIST () \"/\" Drafts\r\n\
                    * 5 EXISTS\r\n\
                    a001 OK LIST completed\r\n";
        let out = collect_untagged(resp, "LIST");
        assert!(out.contains("INBOX"));
        assert!(out.contains("Drafts"));
        assert!(!out.contains("EXISTS"));
        assert!(!out.contains("a001"));
    }

    #[test]
    fn collect_untagged_matches_numeric_responses() {
        let resp = "* 1 FETCH (UID 100)\r\n\
                    * 2 FETCH (UID 101)\r\n\
                    a002 OK FETCH completed\r\n";
        let out = collect_untagged(resp, "FETCH");
        assert!(out.contains("UID 100"));
        assert!(out.contains("UID 101"));
        assert!(!out.contains("a002"));
    }

    #[test]
    fn require_ok_accepts_ok_rejects_no_bad() {
        assert!(require_ok("* untagged\r\na001 OK done\r\n", "a001", "X").is_ok());
        assert!(require_ok("a001 NO bad creds\r\n", "a001", "X").is_err());
        assert!(require_ok("a001 BAD syntax\r\n", "a001", "X").is_err());
    }

    #[test]
    fn tagger_increments() {
        let mut t = Tagger::new();
        assert_eq!(t.next(), "a001");
        assert_eq!(t.next(), "a002");
        assert_eq!(t.next(), "a003");
    }

    // -- LineReader literal handling --------------------------------------

    #[test]
    fn line_reader_inlines_literal_bytes() {
        // Simulate a FETCH response that includes a 5-byte literal.
        let wire = b"* 1 FETCH (BODY[] {5}\r\nhello)\r\na001 OK FETCH completed\r\n";
        let mut src: &[u8] = wire;
        let mut lr = LineReader::new();
        let (text, literals) = lr
            .read_response_with_literals(&mut src, "a001")
            .expect("read response");
        assert_eq!(literals, vec![b"hello".to_vec()]);
        assert!(text.contains("hello"));
        assert!(text.contains("a001 OK"));
    }

    #[test]
    fn line_reader_rejects_oversized_literal() {
        // A server advertising a literal larger than MAX_LITERAL_BYTES must be
        // rejected before we try to allocate/read that many bytes. We don't
        // supply the body — the error has to fire on the size check alone.
        let big = MAX_LITERAL_BYTES + 1;
        let wire = format!("* 1 FETCH (BODY[] {{{big}}}\r\n");
        let mut src: &[u8] = wire.as_bytes();
        let mut lr = LineReader::new();
        let err = lr
            .read_response_with_literals(&mut src, "a001")
            .expect_err("oversized literal must be rejected");
        assert!(matches!(err, Error::BadResponse(_)));
    }

    #[test]
    fn line_reader_handles_simple_tagged_response() {
        let wire = b"* OK greeting\r\na001 OK LOGIN completed\r\n";
        let mut src: &[u8] = wire;
        let mut lr = LineReader::new();
        // First, consume the unsolicited greeting via a dummy tag that won't match.
        // Real code reads it with `*` and the greeting is the first line. Simulate
        // the LOGIN exchange directly here.
        let resp = lr.read_response(&mut src, "a001").unwrap();
        assert!(resp.starts_with("* OK greeting"));
        assert!(resp.contains("a001 OK LOGIN completed"));
    }
}

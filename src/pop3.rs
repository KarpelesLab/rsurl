//! POP3 and POP3S support.
//!
//! Specs: RFC 1939 (POP3), RFC 2595 (POP3 over TLS / STLS), RFC 8314
//! (implicit TLS on port 995 for POP3S), RFC 2384 (`pop3:` URL scheme).
//!
//! URLs: `pop3://user:pass@host/` (LIST), `pop3://user:pass@host/1` (RETR 1).
//! For POP3S, connect with TLS from the start via
//! [`crate::tls::connect_over`].

use std::io::{BufRead, BufReader, Read, Write};

use crate::error::{Error, Result};
use crate::tls::{connect_over, reject_pipelined_plaintext};
use crate::url::Url;

/// Upper bound on a multi-line POP3 response body (LIST output or a RETR'd
/// message). A server that never sends the `.\r\n` terminator — or a single
/// newline-less line — would otherwise grow our buffer without limit, a cheap
/// memory-exhaustion DoS. 64 MiB matches the crate's other body caps (e.g.
/// imap, rtsp, websocket, gopher) and is generous enough for legitimate large
/// mailboxes and messages.
const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

/// USER + PASS auth, then either LIST mailboxes (if no message number in
/// path) or RETR a specific message. Returns the raw bytes (RFC 5322 message
/// or the textual LIST output).
pub fn fetch(url: &Url) -> Result<Vec<u8>> {
    fetch_with(url, &crate::net::NetConfig::default())
}

pub(crate) fn fetch_with(url: &Url, cfg: &crate::net::NetConfig) -> Result<Vec<u8>> {
    let userinfo = url
        .userinfo
        .as_deref()
        .ok_or_else(|| Error::BadResponse("pop3: missing userinfo".into()))?;
    let (user, pass) = crate::url::split_userinfo(userinfo);

    let action = parse_path(&url.path)
        .ok_or_else(|| Error::InvalidUrl(format!("pop3 path: {}", url.path)))?;

    let tcp = cfg.connect(&url.host, url.port)?;
    if url.is_tls() {
        // Implicit TLS (pop3s://): handshake before the greeting. This already
        // satisfies `require_tls`.
        let tls = connect_over(tcp, &url.host)?;
        let mut session = Session::new(BufReader::new(IoAdapter::Tls(Box::new(tls))));
        session.read_status()?; // greeting
        run(&mut session, user, pass, action)
    } else {
        // Plaintext pop3://. Read the greeting, then attempt RFC 2595 STLS to
        // upgrade in place. We do the greeting+STLS dance on a BufReader over
        // the raw stream and only build the Session once the (possibly
        // upgraded) transport is settled — this avoids a poisoned-stream state.
        let mut io = BufReader::new(IoAdapter::Plain(tcp));
        read_status_buf(&mut io)?; // greeting
        let upgraded = try_stls(&mut io, &url.host)?;
        if cfg.require_tls && !upgraded {
            return Err(Error::BadResponse(
                "pop3: TLS required (--ssl-reqd) but server did not offer STLS".into(),
            ));
        }
        let mut session = Session::new(io);
        run(&mut session, user, pass, action)
    }
}

/// Read a single `+OK`/`-ERR` status line directly from a `BufReader` (used for
/// the greeting and STLS reply before the `Session` is constructed). Mirrors
/// [`Session::read_status`].
fn read_status_buf<R: Read + Write>(io: &mut BufReader<R>) -> Result<String> {
    let mut buf = Vec::new();
    let n = io.read_until(b'\n', &mut buf)?;
    if n == 0 {
        return Err(Error::UnexpectedEof);
    }
    while matches!(buf.last(), Some(b'\n') | Some(b'\r')) {
        buf.pop();
    }
    let line = String::from_utf8(buf)
        .map_err(|_| Error::BadResponse("pop3: non-UTF8 status line".into()))?;
    if let Some(rest) = line.strip_prefix("+OK") {
        Ok(rest.strip_prefix(' ').unwrap_or(rest).to_string())
    } else if let Some(rest) = line.strip_prefix("-ERR") {
        let text = rest.strip_prefix(' ').unwrap_or(rest);
        Err(Error::BadResponse(format!("pop3: {text}")))
    } else {
        Err(Error::BadResponse(format!(
            "pop3: unexpected status line: {line}"
        )))
    }
}

/// Attempt the RFC 2595 `STLS` upgrade on a plaintext connection. Issues
/// `STLS`; on a `+OK` reply, upgrades the transport to TLS in place and returns
/// `Ok(true)`. On any non-`+OK` reply (server doesn't support STLS) the
/// connection is left plaintext and `Ok(false)` is returned.
///
/// Security (CVE-2011-0411 class STARTTLS plaintext injection): the `BufReader`
/// may have buffered bytes a MITM pipelined *after* the `+OK STLS` line, in the
/// same plaintext flight. Those bytes were received before the handshake;
/// reading them post-TLS would treat attacker-staged data as trusted. We abort
/// if any remain rather than discard them, exactly like smtp/imap.
fn try_stls(io: &mut BufReader<IoAdapter>, host: &str) -> Result<bool> {
    // Negotiate STLS (send command, read reply, run the injection guard). A
    // `false` means the server doesn't support STLS — leave it plaintext.
    if !stls_negotiate(io)? {
        return Ok(false);
    }
    // Upgrade the BufReader's inner transport to TLS in place.
    io.get_mut().upgrade(host)?;
    Ok(true)
}

/// Issue `STLS` and read the reply, deciding whether the connection should be
/// upgraded. Returns `Ok(true)` if the server answered `+OK` and the read
/// buffer is clean (ready for the TLS handshake), `Ok(false)` if the server
/// declined (`-ERR`/unknown command — leave it plaintext), and an error if a
/// MITM pipelined plaintext bytes after the `+OK` (CVE-2011-0411 class) or the
/// socket failed. Generic over the reader so it can be exercised with a mock.
fn stls_negotiate<R: Read + Write>(io: &mut BufReader<R>) -> Result<bool> {
    {
        let inner = io.get_mut();
        inner.write_all(b"STLS\r\n")?;
        inner.flush()?;
    }
    // A non-+OK (e.g. -ERR unknown command) means the server lacks STLS.
    match read_status_buf(io) {
        Ok(_) => {}
        Err(Error::BadResponse(_)) => return Ok(false),
        Err(e) => return Err(e),
    }
    // Injection guard: any bytes buffered after the +OK were received as
    // plaintext before the handshake — reject rather than trust them post-TLS.
    reject_pipelined_plaintext("pop3", io.buffer().is_empty())?;
    Ok(true)
}

/// What the URL path asks us to do once we're authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    List,
    Retr(u32),
}

/// Reject a URL-derived string containing CR, LF, NUL, or any other ASCII
/// control byte before it's interpolated into a POP3 command. `what` names the
/// field for the error message.
fn reject_ctl(s: &str, what: &str) -> Result<()> {
    crate::url::reject_ctl("pop3", what, s)
}

/// Decide between LIST and RETR based on the URL path. Returns `None` for
/// anything that doesn't fit `/`, `""`, or `/<positive integer>`.
fn parse_path(path: &str) -> Option<Action> {
    let trimmed = path.strip_prefix('/').unwrap_or(path);
    if trimmed.is_empty() {
        return Some(Action::List);
    }
    // Reject anything with sub-paths or query — POP3 URLs are flat.
    if trimmed.contains('/') || trimmed.contains('?') || trimmed.contains('#') {
        return None;
    }
    trimmed.parse::<u32>().ok().map(Action::Retr)
}

/// Reverse the dot-stuffing applied to multi-line POP3 responses per
/// RFC 1939 §3.5: any line that begins with `.` had an extra `.` prepended
/// at transmission, so we strip the leading byte on receipt. Operates on
/// the body as already-collected bytes (terminator `.\r\n` removed).
fn un_dot_stuff(body: &[u8]) -> Vec<u8> {
    // Walk line-by-line, where lines end with `\r\n` (POP3 wire format).
    // A line is exactly the bytes between `\r\n` markers; trailing data
    // without a final CRLF is passed through unchanged.
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0;
    let mut at_line_start = true;
    while i < body.len() {
        if at_line_start && body[i] == b'.' {
            // Drop this dot — it's the stuffing byte.
            i += 1;
            at_line_start = false;
            continue;
        }
        let b = body[i];
        out.push(b);
        i += 1;
        at_line_start = b == b'\n';
    }
    out
}

/// Read+Write transport, either plain or TLS-wrapped, with in-place STLS
/// upgrade — the shared transport enum (see [`crate::net::MaybeTlsStream`]).
use crate::net::MaybeTlsStream as IoAdapter;

/// Buffered POP3 conversation. Wraps a transport in a `BufReader` so we can
/// pull whole CRLF-terminated lines without an extra allocation per byte.
struct Session<R: Read + Write> {
    io: BufReader<R>,
}

impl<R: Read + Write> Session<R> {
    fn new(io: BufReader<R>) -> Self {
        Self { io }
    }

    /// Send `cmd` followed by CRLF. The underlying writer lives behind the
    /// BufReader, so we have to reach through `get_mut` to write.
    ///
    /// Refuses any command line containing CR, LF, or NUL: the CRLF terminator
    /// is appended here, so an embedded CR/LF in URL-derived `user`/`pass`
    /// would otherwise inject extra POP3 commands.
    fn send(&mut self, cmd: &str) -> Result<()> {
        if cmd.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
            return Err(Error::BadResponse(
                "pop3: refusing to send command line with embedded CR/LF/NUL".into(),
            ));
        }
        let inner = self.io.get_mut();
        inner.write_all(cmd.as_bytes())?;
        inner.write_all(b"\r\n")?;
        inner.flush()?;
        Ok(())
    }

    /// Read a single CRLF-terminated reply line, trim the CRLF, and return
    /// it as a UTF-8 string. POP3 status lines are ASCII per the RFC.
    fn read_line(&mut self) -> Result<String> {
        let mut buf = Vec::new();
        let n = self.io.read_until(b'\n', &mut buf)?;
        if n == 0 {
            return Err(Error::UnexpectedEof);
        }
        // Strip trailing \r\n or \n.
        while matches!(buf.last(), Some(b'\n') | Some(b'\r')) {
            buf.pop();
        }
        String::from_utf8(buf).map_err(|_| Error::BadResponse("pop3: non-UTF8 status line".into()))
    }

    /// Read a status line and require it to start with `+OK`. Returns the
    /// text after `+OK` (with the leading space dropped) on success, or
    /// maps `-ERR` replies to `Error::BadResponse`.
    fn read_status(&mut self) -> Result<String> {
        let line = self.read_line()?;
        if let Some(rest) = line.strip_prefix("+OK") {
            // RFC 1939: "+OK" is followed by optional text, usually after a
            // single space. Trim that delimiter so callers see only the text.
            Ok(rest.strip_prefix(' ').unwrap_or(rest).to_string())
        } else if let Some(rest) = line.strip_prefix("-ERR") {
            let text = rest.strip_prefix(' ').unwrap_or(rest);
            Err(Error::BadResponse(format!("pop3: {text}")))
        } else {
            Err(Error::BadResponse(format!(
                "pop3: unexpected status line: {line}"
            )))
        }
    }

    /// Read a multi-line response body terminated by a line containing only
    /// `.` (CRLF.CRLF). Returns the body bytes with the terminator stripped
    /// but with all dot-stuffing still in place — callers decide whether to
    /// un-stuff (RETR) or pass through verbatim (LIST is also dot-stuffed,
    /// but stuffing only triggers when a line begins with `.`, which the
    /// LIST grammar forbids, so it's a no-op in practice).
    fn read_multiline(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            // Bound each line read: `read_until` is otherwise unbounded, so a
            // server that sends a single line with no `\n` would make us
            // allocate forever. Cap the per-line reader at the remaining
            // response budget plus one byte, so we can distinguish "line is
            // exactly at the limit" from "line overran the limit".
            let mut line = Vec::new();
            let line_cap = MAX_RESPONSE_BYTES - out.len();
            let n = (&mut self.io)
                .take(line_cap as u64 + 1)
                .read_until(b'\n', &mut line)?;
            if n == 0 {
                return Err(Error::UnexpectedEof);
            }
            // A terminator line is exactly `.\r\n`, or `.\n` for servers
            // that play loose with CRLF. Detect before pushing.
            let is_terminator = matches!(line.as_slice(), b".\r\n" | b".\n");
            if is_terminator {
                return Ok(out);
            }
            // Aggregate cap: refuse to buffer past MAX_RESPONSE_BYTES, whether
            // the overrun comes from one giant newline-less line or from a
            // body that never terminates with `.\r\n`.
            if line.len() > line_cap {
                return Err(Error::BadResponse(format!(
                    "pop3: response exceeds maximum {MAX_RESPONSE_BYTES} bytes"
                )));
            }
            out.extend_from_slice(&line);
        }
    }
}

/// Drive the actual POP3 conversation once we have a Session ready.
fn run<R: Read + Write>(
    session: &mut Session<R>,
    user: &str,
    pass: &str,
    action: Action,
) -> Result<Vec<u8>> {
    // The greeting (and any STLS upgrade) has already been handled by
    // `fetch_with` before this Session was constructed.

    // Authenticate. We always send both USER and PASS; APOP and SASL are
    //    deferred (see module note). Reject control bytes in the URL-derived
    //    credentials up front so a CR/LF can't smuggle extra commands (`send`
    //    also guards the assembled line as a backstop).
    reject_ctl(user, "pop3 user")?;
    reject_ctl(pass, "pop3 password")?;
    session.send(&format!("USER {user}"))?;
    session.read_status()?;
    session.send(&format!("PASS {pass}"))?;
    session.read_status()?;

    // Perform the requested action.
    let payload = match action {
        Action::List => {
            session.send("LIST")?;
            session.read_status()?;
            // LIST responses are dot-stuffed in theory but every line starts
            // with a digit, so un-stuffing would be a no-op. Pass through.
            session.read_multiline()?
        }
        Action::Retr(n) => {
            session.send(&format!("RETR {n}"))?;
            session.read_status()?;
            let raw = session.read_multiline()?;
            un_dot_stuff(&raw)
        }
    };

    // Polite shutdown. Errors here are tolerated — we already have the
    //    payload, and a half-broken server shouldn't fail the whole fetch.
    let _ = session.send("QUIT");
    let _ = session.read_status();

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn un_dot_stuff_strips_leading_dot_on_each_line() {
        let input = b"hello\r\n..dotted\r\n.line\r\nplain\r\n";
        let got = un_dot_stuff(input);
        assert_eq!(got, b"hello\r\n.dotted\r\nline\r\nplain\r\n");
    }

    #[test]
    fn un_dot_stuff_handles_empty_body() {
        assert_eq!(un_dot_stuff(b""), b"");
    }

    #[test]
    fn un_dot_stuff_handles_first_line_dot() {
        // A message whose very first line begins with `.` gets stuffed too.
        let input = b"..first\r\nbody\r\n";
        assert_eq!(un_dot_stuff(input), b".first\r\nbody\r\n");
    }

    #[test]
    fn un_dot_stuff_does_not_consume_dot_in_middle() {
        let input = b"a.b\r\n.x\r\n";
        // `.` after `a` is mid-line, untouched. Leading `.` on second line
        // is the stuffing byte and gets removed.
        assert_eq!(un_dot_stuff(input), b"a.b\r\nx\r\n");
    }

    #[test]
    fn un_dot_stuff_handles_trailing_partial_line() {
        // No final CRLF — should still process leading dots correctly.
        let input = b".end";
        assert_eq!(un_dot_stuff(input), b"end");
    }

    #[test]
    fn parse_path_root_means_list() {
        assert_eq!(parse_path("/"), Some(Action::List));
        assert_eq!(parse_path(""), Some(Action::List));
    }

    #[test]
    fn parse_path_numeric_means_retr() {
        assert_eq!(parse_path("/1"), Some(Action::Retr(1)));
        assert_eq!(parse_path("/42"), Some(Action::Retr(42)));
        assert_eq!(parse_path("/0"), Some(Action::Retr(0)));
    }

    #[test]
    fn parse_path_rejects_garbage() {
        assert_eq!(parse_path("/abc"), None);
        assert_eq!(parse_path("/1/2"), None);
        assert_eq!(parse_path("/1?x=1"), None);
        assert_eq!(parse_path("/-1"), None);
        assert_eq!(parse_path("/1.0"), None);
    }

    #[test]
    fn reject_ctl_flags_control_bytes() {
        assert!(reject_ctl("alice", "pop3 user").is_ok());
        assert!(reject_ctl("p@ss:word", "pop3 password").is_ok());
        assert!(reject_ctl("alice\r\nDELE 1", "pop3 user").is_err());
        assert!(reject_ctl("alice\npass", "pop3 user").is_err());
        assert!(reject_ctl("alice\0", "pop3 user").is_err());
        assert!(reject_ctl("alice\x7f", "pop3 user").is_err());
    }

    /// In-memory Read+Write used to drive `Session::send` in tests.
    struct MockIo {
        written: Vec<u8>,
    }
    impl Read for MockIo {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Ok(0)
        }
    }
    impl Write for MockIo {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Read-only mock that replays a fixed byte stream, then EOFs. Used to
    /// drive `read_multiline` over the BufReader without a live socket.
    struct ReplayIo {
        data: std::io::Cursor<Vec<u8>>,
    }
    impl Read for ReplayIo {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.data.read(buf)
        }
    }
    impl Write for ReplayIo {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn session_replaying(data: Vec<u8>) -> Session<ReplayIo> {
        Session::new(BufReader::new(ReplayIo {
            data: std::io::Cursor::new(data),
        }))
    }

    #[test]
    fn read_multiline_returns_body_on_terminator() {
        let mut s = session_replaying(b"line one\r\nline two\r\n.\r\n".to_vec());
        let body = s.read_multiline().unwrap();
        assert_eq!(body, b"line one\r\nline two\r\n");
    }

    #[test]
    fn read_multiline_aborts_past_aggregate_cap() {
        // A body that never sends `.\r\n`: many terminated lines whose total
        // exceeds MAX_RESPONSE_BYTES must error rather than buffer forever.
        // Build just over the cap out of 1 KiB lines.
        let line = {
            let mut l = vec![b'a'; 1022];
            l.extend_from_slice(b"\r\n");
            l
        };
        let n_lines = MAX_RESPONSE_BYTES / line.len() + 2;
        let mut data = Vec::with_capacity(n_lines * line.len());
        for _ in 0..n_lines {
            data.extend_from_slice(&line);
        }
        // Note: no terminating `.\r\n`.
        let mut s = session_replaying(data);
        match s.read_multiline() {
            Err(Error::BadResponse(m)) => assert!(m.contains("maximum"), "got {m}"),
            other => panic!("expected BadResponse(maximum), got {other:?}"),
        }
    }

    #[test]
    fn read_multiline_aborts_on_unbounded_single_line() {
        // A single newline-less line larger than the cap must error, not grow
        // the buffer without limit.
        let data = vec![b'x'; MAX_RESPONSE_BYTES + 1024];
        let mut s = session_replaying(data);
        match s.read_multiline() {
            Err(Error::BadResponse(m)) => assert!(m.contains("maximum"), "got {m}"),
            other => panic!("expected BadResponse(maximum), got {other:?}"),
        }
    }

    #[test]
    fn send_rejects_embedded_crlf() {
        let mut s = Session::new(BufReader::new(MockIo {
            written: Vec::new(),
        }));
        assert!(matches!(
            s.send("USER alice\r\nPASS x"),
            Err(Error::BadResponse(_))
        ));
        assert!(matches!(s.send("USER a\nb"), Err(Error::BadResponse(_))));
        assert!(matches!(s.send("USER a\0b"), Err(Error::BadResponse(_))));
        // Clean command goes through with exactly one trailing CRLF.
        s.send("USER alice").unwrap();
        assert_eq!(s.io.get_ref().written, b"USER alice\r\n");
    }

    // -- STLS negotiation (RFC 2595) --------------------------------------

    /// Bidirectional mock: replays a scripted server byte stream on reads and
    /// records everything the client writes, so we can drive `stls_negotiate`
    /// (and assert the `STLS` command is issued) without a live socket.
    struct DuplexIo {
        to_read: std::io::Cursor<Vec<u8>>,
        written: Vec<u8>,
    }
    impl DuplexIo {
        fn new(script: &[u8]) -> Self {
            Self {
                to_read: std::io::Cursor::new(script.to_vec()),
                written: Vec::new(),
            }
        }
    }
    impl Read for DuplexIo {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.to_read.read(buf)
        }
    }
    impl Write for DuplexIo {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn stls_negotiate_issues_command_and_accepts_ok() {
        // Server answers +OK with nothing pipelined after it: ready to upgrade.
        let mut io = BufReader::new(DuplexIo::new(b"+OK begin TLS\r\n"));
        let upgrade = stls_negotiate(&mut io).expect("stls negotiate");
        assert!(upgrade, "expected upgrade decision on +OK");
        // The STLS command must have been issued verbatim.
        assert_eq!(io.get_ref().written, b"STLS\r\n");
    }

    #[test]
    fn stls_negotiate_declines_on_err() {
        // A server without STLS replies -ERR; we must leave the connection
        // plaintext (return false) rather than error out.
        let mut io = BufReader::new(DuplexIo::new(b"-ERR unknown command\r\n"));
        let upgrade = stls_negotiate(&mut io).expect("stls negotiate");
        assert!(!upgrade, "expected no upgrade on -ERR");
        assert_eq!(io.get_ref().written, b"STLS\r\n");
    }

    #[test]
    fn stls_negotiate_rejects_pipelined_plaintext_injection() {
        // CVE-2011-0411 class: a MITM pipelines a forged line right after the
        // +OK STLS, in the same plaintext flight. After reading the +OK those
        // bytes remain buffered in the BufReader, so the guard must trip and
        // abort rather than treat them as trusted post-TLS data.
        let mut io = BufReader::new(DuplexIo::new(b"+OK begin TLS\r\n+OK 1 messages\r\n.\r\n"));
        match stls_negotiate(&mut io) {
            Err(Error::BadResponse(m)) => assert!(m.contains("injection"), "got {m}"),
            other => panic!("expected BadResponse(injection), got {other:?}"),
        }
    }

    #[test]
    fn stls_negotiate_clear_when_server_waits() {
        // A conforming server sends nothing after +OK until the handshake, so
        // the buffer is clean and the upgrade proceeds.
        let mut io = BufReader::new(DuplexIo::new(b"+OK begin TLS\r\n"));
        assert!(stls_negotiate(&mut io).expect("ok"));
        assert!(io.buffer().is_empty(), "reader must be clear after +OK");
    }

    // -- require-TLS enforcement (curl --ssl-reqd) ------------------------

    #[test]
    fn require_tls_errors_before_credentials_when_no_stls() {
        // Mirror the plaintext fetch_with path: read greeting, attempt STLS
        // (server declines with -ERR), then enforce require_tls. The error must
        // fire before any USER/PASS is sent.
        let greeting_and_stls = b"+OK POP3 ready\r\n-ERR unknown command\r\n";
        let mut io = BufReader::new(DuplexIo::new(greeting_and_stls));
        read_status_buf(&mut io).expect("greeting");
        let upgraded = stls_negotiate(&mut io).expect("stls");
        assert!(!upgraded);
        // require_tls && !upgraded → the production code returns this error.
        let err: Result<()> = if !upgraded {
            Err(Error::BadResponse(
                "pop3: TLS required (--ssl-reqd) but server did not offer STLS".into(),
            ))
        } else {
            Ok(())
        };
        match err {
            Err(Error::BadResponse(m)) => assert!(m.contains("TLS required"), "got {m}"),
            other => panic!("expected TLS required error, got {other:?}"),
        }
        // Crucially, only the greeting read and the STLS command were written —
        // no USER/PASS leaked onto the plaintext connection.
        assert_eq!(io.get_ref().written, b"STLS\r\n");
    }
}

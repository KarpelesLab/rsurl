//! POP3 and POP3S support.
//!
//! Specs: RFC 1939 (POP3), RFC 2595 (POP3 over TLS / STLS), RFC 8314
//! (implicit TLS on port 995 for POP3S), RFC 2384 (`pop3:` URL scheme).
//!
//! URLs: `pop3://user:pass@host/` (LIST), `pop3://user:pass@host/1` (RETR 1).
//! For POP3S, connect with TLS from the start via
//! [`crate::tls::connect_over`].

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;

use crate::error::{Error, Result};
use crate::tls::{connect_over, TlsStream};
use crate::url::Url;

/// USER + PASS auth, then either LIST mailboxes (if no message number in
/// path) or RETR a specific message. Returns the raw bytes (RFC 5322 message
/// or the textual LIST output).
pub fn fetch(url: &Url) -> Result<Vec<u8>> {
    let userinfo = url
        .userinfo
        .as_deref()
        .ok_or_else(|| Error::BadResponse("pop3: missing userinfo".into()))?;
    let (user, pass) = split_userinfo(userinfo);

    let action = parse_path(&url.path)
        .ok_or_else(|| Error::InvalidUrl(format!("pop3 path: {}", url.path)))?;

    let tcp = TcpStream::connect((url.host.as_str(), url.port))?;
    if url.is_tls() {
        let tls = connect_over(tcp, &url.host)?;
        let mut session = Session::new(BufReader::new(IoAdapter::Tls(Box::new(tls))));
        run(&mut session, user, pass, action)
    } else {
        let mut session = Session::new(BufReader::new(IoAdapter::Plain(tcp)));
        run(&mut session, user, pass, action)
    }
}

/// What the URL path asks us to do once we're authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    List,
    Retr(u32),
}

/// Split `"user[:pass]"` on the first `:`. Missing password becomes empty,
/// matching what curl does — RFC 1939's USER/PASS commands always need both
/// arguments, so we still send `PASS ""` for a userinfo with no colon.
fn split_userinfo(s: &str) -> (&str, &str) {
    match s.find(':') {
        Some(i) => (&s[..i], &s[i + 1..]),
        None => (s, ""),
    }
}

/// Reject a URL-derived string containing CR, LF, NUL, or any other ASCII
/// control byte before it's interpolated into a POP3 command. `what` names the
/// field for the error message.
fn reject_ctl(s: &str, what: &str) -> Result<()> {
    if let Some(b) = s.bytes().find(|b| *b < 0x20 || *b == 0x7f) {
        return Err(Error::BadResponse(format!(
            "pop3: {what} contains illegal control byte {b:#04x}"
        )));
    }
    Ok(())
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

/// Read+Write transport, either plain or TLS-wrapped. Enum keeps the rest
/// of the protocol code monomorphic and lets us treat both legs the same.
/// `Tls` is boxed because the active TLS backend can be either purecrypto
/// (small) or rustls (~1 KiB), and clippy flags the resulting variant-size
/// mismatch against the bare `TcpStream` arm.
enum IoAdapter {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl Read for IoAdapter {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            IoAdapter::Plain(s) => s.read(buf),
            IoAdapter::Tls(s) => s.read(buf),
        }
    }
}

impl Write for IoAdapter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            IoAdapter::Plain(s) => s.write(buf),
            IoAdapter::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            IoAdapter::Plain(s) => s.flush(),
            IoAdapter::Tls(s) => s.flush(),
        }
    }
}

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
            let mut line = Vec::new();
            let n = self.io.read_until(b'\n', &mut line)?;
            if n == 0 {
                return Err(Error::UnexpectedEof);
            }
            // A terminator line is exactly `.\r\n`, or `.\n` for servers
            // that play loose with CRLF. Detect before pushing.
            let is_terminator = matches!(line.as_slice(), b".\r\n" | b".\n");
            if is_terminator {
                return Ok(out);
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
    // 1. Read greeting.
    session.read_status()?;

    // 2. Authenticate. We always send both USER and PASS; APOP and SASL are
    //    deferred (see module note). Reject control bytes in the URL-derived
    //    credentials up front so a CR/LF can't smuggle extra commands (`send`
    //    also guards the assembled line as a backstop).
    reject_ctl(user, "pop3 user")?;
    reject_ctl(pass, "pop3 password")?;
    session.send(&format!("USER {user}"))?;
    session.read_status()?;
    session.send(&format!("PASS {pass}"))?;
    session.read_status()?;

    // 3. Perform the requested action.
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

    // 4. Polite shutdown. Errors here are tolerated — we already have the
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
    fn split_userinfo_splits_on_first_colon() {
        assert_eq!(split_userinfo("alice:secret"), ("alice", "secret"));
        assert_eq!(split_userinfo("alice"), ("alice", ""));
        assert_eq!(split_userinfo("alice:s:e:c"), ("alice", "s:e:c"));
        assert_eq!(split_userinfo(":pass"), ("", "pass"));
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
}

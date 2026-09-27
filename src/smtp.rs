//! SMTP and SMTPS support — sending mail.
//!
//! Specs: RFC 5321 (SMTP), RFC 3207 (STARTTLS), RFC 4954 (AUTH), RFC 4616
//! (SASL PLAIN), RFC 8314 (implicit TLS on 465 for `smtps`).
//!
//! URLs: `smtp://host[:port]` / `smtps://host[:port]`. The envelope sender and
//! recipients come from `--mail-from` / `--mail-rcpt`, and the message body
//! from `-T file` or `-d` (curl's model). This is a deliberately small subset:
//! EHLO, optional STARTTLS, optional AUTH PLAIN/LOGIN, then MAIL/RCPT/DATA.

use std::io::{BufRead, BufReader, Read, Write};

use crate::error::{Error, Result};
use crate::net::MaybeTlsStream as Stream;
use crate::net::NetConfig;
use crate::tls::reject_pipelined_plaintext;
use crate::url::Url;
use crate::websocket::base64_encode;

/// Options for an SMTP send (envelope + optional credentials).
pub struct SmtpOptions<'a> {
    pub from: &'a str,
    pub rcpts: &'a [String],
    pub user: Option<&'a str>,
    pub pass: Option<&'a str>,
}

/// Reject CR/LF/NUL and other control bytes in a URL/envelope-derived value so
/// it can't smuggle extra SMTP commands onto the control connection.
fn reject_ctl(s: &str, what: &str) -> Result<()> {
    crate::url::reject_ctl("smtp", what, s)
}

/// Send a message. The default operation for an `smtp(s)://` URL with a body.
pub(crate) fn send(url: &Url, body: &[u8], opts: &SmtpOptions, cfg: &NetConfig) -> Result<()> {
    if url.scheme != "smtp" && url.scheme != "smtps" {
        return Err(Error::UnsupportedScheme(url.scheme.clone()));
    }
    reject_ctl(opts.from, "mail-from")?;
    for r in opts.rcpts {
        reject_ctl(r, "mail-rcpt")?;
    }
    if opts.rcpts.is_empty() {
        return Err(Error::BadResponse(
            "smtp: no recipients (--mail-rcpt)".into(),
        ));
    }

    let tcp = cfg.connect(&url.host, url.port)?;
    // Idle bound so a stalled server fails the send instead of hanging it.
    tcp.set_read_timeout(cfg.io_timeout())?;
    tcp.set_write_timeout(Some(IO_TIMEOUT))?;
    let stream = if url.scheme == "smtps" {
        Stream::Tls(Box::new(cfg.tls_connect(tcp, &url.host)?))
    } else {
        Stream::Plain(tcp)
    };
    let mut io = BufReader::new(stream);

    // Greeting.
    let (code, _) = read_reply(&mut io)?;
    if code != 220 {
        return Err(Error::BadResponse(format!("smtp greeting: {code}")));
    }

    // EHLO — the domain is cosmetic here; use the client's view of the host.
    let mut caps = ehlo(&mut io, &url.host)?;

    // STARTTLS upgrade for plaintext connections that advertise it.
    if matches!(io.get_ref(), Stream::Plain(_)) && caps.iter().any(|c| c == "STARTTLS") {
        send_line(&mut io, "STARTTLS")?;
        let (c, m) = read_reply(&mut io)?;
        if c != 220 {
            return Err(Error::BadResponse(format!("smtp STARTTLS: {c} {m}")));
        }
        // Security (CVE-2011-0411 class): any bytes buffered after the 220 are
        // a plaintext-injection attempt — reject before the TLS handshake.
        reject_pipelined_plaintext("smtp", io.buffer().is_empty())?;
        let plain = match io.into_inner() {
            Stream::Plain(s) => s,
            _ => {
                return Err(Error::BadResponse(
                    "smtp: STARTTLS on non-plain stream".into(),
                ))
            }
        };
        let tls = cfg.tls_connect(plain, &url.host)?;
        io = BufReader::new(Stream::Tls(Box::new(tls)));
        caps = ehlo(&mut io, &url.host)?;
    }

    // require-TLS (curl --ssl-reqd): if the connection is still plaintext after
    // the STARTTLS negotiation above (server didn't advertise it, or it was a
    // plain smtp:// scheme with no upgrade), refuse to continue before any
    // credentials or message data leave the host. smtps:// implicit TLS is a
    // `Stream::Tls` here and so already satisfies the requirement.
    require_tls_ok(cfg.require_tls, matches!(io.get_ref(), Stream::Plain(_)))?;

    // AUTH, if credentials were supplied and the server advertises AUTH. As in
    // curl, no AUTH capability means no authentication attempt: a server that
    // hides AUTH until STARTTLS (or a MITM that stripped STARTTLS) must never
    // be handed credentials over the plaintext connection.
    if let (Some(user), Some(pass)) = (opts.user, opts.pass) {
        if auth_mechanisms(&caps).is_some() {
            authenticate(&mut io, &caps, user, pass)?;
        }
    }

    // Envelope.
    send_line(&mut io, &format!("MAIL FROM:<{}>", opts.from))?;
    expect(&mut io, 250, "MAIL FROM")?;
    for r in opts.rcpts {
        send_line(&mut io, &format!("RCPT TO:<{r}>"))?;
        // 251 "user not local; will forward" is a success too (RFC 5321 §4.2.2).
        let (code, text) = read_reply(&mut io)?;
        if code != 250 && code != 251 {
            return Err(Error::BadResponse(format!("smtp RCPT TO: {code} {text}")));
        }
    }

    // DATA + dot-stuffed body terminated by CRLF "." CRLF.
    send_line(&mut io, "DATA")?;
    expect(&mut io, 354, "DATA")?;
    let payload = dot_stuff(body);
    {
        let w = io.get_mut();
        w.write_all(&payload)?;
        w.write_all(end_of_data(&payload))?;
        w.flush()?;
    }
    expect(&mut io, 250, "end of DATA")?;

    let _ = send_line(&mut io, "QUIT");
    let _ = read_reply(&mut io);
    Ok(())
}

/// Idle timeout for every read/write on the SMTP connection.
const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// The end-of-data marker to append after the (dot-stuffed) payload. The
/// marker is `CRLF . CRLF`, but its leading CRLF may be the payload's own
/// final line ending — adding another would append a spurious blank line to
/// every message that already ends in a newline.
fn end_of_data(payload: &[u8]) -> &'static [u8] {
    if payload.is_empty() || payload.ends_with(b"\r\n") {
        b".\r\n"
    } else {
        b"\r\n.\r\n"
    }
}

/// Enforce curl's `--ssl-reqd` for SMTP: when `require_tls` is set, the
/// connection must no longer be plaintext (STARTTLS negotiated, or smtps://
/// implicit TLS). Called after the STARTTLS step and before any AUTH or
/// message data is sent, so credentials never travel in the clear.
fn require_tls_ok(require_tls: bool, still_plain: bool) -> Result<()> {
    if require_tls && still_plain {
        return Err(Error::BadResponse(
            "smtp: TLS required (--ssl-reqd) but server did not offer STARTTLS".into(),
        ));
    }
    Ok(())
}

fn ehlo<R: Read + Write>(io: &mut BufReader<R>, host: &str) -> Result<Vec<String>> {
    send_line(io, &format!("EHLO {host}"))?;
    let (code, text) = read_reply(io)?;
    if code != 250 {
        // Fall back to HELO for ancient servers.
        send_line(io, &format!("HELO {host}"))?;
        let (c2, _) = read_reply(io)?;
        if c2 != 250 {
            return Err(Error::BadResponse(format!("smtp EHLO/HELO: {code}")));
        }
        return Ok(Vec::new());
    }
    // Capabilities are the 2nd..Nth lines, upper-cased keyword first token.
    Ok(text
        .lines()
        .skip(1)
        .map(|l| l.trim().to_ascii_uppercase())
        .collect())
}

/// The SASL mechanisms from the EHLO `AUTH` capability (also the legacy
/// `AUTH=` form), or `None` if the server advertises no AUTH at all.
fn auth_mechanisms(caps: &[String]) -> Option<Vec<&str>> {
    let mut found = None;
    for c in caps {
        let rest = match c.strip_prefix("AUTH") {
            Some(r) if r.is_empty() || r.starts_with([' ', '=']) => r,
            _ => continue,
        };
        found
            .get_or_insert_with(Vec::new)
            .extend(rest.trim_start_matches('=').split_whitespace());
    }
    found
}

fn authenticate<R: Read + Write>(
    io: &mut BufReader<R>,
    caps: &[String],
    user: &str,
    pass: &str,
) -> Result<()> {
    let mechs = auth_mechanisms(caps).unwrap_or_default();
    let supports = |m: &str| mechs.contains(&m);
    if supports("PLAIN") {
        // AUTH PLAIN: base64("\0user\0pass").
        let mut raw = Vec::new();
        raw.push(0);
        raw.extend_from_slice(user.as_bytes());
        raw.push(0);
        raw.extend_from_slice(pass.as_bytes());
        send_line(io, &format!("AUTH PLAIN {}", base64_encode(&raw)))?;
        expect(io, 235, "AUTH PLAIN")?;
    } else if supports("LOGIN") {
        send_line(io, "AUTH LOGIN")?;
        expect(io, 334, "AUTH LOGIN")?;
        send_line(io, &base64_encode(user.as_bytes()))?;
        expect(io, 334, "AUTH LOGIN user")?;
        send_line(io, &base64_encode(pass.as_bytes()))?;
        expect(io, 235, "AUTH LOGIN pass")?;
    } else {
        return Err(Error::BadResponse(
            "smtp: server offers no supported AUTH mechanism (PLAIN/LOGIN)".into(),
        ));
    }
    Ok(())
}

fn send_line<R: Read + Write>(io: &mut BufReader<R>, line: &str) -> Result<()> {
    if line.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        return Err(Error::BadResponse(
            "smtp: refusing to send command with embedded CR/LF/NUL".into(),
        ));
    }
    let w = io.get_mut();
    w.write_all(line.as_bytes())?;
    w.write_all(b"\r\n")?;
    w.flush()?;
    Ok(())
}

/// Read a (possibly multi-line) SMTP reply. Lines look like `250-text`
/// (continuation) or `250 text` (final). Returns `(code, joined_text)`.
fn read_reply<R: Read + Write>(io: &mut BufReader<R>) -> Result<(u16, String)> {
    const MAX_REPLY_BYTES: usize = 64 * 1024;
    let mut text = String::new();
    let mut total = 0usize;
    loop {
        // Bound each line read: `read_line`/`read_until` are otherwise
        // unbounded, so a server (or MITM on plaintext smtp://) that sends a
        // single line with no `\n` — e.g. a multi-gigabyte greeting read right
        // after connect — would make us allocate forever before the running
        // cap below is ever checked. Cap the per-line reader at the remaining
        // reply budget plus one byte, so we can tell "line is exactly at the
        // limit" from "line overran the limit".
        let line_cap = MAX_REPLY_BYTES - total;
        let mut raw = Vec::new();
        let n = (&mut *io)
            .take(line_cap as u64 + 1)
            .read_until(b'\n', &mut raw)?;
        if n == 0 {
            return Err(Error::UnexpectedEof);
        }
        if raw.len() > line_cap {
            return Err(Error::BadResponse("smtp: reply exceeds 64 KiB".into()));
        }
        total += n;
        let line = String::from_utf8_lossy(&raw);
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.len() < 3 || !trimmed.as_bytes()[..3].iter().all(u8::is_ascii_digit) {
            return Err(Error::BadResponse(format!(
                "smtp: bad reply line {trimmed:?}"
            )));
        }
        let code: u16 = trimmed[..3].parse().unwrap_or(0);
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(trimmed[3..].trim_start_matches(['-', ' ']));
        // A space after the code marks the final line; '-' is a continuation.
        if trimmed.as_bytes().get(3) != Some(&b'-') {
            return Ok((code, text));
        }
    }
}

fn expect<R: Read + Write>(io: &mut BufReader<R>, want: u16, ctx: &str) -> Result<()> {
    let (code, text) = read_reply(io)?;
    if code != want {
        return Err(Error::BadResponse(format!("smtp {ctx}: {code} {text}")));
    }
    Ok(())
}

/// Dot-stuff a message body per RFC 5321 §4.5.2: a line starting with `.`
/// gets an extra `.`. Also normalises bare LF to CRLF.
fn dot_stuff(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 16);
    let mut at_line_start = true;
    let mut i = 0;
    while i < body.len() {
        let b = body[i];
        if at_line_start && b == b'.' {
            out.push(b'.');
        }
        if b == b'\n' {
            // Ensure CRLF.
            if out.last() != Some(&b'\r') {
                out.push(b'\r');
            }
            out.push(b'\n');
            at_line_start = true;
        } else if b == b'\r' {
            // Defer; the next byte decides (handled above for \n).
            out.push(b'\r');
            at_line_start = false;
        } else {
            out.push(b);
            at_line_start = false;
        }
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn dot_stuffing_and_crlf() {
        assert_eq!(dot_stuff(b".hidden\n"), b"..hidden\r\n");
        assert_eq!(dot_stuff(b"a\nb"), b"a\r\nb");
        assert_eq!(dot_stuff(b"a\r\nb"), b"a\r\nb");
    }

    #[test]
    fn end_of_data_does_not_double_the_final_crlf() {
        assert_eq!(end_of_data(b"hi\r\n"), b".\r\n");
        assert_eq!(end_of_data(b"hi"), b"\r\n.\r\n");
        assert_eq!(end_of_data(b""), b".\r\n");
    }

    #[test]
    fn auth_mechanisms_parses_both_forms() {
        let caps = vec!["SIZE 100".to_string(), "AUTH LOGIN PLAIN".to_string()];
        assert_eq!(auth_mechanisms(&caps).unwrap(), vec!["LOGIN", "PLAIN"]);
        let caps = vec!["AUTH=LOGIN".to_string()];
        assert_eq!(auth_mechanisms(&caps).unwrap(), vec!["LOGIN"]);
        let caps = vec!["AUTHX FOO".to_string(), "8BITMIME".to_string()];
        assert!(auth_mechanisms(&caps).is_none());
    }

    /// Scripted SMTP server on loopback driving the production [`send`].
    /// `ehlo_caps` are the EHLO capability lines; `rcpt_code` answers RCPT.
    /// Returns the port and a handle yielding everything the client sent.
    fn mock_smtp(
        ehlo_caps: &'static [&'static str],
        rcpt_code: u16,
    ) -> (u16, std::thread::JoinHandle<String>) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            let mut w = s.try_clone().unwrap();
            let mut r = BufReader::new(s);
            let mut log = String::new();
            w.write_all(b"220 hi\r\n").unwrap();
            let mut in_data = false;
            loop {
                let mut line = String::new();
                if r.read_line(&mut line).unwrap_or(0) == 0 {
                    return log;
                }
                log.push_str(&line);
                if in_data {
                    if line == ".\r\n" {
                        in_data = false;
                        w.write_all(b"250 queued\r\n").unwrap();
                    }
                    continue;
                }
                let reply = match &line[..4.min(line.len())] {
                    "EHLO" => {
                        let mut s = String::from("250-mock\r\n");
                        for c in ehlo_caps {
                            s.push_str(&format!("250-{c}\r\n"));
                        }
                        s.push_str("250 OK\r\n");
                        s
                    }
                    "AUTH" => "235 ok\r\n".into(),
                    "MAIL" => "250 ok\r\n".into(),
                    "RCPT" => format!("{rcpt_code} ok\r\n"),
                    "DATA" => {
                        in_data = true;
                        "354 go\r\n".into()
                    }
                    "QUIT" => {
                        w.write_all(b"221 bye\r\n").unwrap();
                        return log;
                    }
                    _ => "500 ?\r\n".into(),
                };
                w.write_all(reply.as_bytes()).unwrap();
            }
        });
        (port, h)
    }

    fn run_send(port: u16, body: &[u8]) -> Result<()> {
        let url = Url::parse(&format!("smtp://127.0.0.1:{port}")).unwrap();
        let rcpts = vec!["to@example.com".to_string()];
        let opts = SmtpOptions {
            from: "me@example.com",
            rcpts: &rcpts,
            user: Some("u"),
            pass: Some("p"),
        };
        send(&url, body, &opts, &NetConfig::default())
    }

    #[test]
    fn no_auth_capability_means_no_credentials_sent() {
        // A server hiding AUTH (e.g. until STARTTLS) must not receive them.
        let (port, h) = mock_smtp(&["SIZE 1000"], 250);
        run_send(port, b"hi\r\n").unwrap();
        let log = h.join().unwrap();
        assert!(!log.contains("AUTH"), "{log}");
        assert!(log.contains("MAIL FROM:<me@example.com>"));
    }

    #[test]
    fn advertised_plain_is_used_and_251_rcpt_accepted() {
        let (port, h) = mock_smtp(&["AUTH LOGIN PLAIN"], 251);
        run_send(port, b"line\r\n").unwrap();
        let log = h.join().unwrap();
        assert!(log.contains("AUTH PLAIN "), "{log}");
        // Body already ends in CRLF: only ".\r\n" follows, no blank line.
        assert!(log.contains("line\r\n.\r\n"), "{log:?}");
        assert!(!log.contains("line\r\n\r\n.\r\n"), "{log:?}");
    }

    #[test]
    fn rejected_rcpt_fails() {
        let (port, h) = mock_smtp(&[], 550);
        assert!(run_send(port, b"x").is_err());
        drop(h);
    }

    #[test]
    fn reject_ctl_blocks_crlf() {
        assert!(reject_ctl("a@b\r\nDATA", "mail-from").is_err());
        assert!(reject_ctl("a@b.com", "mail-from").is_ok());
    }

    /// Minimal Read+Write transport for `read_reply`: replays a fixed script on
    /// reads and records writes (so tests can assert the command flow).
    struct MockIo {
        to_read: io::Cursor<Vec<u8>>,
        written: Vec<u8>,
    }
    impl MockIo {
        fn new(script: &[u8]) -> Self {
            Self {
                to_read: io::Cursor::new(script.to_vec()),
                written: Vec::new(),
            }
        }
        fn sent(&self) -> String {
            String::from_utf8_lossy(&self.written).into_owned()
        }
    }
    impl Read for MockIo {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.to_read.read(buf)
        }
    }
    impl Write for MockIo {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn read_reply_parses_multiline() {
        let io = MockIo::new(b"250-first\r\n250 second\r\n");
        let (code, text) = read_reply(&mut BufReader::new(io)).unwrap();
        assert_eq!(code, 250);
        assert_eq!(text, "first\nsecond");
    }

    #[test]
    fn read_reply_aborts_on_unbounded_single_line() {
        // A newline-less line larger than the 64 KiB cap (e.g. a hostile
        // greeting) must error rather than grow the buffer without limit.
        let data = vec![b'2'; 64 * 1024 + 1024];
        let io = MockIo::new(&data);
        match read_reply(&mut BufReader::new(io)) {
            Err(Error::BadResponse(m)) => assert!(m.contains("64 KiB"), "got {m}"),
            other => panic!("expected BadResponse(64 KiB), got {other:?}"),
        }
    }

    // -- require-TLS enforcement (curl --ssl-reqd) ------------------------

    #[test]
    fn require_tls_ok_passes_when_upgraded_or_disabled() {
        // Disabled: plaintext is fine.
        assert!(require_tls_ok(false, true).is_ok());
        // Enabled but the connection is TLS (STARTTLS done / smtps): fine.
        assert!(require_tls_ok(true, false).is_ok());
    }

    #[test]
    fn require_tls_errors_on_plaintext_before_auth() {
        // EHLO against a server that does NOT advertise STARTTLS, then the
        // require-TLS gate. The gate must reject before any AUTH/MAIL is sent.
        let mut io = BufReader::new(MockIo::new(
            b"250-mail.example.com\r\n250 SIZE 10240000\r\n",
        ));
        let caps = ehlo(&mut io, "client.example").expect("ehlo");
        assert!(
            !caps.iter().any(|c| c == "STARTTLS"),
            "server has no STARTTLS"
        );
        // Connection is still plaintext → require_tls must fail here.
        match require_tls_ok(true, true) {
            Err(Error::BadResponse(m)) => assert!(m.contains("TLS required"), "got {m}"),
            other => panic!("expected TLS required error, got {other:?}"),
        }
        // Only EHLO was written — no AUTH/MAIL/RCPT leaked onto plaintext.
        let sent = io.get_ref().sent();
        assert!(sent.contains("EHLO client.example\r\n"), "{sent:?}");
        assert!(!sent.contains("AUTH"), "no AUTH must be sent: {sent:?}");
        assert!(
            !sent.contains("MAIL FROM"),
            "no MAIL must be sent: {sent:?}"
        );
    }
}

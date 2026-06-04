//! SMTP and SMTPS support — sending mail.
//!
//! Specs: RFC 5321 (SMTP), RFC 3207 (STARTTLS), RFC 4954 (AUTH), RFC 4616
//! (SASL PLAIN), RFC 8314 (implicit TLS on 465 for `smtps`).
//!
//! URLs: `smtp://host[:port]` / `smtps://host[:port]`. The envelope sender and
//! recipients come from `--mail-from` / `--mail-rcpt`, and the message body
//! from `-T file` or `-d` (curl's model). This is a deliberately small subset:
//! EHLO, optional STARTTLS, optional AUTH PLAIN/LOGIN, then MAIL/RCPT/DATA.

use std::io::{self, BufRead, BufReader, Read, Write};

use crate::error::{Error, Result};
use crate::net::{NetConfig, NetStream};
use crate::tls::{connect_over, TlsStream};
use crate::url::Url;
use crate::websocket::base64_encode;

/// Options for an SMTP send (envelope + optional credentials).
pub struct SmtpOptions<'a> {
    pub from: &'a str,
    pub rcpts: &'a [String],
    pub user: Option<&'a str>,
    pub pass: Option<&'a str>,
}

/// Read+Write transport, plain or TLS, with in-place STARTTLS upgrade
/// (mirrors `imap::Stream`).
enum Stream {
    Plain(Box<dyn NetStream>),
    Tls(Box<TlsStream<Box<dyn NetStream>>>),
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read(buf),
            Stream::Tls(s) => s.read(buf),
        }
    }
}
impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.write(buf),
            Stream::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Plain(s) => s.flush(),
            Stream::Tls(s) => s.flush(),
        }
    }
}

/// Reject CR/LF/NUL and other control bytes in a URL/envelope-derived value so
/// it can't smuggle extra SMTP commands onto the control connection.
fn reject_ctl(s: &str, what: &str) -> Result<()> {
    if let Some(b) = s.bytes().find(|b| *b < 0x20 || *b == 0x7f) {
        return Err(Error::BadResponse(format!(
            "smtp: {what} contains illegal control byte {b:#04x}"
        )));
    }
    Ok(())
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
    let stream = if url.scheme == "smtps" {
        Stream::Tls(Box::new(connect_over(tcp, &url.host)?))
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
        if !io.buffer().is_empty() {
            return Err(Error::BadResponse(
                "smtp: server sent data after STARTTLS before TLS (injection)".into(),
            ));
        }
        let plain = match io.into_inner() {
            Stream::Plain(s) => s,
            _ => {
                return Err(Error::BadResponse(
                    "smtp: STARTTLS on non-plain stream".into(),
                ))
            }
        };
        let tls = connect_over(plain, &url.host)?;
        io = BufReader::new(Stream::Tls(Box::new(tls)));
        caps = ehlo(&mut io, &url.host)?;
    }

    // AUTH, if credentials were supplied.
    if let (Some(user), Some(pass)) = (opts.user, opts.pass) {
        authenticate(&mut io, &caps, user, pass)?;
    }

    // Envelope.
    send_line(&mut io, &format!("MAIL FROM:<{}>", opts.from))?;
    expect(&mut io, 250, "MAIL FROM")?;
    for r in opts.rcpts {
        send_line(&mut io, &format!("RCPT TO:<{r}>"))?;
        expect(&mut io, 250, "RCPT TO")?;
    }

    // DATA + dot-stuffed body terminated by CRLF "." CRLF.
    send_line(&mut io, "DATA")?;
    expect(&mut io, 354, "DATA")?;
    let payload = dot_stuff(body);
    {
        let w = io.get_mut();
        w.write_all(&payload)?;
        w.write_all(b"\r\n.\r\n")?;
        w.flush()?;
    }
    expect(&mut io, 250, "end of DATA")?;

    let _ = send_line(&mut io, "QUIT");
    let _ = read_reply(&mut io);
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

fn authenticate<R: Read + Write>(
    io: &mut BufReader<R>,
    caps: &[String],
    user: &str,
    pass: &str,
) -> Result<()> {
    let auth_line = caps.iter().find(|c| c.starts_with("AUTH"));
    let supports = |m: &str| auth_line.is_some_and(|l| l.contains(m));
    if supports("PLAIN") || auth_line.is_none() {
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
    let mut text = String::new();
    let mut total = 0usize;
    loop {
        let mut line = String::new();
        let n = io.read_line(&mut line)?;
        if n == 0 {
            return Err(Error::UnexpectedEof);
        }
        total += n;
        if total > 64 * 1024 {
            return Err(Error::BadResponse("smtp: reply exceeds 64 KiB".into()));
        }
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

    #[test]
    fn dot_stuffing_and_crlf() {
        assert_eq!(dot_stuff(b".hidden\n"), b"..hidden\r\n");
        assert_eq!(dot_stuff(b"a\nb"), b"a\r\nb");
        assert_eq!(dot_stuff(b"a\r\nb"), b"a\r\nb");
    }

    #[test]
    fn reject_ctl_blocks_crlf() {
        assert!(reject_ctl("a@b\r\nDATA", "mail-from").is_err());
        assert!(reject_ctl("a@b.com", "mail-from").is_ok());
    }
}

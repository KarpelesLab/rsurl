//! IMAP and IMAPS support.
//!
//! Specs: RFC 9051 (IMAP4rev2), RFC 3501 (IMAP4rev1), RFC 8314 (implicit TLS
//! on port 993 for IMAPS), RFC 5092 (`imap:` URL scheme), RFC 2595 (STARTTLS
//! over IMAP), RFC 4616 (SASL `PLAIN`).
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
//! After the greeting we probe `CAPABILITY` (or read it from a greeting
//! `[CAPABILITY ...]` response code), use it to drive STARTTLS upgrade on a
//! plaintext `imap://` connection (re-issuing CAPABILITY afterwards per
//! RFC 2595), and pick an authentication mechanism: `AUTHENTICATE PLAIN`,
//! `AUTHENTICATE LOGIN`, or the plain `LOGIN` command (the latter only when
//! the server does not advertise `LOGINDISABLED`).
//!
//! Deferred: IDLE, search/sort, message sets beyond a single UID, namespace
//! handling, literal+ on the client side, mailbox name encoding (UTF-7/UTF-8
//! quoted string promotion), multi-line continuation requests, SASL mechanisms
//! beyond PLAIN/LOGIN (CRAM-MD5, SCRAM, XOAUTH2, ...).

use crate::net::NetStream;
use std::io::{self, Read, Write};

use crate::error::{Error, Result};
use crate::tls::{connect_over, TlsStream};
use crate::url::Url;
use crate::websocket::base64_encode;

/// Upper bound on a single server-declared IMAP literal (`{N}`). The size is
/// chosen by the server, and `read_exact` would otherwise `Vec::with_capacity`
/// and read that many bytes — an unbounded allocation / DoS vector. 64 MiB
/// matches the crate's other body caps (e.g. `rtsp`, `websocket`).
const MAX_LITERAL_BYTES: usize = 64 * 1024 * 1024;

/// Upper bound on a *whole* server response — the accumulated untagged text
/// plus every literal block. `MAX_LITERAL_BYTES` only caps a single literal,
/// so a server could still exhaust memory by streaming endless untagged lines
/// (or many sub-cap literals) before the tagged terminator. Cap the aggregate
/// at the same 64 MiB so a hostile/buggy server can't make us buffer forever.
const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

/// LOGIN/AUTHENTICATE (using userinfo or fall back to anonymous), SELECT the
/// mailbox from `url.path`, then either LIST mailboxes or FETCH a specific
/// message and return the raw RFC 5322 message bytes (or the LIST output).
pub fn fetch(url: &Url) -> Result<Vec<u8>> {
    fetch_with(url, &crate::net::NetConfig::default())
}

pub(crate) fn fetch_with(url: &Url, cfg: &crate::net::NetConfig) -> Result<Vec<u8>> {
    match url.scheme.as_str() {
        "imap" => {
            let sock = cfg.connect(&url.host, url.port)?;
            run(Stream::Plain(sock), url)
        }
        "imaps" => {
            let sock = cfg.connect(&url.host, url.port)?;
            let tls = connect_over(sock, &url.host)?;
            run(Stream::Tls(Box::new(tls)), url)
        }
        other => Err(Error::UnsupportedScheme(other.to_string())),
    }
}

/// Read+Write transport, either plain TCP or TLS-wrapped. Modelling it as an
/// enum (rather than a generic `S: Read + Write`) is what lets STARTTLS upgrade
/// the connection *in place*: we `std::mem::replace` the `Plain` arm with a
/// `Tls` arm wrapping the very same `TcpStream`.
///
/// `Tls` is boxed because the active TLS backend can be either purecrypto
/// (small) or rustls (~1 KiB), and clippy flags the resulting variant-size
/// mismatch against the bare `TcpStream` arm (mirrors `pop3::IoAdapter`).
enum Stream {
    Plain(Box<dyn NetStream>),
    Tls(Box<TlsStream<Box<dyn NetStream>>>),
    /// Transient state only ever observed inside [`Stream::start_tls`] while we
    /// move the inner stream out to hand it to the TLS handshake.
    Poisoned,
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read(buf),
            Stream::Tls(s) => s.read(buf),
            Stream::Poisoned => Err(io::Error::other("imap: stream poisoned")),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.write(buf),
            Stream::Tls(s) => s.write(buf),
            Stream::Poisoned => Err(io::Error::other("imap: stream poisoned")),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Plain(s) => s.flush(),
            Stream::Tls(s) => s.flush(),
            Stream::Poisoned => Err(io::Error::other("imap: stream poisoned")),
        }
    }
}

impl Stream {
    /// True for a plaintext (non-TLS) transport.
    fn is_plain(&self) -> bool {
        matches!(self, Stream::Plain(_))
    }

    /// Upgrade a plaintext connection to TLS in place (RFC 2595 STARTTLS). The
    /// existing TCP stream is handed to [`connect_over`] verifying `host` as the
    /// SNI / certificate name, exactly as `imaps://` does. No-op (and an error)
    /// if the connection is already TLS.
    fn start_tls(&mut self, host: &str) -> Result<()> {
        let plain = match std::mem::replace(self, Stream::Poisoned) {
            Stream::Plain(s) => s,
            // Restore and bail: nothing to upgrade.
            other => {
                *self = other;
                return Err(Error::BadResponse(
                    "imap: STARTTLS requested on a non-plaintext connection".into(),
                ));
            }
        };
        let tls = connect_over(plain, host)?;
        *self = Stream::Tls(Box::new(tls));
        Ok(())
    }
}

fn run(mut sock: Stream, url: &Url) -> Result<Vec<u8>> {
    let mut buf = LineReader::new();

    // Read the unsolicited greeting. Must start with `* OK` (or `* PREAUTH`,
    // in which case the session is already authenticated).
    let greeting = buf.read_response(&mut sock, "*")?;
    let first = greeting.lines().next().unwrap_or("");
    if !first.starts_with("* OK") && !first.starts_with("* PREAUTH") {
        return Err(Error::BadResponse(format!(
            "imap greeting was not OK: {first}"
        )));
    }
    let preauth = first.starts_with("* PREAUTH");

    let mut tagger = Tagger::new();

    // CAPABILITY discovery. The greeting may carry it inline as a
    // `[CAPABILITY ...]` response code; otherwise ask explicitly.
    let mut caps = parse_capability_code(first)
        .or_else(|| parse_capability_line(&greeting))
        .map(Caps::from_tokens)
        .unwrap_or_default();
    if caps.is_empty() {
        caps = request_capability(&mut sock, &mut buf, &mut tagger)?;
    }

    // STARTTLS upgrade for plaintext connections that advertise it (RFC 2595).
    if sock.is_plain() && caps.has("STARTTLS") {
        let tag = tagger.next();
        sock.write_all(format!("{tag} STARTTLS\r\n").as_bytes())?;
        sock.flush()?;
        let resp = buf.read_response(&mut sock, &tag)?;
        require_ok(&resp, &tag, "STARTTLS")?;
        // Security (CVE-2011-0411 class STARTTLS plaintext injection): the
        // `LineReader` buffers socket reads in chunks, so any bytes a MITM
        // pipelines *after* the STARTTLS `OK` line are still sitting in the
        // buffer. They were received as PLAINTEXT before the handshake; reading
        // them after the upgrade would treat attacker-staged data as trusted
        // post-TLS server responses. Discarding is unsafe — abort instead.
        if !buf.is_clear() {
            return Err(Error::BadResponse(
                "STARTTLS: server pipelined data before TLS handshake".into(),
            ));
        }
        // Tagged OK means the server is ready; everything after is TLS.
        sock.start_tls(&url.host)?;
        // RFC 2595: discard the pre-TLS capability list and re-probe, since
        // capabilities (e.g. LOGINDISABLED, AUTH=*) commonly change post-TLS.
        caps = request_capability(&mut sock, &mut buf, &mut tagger)?;
    }

    // Authenticate, if we have credentials and aren't already PREAUTH.
    if !preauth {
        if let Some(userinfo) = url.userinfo.as_deref() {
            let (user, pass) = split_userinfo(userinfo);
            // Security: never interpolate URL-derived control bytes into a
            // command (CRLF injection / command smuggling). Credentials are
            // never logged.
            reject_ctl(user, "imap user")?;
            reject_ctl(pass, "imap password")?;
            authenticate(&mut sock, &mut buf, &mut tagger, &caps, user, pass)?;
        }
    }

    let (mailbox, uid) = parse_path(&url.path);
    if let Some(mbox) = mailbox.as_deref() {
        reject_ctl(mbox, "imap mailbox")?;
    }

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

/// Issue `CAPABILITY` and parse the untagged `* CAPABILITY ...` reply.
fn request_capability<S: Read + Write>(
    sock: &mut S,
    buf: &mut LineReader,
    tagger: &mut Tagger,
) -> Result<Caps> {
    let tag = tagger.next();
    sock.write_all(format!("{tag} CAPABILITY\r\n").as_bytes())?;
    sock.flush()?;
    let resp = buf.read_response(sock, &tag)?;
    require_ok(&resp, &tag, "CAPABILITY")?;
    Ok(parse_capability_line(&resp)
        .map(Caps::from_tokens)
        .unwrap_or_default())
}

/// Authentication-mechanism selection, mirroring curl's preference order.
///
/// The plaintext `LOGIN` command is only used when the server does not
/// advertise `LOGINDISABLED` — and is never attempted when `LOGINDISABLED` is
/// present (RFC 3501 §6.2.3), which a compliant server sets on any connection
/// where cleartext `LOGIN` would be unsafe (i.e. before STARTTLS).
#[derive(Debug, PartialEq, Eq)]
enum AuthMethod {
    /// `AUTHENTICATE PLAIN` with the RFC 4616 initial response.
    SaslPlain,
    /// `AUTHENTICATE LOGIN` across continuation prompts.
    SaslLogin,
    /// The plain `LOGIN` command.
    LoginCommand,
}

/// Pick an auth method from the advertised capabilities. Returns `None` if the
/// server leaves us with no usable mechanism (e.g. only `LOGINDISABLED` and no
/// SASL we support).
fn choose_auth(caps: &Caps) -> Option<AuthMethod> {
    if caps.has("AUTH=PLAIN") {
        return Some(AuthMethod::SaslPlain);
    }
    if caps.has("AUTH=LOGIN") {
        return Some(AuthMethod::SaslLogin);
    }
    if caps.has("LOGINDISABLED") {
        // No SASL we support, and the cleartext LOGIN command is forbidden.
        return None;
    }
    Some(AuthMethod::LoginCommand)
}

fn authenticate<S: Read + Write>(
    sock: &mut S,
    buf: &mut LineReader,
    tagger: &mut Tagger,
    caps: &Caps,
    user: &str,
    pass: &str,
) -> Result<()> {
    match choose_auth(caps) {
        Some(AuthMethod::SaslPlain) => auth_plain(sock, buf, tagger, user, pass),
        Some(AuthMethod::SaslLogin) => auth_login_sasl(sock, buf, tagger, user, pass),
        Some(AuthMethod::LoginCommand) => login_command(sock, buf, tagger, user, pass),
        None => Err(Error::BadResponse(
            "imap: server offers no usable authentication mechanism \
             (LOGINDISABLED and no AUTH=PLAIN/LOGIN); a STARTTLS/imaps \
             connection may be required"
                .into(),
        )),
    }
}

/// `AUTHENTICATE PLAIN` with an initial response (RFC 4616): the SASL message
/// is `authzid \0 authcid \0 passwd`; we send an empty authzid, so the cleartext
/// is `\0user\0pass`, base64-encoded.
fn auth_plain<S: Read + Write>(
    sock: &mut S,
    buf: &mut LineReader,
    tagger: &mut Tagger,
    user: &str,
    pass: &str,
) -> Result<()> {
    let tag = tagger.next();
    let initial = sasl_plain_initial(user, pass);
    // We send the initial response on the same line (IMAP4rev2 / SASL-IR). This
    // line carries credentials — never log it.
    let cmd = format!("{tag} AUTHENTICATE PLAIN {initial}\r\n");
    sock.write_all(cmd.as_bytes())?;
    sock.flush()?;
    let resp = buf.read_response(sock, &tag)?;
    require_ok(&resp, &tag, "AUTHENTICATE PLAIN")
}

/// `AUTHENTICATE LOGIN` (non-standard but widely supported): the server sends
/// two base64 continuation prompts (conventionally "Username:" then
/// "Password:"); we answer each with the base64 of the username then password.
fn auth_login_sasl<S: Read + Write>(
    sock: &mut S,
    buf: &mut LineReader,
    tagger: &mut Tagger,
    user: &str,
    pass: &str,
) -> Result<()> {
    let tag = tagger.next();
    sock.write_all(format!("{tag} AUTHENTICATE LOGIN\r\n").as_bytes())?;
    sock.flush()?;

    // First continuation request → send base64(username).
    let cont = buf.read_response(sock, &tag)?;
    if is_tagged_done(&cont, &tag) {
        // Server completed/failed without prompting (unexpected for LOGIN).
        return require_ok(&cont, &tag, "AUTHENTICATE LOGIN");
    }
    sock.write_all(format!("{}\r\n", base64_encode(user.as_bytes())).as_bytes())?;
    sock.flush()?;

    // Second continuation request → send base64(password).
    let cont = buf.read_response(sock, &tag)?;
    if is_tagged_done(&cont, &tag) {
        return require_ok(&cont, &tag, "AUTHENTICATE LOGIN");
    }
    sock.write_all(format!("{}\r\n", base64_encode(pass.as_bytes())).as_bytes())?;
    sock.flush()?;

    let resp = buf.read_response(sock, &tag)?;
    require_ok(&resp, &tag, "AUTHENTICATE LOGIN")
}

/// The classic `LOGIN <user> <pass>` command (RFC 3501 §6.2.3).
fn login_command<S: Read + Write>(
    sock: &mut S,
    buf: &mut LineReader,
    tagger: &mut Tagger,
    user: &str,
    pass: &str,
) -> Result<()> {
    let tag = tagger.next();
    let cmd = format!(
        "{tag} LOGIN {} {}\r\n",
        quote_imap_string(user),
        quote_imap_string(pass)
    );
    sock.write_all(cmd.as_bytes())?;
    sock.flush()?;
    let resp = buf.read_response(sock, &tag)?;
    require_ok(&resp, &tag, "LOGIN")
}

/// Build the base64 of the RFC 4616 PLAIN initial response, `\0user\0pass`.
fn sasl_plain_initial(user: &str, pass: &str) -> String {
    let mut raw = Vec::with_capacity(user.len() + pass.len() + 2);
    raw.push(0);
    raw.extend_from_slice(user.as_bytes());
    raw.push(0);
    raw.extend_from_slice(pass.as_bytes());
    base64_encode(&raw)
}

/// True if `resp`'s final line is the tagged completion for `tag` (i.e. not a
/// `+ ...` continuation request).
fn is_tagged_done(resp: &str, tag: &str) -> bool {
    let last = resp.lines().rev().find(|l| !l.is_empty()).unwrap_or("");
    last.starts_with(&format!("{tag} ")) || last == tag
}

/// Parsed, normalized IMAP capability set. Stored uppercased so lookups are
/// case-insensitive (RFC 9051 capability names are case-insensitive).
#[derive(Default)]
struct Caps {
    set: Vec<String>,
}

impl Caps {
    fn from_tokens<I, S>(tokens: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let set = tokens
            .into_iter()
            .map(|t| t.as_ref().to_ascii_uppercase())
            .filter(|t| !t.is_empty())
            .collect();
        Self { set }
    }

    fn has(&self, cap: &str) -> bool {
        let needle = cap.to_ascii_uppercase();
        self.set.contains(&needle)
    }

    fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}

/// Pull capability tokens out of a `[CAPABILITY ...]` response code embedded in
/// a line (e.g. the greeting `* OK [CAPABILITY IMAP4rev2 STARTTLS] ready`).
fn parse_capability_code(line: &str) -> Option<Vec<String>> {
    let start = line.find('[')?;
    let end = line[start..].find(']')? + start;
    let inside = &line[start + 1..end];
    let mut toks = inside.split_whitespace();
    if !toks.next()?.eq_ignore_ascii_case("CAPABILITY") {
        return None;
    }
    let caps: Vec<String> = toks.map(|s| s.to_string()).collect();
    if caps.is_empty() {
        None
    } else {
        Some(caps)
    }
}

/// Pull capability tokens out of an untagged `* CAPABILITY ...` line anywhere in
/// `resp`.
fn parse_capability_line(resp: &str) -> Option<Vec<String>> {
    for line in resp.lines() {
        if let Some(rest) = line.strip_prefix("* ") {
            let mut toks = rest.split_whitespace();
            if let Some(first) = toks.next() {
                if first.eq_ignore_ascii_case("CAPABILITY") {
                    let caps: Vec<String> = toks.map(|s| s.to_string()).collect();
                    if !caps.is_empty() {
                        return Some(caps);
                    }
                }
            }
        }
    }
    None
}

fn select_mailbox(
    sock: &mut Stream,
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

/// Reject a URL-derived string containing CR, LF, NUL, or any other ASCII
/// control byte before it's interpolated into an IMAP command. This blocks
/// CRLF/command injection through the userinfo or mailbox name. `what` names
/// the field for the error message — note credentials themselves are never
/// echoed.
fn reject_ctl(s: &str, what: &str) -> Result<()> {
    if let Some(b) = s.bytes().find(|b| *b < 0x20 || *b == 0x7f) {
        return Err(Error::BadResponse(format!(
            "imap: {what} contains illegal control byte {b:#04x}"
        )));
    }
    Ok(())
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

    /// True when no unconsumed bytes remain in the internal buffer. Used to
    /// detect a STARTTLS buffered-plaintext injection (CVE-2011-0411 class):
    /// any bytes a MITM pipelines after the STARTTLS `OK` would otherwise sit
    /// in `self.buf` and be read — as trusted plaintext — after the TLS
    /// upgrade. The caller must verify this is clear before `start_tls`.
    fn is_clear(&self) -> bool {
        self.buf.is_empty()
    }

    /// Read raw bytes until we have at least one complete CRLF-terminated
    /// line in `self.buf`, then pop it (without the trailing CRLF). Returns
    /// an empty string + error if the socket closes mid-line.
    fn read_line<S: Read>(&mut self, sock: &mut S) -> Result<String> {
        let mut tmp = [0u8; 4096];
        // How far into `self.buf` we've already scanned for CRLF. Avoids
        // re-scanning the whole accumulation on every read (otherwise a long
        // line would make `read_line` O(n^2)); only the freshly-read tail is
        // examined, backing up one byte so a CRLF straddling two reads is seen.
        let mut scanned = 0usize;
        loop {
            if let Some(rel) = find_crlf(&self.buf[scanned..]) {
                let pos = scanned + rel;
                let line_bytes: Vec<u8> = self.buf.drain(..pos + 2).collect();
                let without_crlf = &line_bytes[..line_bytes.len() - 2];
                return Ok(String::from_utf8_lossy(without_crlf).into_owned());
            }
            scanned = self.buf.len().saturating_sub(1);
            // Per-line bound: the aggregate `MAX_RESPONSE_BYTES` guard in
            // `read_response_with_literals` only runs between completed lines,
            // so a server that streams endless bytes with no CRLF would grow
            // `self.buf` without limit before that guard ever fires. Abort once
            // a single CRLF-less accumulation exceeds the response cap. (This
            // is distinct from literal byte reads, which go through
            // `read_exact` and are bounded by `MAX_LITERAL_BYTES`.)
            if self.buf.len() > MAX_RESPONSE_BYTES {
                return Err(Error::BadResponse(format!(
                    "imap: response line exceeds maximum {MAX_RESPONSE_BYTES} bytes"
                )));
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
    ///
    /// Also returns when the server sends a continuation request (a line
    /// starting with `+ `), which is how SASL `AUTHENTICATE` exchanges prompt
    /// for the next base64 chunk. The continuation line is included in `text`.
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
            // Aggregate cap across all untagged lines: a server that streams
            // endless lines without ever sending the tagged terminator would
            // otherwise grow `text` (and `self.buf`) without limit.
            if text.len() > MAX_RESPONSE_BYTES {
                return Err(Error::BadResponse(format!(
                    "imap: response exceeds maximum {MAX_RESPONSE_BYTES} bytes"
                )));
            }

            // If this line ends with a literal marker, slurp that many bytes
            // verbatim and treat them as a continuation of the same logical
            // response (so the tagged-line check below doesn't trip on them).
            if let Some(n) = extract_literal_size(&line) {
                if n > MAX_LITERAL_BYTES {
                    return Err(Error::BadResponse(format!(
                        "imap: literal size {n} exceeds maximum {MAX_LITERAL_BYTES}"
                    )));
                }
                // Bound the running total too: many individually-sub-cap
                // literals must not add up past the response cap.
                if text.len().saturating_add(n) > MAX_RESPONSE_BYTES {
                    return Err(Error::BadResponse(format!(
                        "imap: response exceeds maximum {MAX_RESPONSE_BYTES} bytes"
                    )));
                }
                let bytes = self.read_exact(sock, n)?;
                text.push_str(&String::from_utf8_lossy(&bytes));
                literals.push(bytes);
                // After a literal there's always more on the same logical
                // line — keep reading until we hit a real CRLF terminator.
                continue;
            }

            let trimmed = line.trim_end();
            // Continuation request (`+ ...` / bare `+`): the server is waiting
            // for our next line (SASL prompt). Hand control back to the caller.
            if trimmed == "+" || trimmed.starts_with("+ ") {
                return Ok((text, literals));
            }
            // Tagged response? Only a line that starts with our tag plus a
            // space (or is exactly the tag) ends the response.
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

    // -- control-byte rejection --------------------------------------------

    #[test]
    fn reject_ctl_flags_control_bytes() {
        assert!(reject_ctl("alice", "imap user").is_ok());
        assert!(reject_ctl("p@ss:word!", "imap password").is_ok());
        assert!(reject_ctl("INBOX/Sent", "imap mailbox").is_ok());
        assert!(reject_ctl("alice\r\na001 DELETE INBOX", "imap user").is_err());
        assert!(reject_ctl("alice\npass", "imap user").is_err());
        assert!(reject_ctl("alice\0", "imap user").is_err());
        assert!(reject_ctl("alice\x7f", "imap user").is_err()); // DEL
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

    // -- capability parsing ------------------------------------------------

    #[test]
    fn capability_code_from_greeting() {
        let line = "* OK [CAPABILITY IMAP4rev2 STARTTLS LOGINDISABLED] ready";
        let toks = parse_capability_code(line).expect("caps from code");
        let caps = Caps::from_tokens(toks);
        assert!(caps.has("IMAP4rev2"));
        assert!(caps.has("starttls")); // case-insensitive
        assert!(caps.has("LOGINDISABLED"));
        assert!(!caps.has("AUTH=PLAIN"));
    }

    #[test]
    fn capability_code_absent_or_wrong_keyword() {
        assert!(parse_capability_code("* OK ready, no brackets").is_none());
        assert!(parse_capability_code("* OK [UIDVALIDITY 1] hi").is_none());
        assert!(parse_capability_code("* OK [CAPABILITY] empty").is_none());
    }

    #[test]
    fn capability_line_parsed() {
        let resp = "* CAPABILITY IMAP4rev1 AUTH=PLAIN AUTH=LOGIN IDLE\r\n\
                    a001 OK CAPABILITY completed\r\n";
        let caps = Caps::from_tokens(parse_capability_line(resp).expect("caps"));
        assert!(caps.has("IMAP4rev1"));
        assert!(caps.has("AUTH=PLAIN"));
        assert!(caps.has("AUTH=LOGIN"));
        assert!(caps.has("IDLE"));
        assert!(!caps.has("STARTTLS"));
    }

    #[test]
    fn capability_line_missing_returns_none() {
        let resp = "a001 OK CAPABILITY completed\r\n";
        assert!(parse_capability_line(resp).is_none());
    }

    // -- auth method selection ---------------------------------------------

    #[test]
    fn choose_auth_prefers_sasl_plain() {
        let caps = Caps::from_tokens(["AUTH=PLAIN", "AUTH=LOGIN", "LOGINDISABLED"]);
        assert_eq!(choose_auth(&caps), Some(AuthMethod::SaslPlain));
    }

    #[test]
    fn choose_auth_falls_back_to_sasl_login() {
        let caps = Caps::from_tokens(["AUTH=LOGIN", "LOGINDISABLED"]);
        assert_eq!(choose_auth(&caps), Some(AuthMethod::SaslLogin));
    }

    #[test]
    fn choose_auth_falls_back_to_login_command() {
        let caps = Caps::from_tokens(["IMAP4rev1", "IDLE"]);
        assert_eq!(choose_auth(&caps), Some(AuthMethod::LoginCommand));
    }

    #[test]
    fn choose_auth_login_disabled_without_sasl_is_none() {
        // No SASL we support, and cleartext LOGIN is forbidden → no method.
        let caps = Caps::from_tokens(["IMAP4rev1", "LOGINDISABLED"]);
        assert_eq!(choose_auth(&caps), None);
    }

    #[test]
    fn choose_auth_empty_caps_uses_login_command() {
        let caps = Caps::default();
        assert_eq!(choose_auth(&caps), Some(AuthMethod::LoginCommand));
    }

    // -- SASL PLAIN initial response ---------------------------------------

    #[test]
    fn sasl_plain_initial_is_nul_user_nul_pass_base64() {
        // RFC 4616: authzid \0 authcid \0 passwd, empty authzid.
        // base64("\0alice\0secret")
        let got = sasl_plain_initial("alice", "secret");
        let expected = base64_encode(b"\x00alice\x00secret");
        assert_eq!(got, expected);
        // Sanity: decode-by-hand of the known vector.
        assert_eq!(got, "AGFsaWNlAHNlY3JldA==");
    }

    #[test]
    fn sasl_plain_initial_empty_password() {
        let got = sasl_plain_initial("bob", "");
        assert_eq!(got, base64_encode(b"\x00bob\x00"));
    }

    // -- full auth exchanges against a mock --------------------------------

    /// A mock IMAP transport: feeds scripted server bytes and records
    /// everything the client wrote, so we can assert on the command flow.
    struct MockIo {
        to_read: std::io::Cursor<Vec<u8>>,
        written: Vec<u8>,
    }
    impl MockIo {
        fn new(script: &[u8]) -> Self {
            Self {
                to_read: std::io::Cursor::new(script.to_vec()),
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
    fn auth_plain_sends_correct_initial_response() {
        let mut io = MockIo::new(b"a001 OK authenticated\r\n");
        let mut lr = LineReader::new();
        let mut tagger = Tagger::new();
        auth_plain(&mut io, &mut lr, &mut tagger, "alice", "secret").expect("auth plain ok");
        let sent = io.sent();
        assert!(
            sent.starts_with("a001 AUTHENTICATE PLAIN AGFsaWNlAHNlY3JldA=="),
            "unexpected client output: {sent:?}"
        );
    }

    #[test]
    fn auth_login_sasl_walks_two_prompts() {
        // Server prompts twice with `+` continuations, then accepts.
        let script = b"+ VXNlcm5hbWU6\r\n+ UGFzc3dvcmQ6\r\na001 OK welcome\r\n";
        let mut io = MockIo::new(script);
        let mut lr = LineReader::new();
        let mut tagger = Tagger::new();
        auth_login_sasl(&mut io, &mut lr, &mut tagger, "bob", "pw").expect("auth login ok");
        let sent = io.sent();
        // base64("bob") = Ym9i, base64("pw") = cHc=
        assert!(sent.contains("a001 AUTHENTICATE LOGIN\r\n"), "{sent:?}");
        assert!(sent.contains("Ym9i\r\n"), "username b64 missing: {sent:?}");
        assert!(sent.contains("cHc=\r\n"), "password b64 missing: {sent:?}");
    }

    #[test]
    fn read_response_aborts_on_endless_untagged_lines() {
        // A server that streams untagged lines and never sends the tagged
        // terminator must be cut off at MAX_RESPONSE_BYTES rather than
        // buffered forever. Build just over the cap from short untagged lines.
        let line = b"* 1 FETCH (UID 1)\r\n"; // 19 bytes
        let n = MAX_RESPONSE_BYTES / line.len() + 2;
        let mut script = Vec::with_capacity(n * line.len());
        for _ in 0..n {
            script.extend_from_slice(line);
        }
        // No `a001 OK ...` terminator.
        let mut io = MockIo::new(&script);
        let mut lr = LineReader::new();
        match lr.read_response_with_literals(&mut io, "a001") {
            Err(Error::BadResponse(m)) => assert!(m.contains("maximum"), "got {m}"),
            other => panic!("expected BadResponse(maximum), got {other:?}"),
        }
    }

    #[test]
    fn read_line_aborts_on_endless_crlf_less_stream() {
        // A server that streams bytes with no CRLF would otherwise grow
        // `LineReader::buf` without limit, since the aggregate cap only runs
        // between completed lines. The per-line bound must abort first.
        let data = vec![b'x'; MAX_RESPONSE_BYTES + 4096];
        let mut io = MockIo::new(&data);
        let mut lr = LineReader::new();
        match lr.read_line(&mut io) {
            Err(Error::BadResponse(m)) => assert!(m.contains("maximum"), "got {m}"),
            other => panic!("expected BadResponse(maximum), got {other:?}"),
        }
    }

    #[test]
    fn read_response_aborts_when_literals_sum_past_cap() {
        // A literal declared at exactly MAX_LITERAL_BYTES passes the
        // per-literal check (`n > MAX` is false at equality), but the untagged
        // line text already pushed brings the running total past
        // MAX_RESPONSE_BYTES — the aggregate guard must reject it before we
        // read that huge literal body off the wire.
        let big = MAX_LITERAL_BYTES;
        let script = format!("* 1 FETCH (BODY[] {{{big}}}\r\n");
        let mut io = MockIo::new(script.as_bytes());
        let mut lr = LineReader::new();
        match lr.read_response_with_literals(&mut io, "a001") {
            Err(Error::BadResponse(m)) => assert!(m.contains("maximum"), "got {m}"),
            other => panic!("expected BadResponse(maximum), got {other:?}"),
        }
    }

    #[test]
    fn login_command_quotes_and_sends() {
        let mut io = MockIo::new(b"a001 OK logged in\r\n");
        let mut lr = LineReader::new();
        let mut tagger = Tagger::new();
        login_command(&mut io, &mut lr, &mut tagger, "alice", "se cret").expect("login ok");
        assert_eq!(io.sent(), "a001 LOGIN \"alice\" \"se cret\"\r\n");
    }

    // -- STARTTLS decision logic (pre-upgrade) -----------------------------

    #[test]
    fn starttls_offered_drives_upgrade_decision() {
        // The decision to STARTTLS is "plaintext transport AND caps has
        // STARTTLS". We test the predicate directly.
        let caps = Caps::from_tokens(["IMAP4rev1", "STARTTLS", "LOGINDISABLED"]);
        assert!(caps.has("STARTTLS"));
        // Pre-TLS, LOGINDISABLED + no SASL means we must not try cleartext.
        assert_eq!(choose_auth(&caps), None);
    }

    #[test]
    fn starttls_command_flow_against_mock() {
        // Drive request_capability + the STARTTLS command exchange against a
        // mock, stopping right before the (real) TLS upgrade. We verify the
        // client emits CAPABILITY then STARTTLS and reads the tagged OKs.
        let script = b"* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED\r\n\
                       a001 OK CAPABILITY completed\r\n\
                       a002 OK Begin TLS negotiation now\r\n";
        let mut io = MockIo::new(script);
        let mut lr = LineReader::new();
        let mut tagger = Tagger::new();

        // request_capability is generic over Read+Write, so the mock drives the
        // real production code path here (not a test mirror).
        let caps = request_capability(&mut io, &mut lr, &mut tagger).expect("caps");
        assert!(caps.has("STARTTLS"));

        // Issue STARTTLS and confirm the tagged OK (the real code would then
        // call sock.start_tls()).
        let tag = tagger.next();
        io.write_all(format!("{tag} STARTTLS\r\n").as_bytes())
            .unwrap();
        let resp = lr.read_response(&mut io, &tag).expect("starttls resp");
        assert!(require_ok(&resp, &tag, "STARTTLS").is_ok());

        let sent = io.sent();
        assert!(sent.contains("a001 CAPABILITY\r\n"), "{sent:?}");
        assert!(sent.contains("a002 STARTTLS\r\n"), "{sent:?}");
    }

    #[test]
    fn starttls_rejects_pipelined_plaintext_injection() {
        // CVE-2011-0411 class: a MITM appends a forged response right after the
        // STARTTLS `OK`, in the same plaintext flight. After reading the OK
        // line, those leftover bytes remain buffered in the LineReader, so
        // `is_clear()` must be false and the production guard in `run()` aborts
        // the upgrade instead of trusting them post-TLS.
        let script = b"a001 OK Begin TLS negotiation now\r\n\
                       * CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n\
                       a002 OK injected\r\n";
        let mut src: &[u8] = script;
        let mut lr = LineReader::new();
        let resp = lr.read_response(&mut src, "a001").expect("starttls ok");
        assert!(require_ok(&resp, "a001", "STARTTLS").is_ok());
        // The forged bytes are still buffered — the guard must trip.
        assert!(
            !lr.is_clear(),
            "expected pipelined plaintext to remain buffered after STARTTLS OK"
        );
    }

    #[test]
    fn starttls_clear_when_server_waits_for_handshake() {
        // A conforming server sends nothing after the STARTTLS OK until the
        // TLS handshake, so the buffer is fully drained and `is_clear()` holds.
        let script = b"a001 OK Begin TLS negotiation now\r\n";
        let mut src: &[u8] = script;
        let mut lr = LineReader::new();
        let resp = lr.read_response(&mut src, "a001").expect("starttls ok");
        assert!(require_ok(&resp, "a001", "STARTTLS").is_ok());
        assert!(lr.is_clear(), "no pipelined data: reader must be clear");
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
    fn line_reader_returns_on_continuation() {
        // A `+` continuation request ends the read so the caller can respond.
        let wire = b"+ go ahead\r\n";
        let mut src: &[u8] = wire;
        let mut lr = LineReader::new();
        let resp = lr.read_response(&mut src, "a001").expect("cont");
        assert!(resp.starts_with("+ go ahead"));
        assert!(!is_tagged_done(&resp, "a001"));
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

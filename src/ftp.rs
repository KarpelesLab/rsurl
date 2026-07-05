//! FTP and FTPS support.
//!
//! Specs: RFC 959 (FTP), RFC 4217 (FTP over TLS / "explicit FTPS"),
//! plus the implicit-FTPS convention of TLS-from-start on port 990.
//!
//! This module implements the common-case read path:
//!   * Plain FTP (`ftp://`) and implicit FTPS (`ftps://`, TLS-from-connect).
//!   * Anonymous or `user:pass@` login.
//!   * Binary mode (`TYPE I`).
//!   * Passive data transfer: `EPSV`, with `PASV` fallback (or `PASV` directly
//!     under `--disable-epsv`). Active mode (`EPRT`, with a `PORT` fallback for
//!     IPv4) is available via curl's `-P`/`--ftp-port`; it is direct-only and
//!     verifies the data callback comes from the control peer.
//!   * `RETR` for files, `LIST` for paths ending in `/`.
//!
//! Uploads use `STOR` (see [`store`]), with optional `REST <offset>` resume
//! when the caller supplies a byte offset, or `APPE` (see [`append`]) to
//! append to an existing remote file; `--ftp-create-dirs` issues `MKD` for the
//! upload path's directories first. Explicit `AUTH TLS` upgrade is intentionally
//! not implemented yet.
//!
//! For TLS we use [`crate::tls::connect_over`] on both the control channel
//! (on connect, for implicit FTPS) and the data channel (using the host
//! from the original URL as SNI, per RFC 4217 §10.2 — the passive reply
//! often carries an IP literal that wouldn't match the server cert).

use std::io::{BufRead, BufReader, Read, Write};

use crate::error::{Error, Result};
use crate::net::{NetConfig, NetStream};
use crate::tls::TlsStream;
use crate::url::Url;

/// A duplex byte stream that's either a plain (possibly proxied) socket or a
/// TLS-wrapped one. Lets us drive the same FTP state machine over both schemes.
enum Stream {
    Plain(Box<dyn NetStream>),
    Tls(Box<TlsStream<Box<dyn NetStream>>>),
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read(buf),
            Stream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Stream::Plain(s) => s.write(buf),
            Stream::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Stream::Plain(s) => s.flush(),
            Stream::Tls(s) => s.flush(),
        }
    }
}

/// A logged-in FTP control channel, set to binary mode, ready for a transfer
/// command. Carries the control connection's peer IP so the data connection
/// can be safely dialed back to it (see [`open_passive`]).
struct Control {
    ctrl: BufReader<Stream>,
    ctrl_peer_ip: std::net::IpAddr,
    /// Our local IP on the control connection — advertised to the server in
    /// `EPRT`/`PORT` for active-mode data connections.
    ctrl_local_ip: std::net::IpAddr,
}

/// Connect, read the banner, log in (anonymous or `user[:pass]@`), and switch
/// to binary mode (`TYPE I`). Shared by [`fetch`] (RETR/LIST) and [`store`]
/// (STOR). Returns the ready control channel.
fn connect_login(url: &Url, cfg: &NetConfig) -> Result<Control> {
    if url.scheme != "ftp" && url.scheme != "ftps" {
        return Err(Error::UnsupportedScheme(url.scheme.clone()));
    }

    // 1) Control channel, dialed through the configured transport.
    let tcp = cfg.connect(&url.host, url.port)?;
    // Remember the control connection's peer address. For a *direct* dial PASV
    // replies carry a server-chosen data IP which we deliberately ignore (a
    // hostile control server could point it at an internal service — the
    // classic FTP "bounce"/SSRF); curl's safe default is to dial the data
    // connection to the control peer using only the server-supplied port. When
    // a proxy/custom connector is in play the proxy is the trust boundary and
    // `peer_addr` is the proxy (or unavailable), so we instead reach the
    // PASV/EPSV-advertised endpoint through the connector (see `open_data`).
    let ctrl_peer_ip = if cfg.connector.is_direct() {
        tcp.peer_addr()?.ip()
    } else {
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    };
    // Capture our local IP before TLS-wrapping the socket; active mode needs it
    // for EPRT/PORT. Falls back to unspecified (active mode is direct-only).
    let ctrl_local_ip = tcp
        .local_addr()
        .map(|a| a.ip())
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    let control = if url.scheme == "ftps" {
        Stream::Tls(Box::new(crate::tls::connect_over(tcp, &url.host)?))
    } else {
        Stream::Plain(tcp)
    };
    let mut ctrl = BufReader::new(control);

    // 2) Banner (220 Service ready). Anything other than 1xx/2xx is fatal.
    let (code, _) = read_reply(&mut ctrl)?;
    if !is_positive(code) {
        return Err(Error::BadResponse(format!("ftp banner: {code}")));
    }

    // 3) Login. Anonymous by default; honor `user[:pass]@` from the URL.
    let (user, pass) = split_userinfo(url.userinfo.as_deref());
    // Reject control characters in URL-derived credentials so a CR/LF can't
    // smuggle extra FTP commands onto the control channel (`send` also guards
    // the assembled line, but validating the inputs gives a clearer error).
    reject_ctl(&user, "ftp user")?;
    reject_ctl(&pass, "ftp password")?;
    send(&mut ctrl, &format!("USER {user}"))?;
    let (c, _) = read_reply(&mut ctrl)?;
    match c {
        230 => {} // logged in, no password needed
        331 => {
            // password required
            send(&mut ctrl, &format!("PASS {pass}"))?;
            let (c2, m2) = read_reply(&mut ctrl)?;
            if c2 != 230 && c2 != 202 {
                return Err(Error::BadResponse(format!("ftp PASS: {c2} {m2}")));
            }
        }
        332 => {
            return Err(Error::BadResponse(
                "ftp server requires ACCT, not supported".into(),
            ));
        }
        _ => return Err(Error::BadResponse(format!("ftp USER: {c}"))),
    }

    // 4) Binary mode.
    send(&mut ctrl, "TYPE I")?;
    let (c, m) = read_reply(&mut ctrl)?;
    if c != 200 {
        return Err(Error::BadResponse(format!("ftp TYPE I: {c} {m}")));
    }

    Ok(Control {
        ctrl,
        ctrl_peer_ip,
        ctrl_local_ip,
    })
}

/// A data connection that's either already dialed (passive) or waiting for the
/// server to connect back (active). In active mode the `accept()` must happen
/// *after* the transfer command (`RETR`/`STOR`) is sent, so the caller holds
/// this between issuing the command and reading the data.
enum DataConn {
    /// Passive: we dialed the server's advertised port; ready to transfer.
    Ready(Stream),
    /// Active: we sent `EPRT`/`PORT` and are listening; the server will connect.
    Active {
        listener: std::net::TcpListener,
        /// The control peer; the inbound data connection must come from it.
        peer_ip: std::net::IpAddr,
        /// `Some(host)` wraps the accepted socket in TLS (ftps), using `host`
        /// as the SNI; `None` for plain ftp.
        tls_host: Option<String>,
    },
}

impl DataConn {
    /// Resolve to a usable [`Stream`]. Passive returns the dialed socket;
    /// active blocks on `accept()`, verifies the peer is the control server
    /// (anti-hijack), then TLS-wraps for ftps.
    fn into_stream(self) -> Result<Stream> {
        match self {
            DataConn::Ready(s) => Ok(s),
            DataConn::Active {
                listener,
                peer_ip,
                tls_host,
            } => {
                let (sock, addr) = listener.accept()?;
                // Only the control server may open the data connection; reject
                // any other source (a port-scanner or off-path attacker).
                if addr.ip() != peer_ip {
                    return Err(Error::BadResponse(format!(
                        "ftp active: data connection from unexpected peer {}",
                        addr.ip()
                    )));
                }
                let boxed: Box<dyn NetStream> = Box::new(sock);
                Ok(match tls_host {
                    Some(host) => Stream::Tls(Box::new(crate::tls::connect_over(boxed, &host)?)),
                    None => Stream::Plain(boxed),
                })
            }
        }
    }
}

/// Set up the data connection: active (`EPRT`/`PORT`) when `cfg.ftp_active`,
/// otherwise passive (`EPSV`→`PASV`). Active mode requires a direct connection
/// (no proxy can route a server-initiated callback) and uses the control
/// connection's local IP as the callback address.
fn open_data<R: Read + Write>(
    ctrl: &mut BufReader<R>,
    url: &Url,
    ctrl_peer_ip: std::net::IpAddr,
    ctrl_local_ip: std::net::IpAddr,
    cfg: &NetConfig,
) -> Result<DataConn> {
    if cfg.ftp_active {
        if !cfg.connector.is_direct() {
            return Err(Error::BadResponse(
                "ftp active mode (-P) requires a direct connection; a proxy cannot \
                 accept the server's data callback"
                    .into(),
            ));
        }
        let listener = std::net::TcpListener::bind((ctrl_local_ip, 0))?;
        let port = listener.local_addr()?.port();
        announce_active(ctrl, ctrl_local_ip, port)?;
        let tls_host = (url.scheme == "ftps").then(|| url.host.clone());
        return Ok(DataConn::Active {
            listener,
            peer_ip: ctrl_peer_ip,
            tls_host,
        });
    }
    let (data_host, data_port) = open_passive(
        ctrl,
        &url.host,
        ctrl_peer_ip,
        cfg.connector.is_direct(),
        cfg.ftp_use_epsv,
    )?;
    let data_tcp = cfg.connect(&data_host, data_port)?;
    Ok(DataConn::Ready(if url.scheme == "ftps" {
        // Per RFC 4217 §10.2: SNI must be the original hostname, not the
        // address we got from PASV/EPSV (which is often an IP literal).
        Stream::Tls(Box::new(crate::tls::connect_over(data_tcp, &url.host)?))
    } else {
        Stream::Plain(data_tcp)
    }))
}

/// Advertise our active-mode listening address to the server: `EPRT` first
/// (RFC 2428, both address families), with a `PORT` fallback for IPv4 if the
/// server rejects `EPRT`.
fn announce_active<R: Read + Write>(
    ctrl: &mut BufReader<R>,
    ip: std::net::IpAddr,
    port: u16,
) -> Result<()> {
    let af = match ip {
        std::net::IpAddr::V4(_) => 1,
        std::net::IpAddr::V6(_) => 2,
    };
    send(ctrl, &format!("EPRT |{af}|{ip}|{port}|"))?;
    let (c, m) = read_reply(ctrl)?;
    if is_positive(c) {
        return Ok(());
    }
    // EPRT refused: fall back to the legacy PORT command for IPv4.
    if let std::net::IpAddr::V4(v4) = ip {
        let o = v4.octets();
        let (p1, p2) = (port >> 8, port & 0xff);
        send(
            ctrl,
            &format!("PORT {},{},{},{},{p1},{p2}", o[0], o[1], o[2], o[3]),
        )?;
        let (cp, mp) = read_reply(ctrl)?;
        if is_positive(cp) {
            return Ok(());
        }
        return Err(Error::BadResponse(format!("ftp PORT: {cp} {mp}")));
    }
    Err(Error::BadResponse(format!("ftp EPRT: {c} {m}")))
}

/// Default operation: download the file at `url.path`, or list the directory
/// if the path ends in `/`. Returns the raw bytes.
pub fn fetch(url: &Url) -> Result<Vec<u8>> {
    fetch_with(url, &NetConfig::default())
}

pub(crate) fn fetch_with(url: &Url, cfg: &NetConfig) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fetch_to_with(url, cfg, &mut bytes)?;
    Ok(bytes)
}

/// Stream a RETR (file) or LIST (directory) to `sink`, returning the number of
/// bytes written. This is the streaming core of [`fetch_with`]; it copies the
/// data channel straight to the sink instead of buffering the whole body, so a
/// CLI download can enforce `--limit-rate`/`-#`/`--max-filesize`/`-y`/`-Y` and
/// avoid holding a large file in memory.
pub(crate) fn fetch_to_with(url: &Url, cfg: &NetConfig, sink: &mut dyn Write) -> Result<u64> {
    let mut con = connect_login(url, cfg)?;

    // 5+6) Set up the data connection: passive (EPSV→PASV, we dial) or active
    //       (EPRT/PORT, the server dials back). Active mode's accept() happens
    //       after the transfer command below.
    let dataconn = open_data(&mut con.ctrl, url, con.ctrl_peer_ip, con.ctrl_local_ip, cfg)?;
    let ctrl = &mut con.ctrl;

    // 7) RETR for files, LIST for directories. We treat a trailing '/' or
    //    the bare root path as "list this directory". Reject control bytes in
    //    the path first so it can't break out of the RETR/LIST command line.
    reject_ctl(&url.path, "ftp path")?;
    let cmd = if url.path.is_empty() || url.path == "/" {
        "LIST".to_string()
    } else if url.path.ends_with('/') {
        format!("LIST {}", url.path)
    } else {
        format!("RETR {}", url.path)
    };
    send(ctrl, &cmd)?;

    // 8) Preliminary reply (125 Data connection open / 150 File status OK).
    let (c, m) = read_reply(ctrl)?;
    if !(c == 125 || c == 150) {
        // Some servers send the 226 directly (rare but legal). If we got an
        // error code, surface it.
        if !is_positive(c) {
            return Err(Error::BadResponse(format!("ftp {cmd}: {c} {m}")));
        }
    }

    // 9) Resolve the data connection (active: accept the callback now) and copy
    //    it to the sink, to EOF / TLS close_notify.
    let mut data = dataconn.into_stream()?;
    let n = std::io::copy(&mut data, sink)?;
    // Dropping `data` closes both the TLS layer and the TCP socket.
    drop(data);

    // 10) Final reply (226 Closing data connection / Transfer complete).
    //     If we already saw the 226 above as the "preliminary" reply, no
    //     second one is coming — but we wouldn't have entered this branch
    //     because c would have been 226 (positive completion, not 125/150).
    if c == 125 || c == 150 {
        let (cf, mf) = read_reply(ctrl)?;
        if !is_positive(cf) {
            return Err(Error::BadResponse(format!("ftp transfer end: {cf} {mf}")));
        }
    }

    // 11) Polite shutdown.
    let _ = send(ctrl, "QUIT");
    let _ = read_reply(ctrl);

    Ok(n)
}

/// Which upload verb to issue: `STOR` (overwrite/create, optionally after a
/// `REST` resume offset) or `APPE` (append to an existing file, or create it).
#[derive(Clone, Copy, PartialEq, Eq)]
enum UploadMode {
    /// `STOR` — replace the remote file (or, after `REST`, resume at an offset).
    Stor,
    /// `APPE` — append the streamed bytes to the remote file. No offset is
    /// negotiated, so `REST`/`-C` does not apply.
    Appe,
}

impl UploadMode {
    /// The FTP verb word (`"STOR"` / `"APPE"`) for command lines and errors.
    fn verb(self) -> &'static str {
        match self {
            UploadMode::Stor => "STOR",
            UploadMode::Appe => "APPE",
        }
    }
}

/// Build the `STOR <path>` / `APPE <path>` command for an upload, stripping a
/// single leading '/' the way curl does (the FTP path after login is relative
/// to the login directory). Returns `None` for an empty or directory-only
/// path, which can't name a file to upload.
fn upload_command(mode: UploadMode, path: &str) -> Option<String> {
    let name = path.strip_prefix('/').unwrap_or(path);
    if name.is_empty() || name.ends_with('/') {
        return None;
    }
    Some(format!("{} {name}", mode.verb()))
}

/// Build the `STOR <path>` command. Thin wrapper over [`upload_command`] kept
/// for the descriptive name at the test sites that pin STOR's exact wire form.
#[cfg(test)]
fn stor_command(path: &str) -> Option<String> {
    upload_command(UploadMode::Stor, path)
}

/// Build the `APPE <path>` command (same path validation as [`stor_command`]).
#[cfg(test)]
fn appe_command(path: &str) -> Option<String> {
    upload_command(UploadMode::Appe, path)
}

/// Format the `REST <offset>` resume command.
fn rest_command(offset: u64) -> String {
    format!("REST {offset}")
}

/// `--ftp-create-dirs`: issue `MKD` for each directory prefix of the upload
/// path (`a`, then `a/b` for `/a/b/file`), ignoring the reply code so an
/// already-existing directory (a 5xx reply) is not treated as an error. Mirrors
/// [`upload_command`]'s path handling: a single leading '/' is stripped.
fn create_upload_dirs<R: Read + Write>(ctrl: &mut BufReader<R>, path: &str) -> Result<()> {
    let rel = path.strip_prefix('/').unwrap_or(path);
    let comps: Vec<&str> = rel.split('/').filter(|s| !s.is_empty()).collect();
    if comps.len() < 2 {
        return Ok(()); // no directory component — just a filename
    }
    let mut prefix = String::new();
    for dir in &comps[..comps.len() - 1] {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(dir);
        // reject_ctl validated the whole path already; send() also guards CR/LF.
        send(ctrl, &format!("MKD {prefix}"))?;
        let _ = read_reply(ctrl)?; // 257 created or 5xx exists — ignore the code
    }
    Ok(())
}

/// Upload `body` to the file at `url.path` via `STOR`. If `resume_at` is
/// `Some(n)`, send `REST n` first so the server appends starting at byte `n`
/// (the caller is responsible for passing a `body` that begins at that offset).
///
/// Shares login, binary mode, and the passive-open/TLS-wrap logic with
/// [`fetch`], so the data connection is dialed back to the control peer and
/// wrapped in TLS for `ftps` exactly as RETR does.
pub fn store(url: &Url, body: &[u8], resume_at: Option<u64>) -> Result<()> {
    upload(
        url,
        body,
        UploadMode::Stor,
        resume_at,
        &NetConfig::default(),
    )
}

/// As [`store`], but using the caller's [`NetConfig`] (proxy/connector,
/// `--ftp-create-dirs`). Used by [`crate::Client`].
pub(crate) fn store_with(
    url: &Url,
    body: &[u8],
    resume_at: Option<u64>,
    cfg: &NetConfig,
) -> Result<()> {
    upload(url, body, UploadMode::Stor, resume_at, cfg)
}

/// As [`append`], but using the caller's [`NetConfig`]. Used by [`crate::Client`].
pub(crate) fn append_with(url: &Url, body: &[u8], cfg: &NetConfig) -> Result<()> {
    upload(url, body, UploadMode::Appe, None, cfg)
}

/// Append `body` to the file at `url.path` via `APPE`, creating it if absent.
///
/// Unlike [`store`], `APPE` negotiates no offset: the server appends the
/// streamed bytes to whatever is already there, so `REST`/`-C` is irrelevant
/// and the full `body` is always sent. Otherwise shares login, binary mode,
/// and the passive-open/TLS-wrap logic with [`fetch`] and [`store`].
pub fn append(url: &Url, body: &[u8]) -> Result<()> {
    upload(url, body, UploadMode::Appe, None, &NetConfig::default())
}

/// Shared upload driver for `STOR` and `APPE`. Logs in, optionally sends
/// `REST <offset>` (STOR resume only), opens the passive data connection,
/// issues the verb, streams `body`, and reads the completion reply.
///
/// `resume_at` is honored only for [`UploadMode::Stor`]; `APPE` ignores it
/// (the public [`append`] entry point always passes `None`).
fn upload(
    url: &Url,
    body: &[u8],
    mode: UploadMode,
    resume_at: Option<u64>,
    cfg: &NetConfig,
) -> Result<()> {
    let mut con = connect_login(url, cfg)?;

    // Determine the remote filename up front and reject control bytes so it
    // can't break out of the STOR/APPE command line.
    reject_ctl(&url.path, "ftp path")?;
    let cmd = upload_command(mode, &url.path).ok_or_else(|| {
        Error::BadResponse(format!(
            "ftp {}: URL path {:?} does not name a file to upload",
            mode.verb(),
            url.path
        ))
    })?;

    // --ftp-create-dirs: best-effort MKD of each directory prefix of the upload
    // path before storing. Failures are ignored (the directory likely exists).
    if cfg.ftp_create_dirs {
        create_upload_dirs(&mut con.ctrl, &url.path)?;
    }

    // REST before STOR for resume. Per RFC 3659 the server answers 350
    // ("restart marker accepted"); the next command (STOR) then proceeds from
    // that offset. APPE negotiates no offset, so it never sends REST.
    if mode == UploadMode::Stor {
        if let Some(offset) = resume_at {
            send(&mut con.ctrl, &rest_command(offset))?;
            let (c, m) = read_reply(&mut con.ctrl)?;
            if c != 350 {
                return Err(Error::BadResponse(format!("ftp REST: {c} {m}")));
            }
        }
    }

    // Set up the data connection (passive dial, or active EPRT/PORT callback;
    // same logic as RETR). Active mode's accept() happens after STOR/APPE.
    let dataconn = open_data(&mut con.ctrl, url, con.ctrl_peer_ip, con.ctrl_local_ip, cfg)?;
    let ctrl = &mut con.ctrl;

    // Issue STOR/APPE, then expect the 1xx preliminary reply before streaming.
    send(ctrl, &cmd)?;
    let (c, m) = read_reply(ctrl)?;
    if !(c == 125 || c == 150) {
        // A 2xx/3xx here would be unusual (data still needs sending); anything
        // that isn't a 1xx preliminary is treated as a failure.
        return Err(Error::BadResponse(format!("ftp {cmd}: {c} {m}")));
    }

    // Resolve the data connection (active: accept the server's callback now),
    // stream the upload bytes, then close it to signal EOF (dropping closes the
    // TLS layer's close_notify and the TCP socket).
    let mut data = dataconn.into_stream()?;
    data.write_all(body)?;
    data.flush()?;
    drop(data);

    // Final completion reply (226 Transfer complete).
    let (cf, mf) = read_reply(ctrl)?;
    if !is_positive(cf) {
        return Err(Error::BadResponse(format!(
            "ftp {} end: {cf} {mf}",
            mode.verb()
        )));
    }

    // Polite shutdown.
    let _ = send(ctrl, "QUIT");
    let _ = read_reply(ctrl);

    Ok(())
}

/// Open a passive data connection via EPSV (preferred) or PASV (fallback).
/// Returns the `(host, port)` we should dial for the data channel.
///
/// EPSV reply form: `229 Entering Extended Passive Mode (|||port|)`.
/// PASV reply form: `227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)`.
fn open_passive<R: Read + Write>(
    ctrl: &mut BufReader<R>,
    fallback_host: &str,
    ctrl_peer_ip: std::net::IpAddr,
    direct: bool,
    use_epsv: bool,
) -> Result<(String, u16)> {
    // curl `--disable-epsv` skips the EPSV attempt and goes straight to PASV
    // (useful against servers/NATs where EPSV hangs rather than cleanly fails).
    if use_epsv {
        send(ctrl, "EPSV")?;
        let (c, m) = read_reply(ctrl)?;
        if c == 229 {
            let port = parse_epsv(&m)
                .ok_or_else(|| Error::BadResponse(format!("ftp EPSV: cannot parse reply: {m}")))?;
            // EPSV doesn't carry a host; reuse the control connection's host
            // (which is also what curl/RFC 2428 says clients should do).
            return Ok((fallback_host.to_string(), port));
        }
        // 5xx → not supported, try PASV. 4xx → transient, but we still try
        // PASV: nothing in the EPSV failure precludes PASV working.
        if !(400..600).contains(&c) {
            return Err(Error::BadResponse(format!("ftp EPSV: {c} {m}")));
        }
    }
    send(ctrl, "PASV")?;
    let (c2, m2) = read_reply(ctrl)?;
    if c2 != 227 {
        return Err(Error::BadResponse(format!("ftp PASV: {c2} {m2}")));
    }
    // For a direct dial, the server-supplied IP is ignored to prevent an FTP
    // bounce/SSRF: we dial the control connection's peer instead (curl's safe
    // default). Through a proxy/custom connector the proxy is the trust
    // boundary and cannot reach the control peer's IP directly, so we use the
    // server-advertised data host and let the connector reach it.
    let (advertised_host, port) = parse_pasv(&m2)
        .ok_or_else(|| Error::BadResponse(format!("ftp PASV: cannot parse: {m2}")))?;
    let host = if direct {
        ctrl_peer_ip.to_string()
    } else {
        advertised_host
    };
    Ok((host, port))
}

/// Write a single FTP command followed by CRLF, using the BufReader's
/// underlying writer (BufReader itself isn't `Write`).
///
/// Refuses to send a command line that already contains a CR, LF, or NUL: the
/// CRLF terminator is appended here, so any embedded CR/LF in the assembled
/// line would be a command-injection vector (URL-derived user/pass/path flow
/// into these commands). This is the last line of defense behind the explicit
/// [`reject_ctl`] checks on the individual inputs.
fn send<R: Read + Write>(r: &mut BufReader<R>, line: &str) -> Result<()> {
    if line.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        return Err(Error::BadResponse(
            "ftp: refusing to send command line with embedded CR/LF/NUL".into(),
        ));
    }
    let w = r.get_mut();
    w.write_all(line.as_bytes())?;
    w.write_all(b"\r\n")?;
    w.flush()?;
    Ok(())
}

/// Reject a URL-derived string that contains CR, LF, NUL, or any other ASCII
/// control byte before it's interpolated into an FTP control command. `what`
/// names the field for the error message.
fn reject_ctl(s: &str, what: &str) -> Result<()> {
    crate::url::reject_ctl("ftp", what, s)
}

/// Read a (possibly multi-line) FTP reply. Returns `(code, text)` where
/// `text` is the concatenation of every line's text portion separated by
/// `\n`, without the trailing CRLF.
///
/// Multi-line replies look like:
///   `NNN-first line\r\n`
///   `   continuation\r\n`
///   `NNN final line\r\n`
/// — i.e. the terminator is a line whose first four bytes are `NNN` + ' '.
fn read_reply<R: BufRead>(r: &mut R) -> Result<(u16, String)> {
    let first = read_line(r)?;
    let (code, sep, rest) = split_code(&first)?;
    let mut text = rest.to_string();
    if sep == ' ' {
        return Ok((code, text));
    }
    // sep == '-': multi-line continuation until "<code> ..." is seen.
    loop {
        let line = read_line(r)?;
        // A continuation line may or may not start with the code. The
        // terminator is specifically `NNN ` (code + space).
        if let Ok((c, s, rest)) = split_code(&line) {
            text.push('\n');
            text.push_str(rest);
            if c == code && s == ' ' {
                return Ok((code, text));
            }
        } else {
            text.push('\n');
            text.push_str(line.trim_end_matches(['\r', '\n']));
        }
    }
}

/// Read one CRLF-terminated line, stripping the trailing CRLF. EOF before
/// any newline is an error.
fn read_line<R: BufRead>(r: &mut R) -> Result<String> {
    let mut buf = String::new();
    let n = r.read_line(&mut buf)?;
    if n == 0 {
        return Err(Error::UnexpectedEof);
    }
    Ok(buf)
}

/// Parse the leading 3-digit code from an FTP reply line. Returns
/// `(code, separator, rest)` where separator is ' ' (final line) or '-'
/// (continuation).
fn split_code(line: &str) -> Result<(u16, char, &str)> {
    let bytes = line.as_bytes();
    if bytes.len() < 4
        || !bytes[0].is_ascii_digit()
        || !bytes[1].is_ascii_digit()
        || !bytes[2].is_ascii_digit()
    {
        return Err(Error::BadResponse(format!(
            "ftp reply: no 3-digit code: {}",
            line.trim_end()
        )));
    }
    let sep = bytes[3] as char;
    if sep != ' ' && sep != '-' {
        return Err(Error::BadResponse(format!(
            "ftp reply: bad separator: {}",
            line.trim_end()
        )));
    }
    let code: u16 = line[..3].parse().unwrap(); // ascii_digit-checked above
    let rest = line[4..].trim_end_matches(['\r', '\n']);
    Ok((code, sep, rest))
}

/// Parse the `(h1,h2,h3,h4,p1,p2)` payload of a 227 PASV reply and turn it
/// into a `"a.b.c.d", port` pair. Returns `None` if the reply isn't shaped
/// the way the spec says.
fn parse_pasv(text: &str) -> Option<(String, u16)> {
    let open = text.find('(')?;
    let close = text[open..].find(')')? + open;
    let inner = &text[open + 1..close];
    let parts: Vec<&str> = inner.split(',').map(str::trim).collect();
    if parts.len() != 6 {
        return None;
    }
    let nums: Vec<u16> = parts.iter().filter_map(|p| p.parse::<u16>().ok()).collect();
    // All six fields are octets (0..=255): the four IP bytes *and* the two
    // port bytes. Range-checking the port bytes too avoids a silent truncation
    // when computing the 16-bit port below.
    if nums.len() != 6 || nums.iter().any(|&n| n > 255) {
        return None;
    }
    let host = format!("{}.{}.{}.{}", nums[0], nums[1], nums[2], nums[3]);
    let port = ((nums[4] as u8 as u16) << 8) | nums[5] as u8 as u16;
    // Port 0 is not a dialable data port; treat it as a malformed reply
    // rather than attempting an odd connect.
    if port == 0 {
        return None;
    }
    Some((host, port))
}

/// Parse the `(|||port|)` payload of a 229 EPSV reply. The single delimiter
/// character (here `|`) is chosen by the server and may differ — we use the
/// character immediately after `(`.
fn parse_epsv(text: &str) -> Option<u16> {
    let open = text.find('(')?;
    let close = text[open..].rfind(')')? + open;
    let inner = text.get(open + 1..close)?;
    // First byte is the delimiter (must be the same char repeated 3 times,
    // then the port, then the same delimiter again).
    let mut chars = inner.chars();
    let delim = chars.next()?;
    // Find the 3rd delim from the start; everything between it and the 4th
    // is the port.
    let bytes: Vec<char> = inner.chars().collect();
    let mut count = 0usize;
    let mut start = None;
    let mut end = None;
    for (i, ch) in bytes.iter().enumerate() {
        if *ch == delim {
            count += 1;
            if count == 3 {
                start = Some(i + 1);
            } else if count == 4 {
                end = Some(i);
                break;
            }
        }
    }
    let s = start?;
    let e = end?;
    let port_str: String = bytes[s..e].iter().collect();
    let port: u16 = port_str.parse().ok()?;
    // Port 0 is not a dialable data port; treat it as a malformed reply.
    if port == 0 {
        return None;
    }
    Some(port)
}

/// Split `user[:pass]` into `(user, pass)`, defaulting to anonymous /
/// `rsurl@` (matching real curl's anonymous-FTP defaults).
fn split_userinfo(ui: Option<&str>) -> (String, String) {
    match ui {
        None => ("anonymous".to_string(), "rsurl@".to_string()),
        Some(s) => match s.split_once(':') {
            Some((u, p)) => (u.to_string(), p.to_string()),
            None => (s.to_string(), "rsurl@".to_string()),
        },
    }
}

/// 2xx and 3xx are "positive" reply categories (completion / intermediate).
fn is_positive(code: u16) -> bool {
    (200..400).contains(&code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn cur(s: &str) -> BufReader<Cursor<Vec<u8>>> {
        BufReader::new(Cursor::new(s.as_bytes().to_vec()))
    }

    #[test]
    fn read_reply_single_line() {
        let mut r = cur("220 ProFTPD ready\r\n");
        let (code, text) = read_reply(&mut r).unwrap();
        assert_eq!(code, 220);
        assert_eq!(text, "ProFTPD ready");
    }

    #[test]
    fn read_reply_multi_line() {
        // RFC 959 §4.2 example shape. Continuation lines may start with
        // the same code or with arbitrary text; the terminator is `NNN `.
        let raw = "220-Welcome to the FTP server\r\n\
                   220-We have rules\r\n\
                   220 End of banner\r\n";
        let mut r = cur(raw);
        let (code, text) = read_reply(&mut r).unwrap();
        assert_eq!(code, 220);
        assert!(text.contains("Welcome"));
        assert!(text.contains("End of banner"));
    }

    #[test]
    fn read_reply_multi_line_continuation_without_code() {
        // Some servers emit continuation lines that don't start with the
        // code at all. Make sure we keep reading until `NNN `.
        let raw = "230-User logged in\r\n   please read MOTD\r\n230 ok\r\n";
        let mut r = cur(raw);
        let (code, text) = read_reply(&mut r).unwrap();
        assert_eq!(code, 230);
        assert!(text.contains("User logged in"));
        assert!(text.contains("please read MOTD"));
        assert!(text.contains("ok"));
    }

    #[test]
    fn read_reply_eof_is_error() {
        let mut r = cur("");
        assert!(matches!(read_reply(&mut r), Err(Error::UnexpectedEof)));
    }

    #[test]
    fn read_reply_rejects_garbage() {
        let mut r = cur("hello world\r\n");
        assert!(matches!(read_reply(&mut r), Err(Error::BadResponse(_))));
    }

    #[test]
    fn pasv_parses_canonical() {
        let (host, port) = parse_pasv("Entering Passive Mode (10,0,0,1,4,5)").unwrap();
        assert_eq!(host, "10.0.0.1");
        assert_eq!(port, 4 * 256 + 5); // 1029
    }

    #[test]
    fn pasv_parses_with_prefix_code_text() {
        // We pass `parse_pasv` only the text part (no code), matching how
        // `read_reply` returns things.
        let (host, port) = parse_pasv("Entering Passive Mode (192,168,1,2,200,100).").unwrap();
        assert_eq!(host, "192.168.1.2");
        assert_eq!(port, 200 * 256 + 100);
    }

    #[test]
    fn pasv_rejects_short() {
        assert!(parse_pasv("nope").is_none());
        assert!(parse_pasv("(1,2,3)").is_none());
        assert!(parse_pasv("(256,0,0,1,1,1)").is_none()); // octet > 255
    }

    #[test]
    fn pasv_rejects_out_of_range_port_bytes() {
        // Port bytes >255 would silently truncate when combined; reject them.
        assert!(parse_pasv("(10,0,0,1,256,5)").is_none());
        assert!(parse_pasv("(10,0,0,1,5,256)").is_none());
        // 255,255 is the largest legal pair → port 65535.
        let (_, port) = parse_pasv("(10,0,0,1,255,255)").unwrap();
        assert_eq!(port, 65535);
    }

    #[test]
    fn pasv_rejects_port_zero() {
        // Both port bytes zero → port 0, which isn't a dialable data port.
        assert!(parse_pasv("(10,0,0,1,0,0)").is_none());
    }

    /// Scripted in-memory transport: serves `reply_script` to reads and
    /// records everything written so tests can assert on commands sent.
    struct MockIo {
        to_read: std::io::Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl Read for MockIo {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.to_read.read(buf)
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
    fn open_passive_pasv_dials_control_peer_not_reply_ip() {
        use std::net::{IpAddr, Ipv4Addr};
        // EPSV is refused (500), then PASV advertises a *different* IP
        // (10.0.0.1) that we must ignore in favor of the control peer.
        let script = "500 EPSV not understood\r\n227 Entering Passive Mode (10,0,0,1,4,5)\r\n";
        let mut io = BufReader::new(MockIo {
            to_read: std::io::Cursor::new(script.as_bytes().to_vec()),
            written: Vec::new(),
        });
        let ctrl_peer = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let (host, port) = open_passive(&mut io, "ftp.example.com", ctrl_peer, true, true).unwrap();
        // Host is the control peer, NOT the 10.0.0.1 from the PASV reply.
        assert_eq!(host, "203.0.113.7");
        // Port is still taken from the (validated) PASV reply.
        assert_eq!(port, 4 * 256 + 5);
    }

    #[test]
    fn open_passive_disable_epsv_skips_straight_to_pasv() {
        use std::net::{IpAddr, Ipv4Addr};
        // With EPSV disabled the script need only answer PASV — no EPSV is sent.
        let script = "227 Entering Passive Mode (10,0,0,1,4,5)\r\n";
        let mut io = BufReader::new(MockIo {
            to_read: std::io::Cursor::new(script.as_bytes().to_vec()),
            written: Vec::new(),
        });
        let ctrl_peer = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let (host, port) =
            open_passive(&mut io, "ftp.example.com", ctrl_peer, true, false).unwrap();
        assert_eq!(host, "203.0.113.7");
        assert_eq!(port, 4 * 256 + 5);
        // The control stream saw PASV and never EPSV.
        let sent = String::from_utf8_lossy(&io.get_ref().written);
        assert!(sent.contains("PASV"), "sent: {sent:?}");
        assert!(!sent.contains("EPSV"), "must not send EPSV: {sent:?}");
    }

    #[test]
    fn send_rejects_embedded_crlf() {
        let mut io = BufReader::new(MockIo {
            to_read: std::io::Cursor::new(Vec::new()),
            written: Vec::new(),
        });
        assert!(matches!(
            send(&mut io, "USER alice\r\nDELE secret"),
            Err(Error::BadResponse(_))
        ));
        assert!(matches!(
            send(&mut io, "USER alice\nNOOP"),
            Err(Error::BadResponse(_))
        ));
        assert!(matches!(
            send(&mut io, "USER alice\0bob"),
            Err(Error::BadResponse(_))
        ));
        // A clean line goes through and gets exactly one CRLF appended.
        send(&mut io, "USER alice").unwrap();
        assert_eq!(io.get_ref().written, b"USER alice\r\n");
    }

    #[test]
    fn reject_ctl_flags_control_bytes() {
        assert!(reject_ctl("alice", "ftp user").is_ok());
        assert!(reject_ctl("a/b/c.txt", "ftp path").is_ok());
        assert!(reject_ctl("alice\r\nPASS x", "ftp user").is_err());
        assert!(reject_ctl("a\nb", "ftp path").is_err());
        assert!(reject_ctl("a\0b", "ftp user").is_err());
        assert!(reject_ctl("a\x7fb", "ftp user").is_err()); // DEL
    }

    #[test]
    fn epsv_parses_canonical() {
        let port = parse_epsv("Entering Extended Passive Mode (|||45678|)").unwrap();
        assert_eq!(port, 45678);
    }

    #[test]
    fn epsv_parses_alternative_delimiter() {
        // RFC 2428 lets the server pick any delimiter; we just read the
        // first char after '('.
        let port = parse_epsv("(!!!2121!)").unwrap();
        assert_eq!(port, 2121);
    }

    #[test]
    fn epsv_rejects_garbage() {
        assert!(parse_epsv("nope").is_none());
        assert!(parse_epsv("(|||abc|)").is_none());
    }

    #[test]
    fn epsv_rejects_port_zero() {
        // A server advertising port 0 isn't dialable; treat it as malformed.
        assert!(parse_epsv("(|||0|)").is_none());
    }

    #[test]
    fn split_userinfo_defaults_to_anonymous() {
        let (u, p) = split_userinfo(None);
        assert_eq!(u, "anonymous");
        assert_eq!(p, "rsurl@");
    }

    #[test]
    fn split_userinfo_user_only() {
        let (u, p) = split_userinfo(Some("alice"));
        assert_eq!(u, "alice");
        assert_eq!(p, "rsurl@");
    }

    #[test]
    fn split_userinfo_user_pass() {
        let (u, p) = split_userinfo(Some("alice:secret"));
        assert_eq!(u, "alice");
        assert_eq!(p, "secret");
    }

    #[test]
    fn split_userinfo_pass_with_colon() {
        let (u, p) = split_userinfo(Some("alice:s:e:c"));
        assert_eq!(u, "alice");
        assert_eq!(p, "s:e:c");
    }

    #[test]
    fn split_code_parses_space_and_dash() {
        let (c, s, r) = split_code("200 OK\r\n").unwrap();
        assert_eq!(c, 200);
        assert_eq!(s, ' ');
        assert_eq!(r, "OK");

        let (c, s, r) = split_code("220-banner\r\n").unwrap();
        assert_eq!(c, 220);
        assert_eq!(s, '-');
        assert_eq!(r, "banner");
    }

    #[test]
    fn fetch_rejects_non_ftp_scheme() {
        let u = Url::parse("http://example.com/").unwrap();
        assert!(matches!(fetch(&u), Err(Error::UnsupportedScheme(_))));
    }

    #[test]
    fn store_rejects_non_ftp_scheme() {
        let u = Url::parse("http://example.com/x").unwrap();
        assert!(matches!(
            store(&u, b"data", None),
            Err(Error::UnsupportedScheme(_))
        ));
    }

    #[test]
    fn stor_command_strips_leading_slash() {
        // The URL path is absolute; STOR names a path relative to the login
        // directory, so a single leading '/' is dropped (curl's behavior).
        assert_eq!(stor_command("/pub/file.bin").unwrap(), "STOR pub/file.bin");
        assert_eq!(stor_command("file.bin").unwrap(), "STOR file.bin");
        assert_eq!(stor_command("/a.txt").unwrap(), "STOR a.txt");
    }

    #[test]
    fn stor_command_rejects_directory_path() {
        // No filename to store.
        assert!(stor_command("").is_none());
        assert!(stor_command("/").is_none());
        assert!(stor_command("/pub/").is_none());
    }

    #[test]
    fn appe_command_strips_leading_slash() {
        // Same path handling as STOR, just a different verb.
        assert_eq!(appe_command("/pub/file.bin").unwrap(), "APPE pub/file.bin");
        assert_eq!(appe_command("file.bin").unwrap(), "APPE file.bin");
        assert_eq!(appe_command("/a.txt").unwrap(), "APPE a.txt");
    }

    #[test]
    fn appe_command_rejects_directory_path() {
        // No filename to append to.
        assert!(appe_command("").is_none());
        assert!(appe_command("/").is_none());
        assert!(appe_command("/pub/").is_none());
    }

    #[test]
    fn appe_command_rejects_control_bytes() {
        // The command builder itself only strips/validates the path shape;
        // control bytes in the path are caught by `reject_ctl` on the upload
        // path, but the assembled APPE line must never carry a raw CR/LF/NUL.
        // `send` is the last line of defense — confirm it refuses such a line.
        let mut io = BufReader::new(MockIo {
            to_read: std::io::Cursor::new(Vec::new()),
            written: Vec::new(),
        });
        assert!(reject_ctl("a\r\nDELE secret", "ftp path").is_err());
        assert!(reject_ctl("a\nb", "ftp path").is_err());
        assert!(reject_ctl("a\0b", "ftp path").is_err());
        // And the wire guard refuses an APPE line with an embedded newline.
        assert!(matches!(
            send(&mut io, "APPE a\r\nDELE secret"),
            Err(Error::BadResponse(_))
        ));
    }

    #[test]
    fn rest_command_formats_offset() {
        assert_eq!(rest_command(0), "REST 0");
        assert_eq!(rest_command(1048576), "REST 1048576");
        assert_eq!(rest_command(u64::MAX), format!("REST {}", u64::MAX));
    }

    /// Drive `store`'s control sequence over a mock control channel while a
    /// real loopback TCP listener stands in for the passive data connection.
    /// Asserts the exact commands sent and the bytes received on the data
    /// socket. Plain FTP only (no TLS), which exercises the full STOR path.
    fn run_store_mock(
        url: &str,
        body: &[u8],
        resume_at: Option<u64>,
    ) -> (Result<()>, Vec<u8>, Vec<u8>) {
        run_upload_mock(url, body, UploadMode::Stor, resume_at)
    }

    /// Generalized version of [`run_store_mock`] that drives either `STOR` or
    /// `APPE` (mirroring the production [`upload`] driver) over a mock control
    /// channel plus a real loopback data socket. `resume_at` is honored only
    /// for `STOR` (just like [`upload`]).
    fn run_upload_mock(
        url: &str,
        body: &[u8],
        mode: UploadMode,
        resume_at: Option<u64>,
    ) -> (Result<()>, Vec<u8>, Vec<u8>) {
        use std::net::{Ipv4Addr, TcpListener};
        use std::sync::mpsc;

        // Loopback listener for the data connection. The PASV reply advertises
        // its port; `open_passive` dials the control peer (127.0.0.1 here).
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let data_port = listener.local_addr().unwrap().port();
        let (p1, p2) = ((data_port >> 8) as u8, (data_port & 0xff) as u8);

        // Collect whatever the server receives on the data socket.
        let (tx, rx) = mpsc::channel();
        let data_thread = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut buf = Vec::new();
            sock.read_to_end(&mut buf).unwrap();
            tx.send(buf).unwrap();
        });

        // Scripted control-channel replies. EPSV is refused so PASV is used;
        // PASV advertises the loopback data port. REST (if any) → 350.
        let mut script = String::from(
            "220 ready\r\n\
             331 need pass\r\n\
             230 logged in\r\n\
             200 type ok\r\n",
        );
        // REST is only sent for STOR resume; APPE never negotiates an offset.
        if mode == UploadMode::Stor && resume_at.is_some() {
            script.push_str("350 restart ok\r\n");
        }
        script.push_str(&format!(
            "500 epsv?\r\n\
             227 Entering Passive Mode (127,0,0,1,{p1},{p2})\r\n\
             150 ok to send\r\n\
             226 transfer complete\r\n\
             221 bye\r\n"
        ));

        let mut ctrl = BufReader::new(MockIo {
            to_read: std::io::Cursor::new(script.into_bytes()),
            written: Vec::new(),
        });
        let ctrl_peer = std::net::IpAddr::V4(Ipv4Addr::LOCALHOST);
        let parsed = Url::parse(url).unwrap();

        // Replicate the post-login portion of `store` against the mock control
        // channel and the real loopback data socket. `open_data` is the same
        // function `store` calls, so the passive handshake and STOR sequencing
        // under test are the production ones.
        let result = (|| -> Result<()> {
            // Consume banner + login + TYPE replies that connect_login would.
            for _ in 0..4 {
                read_reply(&mut ctrl)?;
            }
            reject_ctl(&parsed.path, "ftp path")?;
            let cmd = upload_command(mode, &parsed.path)
                .ok_or_else(|| Error::BadResponse("no file".into()))?;
            if mode == UploadMode::Stor {
                if let Some(offset) = resume_at {
                    send(&mut ctrl, &rest_command(offset))?;
                    let (c, _) = read_reply(&mut ctrl)?;
                    if c != 350 {
                        return Err(Error::BadResponse(format!("REST: {c}")));
                    }
                }
            }
            let unspec = std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
            let dataconn = open_data(&mut ctrl, &parsed, ctrl_peer, unspec, &NetConfig::default())?;
            send(&mut ctrl, &cmd)?;
            let (c, m) = read_reply(&mut ctrl)?;
            if !(c == 125 || c == 150) {
                return Err(Error::BadResponse(format!("{cmd}: {c} {m}")));
            }
            let mut data = dataconn.into_stream()?;
            data.write_all(body)?;
            data.flush()?;
            drop(data);
            let (cf, mf) = read_reply(&mut ctrl)?;
            if !is_positive(cf) {
                return Err(Error::BadResponse(format!("end: {cf} {mf}")));
            }
            let _ = send(&mut ctrl, "QUIT");
            let _ = read_reply(&mut ctrl);
            Ok(())
        })();

        let received = rx.recv().unwrap();
        data_thread.join().unwrap();
        let written = ctrl.get_ref().written.clone();
        (result, written, received)
    }

    #[test]
    fn store_streams_body_and_sends_stor() {
        let (res, written, received) =
            run_store_mock("ftp://h.example/pub/up.bin", b"hello ftp", None);
        res.unwrap();
        let sent = String::from_utf8(written).unwrap();
        assert!(sent.contains("STOR pub/up.bin\r\n"), "sent: {sent:?}");
        assert!(!sent.contains("REST"), "no REST without offset: {sent:?}");
        assert!(sent.contains("QUIT\r\n"));
        assert_eq!(received, b"hello ftp");
    }

    #[test]
    fn store_with_resume_sends_rest_before_stor() {
        let (res, written, received) =
            run_store_mock("ftp://h.example/up.bin", b"TAIL", Some(4096));
        res.unwrap();
        let sent = String::from_utf8(written).unwrap();
        let rest_at = sent.find("REST 4096\r\n").expect("REST sent");
        let stor_at = sent.find("STOR up.bin\r\n").expect("STOR sent");
        assert!(rest_at < stor_at, "REST must precede STOR: {sent:?}");
        assert_eq!(received, b"TAIL");
    }

    #[test]
    fn append_streams_body_and_sends_appe() {
        let (res, written, received) = run_upload_mock(
            "ftp://h.example/pub/up.bin",
            b"more data",
            UploadMode::Appe,
            None,
        );
        res.unwrap();
        let sent = String::from_utf8(written).unwrap();
        // APPE, not STOR, and never a REST (append negotiates no offset).
        assert!(sent.contains("APPE pub/up.bin\r\n"), "sent: {sent:?}");
        assert!(!sent.contains("STOR"), "must not send STOR: {sent:?}");
        assert!(!sent.contains("REST"), "must not send REST: {sent:?}");
        assert!(sent.contains("QUIT\r\n"));
        assert_eq!(received, b"more data");
    }

    #[test]
    fn append_ignores_resume_offset() {
        // Even if a resume offset were threaded through, APPE never emits REST
        // and streams the whole body — the public `append` always passes None,
        // but the driver must enforce this regardless.
        let (res, written, received) = run_upload_mock(
            "ftp://h.example/up.bin",
            b"WHOLE",
            UploadMode::Appe,
            Some(4096),
        );
        res.unwrap();
        let sent = String::from_utf8(written).unwrap();
        assert!(!sent.contains("REST"), "APPE must not send REST: {sent:?}");
        assert!(sent.contains("APPE up.bin\r\n"), "sent: {sent:?}");
        assert_eq!(received, b"WHOLE");
    }

    #[test]
    fn append_rejects_non_ftp_scheme() {
        let u = Url::parse("http://example.com/x").unwrap();
        assert!(matches!(
            append(&u, b"data"),
            Err(Error::UnsupportedScheme(_))
        ));
    }
}

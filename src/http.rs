use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::url::Url;

const DEFAULT_USER_AGENT: &str = concat!("rsurl/", env!("CARGO_PKG_VERSION"));
const MAX_HEADER_BYTES: usize = 64 * 1024;
pub(crate) const MAX_BODY_BYTES: usize = 256 * 1024 * 1024;

/// Preference for which HTTP version to use over HTTPS. The HTTPS dispatcher
/// picks this up. HTTP/2 is selected via ALPN at TLS-handshake time; if the
/// server doesn't agree (Auto) we transparently fall back to HTTP/1.1.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum HttpVersionPref {
    /// Offer ALPN `["h2", "http/1.1"]` and let the server pick. If h2 is
    /// negotiated, dispatch to the HTTP/2 backend; otherwise speak HTTP/1.1.
    #[default]
    Auto,
    /// Speak HTTP/1.1 only; don't offer ALPN. Matches `curl --http1.1`.
    Http11Only,
    /// Require HTTP/2; abort the request if the server doesn't select it.
    /// Matches `curl --http2-prior-knowledge` semantics.
    Http2Only,
}

/// An HTTP request being constructed.
///
/// Fields are `pub(crate)` so that protocol-variant modules (`http2`, `http3`)
/// can read them without going through `&self` accessors.
#[derive(Debug, Clone)]
pub struct Request {
    pub(crate) method: String,
    pub(crate) url: Url,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
    pub(crate) connect_timeout: Option<Duration>,
    pub(crate) read_timeout: Option<Duration>,
    pub(crate) http_version_pref: HttpVersionPref,
    /// Whether to follow `3xx` redirect responses. `false` by default —
    /// matches curl's behaviour without `-L`.
    pub(crate) follow_redirects: bool,
    /// Maximum number of redirects to follow when `follow_redirects` is on.
    /// 50 is curl's default.
    pub(crate) max_redirs: u32,
    /// Optional HTTP Basic auth credentials. Only sent if the caller has
    /// not already set an `Authorization:` header explicitly. Dropped when
    /// a redirect changes host.
    pub(crate) basic_auth: Option<(String, String)>,
    /// Verify the TLS chain. `false` is curl's `-k` / `--insecure`.
    pub(crate) verify_tls: bool,
    /// Path to a PEM CA bundle that overrides the system trust store
    /// (curl `--cacert`).
    pub(crate) ca_bundle: Option<String>,
    /// Wall-clock cap for the whole operation (across redirects), curl
    /// `--max-time`. `None` means no cap beyond `connect_timeout` /
    /// `read_timeout`.
    pub(crate) max_time: Option<Duration>,
}

impl Request {
    pub fn new(method: &str, url: &str) -> Result<Self> {
        Ok(Request {
            method: method.to_ascii_uppercase(),
            url: Url::parse(url)?,
            headers: Vec::new(),
            body: Vec::new(),
            connect_timeout: Some(Duration::from_secs(30)),
            read_timeout: Some(Duration::from_secs(60)),
            http_version_pref: HttpVersionPref::Auto,
            follow_redirects: false,
            max_redirs: 50,
            basic_auth: None,
            verify_tls: true,
            ca_bundle: None,
            max_time: None,
        })
    }

    pub fn get(url: &str) -> Result<Self> {
        Self::new("GET", url)
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    pub fn body<B: Into<Vec<u8>>>(mut self, body: B) -> Self {
        self.body = body.into();
        self
    }

    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Set the HTTP version preference for HTTPS requests. See
    /// [`HttpVersionPref`].
    pub fn http_version(mut self, pref: HttpVersionPref) -> Self {
        self.http_version_pref = pref;
        self
    }

    /// Force HTTP/2; the request fails if the server does not select ALPN
    /// "h2". Equivalent to `curl --http2` for an `https://` URL.
    pub fn http2_only(mut self) -> Self {
        self.http_version_pref = HttpVersionPref::Http2Only;
        self
    }

    /// Force HTTP/1.1; ALPN is not offered. Equivalent to `curl --http1.1`.
    pub fn http11_only(mut self) -> Self {
        self.http_version_pref = HttpVersionPref::Http11Only;
        self
    }

    /// Toggle redirect following. When on, 301/302/303/307/308 responses
    /// are transparently chased up to [`Self::max_redirs`] hops.
    pub fn follow_redirects(mut self, on: bool) -> Self {
        self.follow_redirects = on;
        self
    }

    /// Cap on redirect hops; only meaningful when
    /// [`Self::follow_redirects`] is on. Default 50.
    pub fn max_redirs(mut self, n: u32) -> Self {
        self.max_redirs = n;
        self
    }

    /// Attach HTTP Basic auth credentials. They become
    /// `Authorization: Basic <base64(user:pass)>` unless the caller already
    /// supplied an `Authorization` header. Credentials are dropped on a
    /// cross-host redirect.
    pub fn basic_auth(mut self, user: &str, pass: &str) -> Self {
        self.basic_auth = Some((user.to_string(), pass.to_string()));
        self
    }

    /// Toggle TLS chain verification. `false` matches curl `-k`.
    pub fn verify_tls(mut self, on: bool) -> Self {
        self.verify_tls = on;
        self
    }

    /// Use a custom CA bundle (PEM) instead of the system trust store.
    pub fn ca_bundle(mut self, path: &str) -> Self {
        self.ca_bundle = Some(path.to_string());
        self
    }

    /// Cap on the whole operation's wall-clock time (curl `--max-time`).
    pub fn max_time(mut self, d: Duration) -> Self {
        self.max_time = Some(d);
        self
    }

    /// Cap on TCP connect time (curl `--connect-timeout`).
    pub fn connect_timeout(mut self, d: Duration) -> Self {
        self.connect_timeout = Some(d);
        self
    }

    pub fn send(self) -> Result<Response> {
        self.send_to(&mut io::sink())
    }

    /// Like [`send`](Self::send), but writes a curl-style `-v` trace to
    /// `trace` as the request progresses: `*` lines for connection / TLS
    /// events, `>` lines for every byte of the request actually placed on
    /// the wire, `<` lines for every status / header byte received. The
    /// trace is built from the same buffers used for I/O, so it cannot
    /// drift from what was sent.
    pub fn send_traced(self, trace: &mut dyn Write) -> Result<Response> {
        self.send_to(trace)
    }

    /// Single-shot send with no redirect handling. Pure protocol dispatch.
    fn send_once(self, trace: &mut dyn Write) -> Result<Response> {
        if !self.verify_tls && self.url.scheme == "https" {
            let _ = writeln!(trace, "* WARNING: certificate verification disabled (-k)");
        }
        match self.url.scheme.as_str() {
            "http" => send_plain(self, trace),
            "https" => send_https(self, trace),
            other => Err(Error::UnsupportedScheme(other.to_string())),
        }
    }

    /// Send the request, then walk through `3xx Location` chains if
    /// [`Self::follow_redirects`] is on. Public users go through
    /// [`Self::send`] / [`Self::send_traced`], which call this.
    fn send_to(self, trace: &mut dyn Write) -> Result<Response> {
        let mut req = self;
        let deadline = req.max_time.map(|d| std::time::Instant::now() + d);
        let mut hops_left = req.max_redirs;
        loop {
            // Honour --max-time before each hop (the per-socket timeout
            // already handles the in-flight case).
            if let Some(end) = deadline {
                if std::time::Instant::now() >= end {
                    return Err(Error::BadResponse("operation timed out".into()));
                }
            }
            let snapshot = req.clone();
            let resp = snapshot.send_once(trace)?;
            if !req.follow_redirects || !is_redirect_status(resp.status) {
                return Ok(resp);
            }
            if hops_left == 0 {
                return Err(Error::BadResponse(format!(
                    "maximum ({}) redirects followed",
                    req.max_redirs
                )));
            }
            let location = match resp.header("location") {
                Some(l) => l.to_string(),
                None => return Ok(resp), // 3xx without Location — give it back.
            };
            let next_url = crate::url::resolve(&req.url, &location)?;
            let _ = writeln!(
                trace,
                "* Following redirect to {}",
                url_to_string(&next_url)
            );

            // RFC 9110: drop sensitive headers on cross-host redirects.
            let host_changed = next_url.host != req.url.host
                || next_url.port != req.url.port
                || next_url.scheme != req.url.scheme;

            let prev_method = req.method.clone();
            let prev_body = std::mem::take(&mut req.body);
            let mut next = req;
            next.url = next_url;
            if host_changed {
                next.headers.retain(|(k, _)| {
                    !k.eq_ignore_ascii_case("authorization") && !k.eq_ignore_ascii_case("cookie")
                });
                next.basic_auth = None;
            }

            // Method/body rewriting per RFC 9110 §15.4 plus curl's default
            // backward-compat behaviour: 301/302/303 rewrite POST/PUT/etc
            // to GET and drop the body; 307/308 preserve method + body.
            if (301..=303).contains(&resp.status)
                && !prev_method.eq_ignore_ascii_case("GET")
                && !prev_method.eq_ignore_ascii_case("HEAD")
            {
                next.method = "GET".to_string();
                // body left empty; drop request-body framing headers since
                // we no longer have a body to describe.
                next.headers.retain(|(k, _)| {
                    !k.eq_ignore_ascii_case("content-type")
                        && !k.eq_ignore_ascii_case("content-length")
                        && !k.eq_ignore_ascii_case("transfer-encoding")
                });
            } else {
                // 307/308, or 301/302/303 on a GET/HEAD: preserve method
                // and restore the body verbatim.
                next.body = prev_body;
            }
            hops_left -= 1;
            req = next;
        }
    }
}

fn is_redirect_status(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn url_to_string(u: &Url) -> String {
    let default = matches!((u.scheme.as_str(), u.port), ("http", 80) | ("https", 443));
    if default {
        format!("{}://{}{}", u.scheme, u.host, u.path)
    } else {
        format!("{}://{}:{}{}", u.scheme, u.host, u.port, u.path)
    }
}

/// A complete HTTP response.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub reason: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    /// Returns the first value of a header, case-insensitive.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn send_plain(req: Request, trace: &mut dyn Write) -> Result<Response> {
    let stream = tcp_connect(&req, trace)?;
    write_request(&stream, &req, trace)?;
    let resp = read_response(stream, &req.method, trace)?;
    let _ = writeln!(trace, "* Connection closed");
    Ok(resp)
}

/// Compute the base64 token to send in `Authorization: Basic <token>`,
/// preferring the explicit credentials set via [`Request::basic_auth`] over
/// any `user:pass@` userinfo in the URL (RFC 7617). Returns `None` if
/// neither source is set or if the explicit pair is empty.
pub(crate) fn effective_basic_auth(req: &Request) -> Option<String> {
    let (user, pass) = match &req.basic_auth {
        Some((u, p)) => (u.clone(), p.clone()),
        None => {
            let info = req.url.userinfo.as_deref()?;
            match info.split_once(':') {
                Some((u, p)) => (u.to_string(), p.to_string()),
                None => (info.to_string(), String::new()),
            }
        }
    };
    if user.is_empty() && pass.is_empty() {
        return None;
    }
    let combined = format!("{user}:{pass}");
    Some(crate::websocket::base64_encode(combined.as_bytes()))
}

/// Build a [`crate::tls::TlsOpts`] from a [`Request`]'s flags, loading the
/// CA bundle from disk if `--cacert` was set.
pub(crate) fn tls_opts_from(req: &Request, alpn: &[&[u8]]) -> Result<crate::tls::TlsOpts> {
    let mut opts = crate::tls::TlsOpts::verifying();
    opts.alpn = alpn.iter().map(|p| p.to_vec()).collect();
    opts.verify = req.verify_tls;
    if let Some(path) = &req.ca_bundle {
        opts.roots = Some(crate::tls::load_roots_from_file(path)?);
    }
    Ok(opts)
}

fn send_https(req: Request, trace: &mut dyn Write) -> Result<Response> {
    // HTTP version routing:
    //
    // * `Http2Only`: dispatch to the HTTP/2 backend; its `Error::H2NotNegotiated`
    //   bubbles up unchanged so the caller sees the hard failure.
    // * `Auto`: try HTTP/2 first (it offers ALPN "h2"); if the server didn't
    //   select h2, [`crate::http2::send`] returns `Error::H2NotNegotiated`,
    //   which we intercept and retry over HTTP/1.1 on a fresh connection.
    //   This is the same behaviour curl gives you by default — h2 if both
    //   ends support it, http/1.1 otherwise.
    // * `Http11Only`: skip h2 entirely and do not offer ALPN.
    match req.http_version_pref {
        HttpVersionPref::Http2Only => {
            let _ = writeln!(trace, "* HTTP/2 required (--http2)");
            return crate::http2::send(req);
        }
        HttpVersionPref::Auto => {
            let _ = writeln!(trace, "* Trying HTTP/2 via ALPN (h2)");
            match crate::http2::send(req.clone()) {
                Ok(resp) => return Ok(resp),
                Err(Error::H2NotNegotiated) => {
                    let _ = writeln!(
                        trace,
                        "* ALPN: server did not select h2, falling back to HTTP/1.1"
                    );
                }
                Err(e) => return Err(e),
            }
        }
        HttpVersionPref::Http11Only => {
            let _ = writeln!(trace, "* HTTP/1.1 forced (--http1.1)");
        }
    }

    // HTTP/1.1 path (Auto fallback or Http11Only). ALPN is not offered so
    // the cert-only handshake doesn't change behaviour for h2-only servers
    // (those would have been satisfied by the h2 attempt above).
    let tcp = tcp_connect(&req, trace)?;
    let opts = tls_opts_from(&req, &[])?;
    let mut tls = crate::tls::connect_over_tls(tcp, &req.url.host, opts)?;
    write_tls_info(&tls, trace);
    write_request(&mut tls, &req, trace)?;
    let resp = read_response(tls, &req.method, trace)?;
    let _ = writeln!(trace, "* Connection closed");
    Ok(resp)
}

fn tcp_connect(req: &Request, trace: &mut dyn Write) -> Result<TcpStream> {
    let addr = format!("{}:{}", req.url.host, req.url.port);
    let first = std::net::ToSocketAddrs::to_socket_addrs(&addr)?
        .next()
        .ok_or_else(|| Error::InvalidUrl(req.url.host.clone()))?;
    let _ = writeln!(trace, "*   Trying {first}...");
    let stream = match req.connect_timeout {
        Some(t) => TcpStream::connect_timeout(&first, t)?,
        None => TcpStream::connect(first)?,
    };
    let peer = stream.peer_addr().unwrap_or(first);
    let _ = writeln!(
        trace,
        "* Connected to {} ({}) port {}",
        req.url.host,
        peer.ip(),
        peer.port()
    );
    stream.set_read_timeout(req.read_timeout)?;
    stream.set_write_timeout(req.read_timeout)?;
    Ok(stream)
}

fn write_tls_info<S: Read + Write>(tls: &crate::tls::TlsStream<S>, trace: &mut dyn Write) {
    if let Some(v) = tls.negotiated_version() {
        let _ = writeln!(trace, "* SSL connection using {v:?}");
    }
    match tls.alpn_selected() {
        Some(p) => {
            let _ = writeln!(
                trace,
                "* ALPN: server accepted {}",
                String::from_utf8_lossy(p)
            );
        }
        None => {
            let _ = writeln!(trace, "* ALPN: no protocol negotiated");
        }
    }
    let certs = tls.peer_certificates();
    let _ = writeln!(trace, "* Server certificate chain: {} cert(s)", certs.len());
    for (i, der) in certs.iter().enumerate() {
        match purecrypto::x509::Certificate::from_der(der.clone()) {
            Ok(cert) => {
                let subject = cert
                    .subject()
                    .ok()
                    .and_then(|d| d.common_name)
                    .unwrap_or_else(|| "?".into());
                let issuer = cert
                    .issuer()
                    .ok()
                    .and_then(|d| d.common_name)
                    .unwrap_or_else(|| "?".into());
                let _ = writeln!(trace, "*  [{i}] subject CN: {subject}");
                let _ = writeln!(trace, "*      issuer  CN: {issuer}");
                if let Ok(v) = cert.validity() {
                    let _ = writeln!(
                        trace,
                        "*      valid: {}  ->  {}",
                        v.not_before.as_str(),
                        v.not_after.as_str()
                    );
                }
            }
            Err(_) => {
                let _ = writeln!(trace, "*  [{i}] (DER unparseable, {} bytes)", der.len());
            }
        }
    }
}

fn write_request<W: Write>(mut w: W, req: &Request, trace: &mut dyn Write) -> Result<()> {
    let host_header = if (req.url.scheme == "http" && req.url.port == 80)
        || (req.url.scheme == "https" && req.url.port == 443)
    {
        req.url.host.clone()
    } else {
        format!("{}:{}", req.url.host, req.url.port)
    };

    let mut buf = Vec::with_capacity(256);
    write!(&mut buf, "{} {} HTTP/1.1\r\n", req.method, req.url.path)?;
    write!(&mut buf, "Host: {host_header}\r\n")?;

    let mut have_ua = false;
    let mut have_accept = false;
    let mut have_accept_enc = false;
    let mut have_clen = false;
    let mut have_auth = false;
    for (k, v) in &req.headers {
        if k.eq_ignore_ascii_case("user-agent") {
            have_ua = true;
        }
        if k.eq_ignore_ascii_case("accept") {
            have_accept = true;
        }
        if k.eq_ignore_ascii_case("accept-encoding") {
            have_accept_enc = true;
        }
        if k.eq_ignore_ascii_case("content-length") {
            have_clen = true;
        }
        if k.eq_ignore_ascii_case("authorization") {
            have_auth = true;
        }
        write!(&mut buf, "{k}: {v}\r\n")?;
    }
    if !have_auth {
        if let Some(creds) = effective_basic_auth(req) {
            write!(&mut buf, "Authorization: Basic {creds}\r\n")?;
        }
    }
    if !have_ua {
        write!(&mut buf, "User-Agent: {DEFAULT_USER_AGENT}\r\n")?;
    }
    if !have_accept {
        write!(&mut buf, "Accept: */*\r\n")?;
    }
    if !have_accept_enc {
        // Default-on equivalent of curl's `--compressed`: we always know
        // how to decode these on the way back (see `crate::compress`).
        write!(&mut buf, "Accept-Encoding: gzip, deflate\r\n")?;
    }
    if !req.body.is_empty() && !have_clen {
        write!(&mut buf, "Content-Length: {}\r\n", req.body.len())?;
    }
    write!(&mut buf, "Connection: close\r\n\r\n")?;

    // Trace what we're about to put on the wire — read straight from `buf`
    // so the trace can't lie about what was sent. Stripping just one trailing
    // `\r\n` leaves the header terminator's blank line, which becomes the
    // closing `> ` line on the trace.
    let head = String::from_utf8_lossy(&buf);
    let head_no_final_crlf = head.strip_suffix("\r\n").unwrap_or(&head);
    for line in head_no_final_crlf.split("\r\n") {
        let _ = writeln!(trace, "> {line}");
    }

    w.write_all(&buf)?;
    if !req.body.is_empty() {
        let _ = writeln!(trace, "* uploading {} body bytes", req.body.len());
        w.write_all(&req.body)?;
    }
    w.flush()?;
    Ok(())
}

fn read_response<R: Read>(stream: R, method: &str, trace: &mut dyn Write) -> Result<Response> {
    let mut r = BufReader::new(stream);

    let mut status_line = String::new();
    let n = r.read_line(&mut status_line)?;
    if n == 0 {
        return Err(Error::UnexpectedEof);
    }
    let trimmed_status = status_line.trim_end_matches(['\r', '\n']);
    let _ = writeln!(trace, "< {trimmed_status}");
    let (version, status, reason) = parse_status_line(trimmed_status)?;

    let mut headers: Vec<(String, String)> = Vec::new();
    let mut header_bytes = 0usize;
    loop {
        let mut line = String::new();
        let n = r.read_line(&mut line)?;
        if n == 0 {
            return Err(Error::UnexpectedEof);
        }
        header_bytes += n;
        if header_bytes > MAX_HEADER_BYTES {
            return Err(Error::BadResponse("headers exceed 64 KiB".into()));
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        let _ = writeln!(trace, "< {trimmed}");
        if trimmed.is_empty() {
            break;
        }
        let (k, v) = trimmed
            .split_once(':')
            .ok_or_else(|| Error::BadResponse(format!("malformed header line: {trimmed:?}")))?;
        headers.push((k.trim().to_string(), v.trim().to_string()));
    }

    let body = read_body(&mut r, &headers, &version, status, method)?;
    let wire_len = body.len();
    let _ = writeln!(trace, "* Received {wire_len} body bytes");
    let (headers, body) = maybe_decode_body(headers, body, trace)?;

    Ok(Response {
        status,
        reason,
        version,
        headers,
        body,
    })
}

/// Headers + body pair, the shape every HTTP-version backend assembles
/// before publishing a [`Response`]. Used by [`maybe_decode_body`] so the
/// signature doesn't trip `clippy::type_complexity`.
pub(crate) type HeadersAndBody = (Vec<(String, String)>, Vec<u8>);

/// If the response carries `Content-Encoding: gzip|deflate|x-gzip|identity`,
/// decode the body and strip the now-stale `Content-Encoding` and
/// `Content-Length` headers. Returns the (possibly-modified) headers + body.
/// Unknown encodings (brotli, zstd, compress, ...) are left intact so a
/// caller that knows how to handle them can still try.
///
/// Shared by HTTP/1.1, HTTP/2, and HTTP/3 — they all assemble a `(headers,
/// body)` pair and need identical post-processing.
pub(crate) fn maybe_decode_body(
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    trace: &mut dyn Write,
) -> Result<HeadersAndBody> {
    let Some(enc) = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-encoding"))
        .map(|(_, v)| v.clone())
    else {
        return Ok((headers, body));
    };
    let wire_len = body.len();
    let out = crate::compress::decode_body(body, &enc)?;
    if out.decoded {
        let _ = writeln!(
            trace,
            "* Decompressed body: {} -> {} bytes ({})",
            wire_len,
            out.body.len(),
            enc
        );
        Ok((crate::compress::strip_after_decode(headers), out.body))
    } else {
        Ok((headers, out.body))
    }
}

fn parse_status_line(line: &str) -> Result<(String, u16, String)> {
    let mut parts = line.splitn(3, ' ');
    let version = parts
        .next()
        .ok_or_else(|| Error::BadResponse(format!("missing version: {line:?}")))?
        .to_string();
    if !version.starts_with("HTTP/") {
        return Err(Error::BadResponse(format!("not HTTP: {version}")));
    }
    let status: u16 = parts
        .next()
        .ok_or_else(|| Error::BadResponse(format!("missing status: {line:?}")))?
        .parse()
        .map_err(|_| Error::BadResponse(format!("bad status: {line:?}")))?;
    let reason = parts.next().unwrap_or("").to_string();
    Ok((version, status, reason))
}

fn read_body<R: BufRead>(
    r: &mut R,
    headers: &[(String, String)],
    _version: &str,
    status: u16,
    method: &str,
) -> Result<Vec<u8>> {
    // RFC 9110: HEAD responses never have a body, nor do these statuses.
    if method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&status)
        || status == 204
        || status == 304
    {
        return Ok(Vec::new());
    }

    let chunked = headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("transfer-encoding") && v.eq_ignore_ascii_case("chunked")
    });
    if chunked {
        return read_chunked(r);
    }

    let content_length = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<u64>().ok());

    let mut body = Vec::new();
    match content_length {
        Some(len) => {
            if len as usize > MAX_BODY_BYTES {
                return Err(Error::BadResponse(format!("body too large: {len}")));
            }
            body.reserve(len as usize);
            r.take(len).read_to_end(&mut body)?;
            if (body.len() as u64) < len {
                return Err(Error::UnexpectedEof);
            }
        }
        None => {
            // No content-length, no chunked — read until EOF (Connection: close).
            r.take(MAX_BODY_BYTES as u64).read_to_end(&mut body)?;
        }
    }
    Ok(body)
}

fn read_chunked<R: BufRead>(r: &mut R) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let mut size_line = String::new();
        let n = r.read_line(&mut size_line)?;
        if n == 0 {
            return Err(Error::UnexpectedEof);
        }
        let size_str = size_line
            .trim_end_matches(['\r', '\n'])
            .split(';')
            .next()
            .unwrap_or("");
        let size = usize::from_str_radix(size_str.trim(), 16)
            .map_err(|_| Error::BadResponse(format!("bad chunk size: {size_str:?}")))?;
        if body.len().saturating_add(size) > MAX_BODY_BYTES {
            return Err(Error::BadResponse("body too large".into()));
        }
        if size == 0 {
            // Consume trailers until empty line.
            loop {
                let mut t = String::new();
                let n = r.read_line(&mut t)?;
                if n == 0 || t.trim_end_matches(['\r', '\n']).is_empty() {
                    break;
                }
            }
            break;
        }
        let start = body.len();
        body.resize(start + size, 0);
        r.read_exact(&mut body[start..])?;
        let mut crlf = [0u8; 2];
        r.read_exact(&mut crlf)?;
        if &crlf != b"\r\n" {
            return Err(Error::BadResponse("missing CRLF after chunk".into()));
        }
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status_line_ok() {
        let (v, s, r) = parse_status_line("HTTP/1.1 200 OK").unwrap();
        assert_eq!(v, "HTTP/1.1");
        assert_eq!(s, 200);
        assert_eq!(r, "OK");
    }

    #[test]
    fn parses_status_line_no_reason() {
        let (_, s, r) = parse_status_line("HTTP/1.0 204").unwrap();
        assert_eq!(s, 204);
        assert_eq!(r, "");
    }

    #[test]
    fn rejects_non_http() {
        assert!(parse_status_line("RTSP/1.0 200 OK").is_err());
    }
}

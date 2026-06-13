use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::net::{connector_from_proxy_url, Connector, DirectConnector, NetStream};
use crate::url::Url;

const DEFAULT_USER_AGENT: &str = concat!("rsurl/", env!("CARGO_PKG_VERSION"));
const MAX_HEADER_BYTES: usize = 64 * 1024;
pub(crate) const MAX_BODY_BYTES: usize = 256 * 1024 * 1024;

/// Preference for which HTTP version to use over HTTPS. The HTTPS dispatcher
/// picks this up. HTTP/2 is selected via ALPN at TLS-handshake time; if the
/// server doesn't agree (Auto) we transparently fall back to HTTP/1.1.
/// HTTP/3 runs over a wholly separate QUIC/UDP path (see [`crate::http3`]).
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
    /// Attempt HTTP/3 over QUIC first; on a transport-level failure (UDP
    /// blocked, QUIC handshake/negotiation failure, timeout) fall back to
    /// the [`Self::Auto`] path (HTTP/2, then HTTP/1.1). Matches `curl
    /// --http3`. A real HTTP response — even a 4xx/5xx — does *not* trigger
    /// fallback.
    Http3,
    /// Require HTTP/3 over QUIC; abort the request if QUIC can't be
    /// established. No fallback. Matches `curl --http3-only`.
    Http3Only,
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
    /// Optional outbound HTTP proxy (the legacy absolute-form / `CONNECT`
    /// path). Set for `http://` proxies; `socks*`/`https://` proxies and
    /// caller-supplied transports go through [`Request::connector`] instead.
    pub(crate) proxy: Option<ProxyConfig>,
    /// List of host suffixes that bypass the proxy. Matches curl's
    /// `NO_PROXY` / `--noproxy`: case-insensitive suffix match against
    /// the request URL host. `*` means "everything bypasses".
    pub(crate) no_proxy: Vec<String>,
    /// Convert international (IDN) hostnames to ASCII/punycode before use.
    /// On by default (curl's behaviour); `false` is curl's `--no-idn`. A no-op
    /// when the crate is built without the `idn` feature.
    pub(crate) idn: bool,
    /// The transport used to reach the origin. Defaults to a direct TCP dial
    /// ([`DirectConnector`]). A non-direct connector (SOCKS/HTTPS proxy or a
    /// caller-supplied implementation) routes the request through it and, in
    /// this milestone, forces HTTP/1.1 with pooling disabled.
    pub(crate) connector: Arc<dyn Connector>,
    /// Force an address family (curl `-4`/`-6`). `None` = either.
    pub(crate) ip_family: Option<IpFamily>,
    /// Static DNS overrides (curl `--resolve`): `(host, port) -> IP`.
    pub(crate) resolve: Vec<(String, u16, std::net::IpAddr)>,
    /// Send `Referer:` set to the previous URL on each redirect hop
    /// (curl `-e ';auto'`).
    pub(crate) auto_referer: bool,
    /// Keep `Authorization`/`Cookie` across cross-host redirects
    /// (curl `--location-trusted`). Off by default.
    pub(crate) redirect_trusted: bool,
    /// Preserve the request method (don't rewrite POST→GET) on 301/302/303
    /// respectively (curl `--post301`/`--post302`/`--post303`).
    pub(crate) keep_post: [bool; 3],
    /// Connect-target overrides (curl `--connect-to`):
    /// `(from_host, from_port, to_host, to_port)`. An empty from-host or a
    /// from-port of 0 is a wildcard. The `Host:`/SNI stay the request's.
    pub(crate) connect_to: Vec<(String, u16, String, u16)>,
    /// TLS version floor/ceiling (curl `--tlsv1.x` / `--tls-max`).
    pub(crate) tls_min: Option<crate::tls::ProtocolVersion>,
    pub(crate) tls_max: Option<crate::tls::ProtocolVersion>,
    /// Use HTTP Digest auth with `basic_auth`'s credentials (curl `--digest`):
    /// send unauthenticated, then answer a `401 Digest` challenge.
    pub(crate) auth_digest: bool,
    /// Path to the client certificate file for mTLS (curl `-E`/`--cert`).
    pub(crate) client_cert: Option<String>,
    /// Path to the client private-key file (curl `--key`). When `None` and
    /// `client_cert` is set, the key is read from the cert file itself.
    pub(crate) client_key: Option<String>,
    /// Passphrase for an encrypted client key (curl `--pass`).
    pub(crate) client_key_pass: Option<String>,
    /// `true` if the client cert file is DER (curl `--cert-type DER`).
    pub(crate) cert_is_der: bool,
    /// `true` if the client key file is DER (curl `--key-type DER`).
    pub(crate) key_is_der: bool,
    /// `--pinnedpubkey` spec (`sha256//BASE64[;...]`). Parsed in
    /// [`tls_opts_from`] into SHA-256 SPKI pins.
    pub(crate) pinned_pubkey: Option<String>,
    /// Directory of additional CA certificates to trust (curl `--capath`),
    /// added on top of the system roots / `--cacert` bundle.
    pub(crate) ca_path: Option<String>,
    /// Path to a CRL file (curl `--crlfile`) to check the server chain against.
    /// Honored by the purecrypto-tls backend; the rustls backend errors.
    pub(crate) crl_file: Option<String>,
    /// Cipher-suite restriction (curl `--ciphers`, TLS≤1.2 OpenSSL names) +
    /// (curl `--tls13-ciphers`, IANA names). Parsed to IANA IDs in
    /// [`tls_opts_from`]. Honored by purecrypto-tls; the rustls backend errors.
    pub(crate) ciphers: Option<String>,
    pub(crate) tls13_ciphers: Option<String>,
}

/// Address-family preference for connecting (curl `-4`/`-6`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpFamily {
    V4,
    V6,
}

/// Where to route HTTP(S) traffic through. Parsed from a curl-style proxy
/// URL — typically `http://user:pass@host:port`. Only `http://` proxies are
/// supported in this milestone; TLS-to-proxy (`https://`) and SOCKS are
/// rejected with [`Error::UnsupportedScheme`].
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub host: String,
    pub port: u16,
    /// Credentials to send in `Proxy-Authorization: Basic`. Either parsed
    /// from `user:pass@proxy` in the proxy URL or supplied separately via
    /// [`Request::proxy_user`].
    pub auth: Option<(String, String)>,
}

impl ProxyConfig {
    /// Parse a proxy URL such as `http://proxy:8080` or
    /// `http://user:pass@proxy:3128`. A bare `host:port` (no scheme) is
    /// also accepted and treated as `http://` — curl behaves the same way
    /// for the value of `-x`.
    pub fn parse(s: &str) -> Result<Self> {
        // Curl accepts `proxy:8080` (no scheme); add one so the URL parser
        // is happy and our scheme check below still rejects exotic schemes.
        let normalised: String = if s.contains("://") {
            s.to_string()
        } else {
            format!("http://{s}")
        };
        let u = Url::parse(&normalised)?;
        if u.scheme != "http" {
            return Err(Error::UnsupportedScheme(format!(
                "proxy scheme {:?} not supported (only http:// at this milestone)",
                u.scheme
            )));
        }
        let auth = u
            .userinfo
            .as_deref()
            .map(|info| match info.split_once(':') {
                Some((u, p)) => (u.to_string(), p.to_string()),
                None => (info.to_string(), String::new()),
            });
        Ok(ProxyConfig {
            host: u.host.clone(),
            port: u.port,
            auth,
        })
    }
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
            proxy: None,
            no_proxy: Vec::new(),
            idn: true,
            connector: Arc::new(DirectConnector),
            ip_family: None,
            resolve: Vec::new(),
            auto_referer: false,
            redirect_trusted: false,
            keep_post: [false; 3],
            connect_to: Vec::new(),
            tls_min: None,
            tls_max: None,
            auth_digest: false,
            client_cert: None,
            client_key: None,
            client_key_pass: None,
            cert_is_der: false,
            key_is_der: false,
            pinned_pubkey: None,
            ca_path: None,
            crl_file: None,
            ciphers: None,
            tls13_ciphers: None,
        })
    }

    /// Authenticate with HTTP Digest using the `-u` credentials (curl
    /// `--digest`): the request is sent unauthenticated, then retried with a
    /// `Digest` response to the server's `401` challenge.
    pub fn digest_auth(mut self, on: bool) -> Self {
        self.auth_digest = on;
        self
    }

    /// Sign the request with AWS Signature V4 (curl `--aws-sigv4`). `spec` is
    /// curl-style `provider1[:provider2[:region[:service]]]`; `region`/`service`
    /// default to the URL host's 2nd/1st labels (else `us-east-1`/`s3`). Adds
    /// `Authorization` + `X-Amz-Date` + `X-Amz-Content-Sha256` headers.
    pub fn aws_sigv4(mut self, spec: &str, access: &str, secret: &str) -> Self {
        let parts: Vec<&str> = spec.split(':').collect();
        let labels: Vec<&str> = self.url.host.split('.').collect();
        let region = parts
            .get(2)
            .filter(|s| !s.is_empty())
            .copied()
            .or_else(|| labels.get(1).copied())
            .unwrap_or("us-east-1");
        let service = parts
            .get(3)
            .filter(|s| !s.is_empty())
            .copied()
            .or_else(|| labels.first().copied())
            .unwrap_or("s3");
        let (path, query) = match self.url.path.split_once('?') {
            Some((p, q)) => (p.to_string(), q.to_string()),
            None => (self.url.path.clone(), String::new()),
        };
        let amz = crate::sigv4::amz_date_now();
        let cfg = crate::sigv4::SigV4 {
            access_key: access,
            secret_key: secret,
            region,
            service,
        };
        let host = self.url.host.clone();
        let method = self.method.clone();
        let body = self.body.clone();
        for (k, v) in crate::sigv4::sign(&cfg, &method, &host, &path, &query, &body, &amz) {
            self.headers.retain(|(hk, _)| !hk.eq_ignore_ascii_case(&k));
            self.headers.push((k, v));
        }
        self
    }

    /// Minimum acceptable TLS version (curl `--tlsv1.x`).
    pub fn tls_min_version(mut self, v: crate::tls::ProtocolVersion) -> Self {
        self.tls_min = Some(v);
        self
    }

    /// Maximum acceptable TLS version (curl `--tls-max`).
    pub fn tls_max_version(mut self, v: crate::tls::ProtocolVersion) -> Self {
        self.tls_max = Some(v);
        self
    }

    /// Add a connect-target override (curl `--connect-to`): requests to
    /// `from_host:from_port` instead connect to `to_host:to_port`, keeping the
    /// original `Host:`/SNI. Empty `from_host` / zero `from_port` are wildcards.
    pub fn connect_to(
        mut self,
        from_host: &str,
        from_port: u16,
        to_host: &str,
        to_port: u16,
    ) -> Self {
        self.connect_to.push((
            from_host.to_string(),
            from_port,
            to_host.to_string(),
            to_port,
        ));
        self
    }

    /// Keep `Authorization`/`Cookie` on cross-host redirects (curl
    /// `--location-trusted`).
    pub fn redirect_trusted(mut self, on: bool) -> Self {
        self.redirect_trusted = on;
        self
    }

    /// Preserve the method (don't downgrade POST→GET) on the given 3xx status
    /// (301/302/303) — curl `--post301`/`--post302`/`--post303`.
    pub fn keep_post_on(mut self, status: u16) -> Self {
        if (301..=303).contains(&status) {
            self.keep_post[(status - 301) as usize] = true;
        }
        self
    }

    /// Send `Referer:` from the previous URL on each redirect (curl `-e ;auto`).
    pub fn auto_referer(mut self, on: bool) -> Self {
        self.auto_referer = on;
        self
    }

    /// Force IPv4 for the connection (curl `-4`).
    pub fn ipv4(mut self) -> Self {
        self.ip_family = Some(IpFamily::V4);
        self
    }

    /// Force IPv6 for the connection (curl `-6`).
    pub fn ipv6(mut self) -> Self {
        self.ip_family = Some(IpFamily::V6);
        self
    }

    /// Add a static DNS override (curl `--resolve`): connections to
    /// `host:port` use `ip` instead of resolving.
    pub fn resolve_addr(mut self, host: &str, port: u16, ip: std::net::IpAddr) -> Self {
        self.resolve.push((host.to_string(), port, ip));
        self
    }

    pub fn get(url: &str) -> Result<Self> {
        Self::new("GET", url)
    }

    /// Override the HTTP method (uppercased), keeping every other setting. Curl
    /// `-X`. Useful to turn a configured request into a `HEAD` probe without
    /// rebuilding it.
    pub fn method(mut self, method: &str) -> Self {
        self.method = method.to_ascii_uppercase();
        self
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

    /// Attempt HTTP/3 over QUIC, falling back to HTTP/2/HTTP/1.1 on a
    /// transport-level failure. Equivalent to `curl --http3` for an
    /// `https://` URL. Has no effect on plaintext `http://` requests.
    pub fn http3(mut self) -> Self {
        self.http_version_pref = HttpVersionPref::Http3;
        self
    }

    /// Force HTTP/3 over QUIC; the request fails if a QUIC connection can't
    /// be established. No fallback. Equivalent to `curl --http3-only`.
    pub fn http3_only(mut self) -> Self {
        self.http_version_pref = HttpVersionPref::Http3Only;
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

    /// Toggle IDN (international hostname → punycode) conversion. On by
    /// default; `false` matches curl `--no-idn`. No effect when the crate is
    /// built without the `idn` feature.
    pub fn idn(mut self, on: bool) -> Self {
        self.idn = on;
        self
    }

    /// Use a custom CA bundle (PEM) instead of the system trust store.
    pub fn ca_bundle(mut self, path: &str) -> Self {
        self.ca_bundle = Some(path.to_string());
        self
    }

    /// Trust additional CA certificates from every file in `dir`, on top of
    /// the system roots (or a `--cacert` bundle). Curl's `--capath`.
    pub fn ca_path(mut self, dir: &str) -> Self {
        self.ca_path = Some(dir.to_string());
        self
    }

    /// Check the server certificate chain against the CRL in `path` (curl
    /// `--crlfile`). Honored by the default purecrypto-tls backend; the
    /// rustls-tls backend returns an error.
    pub fn crl_file(mut self, path: &str) -> Self {
        self.crl_file = Some(path.to_string());
        self
    }

    /// Restrict the offered TLS≤1.2 cipher suites (curl `--ciphers`, a
    /// colon-separated OpenSSL/IANA name list). Honored by purecrypto-tls.
    pub fn ciphers(mut self, list: &str) -> Self {
        self.ciphers = Some(list.to_string());
        self
    }

    /// Restrict the offered TLS 1.3 cipher suites (curl `--tls13-ciphers`,
    /// colon-separated IANA `TLS_*` names). Honored by purecrypto-tls.
    pub fn tls13_ciphers(mut self, list: &str) -> Self {
        self.tls13_ciphers = Some(list.to_string());
        self
    }

    /// Present a client certificate for mutual TLS (curl `-E`/`--cert`).
    /// `path` is the cert file; if no separate [`Self::client_key`] is set the
    /// key is read from the same file. Default type is PEM
    /// (see [`Self::cert_type_der`]).
    pub fn client_cert(mut self, path: &str) -> Self {
        self.client_cert = Some(path.to_string());
        self
    }

    /// Path to the client private key (curl `--key`). Optional when the key is
    /// embedded in the cert file.
    pub fn client_key(mut self, path: &str) -> Self {
        self.client_key = Some(path.to_string());
        self
    }

    /// Passphrase for an encrypted client key (curl `--pass`, or the `:pass`
    /// suffix of `-E cert:pass`).
    pub fn client_key_pass(mut self, pass: &str) -> Self {
        self.client_key_pass = Some(pass.to_string());
        self
    }

    /// Treat the client certificate file as DER (curl `--cert-type DER`).
    /// Default is PEM.
    pub fn cert_type_der(mut self, der: bool) -> Self {
        self.cert_is_der = der;
        self
    }

    /// Treat the client key file as DER (curl `--key-type DER`). Default is PEM.
    pub fn key_type_der(mut self, der: bool) -> Self {
        self.key_is_der = der;
        self
    }

    /// Pin the server's public key (curl `--pinnedpubkey`). `spec` is
    /// `sha256//BASE64[;sha256//BASE64...]`; the leaf cert's SPKI SHA-256 must
    /// match one of the pins or the connection fails. The spec is parsed into
    /// SHA-256 SPKI pins when the TLS options are built for the request.
    pub fn pinned_pubkey(mut self, spec: &str) -> Self {
        self.pinned_pubkey = Some(spec.to_string());
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

    /// Per-read inactivity timeout: the longest a single socket read may block
    /// waiting for data. A fully stalled peer errors after this; a slow but
    /// progressing transfer never trips it. Defaults to 60 s (see
    /// [`Request::new`]); `None` disables it (block indefinitely). This is the
    /// inactivity guard, distinct from the whole-operation cap [`max_time`].
    ///
    /// [`max_time`]: Self::max_time
    pub fn read_timeout(mut self, d: Option<Duration>) -> Self {
        self.read_timeout = d;
        self
    }

    /// Route through an outbound proxy. `spec` is curl-style:
    /// `scheme://[user:pass@]host:port`, or bare `host:port` (treated as
    /// `http://`). Recognised schemes: `http`, `https`, `socks4`, `socks4a`,
    /// `socks5`, `socks5h`.
    ///
    /// `http://` proxies use the absolute-form / `CONNECT` path. The other
    /// schemes install a [`Connector`] (see [`Request::connector`]); in this
    /// milestone they force HTTP/1.1 and disable connection pooling.
    pub fn proxy(mut self, spec: &str) -> Result<Self> {
        let is_http_proxy = match spec.split_once("://") {
            Some((scheme, _)) => scheme.eq_ignore_ascii_case("http"),
            None => true, // bare host:port == http://
        };
        if is_http_proxy {
            self.proxy = Some(ProxyConfig::parse(spec)?);
        } else {
            self.connector = connector_from_proxy_url(spec)?;
        }
        Ok(self)
    }

    /// Use a caller-supplied transport for this request. Overrides the default
    /// direct TCP dial; a non-direct connector forces HTTP/1.1 and disables
    /// pooling in this milestone. See [`crate::net::Connector`].
    pub fn connector(mut self, connector: Arc<dyn Connector>) -> Self {
        self.connector = connector;
        self
    }

    /// Override (or add) proxy `user:pass` credentials independently of
    /// the proxy URL. Mirrors curl `--proxy-user`.
    pub fn proxy_user(mut self, user: &str, pass: &str) -> Result<Self> {
        match self.proxy.as_mut() {
            Some(p) => {
                p.auth = Some((user.to_string(), pass.to_string()));
                Ok(self)
            }
            None => Err(Error::BadResponse(
                "proxy_user called without a proxy set".into(),
            )),
        }
    }

    /// Replace the no-proxy list (curl `NO_PROXY` / `--noproxy`). Each
    /// entry is a host suffix matched case-insensitively against the
    /// target URL's host; a single `*` means "bypass for every host".
    pub fn no_proxy<I, S>(mut self, entries: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.no_proxy = entries.into_iter().map(Into::into).collect();
        self
    }

    pub fn send(self) -> Result<Response> {
        self.send_to(&mut io::sink(), None)
    }

    /// Like [`send`](Self::send), but writes a curl-style `-v` trace to
    /// `trace` as the request progresses: `*` lines for connection / TLS
    /// events, `>` lines for every byte of the request actually placed on
    /// the wire, `<` lines for every status / header byte received. The
    /// trace is built from the same buffers used for I/O, so it cannot
    /// drift from what was sent.
    pub fn send_traced(self, trace: &mut dyn Write) -> Result<Response> {
        self.send_to(trace, None)
    }

    /// Send with cookie support. The jar is consulted before each hop to
    /// inject a `Cookie:` header matching the destination URL, and is
    /// updated with every `Set-Cookie:` line in each response — including
    /// cookies set on intermediate redirect responses. Equivalent to curl's
    /// `-b`/`-c` machinery.
    pub fn send_with_jar(self, jar: &mut crate::cookie::CookieJar) -> Result<Response> {
        self.send_to(&mut io::sink(), Some(jar))
    }

    /// Combination of [`Self::send_traced`] and [`Self::send_with_jar`].
    pub fn send_traced_with_jar(
        self,
        jar: &mut crate::cookie::CookieJar,
        trace: &mut dyn Write,
    ) -> Result<Response> {
        self.send_to(trace, Some(jar))
    }

    /// Stream the response body straight to `sink` instead of buffering it,
    /// so the CLI can apply progress / rate-limit / size-cap per chunk and not
    /// hold large downloads in memory.
    ///
    /// Streaming applies only to a direct (no proxy / custom connector)
    /// HTTP/1.1 connection whose final response has no `Content-Encoding`.
    /// Every other case (HTTP/2 or /3, a proxy, a compressed or empty body)
    /// falls back to the buffered path and writes the resulting body to `sink`.
    /// The returned [`Response`] carries the final status/headers; its `body`
    /// is empty because the bytes went to `sink`.
    pub fn send_download(
        self,
        sink: &mut dyn Write,
        mut jar: Option<&mut crate::cookie::CookieJar>,
        trace: &mut dyn Write,
    ) -> Result<Response> {
        let direct = self.connector.is_direct() && self.proxy.is_none();
        // HTTP/1.1 streaming (plaintext, or `--http1.1`) — follows redirects and
        // manages cookies itself.
        let h1_streamable = direct
            && (self.url.scheme == "http"
                || matches!(self.http_version_pref, HttpVersionPref::Http11Only));
        if h1_streamable {
            return self.stream_h1(sink, jar, trace);
        }
        // HTTP/2 streaming for a direct https GET when h2 is allowed and we are
        // not following redirects (the buffered path handles cross-protocol
        // redirect chains). A custom/proxy connector or `--http1.1` skips this.
        let h2_streamable = direct
            && self.url.scheme == "https"
            && !self.follow_redirects
            && matches!(
                self.http_version_pref,
                HttpVersionPref::Auto | HttpVersionPref::Http2Only
            );
        if h2_streamable {
            let mut req = self;
            req.url.set_idn(req.idn)?;
            // Attach jar cookies to the request, then ingest Set-Cookie below.
            if let Some(j) = jar.as_deref_mut() {
                j.purge_expired();
                req.headers
                    .retain(|(k, _)| !k.eq_ignore_ascii_case("cookie"));
                if let Some(val) = j.cookie_header(&req.url) {
                    req.headers.push(("Cookie".to_string(), val));
                }
            }
            let url = req.url.clone();
            let force_h2 = matches!(req.http_version_pref, HttpVersionPref::Http2Only);
            // Keep a copy to retry over HTTP/1.1 if the server doesn't pick h2.
            let fallback = (!force_h2).then(|| {
                let mut fb = req.clone();
                fb.http_version_pref = HttpVersionPref::Http11Only;
                fb
            });
            match crate::http2::send_to(req, sink, trace) {
                Ok(resp) => {
                    if let Some(j) = jar {
                        j.ingest_response(&url, &resp.headers);
                    }
                    return Ok(resp);
                }
                // Auto: server didn't select h2 — retry the same request forced
                // to HTTP/1.1, which streams via `stream_h1` (it's now https +
                // Http11Only). The jar is re-applied there.
                Err(Error::H2NotNegotiated) => {
                    if let Some(fb) = fallback {
                        return fb.send_download(sink, jar, trace);
                    }
                    return Err(Error::H2NotNegotiated);
                }
                Err(e) => return Err(e),
            }
        }
        // HTTP/3 streaming for a direct https GET under `--http3`/`--http3-only`
        // when not following redirects. On a QUIC transport failure with
        // `--http3` (not `--http3-only`), retry the request over the Auto path.
        let h3_streamable = direct
            && self.url.scheme == "https"
            && !self.follow_redirects
            && matches!(
                self.http_version_pref,
                HttpVersionPref::Http3 | HttpVersionPref::Http3Only
            );
        if h3_streamable {
            let mut req = self;
            req.url.set_idn(req.idn)?;
            if let Some(j) = jar.as_deref_mut() {
                j.purge_expired();
                req.headers
                    .retain(|(k, _)| !k.eq_ignore_ascii_case("cookie"));
                if let Some(val) = j.cookie_header(&req.url) {
                    req.headers.push(("Cookie".to_string(), val));
                }
            }
            let url = req.url.clone();
            let force_h3 = matches!(req.http_version_pref, HttpVersionPref::Http3Only);
            let fallback = (!force_h3).then(|| {
                let mut fb = req.clone();
                fb.http_version_pref = HttpVersionPref::Auto;
                fb
            });
            match crate::http3::send_to(req, sink, trace) {
                Ok(resp) => {
                    if let Some(j) = jar {
                        j.ingest_response(&url, &resp.headers);
                    }
                    return Ok(resp);
                }
                Err(e) if fallback.is_some() && h3_should_fall_back(&e) => {
                    let _ = writeln!(trace, "* HTTP/3 failed ({e}); falling back");
                    return fallback.unwrap().send_download(sink, jar, trace);
                }
                Err(e) => return Err(e),
            }
        }
        self.send_download_buffered(sink, jar, trace)
    }

    /// Buffered download fallback: perform the request normally (following
    /// redirects, h2/h3 negotiation, proxy, decode) and copy the materialized
    /// body to `sink`. Used when streaming isn't applicable.
    fn send_download_buffered(
        self,
        sink: &mut dyn Write,
        jar: Option<&mut crate::cookie::CookieJar>,
        trace: &mut dyn Write,
    ) -> Result<Response> {
        let resp = self.send_to(trace, jar)?;
        sink.write_all(&resp.body)?;
        Ok(Response {
            body: Vec::new(),
            ..resp
        })
    }

    /// HTTP/1.1 streaming download with redirect following (the streamable
    /// branch of [`Self::send_download`]).
    fn stream_h1(
        self,
        sink: &mut dyn Write,
        mut jar: Option<&mut crate::cookie::CookieJar>,
        trace: &mut dyn Write,
    ) -> Result<Response> {
        let mut req = self;
        req.url.set_idn(req.idn)?;
        let mut hops_left = req.max_redirs;
        loop {
            let start = std::time::Instant::now();
            let mut timing = Timing::default();
            let stream: Box<dyn Rw> = if req.url.scheme == "https" {
                let tcp = tcp_connect(&req, trace)?;
                timing.connect = Some(start.elapsed());
                let opts = tls_opts_from(&req, &[])?;
                let tls = crate::tls::connect_over_tls(tcp, &req.url.host, opts)?;
                let appconnect = start.elapsed();
                timing.appconnect = Some(appconnect);
                timing.pretransfer = Some(appconnect);
                write_tls_info(&tls, trace);
                Box::new(tls)
            } else {
                let tcp = tcp_connect(&req, trace)?;
                let connect = start.elapsed();
                timing.connect = Some(connect);
                timing.pretransfer = Some(connect);
                Box::new(tcp)
            };
            let mut bufrd = BufReader::new(stream);

            // Attach a jar-managed Cookie header to a snapshot of the request.
            let mut snapshot = req.clone();
            if let Some(j) = jar.as_deref_mut() {
                j.purge_expired();
                snapshot
                    .headers
                    .retain(|(k, _)| !k.eq_ignore_ascii_case("cookie"));
                if let Some(val) = j.cookie_header(&snapshot.url) {
                    snapshot.headers.push(("Cookie".to_string(), val));
                }
            }
            write_request(
                bufrd.get_mut(),
                &snapshot,
                via_plain_http_proxy(&req),
                trace,
            )?;
            let head = read_head(&mut bufrd, trace)?;
            timing.starttransfer = Some(start.elapsed());
            if let Some(j) = jar.as_deref_mut() {
                j.ingest_response(&req.url, &head.headers);
            }

            // Follow a redirect (mirrors `send_to`'s logic, operating on the
            // head; the small redirect body is drained first).
            if req.follow_redirects && is_redirect_status(head.status) {
                if let Some((_, loc)) = head
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("location"))
                {
                    let location = loc.clone();
                    let _ = read_body(
                        &mut bufrd,
                        &head.headers,
                        &head.version,
                        head.status,
                        &req.method,
                    )?;
                    if hops_left == 0 {
                        return Err(Error::BadResponse(format!(
                            "maximum ({}) redirects followed",
                            req.max_redirs
                        )));
                    }
                    let mut next_url = crate::url::resolve(&req.url, &location)?;
                    // Only http/https are drivable here; reject e.g. a
                    // `gopher://`/`ftp://` Location rather than silently
                    // treating it as plaintext HTTP (mirrors `send_once`).
                    if next_url.scheme != "http" && next_url.scheme != "https" {
                        return Err(Error::UnsupportedScheme(next_url.scheme.clone()));
                    }
                    next_url.set_idn(req.idn)?;
                    let _ = writeln!(
                        trace,
                        "* Following redirect to {}",
                        url_to_string(&next_url)
                    );
                    let host_changed = next_url.host != req.url.host
                        || next_url.port != req.url.port
                        || next_url.scheme != req.url.scheme;
                    let prev_method = req.method.clone();
                    let prev_url = url_to_string(&req.url);
                    let prev_body = std::mem::take(&mut req.body);
                    let status = head.status;
                    let mut next = req;
                    next.url = next_url;
                    if next.auto_referer {
                        next.headers
                            .retain(|(k, _)| !k.eq_ignore_ascii_case("referer"));
                        next.headers.push(("Referer".to_string(), prev_url));
                    }
                    if host_changed && !next.redirect_trusted {
                        next.headers.retain(|(k, _)| {
                            !k.eq_ignore_ascii_case("authorization")
                                && !k.eq_ignore_ascii_case("cookie")
                        });
                        next.basic_auth = None;
                    }
                    let keep_post = if (301..=303).contains(&status) {
                        next.keep_post[(status - 301) as usize]
                    } else {
                        false
                    };
                    if (301..=303).contains(&status)
                        && !keep_post
                        && !prev_method.eq_ignore_ascii_case("GET")
                        && !prev_method.eq_ignore_ascii_case("HEAD")
                    {
                        next.method = "GET".to_string();
                        next.headers.retain(|(k, _)| {
                            !k.eq_ignore_ascii_case("content-type")
                                && !k.eq_ignore_ascii_case("content-length")
                                && !k.eq_ignore_ascii_case("transfer-encoding")
                        });
                    } else {
                        next.body = prev_body;
                    }
                    hops_left -= 1;
                    req = next;
                    continue;
                }
                // 3xx without Location — treat as the final response.
            }

            // Final response. A `Content-Encoding` means we must decode.
            let content_encoding = head
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-encoding"))
                .map(|(_, v)| v.clone());
            if let Some(ce) = content_encoding {
                // Fast path: a single gzip/zstd/br layer over a Content-Length
                // body decodes straight off the wire (bounded by the decoder's
                // budget) without buffering the compressed body. deflate (zlib
                // vs raw ambiguity), multi-layer, chunked, and unknown codings
                // fall through to the buffered decode below.
                let chunked = head.headers.iter().any(|(k, v)| {
                    k.eq_ignore_ascii_case("transfer-encoding") && v.eq_ignore_ascii_case("chunked")
                });
                let has_body = !(req.method.eq_ignore_ascii_case("HEAD")
                    || (100..200).contains(&head.status)
                    || head.status == 204
                    || head.status == 304);
                if has_body && !chunked {
                    if let (Some(codec), Some(len)) = (
                        crate::compress::single_streamable_layer(&ce),
                        parse_content_length(&head.headers)?,
                    ) {
                        if len > MAX_BODY_BYTES as u64 {
                            return Err(Error::BadResponse(format!("body too large: {len}")));
                        }
                        let n = crate::compress::stream_decode(
                            bufrd.by_ref().take(len),
                            codec,
                            sink,
                            MAX_BODY_BYTES as u64,
                        )?;
                        let _ = writeln!(trace, "* Stream-decoded {n} body bytes ({codec:?})");
                        return Ok(Response {
                            status: head.status,
                            reason: head.reason,
                            version: head.version,
                            headers: crate::compress::strip_after_decode(head.headers),
                            body: Vec::new(),
                            timing,
                            final_url: url_to_string(&req.url),
                        });
                    }
                }
                // Buffered fallback (deflate / multi-layer / chunked / unknown).
                let body = read_body(
                    &mut bufrd,
                    &head.headers,
                    &head.version,
                    head.status,
                    &req.method,
                )?;
                let (headers, body) = maybe_decode_body(head.headers, body, trace)?;
                sink.write_all(&body)?;
                return Ok(Response {
                    status: head.status,
                    reason: head.reason,
                    version: head.version,
                    headers,
                    body: Vec::new(),
                    timing,
                    final_url: url_to_string(&req.url),
                });
            }
            let n = stream_body(&mut bufrd, sink, &head.headers, head.status, &req.method)?;
            let _ = writeln!(trace, "* Streamed {n} body bytes");
            return Ok(Response {
                status: head.status,
                reason: head.reason,
                version: head.version,
                headers: head.headers,
                body: Vec::new(),
                timing,
                final_url: url_to_string(&req.url),
            });
        }
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
    ///
    /// `jar`, when present, is consulted before each hop to attach a
    /// matching `Cookie:` header and is updated from each response's
    /// `Set-Cookie:` lines — including those on the intermediate 3xx hops
    /// the redirect chain walks through.
    fn send_to(
        self,
        trace: &mut dyn Write,
        mut jar: Option<&mut crate::cookie::CookieJar>,
    ) -> Result<Response> {
        let mut req = self;
        // Normalise the host to ASCII/punycode (IDN) once up front, so DNS,
        // the `Host:` header, TLS SNI, and cookie matching all see the same
        // ASCII host. Redirect targets are normalised the same way below.
        req.url.set_idn(req.idn)?;
        // For Digest auth, withhold the Basic credentials so the first request
        // goes out unauthenticated; we answer the 401 challenge below.
        let digest_creds = if req.auth_digest {
            req.basic_auth.take()
        } else {
            None
        };
        let mut digest_tried = false;
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
            let mut snapshot = req.clone();
            // Jar-managed Cookie: header. We always strip prior Cookie:
            // entries from the snapshot before re-injecting from the jar,
            // because the previous hop's cookie line is stale once the URL
            // (and thus the matching set) has changed.
            if let Some(j) = jar.as_deref_mut() {
                j.purge_expired();
                snapshot
                    .headers
                    .retain(|(k, _)| !k.eq_ignore_ascii_case("cookie"));
                if let Some(val) = j.cookie_header(&snapshot.url) {
                    snapshot.headers.push(("Cookie".to_string(), val));
                }
            }
            let mut resp = snapshot.send_once(trace)?;
            if let Some(j) = jar.as_deref_mut() {
                j.ingest_response(&req.url, &resp.headers);
            }
            // Digest auth: answer a 401 Digest challenge once, then resend.
            if resp.status == 401 && !digest_tried {
                if let (Some((u, p)), Some(chal)) =
                    (digest_creds.as_ref(), resp.header("www-authenticate"))
                {
                    let scheme = chal.trim_start();
                    // Byte-index slicing here would panic if offset 6 is not a
                    // UTF-8 char boundary, so compare the raw bytes instead —
                    // `chal` is the attacker-controlled WWW-Authenticate value.
                    if scheme
                        .as_bytes()
                        .get(..6)
                        .is_some_and(|b| b.eq_ignore_ascii_case(b"digest"))
                    {
                        if let Some(h) =
                            crate::digest::authorization(u, p, &req.method, &req.url.path, chal)
                        {
                            req.headers
                                .retain(|(k, _)| !k.eq_ignore_ascii_case("authorization"));
                            req.headers.push(("Authorization".to_string(), h));
                            digest_tried = true;
                            continue;
                        }
                    }
                }
            }
            if !req.follow_redirects || !is_redirect_status(resp.status) {
                resp.final_url = url_to_string(&req.url);
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
                None => {
                    // 3xx without Location — give it back as the final response.
                    resp.final_url = url_to_string(&req.url);
                    return Ok(resp);
                }
            };
            let mut next_url = crate::url::resolve(&req.url, &location)?;
            // Apply the same IDN normalisation to the redirect target so the
            // host-change check below and all downstream use compare/operate on
            // the ASCII form (an absolute `Location` may carry a Unicode host).
            next_url.set_idn(req.idn)?;
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
            let prev_url = url_to_string(&req.url);
            let prev_body = std::mem::take(&mut req.body);
            let mut next = req;
            next.url = next_url;
            // -e ';auto': set Referer to the URL we are coming from.
            if next.auto_referer {
                next.headers
                    .retain(|(k, _)| !k.eq_ignore_ascii_case("referer"));
                next.headers.push(("Referer".to_string(), prev_url));
            }
            // --location-trusted keeps credentials across hosts.
            if host_changed && !next.redirect_trusted {
                next.headers.retain(|(k, _)| {
                    !k.eq_ignore_ascii_case("authorization") && !k.eq_ignore_ascii_case("cookie")
                });
                next.basic_auth = None;
            }

            // Method/body rewriting per RFC 9110 §15.4 plus curl's default
            // backward-compat behaviour: 301/302/303 rewrite POST/PUT/etc
            // to GET and drop the body; 307/308 preserve method + body.
            // --post301/302/303 opt out of the downgrade for that status.
            let keep_post = if (301..=303).contains(&resp.status) {
                next.keep_post[(resp.status - 301) as usize]
            } else {
                false
            };
            if (301..=303).contains(&resp.status)
                && !keep_post
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
    /// Per-phase timings for `--write-out` `%{time_*}` variables. Populated on
    /// the direct HTTP/1.1 + HTTPS paths; left empty on reused (pooled)
    /// connections and the HTTP/2 / HTTP/3 backends (see [`Timing`]).
    pub timing: Timing,
    /// The effective URL the response came from — the last hop after any
    /// redirects (curl `CURLINFO_EFFECTIVE_URL`). Set by the buffered
    /// [`send`](Request::send) / `send_to` path; empty on the streaming and
    /// HTTP/2-multiplexed paths, where callers should fall back to the
    /// requested URL.
    pub final_url: String,
}

/// Per-phase wall-clock timings for `--write-out` (`%{time_connect}` etc.),
/// each measured from the start of the (final) request attempt.
///
/// These are filled only on the direct HTTP/1.1 and HTTPS code paths. On a
/// connection reused from the pool, and on the HTTP/2 and HTTP/3 backends, the
/// fields are `None` — those transfers report only `%{time_total}`. A `None`
/// field renders as `0.000000`, matching curl's output for an unmeasured phase.
#[derive(Debug, Clone, Default)]
pub struct Timing {
    /// Time until the TCP connection to the origin was established.
    pub connect: Option<Duration>,
    /// Time until the TLS handshake completed (HTTPS only).
    pub appconnect: Option<Duration>,
    /// Time until just before the request bytes were written.
    pub pretransfer: Option<Duration>,
    /// Time until the full response head had been received (first-byte proxy).
    pub starttransfer: Option<Duration>,
}

impl Response {
    /// Returns the first value of a header, case-insensitive.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The `charset` parameter of the `Content-Type` header, lowercased and
    /// unquoted, if present (e.g. `Some("utf-8")`).
    fn charset(&self) -> Option<String> {
        let ct = self.header("content-type")?;
        for param in ct.split(';').skip(1) {
            let param = param.trim();
            let (k, v) = param.split_once('=')?;
            if k.trim().eq_ignore_ascii_case("charset") {
                return Some(v.trim().trim_matches('"').to_ascii_lowercase());
            }
        }
        None
    }

    /// Decode the response body to a `String` using the `Content-Type` charset.
    ///
    /// The body has already been transparently decompressed (gzip/deflate/br/
    /// zstd) before this point. UTF-8 (the default when no charset is declared)
    /// is decoded lossily — invalid sequences become `U+FFFD`, like
    /// `reqwest::Response::text`; ISO-8859-1 / Latin-1 is mapped directly. A
    /// declared charset rsurl can't decode returns [`Error::Decode`] (use
    /// [`Response::body`](Self::body) for the raw bytes).
    pub fn text(&self) -> Result<String> {
        match self.charset().as_deref() {
            None | Some("utf-8") | Some("utf8") | Some("us-ascii") | Some("ascii") => {
                Ok(String::from_utf8_lossy(&self.body).into_owned())
            }
            // Latin-1 code points are exactly Unicode U+00..=U+FF, so a byte→char
            // map is a faithful decode (unlike windows-1252, which differs in
            // 0x80–0x9F and is therefore rejected rather than mis-decoded).
            Some("iso-8859-1") | Some("iso8859-1") | Some("latin1") => {
                Ok(self.body.iter().map(|&b| b as char).collect())
            }
            Some(other) => Err(Error::Decode(format!(
                "unsupported Content-Type charset {other:?}; \
                 use Response::body for the raw {} bytes",
                self.body.len()
            ))),
        }
    }

    /// Deserialize the response body as JSON into `T`. Requires the `json`
    /// Cargo feature (pure-Rust `serde_json`, off by default).
    ///
    /// ```ignore
    /// let issues: Vec<Issue> = rsurl::get(url)?.error_for_status()?.json()?;
    /// ```
    #[cfg(feature = "json")]
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body).map_err(|e| Error::Decode(format!("json: {e}")))
    }

    /// Consume the response, returning it unchanged for a 1xx–3xx status or
    /// [`Error::Status`] for a 4xx/5xx one — the reqwest-style "turn an HTTP
    /// error status into a `Result` error" convenience.
    ///
    /// ```ignore
    /// let body = rsurl::get(url)?.error_for_status()?.text()?;
    /// ```
    pub fn error_for_status(self) -> Result<Self> {
        if self.status >= 400 {
            Err(Error::Status {
                code: self.status,
                reason: self.reason.clone(),
            })
        } else {
            Ok(self)
        }
    }
}

fn send_plain(req: Request, trace: &mut dyn Write) -> Result<Response> {
    // HTTP/3 runs only over QUIC, which is encrypted by construction, so it
    // has no meaning for a plaintext `http://` URL. `--http3-only` is a hard
    // requirement and must fail; `--http3` is a preference, so we just note it
    // and proceed over HTTP/1.1.
    match req.http_version_pref {
        HttpVersionPref::Http3Only => {
            return Err(Error::UnsupportedScheme(
                "http/3 requires https://, not http://".into(),
            ));
        }
        HttpVersionPref::Http3 => {
            let _ = writeln!(
                trace,
                "* HTTP/3 requested but URL is http://; using HTTP/1.1 (h3 needs https)"
            );
        }
        _ => {}
    }
    // A custom/SOCKS/https-proxy connector handles its own dialing and is not
    // pool-compatible; route it through the boxed HTTP/1.1 path.
    if !req.connector.is_direct() {
        return send_plain_via_connector(req, trace);
    }
    // Pool reuse is only safe for direct connections. Via-proxy we'd be
    // sharing one socket across many origins via absolute-form lines, which
    // works on paper but mixes badly with `Proxy-Authorization:` per-origin
    // semantics — out of scope for this milestone.
    let direct = req.proxy.is_none() || proxy_bypassed(&req);
    if direct {
        if let Some(bufrd) = pool_checkout_plain(&req) {
            let _ = writeln!(trace, "* Reusing existing connection from pool");
            match perform_on_pooled_plain(bufrd, &req, trace) {
                Ok(resp) => return Ok(resp),
                Err(PooledError::Stale(why)) => {
                    let _ = writeln!(trace, "* Pooled connection unusable ({why}); reconnecting");
                    // fall through to a fresh dial
                }
                Err(PooledError::Hard(e)) => return Err(e),
            }
        }
    }
    send_plain_fresh(req, direct, trace)
}

fn send_plain_fresh(req: Request, may_pool: bool, trace: &mut dyn Write) -> Result<Response> {
    let start = std::time::Instant::now();
    let stream = tcp_connect(&req, trace)?;
    let connect = start.elapsed();
    let mut bufrd = BufReader::new(stream);
    write_request(bufrd.get_mut(), &req, via_plain_http_proxy(&req), trace)?;
    let mut resp = read_response_timed(&mut bufrd, &req.method, Some(start), trace)?;
    resp.timing.connect = Some(connect);
    resp.timing.pretransfer = Some(connect); // plaintext: no TLS gap before sending
    finalize_plain(bufrd, &req, &resp, may_pool, trace);
    Ok(resp)
}

/// Dial the origin through `req.connector` and return a configured boxed
/// stream. The connector establishes a transparent pipe to `host:port`
/// (via SOCKS or `CONNECT`), so the caller then speaks origin-form HTTP.
fn connector_connect(req: &Request, trace: &mut dyn Write) -> Result<Box<dyn NetStream>> {
    let _ = writeln!(
        trace,
        "*   Connecting to {}:{} via {:?}",
        req.url.host, req.url.port, req.connector
    );
    let stream = req
        .connector
        .connect(&req.url.host, req.url.port, req.connect_timeout)?;
    stream.set_read_timeout(req.read_timeout)?;
    stream.set_write_timeout(req.read_timeout)?;
    Ok(stream)
}

/// HTTP/1.1 over a caller-supplied / proxy connector (plaintext target). No
/// pooling; the connector tunnels straight to the origin so we use origin-form.
fn send_plain_via_connector(req: Request, trace: &mut dyn Write) -> Result<Response> {
    let stream = connector_connect(&req, trace)?;
    let mut bufrd = BufReader::new(stream);
    write_request(bufrd.get_mut(), &req, false, trace)?;
    let resp = read_response(&mut bufrd, &req.method, trace)?;
    Ok(resp)
}

/// HTTPS over a caller-supplied / proxy connector. The connector yields a pipe
/// to the origin; we run the origin's TLS handshake over it, then HTTP/1.1.
/// `--http2`/`--http3` "only" preferences are rejected (not yet supported on
/// this path).
fn send_https_via_connector(req: Request, trace: &mut dyn Write) -> Result<Response> {
    match req.http_version_pref {
        HttpVersionPref::Http2Only => {
            return Err(Error::UnsupportedScheme(
                "HTTP/2 (--http2) over a custom connector or SOCKS/HTTPS proxy is not supported"
                    .into(),
            ));
        }
        HttpVersionPref::Http3Only => {
            return Err(Error::UnsupportedScheme(
                "HTTP/3 (--http3-only) over a custom connector or SOCKS/HTTPS proxy is not supported"
                    .into(),
            ));
        }
        _ => {}
    }
    let stream = connector_connect(&req, trace)?;
    let opts = tls_opts_from(&req, &[])?;
    let tls = crate::tls::connect_over_tls(stream, &req.url.host, opts)?;
    write_tls_info(&tls, trace);
    let mut bufrd = BufReader::new(tls);
    write_request(bufrd.get_mut(), &req, false, trace)?;
    let resp = read_response(&mut bufrd, &req.method, trace)?;
    Ok(resp)
}

fn perform_on_pooled_plain(
    mut bufrd: BufReader<TcpStream>,
    req: &Request,
    trace: &mut dyn Write,
) -> std::result::Result<Response, PooledError> {
    if let Err(e) = write_request(bufrd.get_mut(), req, via_plain_http_proxy(req), trace) {
        return Err(stale_or_hard(e));
    }
    let resp = match read_response(&mut bufrd, &req.method, trace) {
        Ok(r) => r,
        Err(e) => return Err(stale_or_hard(e)),
    };
    finalize_plain(bufrd, req, &resp, true, trace);
    Ok(resp)
}

fn finalize_plain(
    bufrd: BufReader<TcpStream>,
    req: &Request,
    resp: &Response,
    may_pool: bool,
    trace: &mut dyn Write,
) {
    if may_pool && response_is_reusable(&req.method, resp) {
        crate::pool::plain()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .release(pool_key_for(req), bufrd);
        let _ = writeln!(trace, "* Connection kept alive (pooled)");
    } else {
        let _ = writeln!(trace, "* Connection closed");
    }
}

/// Why a request attempt over a pooled connection failed. `Stale` means the
/// peer probably killed it under us, and the caller should silently retry on
/// a fresh socket. `Hard` is anything else (TLS verification failure, body
/// too large, malformed response, …) and propagates as-is.
enum PooledError {
    Stale(String),
    Hard(Error),
}

fn stale_or_hard(e: Error) -> PooledError {
    // The kinds of failure that mean "the server hung up on the parked
    // socket": EOF on the first read, a connection-reset, a broken pipe on
    // write. Everything else (TLS state errors, bad responses, …) is a real
    // error and the caller must not retry.
    match &e {
        Error::UnexpectedEof => PooledError::Stale("connection closed by peer".into()),
        Error::Io(io_err) => match io_err.kind() {
            io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::NotConnected => PooledError::Stale(io_err.to_string()),
            _ => PooledError::Hard(e),
        },
        _ => PooledError::Hard(e),
    }
}

/// Compute the dial-target discriminator for the pool key from the
/// `--connect-to` and `--resolve` overrides that would steer this request's
/// physical dial. Returns `None` when neither override touches the URL's
/// (host,port) — the common case — so default requests pool together exactly
/// as before. Mirrors the dial logic in [`tcp_connect`] on the direct
/// (non-proxy) path, which is the only path that pools:
///
/// * `--connect-to` remaps host:port — fold the remapped endpoint in.
/// * `--resolve` pins an IP for the (post-connect-to) host:port — fold the IP
///   (as a host string) in, so two requests pinning different IPs never share.
///
/// Keeping the Host/SNI as the URL's is unaffected; this only discriminates
/// *which backend* a parked socket is physically connected to.
fn effective_dial_target(
    connect_to: &[(String, u16, String, u16)],
    resolve: &[(String, u16, std::net::IpAddr)],
    host: &str,
    port: u16,
) -> Option<(String, u16)> {
    let (dial_host, dial_port) = apply_connect_to(connect_to, host, port);
    let remapped = dial_host != host || dial_port != port;
    // --resolve pins a fixed IP for the (post-connect-to) host:port.
    let pinned_ip = resolve
        .iter()
        .find(|(h, p, _)| *p == dial_port && h.eq_ignore_ascii_case(&dial_host))
        .map(|(_, _, ip)| *ip);
    match pinned_ip {
        // A pinned IP fully determines the backend; key on the literal IP so
        // two requests pinning different IPs for the same authority never
        // share a socket.
        Some(ip) => Some((ip.to_string(), dial_port)),
        None if remapped => Some((dial_host, dial_port)),
        None => None,
    }
}

pub(crate) fn pool_key_for(req: &Request) -> crate::pool::Key {
    let u = &req.url;
    crate::pool::Key {
        scheme: u.scheme.clone(),
        host: u.host.clone(),
        port: u.port,
        effective_target: effective_dial_target(&req.connect_to, &req.resolve, &u.host, u.port),
    }
}

fn pool_checkout_plain(req: &Request) -> Option<BufReader<TcpStream>> {
    crate::pool::plain()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .checkout(&pool_key_for(req))
}

/// True iff this request's TLS posture matches what a pooled socket can be
/// safely shared with. A connection made with verification off (`-k`), against
/// a custom CA bundle (`--cacert`)/directory (`--capath`), with a client
/// certificate (`-E`), or with public-key pinning (`--pinnedpubkey`) must NEVER
/// be handed to a later differently-configured request to the same host:port —
/// that would silently downgrade the second request's trust decision (MITM) or
/// reuse the wrong client identity. Mirrors `http2::pool_eligible`.
pub(crate) fn tls_pool_eligible(req: &Request) -> bool {
    req.verify_tls
        && req.ca_bundle.is_none()
        && req.ca_path.is_none()
        && req.client_cert.is_none()
        && req.pinned_pubkey.is_none()
        && req.crl_file.is_none()
        && req.ciphers.is_none()
        && req.tls13_ciphers.is_none()
}

fn pool_checkout_tls(req: &Request) -> Option<BufReader<crate::tls::TlsStream<TcpStream>>> {
    if !tls_pool_eligible(req) {
        return None;
    }
    crate::pool::tls()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .checkout(&pool_key_for(req))
}

/// Server-side keep-alive eligibility. Caller must also have read the body
/// to completion (true here by construction — `read_response` either returns
/// the whole body or returns `Err`). HTTP/1.0 servers need an explicit
/// `Connection: keep-alive`; HTTP/1.1 servers default to keep-alive and need
/// `Connection: close` to opt out. Close-delimited bodies are never reusable
/// because by definition the server has already closed the connection. The
/// request method is needed to disambiguate "no body framing because HEAD"
/// (reusable) from "no body framing because the server intends to close"
/// (not reusable).
fn response_is_reusable(method: &str, resp: &Response) -> bool {
    let conn_close = resp.headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("connection")
            && v.split(',')
                .any(|tok| tok.trim().eq_ignore_ascii_case("close"))
    });
    if conn_close {
        return false;
    }
    let has_framing = resp.headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("content-length")
            || (k.eq_ignore_ascii_case("transfer-encoding") && v.eq_ignore_ascii_case("chunked"))
    });
    let no_body_allowed = method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&resp.status)
        || resp.status == 204
        || resp.status == 304;
    if !has_framing && !no_body_allowed {
        // Close-delimited body: server signalled end-of-message by closing.
        return false;
    }
    if resp.version == "HTTP/1.1" {
        true
    } else {
        // HTTP/1.0 — must see explicit keep-alive.
        resp.headers.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("connection")
                && v.split(',')
                    .any(|tok| tok.trim().eq_ignore_ascii_case("keep-alive"))
        })
    }
}

/// True iff this request is going to a plain-`http://` target via a proxy
/// and is NOT in the no-proxy bypass set. Such requests must use the
/// absolute-form request line per RFC 9112 §3.2.2 and carry an optional
/// `Proxy-Authorization:` header. HTTPS-via-proxy doesn't qualify because
/// the proxy only sees a `CONNECT` tunnel; the request inside is normal.
pub(crate) fn via_plain_http_proxy(req: &Request) -> bool {
    if req.url.scheme != "http" {
        return false;
    }
    match &req.proxy {
        Some(_) => !proxy_bypassed(req),
        None => false,
    }
}

/// True iff `req.url.host` matches any entry of `req.no_proxy`. A single
/// `*` matches everything; otherwise each entry is a case-insensitive host
/// suffix (matching either the whole host or the part after a `.`).
pub(crate) fn proxy_bypassed(req: &Request) -> bool {
    if req.no_proxy.iter().any(|e| e.trim() == "*") {
        return true;
    }
    let h = req.url.host.to_ascii_lowercase();
    req.no_proxy.iter().any(|e| {
        let e = e.trim().trim_start_matches('.').to_ascii_lowercase();
        if e.is_empty() {
            return false;
        }
        h == e || h.ends_with(&format!(".{e}"))
    })
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
    opts.min_version = req.tls_min;
    opts.max_version = req.tls_max;
    // Base trust store: `--cacert` replaces the system roots; otherwise leave
    // `None` so the backend loads the system bundle. `--capath` *adds* a
    // directory of CAs on top of whichever base is in effect (curl semantics).
    if let Some(path) = &req.ca_bundle {
        opts.roots = Some(crate::tls::load_roots_from_file(path)?);
    }
    if let Some(dir) = &req.ca_path {
        opts.roots = Some(crate::tls::load_roots_from_dir(opts.roots.take(), dir)?);
    }
    // Client certificate / key for mTLS. Files are read here so a missing /
    // unreadable file surfaces as an `Error` before the connection is dialed.
    if let Some(cert_path) = &req.client_cert {
        opts.client_cert = Some(std::fs::read(cert_path).map_err(Error::Io)?);
        opts.cert_is_der = req.cert_is_der;
        opts.key_is_der = req.key_is_der;
        opts.client_key_pass = req.client_key_pass.clone();
        if let Some(key_path) = &req.client_key {
            opts.client_key = Some(std::fs::read(key_path).map_err(Error::Io)?);
        }
    }
    // Public-key pinning.
    if let Some(spec) = &req.pinned_pubkey {
        opts.pinned_spki_sha256 = crate::tls::parse_pinned_pubkey(spec)?;
    }
    // CRL file (read here so a missing file errors before dialing).
    if let Some(path) = &req.crl_file {
        opts.crl_pem = Some(std::fs::read(path).map_err(Error::Io)?);
    }
    // Cipher-suite restriction: combine --ciphers (TLS≤1.2) and --tls13-ciphers
    // into one IANA-ID list; the backend intersects it per TLS version.
    if let Some(spec) = &req.ciphers {
        opts.cipher_suites
            .extend(crate::tls::cipher_names_to_ids(spec)?);
    }
    if let Some(spec) = &req.tls13_ciphers {
        opts.cipher_suites
            .extend(crate::tls::cipher_names_to_ids(spec)?);
    }
    Ok(opts)
}

/// Decide whether an error from the HTTP/3 (QUIC) path should trigger a
/// fallback to HTTP/2/HTTP/1.1 under `--http3`.
///
/// Transport-level failures — UDP egress blocked, the QUIC handshake never
/// completing, version negotiation, timeouts, a connection torn down before a
/// response — mean HTTP/3 simply isn't usable here, so we retry over TCP.
/// Anything else (a malformed-but-real response decoded over an established
/// QUIC connection) is propagated: the server *was* reached over h3, so
/// silently re-issuing over h2 could mask a genuine protocol bug. Note that a
/// real HTTP response with a 4xx/5xx status is `Ok(Response)`, not an error,
/// and never reaches this function.
pub(crate) fn h3_should_fall_back(e: &Error) -> bool {
    match e {
        // I/O = UDP socket / connect / timeout failures.
        Error::Io(_) => true,
        // `http3::send` rejects non-`https://` URLs and unresolvable hosts up
        // front; those are configuration issues we can retry over TCP.
        Error::UnsupportedScheme(_) | Error::InvalidUrl(_) => true,
        // The QUIC/HTTP3 layer tags its own connection-establishment errors
        // with an `http3:` prefix. Treat the handshake/connection ones as
        // transport failures; leave mid-response decode failures to propagate.
        Error::BadResponse(m) => {
            m.starts_with("http3: connection closed")
                || m.starts_with("http3: peer closed")
                || m.starts_with("http3: build client")
                || m.starts_with("http3: open_bidi")
                || m.starts_with("http3: open_uni")
                // `feed` is the QUIC datagram-ingest step: a decode failure here
                // means we couldn't parse the peer's packets (version/transport
                // mismatch), i.e. QUIC never came up — a transport failure.
                || m.starts_with("http3: feed")
                // stream read/write errors before any response bytes arrived are
                // likewise a torn-down connection, not a real HTTP response.
                || m.starts_with("http3: stream read")
                || m.starts_with("http3: stream write")
                || m.starts_with("http3: stream finish")
        }
        _ => false,
    }
}

/// Issue several HTTP/2 requests **concurrently over a single connection**
/// using true stream multiplexing, returning one result per request in input
/// order.
///
/// This is the library entry point for HTTP/2 concurrent multiplexing. All
/// requests must target the **same `https://` origin** (scheme/host/port);
/// the batch opens one connection and drives every request's stream together
/// in a single interleaved frame loop, so a slow body or response on one
/// stream does not stall the others. See [`crate::http2::send_multiplexed`]
/// for the full contract, including the graceful fallbacks: a mixed-origin /
/// non-https / non-pool-eligible batch (or a server that won't negotiate
/// `h2`) is issued sequentially instead, still returning correct, in-order
/// results.
///
/// Redirects and cookies are **not** applied here — this is raw protocol
/// dispatch over one connection, intended for callers that want to fan out
/// independent requests to one host. For the redirect/cookie-aware single
/// request path, use [`Request::send`] and friends.
///
/// ```no_run
/// // Fan 100 GETs to one host over a single multiplexed HTTP/2 connection.
/// let reqs: Vec<_> = (0..100)
///     .map(|i| rsurl::Request::get(&format!("https://api.example.com/items/{i}")).unwrap())
///     .collect();
/// for r in rsurl::send_multiplexed(reqs) {
///     if let Ok(resp) = r { let _ = resp.status; }
/// }
/// ```
///
/// Use [`send_multiplexed_traced`] to capture the `-v`-style protocol trace.
pub fn send_multiplexed(reqs: Vec<Request>) -> Vec<Result<Response>> {
    send_multiplexed_traced(reqs, &mut std::io::sink())
}

/// As [`send_multiplexed`], but writes the protocol trace (the `-v` `* > <`
/// lines, interleaved per stream) to `trace`. Pass `&mut std::io::sink()` for
/// no trace — or just call [`send_multiplexed`].
pub fn send_multiplexed_traced(
    mut reqs: Vec<Request>,
    trace: &mut dyn Write,
) -> Vec<Result<Response>> {
    // This path has no redirect loop, so normalise each request's host to
    // ASCII/punycode (IDN) here, before dispatch. Best-effort: an undecodable
    // internationalised host is left raw and surfaces as a per-request
    // connect error rather than failing the whole batch.
    for req in &mut reqs {
        let _ = req.url.set_idn(req.idn);
    }
    crate::http2::send_multiplexed(reqs, trace)
}

fn send_https(req: Request, trace: &mut dyn Write) -> Result<Response> {
    // A custom/SOCKS/https-proxy connector dials the origin itself; HTTP/2 and
    // HTTP/3 do their own direct connect and aren't wired to it yet, so we
    // route the connector through the boxed HTTP/1.1 path.
    if !req.connector.is_direct() {
        return send_https_via_connector(req, trace);
    }
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
    // * `Http3Only` / `Http3`: dispatched on the separate QUIC/UDP path
    //   (`crate::http3::send`) before any TCP work. `Http3Only` returns the
    //   result verbatim; `Http3` falls back to the `Auto` path on a
    //   transport failure.
    // HTTP/3 is attempted first when requested. `Http3Only` returns whatever
    // the QUIC path produces. `Http3` returns a success or a non-transport
    // error verbatim, but on a transport failure it falls through to the
    // `Auto` h2/http1.1 logic below.
    match req.http_version_pref {
        HttpVersionPref::Http3Only => {
            let _ = writeln!(trace, "* Trying HTTP/3 (QUIC), required (--http3-only)");
            return crate::http3::send(req, trace);
        }
        HttpVersionPref::Http3 => {
            let _ = writeln!(trace, "* Trying HTTP/3 (QUIC)...");
            match crate::http3::send(req.clone(), trace) {
                Ok(resp) => return Ok(resp),
                Err(e) if h3_should_fall_back(&e) => {
                    let _ = writeln!(trace, "* HTTP/3 failed ({e}), falling back to HTTP/2/1.1");
                    // Fall through to the Auto path (h2, then http/1.1).
                }
                Err(e) => return Err(e),
            }
        }
        _ => {}
    }

    match req.http_version_pref {
        HttpVersionPref::Http2Only => {
            let _ = writeln!(trace, "* HTTP/2 required (--http2)");
            return crate::http2::send(req, trace);
        }
        HttpVersionPref::Auto | HttpVersionPref::Http3 => {
            let _ = writeln!(trace, "* Trying HTTP/2 via ALPN (h2)");
            match crate::http2::send(req.clone(), trace) {
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
        // `Http3Only` always returns from the first match above; it can never
        // reach this point.
        HttpVersionPref::Http3Only => unreachable!("Http3Only handled above"),
    }

    // HTTP/1.1 path (Auto fallback, Http3 fallback, or Http11Only). ALPN is not offered so
    // the cert-only handshake doesn't change behaviour for h2-only servers
    // (those would have been satisfied by the h2 attempt above).
    let direct = req.proxy.is_none() || proxy_bypassed(&req);
    if direct {
        if let Some(bufrd) = pool_checkout_tls(&req) {
            let _ = writeln!(trace, "* Reusing existing connection from pool");
            match perform_on_pooled_tls(bufrd, &req, trace) {
                Ok(resp) => return Ok(resp),
                Err(PooledError::Stale(why)) => {
                    let _ = writeln!(trace, "* Pooled connection unusable ({why}); reconnecting");
                    // fall through
                }
                Err(PooledError::Hard(e)) => return Err(e),
            }
        }
    }
    send_https_fresh(req, direct, trace)
}

fn send_https_fresh(req: Request, may_pool: bool, trace: &mut dyn Write) -> Result<Response> {
    let start = std::time::Instant::now();
    let tcp = tcp_connect(&req, trace)?;
    let connect = start.elapsed();
    // HTTPS via proxy means we have to ask the proxy to splice us through
    // to the origin before the TLS handshake — the proxy can't see the
    // encrypted bytes, so a CONNECT tunnel is the only way.
    if let Some(p) = req
        .proxy
        .as_ref()
        .filter(|_| !proxy_bypassed(&req) && req.url.scheme == "https")
    {
        connect_tunnel(&tcp, &req.url, p, trace)?;
    }
    let opts = tls_opts_from(&req, &[])?;
    let tls = crate::tls::connect_over_tls(tcp, &req.url.host, opts)?;
    let appconnect = start.elapsed();
    write_tls_info(&tls, trace);
    let mut bufrd = BufReader::new(tls);
    // Always origin-form here: even with a proxy in play we've already
    // tunnelled past it via CONNECT, so the request the origin sees is
    // the normal direct one.
    write_request(bufrd.get_mut(), &req, false, trace)?;
    let mut resp = read_response_timed(&mut bufrd, &req.method, Some(start), trace)?;
    resp.timing.connect = Some(connect);
    resp.timing.appconnect = Some(appconnect);
    resp.timing.pretransfer = Some(appconnect); // request goes out right after TLS
    finalize_tls(bufrd, &req, &resp, may_pool, trace);
    Ok(resp)
}

fn perform_on_pooled_tls(
    mut bufrd: BufReader<crate::tls::TlsStream<TcpStream>>,
    req: &Request,
    trace: &mut dyn Write,
) -> std::result::Result<Response, PooledError> {
    if let Err(e) = write_request(bufrd.get_mut(), req, false, trace) {
        return Err(stale_or_hard(e));
    }
    let resp = match read_response(&mut bufrd, &req.method, trace) {
        Ok(r) => r,
        Err(e) => return Err(stale_or_hard(e)),
    };
    finalize_tls(bufrd, req, &resp, true, trace);
    Ok(resp)
}

fn finalize_tls(
    bufrd: BufReader<crate::tls::TlsStream<TcpStream>>,
    req: &Request,
    resp: &Response,
    may_pool: bool,
    trace: &mut dyn Write,
) {
    // Only park sockets whose verification posture matches a default
    // verifying request — never an `-k`/`--cacert` socket — so a later
    // verifying request can't silently inherit a weaker trust decision.
    if may_pool && tls_pool_eligible(req) && response_is_reusable(&req.method, resp) {
        crate::pool::tls()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .release(pool_key_for(req), bufrd);
        let _ = writeln!(trace, "* Connection kept alive (pooled)");
    } else {
        let _ = writeln!(trace, "* Connection closed");
    }
}

/// Open a TCP socket pointed at whatever the next-hop endpoint actually
/// is — either the request URL's authority or, when [`Request::proxy`] is
/// in play and the host isn't in the no-proxy list, the proxy itself.
///
/// For HTTPS-via-proxy requests, the caller is expected to invoke
/// [`connect_tunnel`] on the returned socket before any TLS handshake.
/// This function intentionally stops at "TCP connected" so that the
/// HTTP/1.1 and HTTP/2 paths can share the same tunnel logic.
/// Apply `--connect-to` remapping to a dial target. An empty from-host or a
/// zero from-port matches any. An empty to-host / zero to-port keeps the
/// original. First match wins.
fn apply_connect_to(rules: &[(String, u16, String, u16)], host: &str, port: u16) -> (String, u16) {
    for (fh, fp, th, tp) in rules {
        let host_ok = fh.is_empty() || fh.eq_ignore_ascii_case(host);
        let port_ok = *fp == 0 || *fp == port;
        if host_ok && port_ok {
            let new_host = if th.is_empty() { host } else { th.as_str() };
            let new_port = if *tp == 0 { port } else { *tp };
            return (new_host.to_string(), new_port);
        }
    }
    (host.to_string(), port)
}

/// Resolve `host:port` to a single socket address, honoring `--resolve`
/// overrides and the `-4`/`-6` address-family preference.
fn resolve_target(host: &str, port: u16, req: &Request) -> Result<std::net::SocketAddr> {
    // --resolve: a fixed address for this host:port wins.
    if let Some((_, _, ip)) = req
        .resolve
        .iter()
        .find(|(h, p, _)| *p == port && h.eq_ignore_ascii_case(host))
    {
        return Ok(std::net::SocketAddr::new(*ip, port));
    }
    let addr = format!("{host}:{port}");
    let mut addrs = std::net::ToSocketAddrs::to_socket_addrs(&addr)?;
    match req.ip_family {
        Some(IpFamily::V4) => addrs
            .find(|a| a.is_ipv4())
            .ok_or_else(|| Error::InvalidUrl(format!("{host}: no IPv4 address"))),
        Some(IpFamily::V6) => addrs
            .find(|a| a.is_ipv6())
            .ok_or_else(|| Error::InvalidUrl(format!("{host}: no IPv6 address"))),
        None => addrs
            .next()
            .ok_or_else(|| Error::InvalidUrl(host.to_string())),
    }
}

pub(crate) fn tcp_connect(req: &Request, trace: &mut dyn Write) -> Result<TcpStream> {
    let proxy = req.proxy.as_ref().filter(|_| !proxy_bypassed(req));
    let (target_host, target_port, via_proxy_label) = match proxy {
        Some(p) => (p.host.as_str(), p.port, true),
        None => (req.url.host.as_str(), req.url.port, false),
    };
    // --connect-to remaps the dial target (not the Host/SNI). Only for the
    // direct (non-proxy) path.
    let (target_host, target_port) = if via_proxy_label {
        (target_host.to_string(), target_port)
    } else {
        apply_connect_to(&req.connect_to, target_host, target_port)
    };
    let first = resolve_target(&target_host, target_port, req)?;
    let _ = writeln!(trace, "*   Trying {first}...");
    let stream = match req.connect_timeout {
        Some(t) => TcpStream::connect_timeout(&first, t)?,
        None => TcpStream::connect(first)?,
    };
    let peer = stream.peer_addr().unwrap_or(first);
    if via_proxy_label {
        let _ = writeln!(
            trace,
            "* Connected to proxy {} ({}) port {}",
            target_host,
            peer.ip(),
            peer.port()
        );
    } else {
        let _ = writeln!(
            trace,
            "* Connected to {} ({}) port {}",
            req.url.host,
            peer.ip(),
            peer.port()
        );
    }
    stream.set_read_timeout(req.read_timeout)?;
    stream.set_write_timeout(req.read_timeout)?;
    Ok(stream)
}

/// Issue an HTTP/1.1 `CONNECT <host>:<port>` over an already-open TCP
/// socket, parse the response line and headers, and return cleanly if the
/// proxy returned `2xx` — the socket is then a transparent byte pipe to
/// `target`, ready to be wrapped in TLS. A non-2xx response (407 Proxy
/// Authentication Required is the common one) surfaces as
/// [`Error::BadResponse`] so the caller can report it.
///
/// CONNECT responses are headers-only; there's no body. We read the wire
/// byte-by-byte rather than through a [`BufReader`] because any data the
/// server sends after the CRLF/CRLF terminator (typically the first
/// `ClientHello` byte) belongs to the *next* layer, not us — losing it
/// to a BufReader's prefetch would corrupt the TLS handshake.
pub(crate) fn connect_tunnel<S: Read + Write>(
    mut stream: S,
    target: &Url,
    proxy: &ProxyConfig,
    trace: &mut dyn Write,
) -> Result<()> {
    let host_port = format!("{}:{}", target.host, target.port);
    let mut buf = Vec::with_capacity(256);
    write!(&mut buf, "CONNECT {host_port} HTTP/1.1\r\n")?;
    write!(&mut buf, "Host: {host_port}\r\n")?;
    write!(&mut buf, "User-Agent: {DEFAULT_USER_AGENT}\r\n")?;
    write!(&mut buf, "Proxy-Connection: Keep-Alive\r\n")?;
    if let Some((user, pass)) = &proxy.auth {
        let combined = format!("{user}:{pass}");
        let creds = crate::websocket::base64_encode(combined.as_bytes());
        write!(&mut buf, "Proxy-Authorization: Basic {creds}\r\n")?;
    }
    write!(&mut buf, "\r\n")?;

    // Mirror the CONNECT we put on the wire into the trace so `-v` shows
    // it before the TLS handshake noise.
    let head = String::from_utf8_lossy(&buf);
    let head_no_final_crlf = head.strip_suffix("\r\n").unwrap_or(&head);
    for line in head_no_final_crlf.split("\r\n") {
        let _ = writeln!(trace, "> {line}");
    }
    stream.write_all(&buf)?;
    stream.flush()?;

    // Read the response one byte at a time until we see the terminator.
    // Bounded by MAX_HEADER_BYTES so a misbehaving proxy can't blow memory.
    let mut line_buf: Vec<u8> = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    let mut status_line: Option<String> = None;
    let mut total = 0usize;
    loop {
        if total > MAX_HEADER_BYTES {
            return Err(Error::BadResponse(
                "CONNECT response headers exceed 64 KiB".into(),
            ));
        }
        let n = stream.read(&mut byte)?;
        if n == 0 {
            return Err(Error::UnexpectedEof);
        }
        total += 1;
        line_buf.push(byte[0]);
        if byte[0] == b'\n' {
            let trimmed_owned = String::from_utf8_lossy(
                line_buf
                    .strip_suffix(b"\n")
                    .unwrap_or(&line_buf)
                    .strip_suffix(b"\r")
                    .unwrap_or(line_buf.strip_suffix(b"\n").unwrap_or(&line_buf)),
            )
            .into_owned();
            let _ = writeln!(trace, "< {trimmed_owned}");
            if status_line.is_none() {
                status_line = Some(trimmed_owned.clone());
            }
            if trimmed_owned.is_empty() {
                break;
            }
            line_buf.clear();
        }
    }

    let status = status_line.ok_or_else(|| Error::BadResponse("CONNECT: no status line".into()))?;
    let parts: Vec<&str> = status.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err(Error::BadResponse(format!(
            "CONNECT: malformed status line {status:?}"
        )));
    }
    let code: u16 = parts[1]
        .parse()
        .map_err(|_| Error::BadResponse(format!("CONNECT: bad status {:?}", parts[1])))?;
    if !(200..300).contains(&code) {
        return Err(Error::BadResponse(format!(
            "CONNECT to {host_port} failed: {status}"
        )));
    }
    let _ = writeln!(trace, "* CONNECT tunnel established to {host_port}");
    Ok(())
}

pub(crate) fn write_tls_info<S: Read + Write>(
    tls: &crate::tls::TlsStream<S>,
    trace: &mut dyn Write,
) {
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

/// True if `name` is a valid HTTP field-name per RFC 7230 `token`: one or more
/// of the `tchar` set (no separators, no controls, no whitespace).
fn is_valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// True if `value` carries a byte that would forge a header boundary or NUL.
/// CR and LF anywhere in a value let an attacker splice extra header lines.
fn header_value_has_forbidden(value: &str) -> bool {
    value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
}

/// Reject a `(name, value)` pair that could not be safely serialised onto the
/// wire — a name outside the RFC 7230 token set, or a name/value carrying
/// CR, LF, or NUL.
fn validate_header(name: &str, value: &str) -> Result<()> {
    if !is_valid_header_name(name) {
        return Err(Error::BadResponse(format!("invalid header name: {name:?}")));
    }
    if header_value_has_forbidden(value) {
        return Err(Error::BadResponse(format!(
            "invalid header value for {name:?}"
        )));
    }
    Ok(())
}

/// Reject a request method that carries CR, LF, a space, or any control char —
/// any of which would corrupt the request line / forge an extra line.
fn validate_method(method: &str) -> Result<()> {
    if method.is_empty() || method.bytes().any(|b| b < 0x20 || b == 0x7f || b == b' ') {
        return Err(Error::BadResponse(format!("invalid method: {method:?}")));
    }
    Ok(())
}

fn write_request<W: Write>(
    mut w: W,
    req: &Request,
    absolute_form: bool,
    trace: &mut dyn Write,
) -> Result<()> {
    // Validate everything that lands on the request line / header block before
    // emitting a single byte, so nothing carrying CR/LF can reach the socket.
    validate_method(&req.method)?;
    for (k, v) in &req.headers {
        validate_header(k, v)?;
    }

    let host_header = if (req.url.scheme == "http" && req.url.port == 80)
        || (req.url.scheme == "https" && req.url.port == 443)
    {
        req.url.host.clone()
    } else {
        format!("{}:{}", req.url.host, req.url.port)
    };

    let mut buf = Vec::with_capacity(256);
    // Absolute-form per RFC 9112 §3.2.2: required when sending to a proxy
    // on a plain HTTP connection. Origin-form (`/path`) for everything
    // else (direct connections, and HTTPS-via-proxy because we tunnel).
    if absolute_form {
        // Re-serialise the target as `scheme://host[:port]<path>` so the
        // proxy can route it. Userinfo is omitted — we move it into
        // `Authorization:`/`Proxy-Authorization:` elsewhere.
        let target = if (req.url.scheme == "http" && req.url.port == 80)
            || (req.url.scheme == "https" && req.url.port == 443)
        {
            format!("{}://{}{}", req.url.scheme, req.url.host, req.url.path)
        } else {
            format!(
                "{}://{}:{}{}",
                req.url.scheme, req.url.host, req.url.port, req.url.path
            )
        };
        write!(&mut buf, "{} {target} HTTP/1.1\r\n", req.method)?;
    } else {
        write!(&mut buf, "{} {} HTTP/1.1\r\n", req.method, req.url.path)?;
    }
    write!(&mut buf, "Host: {host_header}\r\n")?;
    // Proxy-Authorization: Basic ... rides with every request to a plain
    // HTTP proxy. (For HTTPS the credentials went on the CONNECT, not
    // here — origin servers must not see them.)
    if absolute_form {
        if let Some(p) = &req.proxy {
            if let Some((user, pass)) = &p.auth {
                let combined = format!("{user}:{pass}");
                let creds = crate::websocket::base64_encode(combined.as_bytes());
                write!(&mut buf, "Proxy-Authorization: Basic {creds}\r\n")?;
            }
        }
    }

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
    // No explicit `Connection:` header: HTTP/1.1's default is keep-alive,
    // which is what we want for the connection pool. Servers that don't
    // want to keep alive announce it back via `Connection: close` on the
    // response, and we'll honour that in the reuse decision.
    write!(&mut buf, "\r\n")?;

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

/// Read one line (through and including the terminating `\n`) into `buf`,
/// appending to whatever is already there, but refusing to grow the read past
/// `max` bytes without seeing a `\n`. Returns the number of bytes read.
///
/// Unlike [`BufRead::read_line`], which grows its `String` until `\n` or EOF
/// with no in-flight cap, this errors out as soon as `max` bytes have been
/// consumed without a newline. That prevents a malicious or MITM server from
/// streaming an endless newline-free line to exhaust memory (DoS).
///
/// A return of `0` means EOF was hit before any byte was read (same contract as
/// `read_line`). The bytes are appended UTF-8-lossily, matching `read_line`'s
/// behaviour for the well-formed ASCII protocol lines we parse here.
fn read_line_capped<R: BufRead>(r: &mut R, buf: &mut String, max: usize) -> Result<usize> {
    let mut raw: Vec<u8> = Vec::new();
    loop {
        // Cap the amount read in this call by what's left of the budget, plus
        // one byte so a line of exactly `max` data bytes + `\n` still fits.
        let remaining = max.saturating_sub(raw.len());
        let n = r
            .by_ref()
            .take(remaining as u64 + 1)
            .read_until(b'\n', &mut raw)?;
        if n == 0 {
            // EOF.
            break;
        }
        if raw.last() == Some(&b'\n') {
            // Found the line terminator.
            break;
        }
        if raw.len() > max {
            return Err(Error::BadResponse("response line exceeds 64 KiB".into()));
        }
        // Otherwise `take` capped us mid-line but we're still under budget;
        // loop to read more.
    }
    if raw.is_empty() {
        return Ok(0);
    }
    let read = raw.len();
    buf.push_str(&String::from_utf8_lossy(&raw));
    Ok(read)
}

/// Read one HTTP/1.1 response from a buffered stream. The buffer is held by
/// the caller (rather than created inline) because connection-reuse hands
/// the same `BufReader` to back-to-back requests, and the buffer's leftover
/// bytes — even if empty in practice — must travel with the connection.
/// The status line + headers of a response (everything before the body).
struct Head {
    version: String,
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
}

/// Read the status line and header block (up to the blank line). The reader is
/// left positioned at the first body byte.
fn read_head<R: Read>(r: &mut BufReader<R>, trace: &mut dyn Write) -> Result<Head> {
    let mut status_line = String::new();
    let n = read_line_capped(r, &mut status_line, MAX_HEADER_BYTES)?;
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
        let n = read_line_capped(r, &mut line, MAX_HEADER_BYTES)?;
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
    Ok(Head {
        version,
        status,
        reason,
        headers,
    })
}

fn read_response<R: Read>(
    r: &mut BufReader<R>,
    method: &str,
    trace: &mut dyn Write,
) -> Result<Response>
where
    BufReader<R>: TruncationAware,
{
    read_response_timed(r, method, None, trace)
}

/// As [`read_response`], but stamps `Response::timing.starttransfer` from
/// `start` (the start of the request attempt) once the head has arrived.
fn read_response_timed<R: Read>(
    r: &mut BufReader<R>,
    method: &str,
    start: Option<std::time::Instant>,
    trace: &mut dyn Write,
) -> Result<Response>
where
    BufReader<R>: TruncationAware,
{
    let Head {
        version,
        status,
        reason,
        headers,
    } = read_head(r, trace)?;
    let starttransfer = start.map(|s| s.elapsed());

    let body = read_body(r, &headers, &version, status, method)?;
    let wire_len = body.len();
    let _ = writeln!(trace, "* Received {wire_len} body bytes");
    let (headers, body) = maybe_decode_body(headers, body, trace)?;

    Ok(Response {
        status,
        reason,
        version,
        headers,
        body,
        timing: Timing {
            starttransfer,
            ..Default::default()
        },
        // The redirect-following `send_to` overwrites this with the effective
        // URL; this low-level path has no URL of its own.
        final_url: String::new(),
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

/// Resolve the effective `Content-Length` from the header set, rejecting
/// smuggling-friendly ambiguity per RFC 9112 §6.3. Multiple `Content-Length`
/// header lines — or a single line that is itself a comma list — are only
/// acceptable if every value parses and they all agree; any disagreement (or
/// an unparseable value) is a hard error. Returns `None` when no
/// `Content-Length` is present.
fn parse_content_length(headers: &[(String, String)]) -> Result<Option<u64>> {
    let mut seen: Option<u64> = None;
    for (k, v) in headers {
        if !k.eq_ignore_ascii_case("content-length") {
            continue;
        }
        // A value may be a comma list (`5, 5`); split and validate each part.
        for part in v.split(',') {
            // RFC 9112 §6.3: Content-Length is `1*DIGIT`. Reject a leading
            // sign or any non-digit content; only surrounding whitespace
            // (which `trim` removes) is tolerated.
            let t = part.trim();
            if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::BadResponse(format!("bad Content-Length: {v:?}")));
            }
            let n: u64 = t
                .parse()
                .map_err(|_| Error::BadResponse(format!("bad Content-Length: {v:?}")))?;
            match seen {
                Some(prev) if prev != n => {
                    return Err(Error::BadResponse(
                        "conflicting Content-Length values".into(),
                    ));
                }
                _ => seen = Some(n),
            }
        }
    }
    Ok(seen)
}

fn read_body<R: BufRead + TruncationAware>(
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

    // RFC 9112 §6.1: `Transfer-Encoding` present means the message is framed by
    // the transfer coding, and a `Content-Length` alongside it is a smuggling
    // vector (the two framings can disagree). Reject the message rather than
    // pick a side. We only know how to decode `chunked`, so any other coding is
    // its own error below.
    let has_te = headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"));
    let has_cl = headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-length"));
    if has_te && has_cl {
        return Err(Error::BadResponse(
            "both Transfer-Encoding and Content-Length present".into(),
        ));
    }

    let chunked = headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("transfer-encoding") && v.eq_ignore_ascii_case("chunked")
    });
    if chunked {
        return read_chunked(r);
    }

    let content_length = parse_content_length(headers)?;

    let mut body = Vec::new();
    match content_length {
        Some(len) => {
            // Compare against the cap as `u64` *before* any `as usize` cast, so
            // a value that wraps to a small `usize` on a 32-bit target can't
            // slip past the guard.
            if len > MAX_BODY_BYTES as u64 {
                return Err(Error::BadResponse(format!("body too large: {len}")));
            }
            // Reserve only a modest amount up front and let the Vec grow as
            // bytes actually arrive: a peer can claim Content-Length up to
            // MAX_BODY_BYTES (256 MiB) without sending anything, so reserving
            // the full claim would let it force a large allocation for free.
            body.reserve(len.min(64 * 1024) as usize);
            r.take(len).read_to_end(&mut body)?;
            if (body.len() as u64) < len {
                return Err(Error::UnexpectedEof);
            }
        }
        None => {
            // No content-length, no chunked — read until EOF (Connection: close).
            r.take(MAX_BODY_BYTES as u64).read_to_end(&mut body)?;
            // TLS-1: an EOF-delimited body is framed *by the connection close*.
            // If the TLS transport closed without a `close_notify`, the body
            // may have been truncated by an attacker (TCP FIN/RST injection),
            // so reject it rather than return a silently-short body.
            if r.response_truncated() {
                return Err(Error::UnexpectedEof);
            }
        }
    }
    Ok(body)
}

fn read_chunked<R: BufRead>(r: &mut R) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let mut size_line = String::new();
        let n = read_line_capped(r, &mut size_line, MAX_HEADER_BYTES)?;
        if n == 0 {
            return Err(Error::UnexpectedEof);
        }
        let size_str = size_line
            .trim_end_matches(['\r', '\n'])
            .split(';')
            .next()
            .unwrap_or("");
        // RFC 9112 §7.1: chunk-size is `1*HEXDIG`. Reject a leading sign or any
        // non-hex content; only surrounding CR/LF/space the reader leaves
        // (removed by `trim`) is tolerated.
        let s = size_str.trim();
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::BadResponse(format!("bad chunk size: {size_str:?}")));
        }
        let size = usize::from_str_radix(s, 16)
            .map_err(|_| Error::BadResponse(format!("bad chunk size: {size_str:?}")))?;
        if body.len().saturating_add(size) > MAX_BODY_BYTES {
            return Err(Error::BadResponse("body too large".into()));
        }
        if size == 0 {
            // Consume trailers until empty line. Each line is capped, but the
            // total trailer block must be bounded too — otherwise a server can
            // stream non-empty trailer lines forever and pin the thread.
            let mut trailer_bytes: usize = 0;
            loop {
                let mut t = String::new();
                let n = read_line_capped(r, &mut t, MAX_HEADER_BYTES)?;
                if n == 0 || t.trim_end_matches(['\r', '\n']).is_empty() {
                    break;
                }
                trailer_bytes = trailer_bytes.saturating_add(n);
                if trailer_bytes > MAX_HEADER_BYTES {
                    return Err(Error::BadResponse("trailer block too large".into()));
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

/// Any bidirectional byte stream — lets the streaming download path hold a
/// plain or TLS connection behind one boxed type. `truncated()` reports
/// whether the stream closed without a TLS `close_notify` (TLS-1); only the
/// two concrete types we actually box are implemented, so the boxed value can
/// answer the question without downcasting.
trait Rw: Read + Write {
    /// See [`TruncationAware::response_truncated`]. Default `false` for the
    /// plaintext transport, which has no `close_notify` to miss.
    fn truncated(&self) -> bool {
        false
    }
}
impl Rw for TcpStream {}
impl Rw for crate::tls::TlsStream<TcpStream> {
    fn truncated(&self) -> bool {
        self.was_truncated()
    }
}

/// TLS-1: whether a reader hit transport EOF *without* a TLS `close_notify`,
/// i.e. an EOF-delimited (`Connection: close`) response body may have been
/// truncated by an active attacker injecting a TCP FIN/RST. Non-TLS readers
/// and the purecrypto backend (pending KarpelesLab/purecrypto#30) report
/// `false` — they cannot distinguish a clean shutdown from a truncation.
///
/// Consulted *only* in the EOF-delimited branch of [`read_body`]/[`stream_body`];
/// length-delimited, chunked, and HTTP/2 paths never call it, so they keep
/// tolerating a missing `close_notify` exactly as before.
pub(crate) trait TruncationAware {
    fn response_truncated(&self) -> bool;
}

impl TruncationAware for TcpStream {
    fn response_truncated(&self) -> bool {
        false
    }
}

impl TruncationAware for crate::tls::TlsStream<TcpStream> {
    fn response_truncated(&self) -> bool {
        self.was_truncated()
    }
}

// The connector (SOCKS / HTTPS-proxy / caller-supplied transport) path reads
// through a `Box<dyn NetStream>` directly, optionally wrapped in TLS.
impl TruncationAware for Box<dyn NetStream> {
    fn response_truncated(&self) -> bool {
        false
    }
}

impl TruncationAware for crate::tls::TlsStream<Box<dyn NetStream>> {
    fn response_truncated(&self) -> bool {
        self.was_truncated()
    }
}

impl TruncationAware for Box<dyn Rw> {
    fn response_truncated(&self) -> bool {
        (**self).truncated()
    }
}

impl<R: TruncationAware + ?Sized> TruncationAware for BufReader<R> {
    fn response_truncated(&self) -> bool {
        self.get_ref().response_truncated()
    }
}

#[cfg(test)]
impl TruncationAware for std::io::Cursor<Vec<u8>> {
    fn response_truncated(&self) -> bool {
        false
    }
}

/// Stream the response body to `sink` instead of buffering it, returning the
/// number of bytes written. Mirrors [`read_body`]'s framing (no-body statuses,
/// chunked, Content-Length, EOF) but does not decompress — callers use this
/// only when there is no `Content-Encoding`.
fn stream_body<R: BufRead + TruncationAware, W: Write + ?Sized>(
    r: &mut R,
    sink: &mut W,
    headers: &[(String, String)],
    status: u16,
    method: &str,
) -> Result<u64> {
    if method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&status)
        || status == 204
        || status == 304
    {
        return Ok(0);
    }
    let chunked = headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("transfer-encoding") && v.eq_ignore_ascii_case("chunked")
    });
    if chunked {
        return stream_chunked(r, sink);
    }
    match parse_content_length(headers)? {
        Some(len) => {
            if len > MAX_BODY_BYTES as u64 {
                return Err(Error::BadResponse(format!("body too large: {len}")));
            }
            let n = io::copy(&mut r.by_ref().take(len), sink)?;
            if n < len {
                return Err(Error::UnexpectedEof);
            }
            Ok(n)
        }
        None => {
            // EOF-delimited: see the TLS-1 note in `read_body`. Reject a body
            // whose framing close was an unauthenticated transport EOF.
            let n = io::copy(&mut r.by_ref().take(MAX_BODY_BYTES as u64), sink)?;
            if r.response_truncated() {
                return Err(Error::UnexpectedEof);
            }
            Ok(n)
        }
    }
}

/// Stream a chunked body to `sink` (mirrors [`read_chunked`]).
fn stream_chunked<R: BufRead, W: Write + ?Sized>(r: &mut R, sink: &mut W) -> Result<u64> {
    let mut total: u64 = 0;
    loop {
        let mut size_line = String::new();
        let n = read_line_capped(r, &mut size_line, MAX_HEADER_BYTES)?;
        if n == 0 {
            return Err(Error::UnexpectedEof);
        }
        let size_str = size_line
            .trim_end_matches(['\r', '\n'])
            .split(';')
            .next()
            .unwrap_or("");
        let s = size_str.trim();
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::BadResponse(format!("bad chunk size: {size_str:?}")));
        }
        let size = usize::from_str_radix(s, 16)
            .map_err(|_| Error::BadResponse(format!("bad chunk size: {size_str:?}")))?;
        if total.saturating_add(size as u64) > MAX_BODY_BYTES as u64 {
            return Err(Error::BadResponse("body too large".into()));
        }
        if size == 0 {
            // Bound the total trailer block (each line is already capped) so a
            // server can't stream non-empty trailer lines forever.
            let mut trailer_bytes: usize = 0;
            loop {
                let mut t = String::new();
                let n = read_line_capped(r, &mut t, MAX_HEADER_BYTES)?;
                if n == 0 || t.trim_end_matches(['\r', '\n']).is_empty() {
                    break;
                }
                trailer_bytes = trailer_bytes.saturating_add(n);
                if trailer_bytes > MAX_HEADER_BYTES {
                    return Err(Error::BadResponse("trailer block too large".into()));
                }
            }
            break;
        }
        let copied = io::copy(&mut r.by_ref().take(size as u64), sink)?;
        if copied < size as u64 {
            return Err(Error::UnexpectedEof);
        }
        let mut crlf = [0u8; 2];
        r.read_exact(&mut crlf)?;
        if &crlf != b"\r\n" {
            return Err(Error::BadResponse("missing CRLF after chunk".into()));
        }
        total += size as u64;
    }
    Ok(total)
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
    fn method_override_uppercases() {
        let req = Request::get("http://example.com/").unwrap().method("head");
        assert_eq!(req.method, "HEAD");
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

    #[test]
    fn header_name_token_validation() {
        assert!(is_valid_header_name("X-Custom-Header"));
        assert!(is_valid_header_name("Content-Type"));
        assert!(!is_valid_header_name(""));
        assert!(!is_valid_header_name("Bad Name")); // space
        assert!(!is_valid_header_name("Bad:Name")); // colon is a separator
        assert!(!is_valid_header_name("Bad\r\nName"));
    }

    #[test]
    fn validate_header_rejects_crlf_in_value() {
        assert!(validate_header("X", "ok").is_ok());
        assert!(validate_header("X", "evil\r\nInjected: 1").is_err());
        assert!(validate_header("X", "evil\rstuff").is_err());
        assert!(validate_header("X", "evil\nstuff").is_err());
        assert!(validate_header("X", "evil\0stuff").is_err());
    }

    #[test]
    fn validate_method_rejects_control_and_space() {
        assert!(validate_method("GET").is_ok());
        assert!(validate_method("PROPFIND").is_ok());
        assert!(validate_method("").is_err());
        assert!(validate_method("GET HTTP/1.1\r\nEvil:").is_err());
        assert!(validate_method("BAD\r\n").is_err());
        assert!(validate_method("BAD METHOD").is_err());
    }

    #[test]
    fn write_request_refuses_injected_header() {
        // Nothing carrying CR/LF must ever reach the socket: write_request
        // returns an error before emitting a byte.
        let mut req = Request::get("http://example.com/").unwrap();
        req.headers
            .push(("X-Evil".into(), "a\r\nInjected: 1".into()));
        let mut sink = Vec::new();
        let mut trace = Vec::new();
        let err = write_request(&mut sink, &req, false, &mut trace).unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)));
        assert!(sink.is_empty(), "nothing should have been written");
    }

    #[test]
    fn write_request_refuses_injected_method() {
        let mut req = Request::get("http://example.com/").unwrap();
        req.method = "GET\r\nEvil: 1".into();
        let mut sink = Vec::new();
        let mut trace = Vec::new();
        assert!(write_request(&mut sink, &req, false, &mut trace).is_err());
        assert!(sink.is_empty());
    }

    #[test]
    fn http3_builder_methods_set_pref() {
        let r = Request::get("https://example.com/").unwrap().http3();
        assert_eq!(r.http_version_pref, HttpVersionPref::Http3);
        let r = Request::get("https://example.com/").unwrap().http3_only();
        assert_eq!(r.http_version_pref, HttpVersionPref::Http3Only);
        // http_version(pref) covers the new variants too.
        let r = Request::get("https://example.com/")
            .unwrap()
            .http_version(HttpVersionPref::Http3);
        assert_eq!(r.http_version_pref, HttpVersionPref::Http3);
    }

    #[test]
    fn h3_fallback_classification() {
        use std::io;
        // Transport failures fall back under --http3.
        assert!(h3_should_fall_back(&Error::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            "x"
        ))));
        assert!(h3_should_fall_back(&Error::BadResponse(
            "http3: feed: Decode".into()
        )));
        assert!(h3_should_fall_back(&Error::BadResponse(
            "http3: connection closed mid-handshake".into()
        )));
        assert!(h3_should_fall_back(&Error::BadResponse(
            "http3: peer closed connection".into()
        )));
        // A mid-response protocol/decode error over an established QUIC
        // connection is propagated, not silently retried over TCP.
        assert!(!h3_should_fall_back(&Error::BadResponse(
            "qpack: dynamic index out of range".into()
        )));
        assert!(!h3_should_fall_back(&Error::H2NotNegotiated));
    }

    #[test]
    fn http3_only_over_plaintext_http_errors() {
        // --http3-only on an http:// URL must fail clearly (h3 needs TLS/QUIC).
        let req = Request::get("http://example.com/").unwrap().http3_only();
        let mut trace = Vec::new();
        let err = send_plain(req, &mut trace).unwrap_err();
        assert!(matches!(err, Error::UnsupportedScheme(_)));
    }

    #[test]
    fn tls_pool_eligible_only_for_default_posture() {
        let mut req = Request::get("https://example.com/").unwrap();
        assert!(tls_pool_eligible(&req)); // verify on, no custom CA
        req.verify_tls = false;
        assert!(!tls_pool_eligible(&req)); // -k
        req.verify_tls = true;
        req.ca_bundle = Some("/tmp/ca.pem".into());
        assert!(!tls_pool_eligible(&req)); // --cacert
        req.ca_bundle = None;
        req.ca_path = Some("/tmp/cadir".into());
        assert!(!tls_pool_eligible(&req)); // --capath
        req.ca_path = None;
        req.client_cert = Some("/tmp/client.pem".into());
        assert!(!tls_pool_eligible(&req)); // -E (client identity)
        req.client_cert = None;
        req.pinned_pubkey = Some("sha256//AAAA".into());
        assert!(!tls_pool_eligible(&req)); // --pinnedpubkey
        req.pinned_pubkey = None;
        req.crl_file = Some("/tmp/crl.pem".into());
        assert!(!tls_pool_eligible(&req)); // --crlfile
    }

    #[test]
    fn pool_key_no_overrides_pools_together() {
        // Two plain requests to the same authority with no --connect-to /
        // --resolve must produce identical keys (so they share a pooled
        // socket) — the common case, unchanged by this fix.
        let a = Request::get("http://example.com/a").unwrap();
        let b = Request::get("http://example.com/b").unwrap();
        let ka = pool_key_for(&a);
        let kb = pool_key_for(&b);
        assert_eq!(ka, kb);
        assert_eq!(ka.effective_target, None);
    }

    #[test]
    fn pool_key_connect_to_distinguishes_dial_target() {
        // Same URL authority, but --connect-to remaps the dial target. The
        // keys must differ so a socket dialed to one backend isn't reused for
        // a request that would dial elsewhere (connection confusion).
        let plain = Request::get("http://example.com/").unwrap();
        let remapped = Request::get("http://example.com/").unwrap().connect_to(
            "example.com",
            80,
            "10.0.0.1",
            8080,
        );
        let kp = pool_key_for(&plain);
        let kr = pool_key_for(&remapped);
        assert_ne!(kp, kr);
        // SNI/Host (host,port) are unchanged — only the discriminator moves.
        assert_eq!(kr.host, "example.com");
        assert_eq!(kr.port, 80);
        assert_eq!(kr.effective_target, Some(("10.0.0.1".to_string(), 8080)));
        assert_eq!(kp.effective_target, None);
    }

    #[test]
    fn pool_key_resolve_distinguishes_pinned_ip() {
        // Same URL authority, but --resolve pins different IPs. Each must get
        // a distinct key, and neither must equal the no-override key.
        let plain = Request::get("http://example.com/").unwrap();
        let to_a = Request::get("http://example.com/").unwrap().resolve_addr(
            "example.com",
            80,
            "10.0.0.1".parse().unwrap(),
        );
        let to_b = Request::get("http://example.com/").unwrap().resolve_addr(
            "example.com",
            80,
            "10.0.0.2".parse().unwrap(),
        );
        let kp = pool_key_for(&plain);
        let ka = pool_key_for(&to_a);
        let kb = pool_key_for(&to_b);
        assert_ne!(ka, kb);
        assert_ne!(ka, kp);
        assert_ne!(kb, kp);
        assert_eq!(ka.effective_target, Some(("10.0.0.1".to_string(), 80)));
        assert_eq!(kb.effective_target, Some(("10.0.0.2".to_string(), 80)));
    }

    #[test]
    fn pool_key_non_matching_override_is_transparent() {
        // A --connect-to / --resolve rule that doesn't match this (host,port)
        // must leave the discriminator None so pooling is unaffected.
        let req = Request::get("http://example.com/")
            .unwrap()
            .connect_to("other.example", 80, "10.0.0.1", 9000)
            .resolve_addr("other.example", 80, "10.0.0.2".parse().unwrap());
        assert_eq!(pool_key_for(&req).effective_target, None);
        // And it equals the bare request's key.
        let bare = Request::get("http://example.com/").unwrap();
        assert_eq!(pool_key_for(&req), pool_key_for(&bare));
    }

    #[test]
    fn effective_dial_target_resolve_follows_connect_to() {
        // --connect-to remaps to backend:8080, then --resolve pins that
        // remapped host:port to an IP. The discriminator should reflect the
        // pinned IP at the remapped port — matching tcp_connect's order.
        let connect_to = vec![(
            "example.com".to_string(),
            80,
            "backend".to_string(),
            8080u16,
        )];
        let resolve = vec![("backend".to_string(), 8080u16, "10.0.0.5".parse().unwrap())];
        let t = effective_dial_target(&connect_to, &resolve, "example.com", 80);
        assert_eq!(t, Some(("10.0.0.5".to_string(), 8080)));
    }

    #[test]
    fn tls_opts_from_wires_client_cert_and_pins() {
        use std::io::Write;
        // Generate a self-signed Ed25519 cert + key, write them to temp files,
        // and confirm tls_opts_from reads them and parses the --pinnedpubkey.
        let (leaf_der, key_pem) = crate::tls::client_auth::tests_support_ed25519_leaf();
        let cert_pem = purecrypto::x509::Certificate::from_der(leaf_der.clone())
            .unwrap()
            .to_pem();
        let dir = std::env::temp_dir();
        let cert_path = dir.join(format!("rsurl_test_cert_{}.pem", std::process::id()));
        let key_path = dir.join(format!("rsurl_test_key_{}.pem", std::process::id()));
        std::fs::File::create(&cert_path)
            .unwrap()
            .write_all(cert_pem.as_bytes())
            .unwrap();
        std::fs::File::create(&key_path)
            .unwrap()
            .write_all(key_pem.as_bytes())
            .unwrap();

        let pin = crate::tls::client_auth::leaf_spki_sha256(&leaf_der).unwrap();
        let b64 = pin_to_sha256_spec(&pin);

        let req = Request::get("https://example.com/")
            .unwrap()
            .client_cert(cert_path.to_str().unwrap())
            .client_key(key_path.to_str().unwrap())
            .pinned_pubkey(&b64);
        let opts = tls_opts_from(&req, &[]).expect("build TlsOpts");
        assert!(opts.client_cert.is_some());
        assert!(opts.client_key.is_some());
        assert_eq!(opts.pinned_spki_sha256, vec![pin]);

        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);
    }

    /// Base64-encode a 32-byte hash into curl's `sha256//BASE64` pin form.
    fn pin_to_sha256_spec(hash: &[u8; 32]) -> String {
        format!("sha256//{}", crate::websocket::base64_encode(hash))
    }

    #[test]
    fn tls_opts_from_reads_crl_file() {
        use std::io::Write;
        // tls_opts_from only reads the file into `crl_pem`; the backend parses
        // it at connect time, so any bytes round-trip here.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("rsurl_test_crl_{}.pem", std::process::id()));
        let body = b"-----BEGIN X509 CRL-----\nMIIB\n-----END X509 CRL-----\n";
        std::fs::File::create(&path)
            .unwrap()
            .write_all(body)
            .unwrap();
        let req = Request::get("https://example.com/")
            .unwrap()
            .crl_file(path.to_str().unwrap());
        assert!(!tls_pool_eligible(&req)); // a CRL'd request must not reuse a pool socket
        let opts = tls_opts_from(&req, &[]).expect("build TlsOpts");
        assert_eq!(opts.crl_pem.as_deref(), Some(body.as_slice()));
        let _ = std::fs::remove_file(&path);
    }

    /// Build a bare `Response` for the body-ergonomics tests.
    fn resp_with(content_type: Option<&str>, status: u16, body: &[u8]) -> Response {
        let mut headers = Vec::new();
        if let Some(ct) = content_type {
            headers.push(("Content-Type".to_string(), ct.to_string()));
        }
        Response {
            status,
            reason: if status == 404 {
                "Not Found".into()
            } else {
                "OK".into()
            },
            version: "HTTP/1.1".into(),
            headers,
            body: body.to_vec(),
            timing: Timing::default(),
            final_url: String::new(),
        }
    }

    #[test]
    fn response_text_decodes_charsets() {
        // Default (no charset) → UTF-8.
        assert_eq!(
            resp_with(None, 200, "héllo".as_bytes()).text().unwrap(),
            "héllo"
        );
        // Explicit, quoted, mixed-case charset param is honored.
        assert_eq!(
            resp_with(Some("text/plain; Charset=\"UTF-8\""), 200, b"hi")
                .text()
                .unwrap(),
            "hi"
        );
        // Invalid UTF-8 decodes lossily (U+FFFD), never errors.
        let lossy = resp_with(None, 200, b"a\xffb").text().unwrap();
        assert_eq!(lossy, "a\u{fffd}b");
        // Latin-1: byte 0xE9 is 'é'.
        assert_eq!(
            resp_with(Some("text/plain; charset=iso-8859-1"), 200, &[b'c', 0xE9])
                .text()
                .unwrap(),
            "cé"
        );
        // An unsupported declared charset errors rather than mis-decoding.
        let err = resp_with(Some("text/plain; charset=shift_jis"), 200, b"x").text();
        assert!(matches!(err, Err(Error::Decode(_))), "got {err:?}");
    }

    #[test]
    fn response_error_for_status() {
        assert!(resp_with(None, 200, b"ok").error_for_status().is_ok());
        assert!(resp_with(None, 302, b"").error_for_status().is_ok());
        match resp_with(None, 404, b"nope").error_for_status() {
            Err(Error::Status { code, reason }) => {
                assert_eq!(code, 404);
                assert_eq!(reason, "Not Found");
            }
            other => panic!("expected Status error, got {other:?}"),
        }
        assert!(matches!(
            resp_with(None, 500, b"").error_for_status(),
            Err(Error::Status { code: 500, .. })
        ));
    }

    #[cfg(feature = "json")]
    #[test]
    fn response_json_deserializes() {
        let r = resp_with(Some("application/json"), 200, br#"{"a":1,"b":["x","y"]}"#);
        let v: serde_json::Value = r.json().expect("parse json");
        assert_eq!(v["a"], 1);
        assert_eq!(v["b"][1], "y");
        // Malformed JSON surfaces as Error::Decode, not a panic.
        let bad = resp_with(Some("application/json"), 200, b"{not json");
        assert!(matches!(
            bad.json::<serde_json::Value>(),
            Err(Error::Decode(_))
        ));
    }

    #[test]
    fn content_length_single_ok() {
        let h = vec![("Content-Length".to_string(), "42".to_string())];
        assert_eq!(parse_content_length(&h).unwrap(), Some(42));
    }

    #[test]
    fn content_length_absent_is_none() {
        let h = vec![("X".to_string(), "y".to_string())];
        assert_eq!(parse_content_length(&h).unwrap(), None);
    }

    #[test]
    fn content_length_duplicate_agreeing_ok() {
        let h = vec![
            ("Content-Length".to_string(), "5".to_string()),
            ("content-length".to_string(), "5".to_string()),
        ];
        assert_eq!(parse_content_length(&h).unwrap(), Some(5));
    }

    #[test]
    fn content_length_conflicting_rejected() {
        let h = vec![
            ("Content-Length".to_string(), "5".to_string()),
            ("Content-Length".to_string(), "6".to_string()),
        ];
        assert!(parse_content_length(&h).is_err());
    }

    #[test]
    fn content_length_comma_list_conflicting_rejected() {
        let h = vec![("Content-Length".to_string(), "5, 6".to_string())];
        assert!(parse_content_length(&h).is_err());
    }

    #[test]
    fn content_length_comma_list_agreeing_ok() {
        let h = vec![("Content-Length".to_string(), "5, 5".to_string())];
        assert_eq!(parse_content_length(&h).unwrap(), Some(5));
    }

    #[test]
    fn content_length_unparseable_rejected() {
        let h = vec![("Content-Length".to_string(), "not-a-number".to_string())];
        assert!(parse_content_length(&h).is_err());
    }

    #[test]
    fn content_length_signed_rejected() {
        // RFC 9112 §6.3: a leading '+' is not `1*DIGIT`. Accepting it creates a
        // framing differential vs strict upstreams (CL desync primitive).
        let h = vec![("Content-Length".to_string(), "+5".to_string())];
        assert!(parse_content_length(&h).is_err());
    }

    #[test]
    fn content_length_plain_digits_ok() {
        let h = vec![("Content-Length".to_string(), "5".to_string())];
        assert_eq!(parse_content_length(&h).unwrap(), Some(5));
    }

    #[test]
    fn read_body_rejects_te_and_cl_together() {
        use std::io::Cursor;
        // A response advertising both chunked TE and a Content-Length is a
        // smuggling vector and must be rejected outright.
        let headers = vec![
            ("Transfer-Encoding".to_string(), "chunked".to_string()),
            ("Content-Length".to_string(), "5".to_string()),
        ];
        let mut r = BufReader::new(Cursor::new(b"0\r\n\r\n".to_vec()));
        let err = read_body(&mut r, &headers, "HTTP/1.1", 200, "GET").unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)));
    }

    #[test]
    fn read_body_rejects_conflicting_content_length() {
        use std::io::Cursor;
        let headers = vec![
            ("Content-Length".to_string(), "3".to_string()),
            ("Content-Length".to_string(), "4".to_string()),
        ];
        let mut r = BufReader::new(Cursor::new(b"abcd".to_vec()));
        assert!(read_body(&mut r, &headers, "HTTP/1.1", 200, "GET").is_err());
    }

    /// A `BufRead` whose [`TruncationAware`] verdict is configurable, to drive
    /// the TLS-1 EOF-delimited truncation checks in `read_body`/`stream_body`.
    struct TruncReader {
        inner: std::io::Cursor<Vec<u8>>,
        truncated: bool,
    }
    impl Read for TruncReader {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            self.inner.read(b)
        }
    }
    impl BufRead for TruncReader {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            self.inner.fill_buf()
        }
        fn consume(&mut self, n: usize) {
            self.inner.consume(n)
        }
    }
    impl TruncationAware for TruncReader {
        fn response_truncated(&self) -> bool {
            self.truncated
        }
    }

    #[test]
    fn read_body_rejects_truncated_eof_delimited() {
        // No Content-Length and no chunked → EOF-delimited. A TLS close
        // without close_notify (truncated == true) must be rejected (TLS-1).
        let headers: Vec<(String, String)> = vec![];
        let mut r = TruncReader {
            inner: std::io::Cursor::new(b"partial body".to_vec()),
            truncated: true,
        };
        let err = read_body(&mut r, &headers, "HTTP/1.1", 200, "GET").unwrap_err();
        assert!(matches!(err, Error::UnexpectedEof));
    }

    #[test]
    fn read_body_accepts_clean_eof_delimited() {
        // Same EOF-delimited body, but a clean close_notify (truncated ==
        // false) yields the full body.
        let headers: Vec<(String, String)> = vec![];
        let mut r = TruncReader {
            inner: std::io::Cursor::new(b"complete body".to_vec()),
            truncated: false,
        };
        let body = read_body(&mut r, &headers, "HTTP/1.1", 200, "GET").unwrap();
        assert_eq!(body, b"complete body");
    }

    #[test]
    fn read_body_ignores_truncation_for_content_length() {
        // A length-delimited body is framed by Content-Length, not the close,
        // so a missing close_notify is irrelevant and must NOT error.
        let headers = vec![("Content-Length".to_string(), "5".to_string())];
        let mut r = TruncReader {
            inner: std::io::Cursor::new(b"hello".to_vec()),
            truncated: true,
        };
        let body = read_body(&mut r, &headers, "HTTP/1.1", 200, "GET").unwrap();
        assert_eq!(body, b"hello");
    }

    #[test]
    fn stream_body_rejects_truncated_eof_delimited() {
        let headers: Vec<(String, String)> = vec![];
        let mut r = TruncReader {
            inner: std::io::Cursor::new(b"partial".to_vec()),
            truncated: true,
        };
        let mut sink: Vec<u8> = Vec::new();
        let err = stream_body(&mut r, &mut sink, &headers, 200, "GET").unwrap_err();
        assert!(matches!(err, Error::UnexpectedEof));
    }

    #[test]
    fn read_line_capped_errors_on_overlong_line() {
        use std::io::Cursor;
        // A line with no '\n' that exceeds the cap must error, not grow forever.
        let huge = vec![b'a'; MAX_HEADER_BYTES + 4096];
        let mut r = BufReader::new(Cursor::new(huge));
        let mut buf = String::new();
        let err = read_line_capped(&mut r, &mut buf, MAX_HEADER_BYTES).unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)), "got {err:?}");
    }

    #[test]
    fn read_line_capped_reads_normal_line_and_eof() {
        use std::io::Cursor;
        let mut r = BufReader::new(Cursor::new(b"hello\r\nworld".to_vec()));
        let mut a = String::new();
        let n = read_line_capped(&mut r, &mut a, MAX_HEADER_BYTES).unwrap();
        assert_eq!(n, 7);
        assert_eq!(a, "hello\r\n");
        // Second line has no terminator; we return it on EOF like read_line.
        let mut b = String::new();
        let n = read_line_capped(&mut r, &mut b, MAX_HEADER_BYTES).unwrap();
        assert_eq!(n, 5);
        assert_eq!(b, "world");
        // Now truly EOF -> 0.
        let mut c = String::new();
        let n = read_line_capped(&mut r, &mut c, MAX_HEADER_BYTES).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn read_response_rejects_overlong_status_line() {
        use std::io::Cursor;
        // A status line that never contains '\n' and blows past the cap must
        // yield an Err rather than hang or exhaust memory.
        let huge = vec![b'X'; MAX_HEADER_BYTES + 4096];
        let mut r = BufReader::new(Cursor::new(huge));
        let mut trace = Vec::new();
        let err = read_response(&mut r, "GET", &mut trace).unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)), "got {err:?}");
    }

    #[test]
    fn read_response_rejects_overlong_header_line() {
        use std::io::Cursor;
        // Valid status line, then a single header line that never terminates.
        let mut bytes = b"HTTP/1.1 200 OK\r\n".to_vec();
        bytes.extend(std::iter::repeat_n(b'a', MAX_HEADER_BYTES + 4096));
        let mut r = BufReader::new(Cursor::new(bytes));
        let mut trace = Vec::new();
        let err = read_response(&mut r, "GET", &mut trace).unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)), "got {err:?}");
    }

    #[test]
    fn read_chunked_rejects_overlong_size_line() {
        use std::io::Cursor;
        // A chunk-size line that never terminates must error, not OOM.
        let huge = vec![b'f'; MAX_HEADER_BYTES + 4096];
        let mut r = BufReader::new(Cursor::new(huge));
        let err = read_chunked(&mut r).unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)), "got {err:?}");
    }

    #[test]
    fn read_chunked_rejects_signed_chunk_size() {
        use std::io::Cursor;
        // RFC 9112 §7.1: chunk-size is `1*HEXDIG`; a leading '+' must be
        // rejected (chunked desync primitive vs strict upstreams).
        let mut r = BufReader::new(Cursor::new(b"+a\r\n".to_vec()));
        let err = read_chunked(&mut r).unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)), "got {err:?}");
    }

    #[test]
    fn read_chunked_rejects_internal_junk_chunk_size() {
        use std::io::Cursor;
        // Internal whitespace/junk ("a b") survives `trim` and is not
        // `1*HEXDIG`, so it must be rejected — `trim` only removes the
        // surrounding CR/LF the reader leaves, never embedded junk.
        let mut r = BufReader::new(Cursor::new(b"a b\r\n".to_vec()));
        let err = read_chunked(&mut r).unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)), "got {err:?}");
    }

    #[test]
    fn read_chunked_accepts_plain_hex_chunk_size() {
        use std::io::Cursor;
        // "a" (10) and "1f" (31) are valid hex chunk sizes. Feed two chunks
        // and the terminating zero chunk; the body should concatenate cleanly.
        let mut payload = Vec::new();
        payload.extend_from_slice(b"a\r\n"); // size 10
        payload.extend_from_slice(b"0123456789\r\n");
        payload.extend_from_slice(b"1f\r\n"); // size 31
        payload.extend_from_slice(&[b'x'; 31]);
        payload.extend_from_slice(b"\r\n");
        payload.extend_from_slice(b"0\r\n\r\n");
        let mut r = BufReader::new(Cursor::new(payload));
        let body = read_chunked(&mut r).unwrap();
        assert_eq!(body.len(), 10 + 31);
        assert_eq!(&body[..10], b"0123456789");
        assert!(body[10..].iter().all(|&b| b == b'x'));
    }

    #[test]
    fn read_chunked_rejects_oversized_trailer_block() {
        use std::io::Cursor;
        // After the terminating zero chunk, a server streams non-empty trailer
        // lines without ever sending the closing empty line. Each line is short
        // enough to pass the per-line cap, so only a cumulative bound stops it.
        let mut payload = Vec::new();
        payload.extend_from_slice(b"0\r\n");
        let line = b"X-Trailer: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n";
        // Enough lines to exceed MAX_HEADER_BYTES in aggregate.
        let reps = (MAX_HEADER_BYTES / line.len()) + 16;
        for _ in 0..reps {
            payload.extend_from_slice(line);
        }
        let mut r = BufReader::new(Cursor::new(payload));
        let err = read_chunked(&mut r).unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)), "got {err:?}");
    }

    #[test]
    fn stream_chunked_rejects_oversized_trailer_block() {
        use std::io::Cursor;
        let mut payload = Vec::new();
        payload.extend_from_slice(b"0\r\n");
        let line = b"X-Trailer: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n";
        let reps = (MAX_HEADER_BYTES / line.len()) + 16;
        for _ in 0..reps {
            payload.extend_from_slice(line);
        }
        let mut r = BufReader::new(Cursor::new(payload));
        let mut sink = Vec::new();
        let err = stream_chunked(&mut r, &mut sink).unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)), "got {err:?}");
    }

    #[test]
    fn digest_scheme_detection_is_char_boundary_safe() {
        // Mirrors the WWW-Authenticate scheme check in `send_to`. A value whose
        // byte offset 6 lands inside a multibyte UTF-8 char must not panic and
        // must be treated as non-Digest. `"Digé…"` is 4 ASCII + a 2-byte 'é',
        // so offset 6 is mid-char.
        fn is_digest(chal: &str) -> bool {
            let scheme = chal.trim_start();
            scheme
                .as_bytes()
                .get(..6)
                .is_some_and(|b| b.eq_ignore_ascii_case(b"digest"))
        }
        // No panic on a non-char-boundary at offset 6, and not treated as Digest.
        assert!(!is_digest("Digé realm=\"x\""));
        // Multibyte right at the front also must not panic.
        assert!(!is_digest("é"));
        assert!(!is_digest("\u{1f600}abcdef"));
        // Genuine schemes still match / not, by ASCII prefix.
        assert!(is_digest("Digest realm=\"x\""));
        assert!(is_digest("  digest realm=\"x\""));
        assert!(!is_digest("Basic realm=\"x\""));
        assert!(!is_digest("Dig"));
    }

    #[test]
    fn proxy_parse_basic() {
        let p = ProxyConfig::parse("http://proxy.example:3128").unwrap();
        assert_eq!(p.host, "proxy.example");
        assert_eq!(p.port, 3128);
        assert!(p.auth.is_none());
    }

    #[test]
    fn proxy_parse_with_creds() {
        let p = ProxyConfig::parse("http://alice:hunter2@proxy:8080").unwrap();
        assert_eq!(p.host, "proxy");
        assert_eq!(p.port, 8080);
        assert_eq!(p.auth.as_ref().unwrap().0, "alice");
        assert_eq!(p.auth.as_ref().unwrap().1, "hunter2");
    }

    #[test]
    fn proxy_parse_bare_hostport_is_http() {
        // Curl accepts `proxy:8080`; we normalise to http://.
        let p = ProxyConfig::parse("proxy.local:8080").unwrap();
        assert_eq!(p.host, "proxy.local");
        assert_eq!(p.port, 8080);
    }

    #[test]
    fn proxy_parse_rejects_https() {
        let err = ProxyConfig::parse("https://proxy:443").unwrap_err();
        matches!(err, Error::UnsupportedScheme(_));
    }

    #[test]
    fn proxy_bypass_matches_suffix() {
        let mut req = Request::get("http://api.example.com/x").unwrap();
        req.proxy = Some(ProxyConfig::parse("http://proxy:8080").unwrap());
        req.no_proxy = vec!["example.com".into()];
        assert!(proxy_bypassed(&req));
        // sibling host not under example.com
        req.url = Url::parse("http://other.org/x").unwrap();
        assert!(!proxy_bypassed(&req));
    }

    #[test]
    fn proxy_bypass_wildcard() {
        let mut req = Request::get("http://anywhere/").unwrap();
        req.proxy = Some(ProxyConfig::parse("http://p:1").unwrap());
        req.no_proxy = vec!["*".into()];
        assert!(proxy_bypassed(&req));
    }

    #[test]
    fn connect_tunnel_happy_path() {
        // A tiny mock stream: serves the canned `HTTP/1.1 200 OK\r\n\r\n`
        // response and records everything written to it. Confirms that the
        // CONNECT line and Host: target are correctly framed and that the
        // tunnel completes without consuming any byte past the terminator.
        use std::io::{self, Cursor};
        struct Mock {
            written: Vec<u8>,
            reply: Cursor<Vec<u8>>,
            trailing: Vec<u8>, // bytes the reader would deliver AFTER the response
        }
        impl Read for Mock {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let n = self.reply.read(buf)?;
                if n == 0 && !self.trailing.is_empty() {
                    let take = buf.len().min(self.trailing.len());
                    buf[..take].copy_from_slice(&self.trailing[..take]);
                    self.trailing.drain(..take);
                    return Ok(take);
                }
                Ok(n)
            }
        }
        impl Write for Mock {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.written.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let mut mock = Mock {
            written: Vec::new(),
            reply: Cursor::new(b"HTTP/1.1 200 Connection established\r\n\r\n".to_vec()),
            // Pretend the server pre-sent the first byte of a TLS
            // ClientHello immediately after the terminator. The tunnel
            // function must NOT have eaten it.
            trailing: vec![0x16],
        };
        let target = Url::parse("https://origin.example:443/").unwrap();
        let proxy = ProxyConfig {
            host: "proxy".into(),
            port: 3128,
            auth: Some(("u".into(), "p".into())),
        };
        connect_tunnel(&mut mock, &target, &proxy, &mut io::sink()).unwrap();

        let written = String::from_utf8(mock.written.clone()).unwrap();
        assert!(
            written.starts_with("CONNECT origin.example:443 HTTP/1.1\r\n"),
            "request line missing: {written:?}",
        );
        assert!(
            written.contains("Host: origin.example:443\r\n"),
            "Host header missing: {written:?}",
        );
        assert!(
            written.contains("Proxy-Authorization: Basic dTpw\r\n"),
            "auth header missing or wrong: {written:?}",
        );
        // The trailing 0x16 must still be readable through the same stream —
        // any BufReader-style prefetch would have stolen it.
        let mut byte = [0u8; 1];
        assert_eq!(mock.read(&mut byte).unwrap(), 1);
        assert_eq!(byte[0], 0x16, "next-layer byte was consumed by the tunnel");
    }

    #[test]
    fn connect_tunnel_reports_407() {
        use std::io::{self, Cursor};
        let payload =
            b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n";
        let mut mock = std::io::Cursor::new(Vec::new());
        // We need a Read+Write; chain Cursor over a buffer that has the
        // canned reply followed by writes appended; the simplest is to use
        // two structs but for one test just inline a tiny helper.
        struct RW<'a> {
            inner: Cursor<&'a [u8]>,
            sink: &'a mut Vec<u8>,
        }
        impl<'a> Read for RW<'a> {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                self.inner.read(b)
            }
        }
        impl<'a> Write for RW<'a> {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                self.sink.extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut sink = Vec::new();
        let mut rw = RW {
            inner: Cursor::new(payload),
            sink: &mut sink,
        };
        let target = Url::parse("https://origin/").unwrap();
        let proxy = ProxyConfig {
            host: "p".into(),
            port: 1,
            auth: None,
        };
        let err = connect_tunnel(&mut rw, &target, &proxy, &mut io::sink()).unwrap_err();
        match err {
            Error::BadResponse(msg) => assert!(msg.contains("407"), "got {msg:?}"),
            other => panic!("unexpected: {other:?}"),
        }
        // unused so clippy doesn't complain about `mock`
        let _ = mock.write(&[]);
    }
}

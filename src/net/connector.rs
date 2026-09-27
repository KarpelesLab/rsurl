//! The [`Connector`] trait, built-in connectors, and a proxy-URL factory.
//!
//! A `Connector` turns a logical `host:port` target into a connected,
//! plaintext [`NetStream`]. The default [`DirectConnector`] dials TCP
//! directly; the built-in proxy connectors route through an HTTP CONNECT,
//! HTTPS (TLS-to-proxy) CONNECT, or SOCKS4/4a/5/5h proxy. Callers can also
//! implement `Connector` themselves to supply a fully custom transport
//! (a pre-established socket, an in-process pipe, a test double, …).

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::net::socks;
use crate::net::stream::NetStream;
use crate::net::Resolver;
use crate::url::percent_decode;

/// Tells the HTTP layer that plain-`http://` traffic through this connector
/// must use absolute-form request lines and `Proxy-Authorization` (i.e. the
/// connector is a forward proxy), rather than origin-form. Returned by
/// [`Connector::http_forward_proxy`].
#[derive(Debug, Clone)]
pub struct HttpProxyIntent {
    /// Credentials to put in `Proxy-Authorization: Basic`, if any.
    pub auth: Option<(String, String)>,
}

/// A pluggable transport: connect to `host:port` and return a plaintext byte
/// stream. TLS (when the scheme needs it) is layered on top by the caller, so
/// implementations are transport-only.
///
/// The `Debug` bound lets a connector live inside a `#[derive(Debug)]` type
/// such as [`crate::Request`]; a `#[derive(Debug)]` on your implementation
/// satisfies it.
pub trait Connector: Send + Sync + std::fmt::Debug {
    /// Establish a connection to `host:port`. `timeout`, when set, bounds the
    /// connect phase (and any proxy handshake).
    fn connect(
        &self,
        host: &str,
        port: u16,
        timeout: Option<Duration>,
    ) -> Result<Box<dyn NetStream>>;

    /// If this connector is a forward HTTP proxy, the framing intent for
    /// plain-`http://` requests. `None` (the default) means origin-form.
    fn http_forward_proxy(&self) -> Option<HttpProxyIntent> {
        None
    }

    /// Whether this is a plain direct TCP connector. The HTTP connection pool
    /// only reuses sockets for direct connectors.
    fn is_direct(&self) -> bool {
        false
    }

    /// How this connector carries UDP datagrams (HTTP/3, TFTP). Most proxies
    /// cannot tunnel UDP; only a direct dial or a SOCKS5 proxy can. The default
    /// is [`UdpProxy::Unsupported`](crate::net::UdpProxy), so a custom connector opts in by
    /// overriding this.
    fn udp_proxy(&self) -> crate::net::udp::UdpProxy {
        crate::net::udp::UdpProxy::Unsupported
    }
}

/// Open a TCP connection to `host:port` (a name, an IP, or a bracketed IPv6
/// literal), honoring `timeout` for each connect attempt and falling back
/// through every resolved address in order.
fn open_tcp(host: &str, port: u16, timeout: Option<Duration>) -> Result<TcpStream> {
    let addrs = crate::net::StdResolver.resolve(host, port)?;
    Ok(crate::net::connect_any(&addrs, timeout)?)
}

// ---------------------------------------------------------------------------
// Direct
// ---------------------------------------------------------------------------

/// The default connector: a plain TCP dial, no proxy.
#[derive(Debug, Default, Clone)]
pub struct DirectConnector;

impl Connector for DirectConnector {
    fn connect(
        &self,
        host: &str,
        port: u16,
        timeout: Option<Duration>,
    ) -> Result<Box<dyn NetStream>> {
        Ok(Box::new(open_tcp(host, port, timeout)?))
    }

    fn is_direct(&self) -> bool {
        true
    }

    fn udp_proxy(&self) -> crate::net::udp::UdpProxy {
        crate::net::udp::UdpProxy::Direct
    }
}

// ---------------------------------------------------------------------------
// SOCKS4 / SOCKS5
// ---------------------------------------------------------------------------

/// SOCKS4 (or SOCKS4a when `remote_dns`) proxy connector.
#[derive(Debug, Clone)]
pub struct Socks4Connector {
    pub host: String,
    pub port: u16,
    /// The `USERID` field (often empty).
    pub user: String,
    /// `true` for SOCKS4a (proxy-side DNS).
    pub remote_dns: bool,
}

impl Connector for Socks4Connector {
    fn connect(
        &self,
        host: &str,
        port: u16,
        timeout: Option<Duration>,
    ) -> Result<Box<dyn NetStream>> {
        let stream = open_tcp(&self.host, self.port, timeout)?;
        apply_handshake_timeout(&stream, timeout)?;
        let mut s = stream;
        socks::socks4_connect(&mut s, host, port, &self.user, self.remote_dns)?;
        clear_handshake_timeout(&s)?;
        Ok(Box::new(s))
    }
}

/// SOCKS5 (or SOCKS5h when `remote_dns`) proxy connector.
#[derive(Debug, Clone)]
pub struct Socks5Connector {
    pub host: String,
    pub port: u16,
    /// Optional username/password (RFC 1929).
    pub auth: Option<(String, String)>,
    /// `true` for SOCKS5h (proxy-side DNS).
    pub remote_dns: bool,
}

impl Connector for Socks5Connector {
    fn connect(
        &self,
        host: &str,
        port: u16,
        timeout: Option<Duration>,
    ) -> Result<Box<dyn NetStream>> {
        let mut s = open_tcp(&self.host, self.port, timeout)?;
        apply_handshake_timeout(&s, timeout)?;
        let auth = self.auth.as_ref().map(|(u, p)| (u.as_str(), p.as_str()));
        socks::socks5_connect(&mut s, host, port, auth, self.remote_dns)?;
        clear_handshake_timeout(&s)?;
        Ok(Box::new(s))
    }

    fn udp_proxy(&self) -> crate::net::udp::UdpProxy {
        crate::net::udp::UdpProxy::Socks5 {
            host: self.host.clone(),
            port: self.port,
            auth: self.auth.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP CONNECT / HTTPS-to-proxy CONNECT
// ---------------------------------------------------------------------------

/// HTTP forward proxy: `CONNECT host:port` for TLS targets, absolute-form for
/// plain `http://` (signalled via [`Connector::http_forward_proxy`]).
#[derive(Debug, Clone)]
pub struct HttpProxyConnector {
    pub host: String,
    pub port: u16,
    pub auth: Option<(String, String)>,
}

impl Connector for HttpProxyConnector {
    fn connect(
        &self,
        host: &str,
        port: u16,
        timeout: Option<Duration>,
    ) -> Result<Box<dyn NetStream>> {
        let mut s = open_tcp(&self.host, self.port, timeout)?;
        apply_handshake_timeout(&s, timeout)?;
        http_connect(&mut s, host, port, self.auth.as_ref())?;
        clear_handshake_timeout(&s)?;
        Ok(Box::new(s))
    }

    fn http_forward_proxy(&self) -> Option<HttpProxyIntent> {
        Some(HttpProxyIntent {
            auth: self.auth.clone(),
        })
    }
}

/// Like [`HttpProxyConnector`] but the proxy conversation itself runs over TLS
/// (an `https://` proxy). The certificate of the *proxy* is verified against
/// the system roots. To verify the proxy with custom settings (curl's
/// `--proxy-cacert`, `--proxy-insecure`, ...), configure them on
/// [`crate::Client`] or [`crate::Request`] (`proxy_*` methods) and pass the
/// proxy as a URL.
#[derive(Debug, Clone)]
pub struct HttpsProxyConnector {
    pub host: String,
    pub port: u16,
    pub auth: Option<(String, String)>,
}

impl Connector for HttpsProxyConnector {
    fn connect(
        &self,
        host: &str,
        port: u16,
        timeout: Option<Duration>,
    ) -> Result<Box<dyn NetStream>> {
        let tls = crate::tls::TlsSettings::default();
        https_proxy_connect(
            &self.host,
            self.port,
            self.auth.as_ref(),
            &tls,
            host,
            port,
            timeout,
        )
    }

    fn http_forward_proxy(&self) -> Option<HttpProxyIntent> {
        Some(HttpProxyIntent {
            auth: self.auth.clone(),
        })
    }
}

/// An `https://` proxy verified with caller-chosen TLS settings (the curl
/// `--proxy-*` TLS family), independent of the origin's TLS settings.
#[derive(Debug, Clone)]
pub(crate) struct HttpsProxyTlsConnector {
    host: String,
    port: u16,
    auth: Option<(String, String)>,
    tls: crate::tls::TlsSettings,
}

impl Connector for HttpsProxyTlsConnector {
    fn connect(
        &self,
        host: &str,
        port: u16,
        timeout: Option<Duration>,
    ) -> Result<Box<dyn NetStream>> {
        https_proxy_connect(
            &self.host,
            self.port,
            self.auth.as_ref(),
            &self.tls,
            host,
            port,
            timeout,
        )
    }

    fn http_forward_proxy(&self) -> Option<HttpProxyIntent> {
        Some(HttpProxyIntent {
            auth: self.auth.clone(),
        })
    }
}

/// Dial the `https://` proxy at `proxy_host:proxy_port`, handshake TLS with it
/// under `tls` (the proxy's own trust settings), then `CONNECT host:port`.
fn https_proxy_connect(
    proxy_host: &str,
    proxy_port: u16,
    auth: Option<&(String, String)>,
    tls: &crate::tls::TlsSettings,
    host: &str,
    port: u16,
    timeout: Option<Duration>,
) -> Result<Box<dyn NetStream>> {
    // Read the proxy CA / cert / key / CRL files before dialing, so a bad
    // path fails without touching the network.
    let opts = tls.to_opts(&[])?;
    let tcp = open_tcp(proxy_host, proxy_port, timeout)?;
    // A second handle on the same socket: socket options (timeouts) are
    // per-socket, so it lets `TlsProxyStream` re-arm the read/write
    // timeouts after the TLS wrap owns the original handle.
    let ctl = tcp.try_clone()?;
    apply_handshake_timeout(&tcp, timeout)?;
    let mut tls = crate::tls::connect_over_tls(tcp, proxy_host, opts)?;
    http_connect(&mut tls, host, port, auth)?;
    // Hand I/O timeouts back to the protocol layer (as the other proxy
    // connectors do); it re-arms them via `NetStream::set_read_timeout`.
    clear_handshake_timeout(&ctl)?;
    Ok(Box::new(TlsProxyStream { tls, ctl }))
}

/// Wraps the TLS stream to an `https://` proxy as a [`NetStream`]. `ctl` is a
/// cloned handle on the same TCP socket, through which timeouts, address
/// introspection, and shutdown act on the underlying connection. Cloning the
/// whole stream is unsupported (the TLS session state cannot be shared).
struct TlsProxyStream {
    tls: crate::tls::TlsStream<TcpStream>,
    ctl: TcpStream,
}

impl Read for TlsProxyStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.tls.read(buf)
    }
}
impl Write for TlsProxyStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tls.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.tls.flush()
    }
}
impl NetStream for TlsProxyStream {
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.ctl.set_read_timeout(dur)
    }
    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.ctl.set_write_timeout(dur)
    }
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.ctl.peer_addr()
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.ctl.local_addr()
    }
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.ctl.shutdown(how)
    }
    fn try_clone_box(&self) -> io::Result<Box<dyn NetStream>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "cannot clone an https-proxy stream",
        ))
    }
}

/// Issue an HTTP/1.1 `CONNECT host:port` over `stream` and succeed iff the
/// proxy answers `2xx`. The stream is then a transparent pipe to the target.
fn http_connect<S: Read + Write>(
    stream: &mut S,
    host: &str,
    port: u16,
    auth: Option<&(String, String)>,
) -> Result<()> {
    const MAX_HEADER_BYTES: usize = 64 * 1024;
    let host_port = crate::url::authority(host, port);
    let mut buf = Vec::with_capacity(128);
    write!(&mut buf, "CONNECT {host_port} HTTP/1.1\r\n")?;
    write!(&mut buf, "Host: {host_port}\r\n")?;
    write!(&mut buf, "Proxy-Connection: Keep-Alive\r\n")?;
    if let Some((user, pass)) = auth {
        let creds = crate::websocket::base64_encode(format!("{user}:{pass}").as_bytes());
        write!(&mut buf, "Proxy-Authorization: Basic {creds}\r\n")?;
    }
    write!(&mut buf, "\r\n")?;
    stream.write_all(&buf)?;
    stream.flush()?;

    // Read response headers one byte at a time until the blank line.
    let mut status: Option<String> = None;
    let mut line: Vec<u8> = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
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
        if byte[0] == b'\n' {
            let trimmed =
                String::from_utf8_lossy(line.strip_suffix(b"\r").unwrap_or(&line)).into_owned();
            if status.is_none() {
                status = Some(trimmed.clone());
            }
            if trimmed.is_empty() {
                break;
            }
            line.clear();
        } else {
            line.push(byte[0]);
        }
    }

    let status = status.ok_or_else(|| Error::BadResponse("CONNECT: no status line".into()))?;
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
    Ok(())
}

/// Apply `timeout` to a proxy socket for the duration of its handshake.
fn apply_handshake_timeout(s: &TcpStream, timeout: Option<Duration>) -> Result<()> {
    if let Some(t) = timeout {
        s.set_read_timeout(Some(t))?;
        s.set_write_timeout(Some(t))?;
    }
    Ok(())
}

/// Clear the handshake timeout so the protocol layer governs subsequent I/O.
fn clear_handshake_timeout(s: &TcpStream) -> Result<()> {
    s.set_read_timeout(None)?;
    s.set_write_timeout(None)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Unix-domain socket (curl --unix-socket)
// ---------------------------------------------------------------------------

/// Routes every connection through a Unix-domain socket, ignoring the target
/// host/port (curl `--unix-socket`). Unix only.
#[cfg(unix)]
#[derive(Debug, Clone)]
pub struct UnixConnector {
    pub path: std::path::PathBuf,
}

#[cfg(unix)]
impl Connector for UnixConnector {
    fn connect(
        &self,
        _host: &str,
        _port: u16,
        timeout: Option<Duration>,
    ) -> Result<Box<dyn NetStream>> {
        let s = std::os::unix::net::UnixStream::connect(&self.path)?;
        if let Some(t) = timeout {
            s.set_read_timeout(Some(t))?;
            s.set_write_timeout(Some(t))?;
        }
        Ok(Box::new(s))
    }
}

// ---------------------------------------------------------------------------
// Proxy-URL factory
// ---------------------------------------------------------------------------

/// Build a [`Connector`] from a curl-style proxy URL.
///
/// Recognised schemes: `http`, `https`, `socks4`, `socks4a`, `socks5`,
/// `socks5h`. A bare `host:port` (no scheme) is treated as `http`. The port
/// defaults to 1080 when omitted (curl's default proxy port).
///
/// ```
/// let c = rsurl::net::connector_from_proxy_url("socks5h://user:pass@127.0.0.1:1080").unwrap();
/// assert!(!c.is_direct());
/// ```
pub fn connector_from_proxy_url(spec: &str) -> Result<Arc<dyn Connector>> {
    Ok(ProxySpec::parse(spec)?.connector(&crate::tls::TlsSettings::default()))
}

/// A parsed, scheme-validated curl-style proxy URL. Kept (rather than a built
/// [`Connector`]) by [`crate::Client`] and [`crate::Request`] so the connector
/// can be rebuilt per redirect hop — with the current `--proxy-*` TLS
/// settings, and only when the hop's host is not in the no-proxy list.
#[derive(Debug, Clone)]
pub(crate) struct ProxySpec {
    scheme: String,
    auth: Option<(String, String)>,
    host: String,
    port: u16,
}

impl ProxySpec {
    /// Parse `spec` and reject schemes no connector exists for.
    pub(crate) fn parse(spec: &str) -> Result<ProxySpec> {
        let p = parse_proxy_spec(spec)?;
        match p.scheme.as_str() {
            "http" | "https" | "socks4" | "socks4a" | "socks5" | "socks5h" => Ok(p),
            other => Err(Error::UnsupportedScheme(format!(
                "proxy scheme {other:?} not supported (use http/https/socks4/socks4a/socks5/socks5h)"
            ))),
        }
    }

    /// For a plain `http://` proxy, the per-request [`crate::http::ProxyConfig`]
    /// form (absolute-form requests / `CONNECT` in the HTTP layer).
    pub(crate) fn http_config(&self) -> Option<crate::http::ProxyConfig> {
        (self.scheme == "http").then(|| crate::http::ProxyConfig {
            host: self.host.clone(),
            port: self.port,
            auth: self.auth.clone(),
        })
    }

    /// Build the connector for this proxy. `tls` configures the TLS session
    /// *to the proxy* (only used by `https://` proxies).
    pub(crate) fn connector(&self, tls: &crate::tls::TlsSettings) -> Arc<dyn Connector> {
        let p = self.clone();
        let socks_user = || p.auth.as_ref().map(|(u, _)| u.clone()).unwrap_or_default();
        match p.scheme.as_str() {
            "https" => Arc::new(HttpsProxyTlsConnector {
                host: p.host,
                port: p.port,
                auth: p.auth,
                tls: tls.clone(),
            }),
            "socks4" | "socks4a" => Arc::new(Socks4Connector {
                user: socks_user(),
                remote_dns: p.scheme == "socks4a",
                host: p.host,
                port: p.port,
            }),
            "socks5" | "socks5h" => Arc::new(Socks5Connector {
                remote_dns: p.scheme == "socks5h",
                host: p.host,
                port: p.port,
                auth: p.auth,
            }),
            // `parse` admits only the schemes above plus `http`.
            _ => Arc::new(HttpProxyConnector {
                host: p.host,
                port: p.port,
                auth: p.auth,
            }),
        }
    }
}

fn parse_proxy_spec(spec: &str) -> Result<ProxySpec> {
    let (scheme, rest) = match spec.split_once("://") {
        Some((s, r)) => (s.to_ascii_lowercase(), r),
        None => ("http".to_string(), spec),
    };
    // The authority ends at the first `/`, `?`, or `#`: `http://proxy:3128/`
    // (the usual `http_proxy` spelling) carries a path that curl ignores.
    let rest = match rest.find(['/', '?', '#']) {
        Some(i) => &rest[..i],
        None => rest,
    };
    let (userinfo, hostport) = match rest.rfind('@') {
        Some(i) => (Some(&rest[..i]), &rest[i + 1..]),
        None => (None, rest),
    };
    // Credentials in a proxy URL are percent-encoded (`p%40ss` = `p@ss`),
    // exactly as curl decodes them before building the auth exchange.
    let auth = userinfo.map(|info| match info.split_once(':') {
        Some((u, p)) => (percent_decode(u), percent_decode(p)),
        None => (percent_decode(info), String::new()),
    });
    let (host, port) = parse_hostport(hostport)?;
    Ok(ProxySpec {
        scheme,
        auth,
        host,
        port,
    })
}

fn parse_hostport(hp: &str) -> Result<(String, u16)> {
    const DEFAULT_PROXY_PORT: u16 = 1080;
    let bad = |what: &str| Error::InvalidUrl(format!("proxy: {what} in {hp:?}"));
    if let Some(after_bracket) = hp.strip_prefix('[') {
        // IPv6 literal: [::1] or [::1]:port
        let close = after_bracket
            .find(']')
            .ok_or_else(|| bad("unterminated IPv6"))?;
        let host = after_bracket[..close].to_string();
        let tail = &after_bracket[close + 1..];
        let port = if tail.is_empty() {
            DEFAULT_PROXY_PORT
        } else if let Some(p) = tail.strip_prefix(':') {
            p.parse().map_err(|_| bad("bad port"))?
        } else {
            return Err(bad("junk after IPv6 host"));
        };
        if host.is_empty() {
            return Err(bad("empty host"));
        }
        Ok((host, port))
    } else if let Some(i) = hp.rfind(':') {
        let host = hp[..i].to_string();
        let port = hp[i + 1..].parse().map_err(|_| bad("bad port"))?;
        if host.is_empty() {
            return Err(bad("empty host"));
        }
        Ok((host, port))
    } else if hp.is_empty() {
        Err(bad("empty host"))
    } else {
        Ok((hp.to_string(), DEFAULT_PROXY_PORT))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factory_dispatches_schemes() {
        assert!(connector_from_proxy_url("http://p:8080").is_ok());
        assert!(connector_from_proxy_url("https://p:443").is_ok());
        assert!(connector_from_proxy_url("socks4://p:1080").is_ok());
        assert!(connector_from_proxy_url("socks4a://p:1080").is_ok());
        assert!(connector_from_proxy_url("socks5://p:1080").is_ok());
        assert!(connector_from_proxy_url("socks5h://p").is_ok()); // default port
        assert!(matches!(
            connector_from_proxy_url("ftp://p:21"),
            Err(Error::UnsupportedScheme(_))
        ));
    }

    #[test]
    fn factory_parses_auth_and_default_port() {
        let p = parse_proxy_spec("socks5h://alice:secret@proxy.local").unwrap();
        assert_eq!(p.scheme, "socks5h");
        assert_eq!(p.host, "proxy.local");
        assert_eq!(p.port, 1080);
        assert_eq!(p.auth, Some(("alice".into(), "secret".into())));
    }

    #[test]
    fn factory_bare_hostport_is_http() {
        let p = parse_proxy_spec("proxy:3128").unwrap();
        assert_eq!(p.scheme, "http");
        assert_eq!(p.host, "proxy");
        assert_eq!(p.port, 3128);
        assert!(p.auth.is_none());
    }

    #[test]
    fn factory_ipv6_hostport() {
        let p = parse_proxy_spec("socks5://[::1]:1080").unwrap();
        assert_eq!(p.host, "::1");
        assert_eq!(p.port, 1080);
        let p2 = parse_proxy_spec("socks5://[fe80::1]").unwrap();
        assert_eq!(p2.host, "fe80::1");
        assert_eq!(p2.port, 1080);
    }

    /// `http_proxy=http://proxy:3128/` (trailing slash) is the common spelling;
    /// the path must be ignored, not break the port parse.
    #[test]
    fn proxy_spec_ignores_trailing_path() {
        let p = parse_proxy_spec("http://proxy:3128/").unwrap();
        assert_eq!((p.host.as_str(), p.port), ("proxy", 3128));
        let p = parse_proxy_spec("socks5h://u:p@proxy:1080/some/path?x#y").unwrap();
        assert_eq!((p.host.as_str(), p.port), ("proxy", 1080));
        assert_eq!(p.auth, Some(("u".into(), "p".into())));
        let p = parse_proxy_spec("http://[::1]:8080/").unwrap();
        assert_eq!((p.host.as_str(), p.port), ("::1", 8080));
    }

    #[test]
    fn proxy_spec_percent_decodes_credentials() {
        let p = parse_proxy_spec("http://us%65r:p%40ss%3Aword@proxy:3128").unwrap();
        assert_eq!(p.auth, Some(("user".into(), "p@ss:word".into())));
    }

    #[test]
    fn http_config_only_for_http_scheme() {
        let cfg = |s: &str| ProxySpec::parse(s).unwrap().http_config();
        let c = cfg("http://u:p%21@proxy:3128/").unwrap();
        assert_eq!((c.host.as_str(), c.port), ("proxy", 3128));
        assert_eq!(c.auth, Some(("u".into(), "p!".into())));
        assert!(cfg("proxy:8080").is_some());
        assert!(cfg("socks5://proxy:1080").is_none());
        assert!(cfg("https://proxy:443").is_none());
    }

    /// The proxy dial must accept an IPv6 proxy host (stored unbracketed) and
    /// fall back through the resolved addresses.
    #[test]
    fn open_tcp_dials_ipv6_and_ipv4_literals() {
        let l4 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let p4 = l4.local_addr().unwrap().port();
        assert!(open_tcp("127.0.0.1", p4, Some(Duration::from_secs(2))).is_ok());
        if let Ok(l6) = std::net::TcpListener::bind("[::1]:0") {
            let p6 = l6.local_addr().unwrap().port();
            assert!(open_tcp("::1", p6, Some(Duration::from_secs(2))).is_ok());
            assert!(open_tcp("[::1]", p6, Some(Duration::from_secs(2))).is_ok());
        }
    }

    /// The CONNECT request line must bracket an IPv6 target.
    #[test]
    fn http_connect_brackets_ipv6_target() {
        struct Mock {
            reply: std::io::Cursor<Vec<u8>>,
            written: Vec<u8>,
        }
        impl Read for Mock {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.reply.read(buf)
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
        for host in ["::1", "[::1]"] {
            let mut m = Mock {
                reply: std::io::Cursor::new(b"HTTP/1.1 200 OK\r\n\r\n".to_vec()),
                written: Vec::new(),
            };
            http_connect(&mut m, host, 443, None).unwrap();
            let w = String::from_utf8(m.written).unwrap();
            assert!(w.starts_with("CONNECT [::1]:443 HTTP/1.1\r\n"), "{w}");
        }
        let mut m = Mock {
            reply: std::io::Cursor::new(b"HTTP/1.1 407 Auth\r\n\r\n".to_vec()),
            written: Vec::new(),
        };
        assert!(http_connect(&mut m, "h", 443, None).is_err());
    }

    #[test]
    fn direct_connector_is_direct() {
        assert!(DirectConnector.is_direct());
        assert!(DirectConnector.http_forward_proxy().is_none());
    }

    #[test]
    fn http_proxy_connector_signals_forward_intent() {
        let c = HttpProxyConnector {
            host: "p".into(),
            port: 8080,
            auth: Some(("u".into(), "p".into())),
        };
        let intent = c.http_forward_proxy().expect("forward intent");
        assert_eq!(intent.auth, Some(("u".into(), "p".into())));
        assert!(!c.is_direct());
    }
}

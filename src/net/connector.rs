//! The [`Connector`] trait, built-in connectors, and a proxy-URL factory.
//!
//! A `Connector` turns a logical `host:port` target into a connected,
//! plaintext [`NetStream`]. The default [`DirectConnector`] dials TCP
//! directly; the built-in proxy connectors route through an HTTP CONNECT,
//! HTTPS (TLS-to-proxy) CONNECT, or SOCKS4/4a/5/5h proxy. Callers can also
//! implement `Connector` themselves to supply a fully custom transport
//! (a pre-established socket, an in-process pipe, a test double, …).

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::net::socks;
use crate::net::stream::NetStream;

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
}

/// Open a TCP connection to `host:port`, honoring `timeout` for the connect
/// phase. Mirrors the first-address selection in `http::tcp_connect`.
fn open_tcp(host: &str, port: u16, timeout: Option<Duration>) -> Result<TcpStream> {
    let addr = format!("{host}:{port}");
    let first = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| Error::InvalidUrl(host.to_string()))?;
    let stream = match timeout {
        Some(t) => TcpStream::connect_timeout(&first, t)?,
        None => TcpStream::connect(first)?,
    };
    Ok(stream)
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
/// (an `https://` proxy). The certificate of the *proxy* is verified.
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
        let tcp = open_tcp(&self.host, self.port, timeout)?;
        // Set the socket-level timeout *before* the TLS wrap; it persists for
        // the lifetime of the fd (TlsProxyStream cannot re-set it later).
        apply_handshake_timeout(&tcp, timeout)?;
        let mut tls = crate::tls::connect_over(tcp, &self.host)?;
        http_connect(&mut tls, host, port, self.auth.as_ref())?;
        Ok(Box::new(TlsProxyStream(tls)))
    }

    fn http_forward_proxy(&self) -> Option<HttpProxyIntent> {
        Some(HttpProxyIntent {
            auth: self.auth.clone(),
        })
    }
}

/// Wraps the TLS stream to an `https://` proxy as a [`NetStream`]. The socket
/// timeout is fixed at connect time (see [`HttpsProxyConnector::connect`]), so
/// the per-call timeout setters are no-ops; cloning and address introspection
/// are unsupported (only the exotic DICT-over-https-proxy combination would
/// notice).
struct TlsProxyStream(crate::tls::TlsStream<TcpStream>);

impl Read for TlsProxyStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}
impl Write for TlsProxyStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
impl NetStream for TlsProxyStream {
    fn set_read_timeout(&self, _dur: Option<Duration>) -> io::Result<()> {
        Ok(()) // socket-level timeout already applied before the TLS wrap
    }
    fn set_write_timeout(&self, _dur: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "peer_addr unavailable on an https-proxy stream",
        ))
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "local_addr unavailable on an https-proxy stream",
        ))
    }
    fn shutdown(&self, _how: Shutdown) -> io::Result<()> {
        Ok(())
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
    let host_port = format!("{host}:{port}");
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
    let p = parse_proxy_spec(spec)?;
    let socks_user = || p.auth.as_ref().map(|(u, _)| u.clone()).unwrap_or_default();
    let conn: Arc<dyn Connector> = match p.scheme.as_str() {
        "http" => Arc::new(HttpProxyConnector {
            host: p.host,
            port: p.port,
            auth: p.auth,
        }),
        "https" => Arc::new(HttpsProxyConnector {
            host: p.host,
            port: p.port,
            auth: p.auth,
        }),
        "socks4" => Arc::new(Socks4Connector {
            user: socks_user(),
            host: p.host,
            port: p.port,
            remote_dns: false,
        }),
        "socks4a" => Arc::new(Socks4Connector {
            user: socks_user(),
            host: p.host,
            port: p.port,
            remote_dns: true,
        }),
        "socks5" => Arc::new(Socks5Connector {
            host: p.host,
            port: p.port,
            auth: p.auth,
            remote_dns: false,
        }),
        "socks5h" => Arc::new(Socks5Connector {
            host: p.host,
            port: p.port,
            auth: p.auth,
            remote_dns: true,
        }),
        other => {
            return Err(Error::UnsupportedScheme(format!(
            "proxy scheme {other:?} not supported (use http/https/socks4/socks4a/socks5/socks5h)"
        )))
        }
    };
    Ok(conn)
}

struct ProxySpec {
    scheme: String,
    auth: Option<(String, String)>,
    host: String,
    port: u16,
}

fn parse_proxy_spec(spec: &str) -> Result<ProxySpec> {
    let (scheme, rest) = match spec.split_once("://") {
        Some((s, r)) => (s.to_ascii_lowercase(), r),
        None => ("http".to_string(), spec),
    };
    let (userinfo, hostport) = match rest.rfind('@') {
        Some(i) => (Some(&rest[..i]), &rest[i + 1..]),
        None => (None, rest),
    };
    let auth = userinfo.map(|info| match info.split_once(':') {
        Some((u, p)) => (u.to_string(), p.to_string()),
        None => (info.to_string(), String::new()),
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

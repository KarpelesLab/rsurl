//! Pluggable DNS resolution.
//!
//! By default rsurl resolves host names with the standard library's blocking
//! [`ToSocketAddrs`]. A caller can override this — to add caching, split-horizon
//! views, or DNS-over-HTTPS — by implementing [`Resolver`] and attaching it with
//! [`crate::Request::resolver`]. Static per-host pins set via
//! [`crate::Request::resolve_addr`] (curl `--resolve`) still win over the
//! resolver.
//!
//! Cancellation: the standard resolver is blocking and not interruptible, but a
//! transfer's [`crate::CancelToken`] still tears the connection down once it
//! reaches the socket. A custom resolver that captures a token can additionally
//! abort its own lookup early.

use std::net::{SocketAddr, ToSocketAddrs};

use crate::error::{Error, Result};

/// Resolves a host name to one or more socket addresses. Implementors must be
/// `Send + Sync` (a request may run on any thread) and `Debug` (so a
/// [`crate::Request`] holding one stays `Debug`).
pub trait Resolver: Send + Sync + std::fmt::Debug {
    /// Resolve `host:port` to candidate addresses, in connection-attempt order.
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>>;
}

/// The default resolver: the standard library's blocking system resolver.
#[derive(Debug, Default, Clone)]
pub struct StdResolver;

impl Resolver for StdResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        // IP literals need no lookup. This also accepts the URL form of an IPv6
        // literal (`[::1]`, `[fe80::1%251]`), which `to_socket_addrs` rejects.
        if let Some(addr) = crate::url::ip_literal_addr(host, port) {
            return Ok(vec![addr]);
        }
        let host = crate::url::unbracket(host);
        let addrs: Vec<SocketAddr> = (host, port).to_socket_addrs().map_err(Error::Io)?.collect();
        if addrs.is_empty() {
            return Err(Error::InvalidUrl(host.to_string()));
        }
        Ok(addrs)
    }
}

/// Dial `addrs` in order, returning the first successful connection. Each
/// attempt gets the full `timeout` (curl splits it; a per-attempt bound keeps
/// a dead first address from starving the rest). The last error is returned if
/// every address fails, so a dual-stack host with an unreachable AAAA record
/// still connects over IPv4.
pub(crate) fn connect_any(
    addrs: &[SocketAddr],
    timeout: Option<std::time::Duration>,
) -> std::io::Result<std::net::TcpStream> {
    let mut last_err = None;
    for addr in addrs {
        let attempt = match timeout {
            Some(t) => std::net::TcpStream::connect_timeout(addr, t),
            None => std::net::TcpStream::connect(addr),
        };
        match attempt {
            Ok(s) => return Ok(s),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "no addresses to connect to")
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn std_resolver_resolves_localhost() {
        let addrs = StdResolver.resolve("127.0.0.1", 80).unwrap();
        assert_eq!(addrs[0], "127.0.0.1:80".parse().unwrap());
    }

    #[derive(Debug)]
    struct Fixed(SocketAddr);
    impl Resolver for Fixed {
        fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<SocketAddr>> {
            Ok(vec![self.0])
        }
    }

    #[test]
    fn std_resolver_accepts_bracketed_ipv6_literal() {
        let addrs = StdResolver.resolve("[::1]", 8080).unwrap();
        assert_eq!(addrs, vec!["[::1]:8080".parse().unwrap()]);
        let addrs = StdResolver.resolve("::1", 80).unwrap();
        assert_eq!(addrs, vec!["[::1]:80".parse().unwrap()]);
        // Numeric zone ID → scope id.
        let addrs = StdResolver.resolve("[fe80::1%253]", 80).unwrap();
        match addrs[0] {
            SocketAddr::V6(v6) => assert_eq!(v6.scope_id(), 3),
            other => panic!("expected v6, got {other}"),
        }
    }

    #[test]
    fn connect_any_falls_back_to_later_address() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let good = listener.local_addr().unwrap();
        // A closed port on loopback refuses immediately.
        let dead = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        let s = connect_any(&[dead, good], Some(std::time::Duration::from_secs(2))).unwrap();
        assert_eq!(s.peer_addr().unwrap(), good);
        assert!(connect_any(&[dead], Some(std::time::Duration::from_secs(2))).is_err());
        assert!(connect_any(&[], None).is_err());
    }

    #[test]
    fn custom_resolver_is_consulted() {
        let r = Fixed("10.1.2.3:443".parse().unwrap());
        assert_eq!(r.resolve("ignored.example", 443).unwrap()[0].port(), 443);
    }
}

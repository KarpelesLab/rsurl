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
        let addrs: Vec<SocketAddr> = (host, port).to_socket_addrs().map_err(Error::Io)?.collect();
        if addrs.is_empty() {
            return Err(Error::InvalidUrl(host.to_string()));
        }
        Ok(addrs)
    }
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
    fn custom_resolver_is_consulted() {
        let r = Fixed("10.1.2.3:443".parse().unwrap());
        assert_eq!(r.resolve("ignored.example", 443).unwrap()[0].port(), 443);
    }
}

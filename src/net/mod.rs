//! Pluggable network transport.
//!
//! This module lets callers override how `rsurl` reaches the network. The
//! central abstraction is the [`Connector`] trait: given a logical
//! `host:port`, it returns a connected, plaintext [`NetStream`] which the
//! protocol backends then drive (wrapping it in TLS when the scheme requires
//! it). The default [`DirectConnector`] dials TCP directly; the built-in proxy
//! connectors route through HTTP CONNECT, HTTPS-to-proxy CONNECT, or
//! SOCKS4/4a/5/5h. Build one from a curl-style proxy URL with
//! [`connector_from_proxy_url`], or implement [`Connector`] yourself for a
//! fully custom transport.

mod client;
mod connector;
mod proxy_resolver;
mod resolver;
mod socks;
mod stream;
pub(crate) mod udp;

pub use client::Client;
pub(crate) use client::NetConfig;
#[cfg(unix)]
pub use connector::UnixConnector;
pub use connector::{
    connector_from_proxy_url, Connector, DirectConnector, HttpProxyConnector, HttpProxyIntent,
    HttpsProxyConnector, Socks4Connector, Socks5Connector,
};
pub use proxy_resolver::{from_env, EnvProxyResolver, ProxyChoice, ProxyResolver};
pub use resolver::{Resolver, StdResolver};
pub use stream::NetStream;
pub(crate) use stream::MaybeTlsStream;
pub use udp::UdpProxy;

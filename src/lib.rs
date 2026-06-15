//! rsurl — a pure-Rust implementation of curl.
//!
//! Top-level entry points:
//!   * HTTP/HTTPS — [`get`], [`request`], or [`Request`] / [`Response`] directly.
//!   * Any supported scheme — [`transfer`], which dispatches to the right
//!     protocol backend and returns the payload as raw bytes.

#![forbid(unsafe_op_in_unsafe_fn)]

mod cancel;
mod compress;
mod cookie;
mod digest;
mod error;
mod http;
mod idn;
pub mod multi;
pub mod pool;
pub mod resume;
mod sigv4;
mod smtp;
mod telnet;
mod transfer;
mod url;

pub mod net;
pub mod tls;

// Protocol backends — each one owns a single URL scheme family.
#[cfg(feature = "bittorrent")]
pub mod bittorrent;
pub mod dict;
pub mod file;
pub mod ftp;
pub mod gopher;
pub mod http2;
pub mod http3;
pub mod imap;
pub mod ldap;
pub mod mqtt;
pub mod pop3;
pub mod rtsp;
#[cfg(feature = "ssh")]
pub mod ssh;
pub mod tftp;
pub mod websocket;

pub mod ffi;

pub use crate::cancel::CancelToken;
pub use crate::cookie::{Cookie, CookieJar, SameSite};
pub use crate::error::{Error, Result};
pub use crate::http::{
    send_multiplexed, send_multiplexed_traced, HttpVersionPref, Priority, ProxyConfig, Request,
    Response, ResponseHead, Timing, TlsInfo,
};
pub use crate::multi::{EasyId, Multi};
pub use crate::net::Client;
pub use crate::transfer::{transfer, transfer_url};
pub use crate::url::Url;
pub use crate::websocket::{WebSocket, WsClose, WsEvent, WsFrame, WsMessage, WsOpcode};

/// Perform an HTTP GET against `url` and return the full response.
pub fn get<U: AsRef<str>>(url: U) -> Result<Response> {
    Request::get(url.as_ref())?.send()
}

/// Perform an arbitrary HTTP request. Convenience wrapper over [`Request`].
pub fn request<U: AsRef<str>>(method: &str, url: U) -> Result<Response> {
    Request::new(method, url.as_ref())?.send()
}

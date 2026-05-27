//! rsurl — a pure-Rust implementation of curl.
//!
//! Top-level entry points:
//!   * HTTP/HTTPS — [`get`], [`request`], or [`Request`] / [`Response`] directly.
//!   * Any supported scheme — [`transfer`], which dispatches to the right
//!     protocol backend and returns the payload as raw bytes.

#![forbid(unsafe_op_in_unsafe_fn)]

mod compress;
mod error;
mod http;
mod transfer;
mod url;

pub mod tls;

// Protocol backends — each one owns a single URL scheme family.
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
pub mod tftp;
pub mod websocket;

pub mod ffi;

pub use crate::error::{Error, Result};
pub use crate::http::{HttpVersionPref, Request, Response};
pub use crate::transfer::{transfer, transfer_url};
pub use crate::url::Url;

/// Perform an HTTP GET against `url` and return the full response.
pub fn get<U: AsRef<str>>(url: U) -> Result<Response> {
    Request::get(url.as_ref())?.send()
}

/// Perform an arbitrary HTTP request. Convenience wrapper over [`Request`].
pub fn request<U: AsRef<str>>(method: &str, url: U) -> Result<Response> {
    Request::new(method, url.as_ref())?.send()
}

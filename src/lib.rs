//! curlrs — a pure-Rust implementation of curl.
//!
//! See the crate-level README for an overview. The top-level entry points are
//! the free functions [`get`] and [`request`], plus the [`Request`] / [`Response`]
//! types for finer control.

#![forbid(unsafe_op_in_unsafe_fn)]

mod error;
mod http;
mod url;

pub use crate::error::{Error, Result};
pub use crate::http::{Request, Response};
pub use crate::url::Url;

/// Perform an HTTP GET against `url` and return the full response.
pub fn get<U: AsRef<str>>(url: U) -> Result<Response> {
    Request::get(url.as_ref())?.send()
}

/// Perform an arbitrary HTTP request. Convenience wrapper over [`Request`].
pub fn request<U: AsRef<str>>(method: &str, url: U) -> Result<Response> {
    Request::new(method, url.as_ref())?.send()
}

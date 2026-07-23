//! rsurl — a pure-Rust implementation of curl.
//!
//! Top-level entry points:
//!   * HTTP/HTTPS — [`get`], [`request`], or [`Request`] / [`Response`] directly.
//!   * Any supported scheme — [`transfer`], which dispatches to the right
//!     protocol backend and returns the payload as raw bytes.
//!
//! # wasm32 (browser) builds
//!
//! On `wasm32-unknown-unknown` there are no sockets, no threads, and no blocking
//! — the browser owns DNS, TLS, and the HTTP/WebSocket wire. rsurl's own
//! `net`/`proto`/`tls` stack, every socket-bound protocol backend (FTP, SSH,
//! HTTP/2, HTTP/3, BitTorrent, mail, …), and the entire *blocking* API therefore
//! do not exist on that target — they are `#[cfg(not(target_arch = "wasm32"))]`.
//!
//! What remains is the **unified async API** in [`aio`], which compiles on both
//! targets: on native it drives the sans-IO core over real sockets; on wasm it
//! routes HTTP through the Fetch API and WebSockets through the browser's native
//! `WebSocket`. The same [`aio::request`] / [`aio::WebSocket`] calls work in
//! both places — see the [`aio`] module docs for the browser-imposed limits
//! (forbidden headers, CORS, no custom WebSocket handshake headers, …).

#![forbid(unsafe_op_in_unsafe_fn)]

pub mod aio;
mod cancel;
mod error;
mod url;

// Shared, socket-free helper: IDN/UTS-46 host normalisation is pure computation
// (no I/O), so it builds for wasm unchanged. The module compiles on every target
// and feature set — it no-ops internally when the `idn` feature is off — so it
// stays unconditional here (native backends reference `crate::idn` directly).
mod idn;

// ─── Native-only surface ────────────────────────────────────────────────────
// Everything below opens sockets, spawns threads, or exposes the blocking API,
// none of which exists on `wasm32-unknown-unknown`. Gated out wholesale there so
// the crate compiles down to just the `aio` fetch/WebSocket path.
#[cfg(not(target_arch = "wasm32"))]
mod compress;
#[cfg(not(target_arch = "wasm32"))]
mod cookie;
#[cfg(not(target_arch = "wasm32"))]
mod digest;
#[cfg(not(target_arch = "wasm32"))]
pub mod download;
#[cfg(not(target_arch = "wasm32"))]
mod http;
#[cfg(not(target_arch = "wasm32"))]
mod io;
#[cfg(not(target_arch = "wasm32"))]
pub mod multi;
#[cfg(not(target_arch = "wasm32"))]
pub mod pool;
#[cfg(not(target_arch = "wasm32"))]
mod proto;
#[cfg(not(target_arch = "wasm32"))]
pub mod resume;
#[cfg(not(target_arch = "wasm32"))]
mod sigv4;
#[cfg(not(target_arch = "wasm32"))]
mod smtp;
#[cfg(not(target_arch = "wasm32"))]
mod telnet;
#[cfg(not(target_arch = "wasm32"))]
mod transfer;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod test_support;

#[cfg(not(target_arch = "wasm32"))]
pub mod net;
#[cfg(not(target_arch = "wasm32"))]
pub mod tls;

// Protocol backends — each one owns a single URL scheme family. All socket-bound.
#[cfg(all(feature = "bittorrent", not(target_arch = "wasm32")))]
pub mod bittorrent;
#[cfg(not(target_arch = "wasm32"))]
pub mod dict;
#[cfg(not(target_arch = "wasm32"))]
pub mod file;
#[cfg(not(target_arch = "wasm32"))]
pub mod ftp;
#[cfg(not(target_arch = "wasm32"))]
pub mod gopher;
#[cfg(not(target_arch = "wasm32"))]
pub mod http2;
#[cfg(not(target_arch = "wasm32"))]
pub mod http3;
#[cfg(not(target_arch = "wasm32"))]
pub mod imap;
#[cfg(not(target_arch = "wasm32"))]
pub mod ldap;
#[cfg(not(target_arch = "wasm32"))]
pub mod mqtt;
#[cfg(not(target_arch = "wasm32"))]
pub mod pop3;
#[cfg(not(target_arch = "wasm32"))]
pub mod rtsp;
#[cfg(all(feature = "ssh", not(target_arch = "wasm32")))]
pub mod ssh;
#[cfg(not(target_arch = "wasm32"))]
pub mod tftp;
#[cfg(not(target_arch = "wasm32"))]
pub mod websocket;

// C ABI — only compiled with the `ffi` feature, so pure-Rust consumers don't
// carry the `#[no_mangle] extern "C"` symbols. Build with `--features ffi` to
// produce a C-linkable library (see the feature doc in Cargo.toml). Never on wasm.
#[cfg(all(feature = "ffi", not(target_arch = "wasm32")))]
pub mod ffi;

// ─── Public re-exports ──────────────────────────────────────────────────────
pub use crate::cancel::CancelToken;
pub use crate::error::{Error, Result};
pub use crate::url::Url;

#[cfg(not(target_arch = "wasm32"))]
pub use crate::cookie::{Cookie, CookieJar, SameSite};
#[cfg(not(target_arch = "wasm32"))]
pub use crate::download::{download, fetch_to_file, DownloadOptions, DownloadOutcome};
#[cfg(not(target_arch = "wasm32"))]
pub use crate::http::{
    send_multiplexed, send_multiplexed_traced, BodyReader, HttpVersionPref, Priority, ProxyConfig,
    Request, Response, ResponseHead, Timing, TlsInfo,
};
#[cfg(not(target_arch = "wasm32"))]
pub use crate::multi::{EasyId, Multi};
#[cfg(not(target_arch = "wasm32"))]
pub use crate::net::Client;
#[cfg(not(target_arch = "wasm32"))]
pub use crate::transfer::{transfer, transfer_url};
#[cfg(not(target_arch = "wasm32"))]
pub use crate::websocket::{
    WebSocket, WsClose, WsEvent, WsFrame, WsMessage, WsOpcode, WsReader, WsShutdown, WsWriter,
};

/// Perform an HTTP GET against `url` and return the full response.
///
/// Native-only: the browser cannot block, so on wasm use the async
/// [`aio::get`] instead.
#[cfg(not(target_arch = "wasm32"))]
pub fn get<U: AsRef<str>>(url: U) -> Result<Response> {
    Request::get(url.as_ref())?.send()
}

/// Perform an arbitrary HTTP request. Convenience wrapper over [`Request`].
///
/// Native-only: on wasm use the async [`aio::request`] instead.
#[cfg(not(target_arch = "wasm32"))]
pub fn request<U: AsRef<str>>(method: &str, url: U) -> Result<Response> {
    Request::new(method, url.as_ref())?.send()
}

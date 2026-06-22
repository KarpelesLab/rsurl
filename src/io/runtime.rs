//! The runtime-agnostic async substrate for the async driver.
//!
//! Following the quinn model, the crate's async path is **not** bound to any one
//! runtime. It is expressed against two small traits the application supplies an
//! implementation of (or uses the optional [`tokio`](super::tokio) adapter):
//!
//!   * [`AsyncConn`] — a full-duplex async byte connection.
//!   * [`Runtime`] — TCP connect, timers, and the clock.
//!
//! Both use return-position `impl Future` in traits (stable since Rust 1.75;
//! the crate MSRV is 1.88), so the [`asyncio`](super::asyncio) driver stays
//! generic and we never hand-write a `Future`/`Poll` state machine. The traits
//! are deliberately tiny — no `futures-util`, no `tokio` types — so the core
//! build pulls in no async-ecosystem dependency; an adapter for `futures-io`
//! traits can be added later behind a feature.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// A full-duplex async byte stream handed back by a [`Runtime`]. The byte-level
/// analogue of [`std::io::Read`] + [`std::io::Write`]; the driver reads inbound
/// wire bytes and writes a machine's transmits over it.
pub trait AsyncConn: Send {
    /// Read up to `buf.len()` bytes into `buf`. `Ok(0)` signals end-of-input.
    fn read(&mut self, buf: &mut [u8]) -> impl Future<Output = io::Result<usize>> + Send;

    /// Write the entire buffer, retrying short writes.
    fn write_all(&mut self, buf: &[u8]) -> impl Future<Output = io::Result<()>> + Send;

    /// Flush any buffered outbound bytes to the peer.
    fn flush(&mut self) -> impl Future<Output = io::Result<()>> + Send;
}

/// A runtime-agnostic async environment: everything a driver needs from "the
/// outside" beyond the protocol logic. An application implements this for its
/// runtime of choice (or enables the built-in `tokio-rt` adapter); the crate's
/// async code never names a concrete runtime, so it does not fragment the
/// ecosystem into per-runtime crates.
pub trait Runtime {
    /// The connection type this runtime produces.
    type Conn: AsyncConn;

    /// Open a TCP connection to `addr`.
    fn connect(&self, addr: SocketAddr) -> impl Future<Output = io::Result<Self::Conn>> + Send;

    /// Complete after at least `dur` has elapsed (the timer primitive a driver
    /// races a read against to honour a protocol state-machine deadline).
    fn sleep(&self, dur: Duration) -> impl Future<Output = ()> + Send;

    /// The current instant, per this runtime's clock.
    fn now(&self) -> Instant;
}

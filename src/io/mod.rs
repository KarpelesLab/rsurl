//! The sans-IO core: protocol state machines decoupled from I/O, plus the
//! drivers that pump them.
//!
//! Each protocol is (being) refactored into a pure [`Machine`] that performs no
//! I/O. A *driver* owns the transport and pumps a machine to completion:
//!
//!   * [`blocking`] — drives a machine over a `std::net` blocking socket; this
//!     is what the synchronous API, the C ABI, and the CLI use.
//!   * [`asyncio`] — drives a machine over an async connection supplied by a
//!     runtime-agnostic [`Runtime`], for idiomatic `async`/`await` use.
//!
//! See [`machine`] for the contract and the rationale (the sans-IO pattern as
//! used by rustls, quinn, and str0m).
//!
//! As of the cutover, the blocking driver is on the live request path:
//! [`crate::Request::send`] routes HTTP/1.1 (plaintext and direct HTTPS) through
//! [`blocking`], and the async `aio` frontend drives the same machines through
//! [`asyncio`].

pub(crate) mod asyncio;
// The async TLS duplex stream (persistent `wss://` transport) needs a TLS
// backend to name its engine; without one there is nothing to wrap.
#[cfg(any(feature = "rustls-tls", feature = "purecrypto-tls"))]
pub(crate) mod asynctls;
pub(crate) mod blocking;
pub(crate) mod machine;
pub(crate) mod runtime;
#[cfg(feature = "tokio-rt")]
pub(crate) mod tokio;

pub(crate) use machine::Machine;

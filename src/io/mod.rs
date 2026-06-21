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
//! NOTE: this module is built in parallel to the legacy blocking engine and is
//! not yet on the public path, so parts are currently only exercised by tests.
//! The `allow(dead_code)` is removed at the cutover phase, when `Request::send`
//! routes through the driver.
#![allow(dead_code)]

pub(crate) mod asyncio;
pub(crate) mod blocking;
pub(crate) mod machine;
pub(crate) mod runtime;
#[cfg(feature = "tokio-rt")]
pub(crate) mod tokio;

pub(crate) use machine::Machine;

//! Sans-IO protocol cores: pure state machines ([`crate::io::Machine`]) that
//! encode/decode a protocol with no I/O. Drivers in [`crate::io`] pump them.
//!
//! Phase 1 lands HTTP/1.1 ([`http1`]); the other protocol families follow in
//! later phases (see the project plan).
//!
//! NOTE: built in parallel to the legacy engine and not yet on the public path,
//! so parts are currently only used by tests. The `allow(dead_code)` is removed
//! at the cutover phase.
#![allow(dead_code)]

pub(crate) mod http1;

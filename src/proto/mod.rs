//! Sans-IO protocol cores: pure state machines ([`crate::io::Machine`]) that
//! encode/decode a protocol with no I/O. Drivers in [`crate::io`] pump them.
//!
//! [`http1`] (the HTTP/1.1 exchange) and [`tls`] (the layered TLS client) are on
//! the live request path: [`crate::Request::send`] routes plaintext and direct
//! HTTPS HTTP/1.1 through them, and the async `aio` frontend shares the same
//! cores.

pub(crate) mod http1;
pub(crate) mod tls;

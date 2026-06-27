//! Process-wide idle-connection pool for the sans-IO HTTP/1.1 core path.
//!
//! HTTP/2 has its own pool (see `src/http2.rs`) keyed on (scheme, host, port)
//! and storing `Arc<Mutex<Connection<TlsStream<TcpStream>>>>`. HTTP/2 needs
//! shared connections because it multiplexes requests on a single stream-id
//! space; the value is an `Arc<Mutex<…>>` and many callers can hold one. It only
//! shares this module's runtime caps ([`configure`]/`per_key_cap`/`global_cap`).
//!
//! HTTP/1.1 doesn't need sharing: a connection carries one request at a time.
//! What it *does* need is parking — after a response is fully read, the warm
//! TCP/TLS state is parked here, and the next matching request reuses the socket
//! instead of doing a fresh TCP+TLS handshake. This is what curl calls
//! "connection cache" and is the single biggest steady-state win.
//!
//! The pool is `CorePool`, driven by the sans-IO request path (`proto::http1`
//! over `io::blocking`). Design points:
//!
//! * Keyed on `(scheme, host, port)` plus a dial-target/partition discriminator
//!   (`Key`) — exact-match, no virtual-host trickery.
//! * Connections are stored **bare** (no `BufReader`): the sans-IO exchange
//!   buffers received bytes internally and the driver reads exactly the framed
//!   response, so there are never prefetched bytes to carry. Plain entries park
//!   the raw `TcpStream`; TLS entries park the socket plus the live sans-IO
//!   engine, so the next request resumes the negotiated session.
//! * **LIFO checkout** — most-recently-used first (most likely still alive).
//! * **Two caps**: per-key and global, defaulting to 4 and 32 and tunable at
//!   runtime via [`configure`] (shared with the `http2.rs` pool). Returns past
//!   the cap drop the connection on the floor.
//! * **No idle timeout**. Stale connections are detected at checkout time by the
//!   caller — it retries on a fresh socket once if the pooled one was killed.

use std::collections::HashMap;
use std::net::TcpStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

/// Default per-authority cap.
const DEFAULT_PER_KEY_CAP: usize = 4;
/// Default total live pooled conns across all keys.
const DEFAULT_GLOBAL_CAP: usize = 32;

/// Runtime-tunable caps, shared by the HTTP/1.1 pool here and the HTTP/2 pool in
/// `http2.rs`. Adjust with [`configure`].
static PER_KEY_CAP: AtomicUsize = AtomicUsize::new(DEFAULT_PER_KEY_CAP);
static GLOBAL_CAP: AtomicUsize = AtomicUsize::new(DEFAULT_GLOBAL_CAP);

/// Set the connection-pool size limits at runtime (applies to both the HTTP/1.1
/// and HTTP/2 pools): at most `per_key` idle connections per origin and `total`
/// idle connections overall. Each is clamped to a minimum of 1. Takes effect on
/// subsequent connection releases; already-pooled connections are unaffected.
pub fn configure(per_key: usize, total: usize) {
    PER_KEY_CAP.store(per_key.max(1), Ordering::Relaxed);
    GLOBAL_CAP.store(total.max(1), Ordering::Relaxed);
}

/// Current per-authority cap.
pub(crate) fn per_key_cap() -> usize {
    PER_KEY_CAP.load(Ordering::Relaxed)
}

/// Current global cap.
pub(crate) fn global_cap() -> usize {
    GLOBAL_CAP.load(Ordering::Relaxed)
}

/// Serializes tests that read or mutate the process-global pool caps (here and
/// in `http2.rs`), so a concurrent [`configure`] can't perturb their counts.
#[cfg(test)]
pub(crate) static CAP_TEST_LOCK: Mutex<()> = Mutex::new(());

/// Identity of a connection's destination authority.
///
/// `scheme`/`host`/`port` are the request URL's authority (and stay the
/// Host/SNI). `effective_target` is the dial-target discriminator: the
/// post-`--connect-to`/`--resolve` endpoint a request would physically dial.
/// It is `None` in the overwhelmingly common case (no overrides), so default
/// requests pool together exactly as before. When `--connect-to` remaps the
/// host:port, or `--resolve` pins an IP for this (host,port), the discriminator
/// is `Some(..)` — so a pooled socket is only reused by a request that would
/// dial the *same* backend. Without this, two requests sharing a URL authority
/// but with different `--connect-to`/`--resolve` settings could reuse a socket
/// physically connected to a different backend (connection confusion). See
/// `pool_key_for` in `src/http.rs` for how the discriminator is computed.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) struct Key {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    /// Effective dial target after `--connect-to`/`--resolve`. `None` when no
    /// override applies to this (host,port).
    pub effective_target: Option<(String, u16)>,
    /// Caller-supplied connection-pool partition key (e.g. the top-level site),
    /// from [`crate::Request::partition`]. `None` for unpartitioned requests, so
    /// default pooling is unchanged. Two requests with different partition keys
    /// never share a pooled socket or TLS session.
    pub partition: Option<String>,
}

/// Idle-connection pool for the **sans-IO core** request path
/// ([`crate::proto::http1`] driven over a [`NetStream`](crate::net::NetStream)).
///
/// Unlike [`Pool`], it stores the connection bare — no `BufReader`. The sans-IO
/// exchange buffers received bytes internally, and the driver reads exactly the
/// framed response and stops, so there are never prefetched bytes to carry
/// alongside the socket. Plain connections park the raw `TcpStream`; TLS
/// connections park the socket together with the live sans-IO TLS engine, so the
/// next request resumes the negotiated session instead of re-handshaking.
///
/// Keying (`Key`) and the per-key/global caps are shared with [`Pool`] via
/// [`configure`], so the two pools obey one configured budget shape.
pub(crate) struct CorePool<C> {
    entries: HashMap<Key, Vec<C>>,
}

impl<C> CorePool<C> {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Pop one parked conn for `key`, LIFO (most-recently-used first).
    pub(crate) fn checkout(&mut self, key: &Key) -> Option<C> {
        let bucket = self.entries.get_mut(key)?;
        let c = bucket.pop();
        if bucket.is_empty() {
            self.entries.remove(key);
        }
        c
    }

    /// Park `conn` for reuse under `key`, enforcing both caps (overflow drops it).
    pub(crate) fn release(&mut self, key: Key, conn: C) {
        let total: usize = self.entries.values().map(Vec::len).sum();
        if total >= global_cap() {
            return;
        }
        let bucket = self.entries.entry(key).or_default();
        if bucket.len() >= per_key_cap() {
            return;
        }
        bucket.push(conn);
    }

    #[cfg(test)]
    fn total_len(&self) -> usize {
        self.entries.values().map(Vec::len).sum()
    }
}

/// Plain-HTTP idle conns for the sans-IO core path.
static POOL_CORE_PLAIN: OnceLock<Mutex<CorePool<TcpStream>>> = OnceLock::new();

pub(crate) fn core_plain() -> &'static Mutex<CorePool<TcpStream>> {
    POOL_CORE_PLAIN.get_or_init(|| Mutex::new(CorePool::new()))
}

/// The active backend's concrete sans-IO TLS engine type (exactly one backend
/// compiles in). Parked alongside its socket for session reuse.
#[cfg(feature = "rustls-tls")]
pub(crate) type CoreTlsEngine = crate::proto::tls::RustlsEngine;
#[cfg(all(feature = "purecrypto-tls", not(feature = "rustls-tls")))]
pub(crate) type CoreTlsEngine = crate::proto::tls::PurecryptoEngine;

/// A warm TLS session parked in the core pool: the socket plus its live engine.
#[cfg(any(feature = "rustls-tls", feature = "purecrypto-tls"))]
pub(crate) type CoreTlsConn = (TcpStream, CoreTlsEngine);

#[cfg(any(feature = "rustls-tls", feature = "purecrypto-tls"))]
static POOL_CORE_TLS: OnceLock<Mutex<CorePool<CoreTlsConn>>> = OnceLock::new();

#[cfg(any(feature = "rustls-tls", feature = "purecrypto-tls"))]
pub(crate) fn core_tls() -> &'static Mutex<CorePool<CoreTlsConn>> {
    POOL_CORE_TLS.get_or_init(|| Mutex::new(CorePool::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(host: &str, port: u16) -> Key {
        Key {
            scheme: "http".into(),
            host: host.into(),
            port,
            effective_target: None,
            partition: None,
        }
    }

    use super::CAP_TEST_LOCK as CAP_LOCK;

    #[test]
    fn global_cap_enforced_across_keys() {
        let _g = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        configure(DEFAULT_PER_KEY_CAP, DEFAULT_GLOBAL_CAP);
        let cap = global_cap();
        // Integers stand in for parked connections (CorePool stores them bare).
        let mut p: CorePool<u32> = CorePool::new();
        for i in 0..(cap as u32 + 5) {
            // Each key has at most per_key_cap entries — so spread releases
            // across many keys to actually exercise the global cap.
            p.release(k("h", i as u16), i);
        }
        assert_eq!(p.total_len(), cap);
    }

    #[test]
    fn core_pool_lifo_and_caps() {
        let _g = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        configure(DEFAULT_PER_KEY_CAP, DEFAULT_GLOBAL_CAP);
        // CorePool stores connections bare (here, plain integers as stand-ins).
        let mut p: CorePool<u32> = CorePool::new();
        p.release(k("h", 80), 1);
        p.release(k("h", 80), 2);
        // LIFO: most-recently-released comes out first.
        assert_eq!(p.checkout(&k("h", 80)), Some(2));
        assert_eq!(p.checkout(&k("h", 80)), Some(1));
        assert_eq!(p.checkout(&k("h", 80)), None);
        assert_eq!(p.total_len(), 0);

        // Per-key cap is enforced; overflow is dropped.
        let cap = per_key_cap();
        for i in 0..(cap as u32 + 3) {
            p.release(k("h", 80), i);
        }
        assert_eq!(p.total_len(), cap);
    }

    #[test]
    fn configure_sets_and_clamps_caps() {
        let _g = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        configure(2, 5);
        assert_eq!(per_key_cap(), 2);
        assert_eq!(global_cap(), 5);
        // Clamped to a minimum of 1.
        configure(0, 0);
        assert_eq!(per_key_cap(), 1);
        assert_eq!(global_cap(), 1);
        // Restore defaults for any later-running test.
        configure(DEFAULT_PER_KEY_CAP, DEFAULT_GLOBAL_CAP);
    }
}

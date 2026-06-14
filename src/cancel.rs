//! Cooperative cancellation of an in-flight transfer.
//!
//! A [`CancelToken`] is a cheap, clonable handle shared between the thread
//! running a request and any other thread that may want to stop it — a
//! navigation cancel, a `fetch` `AbortController`, or a stop button. Attach one
//! with [`crate::Request::cancel_token`]; from elsewhere call
//! [`CancelToken::cancel`].
//!
//! Cancellation works two ways, together:
//!
//! * **Cooperative.** The request flow checks [`CancelToken::is_cancelled`] at
//!   safe points (before connecting, between redirect hops) and, once a transfer
//!   has been cancelled, its result is reported as [`crate::Error::Cancelled`].
//! * **Prompt.** When the transport is a TCP socket, the request registers a
//!   *shutdown hook* (a cloned socket handle); [`cancel`](CancelToken::cancel)
//!   invokes it to `shutdown` the connection, which unblocks a thread parked in
//!   a blocking read. This frees the connection right away rather than waiting
//!   for the read timeout.
//!
//! One token may be shared across several concurrent transfers (like a single
//! `AbortSignal` aborting multiple fetches): each registers its own hook and
//! removes it on completion via a [`CancelGuard`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// A clonable cancellation handle. Clones share one underlying state, so
/// cancelling any clone cancels them all.
#[derive(Clone, Default)]
pub struct CancelToken {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for CancelToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CancelToken")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

type Hook = Box<dyn Fn() + Send + Sync>;

#[derive(Default)]
struct Inner {
    cancelled: AtomicBool,
    /// Shutdown hooks, one per in-flight connection using this token. A `None`
    /// slot is a removed (completed) registration; slots are reused.
    hooks: Mutex<Vec<Option<Hook>>>,
}

impl CancelToken {
    /// A fresh, not-yet-cancelled token.
    pub fn new() -> Self {
        Self::default()
    }

    /// Cancel every transfer holding this token (or a clone). Idempotent.
    /// Invokes all registered shutdown hooks to tear down live connections.
    pub fn cancel(&self) {
        self.inner.cancelled.store(true, Ordering::SeqCst);
        if let Ok(hooks) = self.inner.hooks.lock() {
            for h in hooks.iter().flatten() {
                h();
            }
        }
    }

    /// Whether [`cancel`](Self::cancel) has been called.
    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::SeqCst)
    }

    /// Register a shutdown hook and return a guard that removes it on drop. If
    /// the token is already cancelled the hook fires immediately and an
    /// already-expired guard is returned.
    pub(crate) fn register(&self, hook: Hook) -> CancelGuard {
        if self.is_cancelled() {
            hook();
            return CancelGuard {
                token: self.clone(),
                idx: usize::MAX,
            };
        }
        let mut hooks = self.inner.hooks.lock().unwrap();
        // Reuse a vacated slot if one exists, else append.
        let idx = match hooks.iter().position(|h| h.is_none()) {
            Some(i) => {
                hooks[i] = Some(hook);
                i
            }
            None => {
                hooks.push(Some(hook));
                hooks.len() - 1
            }
        };
        drop(hooks);
        // Lost-the-race guard: cancelled between the check above and insertion.
        if self.is_cancelled() {
            if let Ok(hooks) = self.inner.hooks.lock() {
                if let Some(Some(h)) = hooks.get(idx) {
                    h();
                }
            }
        }
        CancelGuard {
            token: self.clone(),
            idx,
        }
    }
}

/// Removes a registered shutdown hook when dropped (i.e. when its transfer
/// finishes), so a long-lived token doesn't accumulate dead socket handles.
pub(crate) struct CancelGuard {
    token: CancelToken,
    idx: usize,
}

impl Drop for CancelGuard {
    fn drop(&mut self) {
        if self.idx == usize::MAX {
            return;
        }
        if let Ok(mut hooks) = self.token.inner.hooks.lock() {
            if let Some(slot) = hooks.get_mut(self.idx) {
                *slot = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_sets_flag_and_fires_hooks() {
        let t = CancelToken::new();
        assert!(!t.is_cancelled());
        let fired = Arc::new(AtomicBool::new(false));
        let f2 = fired.clone();
        let _g = t.register(Box::new(move || f2.store(true, Ordering::SeqCst)));
        t.cancel();
        assert!(t.is_cancelled());
        assert!(fired.load(Ordering::SeqCst));
    }

    #[test]
    fn register_after_cancel_fires_immediately() {
        let t = CancelToken::new();
        t.cancel();
        let fired = Arc::new(AtomicBool::new(false));
        let f2 = fired.clone();
        let _g = t.register(Box::new(move || f2.store(true, Ordering::SeqCst)));
        assert!(fired.load(Ordering::SeqCst));
    }

    #[test]
    fn dropped_guard_is_not_invoked() {
        let t = CancelToken::new();
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        {
            let c2 = count.clone();
            let _g = t.register(Box::new(move || {
                c2.fetch_add(1, Ordering::SeqCst);
            }));
            // guard dropped here
        }
        t.cancel();
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn slot_reuse_keeps_active_hooks() {
        let t = CancelToken::new();
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c1 = count.clone();
        let g1 = t.register(Box::new(move || {
            c1.fetch_add(1, Ordering::SeqCst);
        }));
        {
            let c2 = count.clone();
            let _g2 = t.register(Box::new(move || {
                c2.fetch_add(1, Ordering::SeqCst);
            }));
        } // g2 dropped, its slot vacated
        let c3 = count.clone();
        let _g3 = t.register(Box::new(move || {
            c3.fetch_add(1, Ordering::SeqCst);
        })); // reuses g2's slot
        drop(g1); // keep g1's effect out
        t.cancel();
        // g1 removed, g2 removed, g3 active => exactly one fire.
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
}

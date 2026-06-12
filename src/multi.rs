//! Concurrent multi-transfer driver — a thread-backed analogue of curl's
//! "multi" interface.
//!
//! rsurl's per-request API ([`Request::send`](crate::http::Request::send)) is
//! blocking, and [`send_multiplexed`](crate::send_multiplexed) only multiplexes
//! *same-origin* requests over one HTTP/2 connection. [`Multi`] fills the gap:
//! it runs an arbitrary set of independent [`Request`]s concurrently, each on
//! its own worker thread, and reports completions incrementally — the shape the
//! libcurl `curl_multi_*` interface expects, without pulling in an async
//! runtime.
//!
//! ```no_run
//! use rsurl::{Request, multi::Multi};
//! let mut m = Multi::new();
//! let a = m.add(Request::get("https://example.com/a")?);
//! let b = m.add(Request::get("https://example.com/b")?);
//! for (id, result) in m.wait_all() {
//!     match result {
//!         Ok(resp) => println!("{id:?} -> {}", resp.status),
//!         Err(e) => eprintln!("{id:?} failed: {e}"),
//!     }
//! }
//! # let _ = (a, b);
//! # Ok::<(), rsurl::Error>(())
//! ```
//!
//! Completions are delivered on the thread that calls [`Multi::poll`] /
//! [`Multi::next_completed`] / [`Multi::wait_all`], never on the worker threads
//! — so a caller (e.g. the C compatibility layer) can run user callbacks on its
//! own thread even though the I/O happened elsewhere.

use std::collections::VecDeque;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::error::Result;
use crate::http::{Request, Response};

/// Identifies a transfer added to a [`Multi`]. Returned by [`Multi::add`] and
/// echoed back with each completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EasyId(pub u64);

type Completion = (EasyId, Result<Response>);

/// A set of independent transfers run concurrently. See the [module
/// docs](self).
pub struct Multi {
    next_id: u64,
    /// Added but not yet started (waiting for [`perform`](Multi::perform)).
    pending: Vec<(EasyId, Request)>,
    tx: Sender<Completion>,
    rx: Receiver<Completion>,
    /// Worker threads for started-but-not-yet-collected transfers.
    workers: Vec<(EasyId, JoinHandle<()>)>,
    /// Transfers still executing (started, completion not yet drained).
    running: usize,
    /// Drained completions awaiting [`next_completed`](Multi::next_completed).
    ready: VecDeque<Completion>,
}

impl Default for Multi {
    fn default() -> Self {
        Self::new()
    }
}

impl Multi {
    /// Create an empty multi handle.
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        Multi {
            next_id: 0,
            pending: Vec::new(),
            tx,
            rx,
            workers: Vec::new(),
            running: 0,
            ready: VecDeque::new(),
        }
    }

    /// Queue a request. It does not start until the next [`perform`](Multi::perform)
    /// (or [`wait_all`](Multi::wait_all)). Returns its [`EasyId`].
    pub fn add(&mut self, req: Request) -> EasyId {
        let id = EasyId(self.next_id);
        self.next_id += 1;
        self.pending.push((id, req));
        id
    }

    /// Drop a transfer that has not started yet. Returns `true` if it was still
    /// pending (a started transfer cannot be cancelled and returns `false`).
    pub fn remove(&mut self, id: EasyId) -> bool {
        if let Some(pos) = self.pending.iter().position(|(i, _)| *i == id) {
            self.pending.remove(pos);
            true
        } else {
            false
        }
    }

    /// Start every pending transfer (one worker thread each) and collect any
    /// completions that have arrived. Returns the number still running.
    pub fn perform(&mut self) -> usize {
        for (id, req) in self.pending.drain(..) {
            let tx = self.tx.clone();
            let handle = std::thread::spawn(move || {
                // `send` consumes the request and blocks until done; the result
                // (Ok or Err) is posted exactly once.
                let _ = tx.send((id, req.send()));
            });
            self.workers.push((id, handle));
            self.running += 1;
        }
        self.drain_ready();
        self.running
    }

    /// Non-blocking: move any arrived completions out of the channel into the
    /// ready queue, joining their worker threads.
    fn drain_ready(&mut self) {
        while let Ok((id, result)) = self.rx.try_recv() {
            self.join_worker(id);
            self.running -= 1;
            self.ready.push_back((id, result));
        }
    }

    fn join_worker(&mut self, id: EasyId) {
        if let Some(pos) = self.workers.iter().position(|(i, _)| *i == id) {
            let (_, handle) = self.workers.remove(pos);
            let _ = handle.join();
        }
    }

    /// Block until at least one completion is available or `timeout` elapses
    /// (`None` blocks indefinitely). Returns `true` if a completion is ready to
    /// pop with [`next_completed`](Multi::next_completed), `false` on timeout or
    /// when nothing is running.
    pub fn poll(&mut self, timeout: Option<Duration>) -> bool {
        self.drain_ready();
        if !self.ready.is_empty() {
            return true;
        }
        if self.running == 0 {
            return false;
        }
        let got = match timeout {
            Some(t) => self.rx.recv_timeout(t).ok(),
            None => self.rx.recv().ok(),
        };
        if let Some((id, result)) = got {
            self.join_worker(id);
            self.running -= 1;
            self.ready.push_back((id, result));
            self.drain_ready();
            true
        } else {
            false
        }
    }

    /// Pop one finished transfer, if any is ready. Non-blocking.
    pub fn next_completed(&mut self) -> Option<Completion> {
        self.drain_ready();
        self.ready.pop_front()
    }

    /// Number of transfers currently executing (started, not yet collected).
    /// Does not count still-pending ([`add`](Multi::add)ed but not
    /// [`perform`](Multi::perform)ed) transfers.
    pub fn running(&self) -> usize {
        self.running
    }

    /// Whether any transfers are pending or running.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty() && self.running == 0 && self.ready.is_empty()
    }

    /// Start all pending transfers and block until every one finishes,
    /// returning their results. Order is completion order, not add order.
    pub fn wait_all(&mut self) -> Vec<Completion> {
        self.perform();
        let mut out = Vec::new();
        loop {
            while let Some(c) = self.next_completed() {
                out.push(c);
            }
            if self.running == 0 {
                break;
            }
            self.poll(None);
        }
        out
    }
}

impl Drop for Multi {
    fn drop(&mut self) {
        // Join any outstanding workers so threads don't outlive the handle.
        // Each worker finishes once its (timeout-bounded) transfer completes.
        for (_, handle) in self.workers.drain(..) {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_assigns_increasing_ids_and_counts_pending() {
        let mut m = Multi::new();
        let a = m.add(Request::get("http://127.0.0.1:1/a").unwrap());
        let b = m.add(Request::get("http://127.0.0.1:1/b").unwrap());
        assert_eq!(a, EasyId(0));
        assert_eq!(b, EasyId(1));
        // Nothing started yet.
        assert_eq!(m.running(), 0);
        assert!(!m.is_empty());
    }

    #[test]
    fn remove_drops_pending_transfer() {
        let mut m = Multi::new();
        let a = m.add(Request::get("http://127.0.0.1:1/a").unwrap());
        assert!(m.remove(a));
        // Removing again (or a started one) is false.
        assert!(!m.remove(a));
        assert!(m.is_empty());
    }

    #[test]
    fn poll_returns_false_when_nothing_running() {
        let mut m = Multi::new();
        assert!(!m.poll(Some(Duration::from_millis(10))));
        assert!(m.next_completed().is_none());
    }
}

//! Whole-transfer deadline (curl `-m`/`--max-time`) for the blocking
//! non-HTTP protocol backends.
//!
//! A per-read idle timeout alone cannot bound a transfer: a peer trickling one
//! byte per idle period keeps every read "live" forever. [`DeadlineStream`]
//! wraps the plaintext transport a protocol dials and, before every read and
//! write, programs the socket timeout to `min(idle timeout, time remaining)`,
//! failing with [`io::ErrorKind::TimedOut`] once the deadline has passed.
//! Because it wraps the socket *below* TLS, TLS handshakes and record reads
//! are bounded too.

use std::cell::Cell;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr};
use std::time::{Duration, Instant};

use super::stream::NetStream;

/// Marker payload of the [`io::Error`] returned once a deadline has passed, so
/// loops that treat an ordinary read timeout as an idle "tick" (MQTT keep-alive,
/// WebSocket polling, RTSP interleaved capture) can tell the two apart.
#[derive(Debug)]
struct DeadlineExceeded;

impl fmt::Display for DeadlineExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("operation timed out: maximum transfer time (--max-time) reached")
    }
}

impl std::error::Error for DeadlineExceeded {}

/// The error every deadline-bounded operation returns once the deadline has
/// passed: kind [`io::ErrorKind::TimedOut`] (the CLI maps it to exit 28).
pub(crate) fn deadline_exceeded() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, DeadlineExceeded)
}

/// True if `e` is the error produced by [`deadline_exceeded`] — a hard stop,
/// not a retryable idle timeout.
pub(crate) fn is_deadline_exceeded(e: &io::Error) -> bool {
    e.get_ref()
        .is_some_and(|inner| inner.is::<DeadlineExceeded>())
}

/// Time left before `deadline`, or the [`deadline_exceeded`] error if none.
fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(deadline_exceeded)
}

/// The effective timeout for one blocking operation: `min(idle, time left)`.
/// Without a deadline this is just `idle`; with one it is never `None` (so an
/// unbounded idle timeout still stops at the deadline). Errors with kind
/// `TimedOut` once the deadline has passed.
pub(crate) fn op_timeout(
    deadline: Option<Instant>,
    idle: Option<Duration>,
) -> io::Result<Option<Duration>> {
    let Some(deadline) = deadline else {
        return Ok(idle);
    };
    let left = remaining(deadline)?;
    Ok(Some(idle.map_or(left, |i| i.min(left))))
}

/// A [`NetStream`] bounded by an absolute deadline. The idle timeouts set on it
/// via [`NetStream::set_read_timeout`]/[`NetStream::set_write_timeout`] are
/// remembered and combined with the time left before each operation.
pub(crate) struct DeadlineStream {
    inner: Box<dyn NetStream>,
    deadline: Instant,
    read_idle: Cell<Option<Duration>>,
    write_idle: Cell<Option<Duration>>,
}

impl DeadlineStream {
    /// Wrap `inner` so every read/write stops at `deadline`; returns `inner`
    /// unchanged when there is no deadline.
    pub(crate) fn wrap(inner: Box<dyn NetStream>, deadline: Option<Instant>) -> Box<dyn NetStream> {
        match deadline {
            None => inner,
            Some(deadline) => Box::new(DeadlineStream {
                inner,
                deadline,
                read_idle: Cell::new(None),
                write_idle: Cell::new(None),
            }),
        }
    }

    /// The timeout to program for one operation, and whether it is the
    /// deadline (rather than the idle timeout) that bounds it.
    fn budget(&self, idle: Option<Duration>) -> io::Result<(Duration, bool)> {
        let left = remaining(self.deadline)?;
        Ok(match idle {
            Some(i) if i < left => (i, false),
            _ => (left, true),
        })
    }

    /// Turn a socket timeout that the deadline caused into [`deadline_exceeded`].
    fn map_err(&self, e: io::Error, by_deadline: bool) -> io::Error {
        let timed_out = matches!(
            e.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        );
        if timed_out && (by_deadline || Instant::now() >= self.deadline) {
            deadline_exceeded()
        } else {
            e
        }
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let (t, by_deadline) = self.budget(self.read_idle.get())?;
        self.inner.set_read_timeout(Some(t))?;
        self.inner
            .read(buf)
            .map_err(|e| self.map_err(e, by_deadline))
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let (t, by_deadline) = self.budget(self.write_idle.get())?;
        self.inner.set_write_timeout(Some(t))?;
        self.inner
            .write(buf)
            .map_err(|e| self.map_err(e, by_deadline))
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl NetStream for DeadlineStream {
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        // Validate against the real socket (e.g. a zero duration is rejected),
        // then remember it as the idle bound for later reads.
        self.inner.set_read_timeout(dur)?;
        self.read_idle.set(dur);
        Ok(())
    }
    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.inner.set_write_timeout(dur)?;
        self.write_idle.set(dur);
        Ok(())
    }
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.inner.shutdown(how)
    }
    fn try_clone_box(&self) -> io::Result<Box<dyn NetStream>> {
        Ok(Box::new(DeadlineStream {
            inner: self.inner.try_clone_box()?,
            deadline: self.deadline,
            read_idle: Cell::new(self.read_idle.get()),
            write_idle: Cell::new(self.write_idle.get()),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    /// A server that trickles one byte every 100 ms, forever (until the
    /// client goes away). Returns its port.
    fn trickle_server() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            for _ in 0..200 {
                if s.write_all(b"x").is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        port
    }

    #[test]
    fn trickling_peer_is_cut_off_at_the_deadline() {
        let port = trickle_server();
        let start = Instant::now();
        let tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mut s = DeadlineStream::wrap(Box::new(tcp), Some(start + Duration::from_millis(500)));
        // A generous idle timeout that every single read satisfies.
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut got = Vec::new();
        let err = s.read_to_end(&mut got).unwrap_err();
        let took = start.elapsed();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(is_deadline_exceeded(&err), "{err}");
        assert!(!got.is_empty(), "the trickle was being received");
        assert!(
            took >= Duration::from_millis(450) && took < Duration::from_millis(1500),
            "took {took:?}"
        );
        // Every later operation fails immediately.
        assert!(is_deadline_exceeded(&s.read(&mut [0u8; 1]).unwrap_err()));
        assert!(is_deadline_exceeded(&s.write(b"y").unwrap_err()));
    }

    #[test]
    fn deadline_bounds_a_blocking_read_with_no_idle_timeout() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let (_s, _) = l.accept().unwrap();
            std::thread::sleep(Duration::from_millis(1500));
        });
        let start = Instant::now();
        let tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mut s = DeadlineStream::wrap(Box::new(tcp), Some(start + Duration::from_millis(300)));
        s.set_read_timeout(None).unwrap();
        let err = s.read(&mut [0u8; 8]).unwrap_err();
        assert!(is_deadline_exceeded(&err), "{err}");
        assert!(start.elapsed() < Duration::from_millis(1200));
        drop(s);
        h.join().unwrap();
    }

    #[test]
    fn idle_timeout_shorter_than_deadline_is_an_ordinary_timeout() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let (_s, _) = l.accept().unwrap();
            std::thread::sleep(Duration::from_millis(600));
        });
        let tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let s = DeadlineStream::wrap(
            Box::new(tcp),
            Some(Instant::now() + Duration::from_secs(10)),
        );
        s.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        // Clones keep the deadline and the idle bound.
        let mut c = s.try_clone_box().unwrap();
        let err = c.read(&mut [0u8; 8]).unwrap_err();
        assert!(matches!(
            err.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));
        assert!(!is_deadline_exceeded(&err));
        h.join().unwrap();
    }

    #[test]
    fn op_timeout_is_min_of_idle_and_remaining() {
        assert_eq!(op_timeout(None, None).unwrap(), None);
        let idle = Some(Duration::from_secs(1));
        assert_eq!(op_timeout(None, idle).unwrap(), idle);
        let far = Instant::now() + Duration::from_secs(100);
        assert_eq!(op_timeout(Some(far), idle).unwrap(), idle);
        let t = op_timeout(Some(far), None).unwrap().unwrap();
        assert!(t > Duration::from_secs(90));
        let near = Instant::now() + Duration::from_millis(200);
        assert!(op_timeout(Some(near), idle).unwrap().unwrap() <= Duration::from_millis(200));
        let past = Instant::now() - Duration::from_millis(1);
        let err = op_timeout(Some(past), idle).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(is_deadline_exceeded(&err));
    }

    /// The deadline wraps the socket *below* TLS, so a TLS handshake against a
    /// server that never answers is bounded too (the default idle timeout is
    /// 60 s, so without the deadline this would hang for a minute).
    #[test]
    fn tls_handshake_is_bounded_by_the_deadline() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (_s, _) = l.accept().unwrap();
            std::thread::sleep(Duration::from_secs(3));
        });
        let start = Instant::now();
        let err = crate::Client::new()
            .max_time(Duration::from_millis(500))
            .transfer(&format!("gophers://127.0.0.1:{port}/"))
            .unwrap_err();
        match &err {
            crate::Error::Io(e) => assert!(is_deadline_exceeded(e), "{e}"),
            other => panic!("expected the deadline error, got {other:?}"),
        }
        assert!(start.elapsed() < Duration::from_millis(1500));
    }
}

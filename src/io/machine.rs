//! The sans-IO state-machine contract every protocol core implements.
//!
//! A [`Machine`] is a *pure* protocol: it never touches a socket, a clock, or an
//! async runtime. It consumes inbound wire bytes, produces outbound wire bytes,
//! surfaces application-level events, and asks to be woken at deadlines. A
//! *driver* ([`crate::io::blocking`] / [`crate::io::asyncio`]) owns the actual
//! I/O and pumps the machine. The same machine therefore runs unchanged under a
//! blocking std socket (the C ABI / CLI / [`Request::send`](crate::Request)) and
//! under any async runtime (via the runtime-agnostic [`Runtime`](super::Runtime)
//! trait) — this is the sans-IO pattern used by rustls, quinn, and str0m.
//!
//! The driver loop, in the abstract:
//!
//! 1. Drain [`poll_transmit`](Machine::poll_transmit) and write the bytes out.
//! 2. Drain [`poll_event`](Machine::poll_event) and hand events to the caller.
//! 3. If not [`is_finished`](Machine::is_finished), read more wire bytes and feed
//!    them to [`handle_input`](Machine::handle_input).
//! 4. When the wall clock reaches [`next_timeout`](Machine::next_timeout), call
//!    [`handle_timeout`](Machine::handle_timeout).
//!
//! Steps repeat until the machine is finished. Because the contract is just data
//! in / data out, a machine is tested deterministically with *simulated* I/O —
//! feed canned bytes, assert on transmits and events — with no sockets and no
//! sleeps (the quinn-proto testing style).

use std::time::Instant;

use crate::error::Result;

/// A pure, I/O-free protocol state machine. See the [module docs](self).
///
/// Implementors hold all protocol state internally and are driven entirely
/// through these methods; they must not perform I/O, block, or read the clock
/// (time is delivered via [`handle_timeout`](Machine::handle_timeout)).
pub trait Machine {
    /// Application-level outputs the machine produces — e.g. a parsed response
    /// head, a body chunk, or a completion marker. The driver relays these to
    /// the caller; the machine itself never blocks waiting to emit one.
    type Event;

    /// Feed inbound wire bytes and return how many were consumed.
    ///
    /// A machine may consume fewer bytes than offered (e.g. it has a partial
    /// frame and wants the rest contiguously); the driver keeps the unconsumed
    /// tail and re-offers it prepended to the next read. Returning `0` while
    /// `wire` is non-empty means "I need more bytes before I can make progress"
    /// and must not loop forever — the driver will read more and re-offer.
    fn handle_input(&mut self, wire: &[u8]) -> Result<usize>;

    /// Append any bytes the machine wants to send to `out`, returning `true` if
    /// it wrote anything. The driver calls this in a loop until it returns
    /// `false`, then flushes `out` to the transport in one shot.
    fn poll_transmit(&mut self, out: &mut Vec<u8>) -> bool;

    /// Signal that the transport reached end-of-input (a clean half/close): no
    /// more bytes will be delivered via [`handle_input`](Machine::handle_input).
    /// A machine still expecting bytes (an unfinished length- or chunk-framed
    /// body) should error; one framed *by* connection close (HTTP/1 EOF body)
    /// treats this as the body's end. Default: no-op.
    fn handle_eof(&mut self) -> Result<()> {
        Ok(())
    }

    /// Pop the next application-level [`Event`](Machine::Event), or `None` if the
    /// machine has none pending. The driver drains this fully each turn.
    fn poll_event(&mut self) -> Option<Self::Event>;

    /// Advance any time-based state as of `now`. Called by the driver when the
    /// clock reaches the instant last reported by
    /// [`next_timeout`](Machine::next_timeout). A machine with no timers leaves
    /// this empty.
    fn handle_timeout(&mut self, now: Instant) {
        let _ = now;
    }

    /// The next instant at which the driver should call
    /// [`handle_timeout`](Machine::handle_timeout), or `None` if the machine is
    /// not waiting on a timer. The driver uses this to bound its read wait.
    fn next_timeout(&self) -> Option<Instant> {
        None
    }

    /// Whether the machine has completed: nothing left to send, nothing left to
    /// receive, and no timer outstanding. Once `true`, the driver stops pumping
    /// after draining the final events.
    fn is_finished(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trivial machine: echoes whatever it receives back out, then finishes
    /// once it has seen `\n`. Exercises the full contract with simulated I/O.
    #[derive(Default)]
    struct EchoLine {
        outbox: Vec<u8>,
        events: Vec<usize>,
        done: bool,
    }

    impl Machine for EchoLine {
        type Event = usize; // number of bytes echoed for a completed line

        fn handle_input(&mut self, wire: &[u8]) -> Result<usize> {
            if let Some(pos) = wire.iter().position(|&b| b == b'\n') {
                let take = pos + 1;
                self.outbox.extend_from_slice(&wire[..take]);
                self.events.push(take);
                self.done = true;
                Ok(take)
            } else {
                self.outbox.extend_from_slice(wire);
                Ok(wire.len())
            }
        }

        fn poll_transmit(&mut self, out: &mut Vec<u8>) -> bool {
            if self.outbox.is_empty() {
                return false;
            }
            out.append(&mut self.outbox);
            true
        }

        fn poll_event(&mut self) -> Option<usize> {
            if self.events.is_empty() {
                None
            } else {
                Some(self.events.remove(0))
            }
        }

        fn is_finished(&self) -> bool {
            self.done
        }
    }

    #[test]
    fn echo_line_drives_to_completion() {
        let mut m = EchoLine::default();
        assert!(!m.is_finished());

        // Partial input: no newline yet — consumed, queued for transmit, not done.
        assert_eq!(m.handle_input(b"hel").unwrap(), 3);
        let mut out = Vec::new();
        assert!(m.poll_transmit(&mut out));
        assert_eq!(out, b"hel");
        assert!(m.poll_event().is_none());
        assert!(!m.is_finished());

        // Rest of the line arrives; the machine completes and emits one event.
        assert_eq!(m.handle_input(b"lo\nignored").unwrap(), 3);
        out.clear();
        assert!(m.poll_transmit(&mut out));
        assert_eq!(out, b"lo\n");
        assert!(!m.poll_transmit(&mut out)); // nothing more to send
        assert_eq!(m.poll_event(), Some(3));
        assert!(m.poll_event().is_none());
        assert!(m.is_finished());
        assert!(m.next_timeout().is_none());
    }
}

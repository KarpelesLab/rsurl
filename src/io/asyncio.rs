//! The async driver: pump a [`Machine`] to completion over an [`AsyncConn`].
//!
//! Byte-for-byte the same cycle as the [`blocking`](super::blocking) driver
//! (flush transmits → drain events → read input), but `.await`s the connection.
//! Because the loop is identical, a sans-IO core behaves the same under both
//! drivers — that equivalence is the whole point of the sans-IO split.
//!
//! Timer handling (racing the read against [`Runtime::sleep`](super::Runtime))
//! is deferred until a timer-using machine (HTTP/2 keepalive, HTTP/3) is ported;
//! the Phase-1 HTTP/1.1 core reports no timeouts. The hook is the machine's
//! [`next_timeout`](Machine::next_timeout), already honoured by the blocking
//! driver.

use crate::error::{Error, Result};
use crate::io::runtime::AsyncConn;
use crate::io::Machine;

/// Drive `machine` to completion over the async connection `conn`, returning the
/// application events it produced, in order. The async counterpart of the
/// blocking driver in [`super::blocking`].
pub(crate) async fn drive<M, C>(machine: &mut M, conn: &mut C) -> Result<Vec<M::Event>>
where
    M: Machine,
    C: AsyncConn,
{
    let mut events = Vec::new();
    let mut scratch = [0u8; 16 * 1024];
    let mut out = Vec::new();
    // Input the machine has not consumed yet; re-offered, with new bytes
    // appended, on the next read (the `handle_input` contract).
    let mut pending: Vec<u8> = Vec::new();
    let mut eof_seen = false;

    loop {
        // 1. Flush everything the machine wants to send, in one write.
        out.clear();
        while machine.poll_transmit(&mut out) {}
        if !out.is_empty() {
            conn.write_all(&out).await.map_err(Error::Io)?;
            conn.flush().await.map_err(Error::Io)?;
        }

        // 2. Hand the caller every event produced so far.
        while let Some(ev) = machine.poll_event() {
            events.push(ev);
        }

        // 3. Done?
        if machine.is_finished() {
            return Ok(events);
        }

        // A machine that already saw EOF but still isn't finished would spin on
        // repeated 0-byte reads; treat that as a premature close.
        if eof_seen {
            return Err(Error::UnexpectedEof);
        }

        // 4. Read more wire bytes.
        let n = conn.read(&mut scratch).await.map_err(Error::Io)?;
        if n == 0 {
            eof_seen = true;
            machine.handle_eof()?;
        } else {
            pending.extend_from_slice(&scratch[..n]);
            feed(machine, &mut pending)?;
        }
    }
}

/// Offer `pending` to `machine` until it stops consuming, keeping whatever it
/// leaves for the next read. A machine may take less than it is offered (a
/// partial frame it wants contiguously); returning 0 means "need more bytes".
pub(crate) fn feed<M: Machine>(machine: &mut M, pending: &mut Vec<u8>) -> Result<()> {
    while !pending.is_empty() {
        let used = machine.handle_input(pending)?.min(pending.len());
        if used == 0 {
            break;
        }
        pending.drain(..used);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A machine that only consumes whole 4-byte records, one per call, and
    /// finishes after `want` of them.
    struct Records {
        want: usize,
        got: Vec<Vec<u8>>,
    }

    impl Machine for Records {
        type Event = Vec<u8>;
        fn handle_input(&mut self, wire: &[u8]) -> Result<usize> {
            if wire.len() < 4 {
                return Ok(0);
            }
            self.got.push(wire[..4].to_vec());
            Ok(4)
        }
        fn poll_transmit(&mut self, _out: &mut Vec<u8>) -> bool {
            false
        }
        fn poll_event(&mut self) -> Option<Vec<u8>> {
            None
        }
        fn is_finished(&self) -> bool {
            self.got.len() >= self.want
        }
    }

    #[test]
    fn unconsumed_input_is_reoffered() {
        let mut m = Records {
            want: 3,
            got: Vec::new(),
        };
        let mut pending = b"aaaabb".to_vec();
        feed(&mut m, &mut pending).unwrap();
        assert_eq!(pending, b"bb", "partial record kept");
        pending.extend_from_slice(b"bbcccc");
        feed(&mut m, &mut pending).unwrap();
        assert!(pending.is_empty());
        assert_eq!(
            m.got,
            vec![b"aaaa".to_vec(), b"bbbb".to_vec(), b"cccc".to_vec()]
        );
    }
}

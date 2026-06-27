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
            machine.handle_input(&scratch[..n])?;
        }
    }
}

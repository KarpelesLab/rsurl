//! Shared helpers for the crate's in-process socket unit tests.

use std::io::Read;
use std::net::{Shutdown, TcpStream};
use std::time::Duration;

/// Close a server-side connection gracefully, avoiding the spurious TCP RST that
/// macOS/BSD and Windows send when a socket is dropped while data the peer wrote
/// still sits unread in the kernel receive buffer — which surfaces on the
/// client as `ECONNRESET`/`WSAECONNRESET (10054)` mid-read and flakily fails the
/// transfer. Mirrors the integration harness's close in `tests/common`:
/// half-close the write side (sends FIN so the client reliably reads our full
/// response), then briefly drain whatever the client wrote, then let the stream
/// drop to close the read side.
pub(crate) fn graceful_close(stream: &mut TcpStream) {
    let _ = stream.shutdown(Shutdown::Write);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let mut sink = [0u8; 256];
    loop {
        match stream.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(_) => continue,
        }
    }
}

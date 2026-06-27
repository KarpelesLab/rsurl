//! The blocking driver: pump a [`Machine`] to completion over a synchronous
//! byte stream. This is what the synchronous API, the C ABI, and the CLI use.
//!
//! The loop mirrors the abstract sans-IO cycle (flush transmits → drain events →
//! read input), and bounds each blocking read by the machine's next timer so a
//! protocol with deadlines (HTTP/2 keepalive, HTTP/3) gets `handle_timeout`
//! called on time. The stream is a [`NetStream`], which gives a real
//! `set_read_timeout` for that bound.

use std::io::ErrorKind;
use std::time::Instant;

use crate::error::{Error, Result};
use crate::io::Machine;
use crate::net::NetStream;

/// Drive `machine` to completion over the blocking stream `io`, returning the
/// application events it produced, in order.
///
/// Returns [`Error::UnexpectedEof`] if the transport closes while the machine
/// still expects bytes (its [`handle_eof`](Machine::handle_eof) rejects), and
/// propagates any transport or protocol error.
pub(crate) fn drive<M, S>(machine: &mut M, io: &mut S) -> Result<Vec<M::Event>>
where
    M: Machine,
    S: NetStream + ?Sized,
{
    let mut events = Vec::new();
    drive_streaming(machine, io, |ev| {
        events.push(ev);
        Ok(())
    })?;
    Ok(events)
}

/// Like [`drive`], but relay each event to `on_event` as it is produced instead
/// of collecting them into a `Vec` returned at completion. This is what a
/// streaming frontend uses: a machine in streaming mode emits its head and body
/// chunks incrementally, and `on_event` (e.g. writing a body chunk to a sink)
/// runs during the transfer rather than after it. An `on_event` error aborts the
/// drive and propagates.
pub(crate) fn drive_streaming<M, S, F>(machine: &mut M, io: &mut S, mut on_event: F) -> Result<()>
where
    M: Machine,
    S: NetStream + ?Sized,
    F: FnMut(M::Event) -> Result<()>,
{
    let mut scratch = [0u8; 16 * 1024];
    let mut out = Vec::new();
    let mut eof_seen = false;

    loop {
        // 1. Flush everything the machine wants to send, in one write.
        out.clear();
        while machine.poll_transmit(&mut out) {}
        if !out.is_empty() {
            io.write_all(&out).map_err(Error::Io)?;
            io.flush().map_err(Error::Io)?;
        }

        // 2. Relay every event produced so far to the caller.
        while let Some(ev) = machine.poll_event() {
            on_event(ev)?;
        }

        // 3. Done?
        if machine.is_finished() {
            return Ok(());
        }

        // A machine that already saw EOF but still isn't finished would spin on
        // repeated 0-byte reads; treat that as a premature close.
        if eof_seen {
            return Err(Error::UnexpectedEof);
        }

        // 4. Bound the read by the machine's next timer, if it has one.
        if let Some(deadline) = machine.next_timeout() {
            let now = Instant::now();
            if now >= deadline {
                machine.handle_timeout(now);
                continue;
            }
            io.set_read_timeout(Some(deadline - now))
                .map_err(Error::Io)?;
        }

        // 5. Read more wire bytes.
        match io.read(&mut scratch) {
            Ok(0) => {
                eof_seen = true;
                machine.handle_eof()?;
            }
            Ok(n) => {
                machine.handle_input(&scratch[..n])?;
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                // The read deadline (a machine timer) elapsed.
                machine.handle_timeout(Instant::now());
            }
            Err(e) => return Err(Error::Io(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    use crate::proto::http1::{ClientExchange, Event};

    /// A tiny in-process HTTP/1.1 server that returns `response` verbatim after
    /// reading the request head. Returns the bound port.
    fn serve_once(response: &'static [u8]) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let Ok((mut sock, _)) = listener.accept() else {
                return;
            };
            // Drain the request head (until CRLF CRLF) so the client's write
            // completes, then reply.
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            while sock.read(&mut byte).map(|n| n == 1).unwrap_or(false) {
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let _ = sock.write_all(response);
            // Drop closes the socket → EOF, which frames a Connection: close body.
        });
        port
    }

    #[test]
    fn blocking_get_content_length_over_real_socket() {
        let port = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
        let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();

        let req =
            ClientExchange::encode_request("GET", "/", &[("Host".into(), "127.0.0.1".into())], b"");
        let mut x = ClientExchange::new("GET", req);
        let events = super::drive(&mut x, &mut sock).unwrap();

        assert_eq!(events.len(), 1);
        let Event::Response { head, body } = &events[0] else {
            panic!("expected Response event");
        };
        assert_eq!(head.status, 200);
        assert_eq!(body, b"hello");
    }

    #[test]
    fn blocking_get_eof_framed_body_over_real_socket() {
        // No Content-Length, no chunked → body framed by the server's close.
        let port = serve_once(b"HTTP/1.1 200 OK\r\nServer: t\r\n\r\nstreamed payload");
        let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();

        let req = ClientExchange::encode_request("GET", "/", &[("Host".into(), "x".into())], b"");
        let mut x = ClientExchange::new("GET", req);
        let events = super::drive(&mut x, &mut sock).unwrap();

        let Event::Response { head, body } = &events[0] else {
            panic!("expected Response event");
        };
        assert_eq!(head.status, 200);
        assert_eq!(body, b"streamed payload");
    }

    #[test]
    fn drive_streaming_relays_head_body_end_in_order() {
        let port = serve_once(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
              5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
        );
        let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();

        let req = ClientExchange::encode_request("GET", "/", &[("Host".into(), "x".into())], b"");
        let mut x = ClientExchange::new_streaming("GET", req);

        let mut kinds = Vec::new();
        let mut body = Vec::new();
        super::drive_streaming(&mut x, &mut sock, |ev| {
            match ev {
                Event::Head(h) => {
                    assert_eq!(h.status, 200);
                    kinds.push("head");
                }
                Event::Body(b) => {
                    body.extend_from_slice(&b);
                    kinds.push("body");
                }
                Event::End => kinds.push("end"),
                Event::Response { .. } => panic!("streaming mode should not emit Response"),
            }
            Ok(())
        })
        .unwrap();

        assert_eq!(kinds.first().copied(), Some("head"));
        assert_eq!(kinds.last().copied(), Some("end"));
        assert!(kinds.iter().any(|k| *k == "body"));
        assert_eq!(body, b"hello world");
    }
}

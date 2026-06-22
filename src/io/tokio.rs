//! Optional [`Runtime`] adapter for the Tokio runtime, behind the `tokio-rt`
//! feature. This is the *only* place in the crate that names `tokio`; the
//! async driver and protocol cores stay runtime-agnostic. An application using
//! a different runtime implements [`Runtime`]/[`AsyncConn`] the same way.

use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::io::runtime::{AsyncConn, Runtime};

/// A [`Runtime`] backed by the ambient Tokio runtime (the caller drives it with
/// `#[tokio::main]` / `Runtime::block_on` / `tokio::spawn`).
#[derive(Clone, Copy, Debug, Default)]
pub struct TokioRuntime;

/// A Tokio [`TcpStream`] adapted to [`AsyncConn`].
pub struct TokioConn(TcpStream);

impl AsyncConn for TokioConn {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf).await
    }

    async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        AsyncWriteExt::write_all(&mut self.0, buf).await
    }

    async fn flush(&mut self) -> io::Result<()> {
        AsyncWriteExt::flush(&mut self.0).await
    }
}

impl Runtime for TokioRuntime {
    type Conn = TokioConn;

    async fn connect(&self, addr: SocketAddr) -> io::Result<TokioConn> {
        Ok(TokioConn(TcpStream::connect(addr).await?))
    }

    async fn sleep(&self, dur: Duration) {
        tokio::time::sleep(dur).await;
    }

    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    use futures_util::stream::{FuturesUnordered, StreamExt};

    use super::*;
    use crate::io::asyncio;
    use crate::proto::http1::{ClientExchange, Event};

    /// An in-process HTTP/1.1 server that answers every accepted connection with
    /// `Content-Length`-framed `body`. Runs until the process exits.
    fn serve(body: &'static [u8]) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut sock) = conn else { continue };
                let mut buf = Vec::new();
                let mut byte = [0u8; 1];
                while sock.read(&mut byte).map(|n| n == 1).unwrap_or(false) {
                    buf.push(byte[0]);
                    if buf.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                let _ = sock.write_all(resp.as_bytes());
                let _ = sock.write_all(body);
            }
        });
        port
    }

    /// Drive one GET over the tokio adapter and return the body.
    async fn get(rt: &TokioRuntime, port: u16) -> Vec<u8> {
        let addr: SocketAddr = ([127, 0, 0, 1], port).into();
        let mut conn = rt.connect(addr).await.unwrap();
        let req = ClientExchange::encode_request("GET", "/", &[("Host".into(), "x".into())], b"");
        let mut x = ClientExchange::new("GET", req);
        let mut events = asyncio::drive(&mut x, &mut conn).await.unwrap();
        let Event::Response { body, .. } = events.remove(0);
        body
    }

    #[tokio::test]
    async fn async_get_over_tokio() {
        let port = serve(b"hello-async");
        let rt = TokioRuntime;
        assert_eq!(get(&rt, port).await, b"hello-async");
    }

    /// The "multi handle dissolves into FuturesUnordered" story: fan out N
    /// concurrent GETs on one task and collect them as they complete.
    #[tokio::test]
    async fn concurrent_fanout_with_futures_unordered() {
        let port = serve(b"ok");
        let rt = TokioRuntime;
        let mut inflight = FuturesUnordered::new();
        for _ in 0..16 {
            inflight.push(get(&rt, port));
        }
        let mut n = 0;
        while let Some(body) = inflight.next().await {
            assert_eq!(body, b"ok");
            n += 1;
        }
        assert_eq!(n, 16);
    }
}

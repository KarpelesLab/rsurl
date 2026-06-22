//! Experimental **async** HTTP client over the sans-IO stack.
//!
//! This is the first public entry point onto the runtime-agnostic sans-IO
//! engine: a protocol state machine driven over an async connection
//! supplied by a [`Runtime`] you provide (or the built-in [`TokioRuntime`],
//! behind the `tokio-rt` feature). Unlike the blocking API, this composes with
//! `async`/`await` and idiomatic concurrency — fan many [`get`] futures out with
//! `FuturesUnordered` / `JoinSet` instead of a curl-style multi handle.
//!
//! ```no_run
//! # #[cfg(feature = "tokio-rt")]
//! # async fn ex() -> Result<(), rsurl::Error> {
//! let rt = rsurl::aio::TokioRuntime;
//! let resp = rsurl::aio::get(&rt, "https://example.com/").await?;
//! println!("{} {} bytes", resp.status, resp.body.len());
//! # Ok(()) }
//! ```
//!
//! Scope (first cut): HTTP/1.1 `GET` over `http`/`https`, buffered response.
//! DNS is resolved synchronously for now; redirects, pooling, streaming bodies,
//! and the full [`Request`](crate::Request) surface follow as the cutover
//! proceeds.

use std::net::{SocketAddr, ToSocketAddrs};

pub use crate::io::runtime::{AsyncConn, Runtime};
#[cfg(feature = "tokio-rt")]
pub use crate::io::tokio::TokioRuntime;

use crate::error::{Error, Result};
use crate::io::asyncio;
use crate::proto::http1::{ClientExchange, Event};
use crate::proto::tls::TlsClient;
use crate::url::Url;

/// A buffered HTTP response from [`get`].
#[derive(Debug, Clone)]
pub struct Response {
    /// HTTP status code (e.g. 200).
    pub status: u16,
    /// Reason phrase (may be empty on HTTP/2-style status lines).
    pub reason: String,
    /// Response headers, in received order.
    pub headers: Vec<(String, String)>,
    /// The response body (still content-encoded if the server compressed it;
    /// decompression is a later cutover step).
    pub body: Vec<u8>,
}

/// Perform an HTTP/1.1 `GET` of `url` over `rt`, returning the buffered
/// [`Response`]. `https` builds the active TLS backend's engine via
/// [`crate::tls`] and carries the exchange through the sans-IO TLS layer; `http`
/// drives the request directly. The connection is closed after the response
/// (`Connection: close`).
pub async fn get<R: Runtime>(rt: &R, url: &str) -> Result<Response> {
    let u = Url::parse(url)?;
    let addr = resolve(&u.host, u.port)?;
    let mut conn = rt.connect(addr).await.map_err(Error::Io)?;

    let target = if u.path.is_empty() {
        "/".to_string()
    } else {
        u.path.clone()
    };
    let headers = vec![
        ("Host".to_string(), host_header(&u)),
        ("User-Agent".to_string(), "rsurl".to_string()),
        ("Accept".to_string(), "*/*".to_string()),
        ("Connection".to_string(), "close".to_string()),
    ];
    let request = ClientExchange::encode_request("GET", &target, &headers, b"");

    let events: Vec<Event> = match u.scheme.as_str() {
        "http" => {
            let mut exchange = ClientExchange::new("GET", request);
            asyncio::drive(&mut exchange, &mut conn).await?
        }
        "https" => {
            let exchange = ClientExchange::new("GET", request);
            let mut opts = crate::tls::TlsOpts::verifying();
            let engine = crate::tls::build_client_engine(&u.host, &mut opts)?;
            let mut tls = TlsClient::new(engine, exchange);
            asyncio::drive(&mut tls, &mut conn).await?
        }
        other => return Err(Error::UnsupportedScheme(other.to_string())),
    };

    let Event::Response { head, body } = events.into_iter().next().ok_or(Error::UnexpectedEof)?;
    Ok(Response {
        status: head.status,
        reason: head.reason,
        headers: head.headers,
        body,
    })
}

/// Resolve `host:port` to a socket address (synchronous DNS for now).
fn resolve(host: &str, port: u16) -> Result<SocketAddr> {
    (host, port)
        .to_socket_addrs()
        .map_err(Error::Io)?
        .next()
        .ok_or_else(|| Error::BadResponse(format!("could not resolve {host}:{port}")))
}

/// The `Host` header value: bare host on the default port, `host:port` otherwise.
fn host_header(u: &Url) -> String {
    let default = match u.scheme.as_str() {
        "https" => 443,
        _ => 80,
    };
    if u.port == default {
        u.host.clone()
    } else {
        format!("{}:{}", u.host, u.port)
    }
}

#[cfg(all(test, feature = "tokio-rt"))]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    use super::*;

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
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes());
                let _ = sock.write_all(body);
            }
        });
        port
    }

    #[tokio::test]
    async fn async_get_http_over_real_socket() {
        let port = serve(b"hello aio");
        let rt = TokioRuntime;
        let resp = get(&rt, &format!("http://127.0.0.1:{port}/"))
            .await
            .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"hello aio");
    }

    #[tokio::test]
    async fn async_get_sends_host_header() {
        // The server echoes back whether it saw the expected Host header.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = Vec::new();
                let mut byte = [0u8; 1];
                while sock.read(&mut byte).map(|n| n == 1).unwrap_or(false) {
                    buf.push(byte[0]);
                    if buf.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&buf).to_lowercase();
                let ok = head.contains(&format!("host: 127.0.0.1:{port}"));
                let body = if ok { "yes" } else { "no" };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes());
            }
        });
        let rt = TokioRuntime;
        let resp = get(&rt, &format!("http://127.0.0.1:{port}/"))
            .await
            .unwrap();
        assert_eq!(resp.body, b"yes");
    }
}

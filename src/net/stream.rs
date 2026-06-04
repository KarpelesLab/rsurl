//! The object-safe byte-stream trait that connectors hand back.
//!
//! A [`Connector`](crate::net::Connector) returns a `Box<dyn NetStream>` — a
//! plaintext, TCP-equivalent bidirectional pipe to the target. It is only the
//! *plaintext* layer: every protocol in this crate sets its socket timeouts
//! before any TLS upgrade, and the TLS layer ([`crate::tls::connect_over`])
//! requires merely `Read + Write`, so it can wrap a `Box<dyn NetStream>`
//! directly without `NetStream` needing to model the encrypted layer.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::time::Duration;

/// A plaintext, TCP-equivalent byte stream produced by a
/// [`Connector`](crate::net::Connector).
///
/// Object-safe (`Box<dyn NetStream>`) and `Read + Write + Send` so it can be
/// stored in protocol state, handed to [`crate::tls::connect_over`], and used
/// from worker threads. The extra methods mirror the subset of
/// [`std::net::TcpStream`]'s API the protocol backends actually use.
pub trait NetStream: Read + Write + Send {
    /// See [`TcpStream::set_read_timeout`].
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()>;
    /// See [`TcpStream::set_write_timeout`].
    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()>;
    /// See [`TcpStream::peer_addr`].
    fn peer_addr(&self) -> io::Result<SocketAddr>;
    /// See [`TcpStream::local_addr`].
    fn local_addr(&self) -> io::Result<SocketAddr>;
    /// See [`TcpStream::shutdown`].
    fn shutdown(&self, how: Shutdown) -> io::Result<()>;
    /// Boxed analogue of [`TcpStream::try_clone`] — a second owned handle to
    /// the same connection (the DICT backend needs an independent writer).
    fn try_clone_box(&self) -> io::Result<Box<dyn NetStream>>;
}

impl NetStream for TcpStream {
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, dur)
    }
    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        TcpStream::set_write_timeout(self, dur)
    }
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        TcpStream::peer_addr(self)
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        TcpStream::local_addr(self)
    }
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        TcpStream::shutdown(self, how)
    }
    fn try_clone_box(&self) -> io::Result<Box<dyn NetStream>> {
        Ok(Box::new(TcpStream::try_clone(self)?))
    }
}

#[cfg(unix)]
impl NetStream for std::os::unix::net::UnixStream {
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        std::os::unix::net::UnixStream::set_read_timeout(self, dur)
    }
    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        std::os::unix::net::UnixStream::set_write_timeout(self, dur)
    }
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        // Unix sockets have no IP peer address.
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "peer_addr unavailable on a Unix-domain socket",
        ))
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "local_addr unavailable on a Unix-domain socket",
        ))
    }
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        std::os::unix::net::UnixStream::shutdown(self, how)
    }
    fn try_clone_box(&self) -> io::Result<Box<dyn NetStream>> {
        Ok(Box::new(std::os::unix::net::UnixStream::try_clone(self)?))
    }
}

// `Read`/`Write` for `Box<dyn NetStream>` come for free from the std blanket
// impls `impl<T: Read + ?Sized> Read for Box<T>` (and the `Write` analogue),
// since `dyn NetStream: Read + Write`. The `NetStream` methods are reachable
// on a `Box<dyn NetStream>` value through auto-deref, so no forwarding impl is
// required here.

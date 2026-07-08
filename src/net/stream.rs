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

/// A protocol transport that is either plaintext or TLS-wrapped, with support
/// for an in-place STARTTLS-style upgrade. Shared by the line-oriented protocol
/// backends (ftp, imap, smtp, pop3, ldap): modelling the transport as an enum
/// (rather than a generic `S: Read + Write`) is what lets [`upgrade`] swap a
/// `Plain` connection for a `Tls` one wrapping the very same socket in place.
///
/// `Tls` is boxed because the active TLS backend's stream is much larger than a
/// bare `Box<dyn NetStream>`, and clippy flags the variant-size mismatch.
///
/// [`upgrade`]: MaybeTlsStream::upgrade
pub(crate) enum MaybeTlsStream {
    Plain(Box<dyn NetStream>),
    Tls(Box<crate::tls::TlsStream<Box<dyn NetStream>>>),
    /// Transient placeholder held only while [`upgrade`](MaybeTlsStream::upgrade)
    /// moves the inner socket out to hand it to the TLS handshake; reads and
    /// writes error out. In steady state a transport is only `Plain` or `Tls`.
    Upgrading,
}

impl MaybeTlsStream {
    /// True for a plaintext (non-TLS) transport.
    pub(crate) fn is_plain(&self) -> bool {
        matches!(self, Self::Plain(_))
    }

    /// Upgrade a plaintext transport to TLS in place (RFC 2595 / RFC 3207
    /// STARTTLS), verifying `host` as the SNI / certificate name — exactly as an
    /// implicit-TLS scheme does. Errors, leaving the transport unchanged, if it
    /// is not currently plaintext.
    pub(crate) fn upgrade(&mut self, host: &str) -> crate::error::Result<()> {
        let plain = match std::mem::replace(self, Self::Upgrading) {
            Self::Plain(s) => s,
            other => {
                *self = other;
                return Err(crate::error::Error::BadResponse(
                    "STARTTLS requested on a non-plaintext connection".into(),
                ));
            }
        };
        let tls = crate::tls::connect_over(plain, host)?;
        *self = Self::Tls(Box::new(tls));
        Ok(())
    }
}

impl Read for MaybeTlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.read(buf),
            Self::Tls(s) => s.read(buf),
            Self::Upgrading => Err(io::Error::other("tls upgrade in progress")),
        }
    }
}

impl Write for MaybeTlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.write(buf),
            Self::Tls(s) => s.write(buf),
            Self::Upgrading => Err(io::Error::other("tls upgrade in progress")),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(s) => s.flush(),
            Self::Tls(s) => s.flush(),
            Self::Upgrading => Err(io::Error::other("tls upgrade in progress")),
        }
    }
}

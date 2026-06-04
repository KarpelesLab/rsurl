//! TLS backend layered on purecrypto's sans-I/O `Connection` state machine.
//!
//! Exposes [`TlsStream`], a blocking `Read + Write` adapter that runs the TLS
//! handshake on construction and then transparently encrypts/decrypts
//! application bytes on every read/write. Selected by the `purecrypto-tls`
//! Cargo feature (the default); see [`crate::tls`] for the cfg cascade.

use std::io::{self, Read, Write};

use purecrypto::tls::{Config, Connection, HandshakeStatus};

use super::common::ProtocolVersion;
use super::pc_roots;
use crate::error::{Error, Result};

pub use purecrypto::tls::RootCertStore;

const READ_CHUNK: usize = 16 * 1024;

/// Knobs the caller can flip on a single TLS handshake. ALPN list, whether
/// to verify the chain, and an optional custom root store. Used by
/// [`connect_over_tls`]; the older [`connect_over`] / [`connect_over_with_alpn`]
/// wrappers fill this in with defaults.
#[derive(Default, Clone)]
pub struct TlsOpts {
    /// ALPN protocol identifiers to offer (`b"h2"`, `b"http/1.1"`, ...).
    /// Empty means "don't offer ALPN".
    pub alpn: Vec<Vec<u8>>,
    /// When `false`, the chain is accepted without verification — the curl
    /// `-k` / `--insecure` behaviour. Defaults to `true` via
    /// [`TlsOpts::verifying`].
    pub verify: bool,
    /// Roots to trust. When `None`, [`connect_over_tls`] loads the system
    /// bundle. When `Some`, that store is used as-is.
    pub roots: Option<RootCertStore>,
    /// Minimum / maximum acceptable TLS version (curl `--tlsv1.x`/`--tls-max`).
    /// `None` leaves the backend default (TLS 1.2–1.3).
    pub min_version: Option<ProtocolVersion>,
    pub max_version: Option<ProtocolVersion>,
}

impl TlsOpts {
    /// Defaults that match the old `connect_over_with_alpn` behaviour:
    /// verify on, no custom roots, no ALPN.
    pub fn verifying() -> Self {
        TlsOpts {
            alpn: Vec::new(),
            verify: true,
            roots: None,
            min_version: None,
            max_version: None,
        }
    }
}

/// Map the backend-neutral version to purecrypto's, clamping to the 1.2–1.3
/// range the stack supports.
fn to_pc_version(v: ProtocolVersion) -> purecrypto::tls::ProtocolVersion {
    match v {
        ProtocolVersion::TLSv1_3 => purecrypto::tls::ProtocolVersion::TLSv1_3,
        _ => purecrypto::tls::ProtocolVersion::TLSv1_2,
    }
}

/// Load every CA found in the first existing bundle on disk. Thin wrapper
/// around the always-compiled purecrypto-flavoured loader in
/// [`super::pc_roots`], so the QUIC/HTTP/3 path and this backend stay in
/// agreement about which paths are searched and how PEM is parsed.
pub fn load_system_roots() -> Result<RootCertStore> {
    pc_roots::load_system_roots()
}

/// Load CA certificates from a user-supplied PEM bundle (the `--cacert <file>`
/// flag in curl). Thin wrapper around [`super::pc_roots::load_from_file`].
pub fn load_roots_from_file(path: &str) -> Result<RootCertStore> {
    pc_roots::load_from_file(path)
}

/// A blocking TLS adapter around a transport `S: Read + Write` plus a
/// purecrypto `Connection`. The handshake runs in [`connect_over`]; after
/// that, `Read`/`Write` work like an ordinary stream.
pub struct TlsStream<S: Read + Write> {
    conn: Connection,
    sock: S,
    /// Decrypted application bytes that arrived in a single record but
    /// haven't been read out by the caller yet.
    plaintext: Vec<u8>,
    /// Wire bytes that `feed` did not consume on the last call.
    pending_wire: Vec<u8>,
    seen_eof: bool,
}

/// Establish a TLS 1.2/1.3 connection over an existing transport. The peer
/// name is verified against `sni`. ALPN is not offered; use
/// [`connect_over_with_alpn`] to negotiate a specific application protocol.
pub fn connect_over<S: Read + Write>(transport: S, sni: &str) -> Result<TlsStream<S>> {
    connect_over_tls(transport, sni, TlsOpts::verifying())
}

/// Like [`connect_over`], but offers `alpn` as the ALPN protocol list. The
/// server's selection (if any) is available afterward via
/// [`TlsStream::alpn_selected`]. Passing an empty `alpn` slice is equivalent
/// to [`connect_over`].
pub fn connect_over_with_alpn<S: Read + Write>(
    transport: S,
    sni: &str,
    alpn: &[&[u8]],
) -> Result<TlsStream<S>> {
    let mut opts = TlsOpts::verifying();
    opts.alpn = alpn.iter().map(|p| p.to_vec()).collect();
    connect_over_tls(transport, sni, opts)
}

/// Like [`connect_over_with_alpn`], but takes the full [`TlsOpts`] so callers
/// can disable verification (`-k`) or supply a custom root store (`--cacert`).
pub fn connect_over_tls<S: Read + Write>(
    transport: S,
    sni: &str,
    opts: TlsOpts,
) -> Result<TlsStream<S>> {
    let roots = match opts.roots {
        Some(r) => r,
        None => load_system_roots()?,
    };
    let mut builder = Config::builder()
        .tls_only()
        .roots(roots)
        .server_name(sni.to_string())
        .verify_certificates(opts.verify);
    if !opts.alpn.is_empty() {
        builder = builder.alpn(opts.alpn);
    }
    if let Some(v) = opts.min_version {
        builder = builder.min_version(to_pc_version(v));
    }
    if let Some(v) = opts.max_version {
        builder = builder.max_version(to_pc_version(v));
    }
    let cfg = builder.build();
    let conn = Connection::client(&cfg).map_err(tls_err)?;
    let mut s = TlsStream {
        conn,
        sock: transport,
        plaintext: Vec::new(),
        pending_wire: Vec::new(),
        seen_eof: false,
    };
    s.run_handshake()?;
    Ok(s)
}

impl<S: Read + Write> TlsStream<S> {
    /// TLS version negotiated during the handshake, if it succeeded. Mapped
    /// from `purecrypto::tls::ProtocolVersion` to the backend-neutral
    /// [`ProtocolVersion`] so callers don't have to name the purecrypto type.
    pub fn negotiated_version(&self) -> Option<ProtocolVersion> {
        self.conn.negotiated_version().map(map_pc_version)
    }

    /// ALPN protocol the server selected, or `None` if ALPN was not negotiated.
    pub fn alpn_selected(&self) -> Option<&[u8]> {
        self.conn.alpn_selected()
    }

    /// Peer certificate chain in wire order (leaf first), each entry DER-encoded.
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        self.conn.peer_certificates()
    }

    fn run_handshake(&mut self) -> Result<()> {
        let mut buf = [0u8; READ_CHUNK];
        loop {
            // Drain any wire bytes the state machine wants to send.
            self.drain_outgoing().map_err(Error::Io)?;
            match self.conn.handshake().map_err(tls_err)? {
                HandshakeStatus::Complete => return Ok(()),
                HandshakeStatus::WantWrite => continue,
                HandshakeStatus::WantRead => {
                    let n = self.sock.read(&mut buf)?;
                    if n == 0 {
                        return Err(Error::UnexpectedEof);
                    }
                    self.feed_all(&buf[..n]).map_err(Error::Io)?;
                }
            }
        }
    }

    fn drain_outgoing(&mut self) -> io::Result<()> {
        loop {
            let out = self.conn.pop().map_err(io_tls)?;
            if out.is_empty() {
                return Ok(());
            }
            self.sock.write_all(&out)?;
        }
    }

    /// Feed `wire` into the state machine, looping until everything has been
    /// consumed (the API only promises to consume a prefix per call).
    fn feed_all(&mut self, wire: &[u8]) -> io::Result<()> {
        if !self.pending_wire.is_empty() {
            self.pending_wire.extend_from_slice(wire);
            let mut taken = 0;
            while taken < self.pending_wire.len() {
                let n = self
                    .conn
                    .feed(&self.pending_wire[taken..])
                    .map_err(io_tls)?;
                if n == 0 {
                    break;
                }
                taken += n;
            }
            self.pending_wire.drain(..taken);
            return Ok(());
        }
        let mut taken = 0;
        while taken < wire.len() {
            let n = self.conn.feed(&wire[taken..]).map_err(io_tls)?;
            if n == 0 {
                self.pending_wire.extend_from_slice(&wire[taken..]);
                return Ok(());
            }
            taken += n;
        }
        Ok(())
    }
}

impl<S: Read + Write> Write for TlsStream<S> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.conn.send(data).map_err(io_tls)?;
        self.drain_outgoing()?;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.drain_outgoing()?;
        self.sock.flush()
    }
}

impl<S: Read + Write> Read for TlsStream<S> {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        if dst.is_empty() {
            return Ok(0);
        }
        let mut buf = [0u8; READ_CHUNK];
        while self.plaintext.is_empty() {
            if self.seen_eof {
                return Ok(0);
            }
            // Try to decrypt any data already fed into the state machine
            // before reading more from the socket — a previous feed_all may
            // have parked an entire record we haven't recv'd yet.
            let app = self.conn.recv().map_err(io_tls)?;
            if !app.is_empty() {
                self.plaintext = app;
                break;
            }
            let n = self.sock.read(&mut buf)?;
            if n == 0 {
                self.seen_eof = true;
                // Final attempt: maybe a half-record is sitting in the SM.
                let app = self.conn.recv().map_err(io_tls)?;
                if app.is_empty() {
                    return Ok(0);
                }
                self.plaintext = app;
                break;
            }
            self.feed_all(&buf[..n])?;
            // Drain any post-handshake records (e.g. NewSessionTicket) that
            // the SM wants to send back.
            self.drain_outgoing()?;
        }
        let take = dst.len().min(self.plaintext.len());
        dst[..take].copy_from_slice(&self.plaintext[..take]);
        self.plaintext.drain(..take);
        Ok(take)
    }
}

fn map_pc_version(v: purecrypto::tls::ProtocolVersion) -> ProtocolVersion {
    use purecrypto::tls::ProtocolVersion as P;
    match v {
        P::TLSv1_2 => ProtocolVersion::TLSv1_2,
        P::TLSv1_3 => ProtocolVersion::TLSv1_3,
        // Anything else (old TLS, DTLS, unknown) gets surfaced via the
        // on-wire two-byte code so the diagnostic still prints something
        // useful; the trace in `src/http.rs` only ever displays this with
        // `{v:?}` so an `Other(0x0301)` is fine.
        other => ProtocolVersion::Other(other.as_u16()),
    }
}

fn tls_err(e: purecrypto::tls::Error) -> Error {
    Error::BadResponse(format!("tls: {e:?}"))
}

fn io_tls(e: purecrypto::tls::Error) -> io::Error {
    io::Error::other(format!("tls: {e:?}"))
}

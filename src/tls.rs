//! TLS support, layered on purecrypto's sans-I/O `Connection` state machine.
//!
//! Exposes [`TlsStream`], a blocking `Read + Write` adapter that runs the TLS
//! handshake on construction and then transparently encrypts/decrypts
//! application bytes on every read/write.

use std::io::{self, Read, Write};

use purecrypto::tls::{Config, Connection, HandshakeStatus, RootCertStore};

use crate::error::{Error, Result};

const READ_CHUNK: usize = 16 * 1024;

/// Search paths for a system-wide CA bundle, in order of preference.
/// Mirrors what curl/OpenSSL look at on common Unix distros.
const SYSTEM_CA_PATHS: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu/Gentoo
    "/etc/pki/tls/certs/ca-bundle.crt",   // Fedora/RHEL
    "/etc/ssl/cert.pem",                  // Alpine, OpenBSD, macOS (via brew)
    "/etc/ssl/ca-bundle.pem",             // openSUSE
    "/etc/ca-certificates/extracted/tls-ca-bundle.pem", // Arch
];

/// Load every CA found in the first existing bundle on disk. The bundle is
/// scanned for PEM blocks; certificates that purecrypto cannot parse (e.g.
/// unsupported key types) are silently skipped, matching what other
/// pure-Rust TLS stacks do.
pub fn load_system_roots() -> Result<RootCertStore> {
    for path in SYSTEM_CA_PATHS {
        let pem = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(Error::Io(e)),
        };
        let mut roots = RootCertStore::new();
        let mut loaded = 0usize;
        for block in pem_blocks(&pem) {
            if roots.add_pem(&block).is_ok() {
                loaded += 1;
            }
        }
        if loaded == 0 {
            return Err(Error::BadResponse(format!(
                "no usable CA certificates parsed from {path}"
            )));
        }
        return Ok(roots);
    }
    Err(Error::BadResponse(
        "no system CA bundle found; tried common Unix paths".into(),
    ))
}

/// Yield each `-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----` block
/// from a PEM string as its own string.
fn pem_blocks(pem: &str) -> Vec<String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(start) = rest.find(BEGIN) {
        let after_begin = &rest[start..];
        let Some(end_rel) = after_begin.find(END) else {
            break;
        };
        let end_abs = start + end_rel + END.len();
        out.push(rest[start..end_abs].to_string());
        rest = &rest[end_abs..];
    }
    out
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
    connect_over_with_alpn(transport, sni, &[])
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
    let roots = load_system_roots()?;
    let mut builder = Config::builder()
        .tls_only()
        .roots(roots)
        .server_name(sni.to_string())
        .verify_certificates(true);
    if !alpn.is_empty() {
        builder = builder.alpn(alpn.iter().map(|p| p.to_vec()).collect());
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
    /// TLS version negotiated during the handshake, if it succeeded.
    pub fn negotiated_version(&self) -> Option<purecrypto::tls::ProtocolVersion> {
        self.conn.negotiated_version()
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

fn tls_err(e: purecrypto::tls::Error) -> Error {
    Error::BadResponse(format!("tls: {e:?}"))
}

fn io_tls(e: purecrypto::tls::Error) -> io::Error {
    io::Error::other(format!("tls: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_blocks_splits() {
        let pem = "junk\n\
            -----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n\
            noise\n\
            -----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n";
        let blocks = pem_blocks(pem);
        assert_eq!(blocks.len(), 2);
        assert!(blocks[0].contains("AAA"));
        assert!(blocks[1].contains("BBB"));
    }
}

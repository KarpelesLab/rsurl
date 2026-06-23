//! TLS backend layered on purecrypto's sans-I/O `Connection` state machine.
//!
//! Exposes [`TlsStream`], a blocking `Read + Write` adapter that runs the TLS
//! handshake on construction and then transparently encrypts/decrypts
//! application bytes on every read/write. Selected by the `purecrypto-tls`
//! Cargo feature (the default); see [`crate::tls`] for the cfg cascade.

use std::io::{self, Read, Write};

use purecrypto::tls::{Config, Connection, CrlStore, HandshakeStatus};
use zeroize::Zeroize;

use super::common::ProtocolVersion;
use super::{client_auth, pc_roots};
use crate::error::{Error, Result};

pub use purecrypto::tls::RootCertStore;

const READ_CHUNK: usize = 16 * 1024;

/// Knobs the caller can flip on a single TLS handshake. ALPN list, whether
/// to verify the chain, and an optional custom root store. Used by
/// [`connect_over_tls`]; the older [`connect_over`] / [`connect_over_with_alpn`]
/// wrappers fill this in with defaults.
#[derive(Clone)]
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
    /// Raw bytes of the client certificate file (curl `-E`/`--cert`). PEM
    /// (one or more `CERTIFICATE` blocks, leaf first) unless [`Self::cert_is_der`].
    pub client_cert: Option<Vec<u8>>,
    /// Raw bytes of the client private-key file (curl `--key`). When `None`
    /// and `client_cert` is set, the key is looked for inside the cert file.
    pub client_key: Option<Vec<u8>>,
    /// Passphrase for an encrypted client key (curl `--pass` / `-E cert:pass`).
    pub client_key_pass: Option<String>,
    /// The client cert file is DER, not PEM (curl `--cert-type DER`).
    pub cert_is_der: bool,
    /// The client key file is DER, not PEM (curl `--key-type DER`).
    pub key_is_der: bool,
    /// SHA-256 pins of the server leaf SPKI (curl `--pinnedpubkey`). Empty
    /// means no pinning; non-empty requires the leaf to match at least one.
    pub pinned_spki_sha256: Vec<[u8; 32]>,
    /// Raw bytes of a CRL file (curl `--crlfile`) to check the server chain
    /// against. `None` disables CRL checking. PEM (`X509 CRL`) or DER.
    pub crl_pem: Option<Vec<u8>>,
    /// IANA cipher-suite IDs to offer, in preference order (curl `--ciphers` /
    /// `--tls13-ciphers`). Empty leaves purecrypto's full default set.
    pub cipher_suites: Vec<u16>,
    /// Caller-owned certificate-validation hook. When `Some`, rsurl skips its
    /// own chain verification and the callback is the sole trust authority.
    pub verify_callback: Option<super::common::VerifyCallback>,
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
            client_cert: None,
            client_key: None,
            client_key_pass: None,
            cert_is_der: false,
            key_is_der: false,
            pinned_spki_sha256: Vec::new(),
            crl_pem: None,
            cipher_suites: Vec::new(),
            verify_callback: None,
        }
    }
}

/// `TlsOpts` is public API with public fields, so `..Default::default()` in a
/// downstream struct-update must NOT silently disable certificate verification
/// (a `bool` derive would default `verify` to `false`). The safe default is the
/// verifying configuration; opting out of verification must be explicit (`-k`).
impl Default for TlsOpts {
    fn default() -> Self {
        TlsOpts::verifying()
    }
}

/// TLS-5: wipe the client private-key material on drop. `TlsOpts` holds the
/// raw `--key` bytes and the `--pass` passphrase in plain heap and derives
/// `Clone`, so without this the decrypted key bytes would linger in freed
/// memory. A manual `Drop` is the least invasive fix: it keeps the public
/// field types (`Option<Vec<u8>>` / `Option<String>`) unchanged so the
/// `http.rs` call sites still compile, and zeroizes in place via zeroize's
/// `impl Zeroize for Option<T: Zeroize>` (and `for Vec<u8>` / `for String`).
/// `Drop` + `Clone` coexist fine in Rust (only `Drop` + `Copy` conflict, and
/// `TlsOpts` is not `Copy`); each clone wipes its own copy when dropped.
impl Drop for TlsOpts {
    fn drop(&mut self) {
        self.client_key.zeroize();
        self.client_key_pass.zeroize();
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

/// Add every CA in `dir` to a base root store and return it (curl `--capath`,
/// which *adds* to the trust set). When `base` is `None` the system bundle is
/// loaded first, so `--capath` alone augments the default roots; when `base`
/// is `Some` (e.g. a `--cacert` bundle) the directory's CAs are added on top
/// of that.
pub fn load_roots_from_dir(base: Option<RootCertStore>, dir: &str) -> Result<RootCertStore> {
    let mut roots = match base {
        Some(r) => r,
        None => load_system_roots()?,
    };
    pc_roots::add_from_dir(&mut roots, dir)?;
    Ok(roots)
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

/// Build a configured, *un-handshaken* purecrypto [`Connection`] from `sni` and
/// `opts` — the socket-free engine-construction half of [`connect_over_tls`].
/// The sans-IO TLS driver (`crate::proto::tls`) uses this to obtain an engine it
/// drives over its own transport; [`connect_over_tls`] uses it and then runs the
/// blocking handshake. Post-handshake checks (verify callback, SAN-less-leaf,
/// public-key pinning) remain the caller's responsibility.
pub(crate) fn build_client_conn(sni: &str, opts: &mut TlsOpts) -> Result<Connection> {
    // `TlsOpts` has a `Drop` impl (TLS-5: it zeroizes the key material), which
    // forbids moving fields out by value. Take the owned fields we hand to the
    // builder via `Option::take` / `mem::take` so the struct stays whole and
    // its `Drop` still runs.
    let roots = match opts.roots.take() {
        Some(r) => r,
        None => load_system_roots()?,
    };
    // A verify callback is the sole trust authority: run the handshake without
    // our own chain validation, then defer accept/reject to the callback.
    let effective_verify = opts.verify && opts.verify_callback.is_none();
    let mut builder = Config::builder()
        .tls_only()
        .roots(roots)
        .server_name(sni.to_string())
        .verify_certificates(effective_verify)
        // purecrypto 0.6.17 made the TLS entropy source explicit (it no longer
        // defaults to OsRng); supply the OS CSPRNG, restoring the prior default.
        .rng(std::sync::Arc::new(purecrypto::rng::OsRng));
    if !opts.alpn.is_empty() {
        builder = builder.alpn(std::mem::take(&mut opts.alpn));
    }
    if let Some(v) = opts.min_version {
        builder = builder.min_version(to_pc_version(v));
    }
    if let Some(v) = opts.max_version {
        builder = builder.max_version(to_pc_version(v));
    }
    // Cipher-suite restriction (curl `--ciphers`/`--tls13-ciphers`). purecrypto
    // intersects this with the suites it supports, in the given order.
    if !opts.cipher_suites.is_empty() {
        builder = builder.cipher_suites(&opts.cipher_suites);
    }
    // Client certificate / mTLS (curl `-E`/`--cert` + `--key`/`--pass`).
    if let Some(cert_bytes) = &opts.client_cert {
        let (chain, key) = build_identity(
            cert_bytes,
            opts.client_key.as_deref(),
            opts.client_key_pass.as_deref(),
            opts.cert_is_der,
            opts.key_is_der,
        )?;
        builder = builder.identity(chain, key);
    }
    // CRL-based revocation (curl `--crlfile`): the chain is rejected at
    // handshake time if the leaf/intermediates appear on a supplied CRL.
    if let Some(crl_bytes) = &opts.crl_pem {
        let mut store = CrlStore::new();
        // curl's --crlfile accepts a *concatenation* of PEM CRLs. Split out
        // every `X509 CRL` block and add each one — `add_pem` only consumes the
        // first block, so feeding it the whole file would silently drop the
        // revocations in the 2nd+ CRL. A block that fails to parse is surfaced
        // as an error rather than dropped.
        let blocks = std::str::from_utf8(crl_bytes)
            .ok()
            .map(crl_pem_blocks)
            .unwrap_or_default();
        if !blocks.is_empty() {
            for block in &blocks {
                store
                    .add_pem(block)
                    .map_err(|_| Error::BadResponse("--crlfile: invalid PEM CRL block".into()))?;
            }
        } else {
            // No PEM CRL blocks found — treat the file as raw DER (single CRL).
            store
                .add_der(crl_bytes.clone())
                .map_err(|_| Error::BadResponse("--crlfile: not a valid PEM or DER CRL".into()))?;
        }
        builder = builder.crls(store);
    }
    let cfg = builder.build();
    Connection::client(&cfg).map_err(tls_err)
}

/// Like [`connect_over_with_alpn`], but takes the full [`TlsOpts`] so callers
/// can disable verification (`-k`) or supply a custom root store (`--cacert`).
pub fn connect_over_tls<S: Read + Write>(
    transport: S,
    sni: &str,
    mut opts: TlsOpts,
) -> Result<TlsStream<S>> {
    // Recomputed here (it is also derived inside `build_client_conn`) for the
    // post-handshake SAN check below, since that runs after construction.
    let effective_verify = opts.verify && opts.verify_callback.is_none();
    let conn = build_client_conn(sni, &mut opts)?;
    let mut s = TlsStream {
        conn,
        sock: transport,
        plaintext: Vec::new(),
        pending_wire: Vec::new(),
        seen_eof: false,
    };
    s.run_handshake()?;
    // Post-handshake trust policy (shared with the rustls backend): enforce
    // public-key pinning FIRST and unconditionally — a pin mismatch fails closed
    // even when a verify callback is present — then defer to a caller-owned
    // verify callback if one is set (authoritative; the browser model). The
    // HTTP/3 path enforces pins in the same order.
    let chain = s.peer_certificates().to_vec();
    let leaf = chain.first().map(Vec::as_slice);
    if client_auth::enforce_pins_then_callback(
        leaf,
        &opts.pinned_spki_sha256,
        sni,
        &chain,
        opts.verify_callback.as_ref(),
    )? == client_auth::PostHandshakeDecision::CallbackAccepted
    {
        return Ok(s);
    }
    // TLS-4: reject a server leaf with no Subject Alternative Name. purecrypto's
    // hostname check falls back to Common Name when the leaf has no SAN; CN
    // matching is deprecated and rejected by webpki/browsers and the rustls
    // backend, so align the default backend with modern standards. Only meaningful
    // when we actually verified the chain (`-k` skips hostname verification too).
    if effective_verify {
        if let Some(der) = s.peer_certificates().first() {
            if !client_auth::leaf_has_san(der) {
                return Err(Error::BadResponse(
                    "server certificate has no Subject Alternative Name \
                     (CN fallback is not accepted)"
                        .into(),
                ));
            }
        }
    }
    Ok(s)
}

/// Split a `--crlfile` PEM body into its individual `X509 CRL` blocks. Mirrors
/// the certificate splitter in [`super::pc_roots`] so a concatenation of CRLs
/// (which curl accepts) is fully honoured instead of only the first block.
fn crl_pem_blocks(pem: &str) -> Vec<String> {
    pc_roots::pem_blocks_labelled(pem, "X509 CRL")
}

/// Parse the client cert chain + signing key from raw file bytes, honouring the
/// PEM/DER cert/key type flags and an optional key passphrase.
fn build_identity(
    cert_bytes: &[u8],
    key_bytes: Option<&[u8]>,
    pass: Option<&str>,
    cert_is_der: bool,
    key_is_der: bool,
) -> Result<(Vec<Vec<u8>>, purecrypto::tls::SigningKey)> {
    let chain = if cert_is_der {
        client_auth::load_cert_chain_der(cert_bytes)?
    } else {
        let pem = std::str::from_utf8(cert_bytes)
            .map_err(|_| Error::BadResponse("client cert: PEM file is not valid UTF-8".into()))?;
        client_auth::load_cert_chain(pem)?
    };
    // The key may be in its own file (`--key`) or embedded in the cert PEM.
    let key = match key_bytes {
        Some(kb) if key_is_der => client_auth::parse_signing_key_der(kb, pass)?,
        Some(kb) => {
            let pem = std::str::from_utf8(kb).map_err(|_| {
                Error::BadResponse("client key: PEM file is not valid UTF-8".into())
            })?;
            client_auth::parse_signing_key(pem, pass)?
        }
        None if cert_is_der => {
            return Err(Error::BadResponse(
                "client cert: a DER cert has no embedded key; pass --key".into(),
            ))
        }
        None => {
            // No separate key file: the key must live in the cert PEM.
            let pem = std::str::from_utf8(cert_bytes).map_err(|_| {
                Error::BadResponse("client cert: PEM file is not valid UTF-8".into())
            })?;
            client_auth::parse_signing_key(pem, pass)?
        }
    };
    Ok((chain, key))
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

    /// The negotiated cipher suite (IANA id), if the handshake completed.
    pub fn negotiated_cipher_suite(&self) -> Option<u16> {
        self.conn.negotiated_cipher_suite()
    }

    /// Peer certificate chain in wire order (leaf first), each entry DER-encoded.
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        self.conn.peer_certificates()
    }

    /// TLS-1: whether the transport closed without a TLS `close_notify` (a
    /// possible response truncation by an attacker injecting a TCP FIN/RST).
    ///
    /// True only once we've actually seen transport EOF *and* the peer never
    /// delivered a `close_notify` alert. `received_close_notify()` (purecrypto
    /// 0.6.8, KarpelesLab/purecrypto#30) distinguishes a graceful shutdown
    /// from a truncation. The HTTP/1.x layer consults this after an
    /// EOF-delimited body; see `http::read_body`.
    pub fn was_truncated(&self) -> bool {
        self.seen_eof && !self.conn.received_close_notify()
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
        pc_drain_outgoing(&mut self.conn, &mut self.sock)
    }

    /// Feed `wire` into the state machine, looping until everything has been
    /// consumed (the API only promises to consume a prefix per call).
    fn feed_all(&mut self, wire: &[u8]) -> io::Result<()> {
        pc_feed_all(&mut self.conn, &mut self.pending_wire, wire)
    }
}

/// Drain every outgoing wire record the state machine has queued, writing each
/// to `sock`. Shared by the blocking [`TlsStream`] and the concurrent
/// [`TlsConn`].
fn pc_drain_outgoing(conn: &mut Connection, sock: &mut dyn Write) -> io::Result<()> {
    loop {
        let out = conn.pop().map_err(io_tls)?;
        if out.is_empty() {
            return Ok(());
        }
        sock.write_all(&out)?;
    }
}

/// Feed `wire` into the state machine, looping until everything is consumed
/// (each `feed` only promises to take a prefix); leftovers are buffered in
/// `pending`. Shared by [`TlsStream`] and [`TlsConn`].
fn pc_feed_all(conn: &mut Connection, pending: &mut Vec<u8>, wire: &[u8]) -> io::Result<()> {
    if !pending.is_empty() {
        pending.extend_from_slice(wire);
        let mut taken = 0;
        while taken < pending.len() {
            let n = conn.feed(&pending[taken..]).map_err(io_tls)?;
            if n == 0 {
                break;
            }
            taken += n;
        }
        pending.drain(..taken);
        return Ok(());
    }
    let mut taken = 0;
    while taken < wire.len() {
        let n = conn.feed(&wire[taken..]).map_err(io_tls)?;
        if n == 0 {
            pending.extend_from_slice(&wire[taken..]);
            return Ok(());
        }
        taken += n;
    }
    Ok(())
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

/// A concurrent TLS connection: the TLS state machine runs behind a mutex while
/// the blocking socket *read* happens outside it, so one thread can block in
/// [`TlsConn::read`] while others [`TlsConn::write`]. Writes are serialized by
/// the engine lock (TLS records must not interleave on the wire); reads run
/// concurrently. Built from a handshaken [`TlsStream`] via
/// [`TlsStream::into_concurrent`].
pub struct TlsConn {
    engine: std::sync::Mutex<PcEngine>,
    /// A second handle to the same fd, used only for inbound bytes so the
    /// reader never holds the engine lock while blocked in a socket read.
    read_sock: std::sync::Mutex<Box<dyn crate::net::NetStream>>,
}

struct PcEngine {
    conn: Connection,
    write_sock: Box<dyn crate::net::NetStream>,
    pending_wire: Vec<u8>,
    /// Decrypted bytes not yet handed to a `read` caller.
    plaintext: Vec<u8>,
    seen_eof: bool,
}

impl TlsStream<Box<dyn crate::net::NetStream>> {
    /// Convert a handshaken blocking stream into a [`TlsConn`]. `read_sock` is a
    /// clone of the same fd (e.g. via `try_clone_box`) used for inbound bytes;
    /// the original socket becomes the write side. Any wire/plaintext buffered
    /// during the handshake is carried over.
    pub fn into_concurrent(self, read_sock: Box<dyn crate::net::NetStream>) -> TlsConn {
        TlsConn {
            engine: std::sync::Mutex::new(PcEngine {
                conn: self.conn,
                write_sock: self.sock,
                pending_wire: self.pending_wire,
                plaintext: self.plaintext,
                seen_eof: self.seen_eof,
            }),
            read_sock: std::sync::Mutex::new(read_sock),
        }
    }
}

impl TlsConn {
    /// Read decrypted application bytes. Blocks on the socket outside the engine
    /// lock, so a concurrent [`write`](Self::write) is never blocked by a reader
    /// parked here.
    pub fn read(&self, dst: &mut [u8]) -> io::Result<usize> {
        if dst.is_empty() {
            return Ok(0);
        }
        loop {
            // Hand back anything already decrypted, or decrypt a parked record,
            // without touching the socket.
            {
                let mut e = self.engine.lock().unwrap();
                if let Some(n) = e.take_plaintext(dst) {
                    return Ok(n);
                }
                let app = e.conn.recv().map_err(io_tls)?;
                if !app.is_empty() {
                    e.plaintext = app;
                    return Ok(e.take_plaintext(dst).unwrap());
                }
                if e.seen_eof {
                    return Ok(0);
                }
            }
            // Blocking read with NO engine lock held.
            let mut buf = [0u8; READ_CHUNK];
            let n = self.read_sock.lock().unwrap().read(&mut buf)?;
            let mut e = self.engine.lock().unwrap();
            if n == 0 {
                e.seen_eof = true;
                let app = e.conn.recv().map_err(io_tls)?;
                if app.is_empty() {
                    return Ok(0);
                }
                e.plaintext = app;
                return Ok(e.take_plaintext(dst).unwrap());
            }
            let PcEngine {
                conn,
                write_sock,
                pending_wire,
                ..
            } = &mut *e;
            pc_feed_all(conn, pending_wire, &buf[..n])?;
            // Post-handshake records the SM wants to send (e.g. key update).
            pc_drain_outgoing(conn, write_sock)?;
        }
    }

    /// Encrypt and send `data`. Serialized against other writes by the lock.
    pub fn write(&self, data: &[u8]) -> io::Result<()> {
        let mut e = self.engine.lock().unwrap();
        e.conn.send(data).map_err(io_tls)?;
        let PcEngine {
            conn, write_sock, ..
        } = &mut *e;
        pc_drain_outgoing(conn, write_sock)
    }

    pub fn flush(&self) -> io::Result<()> {
        let mut e = self.engine.lock().unwrap();
        let PcEngine {
            conn, write_sock, ..
        } = &mut *e;
        pc_drain_outgoing(conn, write_sock)?;
        write_sock.flush()
    }

    /// Set the inbound read timeout (affects the blocking read in
    /// [`read`](Self::read)).
    pub fn set_read_timeout(&self, dur: Option<std::time::Duration>) -> io::Result<()> {
        self.read_sock.lock().unwrap().set_read_timeout(dur)
    }
}

impl PcEngine {
    /// Move up to `dst.len()` buffered plaintext bytes into `dst`; `None` if the
    /// buffer is empty.
    fn take_plaintext(&mut self, dst: &mut [u8]) -> Option<usize> {
        if self.plaintext.is_empty() {
            return None;
        }
        let n = dst.len().min(self.plaintext.len());
        dst[..n].copy_from_slice(&self.plaintext[..n]);
        self.plaintext.drain(..n);
        Some(n)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_enables_verification() {
        // TLS-2: a `#[derive(Default)]` would leave `verify == false`, silently
        // disabling certificate verification for `..Default::default()` callers.
        assert!(TlsOpts::default().verify);
        assert!(TlsOpts::verifying().verify);
    }

    #[test]
    fn crl_pem_blocks_splits_concatenated_crls() {
        // TLS-3: curl's --crlfile accepts a concatenation of PEM CRLs. The
        // splitter must yield every `X509 CRL` block (not just the first), so
        // revocations in the 2nd+ CRL aren't silently dropped.
        let pem = "-----BEGIN X509 CRL-----\nAAA\n-----END X509 CRL-----\n\
            noise between blocks\n\
            -----BEGIN X509 CRL-----\nBBB\n-----END X509 CRL-----\n";
        let blocks = crl_pem_blocks(pem);
        assert_eq!(blocks.len(), 2);
        assert!(blocks[0].contains("AAA"));
        assert!(blocks[1].contains("BBB"));
    }

    #[test]
    fn crl_pem_blocks_single_unchanged() {
        let pem = "-----BEGIN X509 CRL-----\nAAA\n-----END X509 CRL-----\n";
        let blocks = crl_pem_blocks(pem);
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].contains("AAA"));
    }

    #[test]
    fn crl_pem_blocks_empty_for_der() {
        // Raw DER (no PEM armor) yields no blocks, so the caller falls back to
        // `add_der` for the single-CRL DER case.
        assert!(crl_pem_blocks("not a pem armored crl at all").is_empty());
    }
}

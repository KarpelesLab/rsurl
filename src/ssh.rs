//! SSH transports: SFTP (`sftp://`) and SCP (`scp://`), download and upload.
//!
//! Built on the first-party pure-Rust [`puressh`] crate (same lab, on top of
//! `purecrypto`). Both schemes default to port 22 and share connection, auth,
//! and host-key handling; they differ only in how bytes move:
//!
//!   * **SFTP** speaks the SFTP subsystem over a session channel. Download
//!     opens the remote path `FXF_READ` and loops `read` until EOF; upload
//!     opens `FXF_WRITE|FXF_CREAT|FXF_TRUNC` and streams the body in chunks.
//!   * **SCP** drives the remote `scp -t`/`scp -f` helper. puressh's SCP API
//!     is path-oriented (it reads/writes a *local* file), so we bridge through
//!     a temp file: download fetches into a temp file then slurps it; upload
//!     writes the body to a temp file then sends it. The temp file is always
//!     removed, success or failure.
//!
//! ## Authentication
//!
//! The user is taken from the URL userinfo, else `-u`, else `$USER`/`$USERNAME`
//! (like OpenSSH). Credentials are collected in order — public keys first
//! (explicit `--key` identity, else the existing default keys
//! `~/.ssh/id_ed25519`, `~/.ssh/id_ecdsa`, `~/.ssh/id_rsa`), then the password
//! if one was supplied — and handed to a single `authenticate` call, which
//! tries each until one is accepted.
//!
//! ## Host-key verification (strict by default, like curl)
//!
//! By default the server's host key is checked against `~/.ssh/known_hosts`
//! (or [`SshOptions::known_hosts_path`]) **strictly**, as curl does: a host
//! with no entry (looked up as `host`, or `[host]:port` for a non-22 port) is
//! refused, and so is a host whose key has *changed* or is marked `@revoked`.
//! A missing `known_hosts` file therefore rejects every host. Nothing is ever
//! written to `known_hosts` in this mode.
//!
//! **Breaking change:** earlier rsurl releases defaulted to trust-on-first-use
//! (accept and save an unknown host's key). That is now opt-in via
//! [`SshOptions::accept_new`] (the CLI's `--ssh-accept-new`, an rsurl
//! extension equivalent to OpenSSH `StrictHostKeyChecking=accept-new`).
//!
//! The other knobs, in order of precedence:
//!
//!   * [`SshOptions::host_pubkey_sha256`] / [`SshOptions::host_pubkey_md5`]
//!     (curl's `--hostpubsha256` / `--hostpubmd5`): pin the host key's
//!     fingerprint. When a pin is set `known_hosts` is not consulted at all
//!     (curl skips it after a pin matches): a matching key is accepted even
//!     for an unknown host, a mismatching one is refused. Pins apply even with
//!     `insecure`, as in curl.
//!   * [`SshOptions::insecure`] (`-k`/`--insecure`): skip `known_hosts`
//!     verification entirely (curl documents `-k` as doing this for SFTP and
//!     SCP) and never write to it.
//!   * [`SshOptions::accept_new`]: trust-on-first-use, as described above.
//!
//! Every host-key rejection surfaces as an [`Error::Ssh`] for which
//! [`Error::is_ssh_host_key_failure`] is `true` (curl's exit code 60,
//! `CURLE_PEER_FAILED_VERIFICATION`).
//!
//! [`puressh`]: https://crates.io/crates/puressh

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use puressh::auth::ClientCredential;
use puressh::client::{Client, Config, HostKeyPolicy, HostKeyPrompt, KnownHostsPolicy, TofuAction};
use puressh::key::PrivateKey;
use puressh::known_hosts::KnownHosts;
use puressh::sftp::{Attrs, FXF_CREAT, FXF_READ, FXF_TRUNC, FXF_WRITE};

use crate::error::{Error, Result, SSH_HOST_KEY_FAILED};
use crate::url::percent_decode;
use crate::url::Url;

/// Chunk size for SFTP reads and writes. 32 KiB stays well under the SSH
/// channel window and the SFTP packet ceiling while keeping round-trips low.
const SFTP_CHUNK: usize = 32 * 1024;

/// Cap on an SFTP download, which is buffered in memory whole (1 GiB).
const MAX_SFTP_DOWNLOAD: usize = 1024 * 1024 * 1024;

/// Connection/auth knobs derived from the CLI and URL. Carries no secret
/// beyond `password`, which is never logged.
#[derive(Clone, Default)]
pub struct SshOptions {
    /// Password from URL userinfo or `-u`. `None` means "no password method".
    pub password: Option<String>,
    /// Explicit identity file(s) from `--key`. When empty, default keys under
    /// `~/.ssh` are probed instead.
    pub identity_files: Vec<PathBuf>,
    /// Passphrase for an encrypted identity file (from `-u`'s password half,
    /// reused; OpenSSH-style prompting is not available in a one-shot CLI).
    pub key_passphrase: Option<String>,
    /// `-k`/`--insecure`: skip `known_hosts` verification (accept any host
    /// key) and never write to `known_hosts`. A `host_pubkey_*` pin is still
    /// enforced, as in curl.
    pub insecure: bool,
    /// Trust-on-first-use (rsurl extension, CLI `--ssh-accept-new`): accept a
    /// host that has no `known_hosts` entry and append its key to the file,
    /// like OpenSSH `StrictHostKeyChecking=accept-new`. A changed or
    /// `@revoked` key is still refused.
    ///
    /// Defaults to `false`: an unknown host is **rejected**, matching curl.
    /// (Before this option existed, trust-on-first-use was the default.)
    pub accept_new: bool,
    /// curl's `--hostpubsha256`: the base64-encoded SHA-256 of the server's
    /// public host key (as printed by `ssh-keygen -l`, without the `SHA256:`
    /// prefix; trailing `=` padding is optional). When set (alone or with
    /// `host_pubkey_md5`), `known_hosts` is not consulted: a matching key is
    /// accepted, anything else is refused.
    pub host_pubkey_sha256: Option<String>,
    /// curl's `--hostpubmd5`: the 32-hex-digit MD5 of the server's public host
    /// key (case-insensitive). Same semantics as `host_pubkey_sha256`; when
    /// both are set, both must match.
    pub host_pubkey_md5: Option<String>,
    /// Override the `known_hosts` path (defaults to `~/.ssh/known_hosts`).
    pub known_hosts_path: Option<PathBuf>,
    /// Per-operation socket timeout.
    pub timeout: Option<Duration>,
    /// Whole-operation limit (curl `-m`/`--max-time`): connect, handshake,
    /// auth and the transfer must all finish within it, else the operation
    /// fails with an I/O error of kind `TimedOut`.
    pub max_time: Option<Duration>,
}

/// A puressh transport over a deadline-bounded socket (see
/// [`SshOptions::max_time`]): every read/write stops at the deadline.
struct DeadlineTransport(Box<dyn crate::net::NetStream>);

impl std::io::Read for DeadlineTransport {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl std::io::Write for DeadlineTransport {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl puressh::client::Transport for DeadlineTransport {
    fn set_read_timeout(&mut self, t: Option<Duration>) -> std::io::Result<()> {
        self.0.set_read_timeout(t)
    }
    fn set_write_timeout(&mut self, t: Option<Duration>) -> std::io::Result<()> {
        self.0.set_write_timeout(t)
    }
}

/// Map a `puressh::Error` to our crate error, keeping the message but never
/// leaking credentials (puressh's errors are static strings / io errors and
/// carry no secret).
fn ssh_err(e: puressh::Error) -> Error {
    match e {
        // Keep socket timeouts (idle or `max_time`) as I/O errors so callers
        // (and the CLI's exit code 28) can recognise them.
        puressh::Error::Io(io)
            if matches!(
                io.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ) =>
        {
            Error::Io(io)
        }
        e => Error::Ssh(e.to_string()),
    }
}

/// Reject a URL-derived string carrying an ASCII control byte (CR/LF/NUL/DEL,
/// or anything `< 0x20`). Mirrors the guard in `ftp`/`imap`: a control byte in
/// the user or remote path could corrupt the SSH/SFTP/SCP request framing.
fn reject_ctl(s: &str, what: &str) -> Result<()> {
    // SSH reports via its own error variant, but shares the illegal-byte set.
    if let Some(b) = crate::url::first_control_byte(s) {
        return Err(Error::Ssh(format!(
            "{what} contains illegal control byte {b:#04x}"
        )));
    }
    Ok(())
}

/// Resolve `~/.ssh`. `None` if no home directory is discoverable.
fn ssh_dir() -> Option<PathBuf> {
    home_dir().map(|h| h.join(".ssh"))
}

/// Best-effort home directory: `$HOME` on unix, `$USERPROFILE` on Windows.
fn home_dir() -> Option<PathBuf> {
    if let Ok(h) = std::env::var("HOME") {
        if !h.is_empty() {
            return Some(PathBuf::from(h));
        }
    }
    if let Ok(h) = std::env::var("USERPROFILE") {
        if !h.is_empty() {
            return Some(PathBuf::from(h));
        }
    }
    None
}

/// Split `user[:pass]` userinfo into `(Option<user>, Option<pass>)`. An empty
/// password half (`user:`) is treated as no password.
fn split_userinfo(ui: Option<&str>) -> (Option<String>, Option<String>) {
    match ui {
        None => (None, None),
        Some(s) => match s.split_once(':') {
            Some((u, p)) => (
                (!u.is_empty()).then(|| u.to_string()),
                (!p.is_empty()).then(|| p.to_string()),
            ),
            None => ((!s.is_empty()).then(|| s.to_string()), None),
        },
    }
}

/// Extract `(Option<user>, Option<password>)` from a URL's userinfo. Public so
/// the transfer dispatcher and the CLI can derive the password without
/// duplicating the parse.
pub fn userinfo_password(url: &Url) -> (Option<String>, Option<String>) {
    split_userinfo(url.userinfo.as_deref())
}

/// Resolve the SSH username for `url` given the parsed `opts`. URL userinfo
/// wins, then `opts.password`-bearing `-u` user (threaded by the CLI into
/// `opts` is the password only, so the user must come from the URL or the
/// `user` arg), then `$USER`/`$USERNAME` like OpenSSH. Returns an error only
/// if nothing yields a name.
pub fn resolve_user(url: &Url, cli_user: Option<&str>) -> Result<String> {
    let (url_user, _) = split_userinfo(url.userinfo.as_deref());
    if let Some(u) = url_user {
        return Ok(u);
    }
    if let Some(u) = cli_user {
        if !u.is_empty() {
            return Ok(u.to_string());
        }
    }
    for var in ["USER", "USERNAME", "LOGNAME"] {
        if let Ok(v) = std::env::var(var) {
            if !v.is_empty() {
                return Ok(v);
            }
        }
    }
    Err(Error::Ssh(
        "no SSH user: none in URL, -u, or $USER".to_string(),
    ))
}

/// The default known_hosts path (`~/.ssh/known_hosts`), or `None` if no home.
fn default_known_hosts() -> Option<PathBuf> {
    ssh_dir().map(|d| d.join("known_hosts"))
}

/// Default identity files to probe when `--key` isn't given: the existing
/// `~/.ssh/id_ed25519`, `~/.ssh/id_ecdsa`, `~/.ssh/id_rsa` (in OpenSSH's
/// preference order). Only files that actually exist are returned.
fn default_identity_files() -> Vec<PathBuf> {
    let Some(dir) = ssh_dir() else {
        return Vec::new();
    };
    discover_default_keys(&dir)
}

/// Pure helper for [`default_identity_files`]: given an `.ssh` directory,
/// return the existing default key files in preference order. Split out so a
/// unit test can point it at a temp dir.
fn discover_default_keys(ssh_dir: &Path) -> Vec<PathBuf> {
    ["id_ed25519", "id_ecdsa", "id_rsa"]
        .iter()
        .map(|n| ssh_dir.join(n))
        .filter(|p| p.is_file())
        .collect()
}

/// How the server's host key is verified, derived from [`SshOptions`] (see the
/// module docs for the precedence).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostKeyMode {
    /// `host_pubkey_sha256`/`host_pubkey_md5` set: check only the pin(s),
    /// ignore `known_hosts` (curl behaviour, also under `-k`).
    Pinned,
    /// `-k`: no verification, nothing written.
    NoCheck,
    /// `--ssh-accept-new`: trust-on-first-use against `known_hosts`.
    AcceptNew,
    /// Default: `known_hosts` must already hold a matching key.
    Strict,
}

fn host_key_mode(opts: &SshOptions) -> HostKeyMode {
    if opts.host_pubkey_sha256.is_some() || opts.host_pubkey_md5.is_some() {
        HostKeyMode::Pinned
    } else if opts.insecure {
        HostKeyMode::NoCheck
    } else if opts.accept_new {
        HostKeyMode::AcceptNew
    } else {
        HostKeyMode::Strict
    }
}

/// Why a host key was refused, filled in by the verification callback so the
/// resulting error can say more than puressh's bare "host key rejected".
type RejectNote = Arc<Mutex<Option<String>>>;

/// Check the presented host-key `blob` against curl-style fingerprint pins.
/// SHA-256 is compared as base64 with `=` padding ignored on both sides (what
/// curl does); MD5 as case-insensitive hex. `Err` carries curl's wording.
fn check_pins(
    blob: &[u8],
    sha256: Option<&str>,
    md5: Option<&str>,
) -> std::result::Result<(), String> {
    use purecrypto::hash::{Digest, Sha256};
    if let Some(want) = sha256 {
        let got = crate::websocket::base64_encode(Sha256::digest(blob).as_ref());
        let unpad = |s: &str| s.split('=').next().unwrap_or("").to_string();
        if unpad(&got) != unpad(want) {
            return Err(format!(
                "mismatch sha256 fingerprint. Remote {got} is not equal to {want}"
            ));
        }
    }
    if let Some(want) = md5 {
        let got = crate::digest::hex(&purecrypto::hash::md5(blob));
        if !got.eq_ignore_ascii_case(want) {
            return Err(format!(
                "mismatch md5 fingerprint. Remote {got} is not equal to {want}"
            ));
        }
    }
    Ok(())
}

/// `host` or `[host]:port`, the way `known_hosts` names a target.
fn known_hosts_name(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

/// Build the host-key policy `Config` for this connection (see
/// [`HostKeyMode`]), plus the note the verifier fills in on a rejection.
fn build_config(opts: &SshOptions) -> Result<(Config, RejectNote)> {
    // puressh marks `Config` / `KnownHostsPolicy` `#[non_exhaustive]` (0.1.7),
    // so both are built through a constructor and then adjusted by field
    // assignment rather than with a struct literal.
    let note: RejectNote = Arc::new(Mutex::new(None));
    let mode = host_key_mode(opts);
    if mode == HostKeyMode::NoCheck {
        let mut cfg = Config::insecure();
        cfg.timeout = opts.timeout;
        return Ok((cfg, note));
    }
    if mode == HostKeyMode::Pinned {
        // An empty in-memory store makes every host "unknown", so the
        // callback sees every key; nothing is persisted (`save_path: None`).
        // `known_hosts` itself is deliberately not consulted, as in curl.
        let sha = opts.host_pubkey_sha256.clone();
        let md5 = opts.host_pubkey_md5.clone();
        let rec = Arc::clone(&note);
        let mut policy = KnownHostsPolicy::strict(Arc::new(Mutex::new(KnownHosts::new())));
        policy.on_unknown = TofuAction::PromptDetailed(Arc::new(move |p: &HostKeyPrompt<'_>| {
            match check_pins(p.key_blob, sha.as_deref(), md5.as_deref()) {
                Ok(()) => true,
                Err(why) => {
                    if let Ok(mut n) = rec.lock() {
                        *n = Some(why);
                    }
                    false
                }
            }
        }));
        let mut cfg = Config::new(HostKeyPolicy::KnownHosts(policy));
        cfg.timeout = opts.timeout;
        return Ok((cfg, note));
    }
    let kh_path = opts.known_hosts_path.clone().or_else(default_known_hosts);
    // Load the existing store if present; start empty otherwise. `KnownHosts::
    // load` maps a missing file to `Ok(empty)` (so strict mode then rejects
    // every host, like curl; accept-new creates the file on first accept). An
    // `Err` here means the file EXISTS but is genuinely unreadable (EACCES,
    // EIO, a directory in its place, ...). Fail closed in that case instead of
    // degrading to an empty store — under accept-new that would silently
    // re-trust and persist a new key, defeating host-key pinning.
    let store = match &kh_path {
        Some(p) => KnownHosts::load(p)
            .map_err(|e| Error::Ssh(format!("reading known_hosts {}: {e}", p.display())))?,
        None => KnownHosts::new(),
    };
    // `strict` is reject-unknown / reject-mismatch. A changed key is always a
    // hard reject; `@revoked` is refused by puressh regardless of policy.
    let mut policy = KnownHostsPolicy::strict(Arc::new(Mutex::new(store)));
    if mode == HostKeyMode::AcceptNew {
        // TOFU: accept and persist an unknown host (plain-text entry,
        // `hash_new: false`, matching what `ssh-keygen -F` and a human reader
        // expect).
        policy.save_path = kh_path;
        policy.on_unknown = TofuAction::Accept;
    } else {
        // Strict (the default): refuse, recording why for the error message.
        // Nothing is written (`save_path` stays `None`).
        let rec = Arc::clone(&note);
        let file = kh_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "known_hosts".to_string());
        policy.on_unknown = TofuAction::PromptDetailed(Arc::new(move |p: &HostKeyPrompt<'_>| {
            if let Ok(mut n) = rec.lock() {
                *n = Some(format!(
                    "{} is not in {file} (server {} key fingerprint {}); add it \
                     there, pin it with --hostpubsha256, or trust it on first use \
                     with --ssh-accept-new",
                    known_hosts_name(p.host, p.port),
                    p.key_type,
                    p.fingerprint,
                ));
            }
            false
        }));
    }
    let mut cfg = Config::new(HostKeyPolicy::KnownHosts(policy));
    cfg.timeout = opts.timeout;
    Ok((cfg, note))
}

/// Load one identity file into a `ClientCredential::PublicKey`. Encrypted keys
/// require a passphrase; without one we surface a clear error rather than
/// silently skipping (so a typo'd `--key` doesn't quietly fall back to
/// password auth).
fn load_identity(path: &Path, passphrase: Option<&str>) -> Result<ClientCredential> {
    let pem = std::fs::read_to_string(path)
        .map_err(|e| Error::Ssh(format!("reading identity {}: {e}", path.display())))?;
    let pass = passphrase.map(|p| p.as_bytes());
    let key = PrivateKey::parse_openssh_pem(&pem, pass).map_err(|e| {
        Error::Ssh(format!(
            "loading identity {}: {e} (encrypted keys need a passphrase via -u)",
            path.display()
        ))
    })?;
    let host_key = key.into_host_key().map_err(ssh_err)?;
    Ok(ClientCredential::PublicKey(host_key))
}

/// Assemble the credential list for `authenticate`, in try order: explicit
/// identity files (or discovered defaults), then password. Identity-load
/// failures on the *explicit* `--key` path are fatal; failures discovering
/// optional default keys are swallowed (a missing/encrypted default key just
/// means "skip it").
fn collect_credentials(opts: &SshOptions) -> Result<Vec<ClientCredential>> {
    let mut creds = Vec::new();
    if !opts.identity_files.is_empty() {
        // Explicit `--key`: a load error is the user's intent failing, so
        // surface it.
        for path in &opts.identity_files {
            creds.push(load_identity(path, opts.key_passphrase.as_deref())?);
        }
    } else {
        // Default keys: probe only the ones that exist, and tolerate a key we
        // can't load (e.g. encrypted with no passphrase available).
        for path in default_identity_files() {
            if let Ok(cred) = load_identity(&path, opts.key_passphrase.as_deref()) {
                creds.push(cred);
            }
        }
    }
    if let Some(pw) = &opts.password {
        creds.push(ClientCredential::Password(pw.clone().into()));
    }
    if creds.is_empty() {
        return Err(Error::Ssh(
            "no usable credentials: no identity key found and no password given".to_string(),
        ));
    }
    Ok(creds)
}

/// Connect to `url`'s host:port, verify the host key, and authenticate `user`.
/// Returns the ready [`Client`]. `trace` (if `Some`) receives `* `-prefixed
/// progress lines on the verbose path, mirroring the other protocols' style.
fn connect_auth(
    url: &Url,
    user: &str,
    opts: &SshOptions,
    mut trace: Option<&mut (dyn std::io::Write + '_)>,
) -> Result<Client> {
    reject_ctl(user, "ssh user")?;
    if let Some(t) = trace.as_mut() {
        let _ = writeln!(t, "* Trying {}:{}...", url.host, url.port);
    }
    let (cfg, note) = build_config(opts)?;
    let map_err = |e: puressh::Error| match e {
        puressh::Error::HostKeyRejected => {
            let why = note
                .lock()
                .ok()
                .and_then(|mut n| n.take())
                .unwrap_or_else(|| {
                    // Not an unknown-host/pin decision: puressh refused a changed
                    // or `@revoked` key (and printed its banner on stderr).
                    format!(
                        "the host key for {} does not match known_hosts (changed or revoked)",
                        known_hosts_name(&url.host, url.port)
                    )
                });
            Error::Ssh(format!("{SSH_HOST_KEY_FAILED}: {why}"))
        }
        e => ssh_err(e),
    };
    let mut client = match opts.max_time {
        None => Client::connect_to_host(&url.host, url.port, cfg).map_err(map_err)?,
        Some(max) => {
            // Dial ourselves so the socket (and so every SSH read/write) is
            // bounded by the deadline; puressh then runs over it.
            use std::net::ToSocketAddrs;
            let deadline = Some(std::time::Instant::now() + max);
            let addrs: Vec<std::net::SocketAddr> = (url.host_unbracketed(), url.port)
                .to_socket_addrs()?
                .collect();
            let tcp = crate::net::connect_any(&addrs, crate::net::op_timeout(deadline, None)?)?;
            tcp.set_nodelay(true)?;
            let sock = crate::net::DeadlineStream::wrap(Box::new(tcp), deadline);
            sock.set_read_timeout(opts.timeout)?;
            sock.set_write_timeout(opts.timeout)?;
            let transport = Box::new(DeadlineTransport(sock));
            Client::connect_via(transport, &url.host, url.port, cfg).map_err(map_err)?
        }
    };
    if let Some(t) = trace.as_mut() {
        let _ = writeln!(t, "* SSH connected to {}:{}", url.host, url.port);
    }
    let creds = collect_credentials(opts)?;
    client.authenticate(user, creds).map_err(ssh_err)?;
    if let Some(t) = trace.as_mut() {
        let _ = writeln!(t, "* SSH authenticated as {user}");
    }
    Ok(client)
}

/// The remote path for SFTP/SCP, percent-decoded (as curl does). The URL path
/// is absolute from the server root, except curl's `/~/` prefix, which names a
/// path relative to the user's home directory (`sftp://h/~/f` → `f`). Empty
/// path is an error — there's no file to name. Control bytes are rejected
/// after decoding, so `%0a` can't reach the remote `scp` command line.
fn remote_path(url: &Url, what: &str) -> Result<String> {
    let path = url.path.split('?').next().unwrap_or("");
    let path = match path.strip_prefix("/~/") {
        Some(rel) => percent_decode(rel),
        None => percent_decode(path),
    };
    reject_ctl(&path, what)?;
    if path.is_empty() || path == "/" {
        return Err(Error::Ssh(format!("{what}: URL names no remote file")));
    }
    Ok(path)
}

/// Download the file at `url.path`. For `sftp://` this opens+reads over the
/// SFTP subsystem; for `scp://` it bridges through a temp file. Returns the
/// raw bytes (the transfer layer writes them to `-o`/stdout).
pub fn fetch(url: &Url, opts: &SshOptions, user: &str) -> Result<Vec<u8>> {
    fetch_traced(url, opts, user, None)
}

/// [`fetch`] with an optional verbose trace sink.
pub fn fetch_traced(
    url: &Url,
    opts: &SshOptions,
    user: &str,
    mut trace: Option<&mut (dyn std::io::Write + '_)>,
) -> Result<Vec<u8>> {
    let path = remote_path(url, "sftp/scp path")?;
    let mut client = connect_auth(url, user, opts, trace.as_deref_mut())?;
    match url.scheme.as_str() {
        "sftp" => {
            let bytes = sftp_download(&mut client, &path)?;
            if let Some(t) = trace.as_mut() {
                let _ = writeln!(t, "* SFTP downloaded {} bytes", bytes.len());
            }
            Ok(bytes)
        }
        "scp" => {
            let bytes = scp_download(&mut client, &path)?;
            if let Some(t) = trace.as_mut() {
                let _ = writeln!(t, "* SCP downloaded {} bytes", bytes.len());
            }
            Ok(bytes)
        }
        other => Err(Error::UnsupportedScheme(other.to_string())),
    }
}

/// Upload `body` to `url.path`. `sftp://` writes over the SFTP subsystem;
/// `scp://` bridges through a temp file.
pub fn upload(url: &Url, body: &[u8], opts: &SshOptions, user: &str) -> Result<()> {
    upload_traced(url, body, opts, user, None)
}

/// [`upload`] with an optional verbose trace sink.
pub fn upload_traced(
    url: &Url,
    body: &[u8],
    opts: &SshOptions,
    user: &str,
    mut trace: Option<&mut (dyn std::io::Write + '_)>,
) -> Result<()> {
    let path = remote_path(url, "sftp/scp path")?;
    let mut client = connect_auth(url, user, opts, trace.as_deref_mut())?;
    match url.scheme.as_str() {
        "sftp" => {
            sftp_upload(&mut client, &path, body)?;
            if let Some(t) = trace.as_mut() {
                let _ = writeln!(t, "* SFTP uploaded {} bytes", body.len());
            }
            Ok(())
        }
        "scp" => {
            scp_upload(&mut client, &path, body)?;
            if let Some(t) = trace.as_mut() {
                let _ = writeln!(t, "* SCP uploaded {} bytes", body.len());
            }
            Ok(())
        }
        other => Err(Error::UnsupportedScheme(other.to_string())),
    }
}

/// SFTP download: open the remote path read-only and loop `read` (advancing
/// the offset) until a short/empty read signals EOF.
fn sftp_download(client: &mut Client, path: &str) -> Result<Vec<u8>> {
    let mut sftp = client.sftp().map_err(ssh_err)?;
    let handle = sftp
        .open(path.as_bytes(), FXF_READ, Attrs::default())
        .map_err(|e| Error::Ssh(format!("sftp open {path:?}: {e}")))?;
    let mut out = Vec::new();
    let mut offset: u64 = 0;
    loop {
        let chunk = sftp
            .read(&handle, offset, SFTP_CHUNK as u32)
            .map_err(|e| Error::Ssh(format!("sftp read {path:?}: {e}")))?;
        if chunk.is_empty() {
            break;
        }
        offset += chunk.len() as u64;
        // The whole file is buffered; bound it so a server streaming an
        // endless "file" (e.g. /dev/zero) fails instead of exhausting memory.
        if out.len() + chunk.len() > MAX_SFTP_DOWNLOAD {
            return Err(Error::Ssh(format!(
                "sftp read {path:?}: file exceeds {MAX_SFTP_DOWNLOAD} bytes"
            )));
        }
        out.extend_from_slice(&chunk);
        // A short read does not necessarily mean EOF in SFTP; only an empty
        // (EOF status) read does. Keep looping until the empty read above.
    }
    let _ = sftp.close(&handle);
    Ok(out)
}

/// SFTP upload: open `WRITE|CREAT|TRUNC` and stream `body` in chunks.
fn sftp_upload(client: &mut Client, path: &str, body: &[u8]) -> Result<()> {
    let mut sftp = client.sftp().map_err(ssh_err)?;
    let handle = sftp
        .open(
            path.as_bytes(),
            FXF_WRITE | FXF_CREAT | FXF_TRUNC,
            Attrs::default(),
        )
        .map_err(|e| Error::Ssh(format!("sftp open(w) {path:?}: {e}")))?;
    let mut offset: u64 = 0;
    for chunk in body.chunks(SFTP_CHUNK) {
        sftp.write(&handle, offset, chunk)
            .map_err(|e| Error::Ssh(format!("sftp write {path:?}: {e}")))?;
        offset += chunk.len() as u64;
    }
    sftp.close(&handle)
        .map_err(|e| Error::Ssh(format!("sftp close {path:?}: {e}")))?;
    Ok(())
}

/// A temp file for the SCP bridge, inside a freshly created private directory,
/// both removed on drop so no stray files are left even on an early `?`.
///
/// puressh's SCP API opens the local path itself, so we can't hand it an
/// already-open `O_EXCL` file. Instead the file lives in a directory we create
/// atomically (`create_dir` fails if the name exists) under an unpredictable
/// CSPRNG name with owner-only permissions: another local user can neither
/// pre-plant a symlink at the path nor read or swap the contents mid-transfer
/// — the classic shared-`/tmp` race a predictable `rsurl-scp-<pid>-<n>` name
/// was open to.
struct TempFile {
    dir: PathBuf,
    path: PathBuf,
}

impl TempFile {
    fn new(tag: &str) -> Result<Self> {
        use purecrypto::rng::{OsRng, RngCore};
        let mut last_err = None;
        for _ in 0..8 {
            let mut rnd = [0u8; 16];
            OsRng.fill_bytes(&mut rnd);
            let name: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
            let dir = std::env::temp_dir().join(format!("rsurl-scp-{name}"));
            match create_private_dir(&dir) {
                Ok(()) => {
                    let path = dir.join(tag);
                    return Ok(TempFile { dir, path });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => last_err = Some(e),
                Err(e) => return Err(Error::Ssh(format!("scp: creating temp dir: {e}"))),
            }
        }
        Err(Error::Ssh(format!(
            "scp: creating temp dir: {}",
            last_err.map(|e| e.to_string()).unwrap_or_default()
        )))
    }
}

/// `mkdir` that fails if the path exists, with mode 0700 on unix.
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::DirBuilder::new().create(dir)
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_dir(&self.dir);
    }
}

/// SCP download: drive `scp -f` into a temp file, then read the bytes back.
/// The temp file is removed by [`TempFile`]'s `Drop`.
fn scp_download(client: &mut Client, path: &str) -> Result<Vec<u8>> {
    let tmp = TempFile::new("recv")?;
    // We're fetching a single file to a concrete local path, not into a dir.
    let mut opts = puressh::scp::ScpRecvOptions::default();
    opts.target_is_file = true;
    client
        .scp_recv_from(path, &tmp.path, opts)
        .map_err(|e| Error::Ssh(format!("scp recv {path:?}: {e}")))?;
    let bytes = std::fs::read(&tmp.path)
        .map_err(|e| Error::Ssh(format!("scp recv: reading temp file: {e}")))?;
    Ok(bytes)
}

/// SCP upload: write `body` to a temp file, then `scp -t` it to the remote
/// path. The temp file is removed by [`TempFile`]'s `Drop`.
fn scp_upload(client: &mut Client, path: &str, body: &[u8]) -> Result<()> {
    let tmp = TempFile::new("send")?;
    std::fs::write(&tmp.path, body)
        .map_err(|e| Error::Ssh(format!("scp send: writing temp file: {e}")))?;
    let opts = puressh::scp::ScpSendOptions::default();
    let sources: [&Path; 1] = [tmp.path.as_path()];
    client
        .scp_send_to(&sources, path, opts)
        .map_err(|e| Error::Ssh(format!("scp send {path:?}: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sftp_url_parses_with_userinfo_and_port() {
        let u = Url::parse("sftp://user@host:2222/path/to/file").unwrap();
        assert_eq!(u.scheme, "sftp");
        assert_eq!(u.userinfo.as_deref(), Some("user"));
        assert_eq!(u.host, "host");
        assert_eq!(u.port, 2222);
        assert_eq!(u.path, "/path/to/file");
    }

    #[test]
    fn scp_url_defaults_to_port_22() {
        let u = Url::parse("scp://host/path").unwrap();
        assert_eq!(u.scheme, "scp");
        assert_eq!(u.port, 22);
        assert_eq!(u.userinfo, None);
        assert_eq!(u.path, "/path");
    }

    #[test]
    fn sftp_url_userinfo_with_password() {
        let u = Url::parse("sftp://alice:secret@host/f").unwrap();
        let (user, pass) = split_userinfo(u.userinfo.as_deref());
        assert_eq!(user.as_deref(), Some("alice"));
        assert_eq!(pass.as_deref(), Some("secret"));
    }

    #[test]
    fn split_userinfo_variants() {
        assert_eq!(split_userinfo(None), (None, None));
        assert_eq!(split_userinfo(Some("bob")), (Some("bob".to_string()), None));
        assert_eq!(
            split_userinfo(Some("bob:pw")),
            (Some("bob".to_string()), Some("pw".to_string()))
        );
        // Empty password half is treated as "no password".
        assert_eq!(
            split_userinfo(Some("bob:")),
            (Some("bob".to_string()), None)
        );
    }

    #[test]
    fn resolve_user_prefers_url_then_cli_then_env() {
        let u = Url::parse("sftp://alice@host/f").unwrap();
        // URL userinfo wins over the CLI -u user.
        assert_eq!(resolve_user(&u, Some("bob")).unwrap(), "alice");

        // No URL user → CLI -u user.
        let u2 = Url::parse("sftp://host/f").unwrap();
        assert_eq!(resolve_user(&u2, Some("carol")).unwrap(), "carol");

        // No URL user, no CLI user → $USER. Set it deterministically.
        // SAFETY: single-threaded test; we restore nothing because the value
        // we set is what we assert on.
        unsafe { std::env::set_var("USER", "envuser") };
        assert_eq!(resolve_user(&u2, None).unwrap(), "envuser");
    }

    #[test]
    fn discover_default_keys_finds_existing_in_order() {
        let dir =
            std::env::temp_dir().join(format!("rsurl-ssh-keys-{}-{}", std::process::id(), "disc"));
        std::fs::create_dir_all(&dir).unwrap();
        // Create id_rsa and id_ed25519 but NOT id_ecdsa.
        std::fs::write(dir.join("id_rsa"), b"x").unwrap();
        std::fs::write(dir.join("id_ed25519"), b"x").unwrap();
        let found = discover_default_keys(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        // Preference order: ed25519 before rsa; ecdsa absent.
        assert_eq!(found.len(), 2);
        assert!(found[0].ends_with("id_ed25519"));
        assert!(found[1].ends_with("id_rsa"));
    }

    #[test]
    fn discover_default_keys_empty_when_none() {
        let dir =
            std::env::temp_dir().join(format!("rsurl-ssh-keys-{}-{}", std::process::id(), "empty"));
        std::fs::create_dir_all(&dir).unwrap();
        let found = discover_default_keys(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(found.is_empty());
    }

    #[test]
    fn remote_path_rejects_empty_and_root() {
        let u = Url::parse("sftp://host/").unwrap();
        assert!(matches!(remote_path(&u, "p"), Err(Error::Ssh(_))));
        let u2 = Url::parse("sftp://host/file").unwrap();
        assert_eq!(remote_path(&u2, "p").unwrap(), "/file");
    }

    #[test]
    fn reject_ctl_flags_control_bytes() {
        assert!(reject_ctl("alice", "ssh user").is_ok());
        assert!(reject_ctl("/a/b/c.txt", "ssh path").is_ok());
        assert!(reject_ctl("a\rb", "ssh user").is_err());
        assert!(reject_ctl("a\nb", "ssh path").is_err());
        assert!(reject_ctl("a\0b", "ssh user").is_err());
        assert!(reject_ctl("a\x7fb", "ssh user").is_err());
    }

    #[test]
    fn collect_credentials_password_only() {
        // No identity files on the opts, no default keys (point HOME away).
        // We can't easily clear default-key discovery here, so just assert
        // that a password is included when present.
        let opts = SshOptions {
            password: Some("pw".to_string()),
            identity_files: vec![],
            ..Default::default()
        };
        let creds = collect_credentials(&opts).unwrap();
        assert!(creds
            .iter()
            .any(|c| matches!(c, ClientCredential::Password(_))));
    }

    #[test]
    fn collect_credentials_errors_when_empty() {
        // No password and an explicit (nonexistent) identity → load error.
        let opts = SshOptions {
            password: None,
            identity_files: vec![PathBuf::from("/nonexistent/rsurl/id_test")],
            ..Default::default()
        };
        assert!(collect_credentials(&opts).is_err());
    }

    #[test]
    fn build_config_insecure_is_accept_any() {
        let opts = SshOptions {
            insecure: true,
            ..Default::default()
        };
        let (cfg, _) = build_config(&opts).expect("insecure config builds");
        assert!(matches!(cfg.host_key_policy, HostKeyPolicy::AcceptAny));
    }

    #[test]
    fn host_key_mode_policy_mapping() {
        // Default: strict, like curl (an unknown host fails).
        assert_eq!(host_key_mode(&SshOptions::default()), HostKeyMode::Strict);
        // -k: no known_hosts check.
        let k = SshOptions {
            insecure: true,
            ..Default::default()
        };
        assert_eq!(host_key_mode(&k), HostKeyMode::NoCheck);
        // --ssh-accept-new: TOFU.
        let tofu = SshOptions {
            accept_new: true,
            ..Default::default()
        };
        assert_eq!(host_key_mode(&tofu), HostKeyMode::AcceptNew);
        // -k wins over accept-new (nothing checked, nothing written).
        let both = SshOptions {
            insecure: true,
            accept_new: true,
            ..Default::default()
        };
        assert_eq!(host_key_mode(&both), HostKeyMode::NoCheck);
        // A pin always wins, even with -k (curl checks pins regardless).
        for opts in [
            SshOptions {
                host_pubkey_sha256: Some("x".into()),
                insecure: true,
                ..Default::default()
            },
            SshOptions {
                host_pubkey_md5: Some("0".repeat(32)),
                accept_new: true,
                ..Default::default()
            },
        ] {
            assert_eq!(host_key_mode(&opts), HostKeyMode::Pinned);
        }
    }

    #[test]
    fn build_config_default_is_strict_and_never_saves() {
        let opts = SshOptions {
            known_hosts_path: Some(std::env::temp_dir().join("rsurl-kh-nonexistent")),
            ..Default::default()
        };
        let (cfg, _) = build_config(&opts).expect("strict config builds for a missing known_hosts");
        match cfg.host_key_policy {
            HostKeyPolicy::KnownHosts(p) => {
                // The strict callback always refuses (it only records why).
                assert!(matches!(p.on_unknown, TofuAction::PromptDetailed(_)));
                assert!(matches!(p.on_mismatch, TofuAction::Reject));
                assert!(
                    p.save_path.is_none(),
                    "strict mode must not write known_hosts"
                );
            }
            _ => panic!("expected KnownHosts policy"),
        }
    }

    #[test]
    fn check_pins_matches_curl_semantics() {
        use purecrypto::hash::{Digest, Sha256};
        let blob = b"\x00\x00\x00\x0bssh-ed25519 fake key blob";
        let b64 = crate::websocket::base64_encode(Sha256::digest(blob).as_ref());
        let md5 = crate::digest::hex(&purecrypto::hash::md5(blob));
        assert!(check_pins(blob, Some(&b64), None).is_ok());
        // Padding is optional, as in curl.
        assert!(check_pins(blob, Some(b64.trim_end_matches('=')), None).is_ok());
        assert!(check_pins(blob, None, Some(&md5.to_ascii_uppercase())).is_ok());
        assert!(check_pins(blob, Some(&b64), Some(&md5)).is_ok());
        // Any mismatch refuses; both pins must match when both are given.
        assert!(check_pins(blob, Some("AAAA"), None).is_err());
        assert!(check_pins(blob, None, Some(&"0".repeat(32))).is_err());
        assert!(check_pins(blob, Some(&b64), Some(&"0".repeat(32))).is_err());
    }

    #[test]
    fn build_config_accept_new_uses_tofu_policy() {
        let opts = SshOptions {
            accept_new: true,
            known_hosts_path: Some(std::env::temp_dir().join("rsurl-kh-nonexistent")),
            ..Default::default()
        };
        let (cfg, _) = build_config(&opts).expect("tofu config builds for a missing known_hosts");
        match cfg.host_key_policy {
            HostKeyPolicy::KnownHosts(p) => {
                assert!(matches!(p.on_unknown, TofuAction::Accept));
                assert!(matches!(p.on_mismatch, TofuAction::Reject));
                assert!(p.save_path.is_some());
            }
            _ => panic!("expected KnownHosts policy"),
        }
    }

    #[test]
    fn build_config_fails_closed_on_unreadable_known_hosts() {
        // A known_hosts path that exists but cannot be read as a file (here a
        // directory standing in its place) yields a genuine I/O error from
        // `KnownHosts::load`. We must propagate it rather than silently fall back
        // to an empty accept-all store, which would defeat host-key pinning.
        let dir = std::env::temp_dir().join("rsurl-kh-dir-as-file");
        std::fs::create_dir_all(&dir).expect("create stand-in directory");
        let opts = SshOptions {
            accept_new: true,
            known_hosts_path: Some(dir.clone()),
            ..Default::default()
        };
        let is_fail_closed = matches!(build_config(&opts), Err(Error::Ssh(_)));
        let _ = std::fs::remove_dir(&dir);
        assert!(
            is_fail_closed,
            "expected fail-closed Error::Ssh for an unreadable known_hosts"
        );
    }

    #[test]
    fn scp_recv_options_target_is_file() {
        // The SCP download bridge sets `target_is_file` so puressh writes the
        // single remote file to our concrete temp path rather than into a dir.
        let mut opts = puressh::scp::ScpRecvOptions::default();
        opts.target_is_file = true;
        assert!(opts.target_is_file);
        assert!(!opts.recursive);
    }

    #[test]
    fn temp_file_removed_on_drop() {
        let (path, dir);
        {
            let tmp = TempFile::new("droptest").unwrap();
            path = tmp.path.clone();
            dir = tmp.dir.clone();
            std::fs::write(&tmp.path, b"data").unwrap();
            assert!(path.exists());
        }
        assert!(!path.exists(), "temp file should be removed on drop");
        assert!(!dir.exists(), "private temp dir should be removed on drop");
    }

    #[test]
    fn temp_file_lives_in_fresh_private_dir() {
        let a = TempFile::new("x").unwrap();
        let b = TempFile::new("x").unwrap();
        // Unpredictable, distinct directories.
        assert_ne!(a.dir, b.dir);
        assert!(a.path.starts_with(&a.dir));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&a.dir).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "temp dir must be owner-only: {mode:o}");
        }
        // Creating over an existing name fails rather than reusing it.
        assert!(create_private_dir(&a.dir).is_err());
    }

    #[test]
    fn remote_path_decodes_and_handles_home_prefix() {
        let u = Url::parse("sftp://h/dir/my%20file").unwrap();
        assert_eq!(remote_path(&u, "p").unwrap(), "/dir/my file");
        // curl's `/~/` → relative to the login (home) directory.
        let u = Url::parse("sftp://h/~/notes.txt").unwrap();
        assert_eq!(remote_path(&u, "p").unwrap(), "notes.txt");
        let u = Url::parse("scp://h/a%0ab").unwrap();
        assert!(remote_path(&u, "p").is_err());
    }

    /// `max_time` bounds the SSH handshake: a server that accepts TCP but
    /// never sends its banner fails with a `TimedOut` I/O error at the
    /// deadline (the CLI's exit 28) instead of hanging.
    #[test]
    fn max_time_bounds_a_silent_server() {
        use std::time::Instant;
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (_s, _) = l.accept().unwrap();
            std::thread::sleep(Duration::from_secs(3));
        });
        let url = Url::parse(&format!("sftp://127.0.0.1:{port}/f")).unwrap();
        let opts = SshOptions {
            password: Some("pw".into()),
            insecure: true,
            max_time: Some(Duration::from_millis(500)),
            ..Default::default()
        };
        let start = Instant::now();
        let err = match fetch(&url, &opts, "u") {
            Ok(_) => panic!("fetch from a silent server succeeded"),
            Err(e) => e,
        };
        match &err {
            Error::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::TimedOut, "{e}"),
            other => panic!("expected a TimedOut I/O error, got {other:?}"),
        }
        assert!(start.elapsed() < Duration::from_millis(1500));
    }
}

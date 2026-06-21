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
//! ## Host-key verification (TOFU)
//!
//! By default we verify against `~/.ssh/known_hosts` with trust-on-first-use:
//! an unknown host is accepted and persisted; a host whose key has *changed*
//! is rejected. `-k`/`--insecure` downgrades to accept-any (OpenSSH
//! `StrictHostKeyChecking=no`).
//!
//! [`puressh`]: https://crates.io/crates/puressh

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use puressh::auth::ClientCredential;
use puressh::client::{AlgoOverrides, Client, Config, HostKeyPolicy, KnownHostsPolicy, TofuAction};
use puressh::key::PrivateKey;
use puressh::known_hosts::KnownHosts;
use puressh::sftp::{Attrs, FXF_CREAT, FXF_READ, FXF_TRUNC, FXF_WRITE};

use crate::error::{Error, Result};
use crate::url::Url;

/// Chunk size for SFTP reads and writes. 32 KiB stays well under the SSH
/// channel window and the SFTP packet ceiling while keeping round-trips low.
const SFTP_CHUNK: usize = 32 * 1024;

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
    /// `-k`/`--insecure`: accept any host key instead of TOFU/known_hosts.
    pub insecure: bool,
    /// Override the `known_hosts` path (defaults to `~/.ssh/known_hosts`).
    pub known_hosts_path: Option<PathBuf>,
    /// Per-operation socket timeout.
    pub timeout: Option<Duration>,
}

/// Map a `puressh::Error` to our crate error, keeping the message but never
/// leaking credentials (puressh's errors are static strings / io errors and
/// carry no secret).
fn ssh_err(e: puressh::Error) -> Error {
    Error::Ssh(e.to_string())
}

/// Reject a URL-derived string carrying an ASCII control byte (CR/LF/NUL/DEL,
/// or anything `< 0x20`). Mirrors the guard in `ftp`/`imap`: a control byte in
/// the user or remote path could corrupt the SSH/SFTP/SCP request framing.
fn reject_ctl(s: &str, what: &str) -> Result<()> {
    if let Some(b) = s.bytes().find(|b| *b < 0x20 || *b == 0x7f) {
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

/// Build the host-key policy `Config` for this connection. `-k` ⇒ accept-any;
/// otherwise TOFU against known_hosts (accept+persist unknown, reject changed).
fn build_config(opts: &SshOptions) -> Result<Config> {
    if opts.insecure {
        return Ok(Config {
            host_key_policy: HostKeyPolicy::AcceptAny,
            timeout: opts.timeout,
            algorithms: AlgoOverrides::default(),
        });
    }
    let kh_path = opts.known_hosts_path.clone().or_else(default_known_hosts);
    // Load the existing store if present; start empty otherwise (a fresh
    // known_hosts the first TOFU accept will create). `KnownHosts::load` maps a
    // missing file to `Ok(empty)`, so an `Err` here means the file EXISTS but is
    // genuinely unreadable (EACCES, EIO, a directory in its place, ...). Fail
    // closed in that case instead of degrading to an empty accept-all store —
    // otherwise a populated, pinned known_hosts would silently become TOFU
    // accept-all and persist the new key, defeating host-key pinning.
    let store = match &kh_path {
        Some(p) => KnownHosts::load(p)
            .map_err(|e| Error::Ssh(format!("reading known_hosts {}: {e}", p.display())))?,
        None => KnownHosts::new(),
    };
    let policy = KnownHostsPolicy {
        store: Arc::new(Mutex::new(store)),
        save_path: kh_path,
        hash_new: false,
        on_unknown: TofuAction::Accept,
        on_mismatch: TofuAction::Reject,
    };
    Ok(Config {
        host_key_policy: HostKeyPolicy::KnownHosts(policy),
        timeout: opts.timeout,
        algorithms: AlgoOverrides::default(),
    })
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
    let cfg = build_config(opts)?;
    let mut client = Client::connect_to_host(&url.host, url.port, cfg).map_err(ssh_err)?;
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

/// The remote path for SFTP/SCP: the URL path with a single leading `/`
/// preserved (SFTP paths are absolute from the server root). Empty path is an
/// error — there's no file to name.
fn remote_path<'a>(url: &'a Url, what: &str) -> Result<&'a str> {
    reject_ctl(&url.path, what)?;
    if url.path.is_empty() || url.path == "/" {
        return Err(Error::Ssh(format!("{what}: URL names no remote file")));
    }
    Ok(&url.path)
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
    let path = remote_path(url, "sftp/scp path")?.to_string();
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
    let path = remote_path(url, "sftp/scp path")?.to_string();
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

/// A temp file that removes itself on drop, so the SCP bridge never leaves
/// stray files behind even on an early `?` return.
struct TempFile {
    path: PathBuf,
}

impl TempFile {
    /// Create a unique temp path under the system temp dir. Uses pid + a
    /// monotonically increasing counter for uniqueness without extra deps.
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!("rsurl-scp-{}-{}-{}", std::process::id(), tag, n));
        TempFile { path }
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// SCP download: drive `scp -f` into a temp file, then read the bytes back.
/// The temp file is removed by [`TempFile`]'s `Drop`.
fn scp_download(client: &mut Client, path: &str) -> Result<Vec<u8>> {
    let tmp = TempFile::new("recv");
    // We're fetching a single file to a concrete local path, not into a dir.
    let opts = puressh::scp::ScpRecvOptions {
        target_is_file: true,
        ..Default::default()
    };
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
    let tmp = TempFile::new("send");
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
        let cfg = build_config(&opts).expect("insecure config builds");
        assert!(matches!(cfg.host_key_policy, HostKeyPolicy::AcceptAny));
    }

    #[test]
    fn build_config_tofu_uses_known_hosts_policy() {
        let opts = SshOptions {
            insecure: false,
            known_hosts_path: Some(std::env::temp_dir().join("rsurl-kh-nonexistent")),
            ..Default::default()
        };
        let cfg = build_config(&opts).expect("tofu config builds for a missing known_hosts");
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
            insecure: false,
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
        let opts = puressh::scp::ScpRecvOptions {
            target_is_file: true,
            ..Default::default()
        };
        assert!(opts.target_is_file);
        assert!(!opts.recursive);
    }

    #[test]
    fn temp_file_removed_on_drop() {
        let path;
        {
            let tmp = TempFile::new("droptest");
            path = tmp.path.clone();
            std::fs::write(&tmp.path, b"data").unwrap();
            assert!(path.exists());
        }
        assert!(!path.exists(), "temp file should be removed on drop");
    }
}

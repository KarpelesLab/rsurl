//! End-to-end SSH host-key verification tests: the `rsurl` binary against an
//! in-process puressh SFTP server on 127.0.0.1 (a non-22 port, so known_hosts
//! entries are `[127.0.0.1]:port`). `$HOME` points at a temp dir so the real
//! `~/.ssh` is never read or written.
//!
//! Covers curl's behaviour: an unknown host fails with exit 60, `-k` skips
//! the check without writing known_hosts, `--hostpubsha256`/`--hostpubmd5`
//! pins accept or reject regardless of known_hosts, a changed key fails, and
//! the rsurl `--ssh-accept-new` extension restores trust-on-first-use.

#![cfg(all(feature = "ssh", unix))]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

use puressh::auth::{AuthAttempt, AuthDecision, Authenticator};
use puressh::hostkey::{Ed25519HostKey, HostKey};
use puressh::server::{CommandHandler, Config, ExecResult, Server, SessionEnv, SubsystemHandler};
use puressh::sftp::{SftpServerOptions, SftpServerSession};
use puressh::stream::ChannelStream;

const USER: &str = "alice";
const PASS: &str = "s3cret";
const BODY: &[u8] = b"hello over sftp\n";

struct PasswordAuth;

impl Authenticator for PasswordAuth {
    fn evaluate(&mut self, attempt: AuthAttempt) -> AuthDecision {
        match attempt {
            AuthAttempt::Password { user, password } if user == USER && password == PASS => {
                AuthDecision::Accept
            }
            _ => AuthDecision::Reject,
        }
    }
}

struct NoExec;

impl CommandHandler for NoExec {
    fn handle(&self, _user: &str, _env: &SessionEnv, _command: &str) -> ExecResult {
        ExecResult::new(Vec::new(), b"exec not supported\n".to_vec(), 1)
    }
}

struct Sftp {
    root: PathBuf,
}

impl SubsystemHandler for Sftp {
    fn handle(
        &self,
        _user: &str,
        _env: &SessionEnv,
        name: &str,
        stream: ChannelStream,
    ) -> puressh::Result<()> {
        if name == "sftp" {
            // No jail: the URL names the file by its absolute host path.
            let opts = SftpServerOptions::new(self.root.clone());
            let _ = SftpServerSession::new(opts).run(stream);
        }
        Ok(())
    }
}

/// A unique temp directory, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "rsurl-ssh-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A running SFTP server (serving `hello.txt`) plus an isolated `$HOME`.
struct Fixture {
    port: u16,
    /// The server's public host-key blob (SSH wire format).
    blob: Vec<u8>,
    home: TempDir,
    /// Canonical absolute path of the served file.
    file: String,
    _root: TempDir,
}

impl Fixture {
    fn start(tag: &str) -> Self {
        let root = TempDir::new(&format!("{tag}-root"));
        std::fs::write(root.0.join("hello.txt"), BODY).unwrap();
        let file = std::fs::canonicalize(root.0.join("hello.txt"))
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let home = TempDir::new(&format!("{tag}-home"));
        std::fs::create_dir_all(home.0.join(".ssh")).unwrap();

        let mut seed = [0u8; 32];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(tag.len() as u8);
        }
        let hk = Ed25519HostKey::from_seed(seed);
        let blob = hk.public_blob();

        let mut cfg = Config::new(
            vec![Box::new(hk)],
            Arc::new(|| Box::new(PasswordAuth) as Box<dyn Authenticator>),
            vec!["password"],
            Arc::new(NoExec),
        );
        cfg.subsystem_handler = Some(Arc::new(Sftp {
            root: root.0.clone(),
        }));
        let mut server = Server::bind("127.0.0.1:0", cfg).unwrap();
        let port = server.local_addr().unwrap().port();
        // Detached: serves until the test process exits.
        std::thread::spawn(move || {
            let _ = server.serve();
        });
        Fixture {
            port,
            blob,
            home,
            file,
            _root: root,
        }
    }

    fn url(&self) -> String {
        format!("sftp://{USER}:{PASS}@127.0.0.1:{}{}", self.port, self.file)
    }

    fn known_hosts(&self) -> PathBuf {
        self.home.0.join(".ssh").join("known_hosts")
    }

    fn run(&self, extra: &[&str]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rsurl"));
        for var in [
            "http_proxy",
            "https_proxy",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "all_proxy",
            "ALL_PROXY",
        ] {
            cmd.env_remove(var);
        }
        cmd.env("HOME", &self.home.0)
            .env_remove("USERPROFILE")
            .arg("-sS")
            .args(extra)
            .arg(self.url());
        cmd.output().unwrap()
    }

    fn sha256_b64(&self) -> String {
        use purecrypto::hash::{Digest, Sha256};
        b64(Sha256::digest(&self.blob).as_ref())
    }

    fn md5_hex(&self) -> String {
        purecrypto::hash::md5(&self.blob)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk.len();
        let v = (chunk[0] as u32) << 16
            | (*chunk.get(1).unwrap_or(&0) as u32) << 8
            | *chunk.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= n {
                out.push(T[(v >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn assert_ok(o: &Output) {
    assert_eq!(o.status.code(), Some(0), "stderr: {}", stderr(o));
    assert_eq!(o.stdout, BODY);
}

fn assert_hostkey_fail(o: &Output) {
    assert_eq!(o.status.code(), Some(60), "stderr: {}", stderr(o));
    assert!(o.stdout.is_empty());
    assert!(
        stderr(o).contains("host key verification failed"),
        "stderr: {}",
        stderr(o)
    );
}

fn exists(p: &Path) -> bool {
    p.exists()
}

#[test]
fn unknown_host_is_rejected_with_exit_60() {
    let f = Fixture::start("unknown");
    let o = f.run(&[]);
    assert_hostkey_fail(&o);
    // The target is named the known_hosts way for a non-22 port.
    assert!(
        stderr(&o).contains(&format!("[127.0.0.1]:{}", f.port)),
        "stderr: {}",
        stderr(&o)
    );
    assert!(
        !exists(&f.known_hosts()),
        "strict mode must not write known_hosts"
    );

    // An existing known_hosts without this host rejects too.
    std::fs::write(
        f.known_hosts(),
        format!("[127.0.0.1]:1 ssh-ed25519 {}\n", b64(&f.blob)),
    )
    .unwrap();
    assert_hostkey_fail(&f.run(&[]));
}

#[test]
fn known_host_is_accepted() {
    let f = Fixture::start("known");
    std::fs::write(
        f.known_hosts(),
        format!("[127.0.0.1]:{} ssh-ed25519 {}\n", f.port, b64(&f.blob)),
    )
    .unwrap();
    assert_ok(&f.run(&[]));
}

#[test]
fn changed_host_key_is_rejected_even_with_accept_new() {
    let f = Fixture::start("changed");
    let other = Ed25519HostKey::from_seed([0x5a; 32]).public_blob();
    let line = format!("[127.0.0.1]:{} ssh-ed25519 {}\n", f.port, b64(&other));
    std::fs::write(f.known_hosts(), &line).unwrap();
    assert_hostkey_fail(&f.run(&[]));
    assert_hostkey_fail(&f.run(&["--ssh-accept-new"]));
    assert_eq!(std::fs::read_to_string(f.known_hosts()).unwrap(), line);
}

#[test]
fn insecure_skips_check_and_does_not_write_known_hosts() {
    let f = Fixture::start("insecure");
    assert_ok(&f.run(&["-k"]));
    assert!(!exists(&f.known_hosts()), "-k must not write known_hosts");
    // Still unknown afterwards.
    assert_hostkey_fail(&f.run(&[]));
}

#[test]
fn accept_new_trusts_on_first_use_and_saves() {
    let f = Fixture::start("acceptnew");
    assert_ok(&f.run(&["--ssh-accept-new"]));
    let kh = std::fs::read_to_string(f.known_hosts()).unwrap();
    assert!(
        kh.contains(&format!("[127.0.0.1]:{} ssh-ed25519", f.port)),
        "known_hosts: {kh}"
    );
    // Now known: the strict default accepts it.
    assert_ok(&f.run(&[]));
}

#[test]
fn sha256_pin_accepts_match_and_rejects_mismatch() {
    let f = Fixture::start("sha256");
    let pin = f.sha256_b64();
    // A matching pin accepts an unknown host (known_hosts not consulted)...
    assert_ok(&f.run(&["--hostpubsha256", &pin]));
    // ...with or without base64 padding, as in curl.
    assert_ok(&f.run(&["--hostpubsha256", pin.trim_end_matches('=')]));
    assert!(!exists(&f.known_hosts()));
    // A mismatching pin fails, even under -k (curl checks pins regardless).
    let bad = b64(&[0u8; 32]);
    assert_hostkey_fail(&f.run(&["--hostpubsha256", &bad]));
    assert_hostkey_fail(&f.run(&["-k", "--hostpubsha256", &bad]));
    // A pin overrides a matching known_hosts entry, too.
    std::fs::write(
        f.known_hosts(),
        format!("[127.0.0.1]:{} ssh-ed25519 {}\n", f.port, b64(&f.blob)),
    )
    .unwrap();
    assert_hostkey_fail(&f.run(&["--hostpubsha256", &bad]));
}

#[test]
fn md5_pin_accepts_match_and_rejects_mismatch() {
    let f = Fixture::start("md5");
    assert_ok(&f.run(&["--hostpubmd5", &f.md5_hex().to_ascii_uppercase()]));
    assert_hostkey_fail(&f.run(&["--hostpubmd5", &"0".repeat(32)]));
    // Both pins given: both must match.
    assert_hostkey_fail(&f.run(&[
        "--hostpubsha256",
        &f.sha256_b64(),
        "--hostpubmd5",
        &"0".repeat(32),
    ]));
    // Malformed MD5 is a usage error (curl: exactly 32 characters).
    assert_eq!(f.run(&["--hostpubmd5", "abc"]).status.code(), Some(2));
}

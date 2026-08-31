//! Resumable, retrying HTTP downloads.
//!
//! [`download`] / [`Request::download_resumable`] fetch a URL into a file so
//! that a transfer interrupted by a transient fault — a dropped connection, an
//! HTTP/2 `RST_STREAM` / `GOAWAY` mid-body, a read timeout — is retried and
//! *resumed* rather than restarted from byte 0. Progress survives across calls
//! and process restarts via the on-disk [`crate::resume`] container
//! (`<name>.rsurlpart`): a second invocation continues from the persisted
//! offset with a `Range` request.
//!
//! Two modes (see [`DownloadOptions::segment_size`] /
//! [`segments`](DownloadOptions::segments)):
//!
//! * **single-stream** (default) — one open-ended `Range: bytes=<have>-` GET
//!   streamed to disk. Partial bytes are persisted as they arrive, so a
//!   mid-stream error still makes forward progress. Forcing HTTP/1.1
//!   ([`prefer_http11`](DownloadOptions::prefer_http11), the default) keeps the
//!   body streaming off the socket so a reset leaves the received prefix on
//!   disk; on HTTP/2 the body is buffered, so forward progress there comes from
//!   resuming across attempts.
//! * **segmented** — the file is split into chunks (a fixed `segment_size`, or
//!   `segments` equal parts), each fetched by its own `Range` request,
//!   **streamed straight to disk** (never buffered in memory, so a chunk may be
//!   any size), and tracked in a chunk bitmap. Chunks are fetched over up to
//!   [`parallelism`](DownloadOptions::parallelism) concurrent connections. A
//!   chunk that fails is retried on its own — resuming from wherever its stream
//!   broke — without discarding the chunks that already landed. Even a resource
//!   that fits in a single chunk is a valid (resumable) segmented download.
//!   This mode works uniformly over HTTP/1.1 and HTTP/2.
//!
//! There is no `HEAD` pre-flight: a resumed segmented download reads the total
//! size off its `.rsurlpart`, and a fresh one learns it from the first chunk's
//! own `Content-Range` — the first GET carries real data, not a wasted round
//! trip. Both modes capture the resource's validators (URL, `ETag`,
//! `Last-Modified`, total size) in the resume state and send `If-Range`, so a
//! resource that changed between attempts is detected (the server replies `200`
//! with the full body) and the stale partial is discarded rather than spliced. On completion
//! the size (and [`expected_sha256`](DownloadOptions::expected_sha256), if
//! given) are verified before the `.rsurlpart` is atomically renamed into
//! place; a mismatch deletes the partial so the next run starts clean.
//!
//! # Downloading without a file
//!
//! [`download_to_tmp`] / [`fetch_to_tmp`] fetch into a [`TempBlob`] instead of
//! a path: small payloads stay in memory, larger ones spill to an *anonymous*
//! OS file — one with no name in any directory. Nothing is created next to a
//! final path, in particular no `.rsurlpart` sidecar: a temp blob dies with its
//! handle, so there is nothing for a later process to resume and nothing to
//! clean up. Everything else is unchanged — retry, segmentation, parallelism,
//! `max_size`, `expected_sha256`, progress and rate limiting all work the same,
//! because the engine only ever writes at absolute offsets through one storage
//! abstraction (the crate-private `PartStore`) and neither knows nor cares
//! which backing is underneath.

use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use purecrypto::hash::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::http::Request;
use crate::resume::{self, Kind, ResumeState};
use crate::tmpfile::{write_all_at, TempBlob};

/// Progress callback: invoked with `(bytes_on_disk, total)` as the download
/// advances. `total` is `None` until the size is known (and stays `None` for a
/// connection-close-framed response with no `Content-Length`).
pub type ProgressFn = Box<dyn FnMut(u64, Option<u64>) + Send>;

/// Tuning for a resumable download. Start from [`DownloadOptions::default`] and
/// override the fields you care about.
pub struct DownloadOptions {
    /// Maximum retries for a stalled unit of work (a single-stream attempt that
    /// makes no resumable progress, or one segment). The budget is *refreshed*
    /// whenever a retry does make durable forward progress, so a long transfer
    /// over a link that drops repeatedly still completes — only a unit that
    /// cannot advance at all is eventually abandoned. Default: 5.
    pub max_retries: u32,
    /// `Some(size)` selects segmented mode with fixed `size`-byte chunks;
    /// `None` (default) selects single-stream mode. A server without range
    /// support falls back to a single retrying full download either way. A
    /// resource that fits in one chunk is downloaded as a single (resumable)
    /// chunk — segmented mode does not require more than one.
    pub segment_size: Option<u64>,
    /// Segmented mode alternative to [`segment_size`](Self::segment_size): split
    /// the resource into this many equal chunks (computed after its size is
    /// probed), the classic "N parallel connections" model. Takes precedence
    /// over `segment_size`. A resource too small to split usefully is fetched as
    /// a single resumable stream instead.
    ///
    /// This is independent of [`parallelism`](Self::parallelism), and setting it
    /// *higher* than the worker count is usually what you want: chunks are
    /// claimed dynamically, so a plan with spare chunks lets a fast connection
    /// pick up more work while a slow one is still busy. With exactly one chunk
    /// per worker there is nothing left to rebalance and the transfer can only
    /// finish as fast as its slowest segment.
    pub segments: Option<usize>,
    /// Number of concurrent workers in segmented mode — chunks are fetched in
    /// parallel over that many connections, sharing the chunk bitmap. Default 1
    /// (sequential). Ignored in single-stream mode.
    pub parallelism: usize,
    /// Force HTTP/1.1 to dodge HTTP/2 `RST_STREAM` and keep the body streaming
    /// to disk (so a mid-stream reset preserves the received prefix).
    /// Default: `true`.
    pub prefer_http11: bool,
    /// Optional end-to-end integrity check: the finished file must hash to this
    /// SHA-256, else it is deleted and an error returned. Default: `None`.
    pub expected_sha256: Option<[u8; 32]>,
    /// Refuse a resource larger than this many bytes (curl `--max-filesize`).
    pub max_size: Option<u64>,
    /// Per-attempt wall-clock cap (curl `--max-time`), applied to each request.
    pub max_time: Option<Duration>,
    /// Throttle to at most this many bytes/second (curl `--limit-rate`).
    pub limit_rate: Option<u64>,
    /// Abort if the average rate stays below `min` bytes/sec once `secs` have
    /// elapsed (curl `-Y`/`-y`); the download's retry loop then re-attempts.
    ///
    /// In segmented mode this is measured **per connection**, not across the
    /// transfer: a single segment that falls behind is cut and retried on a
    /// fresh connection, which usually lands somewhere healthier and rescues
    /// the transfer. Only if the replacements are just as slow does the
    /// segment's retry budget run out and the download give up — a low-speed
    /// cut deliberately does not refresh that budget, so a link that is simply
    /// slow still fails the way `-Y` promises. `secs` doubles as the socket
    /// read timeout, so a connection that stalls outright is cut within the
    /// window rather than after the default 60s.
    pub low_speed: Option<(u64, u64)>,
    /// First backoff delay; doubles each failed retry up to `max_backoff`.
    pub initial_backoff: Duration,
    /// Ceiling for the exponential backoff between retries.
    pub max_backoff: Duration,
    /// Optional progress callback (see [`ProgressFn`]).
    pub progress: Option<ProgressFn>,
    /// Spill threshold for the temp-blob entry points ([`download_to_tmp`] /
    /// [`fetch_to_tmp`]): a payload this size or smaller stays in memory, a
    /// larger one moves to an anonymous file. `None` uses
    /// [`DEFAULT_SPILL_THRESHOLD`](crate::tmpfile::DEFAULT_SPILL_THRESHOLD)
    /// (1 MiB). Ignored when downloading to a path.
    pub tmp_spill_threshold: Option<u64>,
    /// Directory the temp blob's anonymous file is created in once it spills
    /// (`None` → the OS temp directory). Ignored when downloading to a path.
    pub tmp_dir: Option<PathBuf>,
}

impl Default for DownloadOptions {
    fn default() -> Self {
        DownloadOptions {
            max_retries: 5,
            segment_size: None,
            segments: None,
            parallelism: 1,
            prefer_http11: true,
            expected_sha256: None,
            max_size: None,
            max_time: None,
            limit_rate: None,
            low_speed: None,
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(30),
            progress: None,
            tmp_spill_threshold: None,
            tmp_dir: None,
        }
    }
}

impl std::fmt::Debug for DownloadOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DownloadOptions")
            .field("max_retries", &self.max_retries)
            .field("segment_size", &self.segment_size)
            .field("segments", &self.segments)
            .field("parallelism", &self.parallelism)
            .field("prefer_http11", &self.prefer_http11)
            .field("expected_sha256", &self.expected_sha256.is_some())
            .field("max_size", &self.max_size)
            .field("max_time", &self.max_time)
            .field("limit_rate", &self.limit_rate)
            .field("low_speed", &self.low_speed)
            .field("initial_backoff", &self.initial_backoff)
            .field("max_backoff", &self.max_backoff)
            .field("progress", &self.progress.is_some())
            .field("tmp_spill_threshold", &self.tmp_spill_threshold)
            .field("tmp_dir", &self.tmp_dir)
            .finish()
    }
}

/// What a completed [`download`] produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DownloadOutcome {
    /// Final size of the downloaded file, in bytes.
    pub bytes_written: u64,
    /// The resource's total size, when the server reported it.
    pub total: Option<u64>,
    /// Byte offset a prior partial was resumed from (0 for a fresh download).
    pub resumed_from: u64,
}

/// Fetch `url` into `path`, resuming and retrying on transient faults.
///
/// For `http(s)://` this is a convenience wrapper over
/// [`Request::download_resumable`]. A `data:` URI (RFC 2397) is decoded inline
/// and written to `path` — there is no network transfer to resume, so it is
/// handled here rather than in `download_resumable` (a `data:` URI cannot be a
/// [`Request`]). `max_size` / `expected_sha256` / `progress` still apply.
pub fn download(url: &str, path: &Path, mut opts: DownloadOptions) -> Result<DownloadOutcome> {
    if let Some(decoded) = decode_data_uri(url) {
        let bytes = checked_data_uri(decoded, &mut opts)?;
        let n = bytes.len() as u64;
        std::fs::write(path, &bytes).map_err(Error::Io)?;
        return Ok(DownloadOutcome {
            bytes_written: n,
            total: Some(n),
            resumed_from: 0,
        });
    }
    Request::get(url)?.download_resumable(path, opts)
}

/// Apply the options an inline `data:` payload can honour — size cap, hash
/// check, a single progress tick — to its decoded bytes. There is no transfer
/// to retry or resume, so the rest of [`DownloadOptions`] doesn't apply.
fn checked_data_uri(decoded: Result<Vec<u8>>, opts: &mut DownloadOptions) -> Result<Vec<u8>> {
    let bytes = decoded?;
    let n = bytes.len() as u64;
    if let Some(max) = opts.max_size {
        if n > max {
            return Err(Error::BadResponse("maximum file size exceeded".into()));
        }
    }
    if let Some(want) = opts.expected_sha256 {
        if Sha256::digest(&bytes) != want {
            return Err(Error::BadResponse(
                "data URI failed SHA-256 verification".into(),
            ));
        }
    }
    if let Some(cb) = opts.progress.as_mut() {
        cb(n, Some(n));
    }
    Ok(bytes)
}

/// Fetch `url` into anonymous temporary storage: no path to choose, no file
/// anyone can open by name, and nothing to clean up — dropping the returned
/// [`TempBlob`] releases it.
///
/// The blob is memory-backed while it is small and spills to an anonymous OS
/// file past [`tmp_spill_threshold`](DownloadOptions::tmp_spill_threshold)
/// (1 MiB by default), so the caller reads it the same way either way
/// ([`Read`] + [`std::io::Seek`] + [`read_at`](TempBlob::read_at)) without
/// caring which it got. No `.rsurlpart` sidecar is written: a temp download is scoped to the
/// handle it fills, so cross-process resume has nothing to resume into.
///
/// Retry, segmentation, parallelism, `max_size`, `expected_sha256`, progress
/// and rate limiting behave exactly as they do for [`download`].
pub fn download_to_tmp(url: &str, mut opts: DownloadOptions) -> Result<TempBlob> {
    if let Some(decoded) = decode_data_uri(url) {
        let bytes = checked_data_uri(decoded, &mut opts)?;
        let blob = new_blob(&opts);
        blob.write_at(0, &bytes).map_err(Error::Io)?;
        return Ok(blob);
    }
    Request::get(url)?.download_to_tmp(opts)
}

/// An empty [`TempBlob`] configured from `opts`.
fn new_blob(opts: &DownloadOptions) -> TempBlob {
    let blob = TempBlob::with_threshold(
        opts.tmp_spill_threshold
            .unwrap_or(crate::tmpfile::DEFAULT_SPILL_THRESHOLD),
    );
    match &opts.tmp_dir {
        Some(dir) => blob.in_dir(dir),
        None => blob,
    }
}

/// Fetch any supported URL into `path`, dispatching to the right engine — a
/// single front door over the crate's transfer backends.
///
/// * `http(s)://` and `data:` → the resumable/segmented engine ([`download`]);
///   `DownloadOptions` (retry, segmentation, parallelism, size/hash checks,
///   progress) apply in full.
/// * `ftp(s)://`, `file://`, and the other one-shot schemes (`dict`, `gopher`,
///   `tftp`, `sftp`/`scp`, `ws(s)`, …) → streamed (FTP/file) or buffered to the
///   file. Of `DownloadOptions`, `max_size` / `expected_sha256` / `progress`
///   apply; resume/segmentation do not (those transports aren't range-based).
/// * `magnet:` / BitTorrent → not handled here: it needs tracker/DHT peer
///   discovery. Use [`crate::bittorrent`] directly. Returns
///   [`Error::UnsupportedScheme`].
pub fn fetch_to_file(url: &str, path: &Path, mut opts: DownloadOptions) -> Result<DownloadOutcome> {
    match url_scheme(url).as_deref() {
        // `data:` is recognised by prefix; `download` handles it and http(s).
        Some("data") | Some("http") | Some("https") => download(url, path, opts),
        Some("magnet") => Err(Error::UnsupportedScheme(
            "magnet: use the bittorrent module (front door has no peer discovery)".into(),
        )),
        Some(_) => {
            let n = fetch_via_transfer(url, path, &mut opts)?;
            Ok(DownloadOutcome {
                bytes_written: n,
                total: Some(n),
                resumed_from: 0,
            })
        }
        None => Err(Error::InvalidUrl(url.to_string())),
    }
}

/// Lower-cased URI scheme (the token before the first `:`), or `None` if `url`
/// has no valid scheme.
fn url_scheme(url: &str) -> Option<String> {
    let colon = url.find(':')?;
    let scheme = &url[..colon];
    if scheme.is_empty()
        || !scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    {
        return None;
    }
    Some(scheme.to_ascii_lowercase())
}

/// [`fetch_to_file`]'s temp-blob twin: fetch any supported URL into anonymous
/// temporary storage. Same dispatch and same option coverage per scheme — see
/// [`download_to_tmp`] for what the temp target does and does not carry.
pub fn fetch_to_tmp(url: &str, mut opts: DownloadOptions) -> Result<TempBlob> {
    match url_scheme(url).as_deref() {
        Some("data") | Some("http") | Some("https") => download_to_tmp(url, opts),
        Some("magnet") => Err(Error::UnsupportedScheme(
            "magnet: use the bittorrent module (front door has no peer discovery)".into(),
        )),
        Some(_) => {
            let mut parsed = crate::url::Url::parse(url)?;
            parsed.set_idn(true)?;
            let mut blob = new_blob(&opts);
            let n = crate::transfer::transfer_url_to_with(
                &parsed,
                &crate::net::NetConfig::default(),
                &mut blob,
            )?;
            one_shot_checks(
                n,
                &mut opts,
                |len| hash_blob_prefix(&blob, len),
                || {
                    let _ = blob.set_len(0);
                },
            )?;
            Ok(blob)
        }
        None => Err(Error::InvalidUrl(url.to_string())),
    }
}

/// Stream/buffer a non-HTTP scheme to `path` via the universal
/// [`crate::transfer`] dispatcher, applying the size/hash/progress options that
/// make sense there.
fn fetch_via_transfer(url: &str, path: &Path, opts: &mut DownloadOptions) -> Result<u64> {
    let mut parsed = crate::url::Url::parse(url)?;
    parsed.set_idn(true)?;
    let n = {
        let mut file = std::fs::File::create(path).map_err(Error::Io)?;
        crate::transfer::transfer_url_to_with(
            &parsed,
            &crate::net::NetConfig::default(),
            &mut file,
        )?
    };
    one_shot_checks(
        n,
        opts,
        |len| hash_prefix(path, len),
        || {
            let _ = std::fs::remove_file(path);
        },
    )?;
    Ok(n)
}

/// The post-transfer policy shared by the one-shot (non-range-based) schemes:
/// size cap, optional SHA-256, and the single progress tick. `discard` throws
/// away what landed when a check fails, so a rejected transfer leaves nothing
/// usable behind.
fn one_shot_checks(
    n: u64,
    opts: &mut DownloadOptions,
    hash: impl FnOnce(u64) -> io::Result<[u8; 32]>,
    discard: impl FnOnce(),
) -> Result<()> {
    if let Some(max) = opts.max_size {
        if n > max {
            discard();
            return Err(Error::BadResponse("maximum file size exceeded".into()));
        }
    }
    if let Some(want) = opts.expected_sha256 {
        match hash(n) {
            Ok(got) if got == want => {}
            Ok(_) => {
                discard();
                return Err(Error::BadResponse(
                    "downloaded file failed SHA-256 verification".into(),
                ));
            }
            Err(e) => return Err(Error::Io(e)),
        }
    }
    if let Some(cb) = opts.progress.as_mut() {
        cb(n, Some(n));
    }
    Ok(())
}

/// Decode a `data:` URI (RFC 2397) into its bytes. Returns `None` if `url` is
/// not a `data:` URI (so the caller falls through to a network fetch), or
/// `Some(Err(..))` if it is one but malformed.
///
/// Grammar: `data:[<mediatype>][;base64],<data>` — a `;base64` marker selects
/// base64, otherwise the data is percent-decoded.
fn decode_data_uri(url: &str) -> Option<Result<Vec<u8>>> {
    let b = url.as_bytes();
    if b.len() < 5 || !b[..5].eq_ignore_ascii_case(b"data:") {
        return None;
    }
    let rest = &url[5..];
    let Some((meta, data)) = rest.split_once(',') else {
        return Some(Err(Error::InvalidUrl(
            "data URI missing ',' separator".into(),
        )));
    };
    let is_base64 = meta
        .split(';')
        .any(|token| token.trim().eq_ignore_ascii_case("base64"));
    let bytes = if is_base64 {
        match crate::tls::client_auth::base64_decode(data) {
            Some(b) => b,
            None => return Some(Err(Error::InvalidUrl("invalid base64 in data URI".into()))),
        }
    } else {
        percent_decode_to_bytes(data)
    };
    Some(Ok(bytes))
}

/// Percent-decode `s` into raw bytes (a `data:` URI's non-base64 payload can
/// encode arbitrary octets via `%XX`).
fn percent_decode_to_bytes(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 3 <= b.len() {
            if let (Some(h), Some(l)) = (hex_nibble(b[i + 1]), hex_nibble(b[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

impl Request {
    /// Perform this request as a resumable, retrying download into `path`.
    ///
    /// The request's method/headers/auth are preserved; the download layer adds
    /// range/validator handling, forces raw (undecoded) bytes so offsets stay
    /// byte-aligned, and follows redirects. See the [module docs](mod@crate::download).
    pub fn download_resumable(self, path: &Path, opts: DownloadOptions) -> Result<DownloadOutcome> {
        Downloader::new(self, Arc::new(FileStore::new(path)), opts).run()
    }

    /// Perform this request as a download into anonymous temporary storage —
    /// [`download_to_tmp`]'s `Request`-level form, the way
    /// [`download_resumable`](Self::download_resumable) is [`download`]'s.
    pub fn download_to_tmp(self, opts: DownloadOptions) -> Result<TempBlob> {
        let blob = Arc::new(new_blob(&opts));
        // The engine holds the only other reference, through the store it is
        // handed here; it is dropped by the time `run` returns.
        let store = Arc::new(TmpStore {
            blob: Arc::clone(&blob),
        });
        Downloader::new(self, store, opts).run()?;
        Arc::try_unwrap(blob)
            .map_err(|_| Error::Io(io::Error::other("temp blob still shared after download")))
    }
}

// ---- where the bytes land ---------------------------------------------------

/// Storage for an in-flight download.
///
/// The engine never seeks a shared cursor and never opens anything by name
/// mid-transfer: it writes at absolute offsets and asks the store to persist,
/// verify and publish. That is what lets one retry/segmentation implementation
/// drive both a `.rsurlpart` on disk ([`FileStore`]) and an anonymous
/// [`TempBlob`] with no name at all ([`TmpStore`]).
trait PartStore: Send + Sync {
    /// Write all of `buf` at absolute offset `at`. Called concurrently by
    /// segment workers, on disjoint ranges.
    fn write_at(&self, at: u64, buf: &[u8]) -> io::Result<()>;

    /// Size the data region to `n` — sparse where the backing allows, and
    /// truncating when `n` is smaller than what is held.
    fn set_len(&self, n: u64) -> io::Result<()>;

    /// Throw away everything written so far (a partial that can't be spliced).
    fn discard(&self);

    /// SHA-256 over the first `len` bytes held.
    fn hash_prefix(&self, len: u64) -> io::Result<[u8; 32]>;

    /// Publish the finished download: `real_size` bytes are final.
    fn finalize(&self, real_size: u64) -> io::Result<()>;

    /// Persist resume state for a *later process*. Stores whose bytes die with
    /// the handle leave this a no-op — which is exactly why a temp download
    /// writes no `.rsurlpart` sidecar.
    fn save_state(&self, real_size: u64, kind: Kind, meta: &[u8]) {
        let _ = (real_size, kind, meta);
    }

    /// Resume state left by an earlier run, if this store can carry any.
    fn load_state(&self) -> Option<ResumeState> {
        None
    }
}

/// The named target: a `<name>.rsurlpart` beside the final path, atomically
/// renamed into place on completion.
///
/// The part file is opened once, lazily, and written positionally from then on
/// — so a download that fails before its first byte (a `404`, a refused
/// connection) leaves no stray partial, and segment workers no longer reopen
/// the file per chunk. The handle is dropped before any rename or unlink, since
/// Windows will not move or delete a file out from under one.
struct FileStore {
    final_path: PathBuf,
    part: PathBuf,
    handle: RwLock<Option<File>>,
}

impl FileStore {
    fn new(path: &Path) -> Self {
        FileStore {
            final_path: path.to_path_buf(),
            part: resume::part_path(path),
            handle: RwLock::new(None),
        }
    }

    /// Run `f` against the part file, opening (creating) it on first use.
    fn with_file<R>(&self, f: impl FnOnce(&File) -> io::Result<R>) -> io::Result<R> {
        {
            let g = self.handle.read().unwrap_or_else(|e| e.into_inner());
            if let Some(fh) = g.as_ref() {
                return f(fh);
            }
        }
        let mut g = self.handle.write().unwrap_or_else(|e| e.into_inner());
        if g.is_none() {
            *g = Some(
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(&self.part)?,
            );
        }
        match g.as_ref() {
            Some(fh) => f(fh),
            None => Err(io::Error::other("part file handle vanished")),
        }
    }

    /// Release the cached handle so the part file can be renamed or removed.
    fn close_handle(&self) {
        *self.handle.write().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

impl PartStore for FileStore {
    fn write_at(&self, at: u64, buf: &[u8]) -> io::Result<()> {
        self.with_file(|f| write_all_at(f, at, buf))
    }

    fn set_len(&self, n: u64) -> io::Result<()> {
        self.with_file(|f| f.set_len(n))
    }

    fn discard(&self) {
        self.close_handle();
        let _ = std::fs::remove_file(&self.part);
    }

    fn hash_prefix(&self, len: u64) -> io::Result<[u8; 32]> {
        hash_prefix(&self.part, len)
    }

    fn finalize(&self, real_size: u64) -> io::Result<()> {
        self.close_handle();
        resume::finalize(&self.part, &self.final_path, real_size)
    }

    fn save_state(&self, real_size: u64, kind: Kind, meta: &[u8]) {
        let _ = resume::write_state(&self.part, real_size, kind, meta);
    }

    fn load_state(&self) -> Option<ResumeState> {
        resume::read_state(&self.part).ok().flatten()
    }
}

/// The anonymous target: a [`TempBlob`] (memory, or an unnamed OS file once it
/// grows). Nothing exists on disk to name, resume from, or clean up, so
/// `save_state`/`load_state` stay at their no-op defaults and "finalize" is
/// just a truncation to the real size.
struct TmpStore {
    blob: Arc<TempBlob>,
}

impl PartStore for TmpStore {
    fn write_at(&self, at: u64, buf: &[u8]) -> io::Result<()> {
        self.blob.write_at(at, buf)
    }

    fn set_len(&self, n: u64) -> io::Result<()> {
        self.blob.set_len(n)
    }

    fn discard(&self) {
        let _ = self.blob.set_len(0);
    }

    fn hash_prefix(&self, len: u64) -> io::Result<[u8; 32]> {
        hash_blob_prefix(&self.blob, len)
    }

    fn finalize(&self, real_size: u64) -> io::Result<()> {
        self.blob.set_len(real_size)
    }
}

/// Captured resource validators used to detect an upstream change between
/// attempts. The URL guards against a stale partial left at the same output
/// path by a *different* download.
#[derive(Clone, Default, PartialEq, Eq)]
struct Validators {
    url: String,
    etag: String,
    last_modified: String,
}

impl Validators {
    /// The value to send as `If-Range` (prefer the strong `ETag`).
    fn if_range(&self) -> Option<&str> {
        if !self.etag.is_empty() {
            Some(&self.etag)
        } else if !self.last_modified.is_empty() {
            Some(&self.last_modified)
        } else {
            None
        }
    }
}

struct Downloader {
    /// Prepared request template (redirects on, decompression off, HTTP/1.1 if
    /// preferred). Cloned per attempt.
    base: Request,
    /// Where the bytes land: a `.rsurlpart` on disk, or a temp blob.
    store: Arc<dyn PartStore>,
    url_key: String,
    opts: DownloadOptions,
}

/// The result of one streaming GET attempt in single-stream mode.
enum Attempt {
    /// The body reached its end; the file holds `written` bytes.
    Done { written: u64, total: Option<u64> },
    /// A transient failure after writing up to `written` bytes on disk.
    /// `resumable` is true when those bytes can be continued with a `Range`
    /// (a `206` response) — only then does progress refresh the retry budget.
    Transient {
        written: u64,
        resumable: bool,
        err: Error,
    },
    /// A permanent failure; do not retry.
    Fatal(Error),
}

/// Outcome of the segmented path that isn't a finished download.
enum SegErr {
    /// The server does not support ranges — fall back to single-stream.
    Fallback,
    /// A permanent failure.
    Fatal(Error),
}

/// What the fresh-download bootstrap GET produced.
enum Bootstrap {
    /// No range support (or a resource small enough to fit one open stream):
    /// the whole body of `n` bytes was streamed straight to disk.
    Full(u64),
    /// A range-capable resource: the total is known, chunk 0 is on disk, and
    /// the remaining chunks can be fetched.
    Ranged {
        total: u64,
        validators: Validators,
        chunk_key: u32,
        plan: Vec<(u64, u64)>,
        bitmap: Vec<u8>,
    },
}

impl Downloader {
    fn new(req: Request, store: Arc<dyn PartStore>, opts: DownloadOptions) -> Self {
        let url = req.url();
        let url_key = format!("{}://{}:{}{}", url.scheme, url.host, url.port, url.path);
        // Raw bytes (offsets must stay byte-aligned across ranged requests) and
        // follow redirects. Force HTTP/1.1 when asked, to dodge H2 RST_STREAM
        // and keep the body streaming to disk.
        let mut base = req.follow_redirects(true).decompress(false);
        if opts.prefer_http11 {
            base = base.http11_only();
        }
        if let Some(t) = opts.max_time {
            base = base.max_time(t);
        }
        // A `-y` window is also how long we are willing to sit on a silent
        // socket: cap the read timeout at it so a connection that stalls
        // outright is cut and retried inside the window instead of after the
        // default 60s.
        if let Some((_, secs)) = opts.low_speed {
            base = base.read_timeout(Some(Duration::from_secs(secs.max(1))));
        }
        Downloader {
            base,
            store,
            url_key,
            opts,
        }
    }

    fn run(mut self) -> Result<DownloadOutcome> {
        let segmented =
            self.opts.segments.is_some() || self.opts.segment_size.is_some_and(|s| s > 0);
        if segmented {
            match self.run_segmented() {
                Ok(outcome) => return Ok(outcome),
                Err(SegErr::Fatal(e)) => return Err(e),
                Err(SegErr::Fallback) => { /* single-stream below */ }
            }
        }
        self.run_single()
    }

    // ---- single-stream mode ------------------------------------------------

    fn run_single(&mut self) -> Result<DownloadOutcome> {
        let (mut have, mut validators) = self.load_stream_state();
        let resumed_from = have;
        let mut budget = self.opts.max_retries;
        let mut attempt_no: u32 = 0;

        loop {
            match self.attempt_single(have, &mut validators) {
                Attempt::Done { written, total } => {
                    self.verify_and_finalize(written, total)?;
                    return Ok(DownloadOutcome {
                        bytes_written: written,
                        total,
                        resumed_from,
                    });
                }
                Attempt::Fatal(e) => return Err(e),
                Attempt::Transient {
                    written,
                    resumable,
                    err,
                } => {
                    let progressed = resumable && written > have;
                    if resumable {
                        have = written;
                    }
                    if progressed {
                        budget = self.opts.max_retries;
                    } else if budget == 0 {
                        return Err(err);
                    } else {
                        budget -= 1;
                    }
                    attempt_no += 1;
                    self.backoff(attempt_no);
                }
            }
        }
    }

    /// Run one GET (ranged when `have > 0`) and stream its body to the part
    /// file, updating `validators` if the server returned a full body.
    fn attempt_single(&mut self, have: u64, validators: &mut Validators) -> Attempt {
        let mut req = self.base.clone();
        if have > 0 {
            req = req.header("Range", &format!("bytes={have}-"));
            if let Some(v) = validators.if_range() {
                req = req.header("If-Range", v);
            }
        }
        let reader = match req.send_reader() {
            Ok(r) => r,
            Err(e) => {
                return classify_pre_body(e, have);
            }
        };
        let status = reader.status();

        // Already complete: the range is unsatisfiable because we hold it all.
        if status == 416 {
            return Attempt::Done {
                written: have,
                total: Some(have),
            };
        }
        if (300..400).contains(&status) {
            // Redirects are followed internally; a surviving 3xx is a dead end.
            return Attempt::Fatal(Error::BadResponse(format!(
                "unexpected redirect status {status}"
            )));
        }
        if (400..500).contains(&status) {
            return Attempt::Fatal(status_error(status, &reader));
        }
        if status >= 500 {
            return Attempt::Transient {
                written: have,
                resumable: false,
                err: status_error(status, &reader),
            };
        }

        // 2xx. Decide the write offset and total.
        let (offset, total, resumable) = if status == 206 {
            match parse_content_range(reader.header("content-range")) {
                Some((start, tot)) if start == have => (have, tot, true),
                // The server's range doesn't line up with what we hold; discard
                // and restart from zero on the next attempt.
                _ => {
                    self.store.discard();
                    return Attempt::Transient {
                        written: 0,
                        resumable: false,
                        err: Error::BadResponse("range offset mismatch on resume".into()),
                    };
                }
            }
        } else {
            // 200: full body. Restart at 0 and refresh validators from this
            // response. The bytes are resumable only for a *fresh* download
            // against a range-capable server: if we sent a Range (have > 0) and
            // still got 200, the server ignored it, so a retry can't continue
            // from an offset and must not refresh the retry budget.
            *validators = self.validators_from(&reader);
            let total = reader
                .header("content-length")
                .and_then(|v| v.trim().parse::<u64>().ok());
            let accepts_ranges = reader
                .header("accept-ranges")
                .is_some_and(|v| v.to_ascii_lowercase().contains("bytes"));
            (0, total, have == 0 && accepts_ranges)
        };

        if let Some(max) = self.opts.max_size {
            if total.is_some_and(|t| t > max) {
                return Attempt::Fatal(Error::BadResponse("maximum file size exceeded".into()));
            }
        }

        self.stream_to_store(reader, offset, total, validators, resumable)
    }

    /// Copy the body reader into the store starting at `offset`, applying
    /// rate/size/low-speed policies and persisting resume state periodically.
    fn stream_to_store(
        &mut self,
        mut reader: crate::http::BodyReader,
        offset: u64,
        total: Option<u64>,
        validators: &Validators,
        resumable: bool,
    ) -> Attempt {
        // Size the data region so a part file's trailer/meta never overlaps
        // real data (and so a file-backed target stays sparse until bytes land).
        if let Some(t) = total {
            if let Err(e) = self.store.set_len(t) {
                return Attempt::Fatal(Error::Io(e));
            }
        } else if offset == 0 {
            // Unknown length, fresh body: drop any stale bytes.
            let _ = self.store.set_len(0);
        }

        let started = Instant::now();
        let mut last_save = started;
        let mut written = offset;
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    self.persist_stream(total, written, validators);
                    return Attempt::Transient {
                        written,
                        resumable,
                        err: Error::Io(e),
                    };
                }
            };
            if let Some(max) = self.opts.max_size {
                if written + n as u64 > max {
                    return Attempt::Fatal(Error::BadResponse("maximum file size exceeded".into()));
                }
            }
            // Rate limiting: sleep so the running average stays under the cap.
            if let Some(rate) = self.opts.limit_rate.filter(|r| *r > 0) {
                let target =
                    Duration::from_secs_f64((written + n as u64 - offset) as f64 / rate as f64);
                let elapsed = started.elapsed();
                if target > elapsed {
                    std::thread::sleep(target - elapsed);
                }
            }
            if let Err(e) = self.store.write_at(written, &buf[..n]) {
                self.persist_stream(total, written, validators);
                return Attempt::Transient {
                    written,
                    resumable,
                    err: Error::Io(e),
                };
            }
            written += n as u64;
            if let Some(cb) = self.opts.progress.as_mut() {
                cb(written, total);
            }
            // Low-speed abort → treated as transient so the retry loop re-tries.
            if let Some((min, secs)) = self.opts.low_speed {
                let el = started.elapsed().as_secs();
                if el >= secs && (written - offset) / el.max(1) < min {
                    self.persist_stream(total, written, validators);
                    return Attempt::Transient {
                        written,
                        resumable,
                        err: low_speed_error(),
                    };
                }
            }
            if last_save.elapsed() >= Duration::from_secs(1) {
                self.persist_stream(total, written, validators);
                last_save = Instant::now();
            }
        }

        // Clean EOF. With a known total, the length-framed reader guarantees we
        // received every byte; otherwise the stream's end is the file's end.
        Attempt::Done {
            written,
            total: total.or(Some(written)),
        }
    }

    /// Persist the single-stream resume trailer (no-op if total is unknown,
    /// since a length-less body can't be range-resumed).
    fn persist_stream(&self, total: Option<u64>, done: u64, validators: &Validators) {
        if let Some(total) = total {
            let meta = stream_meta(total, done, validators);
            self.store.save_state(total, Kind::HttpStream, &meta);
        }
    }

    /// Load a prior single-stream offset + validators, if the partial matches
    /// this resource.
    fn load_stream_state(&self) -> (u64, Validators) {
        if let Some(st) = self.store.load_state() {
            if st.kind == Kind::HttpStream {
                if let Some((done, v)) = parse_stream_meta(&st.meta) {
                    if v.url == self.url_key && done <= st.real_size {
                        return (done, v);
                    }
                }
            }
        }
        (0, Validators::default())
    }

    // ---- segmented mode ----------------------------------------------------

    fn run_segmented(&mut self) -> std::result::Result<DownloadOutcome, SegErr> {
        // The meter owns the progress callback for the duration of the
        // segmented run: it aggregates the bytes every worker lands (including
        // the chunks still in flight) and enforces the transfer-wide rate
        // limit. Hand the callback back on the way out so a single-stream
        // fallback keeps reporting.
        let meter = Arc::new(ByteMeter::new(
            self.opts.progress.take(),
            self.opts.limit_rate,
            self.opts.low_speed,
        ));
        let out = self.run_segmented_metered(&meter);
        meter.report(true);
        self.opts.progress = meter.take_cb();
        out
    }

    fn run_segmented_metered(
        &mut self,
        meter: &Arc<ByteMeter>,
    ) -> std::result::Result<DownloadOutcome, SegErr> {
        // There is NO HEAD probe. Everything we need — total size, range
        // support, validators — is learned either from the on-disk `.rsurlpart`
        // (resume) or from the first chunk's own GET (fresh). The first GET is
        // real data, not a wasted round trip.
        let (total, validators, chunk_key, plan, bitmap, resumed_from) =
            if let Some((total, validators, chunk_key, plan, bitmap)) = self.resume_ranged() {
                // Resume: the total + validators + chunk bitmap are on disk.
                let done = plan_done_bytes(&plan, &bitmap);
                meter.set_total(total);
                meter.seed(done);
                (total, validators, chunk_key, plan, bitmap, done)
            } else {
                // Fresh: the first GET reveals the total and downloads chunk 0.
                match self.bootstrap(meter)? {
                    Bootstrap::Full(written) => {
                        // No range support (or a resource that fits in one open
                        // stream): the whole body is already on disk.
                        self.verify_and_finalize(written, Some(written))
                            .map_err(SegErr::Fatal)?;
                        return Ok(DownloadOutcome {
                            bytes_written: written,
                            total: Some(written),
                            resumed_from: 0,
                        });
                    }
                    // A fresh download resumed nothing: the bootstrap chunk is
                    // progress made *this* run, not bytes off a prior partial.
                    Bootstrap::Ranged {
                        total,
                        validators,
                        chunk_key,
                        plan,
                        bitmap,
                    } => (total, validators, chunk_key, plan, bitmap, 0),
                }
            };

        self.run_chunks(&plan, total, chunk_key, &validators, bitmap, meter)?;
        self.verify_and_finalize(total, Some(total))
            .map_err(SegErr::Fatal)?;
        Ok(DownloadOutcome {
            bytes_written: total,
            total: Some(total),
            resumed_from,
        })
    }

    /// Resume a segmented download entirely from the on-disk `.rsurlpart` — no
    /// network probe. Returns `None` (→ a fresh bootstrap) when there is no
    /// matching prior partial for this resource and chunk layout.
    #[allow(clippy::type_complexity)]
    fn resume_ranged(&self) -> Option<(u64, Validators, u32, Vec<(u64, u64)>, Vec<u8>)> {
        let st = self.store.load_state()?;
        if st.kind != Kind::HttpRanged {
            return None;
        }
        let total = st.real_size;
        let (stored_key, validators, bitmap) = parse_ranged_full(&st.meta)?;
        if validators.url != self.url_key {
            return None;
        }
        // Recompute the layout for the current options; it must line up with
        // what the partial was written against.
        let (chunk_key, plan) = self.chunk_plan(total).ok()?;
        if chunk_key != stored_key || bitmap.len() != plan.len().div_ceil(8) {
            return None;
        }
        Some((total, validators, chunk_key, plan, bitmap))
    }

    /// Start a fresh segmented download: a single GET whose response reveals the
    /// total (from `Content-Range`) and carries the first chunk's bytes. A `200`
    /// (no range support) streams the whole body instead.
    fn bootstrap(&mut self, meter: &ByteMeter) -> std::result::Result<Bootstrap, SegErr> {
        let mut budget = self.opts.max_retries;
        let mut attempt_no = 0u32;
        loop {
            // Open-ended so it works before we know the total; we cap what we
            // read per chunk ourselves.
            let req = self.base.clone().header("Range", "bytes=0-");
            let mut reader = match req.send_reader() {
                Ok(r) => r,
                Err(e) if is_transient(&e) && budget > 0 => {
                    budget -= 1;
                    attempt_no += 1;
                    self.backoff(attempt_no);
                    continue;
                }
                Err(e) => return Err(SegErr::Fatal(e)),
            };

            let status = reader.status();
            if status == 200 {
                // No range support: stream the whole body as a plain download.
                let total = reader
                    .header("content-length")
                    .and_then(|v| v.trim().parse::<u64>().ok());
                if let Some(max) = self.opts.max_size {
                    if total.is_some_and(|t| t > max) {
                        return Err(SegErr::Fatal(Error::BadResponse(
                            "maximum file size exceeded".into(),
                        )));
                    }
                }
                self.prepare_part(total)?;
                if let Some(t) = total {
                    meter.set_total(t);
                }
                let p = pump_to_store(
                    &mut reader,
                    self.store.as_ref(),
                    0,
                    total.unwrap_or(u64::MAX),
                    Some(meter),
                );
                if let Some(e) = p.err {
                    if budget == 0 {
                        return Err(SegErr::Fatal(e));
                    }
                    // This path retries the whole body from offset 0, so the
                    // bytes it just wrote are about to be written again.
                    meter.rewind(p.wrote);
                    budget -= 1;
                    attempt_no += 1;
                    self.backoff(attempt_no);
                    continue;
                }
                return Ok(Bootstrap::Full(p.wrote));
            }
            if status == 416 {
                // Empty resource.
                self.prepare_part(Some(0))?;
                return Ok(Bootstrap::Full(0));
            }
            if (400..500).contains(&status) {
                return Err(SegErr::Fatal(status_error(status, &reader)));
            }
            if status >= 500 {
                if budget == 0 {
                    return Err(SegErr::Fatal(status_error(status, &reader)));
                }
                budget -= 1;
                attempt_no += 1;
                self.backoff(attempt_no);
                continue;
            }
            if status != 206 {
                return Err(SegErr::Fatal(Error::BadResponse(format!(
                    "unexpected status {status}"
                ))));
            }

            // 206: learn the total from Content-Range.
            let total = match parse_content_range(reader.header("content-range")) {
                Some((_, Some(t))) => t,
                _ => return Err(SegErr::Fallback), // no usable total → single-stream
            };
            if total == 0 {
                self.prepare_part(Some(0))?;
                return Ok(Bootstrap::Full(0));
            }
            if let Some(max) = self.opts.max_size {
                if total > max {
                    return Err(SegErr::Fatal(Error::BadResponse(
                        "maximum file size exceeded".into(),
                    )));
                }
            }
            meter.set_total(total);
            let validators = self.validators_from(&reader);
            let (chunk_key, plan) = match self.chunk_plan(total) {
                Ok(x) => x,
                // Too small to split: this open 206 stream is the whole file.
                Err(SegErr::Fallback) => {
                    self.prepare_part(Some(total))?;
                    let p = pump_to_store(&mut reader, self.store.as_ref(), 0, total, Some(meter));
                    if let Some(e) = p.err {
                        if budget == 0 {
                            return Err(SegErr::Fatal(e));
                        }
                        // Retried from offset 0; un-count the partial attempt.
                        meter.rewind(p.wrote);
                        budget -= 1;
                        attempt_no += 1;
                        self.backoff(attempt_no);
                        continue;
                    }
                    return Ok(Bootstrap::Full(p.wrote));
                }
                Err(e) => return Err(e),
            };

            self.prepare_part(Some(total))?;
            let map_len = plan.len().div_ceil(8);
            let mut bitmap = vec![0u8; map_len];

            // Stream chunk 0 from this open response, then finish it (byte-level
            // resume within the chunk) if the stream broke early.
            let (_, end0) = plan[0];
            let want0 = end0 + 1;
            let got0 = pump_to_store(&mut reader, self.store.as_ref(), 0, want0, Some(meter)).wrote;
            drop(reader);
            if got0 < want0 {
                match fetch_chunk_streaming(
                    &self.base,
                    self.store.as_ref(),
                    got0,
                    end0,
                    &validators.etag,
                    self.retry(),
                    meter,
                ) {
                    ChunkResult::Ok => {}
                    ChunkResult::Fallback => return Err(SegErr::Fallback),
                    ChunkResult::Fatal(e) => return Err(SegErr::Fatal(e)),
                }
            }
            bit_set(&mut bitmap, 0);
            self.persist_ranged(chunk_key, total, &validators, &bitmap);
            meter.report(true);
            return Ok(Bootstrap::Ranged {
                total,
                validators,
                chunk_key,
                plan,
                bitmap,
            });
        }
    }

    /// Size the store's data region to `total` so chunk writes have somewhere
    /// to land at their offsets.
    fn prepare_part(&self, total: Option<u64>) -> std::result::Result<(), SegErr> {
        if let Some(t) = total {
            self.store
                .set_len(t)
                .map_err(|e| SegErr::Fatal(Error::Io(e)))?;
        }
        Ok(())
    }

    /// Build the chunk layout. [`segments`](DownloadOptions::segments) (N equal
    /// parts, last takes the remainder) wins over a fixed
    /// [`segment_size`](DownloadOptions::segment_size). Returns the chunk key
    /// stored in the resume meta and the `(start, end)` ranges. A resource too
    /// small to split into the requested number of parts falls back to a single
    /// resumable stream.
    fn chunk_plan(&self, total: u64) -> std::result::Result<(u32, Vec<(u64, u64)>), SegErr> {
        if let Some(n_req) = self.opts.segments {
            let by_size = total.div_ceil(MIN_SEGMENT_BYTES).max(1) as usize;
            let upper = by_size.clamp(1, MAX_SEGMENT_CHUNKS);
            let n = n_req.clamp(1, upper);
            if n < 2 {
                // Not worth splitting — a single resumable stream is as good.
                return Err(SegErr::Fallback);
            }
            let seg = total / n as u64;
            let plan = (0..n)
                .map(|i| {
                    let start = i as u64 * seg;
                    let end = if i == n - 1 {
                        total - 1
                    } else {
                        (i as u64 + 1) * seg - 1
                    };
                    (start, end)
                })
                .collect();
            Ok((seg.min(u32::MAX as u64) as u32, plan))
        } else if let Some(size) = self.opts.segment_size.filter(|s| *s > 0) {
            let n = total.div_ceil(size) as usize;
            let plan = (0..n)
                .map(|i| {
                    let start = i as u64 * size;
                    let end = (start + size).min(total) - 1;
                    (start, end)
                })
                .collect();
            Ok((size.min(u32::MAX as u64) as u32, plan))
        } else {
            Err(SegErr::Fallback)
        }
    }

    /// Drive the plan's chunks to completion with up to
    /// [`parallelism`](DownloadOptions::parallelism) workers sharing the chunk
    /// bitmap. Each chunk streams straight to disk and is retried independently
    /// (resuming from where its stream broke); a chunk the server answers `200`
    /// for (no range support) aborts to a single-stream fallback.
    fn run_chunks(
        &mut self,
        plan: &[(u64, u64)],
        total: u64,
        chunk_key: u32,
        validators: &Validators,
        bitmap: Vec<u8>,
        meter: &Arc<ByteMeter>,
    ) -> std::result::Result<(), SegErr> {
        let num_chunks = plan.len();
        let workers = self
            .opts
            .parallelism
            .clamp(1, num_chunks.max(1))
            .min(MAX_SEGMENT_WORKERS);

        let plan: Arc<Vec<(u64, u64)>> = Arc::new(plan.to_vec());
        let bitmap = Arc::new(Mutex::new(bitmap));
        let next = Arc::new(AtomicUsize::new(0));
        let failed: Arc<Mutex<Option<Error>>> = Arc::new(Mutex::new(None));
        let fallback = Arc::new(AtomicBool::new(false));
        let validators = Arc::new(validators.clone());
        // `If-Range` guards every chunk request: if the resource changed since
        // we learned its size/validators, the server answers `200` instead of
        // `206` and we restart rather than splice mismatched bytes.
        let if_range = Arc::new(validators.etag.clone());
        let retry = self.retry();

        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            let plan = Arc::clone(&plan);
            let bitmap = Arc::clone(&bitmap);
            let next = Arc::clone(&next);
            let failed = Arc::clone(&failed);
            let fallback = Arc::clone(&fallback);
            let meter = Arc::clone(meter);
            let store = Arc::clone(&self.store);
            let validators = Arc::clone(&validators);
            let if_range = Arc::clone(&if_range);
            let base = self.base.clone();
            handles.push(std::thread::spawn(move || loop {
                if failed.lock().unwrap().is_some() || fallback.load(Ordering::Relaxed) {
                    break;
                }
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= num_chunks {
                    break;
                }
                if bit_get(&bitmap.lock().unwrap(), i) {
                    continue;
                }
                let (start, end) = plan[i];
                match fetch_chunk_streaming(
                    &base,
                    store.as_ref(),
                    start,
                    end,
                    &if_range,
                    retry,
                    &meter,
                ) {
                    ChunkResult::Ok => {
                        let mut bm = bitmap.lock().unwrap();
                        bit_set(&mut bm, i);
                        let meta = ranged_meta(chunk_key as u64, total, &validators, &bm);
                        store.save_state(total, Kind::HttpRanged, &meta);
                        drop(bm);
                        meter.report(true);
                    }
                    ChunkResult::Fallback => fallback.store(true, Ordering::Relaxed),
                    ChunkResult::Fatal(e) => *failed.lock().unwrap() = Some(e),
                }
            }));
        }
        for h in handles {
            let _ = h.join();
        }

        if let Some(e) = Arc::try_unwrap(failed)
            .ok()
            .and_then(|m| m.into_inner().ok())
            .flatten()
        {
            return Err(SegErr::Fatal(e));
        }
        if fallback.load(Ordering::Relaxed) {
            return Err(SegErr::Fallback);
        }
        Ok(())
    }

    fn persist_ranged(&self, chunk: u32, total: u64, validators: &Validators, bitmap: &[u8]) {
        let meta = ranged_meta(chunk as u64, total, validators, bitmap);
        self.store.save_state(total, Kind::HttpRanged, &meta);
    }

    // ---- shared helpers ----------------------------------------------------

    fn validators_from(&self, reader: &crate::http::BodyReader) -> Validators {
        Validators {
            url: self.url_key.clone(),
            etag: reader.header("etag").unwrap_or("").to_string(),
            last_modified: reader.header("last-modified").unwrap_or("").to_string(),
        }
    }

    /// Verify size + optional SHA-256, then publish the result (an atomic
    /// rename into place for a file target). On a mismatch the partial is
    /// discarded so the next run starts clean.
    fn verify_and_finalize(&self, real_size: u64, _total: Option<u64>) -> Result<DownloadOutcome> {
        if let Some(want) = self.opts.expected_sha256 {
            match self.store.hash_prefix(real_size) {
                Ok(got) if got == want => {}
                Ok(_) => {
                    self.store.discard();
                    return Err(Error::BadResponse(
                        "downloaded file failed SHA-256 verification".into(),
                    ));
                }
                Err(e) => return Err(Error::Io(e)),
            }
        }
        self.store.finalize(real_size).map_err(Error::Io)?;
        Ok(DownloadOutcome {
            bytes_written: real_size,
            total: Some(real_size),
            resumed_from: 0,
        })
    }

    /// The chunk-fetch retry budget + backoff derived from the options.
    fn retry(&self) -> Retry {
        Retry {
            max: self.opts.max_retries,
            initial: self.opts.initial_backoff,
            cap: self.opts.max_backoff,
        }
    }

    /// Sleep with bounded exponential backoff before retry number `attempt_no`.
    fn backoff(&self, attempt_no: u32) {
        let shift = attempt_no.saturating_sub(1).min(20);
        let delay = self
            .opts
            .initial_backoff
            .saturating_mul(1u32 << shift)
            .min(self.opts.max_backoff);
        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
    }
}

/// Don't split a resource into pieces smaller than this (curl's segment floor).
const MIN_SEGMENT_BYTES: u64 = 1 << 20; // 1 MiB
/// Hard cap on concurrent segment workers regardless of `parallelism`.
const MAX_SEGMENT_WORKERS: usize = 16;
/// Hard cap on how many chunks a plan may hold. Deliberately far above the
/// worker cap: chunks are claimed dynamically, so a plan with more chunks than
/// workers is what lets a fast connection keep pulling work while a slow one is
/// still grinding. One chunk per worker leaves nothing to rebalance, and the
/// transfer finishes no sooner than its slowest segment — the classic "last few
/// percent crawl" at the tail of a parallel download.
const MAX_SEGMENT_CHUNKS: usize = 1024;

/// Don't invoke the progress callback more often than this.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

/// Shared byte accounting for a segmented download.
///
/// Every byte a worker lands on disk is added here, so progress reflects the
/// chunks still *in flight* rather than only the ones that have completed.
/// Counting whole chunks instead makes a transfer with one chunk per worker
/// report almost nothing until the very end (the chunks all finish at once),
/// which reads as a download frozen just short of done.
///
/// It also carries the rate limit, which is a cap on the transfer as a whole
/// and so has to be enforced across every worker at once rather than per
/// connection.
struct ByteMeter {
    /// Bytes on disk: chunks a previous run completed, plus everything pumped
    /// this run.
    done: AtomicU64,
    /// Bytes pumped this run — the basis for the rate limit.
    moved: AtomicU64,
    /// Total size once known; 0 while it is still unknown.
    total: AtomicU64,
    limit_rate: Option<u64>,
    /// The `-Y`/`-y` policy. Held here so it reaches every pump, but applied by
    /// each pump to *its own* connection — see [`DownloadOptions::low_speed`].
    low_speed: Option<(u64, u64)>,
    started: Instant,
    /// The callback and the last time it was invoked, locked together.
    sink: Mutex<(Option<ProgressFn>, Instant)>,
}

impl ByteMeter {
    fn new(cb: Option<ProgressFn>, limit_rate: Option<u64>, low_speed: Option<(u64, u64)>) -> Self {
        let now = Instant::now();
        ByteMeter {
            done: AtomicU64::new(0),
            moved: AtomicU64::new(0),
            total: AtomicU64::new(0),
            limit_rate: limit_rate.filter(|r| *r > 0),
            low_speed: low_speed.filter(|(min, _)| *min > 0),
            started: now,
            sink: Mutex::new((cb, now)),
        }
    }

    fn set_total(&self, total: u64) {
        self.total.store(total, Ordering::Relaxed);
    }

    /// Seed the counter with bytes a previous run already landed.
    fn seed(&self, done: u64) {
        self.done.store(done, Ordering::Relaxed);
    }

    /// Account for `n` freshly written bytes, then sleep if a rate limit is set
    /// and the transfer is running ahead of it.
    fn add(&self, n: u64) {
        self.done.fetch_add(n, Ordering::Relaxed);
        let moved = self.moved.fetch_add(n, Ordering::Relaxed) + n;
        self.report(false);
        if let Some(rate) = self.limit_rate {
            let target = Duration::from_secs_f64(moved as f64 / rate as f64);
            let elapsed = self.started.elapsed();
            if target > elapsed {
                std::thread::sleep(target - elapsed);
            }
        }
    }

    /// Un-count an attempt that is about to be redone from its start (the
    /// bootstrap's whole-body paths retry from offset 0).
    fn rewind(&self, n: u64) {
        self.done.fetch_sub(n, Ordering::Relaxed);
        self.moved.fetch_sub(n, Ordering::Relaxed);
    }

    /// Invoke the progress callback, throttled to [`PROGRESS_INTERVAL`] unless
    /// `force`. A throttled call that finds the lock held just returns: another
    /// worker is already reporting the same counter.
    fn report(&self, force: bool) {
        let mut sink = match if force {
            self.sink.lock().ok()
        } else {
            self.sink.try_lock().ok()
        } {
            Some(g) => g,
            None => return,
        };
        if sink.0.is_none() || (!force && sink.1.elapsed() < PROGRESS_INTERVAL) {
            return;
        }
        let done = self.done.load(Ordering::Relaxed);
        let total = match self.total.load(Ordering::Relaxed) {
            0 => None,
            t => Some(t),
        };
        sink.1 = Instant::now();
        if let Some(cb) = sink.0.as_mut() {
            cb(done, total);
        }
    }

    /// Hand the callback back to the owning [`DownloadOptions`].
    fn take_cb(&self) -> Option<ProgressFn> {
        self.sink.lock().ok().and_then(|mut s| s.0.take())
    }
}

/// Outcome of fetching one chunk (with its own retry budget).
enum ChunkResult {
    /// The chunk's bytes are all on disk.
    Ok,
    /// The server answered a ranged request with `200` — no range support.
    Fallback,
    /// A permanent failure (retries exhausted or a non-retryable status).
    Fatal(Error),
}

/// Fetch `[start, end]` into `store`, **streaming straight through** (never
/// buffering the chunk in memory, so a chunk may be any size). On a transient
/// break it retries, resuming from wherever the stream stopped — byte-level
/// resume *within* the chunk. `Ok` only once every byte is written, so a
/// partial chunk never marks its bitmap bit done.
/// Retry budget + backoff for a chunk fetch.
#[derive(Clone, Copy)]
struct Retry {
    max: u32,
    initial: Duration,
    cap: Duration,
}

fn fetch_chunk_streaming(
    base: &Request,
    store: &dyn PartStore,
    start: u64,
    end: u64,
    if_range: &str,
    retry: Retry,
    meter: &ByteMeter,
) -> ChunkResult {
    let want = end - start + 1;
    let mut got = 0u64;
    let mut budget = retry.max;
    let mut attempt_no = 0u32;
    loop {
        let from = start + got;
        let mut req = base.clone().header("Range", &format!("bytes={from}-{end}"));
        if !if_range.is_empty() {
            req = req.header("If-Range", if_range);
        }
        match stream_chunk_once(req, store, from, want - got, meter) {
            StreamOnce::Fallback => return ChunkResult::Fallback,
            StreamOnce::Fatal(e) => return ChunkResult::Fatal(e),
            StreamOnce::Advanced {
                wrote,
                err,
                too_slow,
            } => {
                got += wrote;
                if got >= want {
                    return ChunkResult::Ok;
                }
                // Progress stalled short of the chunk end (a mid-stream break or
                // a short read); retry the remainder unless the budget is spent.
                let err = err.unwrap_or(Error::UnexpectedEof);
                if wrote > 0 && !too_slow {
                    // Durable forward progress — the next attempt resumes from
                    // the new offset. Refresh the budget the way the
                    // single-stream loop does (and as `max_retries` documents),
                    // so a chunk that keeps advancing over a flaky link is not
                    // abandoned after `max` breaks. `got` only ever grows toward
                    // `want`, so this still terminates.
                    //
                    // A connection we cut for being too slow is the exception:
                    // it did advance, but refreshing on it would retry forever
                    // instead of ever honouring `-Y`. Each replacement costs a
                    // retry, so a genuinely slow link still gives up.
                    budget = retry.max;
                    attempt_no = 0;
                }
                if budget == 0 {
                    return ChunkResult::Fatal(err);
                }
                budget -= 1;
                attempt_no += 1;
                sleep_backoff(attempt_no, retry.initial, retry.cap);
            }
        }
    }
}

/// One request/response for a chunk range, streamed into `store` at `at`.
enum StreamOnce {
    /// Wrote `wrote` bytes; `err` is `Some` if the stream broke mid-chunk,
    /// `None` on a clean end (which, for a length-framed range, means complete).
    /// `too_slow` marks a break that was *our* doing — the connection fell
    /// below the `-Y`/`-y` floor and we cut it.
    Advanced {
        wrote: u64,
        err: Option<Error>,
        too_slow: bool,
    },
    /// The server ignored the range (`200`) — fall back to single-stream.
    Fallback,
    /// A permanent failure.
    Fatal(Error),
}

fn stream_chunk_once(
    req: Request,
    store: &dyn PartStore,
    at: u64,
    want: u64,
    meter: &ByteMeter,
) -> StreamOnce {
    let mut reader = match req.send_reader() {
        Ok(r) => r,
        Err(e) if is_transient(&e) => {
            return StreamOnce::Advanced {
                wrote: 0,
                err: Some(e),
                too_slow: false,
            }
        }
        Err(e) => return StreamOnce::Fatal(e),
    };
    match reader.status() {
        206 => {}
        // `200` means the server ignored our `Range`/`If-Range` — either it
        // doesn't support ranges or (on resume) the resource changed. Either
        // way, fall back to a single-stream restart.
        200 => return StreamOnce::Fallback,
        s if (400..500).contains(&s) => return StreamOnce::Fatal(status_error(s, &reader)),
        s if s >= 500 => {
            return StreamOnce::Advanced {
                wrote: 0,
                err: Some(status_error(s, &reader)),
                too_slow: false,
            }
        }
        s => return StreamOnce::Fatal(Error::BadResponse(format!("unexpected status {s}"))),
    }
    let p = pump_to_store(&mut reader, store, at, want, Some(meter));
    match p.err {
        Some(Error::Io(e)) if pump_open_failed(&e) => StreamOnce::Fatal(Error::Io(e)),
        err => StreamOnce::Advanced {
            wrote: p.wrote,
            err,
            too_slow: p.too_slow,
        },
    }
}

/// A sentinel: the store rejected the write outright (a missing directory, no
/// permission) rather than the transfer breaking — treat that as fatal, not a
/// retryable break.
fn pump_open_failed(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
    )
}

/// What a [`pump_to_store`] call ended on.
struct Pumped {
    /// Bytes this pump landed in the store.
    wrote: u64,
    /// The error that stopped it short of `want`, if any.
    err: Option<Error>,
    /// The stream was cut because *this connection* fell below the `-Y`/`-y`
    /// floor, rather than breaking on its own. The caller retries on a fresh
    /// connection, but must not let the bytes this one did land refresh the
    /// retry budget: if the replacements are equally slow the link is slow, and
    /// `-Y` is supposed to give up.
    too_slow: bool,
}

impl Pumped {
    /// Ended without an error — either `want` bytes landed or the stream closed.
    fn clean(wrote: u64) -> Self {
        Pumped {
            wrote,
            err: None,
            too_slow: false,
        }
    }

    fn broke(wrote: u64, err: Error) -> Self {
        Pumped {
            wrote,
            err: Some(err),
            too_slow: false,
        }
    }
}

/// Stream up to `want` bytes from `reader` into `store` at absolute offset
/// `at`. Never writes past `want` (so an over-long response can't overrun the
/// next chunk).
///
/// Bytes are reported to `meter` as they land, which is how a chunk still in
/// flight shows up in the progress callback and how the transfer-wide rate
/// limit is paced. The meter also carries the `-Y`/`-y` floor, which this
/// applies to its own connection alone: this pump's bytes over this pump's
/// elapsed time, so one slow segment is cut and retried rather than dragging
/// the verdict onto the healthy ones.
fn pump_to_store(
    reader: &mut crate::http::BodyReader,
    store: &dyn PartStore,
    at: u64,
    want: u64,
    meter: Option<&ByteMeter>,
) -> Pumped {
    let low_speed = meter.and_then(|m| m.low_speed);
    let started = Instant::now();
    let mut wrote = 0u64;
    let mut buf = [0u8; 64 * 1024];
    loop {
        if wrote >= want {
            return Pumped::clean(wrote);
        }
        if let Some((min, secs)) = low_speed {
            let el = started.elapsed().as_secs();
            if el >= secs && wrote / el.max(1) < min {
                return Pumped {
                    wrote,
                    err: Some(low_speed_error()),
                    too_slow: true,
                };
            }
        }
        let cap = (want - wrote).min(buf.len() as u64) as usize;
        match reader.read(&mut buf[..cap]) {
            Ok(0) => return Pumped::clean(wrote),
            Ok(n) => {
                if let Err(e) = store.write_at(at + wrote, &buf[..n]) {
                    return Pumped::broke(wrote, Error::Io(e));
                }
                wrote += n as u64;
                if let Some(m) = meter {
                    m.add(n as u64);
                }
            }
            Err(e) => return Pumped::broke(wrote, Error::Io(e)),
        }
    }
}

/// The `-Y`/`-y` abort. The message is load-bearing: the CLI matches on it to
/// return curl's exit code 28.
fn low_speed_error() -> Error {
    Error::Io(io::Error::new(
        io::ErrorKind::TimedOut,
        "transfer below low-speed limit",
    ))
}

/// Bounded exponential backoff sleep before retry number `attempt_no`.
fn sleep_backoff(attempt_no: u32, initial: Duration, max_backoff: Duration) {
    let shift = attempt_no.saturating_sub(1).min(20);
    let delay = initial.saturating_mul(1u32 << shift).min(max_backoff);
    if !delay.is_zero() {
        std::thread::sleep(delay);
    }
}

/// Total bytes already on disk, summing the plan's completed chunks.
fn plan_done_bytes(plan: &[(u64, u64)], bitmap: &[u8]) -> u64 {
    plan.iter()
        .enumerate()
        .filter(|(i, _)| bit_get(bitmap, *i))
        .map(|(_, (s, e))| e - s + 1)
        .sum()
}

/// Classify an error raised before any body byte was read (offset unchanged).
fn classify_pre_body(err: Error, have: u64) -> Attempt {
    if is_transient(&err) {
        Attempt::Transient {
            written: have,
            resumable: false,
            err,
        }
    } else {
        Attempt::Fatal(err)
    }
}

/// Build an [`Error`] for an HTTP error status, reusing the reason phrase.
fn status_error(code: u16, reader: &crate::http::BodyReader) -> Error {
    Error::Status {
        code,
        reason: reader.head().reason.clone(),
    }
}

/// Whether an error is worth retrying: transport resets, timeouts, premature
/// EOF, HTTP/2 stream resets / GOAWAY, and 5xx statuses.
fn is_transient(err: &Error) -> bool {
    match err {
        Error::Io(e) => matches!(
            e.kind(),
            io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::TimedOut
                | io::ErrorKind::UnexpectedEof
                | io::ErrorKind::WouldBlock
                | io::ErrorKind::NotConnected
        ),
        Error::UnexpectedEof => true,
        // HTTP/2 surfaces a mid-stream RST_STREAM / GOAWAY as BadResponse.
        Error::BadResponse(m) => {
            let m = m.to_ascii_lowercase();
            m.contains("reset by server") || m.contains("goaway")
        }
        Error::Status { code, .. } => *code >= 500,
        _ => false,
    }
}

/// Parse `Content-Range: bytes a-b/total` → `(a, Some(total))`, or `total`
/// `None` for a `*` total. Returns `None` if unparseable.
fn parse_content_range(v: Option<&str>) -> Option<(u64, Option<u64>)> {
    let v = v?.trim();
    let rest = v
        .strip_prefix("bytes ")
        .or_else(|| v.strip_prefix("bytes="))?;
    let (range, total) = rest.split_once('/')?;
    let (start, _end) = range.split_once('-')?;
    let start = start.trim().parse::<u64>().ok()?;
    let total = match total.trim() {
        "*" => None,
        t => Some(t.parse::<u64>().ok()?),
    };
    Some((start, total))
}

/// Stream the first `len` bytes of `blob` through SHA-256 — [`hash_prefix`]'s
/// temp-blob twin, reading positionally so it never disturbs a cursor.
fn hash_blob_prefix(blob: &TempBlob, len: u64) -> io::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut at = 0u64;
    let mut buf = [0u8; 64 * 1024];
    while at < len {
        let cap = (len - at).min(buf.len() as u64) as usize;
        let n = blob.read_at(&mut buf[..cap], at)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "temp blob shorter than expected while hashing",
            ));
        }
        hasher.update(&buf[..n]);
        at += n as u64;
    }
    Ok(hasher.finalize())
}

/// Stream the first `len` bytes of `path` through SHA-256.
fn hash_prefix(path: &Path, len: u64) -> io::Result<[u8; 32]> {
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut remaining = len;
    let mut buf = [0u8; 64 * 1024];
    while remaining > 0 {
        let cap = remaining.min(buf.len() as u64) as usize;
        let n = f.read(&mut buf[..cap])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "file shorter than expected while hashing",
            ));
        }
        hasher.update(&buf[..n]);
        remaining -= n as u64;
    }
    Ok(hasher.finalize())
}

// ---- resume meta (de)serialisation -----------------------------------------
//
// On-disk layout is shared with the CLI's `-C -` path.
//   validators tail: three u16-length-prefixed strings (url, etag, last-mod).
//   HttpStream meta:  [total:u64][done:u64] + validators
//   HttpRanged meta:  [chunk:u32][total:u64][vlen:u32][validators][bitmap]

fn encode_validators(v: &Validators) -> Vec<u8> {
    let mut out = Vec::new();
    for s in [&v.url, &v.etag, &v.last_modified] {
        let b = s.as_bytes();
        out.extend_from_slice(&(b.len() as u16).to_le_bytes());
        out.extend_from_slice(b);
    }
    out
}

fn decode_validators(p: &[u8]) -> Option<Validators> {
    let mut p = p;
    let mut take = || -> Option<String> {
        if p.len() < 2 {
            return None;
        }
        let n = u16::from_le_bytes([p[0], p[1]]) as usize;
        let s = String::from_utf8_lossy(p.get(2..2 + n)?).into_owned();
        p = &p[2 + n..];
        Some(s)
    };
    Some(Validators {
        url: take()?,
        etag: take()?,
        last_modified: take()?,
    })
}

fn stream_meta(total: u64, done: u64, validators: &Validators) -> Vec<u8> {
    let mut m = Vec::with_capacity(16);
    m.extend_from_slice(&total.to_le_bytes());
    m.extend_from_slice(&done.to_le_bytes());
    m.extend_from_slice(&encode_validators(validators));
    m
}

fn parse_stream_meta(meta: &[u8]) -> Option<(u64, Validators)> {
    if meta.len() < 16 {
        return None;
    }
    let done = u64::from_le_bytes(meta[8..16].try_into().unwrap());
    let v = decode_validators(&meta[16..])?;
    Some((done, v))
}

fn ranged_meta(chunk: u64, total: u64, validators: &Validators, bitmap: &[u8]) -> Vec<u8> {
    let v = encode_validators(validators);
    let mut m = Vec::with_capacity(16 + v.len() + bitmap.len());
    m.extend_from_slice(&(chunk as u32).to_le_bytes());
    m.extend_from_slice(&total.to_le_bytes());
    m.extend_from_slice(&(v.len() as u32).to_le_bytes());
    m.extend_from_slice(&v);
    m.extend_from_slice(bitmap);
    m
}

/// Decode an `http-ranged` meta block into `(chunk_key, validators, bitmap)`.
/// The total is taken from the container trailer (`real_size`), not repeated
/// here. Returns `None` if the block is malformed.
fn parse_ranged_full(meta: &[u8]) -> Option<(u32, Validators, Vec<u8>)> {
    if meta.len() < 16 {
        return None;
    }
    let chunk = u32::from_le_bytes(meta[0..4].try_into().unwrap());
    let vlen = u32::from_le_bytes(meta[12..16].try_into().unwrap()) as usize;
    let rest = meta.get(16..)?;
    let validators = decode_validators(rest.get(..vlen)?)?;
    let bitmap = rest.get(vlen..)?.to_vec();
    Some((chunk, validators, bitmap))
}

fn bit_get(map: &[u8], i: usize) -> bool {
    map[i / 8] & (1 << (i % 8)) != 0
}
fn bit_set(map: &mut [u8], i: usize) {
    map[i / 8] |= 1 << (i % 8);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;

    /// Deterministic pseudo-random body so a resumed download can be compared
    /// byte-for-byte against a reference.
    fn make_body(n: usize, seed: u64) -> Vec<u8> {
        let mut x = seed | 1;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 33) as u8
            })
            .collect()
    }

    /// A controllable in-process HTTP/1.1 origin. It honours `Range` (206 +
    /// `Content-Range`) and `If-Range`, and can inject a mid-body disconnect on
    /// selected requests to drive the retry/resume paths.
    struct Origin {
        body: Vec<u8>,
        etag: String,
        accept_ranges: bool,
        /// Always answer 200 with the whole body, ignoring any `Range`.
        ignore_range: bool,
        /// Kill the connection after sending this many body bytes...
        kill_after: Option<u64>,
        /// ...but only for a request whose range starts here (None = any).
        kill_range_start: Option<u64>,
        /// Remaining injected kills.
        kills_left: usize,
        /// Trickle the body on this many more requests: a connection that is
        /// alive but far below any sane `-Y` floor.
        slow_left: usize,
        /// ...but only for a request whose range starts here (None = any).
        slow_range_start: Option<u64>,
        /// Range header value of every request received, in order.
        ranges: Vec<String>,
    }

    impl Origin {
        fn shared(body: Vec<u8>, etag: &str) -> Arc<Mutex<Origin>> {
            Arc::new(Mutex::new(Origin {
                body,
                etag: etag.to_string(),
                accept_ranges: true,
                ignore_range: false,
                kill_after: None,
                kill_range_start: None,
                kills_left: 0,
                slow_left: 0,
                slow_range_start: None,
                ranges: Vec::new(),
            }))
        }
    }

    /// Trickle shape for a deliberately slow connection: ~20 KiB/s, which is
    /// well under the floors the low-speed tests set.
    const SLOW_PIECE: usize = 1024;
    const SLOW_PIECES: usize = 64;
    const SLOW_GAP: Duration = Duration::from_millis(50);

    fn start(origin: Arc<Mutex<Origin>>) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut sock) = conn else { continue };
                // A connection per thread: a deliberately slow response must
                // not hold up the retry that is meant to replace it.
                let origin = Arc::clone(&origin);
                thread::spawn(move || handle(&mut sock, &origin));
            }
        });
        port
    }

    fn read_head(sock: &mut TcpStream) -> String {
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        while sock.read(&mut byte).map(|n| n == 1).unwrap_or(false) {
            buf.push(byte[0]);
            if buf.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    fn header_val<'a>(head: &'a str, name: &str) -> Option<&'a str> {
        head.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case(name).then(|| v.trim())
        })
    }

    /// Parse `bytes=a-b` / `bytes=a-` → `(a, Some(b)|None)`.
    fn parse_req_range(v: &str) -> Option<(u64, Option<u64>)> {
        let r = v.trim().strip_prefix("bytes=")?;
        let (a, b) = r.split_once('-')?;
        let start = a.trim().parse::<u64>().ok()?;
        let end = if b.trim().is_empty() {
            None
        } else {
            Some(b.trim().parse::<u64>().ok()?)
        };
        Some((start, end))
    }

    fn handle(sock: &mut TcpStream, origin: &Arc<Mutex<Origin>>) {
        let head = read_head(sock);
        if head.is_empty() {
            return;
        }
        let is_head = head.split_whitespace().next() == Some("HEAD");
        let mut o = origin.lock().unwrap();
        let range = header_val(&head, "range").map(|s| s.to_string());
        let if_range = header_val(&head, "if-range").map(|s| s.to_string());
        o.ranges.push(range.clone().unwrap_or_default());

        let len = o.body.len() as u64;

        // A HEAD probe: headers only (size + range support + validators), no
        // body and no fault injection (kills apply to the real GET transfers).
        if is_head {
            let ar = if o.accept_ranges {
                "Accept-Ranges: bytes\r\n"
            } else {
                ""
            };
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {len}\r\n{ar}ETag: {}\r\nConnection: close\r\n\r\n",
                o.etag
            );
            drop(o);
            let _ = sock.write_all(resp.as_bytes());
            let _ = sock.shutdown(Shutdown::Write);
            return;
        }

        // If-Range mismatch forces a full 200 (resource changed).
        let if_range_ok = if_range.as_deref().map(|v| v == o.etag).unwrap_or(true);
        let use_range = range.is_some() && o.accept_ranges && !o.ignore_range && if_range_ok;

        let (start, end) = match (use_range, range.as_deref().and_then(parse_req_range)) {
            (true, Some((s, e))) => (s, e.unwrap_or(len - 1).min(len - 1)),
            _ => (0u64, len.saturating_sub(1)),
        };

        // Unsatisfiable range → 416.
        if use_range && start >= len {
            let resp = format!(
                "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */{len}\r\n\
                 Content-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = sock.write_all(resp.as_bytes());
            let _ = sock.shutdown(Shutdown::Write);
            return;
        }

        let slice = o.body[start as usize..=end as usize].to_vec();
        let slice_len = slice.len() as u64;
        let status_206 = use_range;
        let head_bytes = if status_206 {
            format!(
                "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {start}-{end}/{len}\r\n\
                 Content-Length: {slice_len}\r\nETag: {}\r\nAccept-Ranges: bytes\r\n\
                 Connection: close\r\n\r\n",
                o.etag
            )
        } else {
            let ar = if o.accept_ranges {
                "Accept-Ranges: bytes\r\n"
            } else {
                ""
            };
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {len}\r\n{ar}ETag: {}\r\nConnection: close\r\n\r\n",
                o.etag
            )
        };

        // Decide whether to inject a kill on this request.
        let kill_here = o.kills_left > 0
            && o.kill_after.is_some()
            && o.kill_range_start.map(|s| s == start).unwrap_or(true);
        let send_n = if kill_here {
            o.kills_left -= 1;
            o.kill_after.unwrap().min(slice_len) as usize
        } else {
            slice.len()
        };
        // Decide whether to answer this one at a crawl instead.
        let slow_here = o.slow_left > 0 && o.slow_range_start.map(|st| st == start).unwrap_or(true);
        if slow_here {
            o.slow_left -= 1;
        }
        let payload = slice[..send_n].to_vec();
        drop(o); // release the lock before the (possibly slow) write

        let _ = sock.write_all(head_bytes.as_bytes());
        if slow_here {
            // Dribble it out so the client's *per-connection* rate check is
            // what cuts the stream, not a read timeout. Bounded, and it stops
            // early once the client hangs up, so a client that never gives up
            // still can't hang the test.
            let _ = sock.flush();
            for piece in payload.chunks(SLOW_PIECE).take(SLOW_PIECES) {
                if sock.write_all(piece).is_err() {
                    break;
                }
                let _ = sock.flush();
                thread::sleep(SLOW_GAP);
            }
        } else {
            let _ = sock.write_all(&payload);
        }
        let _ = sock.flush();
        // Half-close so the client reliably reads what we sent (then sees EOF —
        // a truncated body when we killed early), avoiding a RST race.
        let _ = sock.shutdown(Shutdown::Write);
        let mut sink = [0u8; 64];
        let _ = sock.set_read_timeout(Some(Duration::from_millis(200)));
        while sock.read(&mut sink).map(|n| n > 0).unwrap_or(false) {}
    }

    fn tmp(tag: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("rsurl_dl_{}_{tag}_{n}", std::process::id()))
    }

    fn cleanup(p: &Path) {
        let _ = std::fs::remove_file(p);
        let _ = std::fs::remove_file(resume::part_path(p));
    }

    fn no_backoff() -> DownloadOptions {
        DownloadOptions {
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
            ..Default::default()
        }
    }

    #[test]
    fn resumes_after_midbody_disconnect() {
        let body = make_body(120_000, 0xABCD);
        let origin = Origin::shared(body.clone(), "v1");
        {
            let mut o = origin.lock().unwrap();
            o.kill_after = Some(45_000);
            o.kills_left = 1;
        }
        let port = start(origin.clone());
        let out = tmp("resume");

        let outcome = download(&format!("http://127.0.0.1:{port}/file"), &out, no_backoff())
            .expect("download");

        assert_eq!(outcome.bytes_written, 120_000);
        assert_eq!(std::fs::read(&out).unwrap(), body);
        let ranges = origin.lock().unwrap().ranges.clone();
        // First request full (no Range); second resumes from ~45000.
        assert_eq!(ranges.len(), 2, "ranges: {ranges:?}");
        assert_eq!(ranges[0], "");
        assert_eq!(ranges[1], "bytes=45000-");
        cleanup(&out);
    }

    #[test]
    fn full_download_retry_when_no_range_support() {
        let body = make_body(50_000, 0x1234);
        let origin = Origin::shared(body.clone(), "");
        {
            let mut o = origin.lock().unwrap();
            o.accept_ranges = false;
            o.ignore_range = true; // always 200 full
            o.kill_after = Some(20_000);
            o.kills_left = 1; // kill the first attempt mid-stream
        }
        let port = start(origin.clone());
        let out = tmp("noranges");

        let outcome = download(&format!("http://127.0.0.1:{port}/file"), &out, no_backoff())
            .expect("download");

        assert_eq!(outcome.bytes_written, 50_000);
        assert_eq!(std::fs::read(&out).unwrap(), body);
        // Two full-body attempts: the first was killed, the second completed.
        let ranges = origin.lock().unwrap().ranges.clone();
        assert_eq!(ranges.len(), 2, "ranges: {ranges:?}");
        cleanup(&out);
    }

    #[test]
    fn validator_mismatch_discards_stale_partial() {
        // Upstream is now v2; a stale v1 partial sits on disk from a prior run.
        let v1 = make_body(100_000, 0x1111);
        let v2 = make_body(100_000, 0x2222);
        let origin = Origin::shared(v2.clone(), "v2");
        let port = start(origin);
        let out = tmp("validator");
        let part = resume::part_path(&out);

        // Craft a v1 partial: 40k of v1 bytes + HttpStream state keyed to v1.
        // Derive url_key exactly the way Downloader::new does.
        let url = format!("http://127.0.0.1:{port}/file");
        let u = Request::get(&url).unwrap();
        let u = u.url();
        let stale = Validators {
            url: format!("{}://{}:{}{}", u.scheme, u.host, u.port, u.path),
            etag: "v1".into(),
            last_modified: String::new(),
        };
        {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&part)
                .unwrap();
            f.set_len(100_000).unwrap();
            f.write_all(&v1[..40_000]).unwrap();
        }
        resume::write_state(
            &part,
            100_000,
            Kind::HttpStream,
            &stream_meta(100_000, 40_000, &stale),
        )
        .unwrap();
        assert_eq!(load_state_done(&part), Some(40_000));

        // Run: resume sends Range + If-Range: v1; server (etag v2) returns the
        // full body → stale partial discarded, clean restart, correct bytes.
        let outcome = download(&url, &out, no_backoff()).expect("download v2");
        assert_eq!(outcome.bytes_written, 100_000);
        assert_eq!(std::fs::read(&out).unwrap(), v2);
        assert_ne!(std::fs::read(&out).unwrap(), v1);
        cleanup(&out);
    }

    /// Read back the persisted single-stream offset (test helper).
    fn load_state_done(part: &Path) -> Option<u64> {
        let st = resume::read_state(part).ok()??;
        parse_stream_meta(&st.meta).map(|(done, _)| done)
    }

    #[test]
    fn segmented_retries_only_the_failing_chunk() {
        let body = make_body(10_000, 0x9999);
        let origin = Origin::shared(body.clone(), "seg");
        {
            let mut o = origin.lock().unwrap();
            // Fail the chunk starting at offset 3000 exactly once (send 0 bytes).
            o.kill_after = Some(0);
            o.kill_range_start = Some(3000);
            o.kills_left = 1;
        }
        let port = start(origin.clone());
        let out = tmp("segmented");

        let mut opts = no_backoff();
        opts.segment_size = Some(1000); // 10 chunks
        let outcome = download(&format!("http://127.0.0.1:{port}/file"), &out, opts)
            .expect("segmented download");

        assert_eq!(outcome.bytes_written, 10_000);
        assert_eq!(std::fs::read(&out).unwrap(), body);

        let ranges = origin.lock().unwrap().ranges.clone();
        // No HEAD probe: the first GET (`bytes=0-`) is chunk 0 and reveals the
        // total. Then chunks 1..9 (9 GETs) with chunk 3 retried once = 11.
        assert_eq!(ranges.len(), 11, "ranges: {ranges:?}");
        assert_eq!(ranges[0], "bytes=0-", "first GET doubles as the probe");
        // The chunk at 3000 was requested twice; every other chunk exactly once.
        let at_3000 = ranges.iter().filter(|r| *r == "bytes=3000-3999").count();
        assert_eq!(at_3000, 2, "failed chunk retried: {ranges:?}");
        let at_4000 = ranges.iter().filter(|r| *r == "bytes=4000-4999").count();
        assert_eq!(at_4000, 1, "completed chunks not refetched");
        cleanup(&out);
    }

    #[test]
    fn sha256_mismatch_deletes_partial() {
        let body = make_body(8_000, 0x7777);
        let origin = Origin::shared(body.clone(), "h");
        let port = start(origin);
        let out = tmp("sha");

        let mut opts = no_backoff();
        opts.expected_sha256 = Some([0u8; 32]); // wrong hash
        let err = download(&format!("http://127.0.0.1:{port}/file"), &out, opts).unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)));
        assert!(!out.exists(), "final file not created");
        assert!(!resume::part_path(&out).exists(), "partial deleted");
        cleanup(&out);
    }

    #[test]
    fn sha256_match_finalizes() {
        let body = make_body(8_000, 0x5555);
        let want = Sha256::digest(&body);
        let origin = Origin::shared(body.clone(), "h");
        let port = start(origin);
        let out = tmp("sha_ok");

        let mut opts = no_backoff();
        opts.expected_sha256 = Some(want);
        let outcome =
            download(&format!("http://127.0.0.1:{port}/file"), &out, opts).expect("download");
        assert_eq!(outcome.bytes_written, 8_000);
        assert_eq!(std::fs::read(&out).unwrap(), body);
        cleanup(&out);
    }

    #[test]
    fn is_transient_classifies_h2_reset_and_transport_faults() {
        assert!(is_transient(&Error::BadResponse(
            "stream 1 reset by server, error code 2".into()
        )));
        assert!(is_transient(&Error::BadResponse("received GOAWAY".into())));
        assert!(is_transient(&Error::UnexpectedEof));
        assert!(is_transient(&Error::Io(io::Error::from(
            io::ErrorKind::ConnectionReset
        ))));
        assert!(is_transient(&Error::Io(io::Error::from(
            io::ErrorKind::TimedOut
        ))));
        assert!(is_transient(&Error::Status {
            code: 503,
            reason: "Service Unavailable".into()
        }));
        // Permanent: 4xx, malformed URL, decode, cancellation.
        assert!(!is_transient(&Error::Status {
            code: 404,
            reason: "Not Found".into()
        }));
        assert!(!is_transient(&Error::BadResponse(
            "malformed header".into()
        )));
        assert!(!is_transient(&Error::Cancelled));
    }

    #[test]
    fn data_uri_base64_is_written() {
        let out = tmp("data_b64");
        // "Hello, data!" base64-encoded.
        let outcome = download(
            "data:text/plain;base64,SGVsbG8sIGRhdGEh",
            &out,
            no_backoff(),
        )
        .expect("data uri");
        assert_eq!(outcome.bytes_written, 12);
        assert_eq!(std::fs::read(&out).unwrap(), b"Hello, data!");
        cleanup(&out);
    }

    #[test]
    fn data_uri_percent_encoded_and_plain() {
        let out = tmp("data_pct");
        download("data:,a%20b%2Fc%00d", &out, no_backoff()).expect("data uri");
        assert_eq!(std::fs::read(&out).unwrap(), b"a b/c\0d");
        // No mediatype, no encoding: the payload is used verbatim.
        download("data:,plain", &out, no_backoff()).expect("data uri");
        assert_eq!(std::fs::read(&out).unwrap(), b"plain");
        cleanup(&out);
    }

    #[test]
    fn data_uri_sha256_and_size_and_malformed() {
        let out = tmp("data_meta");
        let body = b"verify me";
        let want = Sha256::digest(body);

        let mut opts = no_backoff();
        opts.expected_sha256 = Some(want);
        let outcome = download("data:,verify me", &out, opts).expect("sha ok");
        assert_eq!(outcome.bytes_written, body.len() as u64);

        let mut opts = no_backoff();
        opts.expected_sha256 = Some([0u8; 32]);
        assert!(
            download("data:,verify me", &out, opts).is_err(),
            "sha mismatch"
        );

        let mut opts = no_backoff();
        opts.max_size = Some(3);
        assert!(download("data:,too long", &out, opts).is_err(), "size cap");

        // Missing comma → malformed data URI.
        assert!(matches!(
            download("data:text/plain", &out, no_backoff()),
            Err(Error::InvalidUrl(_))
        ));
        cleanup(&out);
    }

    #[test]
    fn front_door_dispatches_data_and_http() {
        // data:
        let out = tmp("fd_data");
        fetch_to_file("data:;base64,aGVsbG8=", &out, no_backoff()).expect("data");
        assert_eq!(std::fs::read(&out).unwrap(), b"hello");
        cleanup(&out);

        // http(s): → resumable engine.
        let body = make_body(3_000, 0xF00D);
        let origin = Origin::shared(body.clone(), "fd");
        let port = start(origin);
        let out = tmp("fd_http");
        let outcome =
            fetch_to_file(&format!("http://127.0.0.1:{port}/f"), &out, no_backoff()).expect("http");
        assert_eq!(outcome.bytes_written, 3_000);
        assert_eq!(std::fs::read(&out).unwrap(), body);
        cleanup(&out);
    }

    // `file://` URL formatting is platform-specific (Windows drive letters /
    // backslashes); the `file` module owns those semantics. Here we only need to
    // confirm the front door routes `file:` through the transfer dispatcher, so
    // exercise it where the path→URL mapping is trivial.
    #[cfg(unix)]
    #[test]
    fn front_door_dispatches_file_scheme() {
        let src = tmp("fd_src");
        std::fs::write(&src, b"local file contents").unwrap();
        let out = tmp("fd_file");
        let url = format!("file://{}", src.display());
        let outcome = fetch_to_file(&url, &out, no_backoff()).expect("file");
        assert_eq!(outcome.bytes_written, 19);
        assert_eq!(std::fs::read(&out).unwrap(), b"local file contents");
        cleanup(&out);
        cleanup(&src);
    }

    #[test]
    fn front_door_rejects_magnet_and_bad_scheme() {
        let out = tmp("fd_bad");
        assert!(matches!(
            fetch_to_file("magnet:?xt=urn:btih:abc", &out, no_backoff()),
            Err(Error::UnsupportedScheme(_))
        ));
        assert!(matches!(
            fetch_to_file("not a url", &out, no_backoff()),
            Err(Error::InvalidUrl(_))
        ));
        cleanup(&out);
    }

    #[test]
    fn decode_data_uri_recognition() {
        assert!(decode_data_uri("http://x/").is_none());
        assert!(decode_data_uri("DATA:,x").is_some()); // scheme is case-insensitive
        assert_eq!(decode_data_uri("data:,hi").unwrap().unwrap(), b"hi");
        assert_eq!(
            decode_data_uri("data:;base64,aGk=").unwrap().unwrap(),
            b"hi"
        );
    }

    #[test]
    fn parse_content_range_variants() {
        assert_eq!(
            parse_content_range(Some("bytes 100-199/1000")),
            Some((100, Some(1000)))
        );
        assert_eq!(parse_content_range(Some("bytes 0-0/*")), Some((0, None)));
        assert_eq!(parse_content_range(Some("garbage")), None);
        assert_eq!(parse_content_range(None), None);
    }

    #[test]
    fn fresh_download_no_faults() {
        let body = make_body(5_000, 0x4242);
        let origin = Origin::shared(body.clone(), "e");
        let port = start(origin);
        let out = tmp("fresh");
        let outcome =
            download(&format!("http://127.0.0.1:{port}/file"), &out, no_backoff()).expect("dl");
        assert_eq!(outcome.bytes_written, 5_000);
        assert_eq!(outcome.resumed_from, 0);
        assert_eq!(std::fs::read(&out).unwrap(), body);
        cleanup(&out);
    }

    #[test]
    fn segmented_single_chunk_streams_and_resumes_within_chunk() {
        // segment_size larger than the file → exactly one chunk. It must still
        // download (single-chunk resumable), stream to disk, and — when the
        // stream breaks mid-chunk — resume from the byte it stopped at rather
        // than refetching the chunk from zero.
        let body = make_body(50_000, 0xC0DE);
        let origin = Origin::shared(body.clone(), "one");
        {
            let mut o = origin.lock().unwrap();
            o.kill_after = Some(20_000);
            o.kill_range_start = Some(0); // break the (single) chunk once
            o.kills_left = 1;
        }
        let port = start(origin.clone());
        let out = tmp("onechunk");

        let mut opts = no_backoff();
        opts.segment_size = Some(1_000_000); // >> file → one chunk
        let outcome = download(&format!("http://127.0.0.1:{port}/file"), &out, opts)
            .expect("single-chunk download");
        assert_eq!(outcome.bytes_written, 50_000);
        assert_eq!(std::fs::read(&out).unwrap(), body);

        // The retry resumed from offset 20000 (byte-level within the chunk).
        let ranges = origin.lock().unwrap().ranges.clone();
        assert!(
            ranges.iter().any(|r| r == "bytes=20000-49999"),
            "expected an in-chunk resume from 20000: {ranges:?}"
        );
        cleanup(&out);
    }

    #[test]
    fn segmented_parallel_fetches_every_chunk_once() {
        let body = make_body(10_000, 0xBEEF);
        let origin = Origin::shared(body.clone(), "par");
        let port = start(origin.clone());
        let out = tmp("parallel");

        let mut opts = no_backoff();
        opts.segment_size = Some(1000); // 10 chunks
        opts.parallelism = 4; // fetched concurrently
        let outcome = download(&format!("http://127.0.0.1:{port}/file"), &out, opts)
            .expect("parallel download");
        assert_eq!(outcome.bytes_written, 10_000);
        assert_eq!(std::fs::read(&out).unwrap(), body);

        // Every chunk fetched exactly once (10 ranged GETs; HEAD is not ranged).
        let ranges = origin.lock().unwrap().ranges.clone();
        let range_gets = ranges.iter().filter(|r| r.starts_with("bytes=")).count();
        assert_eq!(range_gets, 10, "one GET per chunk: {ranges:?}");
    }

    #[test]
    fn segmented_resume_reads_total_from_disk_without_probing() {
        // A prior segmented run left an HttpRanged `.rsurlpart` with chunks 0-1
        // done. Resuming must NOT issue any probe (no HEAD, no `bytes=0-`
        // bootstrap) — the total comes off disk — and must fetch only the
        // missing chunks 2,3,4.
        let body = make_body(5_000, 0x3033);
        let origin = Origin::shared(body.clone(), "rv1");
        let port = start(origin.clone());
        let out = tmp("segresume");
        let part = resume::part_path(&out);

        let url = format!("http://127.0.0.1:{port}/file");
        let u = Request::get(&url).unwrap();
        let u = u.url();
        let validators = Validators {
            url: format!("{}://{}:{}{}", u.scheme, u.host, u.port, u.path),
            etag: "rv1".into(),
            last_modified: String::new(),
        };
        // Data region = total (5000); first 2 chunks (0..2000) hold real bytes.
        {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&part)
                .unwrap();
            f.set_len(5_000).unwrap();
            f.write_all(&body[..2_000]).unwrap();
        }
        let mut bitmap = vec![0u8]; // 5 chunks → 1 byte
        bit_set(&mut bitmap, 0);
        bit_set(&mut bitmap, 1);
        resume::write_state(
            &part,
            5_000,
            Kind::HttpRanged,
            &ranged_meta(1000, 5_000, &validators, &bitmap),
        )
        .unwrap();

        let mut opts = no_backoff();
        opts.segment_size = Some(1000);
        let outcome = download(&url, &out, opts).expect("resumed segmented download");
        assert_eq!(outcome.bytes_written, 5_000);
        assert_eq!(outcome.resumed_from, 2_000);
        assert_eq!(std::fs::read(&out).unwrap(), body);

        // Only chunks 2,3,4 fetched; no probe and no refetch of 0,1.
        let ranges = origin.lock().unwrap().ranges.clone();
        assert!(
            !ranges.iter().any(|r| r == "bytes=0-" || r.is_empty()),
            "no probe expected on resume: {ranges:?}"
        );
        let mut got: Vec<_> = ranges.clone();
        got.sort();
        assert_eq!(
            got,
            vec![
                "bytes=2000-2999".to_string(),
                "bytes=3000-3999".to_string(),
                "bytes=4000-4999".to_string(),
            ],
            "only the missing chunks fetched: {ranges:?}"
        );
        cleanup(&out);
    }

    #[test]
    fn segments_mode_splits_into_n_equal_parts() {
        // `segments = N` divides the resource into N parts (post-probe), the
        // "N parallel connections" model the CLI's --parallel-segments uses.
        let body = make_body(4_200_000, 0x5EED);
        let origin = Origin::shared(body.clone(), "seg");
        let port = start(origin.clone());
        let out = tmp("segments");

        let mut opts = no_backoff();
        opts.segments = Some(4);
        opts.parallelism = 4;
        let outcome = download(&format!("http://127.0.0.1:{port}/file"), &out, opts)
            .expect("segments download");
        assert_eq!(outcome.bytes_written, 4_200_000);
        assert_eq!(std::fs::read(&out).unwrap(), body);
        // Nothing was resumed: the bootstrap chunk is progress made this run,
        // not bytes recovered from a prior partial.
        assert_eq!(outcome.resumed_from, 0, "fresh download resumed nothing");

        let ranges = origin.lock().unwrap().ranges.clone();
        let range_gets = ranges.iter().filter(|r| r.starts_with("bytes=")).count();
        assert_eq!(range_gets, 4, "split into 4 segments: {ranges:?}");
        cleanup(&out);
    }

    #[test]
    fn segments_plan_is_capped_independently_of_the_worker_pool() {
        // Chunks are claimed dynamically, so a plan with more chunks than
        // workers is what lets a fast connection keep taking work while a slow
        // one is still busy. Capping the plan at the *worker* limit instead
        // pins the transfer to its slowest segment and the tail crawls, so
        // `segments` above that limit must really produce that many chunks.
        // Comfortably above the worker cap, and above the engine's 1 MiB
        // chunk floor at one MiB per chunk.
        const CHUNKS: usize = MAX_SEGMENT_WORKERS + 4;

        let body = make_body(CHUNKS << 20, 0xC0FFEE);
        let origin = Origin::shared(body.clone(), "wide");
        let port = start(origin.clone());
        let out = tmp("wide");

        let mut opts = no_backoff();
        opts.segments = Some(CHUNKS);
        opts.parallelism = 4;
        let outcome = download(&format!("http://127.0.0.1:{port}/file"), &out, opts)
            .expect("wide segments download");
        assert_eq!(outcome.bytes_written, body.len() as u64);
        assert_eq!(std::fs::read(&out).unwrap(), body);

        let ranges = origin.lock().unwrap().ranges.clone();
        let range_gets = ranges.iter().filter(|r| r.starts_with("bytes=")).count();
        assert_eq!(
            range_gets, CHUNKS,
            "{CHUNKS} chunks over 4 workers: {ranges:?}"
        );
        cleanup(&out);
    }

    #[test]
    fn chunk_retry_budget_refreshes_on_forward_progress() {
        // `max_retries` documents a budget that is refreshed whenever a retry
        // makes durable forward progress — only a unit that cannot advance at
        // all is abandoned. A segment kept advancing by ~400 KiB a shot must
        // therefore survive far more breaks than the raw budget allows.
        let body = make_body(3 << 20, 0xFEED);
        let origin = Origin::shared(body.clone(), "flaky");
        {
            let mut o = origin.lock().unwrap();
            o.kill_after = Some(400_000);
            o.kills_left = 8;
        }
        let port = start(origin.clone());
        let out = tmp("flaky_seg");

        let mut opts = no_backoff();
        opts.segments = Some(2);
        opts.parallelism = 2;
        opts.max_retries = 1; // far fewer than the 8 breaks injected
        let outcome = download(&format!("http://127.0.0.1:{port}/file"), &out, opts)
            .expect("advancing segments must not exhaust the retry budget");
        assert_eq!(outcome.bytes_written, body.len() as u64);
        assert_eq!(std::fs::read(&out).unwrap(), body);
        assert_eq!(
            origin.lock().unwrap().kills_left,
            0,
            "the injected breaks should all have been spent"
        );
        cleanup(&out);
    }

    /// `-Y`/`-y` is measured per connection in segmented mode: one segment that
    /// falls below the floor is cut and retried on a *fresh* connection, which
    /// usually lands somewhere healthier. Killing the whole transfer instead
    /// would throw away three healthy connections over one bad one.
    #[test]
    fn slow_connection_is_cut_and_retried_on_a_fresh_one() {
        const TOTAL: usize = 256 * 1024;
        const CHUNK: u64 = 64 * 1024;

        let body = make_body(TOTAL, 0x5107);
        let origin = Origin::shared(body.clone(), "slow");
        {
            let mut o = origin.lock().unwrap();
            // Only the first request for the second chunk crawls; the retry
            // asks from a later offset, so it is served at full speed.
            o.slow_range_start = Some(CHUNK);
            o.slow_left = 1;
        }
        let port = start(origin.clone());
        let out = tmp("slow_conn");

        let mut opts = no_backoff();
        opts.segment_size = Some(CHUNK);
        opts.parallelism = 2;
        opts.low_speed = Some((100_000, 1)); // 100 KB/s over a 1s window
        let outcome = download(&format!("http://127.0.0.1:{port}/file"), &out, opts)
            .expect("a slow connection should be replaced, not fatal");
        assert_eq!(outcome.bytes_written, TOTAL as u64);
        assert_eq!(std::fs::read(&out).unwrap(), body);

        let ranges = origin.lock().unwrap().ranges.clone();
        let gets = ranges.iter().filter(|r| r.starts_with("bytes=")).count();
        assert!(
            gets > TOTAL / CHUNK as usize,
            "the cut chunk should have been re-requested: {ranges:?}"
        );
        assert!(
            ranges.iter().any(|r| {
                r.strip_prefix("bytes=")
                    .and_then(|r| r.split('-').next())
                    .and_then(|st| st.parse::<u64>().ok())
                    .is_some_and(|st| st > CHUNK && st < 2 * CHUNK)
            }),
            "the retry should resume inside the cut chunk, not restart it: {ranges:?}"
        );
        cleanup(&out);
    }

    /// ...but when every replacement is just as slow it is the link, not the
    /// connection. A low-speed cut deliberately does not refresh the retry
    /// budget, so the transfer still gives up with the error the CLI turns into
    /// curl's exit 28 — otherwise `-Y` would never fire in segmented mode.
    #[test]
    fn persistently_slow_transfer_still_gives_up() {
        const TOTAL: usize = 256 * 1024;
        const CHUNK: u64 = 64 * 1024;

        let body = make_body(TOTAL, 0x5108);
        let origin = Origin::shared(body.clone(), "slower");
        origin.lock().unwrap().slow_left = usize::MAX; // every connection crawls
        let port = start(origin.clone());
        let out = tmp("slow_all");

        let mut opts = no_backoff();
        opts.segment_size = Some(CHUNK);
        opts.parallelism = 1;
        opts.max_retries = 1;
        opts.low_speed = Some((100_000, 1));
        let err = download(&format!("http://127.0.0.1:{port}/file"), &out, opts)
            .expect_err("a persistently slow link must give up");
        assert!(
            err.to_string().contains("low-speed"),
            "expected the -Y abort the CLI maps to exit 28, got {err}"
        );
        cleanup(&out);
    }

    #[test]
    fn progress_reports_bytes_in_flight_and_honours_the_rate_limit() {
        // Counting only *completed* chunks makes a transfer with one chunk per
        // worker report nothing until the very end (they all finish at once),
        // which reads as a download stuck just short of done. Reports must
        // track the bytes actually on disk, mid-chunk included. The rate limit
        // is a cap on the transfer as a whole, so it has to be enforced across
        // every worker at once rather than per connection.
        const TOTAL: usize = 2 << 20;
        const SEG: u64 = (TOTAL / 2) as u64;
        const RATE: u64 = 4 << 20; // ~0.5s for the whole body

        let body = make_body(TOTAL, 0x1234);
        let origin = Origin::shared(body.clone(), "prog");
        let port = start(origin.clone());
        let out = tmp("prog");

        type Reports = Arc<Mutex<Vec<(u64, Option<u64>)>>>;
        let seen: Reports = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let mut opts = no_backoff();
        opts.segments = Some(2);
        opts.parallelism = 2;
        opts.limit_rate = Some(RATE);
        opts.progress = Some(Box::new(move |n, total| {
            sink.lock().unwrap().push((n, total));
        }));

        let started = Instant::now();
        let outcome = download(&format!("http://127.0.0.1:{port}/file"), &out, opts)
            .expect("progress download");
        let elapsed = started.elapsed();
        assert_eq!(outcome.bytes_written, TOTAL as u64);
        assert_eq!(std::fs::read(&out).unwrap(), body);

        let seen = seen.lock().unwrap().clone();
        assert!(!seen.is_empty(), "no progress reported");
        let mut prev = 0;
        for (n, total) in &seen {
            assert!(*n >= prev, "progress went backwards: {seen:?}");
            assert!(*n <= TOTAL as u64, "progress overshot: {seen:?}");
            assert_eq!(*total, Some(TOTAL as u64));
            prev = *n;
        }
        assert_eq!(
            seen.last().map(|(n, _)| *n),
            Some(TOTAL as u64),
            "the final report should be the whole file: {seen:?}"
        );
        // Chunk-granular accounting can only ever report a multiple of the
        // segment size; byte-granular accounting lands between the boundaries.
        assert!(
            seen.iter().any(|(n, _)| *n % SEG != 0),
            "every report sat on a chunk boundary — in-flight bytes are not \
             being counted: {seen:?}"
        );
        // Generous lower bound (half the ideal time) so the check is about the
        // limiter running at all, not about scheduler precision.
        assert!(
            elapsed >= Duration::from_secs_f64(TOTAL as f64 / RATE as f64 / 2.0),
            "finished in {elapsed:?} — the rate limit was not applied"
        );
        cleanup(&out);
    }

    // ---- temp-blob downloads ------------------------------------------------

    /// A scratch directory the temp blob can spill into, so a test can assert
    /// on exactly what did (or didn't) hit the filesystem.
    fn tmp_dir(tag: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("rsurl_tmpdl_{}_{tag}_{n}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Entries left in `dir`. On Unix an anonymous file has no name at all; on
    /// Windows a delete-on-close file still shows one until the handle closes,
    /// so only the `.rsurlpart` claim is checked there.
    fn stray_entries(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| Some(e.ok()?.file_name().to_string_lossy().into_owned()))
            .filter(|name| cfg!(unix) || name.contains("rsurlpart"))
            .collect()
    }

    #[test]
    fn tmp_download_small_body_never_touches_the_filesystem() {
        let body = make_body(4_000, 0x1111);
        let port = start(Origin::shared(body.clone(), "mem"));
        let dir = tmp_dir("mem");

        let mut opts = no_backoff();
        opts.tmp_dir = Some(dir.clone());
        let mut blob =
            download_to_tmp(&format!("http://127.0.0.1:{port}/file"), opts).expect("tmp download");

        assert!(
            blob.is_in_memory(),
            "4 KB is under the 1 MiB spill threshold"
        );
        assert_eq!(blob.len(), 4_000);
        assert_eq!(blob.to_vec().unwrap(), body);
        assert!(stray_entries(&dir).is_empty(), "nothing should be on disk");

        // The handle reads like a file: cursor, seek, positional reads.
        let mut head = [0u8; 8];
        blob.read_exact(&mut head).unwrap();
        assert_eq!(head, body[..8]);
        assert_eq!(blob.seek(SeekFrom::End(-4)).unwrap(), 3_996);
        let mut tail = Vec::new();
        blob.read_to_end(&mut tail).unwrap();
        assert_eq!(tail, body[3_996..]);
        let mut mid = [0u8; 16];
        assert_eq!(blob.read_at(&mut mid, 2_000).unwrap(), 16);
        assert_eq!(mid, body[2_000..2_016]);

        blob.close().unwrap();
        let _ = std::fs::remove_dir(&dir);
    }

    /// Past the threshold the bytes go to an anonymous file — and still no
    /// `.rsurlpart` sidecar, because a temp download has nothing to resume into.
    #[test]
    fn tmp_download_spills_to_an_anonymous_file_with_no_sidecar() {
        let body = make_body(200_000, 0x2222);
        let port = start(Origin::shared(body.clone(), "spill"));
        let dir = tmp_dir("spill");

        let mut opts = no_backoff();
        opts.tmp_dir = Some(dir.clone());
        opts.tmp_spill_threshold = Some(64 * 1024);
        let blob =
            download_to_tmp(&format!("http://127.0.0.1:{port}/file"), opts).expect("tmp download");

        assert!(!blob.is_in_memory(), "200 KB is past the 64 KiB threshold");
        assert_eq!(blob.len(), 200_000);
        assert_eq!(blob.to_vec().unwrap(), body);
        assert!(
            stray_entries(&dir).is_empty(),
            "the spilled file must have no name and leave no sidecar: {:?}",
            stray_entries(&dir)
        );
        drop(blob);
        assert!(stray_entries(&dir).is_empty(), "nothing survives the drop");
        let _ = std::fs::remove_dir(&dir);
    }

    /// The retry/resume machinery is the same one the file path uses: a body cut
    /// mid-stream is continued with a `Range` against the bytes already held.
    #[test]
    fn tmp_download_resumes_after_a_midbody_disconnect() {
        let body = make_body(120_000, 0x3333);
        let origin = Origin::shared(body.clone(), "v1");
        {
            let mut o = origin.lock().unwrap();
            o.kill_after = Some(45_000);
            o.kills_left = 1;
        }
        let port = start(origin.clone());
        let dir = tmp_dir("resume");

        let mut opts = no_backoff();
        opts.tmp_dir = Some(dir.clone());
        opts.tmp_spill_threshold = Some(1024); // exercise the file backing
        let blob =
            download_to_tmp(&format!("http://127.0.0.1:{port}/file"), opts).expect("tmp download");

        assert_eq!(blob.to_vec().unwrap(), body);
        let ranges = origin.lock().unwrap().ranges.clone();
        assert_eq!(ranges.len(), 2, "ranges: {ranges:?}");
        assert_eq!(ranges[1], "bytes=45000-", "resumed, not restarted");
        assert!(stray_entries(&dir).is_empty());
        let _ = std::fs::remove_dir(&dir);
    }

    /// Segmented + parallel works against a temp target too: chunks land at
    /// their own offsets in the anonymous file, with the bitmap held in memory
    /// instead of a sidecar.
    #[test]
    fn tmp_download_segmented_parallel_fetches_every_chunk_once() {
        let body = make_body(40_000, 0x4444);
        let origin = Origin::shared(body.clone(), "seg");
        let port = start(origin.clone());
        let dir = tmp_dir("seg");

        let mut opts = no_backoff();
        opts.tmp_dir = Some(dir.clone());
        opts.tmp_spill_threshold = Some(0); // anonymous file from byte zero
        opts.segment_size = Some(4_000);
        opts.parallelism = 4;
        let blob =
            download_to_tmp(&format!("http://127.0.0.1:{port}/file"), opts).expect("tmp download");

        assert_eq!(blob.len(), 40_000);
        assert_eq!(blob.to_vec().unwrap(), body);
        let ranges = origin.lock().unwrap().ranges.clone();
        assert_eq!(ranges.len(), 10, "one GET per chunk: {ranges:?}");
        assert!(stray_entries(&dir).is_empty(), "no sidecar, no named spill");
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn tmp_download_checks_sha256_and_max_size() {
        let body = make_body(8_000, 0x5566);
        let origin = Origin::shared(body.clone(), "h");
        let port = start(origin);
        let url = format!("http://127.0.0.1:{port}/file");

        let mut opts = no_backoff();
        opts.expected_sha256 = Some(Sha256::digest(&body));
        let blob = download_to_tmp(&url, opts).expect("hash matches");
        assert_eq!(blob.to_vec().unwrap(), body);

        let mut opts = no_backoff();
        opts.expected_sha256 = Some([0u8; 32]);
        assert!(matches!(
            download_to_tmp(&url, opts).unwrap_err(),
            Error::BadResponse(_)
        ));

        let mut opts = no_backoff();
        opts.max_size = Some(100);
        assert!(matches!(
            download_to_tmp(&url, opts).unwrap_err(),
            Error::BadResponse(_)
        ));
    }

    /// The temp front door covers the same schemes `fetch_to_file` does.
    #[test]
    fn fetch_to_tmp_dispatches_data_file_and_http() {
        let blob = fetch_to_tmp("data:text/plain;base64,aGVsbG8=", no_backoff()).unwrap();
        assert_eq!(blob.to_vec().unwrap(), b"hello");

        // `file://` URL formatting is platform-specific (Windows drive letters
        // / backslashes), so exercise that leg where the path→URL mapping is
        // trivial — as `front_door_dispatches_file_scheme` does.
        #[cfg(unix)]
        {
            let src = tmp("tmp_front_door");
            std::fs::write(&src, b"from a local file").unwrap();
            let url = format!("file://{}", src.display());
            let blob = fetch_to_tmp(&url, no_backoff()).unwrap();
            assert_eq!(blob.to_vec().unwrap(), b"from a local file");
            cleanup(&src);
        }

        let body = make_body(2_000, 0x6677);
        let port = start(Origin::shared(body.clone(), "front"));
        let blob = fetch_to_tmp(&format!("http://127.0.0.1:{port}/file"), no_backoff()).unwrap();
        assert_eq!(blob.to_vec().unwrap(), body);

        assert!(matches!(
            fetch_to_tmp("magnet:?xt=urn:btih:0000", no_backoff()).unwrap_err(),
            Error::UnsupportedScheme(_)
        ));
    }
}

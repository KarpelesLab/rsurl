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
//! Two modes (see [`DownloadOptions::segment_size`]):
//!
//! * **single-stream** (default) — one open-ended `Range: bytes=<have>-` GET
//!   streamed to disk. Partial bytes are persisted as they arrive, so a
//!   mid-stream error still makes forward progress. Forcing HTTP/1.1
//!   ([`prefer_http11`](DownloadOptions::prefer_http11), the default) keeps the
//!   body streaming off the socket so a reset leaves the received prefix on
//!   disk; on HTTP/2 the body is buffered, so forward progress there comes from
//!   resuming across attempts.
//! * **segmented** — the file is split into fixed-size chunks, each fetched by
//!   its own bounded `Range` request and tracked in a chunk bitmap. A chunk
//!   that fails is retried on its own without discarding the chunks that
//!   already landed. This is the most robust mode on a flaky link and works
//!   uniformly over HTTP/1.1 and HTTP/2.
//!
//! Both modes capture the resource's validators (URL, `ETag`, `Last-Modified`,
//! total size) in the resume state and send `If-Range`, so a resource that
//! changed between attempts is detected (the server replies `200` with the full
//! body) and the stale partial is discarded rather than spliced. On completion
//! the size (and [`expected_sha256`](DownloadOptions::expected_sha256), if
//! given) are verified before the `.rsurlpart` is atomically renamed into
//! place; a mismatch deletes the partial so the next run starts clean.

use std::fs::OpenOptions;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use purecrypto::hash::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::http::Request;
use crate::resume::{self, Kind};

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
    /// support falls back to a single retrying full download either way.
    pub segment_size: Option<u64>,
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
    pub low_speed: Option<(u64, u64)>,
    /// First backoff delay; doubles each failed retry up to `max_backoff`.
    pub initial_backoff: Duration,
    /// Ceiling for the exponential backoff between retries.
    pub max_backoff: Duration,
    /// Optional progress callback (see [`ProgressFn`]).
    pub progress: Option<ProgressFn>,
}

impl Default for DownloadOptions {
    fn default() -> Self {
        DownloadOptions {
            max_retries: 5,
            segment_size: None,
            prefer_http11: true,
            expected_sha256: None,
            max_size: None,
            max_time: None,
            limit_rate: None,
            low_speed: None,
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(30),
            progress: None,
        }
    }
}

impl std::fmt::Debug for DownloadOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DownloadOptions")
            .field("max_retries", &self.max_retries)
            .field("segment_size", &self.segment_size)
            .field("prefer_http11", &self.prefer_http11)
            .field("expected_sha256", &self.expected_sha256.is_some())
            .field("max_size", &self.max_size)
            .field("max_time", &self.max_time)
            .field("limit_rate", &self.limit_rate)
            .field("low_speed", &self.low_speed)
            .field("initial_backoff", &self.initial_backoff)
            .field("max_backoff", &self.max_backoff)
            .field("progress", &self.progress.is_some())
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
/// Convenience wrapper over [`Request::download_resumable`] for a plain GET.
pub fn download(url: &str, path: &Path, opts: DownloadOptions) -> Result<DownloadOutcome> {
    Request::get(url)?.download_resumable(path, opts)
}

impl Request {
    /// Perform this request as a resumable, retrying download into `path`.
    ///
    /// The request's method/headers/auth are preserved; the download layer adds
    /// range/validator handling, forces raw (undecoded) bytes so offsets stay
    /// byte-aligned, and follows redirects. See the [module docs](mod@crate::download).
    pub fn download_resumable(self, path: &Path, opts: DownloadOptions) -> Result<DownloadOutcome> {
        Downloader::new(self, path, opts).run()
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
    final_path: PathBuf,
    part: PathBuf,
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

impl Downloader {
    fn new(req: Request, path: &Path, opts: DownloadOptions) -> Self {
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
        Downloader {
            base,
            final_path: path.to_path_buf(),
            part: resume::part_path(path),
            url_key,
            opts,
        }
    }

    fn run(mut self) -> Result<DownloadOutcome> {
        if let Some(seg) = self.opts.segment_size.filter(|s| *s > 0) {
            match self.run_segmented(seg) {
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
                    let _ = std::fs::remove_file(&self.part);
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

        self.stream_to_disk(reader, offset, total, validators, resumable)
    }

    /// Copy the body reader into the part file starting at `offset`, applying
    /// rate/size/low-speed policies and persisting resume state periodically.
    fn stream_to_disk(
        &mut self,
        mut reader: crate::http::BodyReader,
        offset: u64,
        total: Option<u64>,
        validators: &Validators,
        resumable: bool,
    ) -> Attempt {
        let mut file = match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.part)
        {
            Ok(f) => f,
            Err(e) => return Attempt::Fatal(Error::Io(e)),
        };
        // Size the data region so the trailer/meta never overlaps real data.
        if let Some(t) = total {
            if let Err(e) = file.set_len(t) {
                return Attempt::Fatal(Error::Io(e));
            }
        } else if offset == 0 {
            // Unknown length, fresh body: drop any stale bytes.
            let _ = file.set_len(0);
        }
        if let Err(e) = file.seek(SeekFrom::Start(offset)) {
            return Attempt::Fatal(Error::Io(e));
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
            if let Err(e) = file.write_all(&buf[..n]) {
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
                        err: Error::Io(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "transfer below low-speed limit",
                        )),
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
            let _ = resume::write_state(&self.part, total, Kind::HttpStream, &meta);
        }
    }

    /// Load a prior single-stream offset + validators, if the partial matches
    /// this resource.
    fn load_stream_state(&self) -> (u64, Validators) {
        if let Ok(Some(st)) = resume::read_state(&self.part) {
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

    fn run_segmented(&mut self, chunk: u64) -> std::result::Result<DownloadOutcome, SegErr> {
        // Probe with a one-byte range to learn the total and confirm range
        // support in a single round trip (fewer server quirks than HEAD).
        let (total, validators) = self.probe_ranged()?;
        if total == 0 {
            // Empty resource: just create the file.
            std::fs::write(&self.final_path, b"").map_err(|e| SegErr::Fatal(Error::Io(e)))?;
            let _ = std::fs::remove_file(&self.part);
            return Ok(DownloadOutcome {
                bytes_written: 0,
                total: Some(0),
                resumed_from: 0,
            });
        }
        if let Some(max) = self.opts.max_size {
            if total > max {
                return Err(SegErr::Fatal(Error::BadResponse(
                    "maximum file size exceeded".into(),
                )));
            }
        }

        let num_chunks = total.div_ceil(chunk) as usize;
        let map_len = num_chunks.div_ceil(8);
        let mut bitmap = self.load_ranged_bitmap(chunk, total, &validators, map_len);
        let resumed_from = bits_set(&bitmap, num_chunks) as u64 * chunk;

        // Size the data region and stamp initial state.
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.part)
        {
            Ok(f) => f.set_len(total).map_err(|e| SegErr::Fatal(Error::Io(e)))?,
            Err(e) => return Err(SegErr::Fatal(Error::Io(e))),
        }
        self.persist_ranged(chunk, total, &validators, &bitmap);

        for i in 0..num_chunks {
            if bit_get(&bitmap, i) {
                continue;
            }
            let start = i as u64 * chunk;
            let end = (start + chunk).min(total) - 1;
            self.fetch_chunk(start, end)?;
            bit_set(&mut bitmap, i);
            self.persist_ranged(chunk, total, &validators, &bitmap);
            if let Some(cb) = self.opts.progress.as_mut() {
                cb((end + 1).min(total), Some(total));
            }
        }

        self.verify_and_finalize(total, Some(total))
            .map_err(SegErr::Fatal)?;
        Ok(DownloadOutcome {
            bytes_written: total,
            total: Some(total),
            resumed_from,
        })
    }

    /// One `bytes=start-end` GET with per-chunk retry, written at `start`.
    /// A `200` (server ignored the range) aborts to single-stream fallback.
    fn fetch_chunk(&mut self, start: u64, end: u64) -> std::result::Result<(), SegErr> {
        let mut budget = self.opts.max_retries;
        let mut attempt_no = 0u32;
        loop {
            let req = self
                .base
                .clone()
                .header("Range", &format!("bytes={start}-{end}"));
            let attempt = self.write_chunk(req, start, end);
            match attempt {
                Ok(()) => return Ok(()),
                Err(ChunkErr::Fallback) => return Err(SegErr::Fallback),
                Err(ChunkErr::Fatal(e)) => return Err(SegErr::Fatal(e)),
                Err(ChunkErr::Transient(e)) => {
                    if budget == 0 {
                        return Err(SegErr::Fatal(e));
                    }
                    budget -= 1;
                    attempt_no += 1;
                    self.backoff(attempt_no);
                }
            }
        }
    }

    fn write_chunk(&self, req: Request, start: u64, end: u64) -> std::result::Result<(), ChunkErr> {
        let reader = match req.send_reader() {
            Ok(r) => r,
            Err(e) if is_transient(&e) => return Err(ChunkErr::Transient(e)),
            Err(e) => return Err(ChunkErr::Fatal(e)),
        };
        match reader.status() {
            206 => {}
            200 => return Err(ChunkErr::Fallback),
            416 => {
                return Err(ChunkErr::Fatal(Error::BadResponse(
                    "server rejected chunk range (416)".into(),
                )))
            }
            s if (400..500).contains(&s) => return Err(ChunkErr::Fatal(status_error(s, &reader))),
            s if s >= 500 => return Err(ChunkErr::Transient(status_error(s, &reader))),
            s => {
                return Err(ChunkErr::Fatal(Error::BadResponse(format!(
                    "unexpected status {s}"
                ))))
            }
        }
        let want = (end - start + 1) as usize;
        let mut file = OpenOptions::new()
            .write(true)
            .open(&self.part)
            .map_err(|e| ChunkErr::Fatal(Error::Io(e)))?;
        file.seek(SeekFrom::Start(start))
            .map_err(|e| ChunkErr::Fatal(Error::Io(e)))?;
        // Buffer the (bounded) chunk, then commit it in one write so a partial
        // chunk never marks the bit as done.
        let mut body = Vec::with_capacity(want);
        if let Err(e) = reader.take(want as u64 + 1).read_to_end(&mut body) {
            return Err(ChunkErr::Transient(Error::Io(e)));
        }
        if body.len() != want {
            return Err(ChunkErr::Transient(Error::BadResponse(format!(
                "short chunk: got {} of {want} bytes",
                body.len()
            ))));
        }
        file.write_all(&body)
            .map_err(|e| ChunkErr::Transient(Error::Io(e)))?;
        Ok(())
    }

    fn probe_ranged(&self) -> std::result::Result<(u64, Validators), SegErr> {
        let mut budget = self.opts.max_retries;
        let mut attempt_no = 0u32;
        loop {
            let req = self.base.clone().header("Range", "bytes=0-0");
            match req.send_reader() {
                Ok(reader) => {
                    let status = reader.status();
                    if status == 206 {
                        let validators = self.validators_from(&reader);
                        match parse_content_range(reader.header("content-range")) {
                            Some((_, Some(total))) => return Ok((total, validators)),
                            // 206 without a usable total → can't segment.
                            _ => return Err(SegErr::Fallback),
                        }
                    } else if status == 200 || status == 416 {
                        return Err(SegErr::Fallback);
                    } else if (400..500).contains(&status) {
                        return Err(SegErr::Fatal(status_error(status, &reader)));
                    } else if status >= 500 && budget > 0 {
                        budget -= 1;
                        attempt_no += 1;
                        self.backoff(attempt_no);
                    } else {
                        return Err(SegErr::Fatal(status_error(status, &reader)));
                    }
                }
                Err(e) if is_transient(&e) && budget > 0 => {
                    budget -= 1;
                    attempt_no += 1;
                    self.backoff(attempt_no);
                }
                Err(e) => return Err(SegErr::Fatal(e)),
            }
        }
    }

    fn load_ranged_bitmap(
        &self,
        chunk: u64,
        total: u64,
        validators: &Validators,
        map_len: usize,
    ) -> Vec<u8> {
        if let Ok(Some(st)) = resume::read_state(&self.part) {
            if st.kind == Kind::HttpRanged {
                if let Some(bm) = parse_ranged_meta(&st.meta, chunk, total, validators) {
                    if bm.len() == map_len {
                        return bm;
                    }
                }
            }
        }
        vec![0u8; map_len]
    }

    fn persist_ranged(&self, chunk: u64, total: u64, validators: &Validators, bitmap: &[u8]) {
        let meta = ranged_meta(chunk, total, validators, bitmap);
        let _ = resume::write_state(&self.part, total, Kind::HttpRanged, &meta);
    }

    // ---- shared helpers ----------------------------------------------------

    fn validators_from(&self, reader: &crate::http::BodyReader) -> Validators {
        Validators {
            url: self.url_key.clone(),
            etag: reader.header("etag").unwrap_or("").to_string(),
            last_modified: reader.header("last-modified").unwrap_or("").to_string(),
        }
    }

    /// Verify size + optional SHA-256, then atomically rename into place. On a
    /// mismatch the partial is deleted so the next run starts clean.
    fn verify_and_finalize(&self, real_size: u64, _total: Option<u64>) -> Result<DownloadOutcome> {
        if let Some(want) = self.opts.expected_sha256 {
            match hash_prefix(&self.part, real_size) {
                Ok(got) if got == want => {}
                Ok(_) => {
                    let _ = std::fs::remove_file(&self.part);
                    return Err(Error::BadResponse(
                        "downloaded file failed SHA-256 verification".into(),
                    ));
                }
                Err(e) => return Err(Error::Io(e)),
            }
        }
        resume::finalize(&self.part, &self.final_path, real_size).map_err(Error::Io)?;
        Ok(DownloadOutcome {
            bytes_written: real_size,
            total: Some(real_size),
            resumed_from: 0,
        })
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

/// Per-chunk attempt error in segmented mode.
enum ChunkErr {
    Transient(Error),
    Fatal(Error),
    /// The server served a full body for a ranged request — no range support.
    Fallback,
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

fn parse_ranged_meta(meta: &[u8], chunk: u64, total: u64, cur: &Validators) -> Option<Vec<u8>> {
    if meta.len() < 16 {
        return None;
    }
    if u32::from_le_bytes(meta[0..4].try_into().unwrap()) != chunk as u32 {
        return None;
    }
    if u64::from_le_bytes(meta[4..12].try_into().unwrap()) != total {
        return None;
    }
    let vlen = u32::from_le_bytes(meta[12..16].try_into().unwrap()) as usize;
    let rest = meta.get(16..)?;
    let stored = decode_validators(rest.get(..vlen)?)?;
    let bitmap = rest.get(vlen..)?.to_vec();
    if !validators_match(&stored, cur) {
        return None;
    }
    Some(bitmap)
}

/// Same resource if the URL matches and, when both carry an `ETag`, they agree.
/// `Last-Modified` is intentionally ignored (it can differ across mirrors).
fn validators_match(stored: &Validators, cur: &Validators) -> bool {
    stored.url == cur.url
        && (cur.etag.is_empty() || stored.etag.is_empty() || stored.etag == cur.etag)
}

fn bit_get(map: &[u8], i: usize) -> bool {
    map[i / 8] & (1 << (i % 8)) != 0
}
fn bit_set(map: &mut [u8], i: usize) {
    map[i / 8] |= 1 << (i % 8);
}
fn bits_set(map: &[u8], num_chunks: usize) -> usize {
    (0..num_chunks).filter(|&i| bit_get(map, i)).count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
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
                ranges: Vec::new(),
            }))
        }
    }

    fn start(origin: Arc<Mutex<Origin>>) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut sock) = conn else { continue };
                handle(&mut sock, &origin);
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
        let mut o = origin.lock().unwrap();
        let range = header_val(&head, "range").map(|s| s.to_string());
        let if_range = header_val(&head, "if-range").map(|s| s.to_string());
        o.ranges.push(range.clone().unwrap_or_default());

        let len = o.body.len() as u64;
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
        let payload = slice[..send_n].to_vec();
        drop(o); // release the lock before the (possibly slow) write

        let _ = sock.write_all(head_bytes.as_bytes());
        let _ = sock.write_all(&payload);
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
        // 1 probe (bytes=0-0) + 10 chunk GETs + 1 retry of the failed chunk.
        assert_eq!(ranges.len(), 12, "ranges: {ranges:?}");
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
}

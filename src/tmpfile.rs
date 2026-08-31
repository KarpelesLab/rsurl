//! Anonymous temporary storage — a transfer target with no file on disk.
//!
//! [`TempBlob`] is what [`crate::download::download_to_tmp`] hands back: bytes
//! the caller reads, seeks and drops without ever naming a path, creating a
//! visible file, or cleaning one up. Payloads below the spill threshold
//! ([`DEFAULT_SPILL_THRESHOLD`], 1 MiB) live in memory; anything larger spills
//! to an **anonymous** OS file — one with no directory entry, so nothing is
//! left behind even if the process is killed:
//!
//! * **Linux** — `open(dir, O_TMPFILE | O_RDWR, 0600)`: the inode never gets a
//!   name at all.
//! * **Other Unix** — create `0600` with `O_EXCL`, then `unlink` immediately;
//!   the name exists only between those two syscalls.
//! * **Windows** — `FILE_FLAG_DELETE_ON_CLOSE | FILE_ATTRIBUTE_TEMPORARY`
//!   (there is no anonymous-file API): the name lives as long as the handle,
//!   and the file is gone when it closes.
//!
//! The caller doesn't have to know which backing it got. `TempBlob` is
//! [`Read`] + [`Seek`] + [`Write`] with a positional
//! [`read_at`](TempBlob::read_at) / [`write_at`](TempBlob::write_at) pair (the
//! Rust spelling of Go's `io.ReaderAt`), and `Drop` releases whichever backing
//! it holds — [`close`](TempBlob::close) is there for callers who want to say
//! so explicitly (and to see an error if one surfaces).
//!
//! Sequential [`Write`] appends at the end of the blob; the [`Read`] / [`Seek`]
//! cursor is independent of it, so a freshly written blob is read from the
//! start without rewinding.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{SystemTime, UNIX_EPOCH};

/// Payloads at or below this many bytes stay in memory; larger ones spill to an
/// anonymous file. 1 MiB.
pub const DEFAULT_SPILL_THRESHOLD: u64 = 1 << 20;

/// Where a [`TempBlob`]'s bytes actually live.
enum Backing {
    Mem(Vec<u8>),
    File(File),
}

/// Anonymous temporary storage: memory while small, an unnamed OS file once it
/// grows past the spill threshold. See the [module docs](mod@crate::tmpfile).
///
/// ```no_run
/// use std::io::Read;
///
/// let mut tmp = rsurl::download::download_to_tmp(
///     "https://example.com/big.bin",
///     rsurl::DownloadOptions::default(),
/// )?;
/// let mut head = [0u8; 16];
/// tmp.read_exact(&mut head)?;          // Read + Seek, wherever it lives
/// println!("{} bytes, in memory: {}", tmp.len(), tmp.is_in_memory());
/// tmp.close()?;                        // or just let it drop
/// # Ok::<(), rsurl::Error>(())
/// ```
pub struct TempBlob {
    inner: RwLock<Backing>,
    /// Logical length. Tracked here rather than read off the backing so the
    /// file case doesn't need a `stat` per write, and so a sparse pre-sized
    /// region reports the size it will have.
    len: AtomicU64,
    /// Byte count above which the blob spills to an anonymous file.
    threshold: u64,
    /// Directory the anonymous file is created in (`None` → the OS temp dir).
    dir: Option<PathBuf>,
    /// The [`Read`] / [`Seek`] cursor. Independent of appending writes.
    pos: u64,
}

impl TempBlob {
    /// An empty blob with the default 1 MiB spill threshold, spilling into the
    /// OS temp directory.
    pub fn new() -> Self {
        TempBlob::with_threshold(DEFAULT_SPILL_THRESHOLD)
    }

    /// An empty blob that spills once it exceeds `threshold` bytes. A threshold
    /// of `0` spills immediately (every byte goes to the anonymous file).
    pub fn with_threshold(threshold: u64) -> Self {
        TempBlob {
            inner: RwLock::new(Backing::Mem(Vec::new())),
            len: AtomicU64::new(0),
            threshold,
            dir: None,
            pos: 0,
        }
    }

    /// Create the anonymous file in `dir` instead of the OS temp directory.
    /// Only matters if the blob actually spills.
    pub fn in_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.dir = Some(dir.into());
        self
    }

    /// Bytes currently held.
    pub fn len(&self) -> u64 {
        self.len.load(Ordering::Acquire)
    }

    /// Whether the blob holds no bytes.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The size above which this blob spills to an anonymous file.
    pub fn spill_threshold(&self) -> u64 {
        self.threshold
    }

    /// Whether the bytes are still in memory (`false` once spilled).
    pub fn is_in_memory(&self) -> bool {
        matches!(&*self.read_guard(), Backing::Mem(_))
    }

    /// Move the contents to an anonymous file now, whatever the threshold says.
    /// A no-op once spilled.
    pub fn spill(&self) -> io::Result<()> {
        let mut g = self.write_guard();
        spill_locked(&mut g, self.dir.as_deref())
    }

    /// Write `buf` at absolute offset `at`, extending the blob (with zeros, if
    /// `at` is past the end) as needed.
    ///
    /// Takes `&self`: several threads may write disjoint ranges concurrently,
    /// which is what lets a segmented download land its chunks in parallel.
    pub fn write_at(&self, at: u64, buf: &[u8]) -> io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let end = at
            .checked_add(buf.len() as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;

        // Fast path: already spilled, so positional writes need no exclusion.
        {
            let g = self.read_guard();
            if let Backing::File(f) = &*g {
                write_all_at(f, at, buf)?;
                drop(g);
                self.grow_to(end);
                return Ok(());
            }
        }

        let mut g = self.write_guard();
        if matches!(&*g, Backing::Mem(_)) && end > self.threshold {
            spill_locked(&mut g, self.dir.as_deref())?;
        }
        match &mut *g {
            Backing::File(f) => write_all_at(f, at, buf)?,
            Backing::Mem(v) => {
                if (v.len() as u64) < end {
                    v.resize(usize_len(end)?, 0);
                }
                let start = usize_len(at)?;
                v[start..start + buf.len()].copy_from_slice(buf);
            }
        }
        drop(g);
        self.grow_to(end);
        Ok(())
    }

    /// Read into `buf` from absolute offset `at`, returning how many bytes were
    /// read (`0` at or past the end). Does not move the [`Read`] cursor.
    pub fn read_at(&self, buf: &mut [u8], at: u64) -> io::Result<usize> {
        let len = self.len();
        if buf.is_empty() || at >= len {
            return Ok(0);
        }
        let cap = ((len - at) as usize).min(buf.len());
        match &*self.read_guard() {
            Backing::Mem(v) => {
                let start = usize_len(at)?;
                let n = cap.min(v.len().saturating_sub(start));
                buf[..n].copy_from_slice(&v[start..start + n]);
                Ok(n)
            }
            Backing::File(f) => read_at_file(f, &mut buf[..cap], at),
        }
    }

    /// Set the logical length: truncate, or extend with zeros. On a file
    /// backing the extension is sparse, so pre-sizing a large download costs no
    /// disk until the bytes land. Pre-sizing past the threshold spills first,
    /// rather than allocating that much memory.
    pub fn set_len(&self, n: u64) -> io::Result<()> {
        let mut g = self.write_guard();
        if matches!(&*g, Backing::Mem(_)) && n > self.threshold {
            spill_locked(&mut g, self.dir.as_deref())?;
        }
        match &mut *g {
            Backing::File(f) => f.set_len(n)?,
            Backing::Mem(v) => v.resize(usize_len(n)?, 0),
        }
        drop(g);
        self.len.store(n, Ordering::Release);
        Ok(())
    }

    /// Drop every byte held, keeping the blob usable (and its backing, once
    /// spilled).
    pub fn clear(&self) -> io::Result<()> {
        self.set_len(0)
    }

    /// Read the whole blob into memory, from offset 0.
    pub fn to_vec(&self) -> io::Result<Vec<u8>> {
        let len = usize_len(self.len())?;
        let mut out = vec![0u8; len];
        let mut done = 0usize;
        while done < len {
            let n = self.read_at(&mut out[done..], done as u64)?;
            if n == 0 {
                out.truncate(done);
                break;
            }
            done += n;
        }
        Ok(out)
    }

    /// Release the backing: the memory is freed, or the anonymous file's last
    /// handle closes and the OS reclaims it. Dropping the blob does exactly the
    /// same thing — this spelling is for callers who want the close to be
    /// explicit (and it is deliberately fallible, so a future backing that can
    /// fail to close has somewhere to report it). Nothing is flushed: an
    /// anonymous file has no readers after this point.
    pub fn close(self) -> io::Result<()> {
        drop(self.inner.into_inner().unwrap_or_else(|e| e.into_inner()));
        Ok(())
    }

    fn read_guard(&self) -> RwLockReadGuard<'_, Backing> {
        self.inner.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write_guard(&self) -> RwLockWriteGuard<'_, Backing> {
        self.inner.write().unwrap_or_else(|e| e.into_inner())
    }

    /// Extend the recorded length to cover `end` (never shrinks it — that is
    /// [`set_len`](Self::set_len)'s job).
    fn grow_to(&self, end: u64) {
        self.len.fetch_max(end, Ordering::AcqRel);
    }
}

impl Default for TempBlob {
    fn default() -> Self {
        TempBlob::new()
    }
}

impl fmt::Debug for TempBlob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TempBlob")
            .field("len", &self.len())
            .field("backing", &if self.is_in_memory() { "memory" } else { "anonymous file" })
            .field("spill_threshold", &self.threshold)
            .finish()
    }
}

/// Sequential reads from the blob's own cursor (independent of appends).
impl Read for TempBlob {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.read_at(buf, self.pos)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for TempBlob {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let want = match from {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(d) => offset(self.len(), d),
            SeekFrom::Current(d) => offset(self.pos, d),
        };
        match want {
            Some(p) => {
                self.pos = p;
                Ok(p)
            }
            None => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek to a negative or overflowing position",
            )),
        }
    }

    fn stream_position(&mut self) -> io::Result<u64> {
        Ok(self.pos)
    }
}

/// Appends at the end of the blob. The [`Read`] cursor is not touched.
impl Write for TempBlob {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_at(self.len(), buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// `base + delta` as a byte offset, or `None` if it would go negative/overflow.
fn offset(base: u64, delta: i64) -> Option<u64> {
    if delta >= 0 {
        base.checked_add(delta as u64)
    } else {
        base.checked_sub(delta.unsigned_abs())
    }
}

/// A `u64` byte count as a `usize`, refusing what this platform can't address.
fn usize_len(n: u64) -> io::Result<usize> {
    usize::try_from(n).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "size exceeds this platform's address space",
        )
    })
}

/// Replace an in-memory backing with an anonymous file holding the same bytes.
/// A no-op if already spilled.
fn spill_locked(g: &mut RwLockWriteGuard<'_, Backing>, dir: Option<&Path>) -> io::Result<()> {
    let bytes = match &mut **g {
        Backing::File(_) => return Ok(()),
        Backing::Mem(v) => std::mem::take(v),
    };
    let file = anon_file(dir)?;
    if !bytes.is_empty() {
        write_all_at(&file, 0, &bytes)?;
    }
    **g = Backing::File(file);
    Ok(())
}

/// Open an anonymous file in `dir` (the OS temp dir when `None`). See the
/// module docs for what "anonymous" means on each platform.
fn anon_file(dir: Option<&Path>) -> io::Result<File> {
    let owned;
    let dir = match dir {
        Some(d) => d,
        None => {
            owned = std::env::temp_dir();
            &owned
        }
    };
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Ok(f) = o_tmpfile(dir) {
        return Ok(f);
    }
    unnamed_file(dir)
}

/// `O_TMPFILE`: a file with no directory entry, ever. Linux ≥ 3.11 on a
/// filesystem that supports it; every other case falls back to the
/// create-then-unlink path.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn o_tmpfile(dir: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    // O_TMPFILE = O_DIRECTORY | 0o20000000 on every Linux architecture Rust
    // targets. Not exported by std, and rsurl links no libc, so it is spelled
    // out here; a wrong guess would just fail the open and fall back.
    const O_TMPFILE: i32 = 0o20_200_000;
    OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(O_TMPFILE)
        .mode(0o600)
        .open(dir)
}

/// Create a uniquely named file and immediately strip its name: `unlink` on
/// Unix, `FILE_FLAG_DELETE_ON_CLOSE` on Windows (which keeps the name until the
/// handle closes — the closest that platform offers).
fn unnamed_file(dir: &Path) -> io::Result<File> {
    let mut last = io::Error::other("no temp name attempted");
    for attempt in 0..32u32 {
        let path = dir.join(unique_name(attempt));
        match create_exclusive(&path) {
            Ok(f) => {
                #[cfg(unix)]
                {
                    // The name existed only for these two syscalls; the open
                    // handle keeps the inode alive with nothing pointing at it.
                    std::fs::remove_file(&path)?;
                }
                return Ok(f);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = e,
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

#[cfg(unix)]
fn create_exclusive(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(windows)]
fn create_exclusive(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    /// Hint to the cache manager to avoid flushing to disk where it can.
    const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x0000_0100;
    /// Delete the file once the last handle to it closes.
    const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;
    /// Let the deletion go through while our own handle is open.
    const FILE_SHARE_ALL: u32 = 0x0000_0007;
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(FILE_SHARE_ALL)
        .attributes(FILE_ATTRIBUTE_TEMPORARY)
        .custom_flags(FILE_FLAG_DELETE_ON_CLOSE)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
fn create_exclusive(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
}

/// A name unlikely to collide: pid + monotonically bumped counter + clock. It
/// exists for at most two syscalls (Unix) or the handle's lifetime (Windows).
fn unique_name(attempt: u32) -> String {
    use std::sync::atomic::AtomicU64;
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(".rsurl-tmp-{}-{nanos}-{n}-{attempt}", std::process::id())
}

/// Positional write of the whole buffer — no shared file cursor, so concurrent
/// writers to disjoint ranges don't interfere.
#[cfg(unix)]
pub(crate) fn write_all_at(f: &File, at: u64, buf: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    f.write_all_at(buf, at)
}

#[cfg(windows)]
pub(crate) fn write_all_at(f: &File, at: u64, buf: &[u8]) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    let mut done = 0usize;
    while done < buf.len() {
        match f.seek_write(&buf[done..], at + done as u64) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write whole buffer",
                ))
            }
            Ok(n) => done += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn write_all_at(_f: &File, _at: u64, _buf: &[u8]) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "positional writes are not supported on this platform",
    ))
}

#[cfg(unix)]
fn read_at_file(f: &File, buf: &mut [u8], at: u64) -> io::Result<usize> {
    use std::os::unix::fs::FileExt;
    f.read_at(buf, at)
}

#[cfg(windows)]
fn read_at_file(f: &File, buf: &mut [u8], at: u64) -> io::Result<usize> {
    use std::os::windows::fs::FileExt;
    f.seek_read(buf, at)
}

#[cfg(not(any(unix, windows)))]
fn read_at_file(_f: &File, _buf: &mut [u8], _at: u64) -> io::Result<usize> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "positional reads are not supported on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_payload_stays_in_memory() {
        let mut b = TempBlob::new();
        b.write_all(b"hello temp").unwrap();
        assert!(b.is_in_memory());
        assert_eq!(b.len(), 10);
        assert_eq!(b.to_vec().unwrap(), b"hello temp");

        let mut got = Vec::new();
        b.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"hello temp");
    }

    #[test]
    fn crossing_the_threshold_spills_and_keeps_the_bytes() {
        let b = TempBlob::with_threshold(16);
        b.write_at(0, b"0123456789").unwrap();
        assert!(b.is_in_memory(), "under threshold");
        b.write_at(10, b"abcdefghij").unwrap();
        assert!(!b.is_in_memory(), "20 bytes > 16-byte threshold");
        assert_eq!(b.len(), 20);
        assert_eq!(b.to_vec().unwrap(), b"0123456789abcdefghij");
    }

    #[test]
    fn read_at_and_seek_agree_across_backings() {
        for threshold in [u64::MAX, 0] {
            let mut b = TempBlob::with_threshold(threshold);
            b.write_all(b"abcdefghij").unwrap();
            assert_eq!(b.is_in_memory(), threshold == u64::MAX);

            let mut buf = [0u8; 4];
            assert_eq!(b.read_at(&mut buf, 3).unwrap(), 4);
            assert_eq!(&buf, b"defg");
            // read_at leaves the cursor alone.
            assert_eq!(b.stream_position().unwrap(), 0);

            assert_eq!(b.seek(SeekFrom::End(-3)).unwrap(), 7);
            let mut tail = Vec::new();
            b.read_to_end(&mut tail).unwrap();
            assert_eq!(tail, b"hij");
            // Past the end reads nothing rather than erroring.
            assert_eq!(b.read_at(&mut buf, 999).unwrap(), 0);
            assert!(b.seek(SeekFrom::End(-99)).is_err());
        }
    }

    #[test]
    fn sparse_writes_zero_fill_and_set_len_truncates() {
        let b = TempBlob::with_threshold(8);
        b.write_at(4, b"XY").unwrap();
        assert_eq!(b.len(), 6);
        assert_eq!(b.to_vec().unwrap(), b"\0\0\0\0XY");

        // Pre-size past the threshold: spills instead of allocating.
        b.set_len(64).unwrap();
        assert!(!b.is_in_memory());
        assert_eq!(b.len(), 64);
        b.set_len(6).unwrap();
        assert_eq!(b.to_vec().unwrap(), b"\0\0\0\0XY");
        b.clear().unwrap();
        assert!(b.is_empty());
    }

    #[test]
    fn concurrent_positional_writes_land_in_the_right_places() {
        use std::sync::Arc;
        let b = Arc::new(TempBlob::with_threshold(0)); // file-backed from byte 0
        b.set_len(4 * 4096).unwrap();
        let mut hs = Vec::new();
        for i in 0..4u64 {
            let b = Arc::clone(&b);
            hs.push(std::thread::spawn(move || {
                b.write_at(i * 4096, &vec![b'a' + i as u8; 4096]).unwrap();
            }));
        }
        for h in hs {
            h.join().unwrap();
        }
        let all = b.to_vec().unwrap();
        assert_eq!(all.len(), 4 * 4096);
        for i in 0..4usize {
            assert!(all[i * 4096..(i + 1) * 4096]
                .iter()
                .all(|&c| c == b'a' + i as u8));
        }
    }

    /// The spilled file must not be reachable by name: the temp directory gains
    /// no `.rsurl-tmp-*` entry that outlives (or even coexists with, on Unix)
    /// the handle.
    #[cfg(unix)]
    #[test]
    fn spilled_file_has_no_name() {
        let dir = std::env::temp_dir().join(format!("rsurl-anon-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        {
            let b = TempBlob::with_threshold(0).in_dir(&dir);
            b.write_at(0, b"invisible").unwrap();
            assert!(!b.is_in_memory());
            let entries: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
            assert!(
                entries.is_empty(),
                "anonymous file left a directory entry: {entries:?}"
            );
            assert_eq!(b.to_vec().unwrap(), b"invisible");
        }
        let entries: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
        assert!(entries.is_empty(), "temp dir not clean after drop");
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn close_reports_success_for_both_backings() {
        TempBlob::new().close().unwrap();
        let b = TempBlob::with_threshold(0);
        b.write_at(0, b"x").unwrap();
        b.close().unwrap();
    }
}

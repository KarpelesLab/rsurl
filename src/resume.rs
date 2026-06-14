//! Shared partial-download format for resumable transfers.
//!
//! An in-progress download is written to a `<name>.rsurlpart` file: the data at
//! its true byte offsets (so it may be sparse), followed by an opaque
//! caller-defined *metadata block*, followed by a fixed 32-byte **trailer** at
//! EOF (ZIP-style — the trailer is found by seeking from the end). On
//! completion the file is truncated to `real_size` (dropping the metadata +
//! trailer) and renamed to its final name.
//!
//! The same container doubles as a *sidecar*: a multi-file torrent writes its
//! state to a hidden `<dir>/.rsurlpart` whose data region is empty
//! (`real_size == 0`), so the file is just `[meta][trailer]`.
//!
//! The metadata block is opaque here — each subsystem (the torrent engine, HTTP
//! download) defines and parses its own contents, keyed by [`Kind`]. This
//! module only frames it and verifies integrity, so it stays free of the
//! `bittorrent` feature and is usable by plain HTTP downloads.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Trailer magic — also lets us recognise a `.rsurlpart` on sight.
const MAGIC: &[u8; 8] = b"RSURLPRT";
/// Current on-disk format version.
const VERSION: u16 = 1;
/// Fixed trailer size in bytes (see module docs for the layout).
pub const TRAILER_LEN: u64 = 32;

/// What kind of transfer produced the metadata block (so the right parser is
/// used on resume).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// BitTorrent: meta holds the infohash + piece bitfield.
    Torrent,
    /// Single-stream HTTP: meta holds the contiguous byte count + validators.
    HttpStream,
    /// Ranged/parallel HTTP: meta holds a chunk bitmap + validators.
    HttpRanged,
}

impl Kind {
    fn to_u16(self) -> u16 {
        match self {
            Kind::Torrent => 1,
            Kind::HttpStream => 2,
            Kind::HttpRanged => 3,
        }
    }
    fn from_u16(v: u16) -> Option<Kind> {
        match v {
            1 => Some(Kind::Torrent),
            2 => Some(Kind::HttpStream),
            3 => Some(Kind::HttpRanged),
            _ => None,
        }
    }
}

/// Decoded resume state read back from a `.rsurlpart` container.
#[derive(Debug, Clone)]
pub struct ResumeState {
    /// Final size of the data region (0 for a sidecar).
    pub real_size: u64,
    pub kind: Kind,
    /// The caller's opaque metadata block.
    pub meta: Vec<u8>,
}

/// The partial-file path for a final output path: appends `.rsurlpart`.
///
/// Note this *appends* rather than replacing the extension (so `video.mkv`
/// becomes `video.mkv.rsurlpart`, not `video.rsurlpart`).
pub fn part_path(final_path: &Path) -> PathBuf {
    let mut s: OsString = final_path.as_os_str().to_os_string();
    s.push(".rsurlpart");
    PathBuf::from(s)
}

/// Read and validate the trailer of `path`, returning its [`ResumeState`].
///
/// Returns `Ok(None)` when the file is missing, too short, or its trailer is
/// not a valid, CRC-matching rsurl trailer — i.e. there is no usable state and
/// the caller should start fresh.
pub fn read_state(path: &Path) -> io::Result<Option<ResumeState>> {
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let total = f.metadata()?.len();
    if total < TRAILER_LEN {
        return Ok(None);
    }
    let mut t = [0u8; TRAILER_LEN as usize];
    f.seek(SeekFrom::Start(total - TRAILER_LEN))?;
    f.read_exact(&mut t)?;
    if &t[0..8] != MAGIC {
        return Ok(None);
    }
    let version = u16::from_le_bytes([t[8], t[9]]);
    if version != VERSION {
        return Ok(None);
    }
    let Some(kind) = Kind::from_u16(u16::from_le_bytes([t[10], t[11]])) else {
        return Ok(None);
    };
    let real_size = u64::from_le_bytes(t[12..20].try_into().unwrap());
    let meta_len = u64::from_le_bytes(t[20..28].try_into().unwrap());
    let crc = u32::from_le_bytes(t[28..32].try_into().unwrap());

    // The meta block sits immediately after the data region.
    if real_size
        .checked_add(meta_len)
        .and_then(|n| n.checked_add(TRAILER_LEN))
        != Some(total)
    {
        return Ok(None);
    }
    let meta_len_usize = match usize::try_from(meta_len) {
        Ok(n) => n,
        Err(_) => return Ok(None),
    };
    let mut meta = vec![0u8; meta_len_usize];
    f.seek(SeekFrom::Start(real_size))?;
    f.read_exact(&mut meta)?;
    if crc32(&meta) != crc {
        return Ok(None);
    }
    Ok(Some(ResumeState {
        real_size,
        kind,
        meta,
    }))
}

/// Write (or overwrite) the metadata block + trailer of the container at
/// `path`, leaving the data region `[0, real_size)` untouched.
///
/// The trailer is written last and carries a CRC of the meta block, so a torn
/// write is detected on the next [`read_state`] (which then reports no state).
/// The file is created if absent (a sidecar uses `real_size == 0`).
pub fn write_state(path: &Path, real_size: u64, kind: Kind, meta: &[u8]) -> io::Result<()> {
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    f.seek(SeekFrom::Start(real_size))?;
    f.write_all(meta)?;
    let mut t = [0u8; TRAILER_LEN as usize];
    t[0..8].copy_from_slice(MAGIC);
    t[8..10].copy_from_slice(&VERSION.to_le_bytes());
    t[10..12].copy_from_slice(&kind.to_u16().to_le_bytes());
    t[12..20].copy_from_slice(&real_size.to_le_bytes());
    t[20..28].copy_from_slice(&(meta.len() as u64).to_le_bytes());
    t[28..32].copy_from_slice(&crc32(meta).to_le_bytes());
    f.write_all(&t)?;
    // Drop any stale bytes from a previously-larger meta block.
    let end = real_size + meta.len() as u64 + TRAILER_LEN;
    f.set_len(end)?;
    f.flush()
}

/// Finalise a completed single-file download: truncate the data file to
/// `real_size` (dropping the meta + trailer) and rename it to `final_path`.
///
/// The caller must have dropped all open handles to `part_path` first (Windows
/// refuses to rename an open file).
pub fn finalize(part_path: &Path, final_path: &Path, real_size: u64) -> io::Result<()> {
    {
        let f = OpenOptions::new().write(true).open(part_path)?;
        f.set_len(real_size)?;
    }
    std::fs::rename(part_path, final_path)
}

/// CRC-32 (IEEE 802.3, the zlib/PNG polynomial), computed without a table.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("rsurl_resume_{}_{}", std::process::id(), name))
    }

    #[test]
    fn crc32_known_vector() {
        // CRC-32 of "123456789" is 0xCBF43926.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn part_path_appends_extension() {
        assert_eq!(
            part_path(Path::new("/d/video.mkv")),
            PathBuf::from("/d/video.mkv.rsurlpart")
        );
        assert_eq!(
            part_path(Path::new("noext")),
            PathBuf::from("noext.rsurlpart")
        );
    }

    #[test]
    fn data_plus_trailer_round_trip() {
        let p = tmp("rt.bin");
        let _ = std::fs::remove_file(&p);
        // Lay down a data region, then the state.
        let data = b"hello world payload";
        std::fs::write(&p, data).unwrap();
        let meta = b"some-opaque-metadata".to_vec();
        write_state(&p, data.len() as u64, Kind::HttpStream, &meta).unwrap();

        let st = read_state(&p).unwrap().expect("state");
        assert_eq!(st.real_size, data.len() as u64);
        assert_eq!(st.kind, Kind::HttpStream);
        assert_eq!(st.meta, meta);
        // Data region is intact.
        let mut f = File::open(&p).unwrap();
        let mut buf = vec![0u8; data.len()];
        f.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, data);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn sidecar_round_trip() {
        let p = tmp("sidecar");
        let _ = std::fs::remove_file(&p);
        let meta = vec![1, 2, 3, 4, 5];
        write_state(&p, 0, Kind::Torrent, &meta).unwrap();
        let st = read_state(&p).unwrap().expect("state");
        assert_eq!(st.real_size, 0);
        assert_eq!(st.kind, Kind::Torrent);
        assert_eq!(st.meta, meta);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn rewrite_shrinks_stale_meta() {
        let p = tmp("rewrite");
        let _ = std::fs::remove_file(&p);
        write_state(&p, 0, Kind::Torrent, &[7u8; 100]).unwrap();
        write_state(&p, 0, Kind::Torrent, &[9u8; 4]).unwrap();
        let st = read_state(&p).unwrap().expect("state");
        assert_eq!(st.meta, vec![9u8; 4]);
        // File is exactly meta + trailer (no stale tail).
        assert_eq!(std::fs::metadata(&p).unwrap().len(), 4 + TRAILER_LEN);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn corruption_is_rejected() {
        let p = tmp("corrupt");
        let _ = std::fs::remove_file(&p);
        std::fs::write(&p, b"data").unwrap();
        write_state(&p, 4, Kind::HttpStream, b"meta").unwrap();
        // Flip a byte in the meta region → CRC mismatch → no usable state.
        let mut bytes = std::fs::read(&p).unwrap();
        bytes[5] ^= 0xFF;
        std::fs::write(&p, &bytes).unwrap();
        assert!(read_state(&p).unwrap().is_none());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn missing_and_short_files_are_none() {
        let p = tmp("missing");
        let _ = std::fs::remove_file(&p);
        assert!(read_state(&p).unwrap().is_none());
        std::fs::write(&p, b"tiny").unwrap();
        assert!(read_state(&p).unwrap().is_none());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn finalize_truncates_and_renames() {
        let part = tmp("fin.part");
        let fin = tmp("fin.out");
        let _ = std::fs::remove_file(&part);
        let _ = std::fs::remove_file(&fin);
        let data = b"final contents here";
        std::fs::write(&part, data).unwrap();
        write_state(&part, data.len() as u64, Kind::HttpStream, b"xx").unwrap();
        assert!(std::fs::metadata(&part).unwrap().len() > data.len() as u64);

        finalize(&part, &fin, data.len() as u64).unwrap();
        assert!(!part.exists());
        assert_eq!(std::fs::read(&fin).unwrap(), data);
        let _ = std::fs::remove_file(&fin);
    }
}

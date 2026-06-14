//! Download entry point and shared transfer types.
//!
//! [`download`] builds the [`Storage`] and hands the
//! swarm to [`engine::run`], which fetches and verifies
//! pieces from many peers concurrently. It also drives resume: the partial
//! data is held in a [`crate::resume`] container (an in-file trailer for a
//! single-file torrent, a `<topdir>/.rsurlpart` sidecar for a multi-file one),
//! the verified-piece bitfield is persisted periodically, and on completion
//! the single-file partial is truncated + renamed to its final name.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::Result;
use crate::resume;

use super::engine;
use super::metainfo::Metainfo;
use super::picker::Bitfield;
use super::seed;
use super::storage::Storage;

/// When (if ever) to keep seeding after the download completes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SeedMode {
    /// Exit as soon as the download completes (the curl-like default).
    Off,
    /// Keep seeding until the process is terminated.
    Forever,
    /// Keep seeding until uploaded/downloaded reaches this ratio.
    UntilRatio(f64),
}

/// Knobs for a torrent transfer.
#[derive(Debug, Clone)]
pub struct TorrentOptions {
    /// 20-byte peer id; if all-zero, [`download`] generates a random one.
    pub peer_id: [u8; 20],
    /// Port we advertise to peers/trackers and listen on when seeding.
    pub listen_port: u16,
    pub connect_timeout: Duration,
    /// Per-read/write socket timeout for a peer connection.
    pub peer_timeout: Duration,
    /// Whether to seed after completing (and for how long).
    pub seed: SeedMode,
    /// Diagnostic verbosity to stderr: 0 = quiet, 1 = periodic swarm summary,
    /// 2+ = per-peer lifecycle. Driven by repeated `-v`.
    pub verbosity: u8,
}

impl Default for TorrentOptions {
    fn default() -> Self {
        TorrentOptions {
            peer_id: [0u8; 20],
            listen_port: 6881,
            connect_timeout: Duration::from_secs(10),
            peer_timeout: Duration::from_secs(30),
            seed: SeedMode::Off,
            verbosity: 0,
        }
    }
}

/// Live progress, passed to the caller's callback after each verified piece.
#[derive(Debug, Clone, Copy)]
pub struct Progress {
    pub downloaded: u64,
    pub total: u64,
    pub pieces_complete: usize,
    pub num_pieces: usize,
    /// Bytes uploaded so far (non-zero only while seeding).
    pub uploaded: u64,
}

/// Final transfer statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct Stats {
    pub downloaded: u64,
    pub uploaded: u64,
}

/// Download `meta` into the files given by `layout` (resolved absolute, final
/// paths), pulling from `peers` concurrently. Calls `progress` after each
/// verified piece. Resumes automatically from any prior partial state and
/// finalises the output on completion. Returns an error if the swarm can't
/// complete the download (the partial is left in place to resume later).
pub fn download(
    meta: &Metainfo,
    layout: Vec<(PathBuf, u64)>,
    peers: &[SocketAddr],
    opts: &TorrentOptions,
    progress: &mut dyn FnMut(&Progress),
) -> Result<Stats> {
    let peer_id = if opts.peer_id == [0u8; 20] {
        super::generate_peer_id()?
    } else {
        opts.peer_id
    };
    let num_pieces = meta.num_pieces();
    let single = layout.len() == 1;

    // Where the data is written, where resume state lives, and (single-file)
    // the final name to rename to on completion.
    //  - single-file: data + in-file trailer in `<final>.rsurlpart`.
    //  - multi-file:  data at the final paths; state in `<topdir>/.rsurlpart`.
    let (final_single, storage_layout, state_path) = if single {
        let (final_path, len) = layout[0].clone();
        let part = resume::part_path(&final_path);
        (Some(final_path), vec![(part.clone(), len)], part)
    } else {
        let sidecar = topdir(&layout, &meta.name).join(".rsurlpart");
        (None, layout.clone(), sidecar)
    };
    let real_size = if single { meta.total_length } else { 0 };

    let mut storage = Storage::create(storage_layout, meta.piece_length, meta.pieces.clone())?;

    // Resume: restore the verified-piece bitfield if a matching partial exists.
    if let Ok(Some(st)) = resume::read_state(&state_path) {
        if st.kind == resume::Kind::Torrent {
            if let Some(bits) = parse_meta(&st.meta, meta.info_hash, num_pieces) {
                storage.restore_have(&bits);
            }
        }
    }

    // Periodic state persistence (engine calls this on its ~2 s tick).
    let info_hash = meta.info_hash;
    let save_path = state_path.clone();
    let mut save = |bf: &Bitfield| {
        let _ = resume::write_state(
            &save_path,
            real_size,
            resume::Kind::Torrent,
            &encode_meta(info_hash, bf),
        );
    };

    let stats = match engine::run(
        meta,
        &mut storage,
        peers,
        peer_id,
        opts,
        progress,
        &mut save,
    ) {
        Ok(s) => s,
        Err(e) => {
            // Persist the latest partial state so a re-run resumes from here.
            save(storage.bitfield());
            return Err(e);
        }
    };

    // Complete: finalise the output.
    if let Some(final_path) = final_single {
        drop(storage); // close the .rsurlpart handle before renaming (Windows)
        resume::finalize(&state_path, &final_path, meta.total_length)?;
        if opts.seed == SeedMode::Off {
            return Ok(stats);
        }
        // Seed from the finalised file.
        let mut ss = Storage::create(
            vec![(final_path, meta.total_length)],
            meta.piece_length,
            meta.pieces.clone(),
        )?;
        ss.restore_have(&full_bitfield(num_pieces));
        seed::run(meta, ss, peer_id, opts, stats, progress)
    } else {
        let _ = std::fs::remove_file(&state_path); // drop the sidecar
        if opts.seed == SeedMode::Off {
            return Ok(stats);
        }
        seed::run(meta, storage, peer_id, opts, stats, progress)
    }
}

/// Serialise resume metadata for a torrent: infohash followed by the bitfield.
fn encode_meta(info_hash: [u8; 20], bf: &Bitfield) -> Vec<u8> {
    let mut v = Vec::with_capacity(20 + bf.as_bytes().len());
    v.extend_from_slice(&info_hash);
    v.extend_from_slice(bf.as_bytes());
    v
}

/// Parse resume metadata, returning the bitfield only if the infohash matches.
fn parse_meta(meta: &[u8], expect: [u8; 20], num_pieces: usize) -> Option<Bitfield> {
    if meta.len() < 20 || meta[..20] != expect {
        return None;
    }
    Some(Bitfield::from_bytes(&meta[20..], num_pieces))
}

fn full_bitfield(num_pieces: usize) -> Bitfield {
    let mut bf = Bitfield::new(num_pieces);
    for i in 0..num_pieces {
        bf.set(i);
    }
    bf
}

/// The torrent's top-level directory: the ancestor of the layout paths whose
/// final component is the torrent name (where the sidecar belongs).
fn topdir(layout: &[(PathBuf, u64)], name: &str) -> PathBuf {
    let want: &std::ffi::OsStr = name.as_ref();
    let first = layout[0].0.as_path();
    let mut cur = first;
    while let Some(parent) = cur.parent() {
        if parent.file_name() == Some(want) {
            return parent.to_path_buf();
        }
        cur = parent;
    }
    first.parent().unwrap_or(Path::new(".")).to_path_buf()
}

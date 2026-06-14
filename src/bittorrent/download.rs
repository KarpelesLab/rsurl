//! Download entry point and shared transfer types.
//!
//! [`download`] builds the [`Storage`] and hands the
//! swarm to [`engine::run`], which fetches and verifies
//! pieces from many peers concurrently.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::error::Result;

use super::engine;
use super::metainfo::Metainfo;
use super::storage::Storage;

/// Knobs for a torrent transfer.
#[derive(Debug, Clone)]
pub struct TorrentOptions {
    /// 20-byte peer id; if all-zero, [`download`] generates a random one.
    pub peer_id: [u8; 20],
    /// Port we advertise to peers/trackers (the listen port when seeding).
    pub listen_port: u16,
    pub connect_timeout: Duration,
    /// Per-read/write socket timeout for a peer connection.
    pub peer_timeout: Duration,
}

impl Default for TorrentOptions {
    fn default() -> Self {
        TorrentOptions {
            peer_id: [0u8; 20],
            listen_port: 6881,
            connect_timeout: Duration::from_secs(10),
            peer_timeout: Duration::from_secs(30),
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
}

/// Final transfer statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct Stats {
    pub downloaded: u64,
    pub uploaded: u64,
}

/// Download `meta` into the files given by `layout` (resolved absolute paths),
/// pulling from `peers` concurrently. Calls `progress` after each verified
/// piece. Returns an error if the swarm can't complete the download.
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
    let mut storage = Storage::create(layout, meta.piece_length, meta.pieces.clone())?;
    engine::run(meta, &mut storage, peers, peer_id, opts, progress)
}

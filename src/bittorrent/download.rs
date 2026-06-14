//! Download driver.
//!
//! Phase 3: connect to peers one at a time and fetch the pieces each one has,
//! verifying every piece against its SHA-1 before it is written. Phase 4
//! replaces the sequential peer loop with a concurrent swarm engine behind the
//! same [`download`] entry point.

use std::collections::HashSet;
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

use crate::error::{Error, Result};

use super::metainfo::Metainfo;
use super::peer::{self, Handshake, Message, BLOCK_SIZE};
use super::picker::Bitfield;
use super::storage::Storage;

fn derr(msg: impl Into<String>) -> Error {
    Error::BadResponse(format!("bittorrent: {}", msg.into()))
}

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
/// pulling from `peers`. Calls `progress` after each verified piece.
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

    // Empty torrent (0 bytes) is trivially complete.
    if storage.is_complete() {
        return Ok(Stats::default());
    }

    let mut last_err: Option<Error> = None;
    for &addr in peers {
        if storage.is_complete() {
            break;
        }
        if let Err(e) = leech_from_peer(meta, addr, peer_id, &mut storage, opts, progress) {
            last_err = Some(e);
        }
    }

    if storage.is_complete() {
        Ok(Stats {
            downloaded: storage.total_length(),
            uploaded: 0,
        })
    } else {
        Err(last_err.unwrap_or_else(|| derr("no peer provided all pieces")))
    }
}

/// Fetch from a single peer every piece it has that we still need.
fn leech_from_peer(
    meta: &Metainfo,
    addr: SocketAddr,
    peer_id: [u8; 20],
    storage: &mut Storage,
    opts: &TorrentOptions,
    progress: &mut dyn FnMut(&Progress),
) -> Result<()> {
    let mut sock = TcpStream::connect_timeout(&addr, opts.connect_timeout).map_err(Error::Io)?;
    sock.set_read_timeout(Some(opts.peer_timeout))
        .map_err(Error::Io)?;
    sock.set_write_timeout(Some(opts.peer_timeout))
        .map_err(Error::Io)?;

    peer::write_handshake(&mut sock, &Handshake::new(meta.info_hash, peer_id))?;
    let hs = peer::read_handshake(&mut sock)?;
    if hs.info_hash != meta.info_hash {
        return Err(derr("peer infohash mismatch"));
    }

    peer::write_message(&mut sock, &Message::Interested)?;

    let n = meta.num_pieces();
    let mut peer_bf = Bitfield::new(n);
    let mut unchoked = false;

    loop {
        if storage.is_complete() {
            return Ok(());
        }
        if unchoked {
            if let Some(idx) = next_missing(storage, &peer_bf) {
                let size = storage.piece_size(idx);
                let data = download_piece(&mut sock, idx as u32, size)?;
                if !storage.write_piece(idx, &data)? {
                    return Err(derr("piece failed hash check"));
                }
                report(storage, meta, progress);
                continue;
            } else {
                // Peer has nothing more we need.
                return Ok(());
            }
        }
        match peer::read_message(&mut sock)? {
            Message::Unchoke => unchoked = true,
            Message::Choke => unchoked = false,
            Message::Bitfield(b) => peer_bf = Bitfield::from_bytes(&b, n),
            Message::Have(i) => peer_bf.set(i as usize),
            _ => {}
        }
    }
}

/// Download one whole piece by pipelining its block requests, then reading the
/// `piece` replies (tolerating interleaved control messages).
fn download_piece<S: std::io::Read + std::io::Write>(
    sock: &mut S,
    index: u32,
    size: u64,
) -> Result<Vec<u8>> {
    if size > u32::MAX as u64 {
        return Err(derr("piece larger than 4 GiB is unsupported"));
    }
    let size = size as u32;
    let mut buf = vec![0u8; size as usize];

    // Request every block of the piece up front (the engine in phase 4 caps the
    // in-flight window per peer; a single cooperative peer can take them all).
    let mut begin = 0u32;
    let mut outstanding: HashSet<u32> = HashSet::new();
    while begin < size {
        let length = BLOCK_SIZE.min(size - begin);
        peer::write_message(
            sock,
            &Message::Request {
                index,
                begin,
                length,
            },
        )?;
        outstanding.insert(begin);
        begin += length;
    }

    while !outstanding.is_empty() {
        match peer::read_message(sock)? {
            Message::Piece {
                index: pi,
                begin: pb,
                block,
            } if pi == index => {
                let off = pb as usize;
                if off + block.len() <= buf.len() && outstanding.remove(&pb) {
                    buf[off..off + block.len()].copy_from_slice(&block);
                }
            }
            // Ignore keep-alives, haves, (un)chokes, other-piece blocks, etc.;
            // a stalled peer is bounded by the socket read timeout.
            _ => {}
        }
    }
    Ok(buf)
}

fn next_missing(storage: &Storage, peer_bf: &Bitfield) -> Option<usize> {
    (0..storage.num_pieces()).find(|&i| !storage.has(i) && peer_bf.has(i))
}

fn report(storage: &Storage, meta: &Metainfo, progress: &mut dyn FnMut(&Progress)) {
    progress(&Progress {
        downloaded: storage.bytes_complete(),
        total: meta.total_length,
        pieces_complete: storage.bitfield().count(),
        num_pieces: meta.num_pieces(),
    });
}

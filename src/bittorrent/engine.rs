//! Concurrent swarm engine.
//!
//! One thread per peer connection. A single engine thread (the caller's) owns
//! the [`Storage`] and [`Picker`] — there is no shared piece-state lock. Peers
//! talk to the engine over an mpsc channel (`ToEngine`); the engine assigns
//! whole pieces to idle peers (rarest-first) over each peer's command channel
//! (`ToPeer`). A peer downloads its assigned piece (pipelining the block
//! requests), returns it, and the engine verifies + writes it.

use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, TcpStream};
use std::sync::mpsc::{self, Sender};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::error::{Error, Result};

use super::download::{Progress, Stats, TorrentOptions};
use super::metainfo::Metainfo;
use super::peer::{self, Handshake, Message, BLOCK_SIZE};
use super::picker::{Bitfield, Picker};
use super::storage::Storage;

fn eerr(msg: impl Into<String>) -> Error {
    Error::BadResponse(format!("bittorrent: {}", msg.into()))
}

/// Peer → engine events.
enum ToEngine {
    Joined {
        peer: usize,
        bitfield: Bitfield,
        cmd: Sender<ToPeer>,
    },
    PieceDone {
        peer: usize,
        index: usize,
        data: Vec<u8>,
    },
    Failed {
        peer: usize,
        index: usize,
    },
    Gone {
        peer: usize,
    },
}

/// Engine → peer commands.
enum ToPeer {
    Assign { index: usize, size: u64 },
    Stop,
}

/// Run the swarm until the torrent completes or peers are exhausted.
pub fn run(
    meta: &Metainfo,
    storage: &mut Storage,
    peers: &[SocketAddr],
    peer_id: [u8; 20],
    opts: &TorrentOptions,
    progress: &mut dyn FnMut(&Progress),
) -> Result<Stats> {
    if storage.is_complete() {
        return Ok(Stats {
            downloaded: storage.total_length(),
            uploaded: 0,
        });
    }
    if peers.is_empty() {
        return Err(eerr("no peers to download from"));
    }

    let (tx, rx) = mpsc::channel::<ToEngine>();
    let num_pieces = meta.num_pieces();

    // Spawn one worker per peer.
    let mut handles: Vec<JoinHandle<()>> = Vec::with_capacity(peers.len());
    for (i, &addr) in peers.iter().enumerate() {
        let tx = tx.clone();
        let info_hash = meta.info_hash;
        let ct = opts.connect_timeout;
        let pt = opts.peer_timeout;
        handles.push(std::thread::spawn(move || {
            peer_worker(i, addr, info_hash, peer_id, num_pieces, ct, pt, tx);
        }));
    }
    drop(tx); // engine holds no sender; rx ends once every peer thread exits.

    let mut picker = Picker::new(num_pieces);
    let mut peer_bf: HashMap<usize, Bitfield> = HashMap::new();
    let mut peer_cmd: HashMap<usize, Sender<ToPeer>> = HashMap::new();
    let mut assigned: HashSet<usize> = HashSet::new();
    let mut peer_piece: HashMap<usize, usize> = HashMap::new();

    while !storage.is_complete() {
        let ev = match rx.recv() {
            Ok(e) => e,
            Err(_) => break, // all peers gone
        };
        match ev {
            ToEngine::Joined {
                peer,
                bitfield,
                cmd,
            } => {
                picker.add_bitfield(&bitfield);
                peer_bf.insert(peer, bitfield);
                peer_cmd.insert(peer, cmd);
                try_assign(
                    peer,
                    storage,
                    &picker,
                    &peer_bf,
                    &mut assigned,
                    &mut peer_piece,
                    &peer_cmd,
                );
            }
            ToEngine::PieceDone { peer, index, data } => {
                assigned.remove(&index);
                peer_piece.remove(&peer);
                match storage.write_piece(index, &data) {
                    Ok(true) => progress(&snapshot(storage, meta)),
                    Ok(false) => { /* hash mismatch: leave unassigned to retry elsewhere */ }
                    Err(e) => {
                        stop_all(&peer_cmd, handles);
                        return Err(e); // disk error is fatal
                    }
                }
                try_assign(
                    peer,
                    storage,
                    &picker,
                    &peer_bf,
                    &mut assigned,
                    &mut peer_piece,
                    &peer_cmd,
                );
            }
            ToEngine::Failed { peer, index } => {
                assigned.remove(&index);
                peer_piece.remove(&peer);
                // The peer also sends Gone; the freed piece is picked up by the
                // next peer that finishes a piece.
            }
            ToEngine::Gone { peer } => {
                if let Some(bf) = peer_bf.remove(&peer) {
                    picker.remove_bitfield(&bf);
                }
                peer_cmd.remove(&peer);
                if let Some(p) = peer_piece.remove(&peer) {
                    assigned.remove(&p);
                }
            }
        }
    }

    stop_all(&peer_cmd, handles);

    if storage.is_complete() {
        Ok(Stats {
            downloaded: storage.total_length(),
            uploaded: 0,
        })
    } else {
        Err(eerr("download did not complete (peers exhausted)"))
    }
}

#[allow(clippy::too_many_arguments)]
fn try_assign(
    peer: usize,
    storage: &Storage,
    picker: &Picker,
    peer_bf: &HashMap<usize, Bitfield>,
    assigned: &mut HashSet<usize>,
    peer_piece: &mut HashMap<usize, usize>,
    peer_cmd: &HashMap<usize, Sender<ToPeer>>,
) {
    let (Some(bf), Some(cmd)) = (peer_bf.get(&peer), peer_cmd.get(&peer)) else {
        return;
    };
    if storage.is_complete() {
        let _ = cmd.send(ToPeer::Stop);
        return;
    }
    match picker.pick(storage.bitfield(), bf, assigned) {
        Some(idx) => {
            assigned.insert(idx);
            peer_piece.insert(peer, idx);
            let size = storage.piece_size(idx);
            if cmd.send(ToPeer::Assign { index: idx, size }).is_err() {
                assigned.remove(&idx);
                peer_piece.remove(&peer);
            }
        }
        // This peer has no piece we still need that isn't already in flight.
        None => {
            let _ = cmd.send(ToPeer::Stop);
        }
    }
}

fn snapshot(storage: &Storage, meta: &Metainfo) -> Progress {
    Progress {
        downloaded: storage.bytes_complete(),
        total: meta.total_length,
        pieces_complete: storage.bitfield().count(),
        num_pieces: meta.num_pieces(),
    }
}

fn stop_all(peer_cmd: &HashMap<usize, Sender<ToPeer>>, handles: Vec<JoinHandle<()>>) {
    for cmd in peer_cmd.values() {
        let _ = cmd.send(ToPeer::Stop);
    }
    for h in handles {
        let _ = h.join();
    }
}

/// A single peer connection: handshake, learn its pieces, then loop fetching
/// whole pieces the engine assigns.
#[allow(clippy::too_many_arguments)]
fn peer_worker(
    peer: usize,
    addr: SocketAddr,
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    num_pieces: usize,
    connect_timeout: Duration,
    peer_timeout: Duration,
    tx: Sender<ToEngine>,
) {
    let _ = run_peer(
        peer,
        addr,
        info_hash,
        peer_id,
        num_pieces,
        connect_timeout,
        peer_timeout,
        &tx,
    );
    let _ = tx.send(ToEngine::Gone { peer });
}

#[allow(clippy::too_many_arguments)]
fn run_peer(
    peer: usize,
    addr: SocketAddr,
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    num_pieces: usize,
    connect_timeout: Duration,
    peer_timeout: Duration,
    tx: &Sender<ToEngine>,
) -> Result<()> {
    let mut sock = TcpStream::connect_timeout(&addr, connect_timeout).map_err(Error::Io)?;
    sock.set_read_timeout(Some(peer_timeout))
        .map_err(Error::Io)?;
    sock.set_write_timeout(Some(peer_timeout))
        .map_err(Error::Io)?;

    peer::write_handshake(&mut sock, &Handshake::new(info_hash, peer_id))?;
    let hs = peer::read_handshake(&mut sock)?;
    if hs.info_hash != info_hash {
        return Err(eerr("peer infohash mismatch"));
    }
    peer::write_message(&mut sock, &Message::Interested)?;

    // Read until unchoked, accumulating the peer's advertised pieces.
    let mut bf = Bitfield::new(num_pieces);
    let mut unchoked = false;
    while !unchoked {
        match peer::read_message(&mut sock)? {
            Message::Unchoke => unchoked = true,
            Message::Choke => {}
            Message::Bitfield(b) => bf = Bitfield::from_bytes(&b, num_pieces),
            Message::Have(i) => bf.set(i as usize),
            _ => {}
        }
    }

    let (cmd_tx, cmd_rx) = mpsc::channel::<ToPeer>();
    if tx
        .send(ToEngine::Joined {
            peer,
            bitfield: bf,
            cmd: cmd_tx,
        })
        .is_err()
    {
        return Ok(()); // engine gone
    }

    loop {
        match cmd_rx.recv() {
            Ok(ToPeer::Assign { index, size }) => {
                match download_piece(&mut sock, index as u32, size) {
                    Ok(data) => {
                        if tx.send(ToEngine::PieceDone { peer, index, data }).is_err() {
                            return Ok(());
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(ToEngine::Failed { peer, index });
                        return Err(e);
                    }
                }
            }
            Ok(ToPeer::Stop) | Err(_) => return Ok(()),
        }
    }
}

/// Download one whole piece, pipelining its block requests.
fn download_piece<S: std::io::Read + std::io::Write>(
    sock: &mut S,
    index: u32,
    size: u64,
) -> Result<Vec<u8>> {
    if size > u32::MAX as u64 {
        return Err(eerr("piece larger than 4 GiB is unsupported"));
    }
    let size = size as u32;
    let mut buf = vec![0u8; size as usize];

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
            // Keep-alives, haves, (un)chokes, other-piece blocks: ignored; a
            // stalled peer is bounded by the socket read timeout.
            _ => {}
        }
    }
    Ok(buf)
}

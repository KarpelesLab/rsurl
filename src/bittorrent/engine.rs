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
use std::time::Duration;

use crate::error::{Error, Result};

use super::download::{Progress, Stats, TorrentOptions};
use super::metainfo::Metainfo;
use super::peer::{self, Handshake, Message, BLOCK_SIZE};
use super::picker::{Bitfield, Picker};
use super::storage::Storage;

/// Number of block requests kept in flight per piece (sliding window).
const PIPELINE_DEPTH: usize = 16;

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

    // Spawn one worker per peer. Workers are detached (not joined): a peer
    // blocked mid-piece on a slow/stalled socket must not hold up a completed
    // transfer — it exits on Stop when idle, or when its socket times out.
    let verbosity = opts.verbosity;
    let peer_verbose = verbosity >= 2; // per-peer lifecycle only at -vv
    for (i, &addr) in peers.iter().enumerate() {
        let tx = tx.clone();
        let info_hash = meta.info_hash;
        let ct = opts.connect_timeout;
        let pt = opts.peer_timeout;
        std::thread::spawn(move || {
            peer_worker(
                i,
                addr,
                info_hash,
                peer_id,
                num_pieces,
                ct,
                pt,
                peer_verbose,
                tx,
            );
        });
    }
    drop(tx); // engine holds no sender; rx ends once every peer thread exits.

    let mut picker = Picker::new(num_pieces);
    let mut peer_bf: HashMap<usize, Bitfield> = HashMap::new();
    let mut peer_cmd: HashMap<usize, Sender<ToPeer>> = HashMap::new();
    let mut assigned: HashSet<usize> = HashSet::new();
    let mut peer_piece: HashMap<usize, usize> = HashMap::new();
    let mut endgame_announced = false;

    while !storage.is_complete() {
        let ev = match rx.recv_timeout(Duration::from_secs(2)) {
            Ok(e) => e,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // -v: a periodic swarm summary instead of per-peer spam.
                if verbosity >= 1 {
                    eprintln!(
                        "* swarm: {} peers, {} pieces in flight, {}/{} complete",
                        peer_cmd.len(),
                        assigned.len(),
                        storage.bitfield().count(),
                        num_pieces,
                    );
                }
                continue;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break, // all peers gone
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
                    verbosity,
                    &mut endgame_announced,
                );
            }
            ToEngine::PieceDone { peer, index, data } => {
                peer_piece.remove(&peer);
                if storage.has(index) {
                    // A duplicate copy (endgame) of a piece we already have.
                } else {
                    match storage.write_piece(index, &data) {
                        Ok(true) => {
                            assigned.remove(&index);
                            progress(&snapshot(storage, meta));
                        }
                        // Bad data: free it for re-pick unless another peer is
                        // still downloading the same piece (endgame).
                        Ok(false) => {
                            if !peer_piece.values().any(|&p| p == index) {
                                assigned.remove(&index);
                            }
                        }
                        Err(e) => {
                            stop_all(&peer_cmd);
                            return Err(e); // disk error is fatal
                        }
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
                    verbosity,
                    &mut endgame_announced,
                );
            }
            ToEngine::Failed { peer, index } => {
                peer_piece.remove(&peer);
                // Free the piece only if no other peer is still on it (endgame).
                if !peer_piece.values().any(|&p| p == index) {
                    assigned.remove(&index);
                }
            }
            ToEngine::Gone { peer } => {
                if let Some(bf) = peer_bf.remove(&peer) {
                    picker.remove_bitfield(&bf);
                }
                peer_cmd.remove(&peer);
                if let Some(p) = peer_piece.remove(&peer) {
                    if !peer_piece.values().any(|&x| x == p) {
                        assigned.remove(&p);
                    }
                }
            }
        }
    }

    stop_all(&peer_cmd);

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
    verbosity: u8,
    endgame_announced: &mut bool,
) {
    let (Some(bf), Some(cmd)) = (peer_bf.get(&peer), peer_cmd.get(&peer)) else {
        return;
    };
    if storage.is_complete() {
        let _ = cmd.send(ToPeer::Stop);
        return;
    }

    // `fresh` means a not-yet-in-flight piece (added to `assigned` here); an
    // endgame duplicate is already in `assigned` and owned by another peer too.
    let (idx, fresh) = match picker.pick(storage.bitfield(), bf, assigned) {
        Some(idx) => {
            assigned.insert(idx);
            (Some(idx), true)
        }
        None => {
            // Endgame: once every still-missing piece is already in flight, an
            // idle peer re-requests one it has so the tail isn't stuck behind a
            // single slow peer. First valid copy wins; late copies are dropped.
            let complete = storage.bitfield().count();
            let unassigned = storage
                .num_pieces()
                .saturating_sub(complete + assigned.len());
            if unassigned == 0 {
                let dup = endgame_pick(storage, bf, peer_piece, assigned);
                if dup.is_some() && verbosity >= 1 && !*endgame_announced {
                    *endgame_announced = true;
                    eprintln!("* endgame: re-requesting in-flight pieces from idle peers");
                }
                (dup, false)
            } else {
                (None, false)
            }
        }
    };

    match idx {
        Some(idx) => {
            peer_piece.insert(peer, idx);
            let size = storage.piece_size(idx);
            if cmd.send(ToPeer::Assign { index: idx, size }).is_err() {
                if fresh {
                    assigned.remove(&idx);
                }
                peer_piece.remove(&peer);
            }
        }
        // Nothing this peer can usefully fetch.
        None => {
            let _ = cmd.send(ToPeer::Stop);
        }
    }
}

/// Pick an in-flight piece this peer has (and we still lack) to duplicate in
/// endgame, preferring the one with the fewest peers currently on it so idle
/// peers spread across the remaining pieces rather than piling on one.
fn endgame_pick(
    storage: &Storage,
    bf: &Bitfield,
    peer_piece: &HashMap<usize, usize>,
    assigned: &HashSet<usize>,
) -> Option<usize> {
    let mut assignees: HashMap<usize, usize> = HashMap::new();
    for &p in peer_piece.values() {
        *assignees.entry(p).or_insert(0) += 1;
    }
    assigned
        .iter()
        .copied()
        .filter(|&idx| bf.has(idx) && !storage.has(idx))
        .min_by_key(|idx| assignees.get(idx).copied().unwrap_or(0))
}

fn snapshot(storage: &Storage, meta: &Metainfo) -> Progress {
    Progress {
        downloaded: storage.bytes_complete(),
        total: meta.total_length,
        pieces_complete: storage.bitfield().count(),
        num_pieces: meta.num_pieces(),
        uploaded: 0,
    }
}

/// Ask every worker to stop. Workers are detached, so we do not join them —
/// a peer blocked mid-piece would otherwise pin us for its full read timeout;
/// it terminates on its own once the socket times out.
fn stop_all(peer_cmd: &HashMap<usize, Sender<ToPeer>>) {
    for cmd in peer_cmd.values() {
        let _ = cmd.send(ToPeer::Stop);
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
    verbose: bool,
    tx: Sender<ToEngine>,
) {
    let r = run_peer(
        peer,
        addr,
        info_hash,
        peer_id,
        num_pieces,
        connect_timeout,
        peer_timeout,
        verbose,
        &tx,
    );
    if verbose {
        match &r {
            Ok(()) => eprintln!("* peer {addr}: disconnected"),
            Err(e) => eprintln!("* peer {addr}: {e}"),
        }
    }
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
    verbose: bool,
    tx: &Sender<ToEngine>,
) -> Result<()> {
    let mut sock = TcpStream::connect_timeout(&addr, connect_timeout).map_err(Error::Io)?;
    sock.set_read_timeout(Some(peer_timeout))
        .map_err(Error::Io)?;
    sock.set_write_timeout(Some(peer_timeout))
        .map_err(Error::Io)?;
    if verbose {
        eprintln!("* peer {addr}: connected");
    }

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
    if verbose {
        eprintln!("* peer {addr}: unchoked ({} pieces available)", bf.count());
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

    let num_blocks = (size as usize).div_ceil(BLOCK_SIZE as usize);
    let mut filled = vec![false; num_blocks];
    let mut next_block = 0usize; // next block index to request
    let mut received = 0usize; // distinct blocks stored
    let mut outstanding = 0usize;

    // Pipeline a bounded window of block requests rather than flooding the
    // whole piece at once: a 4 MiB piece is 256 blocks, and many peers cap
    // their incoming request queue and silently drop the overflow, which would
    // otherwise stall the piece forever.
    while received < num_blocks {
        while outstanding < PIPELINE_DEPTH && next_block < num_blocks {
            let begin = next_block as u32 * BLOCK_SIZE;
            let length = BLOCK_SIZE.min(size - begin);
            peer::write_message(
                sock,
                &Message::Request {
                    index,
                    begin,
                    length,
                },
            )?;
            next_block += 1;
            outstanding += 1;
        }
        match peer::read_message(sock)? {
            Message::Piece {
                index: pi,
                begin: pb,
                block,
            } if pi == index => {
                outstanding = outstanding.saturating_sub(1);
                let off = pb as usize;
                if pb % BLOCK_SIZE == 0 {
                    let bi = (pb / BLOCK_SIZE) as usize;
                    if bi < num_blocks && !filled[bi] && off + block.len() <= buf.len() {
                        buf[off..off + block.len()].copy_from_slice(&block);
                        filled[bi] = true;
                        received += 1;
                    }
                }
            }
            // Keep-alives, haves, (un)chokes, other-piece blocks: ignored; a
            // stalled peer is bounded by the socket read timeout.
            _ => {}
        }
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A storage of `num` pieces (piece length 4), none complete.
    fn empty_storage(num: usize) -> Storage {
        let hashes = vec![[0u8; 20]; num];
        let path = std::env::temp_dir().join("rsurl_engine_test_unused");
        Storage::create(vec![(path, (num * 4) as u64)], 4, hashes).unwrap()
    }

    #[test]
    fn endgame_pick_prefers_fewest_assignees() {
        let st = empty_storage(5);
        let mut bf = Bitfield::new(5);
        for i in 0..5 {
            bf.set(i); // peer has every piece
        }
        let assigned: HashSet<usize> = [1, 2, 3].into_iter().collect();
        // piece 1 has two assignees, pieces 2 and 3 one each.
        let mut pp: HashMap<usize, usize> = HashMap::new();
        pp.insert(10, 1);
        pp.insert(11, 1);
        pp.insert(12, 2);
        pp.insert(13, 3);
        // Should avoid the doubly-assigned piece 1.
        assert!(matches!(
            endgame_pick(&st, &bf, &pp, &assigned),
            Some(2) | Some(3)
        ));
    }

    #[test]
    fn endgame_pick_skips_pieces_peer_lacks() {
        let st = empty_storage(5);
        let mut bf = Bitfield::new(5);
        bf.set(2); // peer only has piece 2
        let assigned: HashSet<usize> = [1, 2].into_iter().collect();
        let pp: HashMap<usize, usize> = HashMap::new();
        // Piece 1 is in flight but the peer lacks it; only 2 is eligible.
        assert_eq!(endgame_pick(&st, &bf, &pp, &assigned), Some(2));
    }

    #[test]
    fn endgame_pick_none_when_nothing_eligible() {
        let st = empty_storage(3);
        let bf = Bitfield::new(3); // peer has nothing
        let assigned: HashSet<usize> = [0, 1, 2].into_iter().collect();
        let pp: HashMap<usize, usize> = HashMap::new();
        assert_eq!(endgame_pick(&st, &bf, &pp, &assigned), None);
    }
}

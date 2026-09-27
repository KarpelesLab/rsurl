//! Concurrent swarm engine.
//!
//! One worker thread per peer connection (plus a reader thread that turns the
//! peer's wire messages into events). A single engine thread (the caller's)
//! owns the [`Storage`] and [`Picker`] — there is no shared piece-state lock.
//! Peers talk to the engine over an mpsc channel (`ToEngine`); the engine
//! assigns whole pieces to idle, unchoked peers (rarest-first) over each
//! peer's inbox (`Inbox`). A peer downloads its assigned piece (pipelining the
//! block requests), returns it, and the engine verifies + writes it.
//!
//! Liveness rules (BEP 3 semantics a real swarm exercises):
//!
//! * A peer that chokes us discards our pending requests; the worker forgets
//!   them and re-requests the missing blocks once unchoked. A piece held by a
//!   peer that stays choked past `peer_timeout` is handed back to the engine.
//! * An unchoked peer that delivers no block for `peer_timeout` is dropped,
//!   however much other traffic (keep-alives, haves) it sends meanwhile.
//! * `have` messages keep the picker current, and a peer with nothing useful
//!   *yet* stays connected (idle) until it announces something we need —
//!   unless untried peers are queued, in which case it yields its slot.
//! * A peer whose data repeatedly fails the hash check is banned, and never
//!   re-assigned a piece it already corrupted.
//! * If no peer is working on anything and nothing useful has happened for a
//!   while, the download fails instead of waiting forever.

use std::collections::{HashMap, HashSet};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

use super::download::{Progress, Stats, TorrentOptions};
use super::metainfo::Metainfo;
use super::peer::{self, Handshake, Message, BLOCK_SIZE};
use super::picker::{Bitfield, Picker};
use super::storage::Storage;

/// Number of block requests kept in flight per piece (sliding window).
const PIPELINE_DEPTH: usize = 16;
/// Most peer connections open at once (one worker + reader thread each);
/// further peers are queued and dialled as slots free up.
const MAX_PEERS: usize = 50;
/// Hash failures after which a peer is banned.
const MAX_STRIKES: u32 = 3;
/// Budget for piece buffers held in memory at once: each busy peer holds a
/// whole piece (up to 128 MiB), so fewer pieces run concurrently when pieces
/// are large.
const MAX_BUFFERED: u64 = 512 * 1024 * 1024;
/// Wire messages a reader thread may queue ahead of its worker.
const MAX_QUEUED: usize = 64;
/// Engine housekeeping cadence (summary, resume-state save).
const REPORT_EVERY: Duration = Duration::from_secs(2);

fn eerr(msg: impl Into<String>) -> Error {
    Error::BadResponse(format!("bittorrent: {}", msg.into()))
}

/// Peer → engine events.
enum ToEngine {
    /// First unchoke: the peer's pieces so far, and its inbox.
    Joined {
        peer: usize,
        bitfield: Bitfield,
        cmd: Sender<Inbox>,
    },
    /// The peer announced a piece it did not have before.
    Have {
        peer: usize,
        index: usize,
    },
    Choked {
        peer: usize,
    },
    Unchoked {
        peer: usize,
    },
    PieceDone {
        peer: usize,
        index: usize,
        data: Vec<u8>,
    },
    /// Choked too long mid-piece: the piece is handed back, the peer stays.
    Released {
        peer: usize,
        index: usize,
    },
    /// The worker exited (its piece, if any, is free again).
    Gone {
        peer: usize,
    },
}

/// A worker's inbox: engine commands and (from its reader thread) wire input.
enum Inbox {
    Assign { index: usize, size: u64 },
    Stop,
    Wire(Message),
    WireErr(Error),
}

/// Run the swarm until the torrent completes, stalls, or peers are exhausted.
pub fn run(
    meta: &Metainfo,
    storage: &mut Storage,
    peers: &[SocketAddr],
    peer_id: [u8; 20],
    opts: &TorrentOptions,
    progress: &mut dyn FnMut(&Progress),
    save: &mut dyn FnMut(&Bitfield),
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
    let verbosity = opts.verbosity;
    let cfg = WorkerCfg {
        info_hash: meta.info_hash,
        peer_id,
        num_pieces,
        connect_timeout: opts.connect_timeout,
        peer_timeout: opts.peer_timeout,
        verbose: verbosity >= 2, // per-peer lifecycle only at -vv
    };

    // Workers are detached (not joined): the engine stops them by message and
    // each closes its socket on exit, which also ends its reader thread.
    let mut next_peer = 0usize;
    let mut live = 0usize;
    let spawn_more = |next_peer: &mut usize, live: &mut usize| {
        while *live < MAX_PEERS && *next_peer < peers.len() {
            let (i, addr, tx) = (*next_peer, peers[*next_peer], tx.clone());
            std::thread::spawn(move || peer_worker(i, addr, cfg, tx));
            *next_peer += 1;
            *live += 1;
        }
    };
    spawn_more(&mut next_peer, &mut live);

    let max_busy = (MAX_BUFFERED / meta.piece_length.max(1)).clamp(1, MAX_PEERS as u64) as usize;
    let mut sw = Swarm {
        storage,
        picker: Picker::new(num_pieces),
        peers: HashMap::new(),
        assigned: HashSet::new(),
        max_busy,
        verbosity,
        endgame_announced: false,
        last_progress: Instant::now(),
    };
    // Nothing useful for this long, with no piece in flight, means the swarm
    // can't finish the download.
    let stall_limit = (opts.peer_timeout * 4).max(Duration::from_secs(5));
    let mut last_report = Instant::now();

    let result = loop {
        if sw.storage.is_complete() {
            break Ok(());
        }
        if live == 0 && next_peer >= peers.len() {
            break Err(eerr("download did not complete (peers exhausted)"));
        }
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(ToEngine::Gone { peer }) => {
                live -= 1;
                sw.gone(peer);
                spawn_more(&mut next_peer, &mut live);
            }
            Ok(ev) => {
                if let Err(e) = sw.handle(ev, meta, progress) {
                    break Err(e); // disk error is fatal
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => unreachable!("engine holds a sender"),
        }

        if last_report.elapsed() >= REPORT_EVERY {
            last_report = Instant::now();
            // -v: a periodic swarm summary instead of per-peer spam.
            if verbosity >= 1 {
                eprintln!(
                    "* swarm: {} peers, {} pieces in flight, {}/{} complete",
                    sw.peers.len(),
                    sw.assigned.len(),
                    sw.storage.bitfield().count(),
                    num_pieces,
                );
            }
            // Persist resume state periodically (bounded I/O).
            save(sw.storage.bitfield());
        }

        // Give the slot of a peer that has had nothing for us for a while to
        // an untried one.
        if next_peer < peers.len() {
            sw.evict_idle(opts.peer_timeout);
        }

        if sw.busy() == 0 && sw.last_progress.elapsed() >= stall_limit {
            break Err(eerr(
                "download stalled (no peer can supply the missing pieces)",
            ));
        }
    };

    sw.stop_all();
    result?;
    Ok(Stats {
        downloaded: sw.storage.total_length(),
        uploaded: 0,
    })
}

/// Engine-side view of one joined peer.
struct PeerState {
    bf: Bitfield,
    cmd: Sender<Inbox>,
    piece: Option<usize>,
    unchoked: bool,
    strikes: u32,
    /// Pieces this peer sent corrupt data for; never assigned to it again.
    bad: HashSet<usize>,
    idle_since: Instant,
}

struct Swarm<'a> {
    storage: &'a mut Storage,
    picker: Picker,
    peers: HashMap<usize, PeerState>,
    /// Pieces currently being fetched (by one peer, or several in endgame).
    assigned: HashSet<usize>,
    max_busy: usize,
    verbosity: u8,
    endgame_announced: bool,
    /// Last time something happened that could move the download forward.
    last_progress: Instant,
}

impl Swarm<'_> {
    fn handle(
        &mut self,
        ev: ToEngine,
        meta: &Metainfo,
        progress: &mut dyn FnMut(&Progress),
    ) -> Result<()> {
        match ev {
            ToEngine::Joined {
                peer,
                bitfield,
                cmd,
            } => {
                self.picker.add_bitfield(&bitfield);
                self.peers.insert(
                    peer,
                    PeerState {
                        bf: bitfield,
                        cmd,
                        piece: None,
                        unchoked: true,
                        strikes: 0,
                        bad: HashSet::new(),
                        idle_since: Instant::now(),
                    },
                );
                self.last_progress = Instant::now();
                self.assign(peer);
            }
            ToEngine::Have { peer, index } => {
                let Some(ps) = self.peers.get_mut(&peer) else {
                    return Ok(());
                };
                if index < ps.bf.len() && !ps.bf.has(index) {
                    ps.bf.set(index);
                    self.picker.add_have(index);
                    if !self.storage.has(index) {
                        self.last_progress = Instant::now();
                        self.assign(peer);
                    }
                }
            }
            ToEngine::Choked { peer } => {
                if let Some(ps) = self.peers.get_mut(&peer) {
                    ps.unchoked = false;
                }
            }
            ToEngine::Unchoked { peer } => {
                if let Some(ps) = self.peers.get_mut(&peer) {
                    ps.unchoked = true;
                    self.last_progress = Instant::now();
                    self.assign(peer);
                }
            }
            ToEngine::PieceDone { peer, index, data } => {
                self.clear_piece(peer, index);
                if !self.storage.has(index) {
                    match self.storage.write_piece(index, &data) {
                        Ok(true) => {
                            self.assigned.remove(&index);
                            self.last_progress = Instant::now();
                            progress(&snapshot(self.storage, meta));
                        }
                        Ok(false) => self.strike(peer, index),
                        Err(e) => return Err(e),
                    }
                }
                // (else: a duplicate copy (endgame) of a piece we have.)
                self.assign(peer);
                self.assign_idle();
            }
            ToEngine::Released { peer, index } => {
                self.clear_piece(peer, index);
                if let Some(ps) = self.peers.get_mut(&peer) {
                    ps.unchoked = false;
                }
                self.assign_idle();
            }
            ToEngine::Gone { peer } => self.gone(peer),
        }
        Ok(())
    }

    /// A worker exited: forget the peer and free its piece for others.
    fn gone(&mut self, peer: usize) {
        if let Some(ps) = self.peers.remove(&peer) {
            self.picker.remove_bitfield(&ps.bf);
            if let Some(p) = ps.piece {
                self.release(p);
            }
        }
        self.assign_idle();
    }

    /// `peer` is no longer working on `index` (it finished, or gave it back).
    fn clear_piece(&mut self, peer: usize, index: usize) {
        if let Some(ps) = self.peers.get_mut(&peer) {
            if ps.piece == Some(index) {
                ps.piece = None;
                ps.idle_since = Instant::now();
            }
        }
        self.release(index);
    }

    /// Free `index` for re-pick unless another peer is still on it (endgame).
    fn release(&mut self, index: usize) {
        if !self.peers.values().any(|ps| ps.piece == Some(index)) {
            self.assigned.remove(&index);
        }
    }

    /// Bad data from `peer` for `index`: never give it that piece again, and
    /// ban it once it has failed too often.
    fn strike(&mut self, peer: usize, index: usize) {
        let Some(ps) = self.peers.get_mut(&peer) else {
            return;
        };
        ps.strikes += 1;
        ps.bad.insert(index);
        if ps.strikes >= MAX_STRIKES {
            if self.verbosity >= 1 {
                eprintln!("* banning a peer after {} hash failures", ps.strikes);
            }
            let _ = ps.cmd.send(Inbox::Stop);
            // Its Gone event finds nothing left to clean up.
            self.gone(peer);
        }
    }

    fn busy(&self) -> usize {
        self.peers.values().filter(|ps| ps.piece.is_some()).count()
    }

    fn assign_idle(&mut self) {
        let mut idle: Vec<usize> = self
            .peers
            .iter()
            .filter(|(_, ps)| ps.piece.is_none() && ps.unchoked)
            .map(|(&id, _)| id)
            .collect();
        idle.sort_unstable();
        for id in idle {
            self.assign(id);
        }
    }

    /// Hand `peer` a piece if it is unchoked, idle, and has one we need. A
    /// peer with nothing to offer simply stays idle (a later `have` may change
    /// that).
    fn assign(&mut self, peer: usize) {
        if self.storage.is_complete() || self.busy() >= self.max_busy {
            return;
        }
        let Some(ps) = self.peers.get(&peer) else {
            return;
        };
        if !ps.unchoked || ps.piece.is_some() {
            return;
        }
        // The peer's pieces, minus any it already corrupted.
        let mut bf = ps.bf.clone();
        for &b in &ps.bad {
            bf.unset(b);
        }

        // `fresh` means a not-yet-in-flight piece; an endgame duplicate is
        // already in `assigned` and owned by another peer too.
        let (idx, fresh) = match self
            .picker
            .pick(self.storage.bitfield(), &bf, &self.assigned)
        {
            Some(idx) => (Some(idx), true),
            None => {
                // Endgame: once every still-missing piece is already in
                // flight, an idle peer re-requests one it has so the tail
                // isn't stuck behind a single slow peer. First valid copy
                // wins; late copies are dropped.
                let complete = self.storage.bitfield().count();
                let unassigned = self
                    .storage
                    .num_pieces()
                    .saturating_sub(complete + self.assigned.len());
                if unassigned == 0 {
                    let peer_piece: HashMap<usize, usize> = self
                        .peers
                        .iter()
                        .filter_map(|(&id, p)| p.piece.map(|i| (id, i)))
                        .collect();
                    let dup = endgame_pick(self.storage, &bf, &peer_piece, &self.assigned);
                    if dup.is_some() && self.verbosity >= 1 && !self.endgame_announced {
                        self.endgame_announced = true;
                        eprintln!("* endgame: re-requesting in-flight pieces from idle peers");
                    }
                    (dup, false)
                } else {
                    (None, false)
                }
            }
        };
        let Some(idx) = idx else {
            return;
        };
        let size = self.storage.piece_size(idx);
        let ps = self.peers.get_mut(&peer).expect("checked above");
        if ps.cmd.send(Inbox::Assign { index: idx, size }).is_ok() {
            ps.piece = Some(idx);
            if fresh {
                self.assigned.insert(idx);
            }
        }
    }

    /// Stop peers that have been idle longer than `after`, freeing their
    /// connection slots (only called while untried peers are queued).
    fn evict_idle(&mut self, after: Duration) {
        let stale: Vec<usize> = self
            .peers
            .iter()
            .filter(|(_, ps)| ps.piece.is_none() && ps.idle_since.elapsed() >= after)
            .map(|(&id, _)| id)
            .collect();
        for id in stale {
            if let Some(ps) = self.peers.get(&id) {
                let _ = ps.cmd.send(Inbox::Stop);
            }
            self.gone(id);
        }
    }

    /// Ask every worker to stop. Workers are detached, so we do not join them.
    fn stop_all(&self) {
        for ps in self.peers.values() {
            let _ = ps.cmd.send(Inbox::Stop);
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
        .min_by_key(|&idx| (assignees.get(&idx).copied().unwrap_or(0), idx))
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

/// Per-peer settings shared by every worker.
#[derive(Clone, Copy)]
struct WorkerCfg {
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    num_pieces: usize,
    connect_timeout: Duration,
    peer_timeout: Duration,
    verbose: bool,
}

/// A single peer connection: handshake, learn its pieces, then fetch whole
/// pieces the engine assigns. Always reports `Gone` when it ends.
fn peer_worker(peer: usize, addr: SocketAddr, cfg: WorkerCfg, tx: Sender<ToEngine>) {
    let r = run_peer(peer, addr, cfg, &tx);
    if cfg.verbose {
        match &r {
            Ok(()) => eprintln!("* peer {addr}: disconnected"),
            Err(e) => eprintln!("* peer {addr}: {e}"),
        }
    }
    let _ = tx.send(ToEngine::Gone { peer });
}

/// State shared by a worker and its reader thread.
#[derive(Default)]
struct ReaderShared {
    /// Wire messages queued but not yet taken by the worker.
    pending: AtomicUsize,
    /// Set once the worker exits.
    closed: AtomicBool,
}

/// Closes the connection when the worker exits (on any path), which unblocks
/// and ends its reader thread.
struct CloseOnDrop(TcpStream, Arc<ReaderShared>);

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        self.1.closed.store(true, Ordering::Release);
        let _ = self.0.shutdown(Shutdown::Both);
    }
}

/// Read wire messages into the worker's inbox until the socket fails or the
/// worker goes away. Throttled to [`MAX_QUEUED`] outstanding messages so a
/// fast peer is held back by TCP flow control rather than growing the queue.
fn reader_loop(mut sock: TcpStream, tx: Sender<Inbox>, shared: Arc<ReaderShared>) {
    loop {
        while shared.pending.load(Ordering::Acquire) >= MAX_QUEUED {
            if shared.closed.load(Ordering::Acquire) {
                return;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        let item = match peer::read_message(&mut sock) {
            Ok(m) => Inbox::Wire(m),
            Err(e) => Inbox::WireErr(e),
        };
        let last = matches!(item, Inbox::WireErr(_));
        shared.pending.fetch_add(1, Ordering::AcqRel);
        if tx.send(item).is_err() || last {
            return;
        }
    }
}

fn run_peer(peer: usize, addr: SocketAddr, cfg: WorkerCfg, tx: &Sender<ToEngine>) -> Result<()> {
    let num_pieces = cfg.num_pieces;
    let pt = cfg.peer_timeout;
    let mut sock = TcpStream::connect_timeout(&addr, cfg.connect_timeout).map_err(Error::Io)?;
    sock.set_read_timeout(Some(pt)).map_err(Error::Io)?;
    sock.set_write_timeout(Some(pt)).map_err(Error::Io)?;
    if cfg.verbose {
        eprintln!("* peer {addr}: connected");
    }

    peer::write_handshake(&mut sock, &Handshake::new(cfg.info_hash, cfg.peer_id))?;
    let hs = peer::read_handshake(&mut sock)?;
    if hs.info_hash != cfg.info_hash {
        return Err(eerr("peer infohash mismatch"));
    }
    peer::write_message(&mut sock, &Message::Interested)?;

    // From here a reader thread owns the read side (no read timeout: every
    // deadline is enforced here), and the worker multiplexes wire messages
    // and engine commands on one inbox.
    sock.set_read_timeout(None).map_err(Error::Io)?;
    let shared = Arc::new(ReaderShared::default());
    let (in_tx, inbox) = mpsc::channel::<Inbox>();
    {
        let reader = sock.try_clone().map_err(Error::Io)?;
        let (in_tx, shared) = (in_tx.clone(), Arc::clone(&shared));
        std::thread::spawn(move || reader_loop(reader, in_tx, shared));
    }
    let _close = CloseOnDrop(sock.try_clone().map_err(Error::Io)?, Arc::clone(&shared));
    let recv = |timeout: Duration| {
        let r = inbox.recv_timeout(timeout.max(Duration::from_millis(1)));
        if let Ok(Inbox::Wire(_) | Inbox::WireErr(_)) = r {
            shared.pending.fetch_sub(1, Ordering::AcqRel);
        }
        r
    };

    // Phase 1: collect the peer's pieces until it unchokes us, within a
    // deadline that other traffic doesn't extend.
    let mut bf = Bitfield::new(num_pieces);
    let mut got_bitfield = false;
    let join_deadline = Instant::now() + pt * 2;
    loop {
        let now = Instant::now();
        if now >= join_deadline {
            return Err(eerr("peer never unchoked us"));
        }
        match recv(join_deadline - now) {
            Ok(Inbox::Wire(Message::Unchoke)) => break,
            Ok(Inbox::Wire(Message::Bitfield(b))) => {
                merge_wire_bitfield(&mut bf, &mut got_bitfield, &b)?;
            }
            Ok(Inbox::Wire(Message::Have(i))) => {
                check_have(i, num_pieces)?;
                bf.set(i as usize);
            }
            Ok(Inbox::WireErr(e)) => return Err(e),
            Ok(_) | Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
        }
    }
    if cfg.verbose {
        eprintln!("* peer {addr}: unchoked ({} pieces available)", bf.count());
    }
    let joined = ToEngine::Joined {
        peer,
        bitfield: bf.clone(),
        cmd: in_tx,
    };
    if tx.send(joined).is_err() {
        return Ok(()); // engine gone
    }

    // Phase 2: serve the engine.
    let mut choked = false;
    let mut choked_since = Instant::now();
    let mut job: Option<Job> = None;
    loop {
        let now = Instant::now();
        let wait = match &job {
            Some(_) if choked => (choked_since + pt).saturating_duration_since(now),
            Some(j) => (j.last_progress + pt).saturating_duration_since(now),
            None => Duration::from_secs(1),
        };
        match recv(wait) {
            Ok(Inbox::Assign { index, size }) => {
                let mut j = Job::new(index, size)?;
                if choked {
                    // Assigned while choked (a race with our Choked event):
                    // the grace period runs from now.
                    choked_since = Instant::now();
                } else {
                    j.pump(&mut sock)?;
                }
                job = Some(j);
            }
            Ok(Inbox::Stop) | Err(RecvTimeoutError::Disconnected) => return Ok(()),
            Ok(Inbox::WireErr(e)) => return Err(e),
            Ok(Inbox::Wire(msg)) => match msg {
                Message::Choke if !choked => {
                    choked = true;
                    choked_since = Instant::now();
                    if let Some(j) = job.as_mut() {
                        j.on_choke();
                    }
                    if tx.send(ToEngine::Choked { peer }).is_err() {
                        return Ok(());
                    }
                }
                Message::Unchoke if choked => {
                    choked = false;
                    if let Some(j) = job.as_mut() {
                        j.last_progress = Instant::now();
                        j.pump(&mut sock)?;
                    }
                    if tx.send(ToEngine::Unchoked { peer }).is_err() {
                        return Ok(());
                    }
                }
                Message::Have(i) => {
                    check_have(i, num_pieces)?;
                    if !bf.has(i as usize) {
                        bf.set(i as usize);
                        let ev = ToEngine::Have {
                            peer,
                            index: i as usize,
                        };
                        if tx.send(ev).is_err() {
                            return Ok(());
                        }
                    }
                }
                Message::Bitfield(b) => {
                    // Tolerated late (once), reported as the haves it adds.
                    let before = bf.clone();
                    merge_wire_bitfield(&mut bf, &mut got_bitfield, &b)?;
                    for i in (0..num_pieces).filter(|&i| bf.has(i) && !before.has(i)) {
                        if tx.send(ToEngine::Have { peer, index: i }).is_err() {
                            return Ok(());
                        }
                    }
                }
                Message::Piece {
                    index,
                    begin,
                    block,
                } => {
                    // Blocks for anything but the current piece are ignored.
                    // (No `continue` here: the deadline check below must run
                    // however much the peer sends.)
                    let stored = match job.as_mut() {
                        Some(j) if j.index == index => j.on_block(begin, &block),
                        _ => false,
                    };
                    if stored && job.as_ref().is_some_and(Job::is_done) {
                        let j = job.take().expect("job present");
                        let ev = ToEngine::PieceDone {
                            peer,
                            index: j.index as usize,
                            data: j.buf,
                        };
                        if tx.send(ev).is_err() {
                            return Ok(());
                        }
                    } else if stored && !choked {
                        if let Some(j) = job.as_mut() {
                            j.pump(&mut sock)?;
                        }
                    }
                }
                // Keep-alives, interest, requests (we don't serve while
                // downloading), cancels, port, extensions: nothing to do.
                _ => {}
            },
            Err(RecvTimeoutError::Timeout) => {}
        }

        // Deadlines, independent of unrelated wire traffic.
        let now = Instant::now();
        if let Some(j) = &job {
            if choked && now >= choked_since + pt {
                let index = j.index as usize;
                job = None;
                if tx.send(ToEngine::Released { peer, index }).is_err() {
                    return Ok(());
                }
            } else if !choked && now >= j.last_progress + pt {
                return Err(eerr("peer stalled mid-piece"));
            }
        }
    }
}

/// Apply a wire `bitfield` payload: validated (BEP 3 length and spare bits),
/// accepted once, and merged so earlier `have`s are not lost.
fn merge_wire_bitfield(bf: &mut Bitfield, got: &mut bool, payload: &[u8]) -> Result<()> {
    if *got {
        return Err(eerr("peer sent a second bitfield"));
    }
    let wire = Bitfield::from_wire(payload, bf.len()).ok_or_else(|| eerr("malformed bitfield"))?;
    bf.merge(&wire);
    *got = true;
    Ok(())
}

fn check_have(index: u32, num_pieces: usize) -> Result<()> {
    if index as usize >= num_pieces {
        return Err(eerr("have index out of range"));
    }
    Ok(())
}

/// One piece being fetched from a peer.
struct Job {
    index: u32,
    size: u32,
    buf: Vec<u8>,
    /// Blocks requested and (as far as we know) still pending at the peer.
    requested: Vec<bool>,
    filled: Vec<bool>,
    received: usize,
    outstanding: usize,
    /// Scan cursor for the next block to request.
    next: usize,
    /// Last block arrival (or unchoke): the stall deadline runs from here.
    last_progress: Instant,
}

impl Job {
    fn new(index: usize, size: u64) -> Result<Job> {
        if size > u32::MAX as u64 {
            return Err(eerr("piece larger than 4 GiB is unsupported"));
        }
        let index = u32::try_from(index).map_err(|_| eerr("piece index out of range"))?;
        let size = size as u32;
        let num_blocks = (size as usize).div_ceil(BLOCK_SIZE as usize);
        Ok(Job {
            index,
            size,
            buf: vec![0u8; size as usize],
            requested: vec![false; num_blocks],
            filled: vec![false; num_blocks],
            received: 0,
            outstanding: 0,
            next: 0,
            last_progress: Instant::now(),
        })
    }

    fn num_blocks(&self) -> usize {
        self.filled.len()
    }

    fn block_len(&self, bi: usize) -> u32 {
        BLOCK_SIZE.min(self.size - bi as u32 * BLOCK_SIZE)
    }

    fn is_done(&self) -> bool {
        self.received == self.num_blocks()
    }

    /// Keep a bounded window of block requests in flight rather than flooding
    /// the whole piece: many peers cap their request queue and silently drop
    /// the overflow.
    fn pump<W: std::io::Write>(&mut self, w: &mut W) -> Result<()> {
        while self.outstanding < PIPELINE_DEPTH && self.next < self.num_blocks() {
            let bi = self.next;
            self.next += 1;
            if self.filled[bi] || self.requested[bi] {
                continue;
            }
            peer::write_message(
                w,
                &Message::Request {
                    index: self.index,
                    begin: bi as u32 * BLOCK_SIZE,
                    length: self.block_len(bi),
                },
            )?;
            self.requested[bi] = true;
            self.outstanding += 1;
        }
        Ok(())
    }

    /// The peer choked us, discarding every pending request (BEP 3): forget
    /// them so the missing blocks are requested again after an unchoke.
    fn on_choke(&mut self) {
        for (req, &filled) in self.requested.iter_mut().zip(&self.filled) {
            if !filled {
                *req = false;
            }
        }
        self.outstanding = 0;
        self.next = 0;
    }

    /// Store a block. Only a whole, correctly sized block at a block boundary
    /// that we don't have yet counts; returns whether it was stored.
    fn on_block(&mut self, begin: u32, block: &[u8]) -> bool {
        if !begin.is_multiple_of(BLOCK_SIZE) {
            return false;
        }
        let bi = (begin / BLOCK_SIZE) as usize;
        if bi >= self.num_blocks() || self.filled[bi] || block.len() != self.block_len(bi) as usize
        {
            return false;
        }
        let off = begin as usize;
        self.buf[off..off + block.len()].copy_from_slice(block);
        self.filled[bi] = true;
        self.received += 1;
        if self.requested[bi] {
            self.outstanding = self.outstanding.saturating_sub(1);
        }
        self.last_progress = Instant::now();
        true
    }
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

    fn requests(wire: &[u8]) -> Vec<(u32, u32, u32)> {
        let mut c = std::io::Cursor::new(wire);
        let mut out = Vec::new();
        while (c.position() as usize) < wire.len() {
            if let Message::Request {
                index,
                begin,
                length,
            } = peer::read_message(&mut c).unwrap()
            {
                out.push((index, begin, length));
            }
        }
        out
    }

    /// After a choke the pending requests are forgotten and, on unchoke, the
    /// still-missing blocks are requested again (the old engine waited for
    /// them forever).
    #[test]
    fn job_rerequests_after_choke() {
        let size = BLOCK_SIZE * 3 + 10;
        let mut j = Job::new(7, size as u64).unwrap();
        let mut wire = Vec::new();
        j.pump(&mut wire).unwrap();
        assert_eq!(requests(&wire).len(), 4);
        assert_eq!(j.outstanding, 4);

        // Block 1 arrives, then the peer chokes us.
        assert!(j.on_block(BLOCK_SIZE, &vec![1u8; BLOCK_SIZE as usize]));
        j.on_choke();
        assert_eq!(j.outstanding, 0);

        wire.clear();
        j.pump(&mut wire).unwrap();
        let begins: Vec<u32> = requests(&wire).iter().map(|r| r.1).collect();
        assert_eq!(begins, vec![0, BLOCK_SIZE * 2, BLOCK_SIZE * 3]);
        // The short tail block is requested with its exact length.
        assert_eq!(requests(&wire)[2].2, 10);
    }

    /// Only exact, aligned, not-yet-stored blocks count.
    #[test]
    fn job_rejects_malformed_blocks() {
        let size = BLOCK_SIZE + 10;
        let mut j = Job::new(0, size as u64).unwrap();
        assert!(!j.on_block(1, &[0u8; 4]), "unaligned");
        assert!(!j.on_block(0, &[0u8; 4]), "short block");
        assert!(!j.on_block(BLOCK_SIZE * 2, &[0u8; 10]), "past the end");
        assert!(!j.on_block(BLOCK_SIZE, &[0u8; 11]), "tail too long");
        assert!(j.on_block(BLOCK_SIZE, &[0u8; 10]));
        assert!(!j.on_block(BLOCK_SIZE, &[0u8; 10]), "duplicate");
        assert!(j.on_block(0, &vec![0u8; BLOCK_SIZE as usize]));
        assert!(j.is_done());
    }

    #[test]
    fn wire_bitfield_is_validated_merged_and_accepted_once() {
        let mut bf = Bitfield::new(10);
        bf.set(9); // an earlier `have`
        let mut got = false;
        assert!(merge_wire_bitfield(&mut bf, &mut got, &[0x80]).is_err());
        assert!(merge_wire_bitfield(&mut bf, &mut got, &[0x80, 0x01]).is_err());
        merge_wire_bitfield(&mut bf, &mut got, &[0x80, 0x00]).unwrap();
        assert!(bf.has(0) && bf.has(9), "have survives the bitfield");
        assert!(merge_wire_bitfield(&mut bf, &mut got, &[0x80, 0x00]).is_err());
    }
}

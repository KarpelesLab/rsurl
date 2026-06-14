//! Seeding: serve verified pieces to peers over inbound connections.
//!
//! After a download completes, [`run`] binds the listen port and answers
//! incoming peers — handshake, advertise the full bitfield, unchoke on
//! interest, and serve `request`s from [`Storage`]. It tracks uploaded bytes
//! and stops once a share-ratio target is met (or runs until the process is
//! terminated for [`SeedMode::Forever`](super::download::SeedMode)).

use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

use super::download::{Progress, SeedMode, Stats, TorrentOptions};
use super::metainfo::Metainfo;
use super::peer::{self, Handshake, Message};
use super::storage::Storage;

/// Largest `request` length we will serve, bounding per-request allocation.
const MAX_REQUEST: u32 = 128 * 1024;

fn serr(msg: impl Into<String>) -> Error {
    Error::BadResponse(format!("bt seed: {}", msg.into()))
}

/// Seed `storage` (which must be complete) until the [`SeedMode`] says to stop.
pub fn run(
    meta: &Metainfo,
    storage: Storage,
    peer_id: [u8; 20],
    opts: &TorrentOptions,
    mut stats: Stats,
    progress: &mut dyn FnMut(&Progress),
) -> Result<Stats> {
    let info_hash = meta.info_hash;
    let num_pieces = meta.num_pieces();
    let complete_bf = storage.bitfield().as_bytes().to_vec();
    let storage = Arc::new(Mutex::new(storage));
    let uploaded = Arc::new(AtomicU64::new(stats.uploaded));
    let peer_timeout = opts.peer_timeout;

    // Share ratio is against this session's downloaded bytes; for a seed-only
    // run (nothing downloaded) fall back to the torrent size as the unit.
    let denom = if stats.downloaded > 0 {
        stats.downloaded
    } else {
        meta.total_length.max(1)
    };
    let target_upload = match opts.seed {
        SeedMode::UntilRatio(r) if r > 0.0 => Some((r * denom as f64) as u64),
        _ => None,
    };

    let listener = TcpListener::bind(("0.0.0.0", opts.listen_port)).map_err(Error::Io)?;
    listener.set_nonblocking(true).map_err(Error::Io)?;

    let mut last_report = Instant::now();
    loop {
        match listener.accept() {
            Ok((stream, _addr)) => {
                // A socket from accept() inherits the listener's non-blocking
                // flag on macOS/BSD and Windows (but not Linux); force blocking
                // so serve()'s timeout-based reads behave consistently.
                let _ = stream.set_nonblocking(false);
                let storage = Arc::clone(&storage);
                let uploaded = Arc::clone(&uploaded);
                let bf = complete_bf.clone();
                std::thread::spawn(move || {
                    let _ = serve(
                        stream,
                        info_hash,
                        peer_id,
                        num_pieces,
                        &bf,
                        storage,
                        &uploaded,
                        peer_timeout,
                    );
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(Error::Io(e)),
        }

        let up = uploaded.load(Ordering::Relaxed);
        if last_report.elapsed() >= Duration::from_millis(500) {
            progress(&Progress {
                downloaded: stats.downloaded,
                total: meta.total_length,
                pieces_complete: num_pieces,
                num_pieces,
                uploaded: up,
            });
            last_report = Instant::now();
        }
        if let Some(t) = target_upload {
            if up >= t {
                stats.uploaded = up;
                return Ok(stats);
            }
        }
    }
}

/// Serve one inbound peer connection for as long as it stays open.
#[allow(clippy::too_many_arguments)]
fn serve(
    mut s: TcpStream,
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    num_pieces: usize,
    bitfield_bytes: &[u8],
    storage: Arc<Mutex<Storage>>,
    uploaded: &AtomicU64,
    timeout: Duration,
) -> Result<()> {
    s.set_read_timeout(Some(timeout)).map_err(Error::Io)?;
    s.set_write_timeout(Some(timeout)).map_err(Error::Io)?;

    let hs = peer::read_handshake(&mut s)?;
    if hs.info_hash != info_hash {
        return Err(serr("peer infohash mismatch"));
    }
    peer::write_handshake(&mut s, &Handshake::new(info_hash, peer_id))?;
    peer::write_message(&mut s, &Message::Bitfield(bitfield_bytes.to_vec()))?;

    loop {
        match peer::read_message(&mut s)? {
            Message::Interested => peer::write_message(&mut s, &Message::Unchoke)?,
            Message::Request {
                index,
                begin,
                length,
            } => {
                if length > MAX_REQUEST || index as usize >= num_pieces {
                    return Err(serr("invalid request"));
                }
                let block = {
                    let mut st = storage.lock().unwrap();
                    st.read_block(index as usize, begin, length)?
                };
                let n = block.len() as u64;
                peer::write_message(
                    &mut s,
                    &Message::Piece {
                        index,
                        begin,
                        block,
                    },
                )?;
                uploaded.fetch_add(n, Ordering::Relaxed);
            }
            // We are a pure seed: ignore everything else, including cancels.
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bittorrent::metainfo::sha1;
    use crate::bittorrent::peer::BLOCK_SIZE;
    use std::path::PathBuf;

    #[test]
    fn serves_a_block_to_a_leecher() {
        // A tiny complete torrent: 8 bytes, one piece.
        let data = b"abcdefgh".to_vec();
        let hashes = vec![sha1(&data)];
        let path: PathBuf =
            std::env::temp_dir().join(format!("rsurl_seed_{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut storage = Storage::create(vec![(path.clone(), 8)], 8, hashes).unwrap();
        assert!(storage.write_piece(0, &data).unwrap());
        assert!(storage.is_complete());
        let bf = storage.bitfield().as_bytes().to_vec();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let uploaded = Arc::new(AtomicU64::new(0));

        let storage = Arc::new(Mutex::new(storage));
        let up2 = Arc::clone(&uploaded);
        let st2 = Arc::clone(&storage);
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let _ = serve(
                stream,
                [7u8; 20],
                [9u8; 20],
                1,
                &bf,
                st2,
                &up2,
                Duration::from_secs(5),
            );
        });

        // Act as a leecher.
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        peer::write_handshake(&mut c, &Handshake::new([7u8; 20], [1u8; 20])).unwrap();
        let hs = peer::read_handshake(&mut c).unwrap();
        assert_eq!(hs.info_hash, [7u8; 20]);
        // Bitfield, then unchoke after we express interest.
        assert!(matches!(
            peer::read_message(&mut c).unwrap(),
            Message::Bitfield(_)
        ));
        peer::write_message(&mut c, &Message::Interested).unwrap();
        assert_eq!(peer::read_message(&mut c).unwrap(), Message::Unchoke);
        peer::write_message(
            &mut c,
            &Message::Request {
                index: 0,
                begin: 0,
                length: BLOCK_SIZE.min(8),
            },
        )
        .unwrap();
        match peer::read_message(&mut c).unwrap() {
            Message::Piece { block, .. } => assert_eq!(block, data),
            other => panic!("expected piece, got {other:?}"),
        }
        drop(c);
        let _ = handle.join();
        assert_eq!(uploaded.load(Ordering::Relaxed), 8);
        let _ = std::fs::remove_file(&path);
    }
}

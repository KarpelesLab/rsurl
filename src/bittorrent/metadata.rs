//! Magnet metadata download (BEP 9 `ut_metadata` over the BEP 10 extension
//! protocol).
//!
//! A `magnet:` link carries only the infohash, so the `info` dictionary itself
//! must be fetched from a peer before anything can be downloaded. We perform
//! the standard handshake (advertising extensions), exchange BEP 10 extended
//! handshakes to learn the peer's `ut_metadata` id and the metadata size, then
//! request the info dict in 16 KiB pieces and reassemble it. The result is
//! verified against the infohash before use.

use std::collections::BTreeMap;
use std::io::Read;
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use crate::error::{Error, Result};

use super::bencode::{self, Value};
use super::metainfo::{sha1, Metainfo};
use super::peer::{self, Handshake, Message};

/// How many peers to probe for metadata at once.
const MAX_PARALLEL: usize = 30;

/// `ut_metadata` transfers the info dict in 16 KiB pieces (BEP 9).
const METADATA_PIECE: usize = 16 * 1024;
/// Sanity cap on a torrent's info dict; far beyond any real torrent, it bounds
/// allocation against a hostile `metadata_size`.
const MAX_METADATA: usize = 64 * 1024 * 1024;
/// The extended-message id we advertise for `ut_metadata`; peers address their
/// data replies to us using this id.
const OUR_UT_METADATA_ID: u8 = 1;

fn merr(msg: impl Into<String>) -> Error {
    Error::BadResponse(format!("bt metadata: {}", msg.into()))
}

/// Fetch the `info` dictionary for `info_hash` from `peers` and parse it into a
/// [`Metainfo`]. Peers are probed concurrently (a bounded number at a
/// time) and the first verified metadata wins; remaining attempts are
/// abandoned. Returns the parsed metadata together with the raw, verified
/// `info` bytes (so the caller can write a `.torrent`), or the last error if no
/// peer yields valid metadata.
pub fn fetch_metainfo(
    info_hash: [u8; 20],
    peers: &[SocketAddr],
    peer_id: [u8; 20],
    connect_timeout: Duration,
    peer_timeout: Duration,
    verbose: bool,
) -> Result<(Metainfo, Vec<u8>)> {
    if peers.is_empty() {
        return Err(merr("no peers to fetch metadata from"));
    }

    let peers: Arc<Vec<SocketAddr>> = Arc::new(peers.to_vec());
    let next = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<Result<Vec<u8>>>();

    let workers = MAX_PARALLEL.min(peers.len());
    for _ in 0..workers {
        let tx = tx.clone();
        let peers = Arc::clone(&peers);
        let next = Arc::clone(&next);
        let done = Arc::clone(&done);
        std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= peers.len() {
                    break;
                }
                let addr = peers[i];
                let r = fetch_info(addr, info_hash, peer_id, connect_timeout, peer_timeout);
                let ok = r.is_ok();
                if verbose {
                    match &r {
                        Ok(info) => eprintln!("* metadata peer {addr}: got {} bytes", info.len()),
                        Err(e) => eprintln!("* metadata peer {addr}: {e}"),
                    }
                }
                if tx.send(r).is_err() || ok {
                    break;
                }
            }
        });
    }
    drop(tx); // so rx closes once every worker exits

    let mut last = merr("no peer served metadata");
    while let Ok(msg) = rx.recv() {
        match msg {
            Ok(info) => {
                done.store(true, Ordering::Relaxed);
                return Metainfo::from_info_dict(&info).map(|m| (m, info));
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Connect to one peer and return the raw, infohash-verified `info` bytes.
pub fn fetch_info(
    addr: SocketAddr,
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    connect_timeout: Duration,
    peer_timeout: Duration,
) -> Result<Vec<u8>> {
    let mut sock = TcpStream::connect_timeout(&addr, connect_timeout).map_err(Error::Io)?;
    sock.set_read_timeout(Some(peer_timeout))
        .map_err(Error::Io)?;
    sock.set_write_timeout(Some(peer_timeout))
        .map_err(Error::Io)?;

    peer::write_handshake(&mut sock, &Handshake::new(info_hash, peer_id))?;
    let hs = peer::read_handshake(&mut sock)?;
    if hs.info_hash != info_hash {
        return Err(merr("peer infohash mismatch"));
    }
    if !hs.supports_extensions() {
        return Err(merr("peer does not support the extension protocol"));
    }

    peer::write_message(&mut sock, &ext_handshake())?;
    let (peer_ut_id, size) = read_peer_handshake(&mut sock)?;
    if size == 0 || size > MAX_METADATA {
        return Err(merr("peer reported an implausible metadata size"));
    }
    let num_pieces = size.div_ceil(METADATA_PIECE);

    let mut info = Vec::with_capacity(size);
    for piece in 0..num_pieces {
        peer::write_message(&mut sock, &request_piece(peer_ut_id, piece))?;
        let data = read_piece_data(&mut sock, piece)?;
        info.extend_from_slice(&data);
        if info.len() > size {
            return Err(merr("metadata overran the reported size"));
        }
    }
    if info.len() != size {
        return Err(merr("metadata incomplete"));
    }
    if sha1(&info) != info_hash {
        return Err(merr("metadata failed infohash verification"));
    }
    Ok(info)
}

/// Our extended handshake: a `d{m:{ut_metadata:1}}e` advertising support.
fn ext_handshake() -> Message {
    let mut m = BTreeMap::new();
    m.insert(
        b"ut_metadata".to_vec(),
        Value::Int(i64::from(OUR_UT_METADATA_ID)),
    );
    let mut d = BTreeMap::new();
    d.insert(b"m".to_vec(), Value::Dict(m));
    Message::Extended {
        ext_id: 0,
        payload: bencode::encode(&Value::Dict(d)),
    }
}

/// A `ut_metadata` request for one piece, addressed to the peer's id.
fn request_piece(peer_ut_id: u8, piece: usize) -> Message {
    let mut d = BTreeMap::new();
    d.insert(b"msg_type".to_vec(), Value::Int(0)); // 0 = request
    d.insert(b"piece".to_vec(), Value::Int(piece as i64));
    Message::Extended {
        ext_id: peer_ut_id,
        payload: bencode::encode(&Value::Dict(d)),
    }
}

/// Read messages until the peer's extended handshake (ext id 0), returning its
/// `ut_metadata` message id and advertised `metadata_size`.
fn read_peer_handshake<R: Read>(r: &mut R) -> Result<(u8, usize)> {
    loop {
        if let Message::Extended { ext_id: 0, payload } = peer::read_message(r)? {
            let v = bencode::parse(&payload)?;
            let ut_id = v
                .get(b"m")
                .and_then(|m| m.get(b"ut_metadata"))
                .and_then(Value::as_int)
                .ok_or_else(|| merr("peer does not offer ut_metadata"))?;
            if !(1..=255).contains(&ut_id) {
                return Err(merr("peer ut_metadata id out of range"));
            }
            let size = v
                .get(b"metadata_size")
                .and_then(Value::as_int)
                .ok_or_else(|| merr("peer did not advertise metadata_size"))?;
            if size < 0 {
                return Err(merr("negative metadata_size"));
            }
            return Ok((ut_id as u8, size as usize));
        }
        // Bitfield/have/choke and other setup traffic: ignored.
    }
}

/// Read messages until a `ut_metadata` data reply for `piece`, returning the
/// raw piece bytes (the part after the bencoded header dict).
fn read_piece_data<R: Read>(r: &mut R, piece: usize) -> Result<Vec<u8>> {
    loop {
        if let Message::Extended { ext_id, payload } = peer::read_message(r)? {
            if ext_id != OUR_UT_METADATA_ID {
                continue;
            }
            // A bencoded header dict, then the raw piece bytes immediately after.
            let mut dec = bencode::Decoder::new(&payload);
            let header = dec.value()?;
            let body = &payload[dec.pos()..];
            let msg_type = header
                .get(b"msg_type")
                .and_then(Value::as_int)
                .unwrap_or(-1);
            let pcs = header.get(b"piece").and_then(Value::as_int).unwrap_or(-1);
            match msg_type {
                1 => {
                    // data
                    if pcs != piece as i64 {
                        return Err(merr("peer sent the wrong metadata piece"));
                    }
                    return Ok(body.to_vec());
                }
                2 => return Err(merr("peer rejected the metadata request")),
                _ => {} // 0 (request) or unknown: keep reading
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn parses_peer_handshake() {
        let mut m = BTreeMap::new();
        m.insert(b"ut_metadata".to_vec(), Value::Int(3));
        let mut d = BTreeMap::new();
        d.insert(b"m".to_vec(), Value::Dict(m));
        d.insert(b"metadata_size".to_vec(), Value::Int(1234));
        let msg = Message::Extended {
            ext_id: 0,
            payload: bencode::encode(&Value::Dict(d)),
        };
        let mut buf = Vec::new();
        peer::write_message(&mut buf, &msg).unwrap();
        let (id, size) = read_peer_handshake(&mut Cursor::new(buf)).unwrap();
        assert_eq!(id, 3);
        assert_eq!(size, 1234);
    }

    #[test]
    fn parses_data_piece_with_trailing_bytes() {
        let mut d = BTreeMap::new();
        d.insert(b"msg_type".to_vec(), Value::Int(1));
        d.insert(b"piece".to_vec(), Value::Int(0));
        d.insert(b"total_size".to_vec(), Value::Int(5));
        let mut payload = bencode::encode(&Value::Dict(d));
        payload.extend_from_slice(b"hello");
        let msg = Message::Extended {
            ext_id: OUR_UT_METADATA_ID,
            payload,
        };
        let mut buf = Vec::new();
        peer::write_message(&mut buf, &msg).unwrap();
        let data = read_piece_data(&mut Cursor::new(buf), 0).unwrap();
        assert_eq!(data, b"hello");
    }
}

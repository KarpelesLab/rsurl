//! End-to-end BitTorrent download test: an in-process seeder serves a known
//! payload over the real peer wire protocol, and `rsurl::bittorrent::download`
//! fetches + verifies it. Exercises bencode/metainfo, the handshake, message
//! framing, the piece picker, and storage together.

use std::collections::BTreeMap;
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use purecrypto::hash::{Digest, Sha1};

use rsurl::bittorrent::bencode::{encode, Value};
use rsurl::bittorrent::peer::{self, Handshake, Message};
use rsurl::bittorrent::{download, Bitfield, Metainfo, TorrentOptions};

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    let mut o = [0u8; 20];
    o.copy_from_slice(h.finalize().as_ref());
    o
}

/// Build a single-file `.torrent` for `data` with the given piece length, plus
/// the parsed `Metainfo`.
fn make_torrent(data: &[u8], piece_len: usize, name: &str) -> Metainfo {
    let mut pieces = Vec::new();
    for chunk in data.chunks(piece_len) {
        pieces.extend_from_slice(&sha1(chunk));
    }
    let mut info = BTreeMap::new();
    info.insert(b"name".to_vec(), Value::Bytes(name.as_bytes().to_vec()));
    info.insert(b"piece length".to_vec(), Value::Int(piece_len as i64));
    info.insert(b"length".to_vec(), Value::Int(data.len() as i64));
    info.insert(b"pieces".to_vec(), Value::Bytes(pieces));
    let mut root = BTreeMap::new();
    root.insert(b"info".to_vec(), Value::Dict(info));
    let bytes = encode(&Value::Dict(root));
    Metainfo::from_bytes(&bytes).unwrap()
}

/// Spawn a one-connection seeder that has the whole `data` and serves any
/// block request. Returns the listening port.
fn start_seeder(data: Vec<u8>, meta: Metainfo) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let piece_len = meta.piece_length as usize;
    let num_pieces = meta.num_pieces();
    let info_hash = meta.info_hash;

    thread::spawn(move || {
        let Ok((mut s, _)) = listener.accept() else {
            return;
        };
        s.set_read_timeout(Some(Duration::from_secs(10))).ok();
        // Handshake.
        let hs = match peer::read_handshake(&mut s) {
            Ok(h) => h,
            Err(_) => return,
        };
        if hs.info_hash != info_hash {
            return;
        }
        let _ = peer::write_handshake(&mut s, &Handshake::new(info_hash, [0x55; 20]));

        // Advertise every piece, then unchoke on interest.
        let mut bf = Bitfield::new(num_pieces);
        for i in 0..num_pieces {
            bf.set(i);
        }
        let _ = peer::write_message(&mut s, &Message::Bitfield(bf.as_bytes().to_vec()));

        loop {
            let msg = match peer::read_message(&mut s) {
                Ok(m) => m,
                Err(_) => return,
            };
            match msg {
                Message::Interested => {
                    let _ = peer::write_message(&mut s, &Message::Unchoke);
                }
                Message::Request {
                    index,
                    begin,
                    length,
                } => {
                    let off = index as usize * piece_len + begin as usize;
                    let end = (off + length as usize).min(data.len());
                    if off <= end {
                        let block = data[off..end].to_vec();
                        let _ = peer::write_message(
                            &mut s,
                            &Message::Piece {
                                index,
                                begin,
                                block,
                            },
                        );
                    }
                }
                _ => {}
            }
        }
    });
    port
}

#[test]
fn downloads_and_verifies_from_seeder() {
    // Deterministic 25 000-byte payload, 4 KiB pieces (last piece short).
    let data: Vec<u8> = (0..25_000u32).map(|i| (i % 257) as u8).collect();
    let meta = make_torrent(&data, 4096, "payload.bin");
    assert!(meta.num_pieces() >= 6);

    let port = start_seeder(data.clone(), meta.clone());
    let peers = vec![format!("127.0.0.1:{port}").parse().unwrap()];

    let out = std::env::temp_dir().join(format!("rsurl_bt_dl_{}.bin", std::process::id()));
    let _ = std::fs::remove_file(&out);
    let layout = vec![(out.clone(), data.len() as u64)];

    let opts = TorrentOptions::default();
    let mut last = 0u64;
    let stats = download(&meta, layout, &peers, &opts, &mut |p| {
        assert!(p.downloaded >= last);
        last = p.downloaded;
    })
    .expect("download");

    assert_eq!(stats.downloaded, data.len() as u64);
    assert_eq!(
        std::fs::read(&out).unwrap(),
        data,
        "downloaded file mismatch"
    );
    let _ = std::fs::remove_file(&out);
}

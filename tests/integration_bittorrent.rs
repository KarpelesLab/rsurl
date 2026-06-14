//! End-to-end BitTorrent download test: an in-process seeder serves a known
//! payload over the real peer wire protocol, and `rsurl::bittorrent::download`
//! fetches + verifies it. Exercises bencode/metainfo, the handshake, message
//! framing, the piece picker, and storage together.
#![cfg(feature = "bittorrent")]

use std::collections::BTreeMap;
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use purecrypto::hash::{Digest, Sha1};

use rsurl::bittorrent::bencode::{encode, parse, Value};
use rsurl::bittorrent::peer::{self, Handshake, Message};
use rsurl::bittorrent::{download, Bitfield, Metainfo, TorrentOptions};

/// ut_metadata piece size (BEP 9).
const METADATA_PIECE: usize = 16 * 1024;

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    let mut o = [0u8; 20];
    o.copy_from_slice(h.finalize().as_ref());
    o
}

/// Build a single-file `.torrent` for `data` with the given piece length.
/// Returns the encoded `.torrent` bytes and the parsed `Metainfo`.
fn make_torrent_bytes(data: &[u8], piece_len: usize, name: &str) -> (Vec<u8>, Metainfo) {
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
    let meta = Metainfo::from_bytes(&bytes).unwrap();
    (bytes, meta)
}

fn make_torrent(data: &[u8], piece_len: usize, name: &str) -> Metainfo {
    make_torrent_bytes(data, piece_len, name).1
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

/// Drive the actual `rsurl` binary: `--torrent --bt-peer <seeder> -o <file>`
/// against a `.torrent` on disk and the in-process seeder.
#[test]
fn cli_downloads_torrent_to_output() {
    let data: Vec<u8> = (0..18_000u32)
        .map(|i| (i.wrapping_mul(7) % 251) as u8)
        .collect();
    let (torrent_bytes, meta) = make_torrent_bytes(&data, 4096, "cli.bin");

    let port = start_seeder(data.clone(), meta.clone());

    let pid = std::process::id();
    let tdir = std::env::temp_dir();
    let torrent_path = tdir.join(format!("rsurl_cli_{pid}.torrent"));
    let out = tdir.join(format!("rsurl_cli_{pid}.bin"));
    std::fs::write(&torrent_path, &torrent_bytes).unwrap();
    let _ = std::fs::remove_file(&out);

    let status = std::process::Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .arg("--torrent")
        .arg("--bt-peer")
        .arg(format!("127.0.0.1:{port}"))
        .arg("-s")
        .arg("-o")
        .arg(&out)
        .arg(&torrent_path)
        .status()
        .expect("spawn rsurl");

    assert!(status.success(), "rsurl exited with {status}");
    assert_eq!(std::fs::read(&out).unwrap(), data, "cli download mismatch");

    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&torrent_path);
}

/// Build the raw bencoded `info` dictionary for a single-file torrent.
fn make_info_bytes(data: &[u8], piece_len: usize, name: &str) -> Vec<u8> {
    let mut pieces = Vec::new();
    for chunk in data.chunks(piece_len) {
        pieces.extend_from_slice(&sha1(chunk));
    }
    let mut info = BTreeMap::new();
    info.insert(b"name".to_vec(), Value::Bytes(name.as_bytes().to_vec()));
    info.insert(b"piece length".to_vec(), Value::Int(piece_len as i64));
    info.insert(b"length".to_vec(), Value::Int(data.len() as i64));
    info.insert(b"pieces".to_vec(), Value::Bytes(pieces));
    encode(&Value::Dict(info))
}

fn to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

fn meta_ext_handshake(ut_id: i64, size: usize) -> Message {
    let mut m = BTreeMap::new();
    m.insert(b"ut_metadata".to_vec(), Value::Int(ut_id));
    let mut d = BTreeMap::new();
    d.insert(b"m".to_vec(), Value::Dict(m));
    d.insert(b"metadata_size".to_vec(), Value::Int(size as i64));
    Message::Extended {
        ext_id: 0,
        payload: encode(&Value::Dict(d)),
    }
}

fn meta_data_msg(to_id: u8, piece: usize, total: usize, chunk: &[u8]) -> Message {
    let mut d = BTreeMap::new();
    d.insert(b"msg_type".to_vec(), Value::Int(1));
    d.insert(b"piece".to_vec(), Value::Int(piece as i64));
    d.insert(b"total_size".to_vec(), Value::Int(total as i64));
    let mut payload = encode(&Value::Dict(d));
    payload.extend_from_slice(chunk);
    Message::Extended {
        ext_id: to_id,
        payload,
    }
}

/// A seeder that both serves the BEP 9 metadata (ut_metadata) and the actual
/// pieces, over as many connections as are opened. Returns its port.
fn start_meta_seeder(data: Vec<u8>, info_bytes: Vec<u8>) -> u16 {
    let info_hash = sha1(&info_bytes);
    let meta = Metainfo::from_info_dict(&info_bytes).unwrap();
    let piece_len = meta.piece_length as usize;
    let num_pieces = meta.num_pieces();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut s) = conn else {
                return;
            };
            let data = data.clone();
            let info_bytes = info_bytes.clone();
            thread::spawn(move || {
                s.set_read_timeout(Some(Duration::from_secs(10))).ok();
                let hs = match peer::read_handshake(&mut s) {
                    Ok(h) => h,
                    Err(_) => return,
                };
                if hs.info_hash != info_hash {
                    return;
                }
                let _ = peer::write_handshake(&mut s, &Handshake::new(info_hash, [0x55; 20]));

                let mut bf = Bitfield::new(num_pieces);
                for i in 0..num_pieces {
                    bf.set(i);
                }
                let _ = peer::write_message(&mut s, &Message::Bitfield(bf.as_bytes().to_vec()));
                // Advertise ut_metadata (our id 2) + the metadata size.
                let _ = peer::write_message(&mut s, &meta_ext_handshake(2, info_bytes.len()));

                let mut client_ut_id: u8 = 1;
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
                                let _ = peer::write_message(
                                    &mut s,
                                    &Message::Piece {
                                        index,
                                        begin,
                                        block: data[off..end].to_vec(),
                                    },
                                );
                            }
                        }
                        Message::Extended { ext_id: 0, payload } => {
                            // Learn the client's ut_metadata id for our replies.
                            if let Ok(v) = parse(&payload) {
                                if let Some(id) = v
                                    .get(b"m")
                                    .and_then(|m| m.get(b"ut_metadata"))
                                    .and_then(Value::as_int)
                                {
                                    client_ut_id = id as u8;
                                }
                            }
                        }
                        Message::Extended { payload, .. } => {
                            // A ut_metadata request addressed to our id (2).
                            let piece = parse(&payload)
                                .ok()
                                .and_then(|v| v.get(b"piece").and_then(Value::as_int))
                                .unwrap_or(0) as usize;
                            let start = piece * METADATA_PIECE;
                            let end = (start + METADATA_PIECE).min(info_bytes.len());
                            let _ = peer::write_message(
                                &mut s,
                                &meta_data_msg(
                                    client_ut_id,
                                    piece,
                                    info_bytes.len(),
                                    &info_bytes[start..end],
                                ),
                            );
                        }
                        _ => {}
                    }
                }
            });
        }
    });
    port
}

/// Full magnet flow through the binary: fetch the info dict via ut_metadata,
/// then download + verify the data — all from one in-process seeder.
#[test]
fn cli_downloads_magnet() {
    let data: Vec<u8> = (0..30_000u32)
        .map(|i| (i.wrapping_mul(13) % 247) as u8)
        .collect();
    let info_bytes = make_info_bytes(&data, 4096, "magnet.bin");
    let info_hash = sha1(&info_bytes);

    let port = start_meta_seeder(data.clone(), info_bytes);
    let magnet = format!(
        "magnet:?xt=urn:btih:{}&dn=magnet.bin&x.pe=127.0.0.1:{port}",
        to_hex(&info_hash)
    );

    let pid = std::process::id();
    let out = std::env::temp_dir().join(format!("rsurl_magnet_{pid}.bin"));
    let _ = std::fs::remove_file(&out);

    let status = std::process::Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .arg("-s")
        .arg("-o")
        .arg(&out)
        .arg(&magnet)
        .status()
        .expect("spawn rsurl");

    assert!(status.success(), "rsurl exited with {status}");
    assert_eq!(
        std::fs::read(&out).unwrap(),
        data,
        "magnet download mismatch"
    );

    let _ = std::fs::remove_file(&out);
}

/// Grab a likely-free localhost port by binding then releasing it.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// `--share-ratio`: the binary downloads from a seeder, then seeds on its
/// listen port; a test leecher drains the whole torrent (ratio 1.0), after
/// which the binary must exit on its own.
#[test]
fn cli_seeds_until_share_ratio() {
    use std::io::Read;

    let data: Vec<u8> = (0..12_000u32).map(|i| (i % 251) as u8).collect();
    let (torrent_bytes, meta) = make_torrent_bytes(&data, 4096, "seed.bin");
    let piece_len = meta.piece_length as usize;
    let info_hash = meta.info_hash;
    let num_pieces = meta.num_pieces();

    // Upstream seeder the binary downloads from.
    let src_port = start_seeder(data.clone(), meta.clone());
    let listen_port = free_port();

    let pid = std::process::id();
    let tdir = std::env::temp_dir();
    let torrent_path = tdir.join(format!("rsurl_seed_{pid}.torrent"));
    let out = tdir.join(format!("rsurl_seed_{pid}.bin"));
    std::fs::write(&torrent_path, &torrent_bytes).unwrap();
    let _ = std::fs::remove_file(&out);

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_rsurl"))
        .arg("--torrent")
        .arg("--bt-peer")
        .arg(format!("127.0.0.1:{src_port}"))
        .arg("--listen-port")
        .arg(listen_port.to_string())
        .arg("--share-ratio")
        .arg("1.0")
        .arg("-s")
        .arg("-o")
        .arg(&out)
        .arg(&torrent_path)
        .spawn()
        .expect("spawn rsurl");

    // Once the download finishes the binary starts listening; retry-connect.
    let mut c = None;
    for _ in 0..100 {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", listen_port)) {
            c = Some(s);
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    let mut c = c.expect("connect to seeding rsurl");
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();

    // Leech every piece to push the binary's upload ratio to 1.0.
    peer::write_handshake(&mut c, &Handshake::new(info_hash, [1u8; 20])).unwrap();
    let hs = peer::read_handshake(&mut c).unwrap();
    assert_eq!(hs.info_hash, info_hash);
    // First message is the seeder's bitfield.
    assert!(matches!(
        peer::read_message(&mut c).unwrap(),
        Message::Bitfield(_)
    ));
    peer::write_message(&mut c, &Message::Interested).unwrap();
    assert_eq!(peer::read_message(&mut c).unwrap(), Message::Unchoke);

    let mut got = vec![0u8; data.len()];
    for i in 0..num_pieces {
        let off = i * piece_len;
        let len = (piece_len).min(data.len() - off) as u32;
        peer::write_message(
            &mut c,
            &Message::Request {
                index: i as u32,
                begin: 0,
                length: len,
            },
        )
        .unwrap();
        match peer::read_message(&mut c).unwrap() {
            Message::Piece { index, block, .. } => {
                let o = index as usize * piece_len;
                got[o..o + block.len()].copy_from_slice(&block);
            }
            other => panic!("expected piece, got {other:?}"),
        }
    }
    assert_eq!(got, data, "leeched data mismatch");
    // Let any trailing bytes drain, then drop the connection.
    let _ = c.set_read_timeout(Some(Duration::from_millis(200)));
    let mut sink = [0u8; 64];
    let _ = c.read(&mut sink);
    drop(c);

    // The binary should reach ratio 1.0 and exit cleanly on its own.
    let status = child.wait().expect("wait rsurl");
    assert!(status.success(), "rsurl seeding exit: {status}");
    assert_eq!(std::fs::read(&out).unwrap(), data, "seed output mismatch");

    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&torrent_path);
}

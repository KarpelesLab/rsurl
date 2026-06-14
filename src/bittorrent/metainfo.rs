//! `.torrent` metainfo parsing (BEP 3) and infohash computation.

use std::path::{Path, PathBuf};

use purecrypto::hash::{Digest, Sha1};

use crate::error::{Error, Result};

use super::bencode::{self, Value};

fn terr(msg: &str) -> Error {
    Error::BadResponse(format!("torrent: {msg}"))
}

/// SHA-1 of `data` as a 20-byte array.
pub(crate) fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    let mut out = [0u8; 20];
    out.copy_from_slice(h.finalize().as_ref());
    out
}

/// One file within the torrent (single-file torrents have exactly one, whose
/// `path` is just the torrent name).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    /// Relative path under the download base (sanitized: no `..`, absolute, or
    /// separator components).
    pub path: PathBuf,
    pub length: u64,
}

/// Parsed `.torrent` metainfo plus the computed infohash.
#[derive(Debug, Clone)]
pub struct Metainfo {
    /// SHA-1 of the bencoded `info` dictionary (the swarm identifier).
    pub info_hash: [u8; 20],
    pub name: String,
    pub piece_length: u64,
    /// SHA-1 of each piece, in order.
    pub pieces: Vec<[u8; 20]>,
    /// Files in the order they tile the linear piece space.
    pub files: Vec<FileEntry>,
    pub total_length: u64,
    /// Tracker announce URLs (announce-list tiers flattened, plus `announce`).
    pub trackers: Vec<String>,
    pub private: bool,
}

impl Metainfo {
    /// Parse a `.torrent` from its raw bytes.
    pub fn from_bytes(torrent: &[u8]) -> Result<Metainfo> {
        let root = bencode::parse(torrent)?;

        // Hash the *original* bytes of the `info` value.
        let mut dec = bencode::Decoder::new(torrent);
        let spans = dec.dict_entry_spans()?;
        let info_range = spans
            .into_iter()
            .find(|(k, _)| k == b"info")
            .map(|(_, r)| r)
            .ok_or_else(|| terr("missing info dictionary"))?;
        let info_hash = sha1(&torrent[info_range]);

        let info = root
            .get(b"info")
            .ok_or_else(|| terr("missing info dictionary"))?;
        let name = info
            .get(b"name")
            .and_then(Value::as_str)
            .ok_or_else(|| terr("missing info.name"))?
            .to_string();
        // The torrent name is itself a path component (top dir / single file
        // name); reject anything that could escape the download base.
        sanitize_component(&name)?;

        let piece_length =
            info.get(b"piece length")
                .and_then(Value::as_int)
                .filter(|&n| n > 0)
                .ok_or_else(|| terr("missing/invalid info.piece length"))? as u64;

        let pieces_raw = info
            .get(b"pieces")
            .and_then(Value::as_bytes)
            .ok_or_else(|| terr("missing info.pieces"))?;
        if pieces_raw.is_empty() || pieces_raw.len() % 20 != 0 {
            return Err(terr("info.pieces is not a multiple of 20 bytes"));
        }
        let pieces: Vec<[u8; 20]> = pieces_raw
            .chunks_exact(20)
            .map(|c| {
                let mut a = [0u8; 20];
                a.copy_from_slice(c);
                a
            })
            .collect();

        // Single-file (`length`) vs multi-file (`files`).
        let (files, total_length) = if let Some(len) = info.get(b"length").and_then(Value::as_int) {
            if len < 0 {
                return Err(terr("negative file length"));
            }
            (
                vec![FileEntry {
                    path: PathBuf::from(&name),
                    length: len as u64,
                }],
                len as u64,
            )
        } else if let Some(list) = info.get(b"files").and_then(Value::as_list) {
            let mut files = Vec::with_capacity(list.len());
            let mut total: u64 = 0;
            for f in list {
                let len = f
                    .get(b"length")
                    .and_then(Value::as_int)
                    .filter(|&n| n >= 0)
                    .ok_or_else(|| terr("missing/invalid files[].length"))?
                    as u64;
                let comps = f
                    .get(b"path")
                    .and_then(Value::as_list)
                    .ok_or_else(|| terr("missing files[].path"))?;
                let mut rel = PathBuf::new();
                for c in comps {
                    let s = c.as_str().ok_or_else(|| terr("non-utf8 path component"))?;
                    sanitize_component(s)?;
                    rel.push(s);
                }
                if rel.as_os_str().is_empty() {
                    return Err(terr("empty file path"));
                }
                // Files live under the torrent's name directory.
                let path = Path::new(&name).join(rel);
                total = total
                    .checked_add(len)
                    .ok_or_else(|| terr("total length overflow"))?;
                files.push(FileEntry { path, length: len });
            }
            if files.is_empty() {
                return Err(terr("empty files list"));
            }
            (files, total)
        } else {
            return Err(terr("info has neither length nor files"));
        };

        // The piece table must cover exactly the data.
        let expected_pieces = total_length.div_ceil(piece_length).max(1) as usize;
        if total_length > 0 && pieces.len() != expected_pieces {
            return Err(terr("piece count does not match total length"));
        }

        // Trackers: announce-list (list of tiers) flattened, then announce.
        let mut trackers = Vec::new();
        if let Some(tiers) = root.get(b"announce-list").and_then(Value::as_list) {
            for tier in tiers {
                if let Some(list) = tier.as_list() {
                    for t in list {
                        if let Some(s) = t.as_str() {
                            trackers.push(s.to_string());
                        }
                    }
                }
            }
        }
        if let Some(a) = root.get(b"announce").and_then(Value::as_str) {
            if !trackers.iter().any(|t| t == a) {
                trackers.push(a.to_string());
            }
        }

        let private = info.get(b"private").and_then(Value::as_int) == Some(1);

        Ok(Metainfo {
            info_hash,
            name,
            piece_length,
            pieces,
            files,
            total_length,
            trackers,
            private,
        })
    }

    pub fn num_pieces(&self) -> usize {
        self.pieces.len()
    }

    /// Byte length of piece `index` (the last piece may be short).
    pub fn piece_size(&self, index: usize) -> u64 {
        if index + 1 < self.pieces.len() {
            self.piece_length
        } else {
            // Last piece.
            let before = self.piece_length * index as u64;
            self.total_length.saturating_sub(before)
        }
    }
}

/// Reject a path component that could escape the download directory.
fn sanitize_component(s: &str) -> Result<()> {
    if s.is_empty()
        || s == "."
        || s == ".."
        || s.contains('/')
        || s.contains('\\')
        || s.contains('\0')
    {
        return Err(terr("unsafe path component"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Build a minimal single-file torrent and the infohash we expect (SHA-1 of
    /// the encoded `info` dict).
    fn single_file_torrent() -> (Vec<u8>, [u8; 20]) {
        let mut info = BTreeMap::new();
        info.insert(b"name".to_vec(), Value::Bytes(b"hello.txt".to_vec()));
        info.insert(b"piece length".to_vec(), Value::Int(16384));
        info.insert(b"length".to_vec(), Value::Int(10));
        info.insert(b"pieces".to_vec(), Value::Bytes(vec![0u8; 20]));
        let info_val = Value::Dict(info);
        let expected = sha1(&bencode::encode(&info_val));

        let mut root = BTreeMap::new();
        root.insert(
            b"announce".to_vec(),
            Value::Bytes(b"http://t/announce".to_vec()),
        );
        root.insert(b"info".to_vec(), info_val);
        (bencode::encode(&Value::Dict(root)), expected)
    }

    #[test]
    fn parses_single_file_and_infohash() {
        let (bytes, expected_hash) = single_file_torrent();
        let m = Metainfo::from_bytes(&bytes).unwrap();
        assert_eq!(m.info_hash, expected_hash);
        assert_eq!(m.name, "hello.txt");
        assert_eq!(m.piece_length, 16384);
        assert_eq!(m.total_length, 10);
        assert_eq!(m.files.len(), 1);
        assert_eq!(m.files[0].path, PathBuf::from("hello.txt"));
        assert_eq!(m.num_pieces(), 1);
        assert_eq!(m.piece_size(0), 10);
        assert_eq!(m.trackers, vec!["http://t/announce".to_string()]);
    }

    #[test]
    fn parses_multi_file() {
        let mut info = BTreeMap::new();
        info.insert(b"name".to_vec(), Value::Bytes(b"dir".to_vec()));
        info.insert(b"piece length".to_vec(), Value::Int(4));
        info.insert(b"pieces".to_vec(), Value::Bytes(vec![0u8; 40])); // 2 pieces
        let mkfile = |len: i64, parts: &[&str]| {
            let mut f = BTreeMap::new();
            f.insert(b"length".to_vec(), Value::Int(len));
            f.insert(
                b"path".to_vec(),
                Value::List(
                    parts
                        .iter()
                        .map(|p| Value::Bytes(p.as_bytes().to_vec()))
                        .collect(),
                ),
            );
            Value::Dict(f)
        };
        info.insert(
            b"files".to_vec(),
            Value::List(vec![mkfile(5, &["a.txt"]), mkfile(3, &["sub", "b.txt"])]),
        );
        let mut root = BTreeMap::new();
        root.insert(b"info".to_vec(), Value::Dict(info));
        let bytes = bencode::encode(&Value::Dict(root));

        let m = Metainfo::from_bytes(&bytes).unwrap();
        assert_eq!(m.total_length, 8);
        assert_eq!(m.files.len(), 2);
        assert_eq!(m.files[0].path, PathBuf::from("dir/a.txt"));
        assert_eq!(m.files[1].path, PathBuf::from("dir/sub/b.txt"));
        assert_eq!(m.num_pieces(), 2);
        assert_eq!(m.piece_size(0), 4);
        assert_eq!(m.piece_size(1), 4);
    }

    #[test]
    fn rejects_path_traversal() {
        let mut info = BTreeMap::new();
        info.insert(b"name".to_vec(), Value::Bytes(b"dir".to_vec()));
        info.insert(b"piece length".to_vec(), Value::Int(4));
        info.insert(b"pieces".to_vec(), Value::Bytes(vec![0u8; 20]));
        let mut f = BTreeMap::new();
        f.insert(b"length".to_vec(), Value::Int(1));
        f.insert(
            b"path".to_vec(),
            Value::List(vec![
                Value::Bytes(b"..".to_vec()),
                Value::Bytes(b"etc".to_vec()),
            ]),
        );
        info.insert(b"files".to_vec(), Value::List(vec![Value::Dict(f)]));
        let mut root = BTreeMap::new();
        root.insert(b"info".to_vec(), Value::Dict(info));
        let bytes = bencode::encode(&Value::Dict(root));
        assert!(Metainfo::from_bytes(&bytes).is_err());
    }
}

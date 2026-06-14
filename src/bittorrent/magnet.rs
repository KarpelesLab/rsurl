//! Magnet link parsing (BEP 9 `xt=urn:btih:`).
//!
//! `magnet:?xt=urn:btih:<40-hex|32-base32>&dn=<name>&tr=<tracker>&x.pe=<ip:port>`

use std::net::SocketAddr;

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Magnet {
    /// BitTorrent v1 infohash (SHA-1, 20 bytes).
    pub info_hash: [u8; 20],
    pub display_name: Option<String>,
    pub trackers: Vec<String>,
    /// Peers from `x.pe=` (direct peer addresses).
    pub peers: Vec<SocketAddr>,
}

fn merr(msg: &str) -> Error {
    Error::InvalidUrl(format!("magnet: {msg}"))
}

impl Magnet {
    pub fn parse(s: &str) -> Result<Magnet> {
        let query = s
            .strip_prefix("magnet:?")
            .ok_or_else(|| merr("not a magnet link"))?;

        let mut info_hash: Option<[u8; 20]> = None;
        let mut display_name = None;
        let mut trackers = Vec::new();
        let mut peers = Vec::new();

        for pair in query.split('&') {
            let (key, val) = match pair.split_once('=') {
                Some(kv) => kv,
                None => continue,
            };
            let val = percent_decode(val);
            match key {
                "xt" => {
                    if let Some(ih) = val.strip_prefix("urn:btih:") {
                        info_hash = Some(parse_infohash(ih)?);
                    }
                    // urn:btmh: (v2) is intentionally unsupported.
                }
                "dn" => display_name = Some(val),
                "tr" => trackers.push(val),
                "x.pe" => {
                    if let Ok(addr) = val.parse::<SocketAddr>() {
                        peers.push(addr);
                    }
                }
                _ => {}
            }
        }

        let info_hash = info_hash.ok_or_else(|| merr("missing or unsupported xt=urn:btih:"))?;
        Ok(Magnet {
            info_hash,
            display_name,
            trackers,
            peers,
        })
    }
}

/// Parse a btih value: 40 hex chars or 32 base32 chars → 20 bytes.
fn parse_infohash(s: &str) -> Result<[u8; 20]> {
    match s.len() {
        40 => hex_decode(s),
        32 => base32_decode(s),
        _ => Err(merr("infohash must be 40 hex or 32 base32 chars")),
    }
}

fn hex_decode(s: &str) -> Result<[u8; 20]> {
    let b = s.as_bytes();
    let mut out = [0u8; 20];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_val(b[i * 2]).ok_or_else(|| merr("bad hex infohash"))?;
        let lo = hex_val(b[i * 2 + 1]).ok_or_else(|| merr("bad hex infohash"))?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// RFC 4648 base32 of exactly 32 chars → 20 bytes (no padding).
fn base32_decode(s: &str) -> Result<[u8; 20]> {
    let mut acc: u64 = 0;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(20);
    for c in s.bytes() {
        let v = base32_val(c).ok_or_else(|| merr("bad base32 infohash"))?;
        acc = (acc << 5) | v as u64;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if out.len() != 20 {
        return Err(merr("base32 infohash wrong length"));
    }
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&out);
    Ok(arr)
}

fn base32_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a'),
        b'2'..=b'7' => Some(c - b'2' + 26),
        _ => None,
    }
}

/// Decode `%HH` escapes (and `+` → space, as magnet query values are
/// form-encoded in practice). Invalid escapes pass through verbatim.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                if let (Some(h), Some(l)) = (hex_val(b[i + 1]), hex_val(b[i + 2])) {
                    out.push((h << 4) | l);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn parses_hex_magnet_with_trackers() {
        let m = Magnet::parse(&format!(
            "magnet:?xt=urn:btih:{HEX}&dn=My+File&tr=http%3A%2F%2Ftracker%2Fannounce&tr=udp%3A%2F%2Ft2%3A80"
        ))
        .unwrap();
        assert_eq!(m.info_hash[0], 0x01);
        assert_eq!(m.info_hash[19], 0x67);
        assert_eq!(m.display_name.as_deref(), Some("My File"));
        assert_eq!(
            m.trackers,
            vec![
                "http://tracker/announce".to_string(),
                "udp://t2:80".to_string()
            ]
        );
    }

    #[test]
    fn hex_and_base32_agree() {
        // base32 of the same 20 bytes as HEX.
        let hexm = Magnet::parse(&format!("magnet:?xt=urn:btih:{HEX}")).unwrap();
        // Encode hexm.info_hash to base32 and round-trip.
        let b32 = to_base32(&hexm.info_hash);
        assert_eq!(b32.len(), 32);
        let b32m = Magnet::parse(&format!("magnet:?xt=urn:btih:{b32}")).unwrap();
        assert_eq!(hexm.info_hash, b32m.info_hash);
    }

    #[test]
    fn parses_peer_addresses() {
        let m = Magnet::parse(&format!("magnet:?xt=urn:btih:{HEX}&x.pe=1.2.3.4%3A6881")).unwrap();
        assert_eq!(m.peers, vec!["1.2.3.4:6881".parse().unwrap()]);
    }

    #[test]
    fn rejects_bad() {
        assert!(Magnet::parse("http://x/").is_err());
        assert!(Magnet::parse("magnet:?dn=x").is_err()); // no xt
        assert!(Magnet::parse("magnet:?xt=urn:btih:zz").is_err()); // bad length
    }

    fn to_base32(bytes: &[u8]) -> String {
        const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut acc: u64 = 0;
        let mut bits = 0u32;
        let mut out = String::new();
        for &b in bytes {
            acc = (acc << 8) | b as u64;
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(A[((acc >> bits) & 0x1f) as usize] as char);
            }
        }
        if bits > 0 {
            out.push(A[((acc << (5 - bits)) & 0x1f) as usize] as char);
        }
        out
    }
}

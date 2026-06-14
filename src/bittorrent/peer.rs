//! Peer wire protocol (BEP 3) framing + handshake, plus the BEP 10 extension
//! message used later for magnet metadata.

use std::io::{Read, Write};

use crate::error::{Error, Result};

/// Protocol identifier string sent in the handshake.
pub const PSTR: &[u8] = b"BitTorrent protocol";

/// Block size used for `request` (BEP 3 recommends 16 KiB).
pub const BLOCK_SIZE: u32 = 16 * 1024;

/// Largest message payload we will accept, bounding allocation on hostile
/// input (a piece block plus generous slack).
const MAX_MSG_PAYLOAD: usize = 1 << 20;

fn perr(msg: impl Into<String>) -> Error {
    Error::BadResponse(format!("bt peer: {}", msg.into()))
}

/// The 68-byte BitTorrent handshake.
#[derive(Debug, Clone)]
pub struct Handshake {
    pub reserved: [u8; 8],
    pub info_hash: [u8; 20],
    pub peer_id: [u8; 20],
}

impl Handshake {
    /// A handshake advertising the BEP 10 extension protocol (reserved bit
    /// 0x10 in byte 5), which is harmless to peers that don't support it.
    pub fn new(info_hash: [u8; 20], peer_id: [u8; 20]) -> Self {
        let mut reserved = [0u8; 8];
        reserved[5] |= 0x10; // extension protocol (BEP 10)
        Handshake {
            reserved,
            info_hash,
            peer_id,
        }
    }

    /// Whether the peer advertised BEP 10 extension support.
    pub fn supports_extensions(&self) -> bool {
        self.reserved[5] & 0x10 != 0
    }

    fn to_bytes(&self) -> [u8; 68] {
        let mut b = [0u8; 68];
        b[0] = PSTR.len() as u8;
        b[1..20].copy_from_slice(PSTR);
        b[20..28].copy_from_slice(&self.reserved);
        b[28..48].copy_from_slice(&self.info_hash);
        b[48..68].copy_from_slice(&self.peer_id);
        b
    }
}

pub fn write_handshake<W: Write>(w: &mut W, h: &Handshake) -> Result<()> {
    w.write_all(&h.to_bytes()).map_err(Error::Io)?;
    w.flush().map_err(Error::Io)
}

pub fn read_handshake<R: Read>(r: &mut R) -> Result<Handshake> {
    let mut b = [0u8; 68];
    read_exact(r, &mut b)?;
    if b[0] as usize != PSTR.len() || &b[1..20] != PSTR {
        return Err(perr("bad protocol header"));
    }
    let mut reserved = [0u8; 8];
    reserved.copy_from_slice(&b[20..28]);
    let mut info_hash = [0u8; 20];
    info_hash.copy_from_slice(&b[28..48]);
    let mut peer_id = [0u8; 20];
    peer_id.copy_from_slice(&b[48..68]);
    Ok(Handshake {
        reserved,
        info_hash,
        peer_id,
    })
}

/// A peer wire message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    KeepAlive,
    Choke,
    Unchoke,
    Interested,
    NotInterested,
    Have(u32),
    Bitfield(Vec<u8>),
    Request {
        index: u32,
        begin: u32,
        length: u32,
    },
    Piece {
        index: u32,
        begin: u32,
        block: Vec<u8>,
    },
    Cancel {
        index: u32,
        begin: u32,
        length: u32,
    },
    Port(u16),
    /// BEP 10 extension message: extended id (0 = handshake) + bencoded/raw payload.
    Extended {
        ext_id: u8,
        payload: Vec<u8>,
    },
}

const ID_CHOKE: u8 = 0;
const ID_UNCHOKE: u8 = 1;
const ID_INTERESTED: u8 = 2;
const ID_NOT_INTERESTED: u8 = 3;
const ID_HAVE: u8 = 4;
const ID_BITFIELD: u8 = 5;
const ID_REQUEST: u8 = 6;
const ID_PIECE: u8 = 7;
const ID_CANCEL: u8 = 8;
const ID_PORT: u8 = 9;
const ID_EXTENDED: u8 = 20;

pub fn read_message<R: Read>(r: &mut R) -> Result<Message> {
    let mut len_buf = [0u8; 4];
    read_exact(r, &mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Ok(Message::KeepAlive);
    }
    if len > MAX_MSG_PAYLOAD {
        return Err(perr(format!("message too large: {len}")));
    }
    let mut body = vec![0u8; len];
    read_exact(r, &mut body)?;
    let id = body[0];
    let payload = &body[1..];
    let msg = match id {
        ID_CHOKE => Message::Choke,
        ID_UNCHOKE => Message::Unchoke,
        ID_INTERESTED => Message::Interested,
        ID_NOT_INTERESTED => Message::NotInterested,
        ID_HAVE => Message::Have(be32(payload)?),
        ID_BITFIELD => Message::Bitfield(payload.to_vec()),
        ID_REQUEST => {
            let (i, b, l) = three_be32(payload)?;
            Message::Request {
                index: i,
                begin: b,
                length: l,
            }
        }
        ID_PIECE => {
            if payload.len() < 8 {
                return Err(perr("short piece message"));
            }
            Message::Piece {
                index: u32::from_be_bytes(payload[0..4].try_into().unwrap()),
                begin: u32::from_be_bytes(payload[4..8].try_into().unwrap()),
                block: payload[8..].to_vec(),
            }
        }
        ID_CANCEL => {
            let (i, b, l) = three_be32(payload)?;
            Message::Cancel {
                index: i,
                begin: b,
                length: l,
            }
        }
        ID_PORT => {
            if payload.len() < 2 {
                return Err(perr("short port message"));
            }
            Message::Port(u16::from_be_bytes([payload[0], payload[1]]))
        }
        ID_EXTENDED => {
            if payload.is_empty() {
                return Err(perr("empty extended message"));
            }
            Message::Extended {
                ext_id: payload[0],
                payload: payload[1..].to_vec(),
            }
        }
        other => return Err(perr(format!("unknown message id {other}"))),
    };
    Ok(msg)
}

pub fn write_message<W: Write>(w: &mut W, msg: &Message) -> Result<()> {
    let mut buf = Vec::new();
    match msg {
        Message::KeepAlive => buf.extend_from_slice(&0u32.to_be_bytes()),
        Message::Choke => frame(&mut buf, ID_CHOKE, &[]),
        Message::Unchoke => frame(&mut buf, ID_UNCHOKE, &[]),
        Message::Interested => frame(&mut buf, ID_INTERESTED, &[]),
        Message::NotInterested => frame(&mut buf, ID_NOT_INTERESTED, &[]),
        Message::Have(i) => frame(&mut buf, ID_HAVE, &i.to_be_bytes()),
        Message::Bitfield(b) => frame(&mut buf, ID_BITFIELD, b),
        Message::Request {
            index,
            begin,
            length,
        } => frame(&mut buf, ID_REQUEST, &three(*index, *begin, *length)),
        Message::Piece {
            index,
            begin,
            block,
        } => {
            let mut p = Vec::with_capacity(8 + block.len());
            p.extend_from_slice(&index.to_be_bytes());
            p.extend_from_slice(&begin.to_be_bytes());
            p.extend_from_slice(block);
            frame(&mut buf, ID_PIECE, &p);
        }
        Message::Cancel {
            index,
            begin,
            length,
        } => frame(&mut buf, ID_CANCEL, &three(*index, *begin, *length)),
        Message::Port(p) => frame(&mut buf, ID_PORT, &p.to_be_bytes()),
        Message::Extended { ext_id, payload } => {
            let mut p = Vec::with_capacity(1 + payload.len());
            p.push(*ext_id);
            p.extend_from_slice(payload);
            frame(&mut buf, ID_EXTENDED, &p);
        }
    }
    w.write_all(&buf).map_err(Error::Io)?;
    w.flush().map_err(Error::Io)
}

fn frame(buf: &mut Vec<u8>, id: u8, payload: &[u8]) {
    let len = 1 + payload.len();
    buf.extend_from_slice(&(len as u32).to_be_bytes());
    buf.push(id);
    buf.extend_from_slice(payload);
}

fn three(a: u32, b: u32, c: u32) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0..4].copy_from_slice(&a.to_be_bytes());
    out[4..8].copy_from_slice(&b.to_be_bytes());
    out[8..12].copy_from_slice(&c.to_be_bytes());
    out
}

fn be32(p: &[u8]) -> Result<u32> {
    if p.len() < 4 {
        return Err(perr("short u32 payload"));
    }
    Ok(u32::from_be_bytes(p[0..4].try_into().unwrap()))
}

fn three_be32(p: &[u8]) -> Result<(u32, u32, u32)> {
    if p.len() < 12 {
        return Err(perr("short request/cancel payload"));
    }
    Ok((
        u32::from_be_bytes(p[0..4].try_into().unwrap()),
        u32::from_be_bytes(p[4..8].try_into().unwrap()),
        u32::from_be_bytes(p[8..12].try_into().unwrap()),
    ))
}

fn read_exact<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<()> {
    r.read_exact(buf).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            Error::UnexpectedEof
        } else {
            Error::Io(e)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn handshake_round_trip() {
        let h = Handshake::new([7u8; 20], [9u8; 20]);
        assert!(h.supports_extensions());
        let mut buf = Vec::new();
        write_handshake(&mut buf, &h).unwrap();
        assert_eq!(buf.len(), 68);
        let back = read_handshake(&mut Cursor::new(buf)).unwrap();
        assert_eq!(back.info_hash, [7u8; 20]);
        assert_eq!(back.peer_id, [9u8; 20]);
        assert!(back.supports_extensions());
    }

    #[test]
    fn messages_round_trip() {
        let cases = [
            Message::KeepAlive,
            Message::Choke,
            Message::Unchoke,
            Message::Interested,
            Message::NotInterested,
            Message::Have(123),
            Message::Bitfield(vec![0xff, 0x0f]),
            Message::Request {
                index: 1,
                begin: 16384,
                length: 16384,
            },
            Message::Piece {
                index: 2,
                begin: 0,
                block: vec![1, 2, 3, 4],
            },
            Message::Cancel {
                index: 3,
                begin: 8,
                length: 9,
            },
            Message::Port(6881),
            Message::Extended {
                ext_id: 0,
                payload: b"d1:md11:ut_metadatai1eee".to_vec(),
            },
        ];
        for m in cases {
            let mut buf = Vec::new();
            write_message(&mut buf, &m).unwrap();
            let back = read_message(&mut Cursor::new(buf)).unwrap();
            assert_eq!(back, m);
        }
    }

    #[test]
    fn rejects_oversized_message() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&((MAX_MSG_PAYLOAD as u32) + 1).to_be_bytes());
        assert!(read_message(&mut Cursor::new(buf)).is_err());
    }
}

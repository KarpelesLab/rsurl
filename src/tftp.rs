//! TFTP support (RFC 1350, plus RFC 2347 option extension, RFC 2348 blksize,
//! RFC 2349 timeout/tsize).
//!
//! TFTP runs over UDP, default port 69. URL: `tftp://host/path`. Default
//! operation is a read (RRQ) of `url.path` in octet mode, reassembling
//! 512-byte (or negotiated) blocks until a short block signals end.
//!
//! Both the read side (RRQ) and the write side (WRQ) are implemented. Option
//! negotiation (RFC 2347) is not done; we send a plain RRQ/WRQ in `octet` mode,
//! accept 512-byte DATA blocks on read, and send 512-byte DATA blocks on write
//! (a short final block — possibly empty — terminates the upload).

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};

use crate::net::udp::open_udp_transport;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::url::Url;

/// TFTP opcodes (RFC 1350 §5).
const OP_RRQ: u16 = 1;
const OP_WRQ: u16 = 2;
const OP_DATA: u16 = 3;
const OP_ACK: u16 = 4;
const OP_ERROR: u16 = 5;

/// Default TFTP block size (RFC 1350).
const BLOCK_SIZE: usize = 512;

/// Per-packet receive timeout. Matches typical TFTP client behaviour.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Number of times we resend the last packet on timeout before giving up.
const MAX_RETRIES: u32 = 3;

/// Hard wall-clock ceiling on a whole transfer. The per-packet `READ_TIMEOUT`
/// alone can't stop a server that dribbles one valid packet every few seconds
/// indefinitely, so we also cap the total elapsed time and bail past it.
const MAX_TOTAL_DURATION: Duration = Duration::from_secs(600);

/// Hard upper bound on a single transfer (256 MiB). TFTP has no built-in
/// length so we cap to avoid runaway allocation against a hostile server.
const MAX_TOTAL_BYTES: usize = 256 * 1024 * 1024;

/// Result of parsing one DATA packet's header. `data` borrows from the input.
#[derive(Debug, PartialEq, Eq)]
struct DataPacket<'a> {
    block: u16,
    data: &'a [u8],
}

/// Build a request packet for the given opcode (RRQ or WRQ):
/// `<2-byte opcode><filename>\x00octet\x00`.
fn build_request(opcode: u16, filename: &str) -> Vec<u8> {
    let mut p = Vec::with_capacity(2 + filename.len() + 1 + 5 + 1);
    p.extend_from_slice(&opcode.to_be_bytes());
    p.extend_from_slice(filename.as_bytes());
    p.push(0);
    p.extend_from_slice(b"octet");
    p.push(0);
    p
}

/// Build a Read Request packet:
/// `\x00\x01<filename>\x00octet\x00`.
fn build_rrq(filename: &str) -> Vec<u8> {
    build_request(OP_RRQ, filename)
}

/// Build a Write Request packet:
/// `\x00\x02<filename>\x00octet\x00`.
fn build_wrq(filename: &str) -> Vec<u8> {
    build_request(OP_WRQ, filename)
}

/// Build a DATA packet: `\x00\x03<2-byte block#><payload>`.
fn build_data(block: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(4 + payload.len());
    p.extend_from_slice(&OP_DATA.to_be_bytes());
    p.extend_from_slice(&block.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

/// Build an ACK packet: `\x00\x04<2-byte block#>`.
fn build_ack(block: u16) -> [u8; 4] {
    let mut p = [0u8; 4];
    p[0..2].copy_from_slice(&OP_ACK.to_be_bytes());
    p[2..4].copy_from_slice(&block.to_be_bytes());
    p
}

/// Parse the opcode at the start of a packet, returning `None` if too short.
fn parse_opcode(buf: &[u8]) -> Option<u16> {
    if buf.len() < 2 {
        return None;
    }
    Some(u16::from_be_bytes([buf[0], buf[1]]))
}

/// Parse a DATA packet (opcode 3). Returns the block number and a slice
/// pointing into `buf` for the payload bytes.
fn parse_data(buf: &[u8]) -> Result<DataPacket<'_>> {
    if buf.len() < 4 {
        return Err(Error::BadResponse("tftp: short DATA packet".into()));
    }
    if parse_opcode(buf) != Some(OP_DATA) {
        return Err(Error::BadResponse("tftp: not a DATA packet".into()));
    }
    let block = u16::from_be_bytes([buf[2], buf[3]]);
    Ok(DataPacket {
        block,
        data: &buf[4..],
    })
}

/// Parse an ACK packet (opcode 4). Returns the acknowledged block number.
fn parse_ack(buf: &[u8]) -> Result<u16> {
    if buf.len() < 4 {
        return Err(Error::BadResponse("tftp: short ACK packet".into()));
    }
    if parse_opcode(buf) != Some(OP_ACK) {
        return Err(Error::BadResponse("tftp: not an ACK packet".into()));
    }
    Ok(u16::from_be_bytes([buf[2], buf[3]]))
}

/// Parse an ERROR packet (opcode 5). Returns the human-readable message
/// (trimmed of the trailing NUL if present). The error code itself is
/// discarded; the message is what users want to see.
fn parse_error(buf: &[u8]) -> Result<String> {
    if buf.len() < 4 {
        return Err(Error::BadResponse("tftp: short ERROR packet".into()));
    }
    if parse_opcode(buf) != Some(OP_ERROR) {
        return Err(Error::BadResponse("tftp: not an ERROR packet".into()));
    }
    // bytes [2..4] are the error code, then a NUL-terminated message.
    let msg_bytes = &buf[4..];
    let end = msg_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(msg_bytes.len());
    Ok(String::from_utf8_lossy(&msg_bytes[..end]).into_owned())
}

/// Resolve `host:port` to the first usable socket address.
fn resolve(host: &str, port: u16) -> Result<SocketAddr> {
    (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| Error::BadResponse(format!("tftp: cannot resolve {host}:{port}")))
}

/// Extract and validate the TFTP filename from `url.path`.
///
/// Strips the leading '/' to get the TFTP filename. Anything past a '?' (a
/// query, which TFTP doesn't actually have) is left in place — TFTP servers
/// will just see it as part of the filename. Rejects an empty filename or one
/// containing a NUL (which would corrupt the request packet's framing).
fn filename_of(url: &Url) -> Result<&str> {
    let filename = url.path.strip_prefix('/').unwrap_or(&url.path);
    if filename.is_empty() {
        return Err(Error::InvalidUrl(format!(
            "tftp: empty filename in {}://{}/{}",
            url.scheme, url.host, url.path
        )));
    }
    if filename.as_bytes().contains(&0) {
        return Err(Error::InvalidUrl("tftp: filename contains NUL".into()));
    }
    Ok(filename)
}

/// RRQ the file at `url.path` and return the reassembled bytes.
pub fn fetch(url: &Url) -> Result<Vec<u8>> {
    fetch_with(url, &crate::net::NetConfig::default())
}

/// Download over TFTP. A direct UDP socket by default; through a SOCKS5 proxy
/// when the connector is one (UDP ASSOCIATE). A non-UDP-capable proxy
/// (http/https/socks4) is rejected. The TID-latching/validation below keys on
/// the *decapsulated* peer that `recv_from` returns, so spoof protection and
/// the legitimate mid-transfer TID port-switch both keep working.
pub(crate) fn fetch_with(url: &Url, cfg: &crate::net::NetConfig) -> Result<Vec<u8>> {
    let filename = filename_of(url)?;

    let server = resolve(&url.host, url.port)?;
    let socket = open_udp_transport(cfg.connector.udp_proxy(), server)?;
    socket.set_read_timeout(Some(READ_TIMEOUT))?;

    let rrq = build_rrq(filename);

    // After the first DATA arrives, the server picks a fresh ephemeral port
    // (the TID) and all subsequent traffic uses it. We track it here.
    let mut peer: Option<SocketAddr> = None;

    let mut out: Vec<u8> = Vec::new();
    let mut expected_block: u16 = 1;
    // Buffer big enough for the largest DATA packet we might see (4 header
    // bytes + 512 payload). A small extra margin doesn't hurt.
    let mut buf = [0u8; 4 + BLOCK_SIZE + 16];

    // Send the RRQ with retries, then enter the data loop. After we ACK each
    // DATA, that ACK becomes the new "last packet" we'd retransmit on timeout.
    let mut last_packet: Vec<u8> = rrq;
    let mut last_dest: SocketAddr = server;

    socket.send_to(&last_packet, last_dest)?;
    let mut retries: u32 = 0;
    let deadline = Instant::now() + MAX_TOTAL_DURATION;

    loop {
        if Instant::now() >= deadline {
            return Err(Error::BadResponse(format!(
                "tftp: transfer exceeded {}s deadline",
                MAX_TOTAL_DURATION.as_secs()
            )));
        }
        let (n, from) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) => {
                // WouldBlock / TimedOut from set_read_timeout.
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) {
                    if retries >= MAX_RETRIES {
                        return Err(Error::UnexpectedEof);
                    }
                    retries += 1;
                    socket.send_to(&last_packet, last_dest)?;
                    continue;
                }
                return Err(Error::Io(e));
            }
        };

        // TID handling (RFC 1350 §4: "If a source TID does not match, the
        // packet should be discarded as erroneously sent from somewhere
        // else"). Once we've latched the server's TID we accept only that
        // exact peer. Before latching, the TID *cannot* be validated — the
        // server replies from a fresh ephemeral port we don't know yet — so
        // the first reply is only IP-filtered: its source IP must match the
        // host we sent the RRQ to, but its source port will differ.
        if let Some(p) = peer {
            if from != p {
                continue;
            }
        } else if from.ip() != server.ip() {
            continue;
        }

        let pkt = &buf[..n];
        match parse_opcode(pkt) {
            Some(OP_DATA) => {
                let data = parse_data(pkt)?;

                if data.block != expected_block {
                    // Either a duplicate of an already-acked block (re-ack
                    // it so the sender unblocks) or out-of-order garbage we
                    // ignore. Re-acking an old block is harmless — but only
                    // once the TID is latched: before that, `from` is an
                    // unvalidated (IP-filtered only) source and we must not
                    // emit a reply to it. Send the re-ACK to the latched peer.
                    if let Some(p) = peer {
                        if data.block.wrapping_add(1) == expected_block {
                            let ack = build_ack(data.block);
                            socket.send_to(&ack, p)?;
                        }
                    }
                    continue;
                }

                // Latch onto this peer's TID on the first valid DATA.
                if peer.is_none() {
                    peer = Some(from);
                }

                if out.len() + data.data.len() > MAX_TOTAL_BYTES {
                    return Err(Error::BadResponse(format!(
                        "tftp: transfer exceeds {} bytes",
                        MAX_TOTAL_BYTES
                    )));
                }
                out.extend_from_slice(data.data);

                let ack = build_ack(data.block);
                socket.send_to(&ack, from)?;

                let is_last = data.data.len() < BLOCK_SIZE;
                if is_last {
                    return Ok(out);
                }

                // Prepare to retransmit this ACK if the next DATA times out.
                last_packet = ack.to_vec();
                last_dest = from;
                retries = 0;

                // u16 wrap: 65535 -> 0 is permitted by common TFTP usage,
                // but for safety we explicitly bail rather than risk an
                // ambiguous loop. (A 256 MiB cap means a 512-byte block
                // stream can need block numbers up to ~524288, which does
                // wrap once. Punt as documented in the spec.)
                expected_block = match expected_block.checked_add(1) {
                    Some(b) => b,
                    None => {
                        return Err(Error::BadResponse(
                            "tftp: block number wrapped; refusing oversized transfer".into(),
                        ));
                    }
                };
            }
            Some(OP_ERROR) => {
                let msg = parse_error(pkt)?;
                return Err(Error::BadResponse(format!("tftp: {msg}")));
            }
            Some(op) => {
                return Err(Error::BadResponse(format!("tftp: unexpected opcode {op}")));
            }
            None => {
                return Err(Error::BadResponse("tftp: packet too short".into()));
            }
        }
    }
}

/// WRQ-upload `data` to the file at `url.path`.
///
/// Sends a Write Request, waits for the server's ACK of block 0 (latching its
/// TID exactly as the read path does), then drives a lockstep DATA/ACK loop:
/// send DATA block N, wait for ACK N (retransmitting on timeout), advance. A
/// final block shorter than `BLOCK_SIZE` — possibly empty when `data` is an
/// exact multiple of 512 — terminates the transfer per RFC 1350 §6.
pub fn store(url: &Url, data: &[u8]) -> Result<()> {
    let filename = filename_of(url)?;

    // Cap uploads at the same ceiling as downloads. TFTP block numbers are a
    // u16, so a 512-byte stream can address at most 65535 blocks before the
    // first wrap; the 256 MiB cap stays well within a single wrap.
    if data.len() > MAX_TOTAL_BYTES {
        return Err(Error::BadResponse(format!(
            "tftp: upload exceeds {MAX_TOTAL_BYTES} bytes"
        )));
    }

    let server = resolve(&url.host, url.port)?;
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(READ_TIMEOUT))?;

    let wrq = build_wrq(filename);

    // The server picks a fresh ephemeral port (its TID) for its first reply
    // (ACK 0 or, if it negotiated options we didn't ask for, an OACK). We latch
    // that port from the first valid reply and reject anything from elsewhere.
    let mut peer: Option<SocketAddr> = None;

    let mut buf = [0u8; 4 + BLOCK_SIZE + 16];

    // The packet we retransmit on timeout, and where we send it. We start by
    // (re)sending the WRQ to the server's well-known port; once we've latched
    // the peer TID, retransmits target that instead.
    let mut last_packet: Vec<u8> = wrq;
    let mut last_dest: SocketAddr = server;

    socket.send_to(&last_packet, last_dest)?;
    let mut retries: u32 = 0;
    let deadline = Instant::now() + MAX_TOTAL_DURATION;

    // `block` is the block number we're currently waiting to have ACKed. While
    // we're still waiting for ACK 0 (the WRQ's acknowledgement) `block` is 0 and
    // `payload_start` is 0 (no payload sent yet). After ACK 0 we send block 1,
    // and so on. `sent_final` records that we've transmitted the short final
    // block, so the matching ACK ends the transfer.
    let mut block: u16 = 0;
    // Offset into `data` of the block we last sent (only meaningful once
    // `block >= 1`).
    let mut sent_offset: usize = 0;
    let mut sent_final = false;

    loop {
        if Instant::now() >= deadline {
            return Err(Error::BadResponse(format!(
                "tftp: transfer exceeded {}s deadline",
                MAX_TOTAL_DURATION.as_secs()
            )));
        }
        let (n, from) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) => {
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) {
                    if retries >= MAX_RETRIES {
                        return Err(Error::UnexpectedEof);
                    }
                    retries += 1;
                    socket.send_to(&last_packet, last_dest)?;
                    continue;
                }
                return Err(Error::Io(e));
            }
        };

        // TID validation, mirroring the read path: once latched, only the
        // peer's exact TID is accepted. Before latching, the TID cannot be
        // validated (the server replies from a fresh ephemeral port), so the
        // first reply is only IP-filtered: its source IP must match the host
        // we sent the WRQ to, but its source port will differ.
        if let Some(p) = peer {
            if from != p {
                continue;
            }
        } else if from.ip() != server.ip() {
            continue;
        }

        let pkt = &buf[..n];
        match parse_opcode(pkt) {
            Some(OP_ACK) => {
                let acked = parse_ack(pkt)?;

                // Ignore an ACK that doesn't acknowledge the block we're
                // waiting on. A stale/duplicate ACK (e.g. the server re-acking
                // block N-1) must not advance us, or we'd skip a block.
                if acked != block {
                    continue;
                }

                // Latch onto the peer's TID on the first valid reply.
                if peer.is_none() {
                    peer = Some(from);
                }

                // The final block has now been acknowledged: we're done.
                if sent_final {
                    return Ok(());
                }

                // Advance to the next block. After ACK 0 we've sent nothing
                // yet; otherwise step past the block we just sent.
                let next_offset = if block == 0 {
                    0
                } else {
                    sent_offset + BLOCK_SIZE
                };
                let next_block = match block.checked_add(1) {
                    Some(b) => b,
                    None => {
                        return Err(Error::BadResponse(
                            "tftp: block number wrapped; refusing oversized transfer".into(),
                        ));
                    }
                };

                let end = (next_offset + BLOCK_SIZE).min(data.len());
                let payload = &data[next_offset..end];
                let dgram = build_data(next_block, payload);
                socket.send_to(&dgram, from)?;

                block = next_block;
                sent_offset = next_offset;
                sent_final = payload.len() < BLOCK_SIZE;
                last_packet = dgram;
                last_dest = from;
                retries = 0;
            }
            Some(OP_ERROR) => {
                let msg = parse_error(pkt)?;
                return Err(Error::BadResponse(format!("tftp: {msg}")));
            }
            Some(op) => {
                return Err(Error::BadResponse(format!("tftp: unexpected opcode {op}")));
            }
            None => {
                return Err(Error::BadResponse("tftp: packet too short".into()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rrq_builds_in_octet_mode() {
        let p = build_rrq("hello.txt");
        // opcode 1, filename, 0, "octet", 0
        assert_eq!(p[0..2], [0x00, 0x01]);
        assert_eq!(&p[2..2 + b"hello.txt".len()], b"hello.txt");
        let after_name = 2 + b"hello.txt".len();
        assert_eq!(p[after_name], 0);
        assert_eq!(&p[after_name + 1..after_name + 1 + 5], b"octet");
        assert_eq!(*p.last().unwrap(), 0);
        assert_eq!(p.len(), 2 + 9 + 1 + 5 + 1);
    }

    #[test]
    fn rrq_handles_empty_filename_shape() {
        // We don't reject here (`fetch` does), but the encoding should still
        // be well-formed: two NULs around an empty mode string.
        let p = build_rrq("");
        assert_eq!(
            p,
            vec![0x00, 0x01, 0x00, b'o', b'c', b't', b'e', b't', 0x00]
        );
    }

    #[test]
    fn ack_encodes_block_number_big_endian() {
        assert_eq!(build_ack(0), [0x00, 0x04, 0x00, 0x00]);
        assert_eq!(build_ack(1), [0x00, 0x04, 0x00, 0x01]);
        assert_eq!(build_ack(0x0102), [0x00, 0x04, 0x01, 0x02]);
        assert_eq!(build_ack(0xFFFF), [0x00, 0x04, 0xFF, 0xFF]);
    }

    #[test]
    fn parse_opcode_handles_short_input() {
        assert_eq!(parse_opcode(&[]), None);
        assert_eq!(parse_opcode(&[0x00]), None);
        assert_eq!(parse_opcode(&[0x00, 0x03]), Some(3));
        assert_eq!(parse_opcode(&[0x00, 0x05, 0xAA]), Some(5));
    }

    #[test]
    fn parse_data_extracts_block_and_payload() {
        let pkt = [0x00, 0x03, 0x00, 0x07, b'a', b'b', b'c'];
        let d = parse_data(&pkt).unwrap();
        assert_eq!(d.block, 7);
        assert_eq!(d.data, b"abc");
    }

    #[test]
    fn parse_data_allows_empty_payload() {
        // A DATA with zero payload bytes (block 0 of a tsize=0 file etc.)
        // is well-formed; it just signals EOF immediately.
        let pkt = [0x00, 0x03, 0x00, 0x42];
        let d = parse_data(&pkt).unwrap();
        assert_eq!(d.block, 0x42);
        assert_eq!(d.data, b"");
    }

    #[test]
    fn parse_data_rejects_short_header() {
        assert!(parse_data(&[]).is_err());
        assert!(parse_data(&[0x00, 0x03]).is_err());
        assert!(parse_data(&[0x00, 0x03, 0x00]).is_err());
    }

    #[test]
    fn parse_data_rejects_wrong_opcode() {
        let pkt = [0x00, 0x04, 0x00, 0x01];
        assert!(parse_data(&pkt).is_err());
    }

    #[test]
    fn parse_error_strips_trailing_nul() {
        let pkt = [0x00, 0x05, 0x00, 0x01, b'N', b'o', b'p', b'e', 0x00];
        let m = parse_error(&pkt).unwrap();
        assert_eq!(m, "Nope");
    }

    #[test]
    fn parse_error_tolerates_missing_nul() {
        // Some implementations forget the terminator. Be lenient.
        let pkt = [0x00, 0x05, 0x00, 0x02, b'h', b'i'];
        let m = parse_error(&pkt).unwrap();
        assert_eq!(m, "hi");
    }

    #[test]
    fn parse_error_handles_empty_message() {
        let pkt = [0x00, 0x05, 0x00, 0x03, 0x00];
        let m = parse_error(&pkt).unwrap();
        assert_eq!(m, "");
    }

    #[test]
    fn parse_error_rejects_short_header() {
        assert!(parse_error(&[0x00, 0x05]).is_err());
        assert!(parse_error(&[0x00, 0x05, 0x00]).is_err());
    }

    #[test]
    fn parse_error_rejects_wrong_opcode() {
        let pkt = [0x00, 0x03, 0x00, 0x01, b'x', 0x00];
        assert!(parse_error(&pkt).is_err());
    }

    #[test]
    fn parse_error_invalid_utf8_lossy() {
        // 0xFF is not valid UTF-8; from_utf8_lossy substitutes U+FFFD.
        let pkt = [0x00, 0x05, 0x00, 0x01, 0xFF, 0x00];
        let m = parse_error(&pkt).unwrap();
        assert!(m.contains('\u{FFFD}'));
    }

    // ---- write side (WRQ) ----

    #[test]
    fn wrq_builds_in_octet_mode() {
        let p = build_wrq("hello.txt");
        // opcode 2, filename, 0, "octet", 0
        assert_eq!(p[0..2], [0x00, 0x02]);
        assert_eq!(&p[2..2 + b"hello.txt".len()], b"hello.txt");
        let after_name = 2 + b"hello.txt".len();
        assert_eq!(p[after_name], 0);
        assert_eq!(&p[after_name + 1..after_name + 1 + 5], b"octet");
        assert_eq!(*p.last().unwrap(), 0);
        assert_eq!(p.len(), 2 + 9 + 1 + 5 + 1);
    }

    #[test]
    fn wrq_and_rrq_share_framing_only_opcode_differs() {
        let r = build_rrq("f");
        let w = build_wrq("f");
        assert_eq!(r[0..2], [0x00, 0x01]);
        assert_eq!(w[0..2], [0x00, 0x02]);
        assert_eq!(&r[2..], &w[2..]);
    }

    #[test]
    fn data_packet_builds_header_and_payload() {
        let p = build_data(1, b"abc");
        // opcode 3, block 1, payload
        assert_eq!(p, vec![0x00, 0x03, 0x00, 0x01, b'a', b'b', b'c']);
    }

    #[test]
    fn data_packet_block_number_big_endian() {
        let p = build_data(0x0102, b"");
        assert_eq!(p, vec![0x00, 0x03, 0x01, 0x02]);
    }

    #[test]
    fn data_packet_full_block_is_516_bytes() {
        let payload = vec![0x5Au8; BLOCK_SIZE];
        let p = build_data(7, &payload);
        assert_eq!(p.len(), 4 + BLOCK_SIZE);
        assert_eq!(p[0..4], [0x00, 0x03, 0x00, 0x07]);
        assert_eq!(&p[4..], &payload[..]);
    }

    #[test]
    fn parse_ack_extracts_block_number() {
        assert_eq!(parse_ack(&[0x00, 0x04, 0x00, 0x00]).unwrap(), 0);
        assert_eq!(parse_ack(&[0x00, 0x04, 0x00, 0x01]).unwrap(), 1);
        assert_eq!(parse_ack(&[0x00, 0x04, 0xFF, 0xFF]).unwrap(), 0xFFFF);
        // Trailing junk after the 4-byte header is ignored.
        assert_eq!(parse_ack(&[0x00, 0x04, 0x12, 0x34, 0xAA]).unwrap(), 0x1234);
    }

    #[test]
    fn parse_ack_rejects_short_header() {
        assert!(parse_ack(&[]).is_err());
        assert!(parse_ack(&[0x00, 0x04]).is_err());
        assert!(parse_ack(&[0x00, 0x04, 0x00]).is_err());
    }

    #[test]
    fn parse_ack_rejects_wrong_opcode() {
        // a DATA packet is not an ACK
        assert!(parse_ack(&[0x00, 0x03, 0x00, 0x01]).is_err());
    }

    /// The block-splitting math the send loop performs, factored out so the
    /// final-block termination rule can be unit-tested without a socket. Returns
    /// the (block#, payload-slice) pairs in order, exactly as `store` would emit
    /// them after each ACK.
    fn split_blocks(data: &[u8]) -> Vec<(u16, &[u8])> {
        let mut out = Vec::new();
        let mut block: u16 = 0;
        let mut offset = 0usize;
        loop {
            let next_offset = if block == 0 { 0 } else { offset + BLOCK_SIZE };
            let next_block = block.checked_add(1).expect("no wrap in test sizes");
            let end = (next_offset + BLOCK_SIZE).min(data.len());
            let payload = &data[next_offset..end];
            out.push((next_block, payload));
            block = next_block;
            offset = next_offset;
            if payload.len() < BLOCK_SIZE {
                break;
            }
        }
        out
    }

    #[test]
    fn split_blocks_short_single_block() {
        let data = b"hello";
        let blocks = split_blocks(data);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].0, 1);
        assert_eq!(blocks[0].1, b"hello");
    }

    #[test]
    fn split_blocks_empty_input_sends_one_empty_block() {
        // An empty file still requires one (empty, short) DATA block to mark EOF.
        let blocks = split_blocks(b"");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0], (1u16, &b""[..]));
    }

    #[test]
    fn split_blocks_exact_multiple_appends_trailing_empty_block() {
        // Exactly one full block: a trailing empty block is required so the
        // peer can tell the transfer ended (RFC 1350 §6).
        let data = vec![0xABu8; BLOCK_SIZE];
        let blocks = split_blocks(&data);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].0, 1);
        assert_eq!(blocks[0].1.len(), BLOCK_SIZE);
        assert_eq!(blocks[1].0, 2);
        assert_eq!(blocks[1].1.len(), 0);
    }

    #[test]
    fn split_blocks_two_full_blocks_plus_empty() {
        let data = vec![1u8; 2 * BLOCK_SIZE];
        let blocks = split_blocks(&data);
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0].0, 1);
        assert_eq!(blocks[1].0, 2);
        assert_eq!(blocks[2].0, 3);
        assert_eq!(blocks[2].1.len(), 0);
    }

    #[test]
    fn split_blocks_partial_final_block_no_trailing_empty() {
        // One full block + a short block: the short block terminates; no extra
        // empty block.
        let mut data = vec![0u8; BLOCK_SIZE];
        data.extend_from_slice(b"tail");
        let blocks = split_blocks(&data);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[1].0, 2);
        assert_eq!(blocks[1].1, b"tail");
    }

    #[test]
    fn split_blocks_reassemble_matches_input() {
        // Sanity: concatenating every block's payload reproduces the input.
        for &len in &[0usize, 1, 511, 512, 513, 1024, 1500, 4096] {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let blocks = split_blocks(&data);
            let joined: Vec<u8> = blocks.iter().flat_map(|(_, p)| p.iter().copied()).collect();
            assert_eq!(joined, data, "len {len}");
        }
    }

    // ---- end-to-end write over loopback UDP, with TID validation ----

    use std::net::UdpSocket;
    use std::thread;

    /// Minimal in-test TFTP server that accepts a WRQ and collects the upload.
    /// Replies from a *fresh* socket (a new TID) so the client must latch and
    /// validate it. When `inject_foreign_tid` is set, after latching it sends a
    /// spurious ACK 1 from an unrelated socket (a bogus TID); the client must
    /// discard that and only honour ACKs from the latched TID, or the collected
    /// bytes would diverge from the payload.
    fn run_mock_wrq_server(server: UdpSocket, inject_foreign_tid: bool) -> Vec<u8> {
        // Receive the WRQ on the well-known socket. `from` is the client's
        // address (its TID); replies go back there.
        let mut buf = [0u8; 4 + BLOCK_SIZE + 16];
        let (n, from) = server.recv_from(&mut buf).unwrap();
        assert_eq!(parse_opcode(&buf[..n]), Some(OP_WRQ));

        // A new socket → new TID for all real replies.
        let tid_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        tid_sock
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        // Real ACK 0 from our TID, latching it on the client side.
        tid_sock.send_to(&build_ack(0), from).unwrap();

        let foreign = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut injected = false;

        let mut collected = Vec::new();
        let mut expected: u16 = 1;
        loop {
            let (n, peer) = tid_sock.recv_from(&mut buf).unwrap();
            let d = parse_data(&buf[..n]).unwrap();
            assert_eq!(d.block, expected);
            collected.extend_from_slice(d.data);

            // After receiving the first DATA, fire a bogus ACK from a foreign
            // TID. The client must ignore it; we then send the legitimate ACK.
            if inject_foreign_tid && !injected {
                foreign.send_to(&build_ack(d.block), peer).unwrap();
                injected = true;
            }

            tid_sock.send_to(&build_ack(d.block), peer).unwrap();
            let last = d.data.len() < BLOCK_SIZE;
            expected = expected.wrapping_add(1);
            if last {
                break;
            }
        }
        collected
    }

    fn test_url(port: u16, path: &str) -> Url {
        Url {
            scheme: "tftp".into(),
            userinfo: None,
            host: "127.0.0.1".into(),
            port,
            path: path.into(),
        }
    }

    fn upload_roundtrip_inner(payload: Vec<u8>, inject_foreign_tid: bool) {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_port = server.local_addr().unwrap().port();
        let handle = thread::spawn(move || run_mock_wrq_server(server, inject_foreign_tid));

        let url = test_url(server_port, "/upload.bin");
        store(&url, &payload).unwrap();
        let got = handle.join().unwrap();
        assert_eq!(got, payload);
    }

    fn upload_roundtrip(payload: Vec<u8>) {
        upload_roundtrip_inner(payload, false);
    }

    #[test]
    fn store_uploads_short_file() {
        upload_roundtrip(b"hello, tftp world".to_vec());
    }

    #[test]
    fn store_uploads_empty_file() {
        upload_roundtrip(Vec::new());
    }

    #[test]
    fn store_uploads_exact_multiple_of_block() {
        upload_roundtrip(vec![0x7Eu8; BLOCK_SIZE]);
    }

    #[test]
    fn store_uploads_multi_block_file() {
        let payload: Vec<u8> = (0..(2 * BLOCK_SIZE + 100))
            .map(|i| (i % 256) as u8)
            .collect();
        upload_roundtrip(payload);
    }

    #[test]
    fn store_ignores_foreign_tid_acks() {
        // A multi-block upload where the server injects a bogus ACK from an
        // unrelated TID. The client must reject it and complete cleanly.
        let payload: Vec<u8> = (0..(2 * BLOCK_SIZE + 7)).map(|i| (i % 256) as u8).collect();
        upload_roundtrip_inner(payload, true);
    }

    #[test]
    fn store_rejects_empty_filename() {
        let url = test_url(69, "/");
        assert!(matches!(store(&url, b"x"), Err(Error::InvalidUrl(_))));
    }

    #[test]
    fn store_surfaces_server_error_packet() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_port = server.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let mut buf = [0u8; 64];
            let (n, from) = server.recv_from(&mut buf).unwrap();
            assert_eq!(parse_opcode(&buf[..n]), Some(OP_WRQ));
            // Reply with ERROR (code 2 = access violation).
            let err = [0x00, 0x05, 0x00, 0x02, b'n', b'o', 0x00];
            server.send_to(&err, from).unwrap();
        });

        let url = test_url(server_port, "/denied");
        let err = store(&url, b"data").unwrap_err();
        match err {
            Error::BadResponse(m) => assert!(m.contains("no"), "got {m}"),
            other => panic!("expected BadResponse, got {other:?}"),
        }
        handle.join().unwrap();
    }
}

//! Tracker clients: HTTP/HTTPS announce (BEP 3) and UDP announce (BEP 15).
//!
//! [`announce`] dispatches on the tracker URL's scheme, returning the peer list
//! and the re-announce interval. HTTP uses the crate's own HTTP client;
//! UDP uses the crate's `net::udp` socket.

use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::net::udp::{DirectUdp, UdpTransport};

use super::bencode::{self, Value};

fn terr(msg: impl Into<String>) -> Error {
    Error::BadResponse(format!("tracker: {}", msg.into()))
}

/// Announce event (BEP 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    None,
    Started,
    Stopped,
    Completed,
}

impl Event {
    fn http_str(self) -> Option<&'static str> {
        match self {
            Event::None => None,
            Event::Started => Some("started"),
            Event::Stopped => Some("stopped"),
            Event::Completed => Some("completed"),
        }
    }
    fn udp_code(self) -> u32 {
        match self {
            Event::None => 0,
            Event::Completed => 1,
            Event::Started => 2,
            Event::Stopped => 3,
        }
    }
}

/// What we tell the tracker about this transfer.
#[derive(Debug, Clone)]
pub struct AnnounceParams {
    pub info_hash: [u8; 20],
    pub peer_id: [u8; 20],
    pub port: u16,
    pub uploaded: u64,
    pub downloaded: u64,
    pub left: u64,
    pub event: Event,
    pub num_want: i32,
    pub key: u32,
}

/// Tracker reply distilled to what the engine needs.
#[derive(Debug, Clone)]
pub struct AnnounceResponse {
    pub interval: u32,
    pub peers: Vec<SocketAddr>,
}

/// Announce to `tracker_url`, dispatching by scheme.
pub fn announce(
    tracker_url: &str,
    p: &AnnounceParams,
    timeout: Duration,
) -> Result<AnnounceResponse> {
    if tracker_url.starts_with("http://") || tracker_url.starts_with("https://") {
        http_announce(tracker_url, p, timeout)
    } else if tracker_url.starts_with("udp://") {
        udp_announce(tracker_url, p, timeout)
    } else {
        Err(terr(format!("unsupported tracker scheme: {tracker_url}")))
    }
}

// ---------------------------------------------------------------------------
// HTTP(S)
// ---------------------------------------------------------------------------

fn http_announce(url: &str, p: &AnnounceParams, timeout: Duration) -> Result<AnnounceResponse> {
    let sep = if url.contains('?') { '&' } else { '?' };
    let mut full = format!("{url}{sep}info_hash=");
    full.push_str(&percent_encode_raw(&p.info_hash));
    full.push_str("&peer_id=");
    full.push_str(&percent_encode_raw(&p.peer_id));
    full.push_str(&format!(
        "&port={}&uploaded={}&downloaded={}&left={}&compact=1&numwant={}&key={}",
        p.port, p.uploaded, p.downloaded, p.left, p.num_want, p.key,
    ));
    if let Some(ev) = p.event.http_str() {
        full.push_str("&event=");
        full.push_str(ev);
    }

    let resp = crate::Request::get(&full)?.max_time(timeout).send()?;
    if resp.status != 200 {
        return Err(terr(format!("HTTP tracker status {}", resp.status)));
    }
    parse_http_response(&resp.body)
}

fn parse_http_response(body: &[u8]) -> Result<AnnounceResponse> {
    let root = bencode::parse(body)?;
    if let Some(reason) = root.get(b"failure reason").and_then(Value::as_str) {
        return Err(terr(format!("tracker failure: {reason}")));
    }
    let interval = root
        .get(b"interval")
        .and_then(Value::as_int)
        .filter(|&i| i > 0)
        .unwrap_or(1800) as u32;

    let mut peers = Vec::new();
    match root.get(b"peers") {
        // Compact form: 6 bytes per peer (4 IPv4 + 2 port, big-endian).
        Some(Value::Bytes(b)) => peers.extend(parse_compact_v4(b)),
        // Dictionary form: list of {ip, port}.
        Some(Value::List(list)) => {
            for entry in list {
                if let (Some(ip), Some(port)) = (
                    entry.get(b"ip").and_then(Value::as_str),
                    entry.get(b"port").and_then(Value::as_int),
                ) {
                    if let Ok(addr) = format!("{ip}:{port}").parse::<SocketAddr>() {
                        peers.push(addr);
                    }
                }
            }
        }
        _ => {}
    }
    if let Some(Value::Bytes(b)) = root.get(b"peers6") {
        peers.extend(parse_compact_v6(b));
    }

    Ok(AnnounceResponse { interval, peers })
}

fn parse_compact_v4(b: &[u8]) -> Vec<SocketAddr> {
    b.chunks_exact(6).map(super::compact_v4).collect()
}

fn parse_compact_v6(b: &[u8]) -> Vec<SocketAddr> {
    b.chunks_exact(18)
        .map(|c| {
            let mut o = [0u8; 16];
            o.copy_from_slice(&c[..16]);
            let ip = Ipv6Addr::from(o);
            let port = u16::from_be_bytes([c[16], c[17]]);
            SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0))
        })
        .collect()
}

/// Percent-encode raw bytes for a tracker query: unreserved characters pass
/// through, everything else becomes `%HH` (RFC 3986 unreserved set).
fn percent_encode_raw(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for &b in bytes {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(hex_upper(b >> 4));
            out.push(hex_upper(b & 0x0f));
        }
    }
    out
}

fn hex_upper(n: u8) -> char {
    (if n < 10 { b'0' + n } else { b'A' + (n - 10) }) as char
}

// ---------------------------------------------------------------------------
// UDP (BEP 15)
// ---------------------------------------------------------------------------

const UDP_PROTOCOL_ID: u64 = 0x0000_0417_2710_1980;
const ACTION_CONNECT: u32 = 0;
const ACTION_ANNOUNCE: u32 = 1;
const ACTION_ERROR: u32 = 3;

fn udp_announce(url: &str, p: &AnnounceParams, timeout: Duration) -> Result<AnnounceResponse> {
    // udp://host:port[/path] — resolve host:port.
    let hostport = url
        .strip_prefix("udp://")
        .and_then(|r| r.split('/').next())
        .ok_or_else(|| terr("malformed udp tracker url"))?;
    let addr = std::net::ToSocketAddrs::to_socket_addrs(&hostport)
        .map_err(Error::Io)?
        .next()
        .ok_or_else(|| terr("tracker did not resolve"))?;

    let sock = DirectUdp::bind_for(addr)?;
    sock.set_read_timeout(Some(timeout)).map_err(Error::Io)?;
    sock.set_write_timeout(Some(timeout)).map_err(Error::Io)?;

    // 1) Connect.
    let txn = rand_u32(p.key);
    let mut req = Vec::with_capacity(16);
    req.extend_from_slice(&UDP_PROTOCOL_ID.to_be_bytes());
    req.extend_from_slice(&ACTION_CONNECT.to_be_bytes());
    req.extend_from_slice(&txn.to_be_bytes());
    let resp = udp_round_trip(&sock, addr, &req, 16)?;
    if u32::from_be_bytes([resp[0], resp[1], resp[2], resp[3]]) != ACTION_CONNECT
        || resp[4..8] != txn.to_be_bytes()
    {
        return Err(terr("bad UDP connect response"));
    }
    let connection_id = u64::from_be_bytes(resp[8..16].try_into().unwrap());

    // 2) Announce.
    let txn2 = txn.wrapping_add(1);
    let mut a = Vec::with_capacity(98);
    a.extend_from_slice(&connection_id.to_be_bytes());
    a.extend_from_slice(&ACTION_ANNOUNCE.to_be_bytes());
    a.extend_from_slice(&txn2.to_be_bytes());
    a.extend_from_slice(&p.info_hash);
    a.extend_from_slice(&p.peer_id);
    a.extend_from_slice(&p.downloaded.to_be_bytes());
    a.extend_from_slice(&p.left.to_be_bytes());
    a.extend_from_slice(&p.uploaded.to_be_bytes());
    a.extend_from_slice(&p.event.udp_code().to_be_bytes());
    a.extend_from_slice(&0u32.to_be_bytes()); // IP (0 = source)
    a.extend_from_slice(&p.key.to_be_bytes());
    a.extend_from_slice(&p.num_want.to_be_bytes());
    a.extend_from_slice(&p.port.to_be_bytes());

    let r = udp_round_trip(&sock, addr, &a, 20)?;
    let action = u32::from_be_bytes([r[0], r[1], r[2], r[3]]);
    if r[4..8] != txn2.to_be_bytes() {
        return Err(terr("UDP announce transaction mismatch"));
    }
    if action == ACTION_ERROR {
        let msg = String::from_utf8_lossy(&r[8..]).into_owned();
        return Err(terr(format!("UDP tracker error: {msg}")));
    }
    if action != ACTION_ANNOUNCE {
        return Err(terr("unexpected UDP announce action"));
    }
    let interval = u32::from_be_bytes([r[8], r[9], r[10], r[11]]).max(1);
    // [12..16] leechers, [16..20] seeders, then 6-byte compact peers.
    let peers = parse_compact_v4(&r[20..]);
    Ok(AnnounceResponse { interval, peers })
}

/// Send `req`, retrying a few times, and return a response of at least
/// `min_len` bytes (BEP 15 suggests retransmits with backoff).
fn udp_round_trip(
    sock: &DirectUdp,
    addr: SocketAddr,
    req: &[u8],
    min_len: usize,
) -> Result<Vec<u8>> {
    let mut last_err = terr("no UDP response");
    for _ in 0..3 {
        sock.send_to(req, addr).map_err(Error::Io)?;
        let mut buf = [0u8; 2048];
        match sock.recv_from(&mut buf) {
            Ok((n, from)) if from.ip() == addr.ip() && n >= min_len => {
                return Ok(buf[..n].to_vec());
            }
            Ok(_) => continue,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                last_err = terr("UDP tracker timed out");
                continue;
            }
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Err(last_err)
}

/// Cheap transaction-id source seeded from the announce key (no need for a
/// CSPRNG here; the connection-id round-trip is the real anti-spoofing guard).
fn rand_u32(seed: u32) -> u32 {
    let mut x = seed ^ 0x9E37_79B9;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    x
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::net::UdpSocket;

    #[test]
    fn encodes_raw_bytes() {
        assert_eq!(percent_encode_raw(&[0x00, 0x10, b'A', b'~']), "%00%10A~");
    }

    #[test]
    fn parses_compact_http_response() {
        let mut d = BTreeMap::new();
        d.insert(b"interval".to_vec(), Value::Int(900));
        // two peers: 1.2.3.4:6881 and 5.6.7.8:6882
        let peers = vec![1, 2, 3, 4, 0x1a, 0xe1, 5, 6, 7, 8, 0x1a, 0xe2];
        d.insert(b"peers".to_vec(), Value::Bytes(peers));
        let body = bencode::encode(&Value::Dict(d));
        let r = parse_http_response(&body).unwrap();
        assert_eq!(r.interval, 900);
        assert_eq!(
            r.peers,
            vec![
                "1.2.3.4:6881".parse().unwrap(),
                "5.6.7.8:6882".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn surfaces_failure_reason() {
        let mut d = BTreeMap::new();
        d.insert(b"failure reason".to_vec(), Value::Bytes(b"banned".to_vec()));
        let body = bencode::encode(&Value::Dict(d));
        assert!(parse_http_response(&body).is_err());
    }

    /// Stand up a one-shot in-process UDP tracker that speaks BEP 15 and
    /// confirm a full connect+announce round-trip returns the seeded peer.
    #[test]
    fn udp_connect_announce_roundtrip() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            // connect
            let (n, peer) = server.recv_from(&mut buf).unwrap();
            assert!(n >= 16);
            let txn = &buf[12..16];
            let mut resp = Vec::new();
            resp.extend_from_slice(&ACTION_CONNECT.to_be_bytes());
            resp.extend_from_slice(txn);
            resp.extend_from_slice(&0x1122_3344_5566_7788u64.to_be_bytes());
            server.send_to(&resp, peer).unwrap();
            // announce
            let (n, peer) = server.recv_from(&mut buf).unwrap();
            assert!(n >= 98);
            let txn2 = &buf[12..16];
            let mut resp = Vec::new();
            resp.extend_from_slice(&ACTION_ANNOUNCE.to_be_bytes());
            resp.extend_from_slice(txn2);
            resp.extend_from_slice(&1800u32.to_be_bytes()); // interval
            resp.extend_from_slice(&0u32.to_be_bytes()); // leechers
            resp.extend_from_slice(&1u32.to_be_bytes()); // seeders
            resp.extend_from_slice(&[9, 8, 7, 6, 0x1a, 0xe1]); // 9.8.7.6:6881
            server.send_to(&resp, peer).unwrap();
        });

        let params = AnnounceParams {
            info_hash: [1u8; 20],
            peer_id: [2u8; 20],
            port: 6881,
            uploaded: 0,
            downloaded: 0,
            left: 100,
            event: Event::Started,
            num_want: 50,
            key: 0xCAFE,
        };
        let r = announce(
            &format!("udp://127.0.0.1:{port}"),
            &params,
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(r.interval, 1800);
        assert_eq!(r.peers, vec!["9.8.7.6:6881".parse().unwrap()]);
        handle.join().unwrap();
    }
}

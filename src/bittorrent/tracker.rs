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
    b.as_chunks::<6>()
        .0
        .iter()
        .map(|c| super::compact_v4(c))
        .collect()
}

fn parse_compact_v6(b: &[u8]) -> Vec<SocketAddr> {
    b.as_chunks::<18>()
        .0
        .iter()
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
    let (hostport, url_data) = split_udp_url(url)?;
    let addr = std::net::ToSocketAddrs::to_socket_addrs(&hostport)
        .map_err(Error::Io)?
        .next()
        .ok_or_else(|| terr("tracker did not resolve"))?;

    let sock = DirectUdp::bind_for(addr)?;
    sock.set_read_timeout(Some(timeout)).map_err(Error::Io)?;
    sock.set_write_timeout(Some(timeout)).map_err(Error::Io)?;

    // 1) Connect. Transaction ids come from the CSPRNG (BEP 15): together
    // with the source address check they are what stops an off-path attacker
    // from forging the connect/announce replies and injecting peers.
    let txn = super::random_u32()?;
    let mut req = Vec::with_capacity(16);
    req.extend_from_slice(&UDP_PROTOCOL_ID.to_be_bytes());
    req.extend_from_slice(&ACTION_CONNECT.to_be_bytes());
    req.extend_from_slice(&txn.to_be_bytes());
    let resp = udp_round_trip(&sock, addr, &req, txn)?;
    let action = be_u32(&resp[0..4]);
    if action == ACTION_ERROR {
        return Err(udp_error(&resp));
    }
    if action != ACTION_CONNECT || resp.len() < 16 {
        return Err(terr("bad UDP connect response"));
    }
    let connection_id = u64::from_be_bytes(resp[8..16].try_into().unwrap());

    // 2) Announce.
    let txn2 = super::random_u32()?;
    let mut a = Vec::with_capacity(98 + url_data.len() + 8);
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
    append_url_data(&mut a, url_data.as_bytes());

    let r = udp_round_trip(&sock, addr, &a, txn2)?;
    let action = be_u32(&r[0..4]);
    if action == ACTION_ERROR {
        return Err(udp_error(&r));
    }
    if action != ACTION_ANNOUNCE || r.len() < 20 {
        return Err(terr("unexpected UDP announce response"));
    }
    let interval = be_u32(&r[8..12]).max(1);
    // [12..16] leechers, [16..20] seeders, then compact peers: 6-byte for an
    // IPv4 tracker, 18-byte for an IPv6 one (BEP 15).
    let peers = if addr.is_ipv6() {
        parse_compact_v6(&r[20..])
    } else {
        parse_compact_v4(&r[20..])
    };
    Ok(AnnounceResponse { interval, peers })
}

/// Split `udp://host:port[/path][?query]` into the `host:port` to resolve and
/// the path+query (BEP 41 "URL data", e.g. a private tracker's passkey).
fn split_udp_url(url: &str) -> Result<(String, String)> {
    let rest = url
        .strip_prefix("udp://")
        .ok_or_else(|| terr("malformed udp tracker url"))?;
    let rest = rest.split('#').next().unwrap_or(rest);
    let cut = rest.find(['/', '?']).unwrap_or(rest.len());
    let (hostport, data) = rest.split_at(cut);
    if hostport.is_empty() {
        return Err(terr("malformed udp tracker url"));
    }
    Ok((hostport.to_string(), data.to_string()))
}

/// BEP 41 option type carrying (part of) the announce URL's path and query.
const OPT_URL_DATA: u8 = 0x2;

/// Append `data` as BEP 41 `URLData` options (at most 255 bytes each).
/// Trackers that predate BEP 41 ignore the trailing bytes.
fn append_url_data(out: &mut Vec<u8>, data: &[u8]) {
    for chunk in data.chunks(255) {
        out.push(OPT_URL_DATA);
        out.push(chunk.len() as u8);
        out.extend_from_slice(chunk);
    }
}

fn be_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// An `error` action reply: the rest of the datagram is the message.
fn udp_error(resp: &[u8]) -> Error {
    let msg = String::from_utf8_lossy(&resp[8..]).into_owned();
    terr(format!("UDP tracker error: {msg}"))
}

/// Send `req`, retrying a few times (BEP 15 retransmits), and return the first
/// reply from the tracker's exact address (IP *and* port) that echoes `txn`.
/// Replies are at least the 8-byte action + transaction header; callers check
/// the per-action length (an `error` reply may be that short). Datagrams from
/// elsewhere, or with a stale transaction id, are skipped without consuming a
/// retransmit.
fn udp_round_trip(sock: &DirectUdp, addr: SocketAddr, req: &[u8], txn: u32) -> Result<Vec<u8>> {
    /// Bound on stray datagrams read per attempt (so a flood can't pin us).
    const MAX_STRAY: usize = 16;
    let mut last_err = terr("no UDP response");
    for _ in 0..3 {
        sock.send_to(req, addr).map_err(Error::Io)?;
        let mut buf = [0u8; 2048];
        for _ in 0..MAX_STRAY {
            match sock.recv_from(&mut buf) {
                Ok((n, from)) if from == addr && n >= 8 && buf[4..8] == txn.to_be_bytes() => {
                    return Ok(buf[..n].to_vec());
                }
                Ok(_) => continue, // spoofed / stale / truncated
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    last_err = terr("UDP tracker timed out");
                    break;
                }
                Err(e) => return Err(Error::Io(e)),
            }
        }
    }
    Err(last_err)
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

    fn params() -> AnnounceParams {
        AnnounceParams {
            info_hash: [1u8; 20],
            peer_id: [2u8; 20],
            port: 6881,
            uploaded: 0,
            downloaded: 0,
            left: 100,
            event: Event::Started,
            num_want: 50,
            key: 0,
        }
    }

    #[test]
    fn splits_udp_url_host_from_url_data() {
        assert_eq!(
            split_udp_url("udp://t.example:6969/announce?passkey=abc").unwrap(),
            ("t.example:6969".into(), "/announce?passkey=abc".into())
        );
        assert_eq!(
            split_udp_url("udp://t.example:6969?passkey=abc").unwrap(),
            ("t.example:6969".into(), "?passkey=abc".into())
        );
        assert_eq!(
            split_udp_url("udp://[::1]:6969").unwrap(),
            ("[::1]:6969".into(), String::new())
        );
        assert!(split_udp_url("udp:///x").is_err());
    }

    #[test]
    fn url_data_is_chunked_into_bep41_options() {
        let mut out = Vec::new();
        let data = vec![b'x'; 300];
        append_url_data(&mut out, &data);
        assert_eq!(out[0], OPT_URL_DATA);
        assert_eq!(out[1], 255);
        assert_eq!(out[257], OPT_URL_DATA);
        assert_eq!(out[258], 45);
        assert_eq!(out.len(), 2 + 255 + 2 + 45);
    }

    /// Transaction ids are unpredictable (not derived from `key`, which the
    /// CLI always passes as 0).
    #[test]
    fn udp_transaction_ids_are_random() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let mut txns = Vec::new();
            let mut buf = [0u8; 2048];
            for _ in 0..2 {
                // Answer each connect with an error so the announce stops there.
                let (_, peer) = server.recv_from(&mut buf).unwrap();
                txns.push(buf[12..16].to_vec());
                let mut resp = ACTION_ERROR.to_be_bytes().to_vec();
                resp.extend_from_slice(&buf[12..16]);
                resp.extend_from_slice(b"nope");
                server.send_to(&resp, peer).unwrap();
            }
            txns
        });
        let url = format!("udp://127.0.0.1:{port}");
        for _ in 0..2 {
            let e = announce(&url, &params(), Duration::from_secs(5)).unwrap_err();
            assert!(e.to_string().contains("nope"), "{e}");
        }
        let txns = handle.join().unwrap();
        assert_ne!(txns[0], txns[1], "transaction id must not be constant");
    }

    /// A reply from the right IP but the wrong port, or with the wrong
    /// transaction id, is ignored; a short `error` reply is still surfaced.
    #[test]
    fn udp_ignores_spoofed_replies_and_surfaces_short_errors() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let spoofer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            let (_, peer) = server.recv_from(&mut buf).unwrap();
            let txn = buf[12..16].to_vec();
            // Forged connect reply from another port on the same IP.
            let mut forged = ACTION_CONNECT.to_be_bytes().to_vec();
            forged.extend_from_slice(&txn);
            forged.extend_from_slice(&0xdead_beefu64.to_be_bytes());
            spoofer.send_to(&forged, peer).unwrap();
            // Stale transaction id from the real server.
            let mut stale = ACTION_CONNECT.to_be_bytes().to_vec();
            stale.extend_from_slice(&[0, 0, 0, 0]);
            stale.extend_from_slice(&0u64.to_be_bytes());
            server.send_to(&stale, peer).unwrap();
            // The genuine reply: a bare 8-byte error (no message).
            let mut resp = ACTION_ERROR.to_be_bytes().to_vec();
            resp.extend_from_slice(&txn);
            server.send_to(&resp, peer).unwrap();
        });
        let e = announce(
            &format!("udp://127.0.0.1:{port}"),
            &params(),
            Duration::from_secs(5),
        )
        .unwrap_err();
        assert!(e.to_string().contains("UDP tracker error"), "{e}");
        handle.join().unwrap();
    }

    /// The announce carries the URL's path+query as BEP 41 URL data, and an
    /// announce `error` reply shorter than a full announce reply is reported.
    #[test]
    fn udp_announce_sends_url_data_and_reports_errors() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            let (_, peer) = server.recv_from(&mut buf).unwrap();
            let mut resp = ACTION_CONNECT.to_be_bytes().to_vec();
            resp.extend_from_slice(&buf[12..16]);
            resp.extend_from_slice(&7u64.to_be_bytes());
            server.send_to(&resp, peer).unwrap();
            let (n, peer) = server.recv_from(&mut buf).unwrap();
            let opts = buf[98..n].to_vec();
            let mut resp = ACTION_ERROR.to_be_bytes().to_vec();
            resp.extend_from_slice(&buf[12..16]);
            resp.extend_from_slice(b"bad");
            server.send_to(&resp, peer).unwrap();
            opts
        });
        let e = announce(
            &format!("udp://127.0.0.1:{port}/announce?pk=1"),
            &params(),
            Duration::from_secs(5),
        )
        .unwrap_err();
        assert!(e.to_string().contains("bad"), "{e}");
        let opts = handle.join().unwrap();
        let data = b"/announce?pk=1";
        let mut want = vec![OPT_URL_DATA, data.len() as u8];
        want.extend_from_slice(data);
        assert_eq!(opts, want);
    }
}

//! Minimal mainline DHT (BEP 5) peer discovery.
//!
//! Just enough of the Kademlia-based DHT to find peers for a torrent with no
//! working tracker: an iterative `get_peers` lookup over UDP (the KRPC
//! protocol). This is a transient, one-shot lookup driven from bootstrap nodes
//! — we do not maintain a persistent routing table or answer incoming queries.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::time::{Duration, Instant};

use purecrypto::rng::{OsRng, RngCore};

use crate::error::{Error, Result};
use crate::net::udp::{DirectUdp, UdpTransport};

use super::bencode::{self, Value};

/// Well-known mainline DHT bootstrap hosts.
pub const BOOTSTRAP_NODES: &[&str] = &[
    "router.bittorrent.com:6881",
    "router.utorrent.com:6881",
    "dht.transmissionbt.com:6881",
    "dht.libtorrent.org:25401",
];

/// How many of the closest unqueried nodes to query per round.
const ALPHA: usize = 8;
/// Stop once we've collected at least this many peers.
const ENOUGH_PEERS: usize = 30;
/// Cap the retained node frontier so a hostile swarm can't grow it unbounded.
const MAX_KNOWN: usize = 128;
/// Bound datagrams read while waiting for one query's matching reply.
const MAX_REPLIES_PER_QUERY: usize = 8;

fn derr(msg: impl Into<String>) -> Error {
    Error::BadResponse(format!("dht: {}", msg.into()))
}

/// Generate a random 160-bit node id.
pub fn random_node_id() -> [u8; 20] {
    let mut id = [0u8; 20];
    OsRng.fill_bytes(&mut id);
    id
}

/// Resolve the built-in bootstrap hosts to socket addresses, skipping any that
/// fail to resolve.
pub fn default_bootstrap() -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for host in BOOTSTRAP_NODES {
        if let Ok(addrs) = host.to_socket_addrs() {
            out.extend(addrs);
        }
    }
    out
}

/// XOR distance between two ids (a 20-byte big-endian magnitude).
fn distance(a: &[u8; 20], b: &[u8; 20]) -> [u8; 20] {
    let mut d = [0u8; 20];
    for (i, slot) in d.iter_mut().enumerate() {
        *slot = a[i] ^ b[i];
    }
    d
}

/// Iteratively look up peers for `info_hash`, starting from `bootstrap`.
///
/// Returns whatever peers were discovered before `overall_timeout` elapses or
/// the node frontier is exhausted (an empty list if none answered).
pub fn find_peers(
    info_hash: [u8; 20],
    bootstrap: &[SocketAddr],
    node_id: [u8; 20],
    overall_timeout: Duration,
) -> Result<Vec<SocketAddr>> {
    if bootstrap.is_empty() {
        return Err(derr("no bootstrap nodes"));
    }
    let sock = DirectUdp::bind_for(bootstrap[0])?;
    sock.set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(Error::Io)?;
    sock.set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(Error::Io)?;

    let deadline = Instant::now() + overall_timeout;
    let mut peers: HashSet<SocketAddr> = HashSet::new();
    let mut queried: HashSet<SocketAddr> = HashSet::new();
    let mut known: Vec<([u8; 20], SocketAddr)> = Vec::new();
    let mut frontier: Vec<SocketAddr> = bootstrap.to_vec();
    let mut txn: u16 = 0;

    while !frontier.is_empty() && Instant::now() < deadline {
        for addr in std::mem::take(&mut frontier) {
            if Instant::now() >= deadline {
                break;
            }
            if !queried.insert(addr) {
                continue;
            }
            txn = txn.wrapping_add(1);
            let tid = txn.to_be_bytes();
            let req = build_get_peers(&tid, &node_id, &info_hash);
            if let Ok(reply) = query(&sock, addr, &req, &tid) {
                for p in reply.peers {
                    peers.insert(p);
                }
                for (id, naddr) in reply.nodes {
                    if !queried.contains(&naddr) && !known.iter().any(|(_, a)| *a == naddr) {
                        known.push((id, naddr));
                    }
                }
            }
        }
        if peers.len() >= ENOUGH_PEERS {
            break;
        }
        // Closest-first by XOR distance; keep the frontier bounded.
        known.sort_by_key(|(id, _)| distance(id, &info_hash));
        known.truncate(MAX_KNOWN);
        frontier = known
            .iter()
            .filter(|(_, a)| !queried.contains(a))
            .take(ALPHA)
            .map(|(_, a)| *a)
            .collect();
    }
    Ok(peers.into_iter().collect())
}

struct Reply {
    peers: Vec<SocketAddr>,
    nodes: Vec<([u8; 20], SocketAddr)>,
}

/// Build a `get_peers` KRPC query.
fn build_get_peers(txn: &[u8], node_id: &[u8; 20], info_hash: &[u8; 20]) -> Vec<u8> {
    use std::collections::BTreeMap;
    let mut a = BTreeMap::new();
    a.insert(b"id".to_vec(), Value::Bytes(node_id.to_vec()));
    a.insert(b"info_hash".to_vec(), Value::Bytes(info_hash.to_vec()));
    let mut q = BTreeMap::new();
    q.insert(b"a".to_vec(), Value::Dict(a));
    q.insert(b"q".to_vec(), Value::Bytes(b"get_peers".to_vec()));
    q.insert(b"t".to_vec(), Value::Bytes(txn.to_vec()));
    q.insert(b"y".to_vec(), Value::Bytes(b"q".to_vec()));
    bencode::encode(&Value::Dict(q))
}

/// Send `req` to `addr` and read datagrams until one is a valid `r`-response
/// carrying our transaction id, or the read times out.
fn query(sock: &DirectUdp, addr: SocketAddr, req: &[u8], txn: &[u8]) -> Result<Reply> {
    sock.send_to(req, addr).map_err(Error::Io)?;
    let mut buf = [0u8; 2048];
    for _ in 0..MAX_REPLIES_PER_QUERY {
        match sock.recv_from(&mut buf) {
            Ok((n, from)) if from.ip() == addr.ip() => {
                if let Some(reply) = parse_response(&buf[..n], txn) {
                    return Ok(reply);
                }
                // Not ours (stale / wrong txn): keep reading.
            }
            Ok(_) => continue,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return Err(derr("query timed out"));
            }
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Err(derr("no matching reply"))
}

/// Parse a KRPC response, requiring `y == "r"` and a matching transaction id.
fn parse_response(buf: &[u8], txn: &[u8]) -> Option<Reply> {
    let root = bencode::parse(buf).ok()?;
    if root.get(b"y").and_then(Value::as_bytes) != Some(b"r") {
        return None;
    }
    if root.get(b"t").and_then(Value::as_bytes) != Some(txn) {
        return None;
    }
    let r = root.get(b"r")?;

    let mut peers = Vec::new();
    if let Some(vals) = r.get(b"values").and_then(Value::as_list) {
        for v in vals {
            if let Some(b) = v.as_bytes() {
                if b.len() == 6 {
                    peers.push(super::compact_v4(b));
                }
            }
        }
    }
    let mut nodes = Vec::new();
    if let Some(b) = r.get(b"nodes").and_then(Value::as_bytes) {
        for c in b.chunks_exact(26) {
            let mut id = [0u8; 20];
            id.copy_from_slice(&c[..20]);
            let ip = Ipv4Addr::new(c[20], c[21], c[22], c[23]);
            let port = u16::from_be_bytes([c[24], c[25]]);
            nodes.push((id, SocketAddr::V4(SocketAddrV4::new(ip, port))));
        }
    }
    Some(Reply { peers, nodes })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::net::UdpSocket;

    #[test]
    fn distance_orders_by_xor() {
        let target = [0u8; 20];
        let mut near = [0u8; 20];
        near[19] = 1;
        let mut far = [0u8; 20];
        far[0] = 1;
        assert!(distance(&near, &target) < distance(&far, &target));
    }

    #[test]
    fn parses_values_response() {
        let mut r = BTreeMap::new();
        r.insert(b"id".to_vec(), Value::Bytes(vec![0u8; 20]));
        r.insert(b"token".to_vec(), Value::Bytes(b"tok".to_vec()));
        r.insert(
            b"values".to_vec(),
            Value::List(vec![Value::Bytes(vec![1, 2, 3, 4, 0x1a, 0xe1])]),
        );
        let mut root = BTreeMap::new();
        root.insert(b"r".to_vec(), Value::Dict(r));
        root.insert(b"t".to_vec(), Value::Bytes(vec![0, 7]));
        root.insert(b"y".to_vec(), Value::Bytes(b"r".to_vec()));
        let buf = bencode::encode(&Value::Dict(root));

        let reply = parse_response(&buf, &[0, 7]).expect("parse");
        assert_eq!(reply.peers, vec!["1.2.3.4:6881".parse().unwrap()]);
        // Wrong transaction id is rejected.
        assert!(parse_response(&buf, &[9, 9]).is_none());
    }

    /// An in-process DHT node that answers one `get_peers` with a peer in
    /// `values`; confirm the iterative lookup surfaces it.
    #[test]
    fn find_peers_against_local_node() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            let (n, peer) = server.recv_from(&mut buf).unwrap();
            let q = bencode::parse(&buf[..n]).unwrap();
            let txn = q.get(b"t").and_then(Value::as_bytes).unwrap().to_vec();

            let mut r = BTreeMap::new();
            r.insert(b"id".to_vec(), Value::Bytes(vec![0xab; 20]));
            r.insert(b"token".to_vec(), Value::Bytes(b"tok".to_vec()));
            r.insert(
                b"values".to_vec(),
                Value::List(vec![Value::Bytes(vec![9, 8, 7, 6, 0x1a, 0xe2])]),
            );
            let mut root = BTreeMap::new();
            root.insert(b"r".to_vec(), Value::Dict(r));
            root.insert(b"t".to_vec(), Value::Bytes(txn));
            root.insert(b"y".to_vec(), Value::Bytes(b"r".to_vec()));
            server
                .send_to(&bencode::encode(&Value::Dict(root)), peer)
                .unwrap();
        });

        let boot: Vec<SocketAddr> = vec![format!("127.0.0.1:{port}").parse().unwrap()];
        let peers = find_peers([0x11; 20], &boot, [0x22; 20], Duration::from_secs(5)).unwrap();
        assert_eq!(peers, vec!["9.8.7.6:6882".parse().unwrap()]);
        handle.join().unwrap();
    }
}

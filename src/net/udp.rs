//! Pluggable UDP transport for the datagram protocols (HTTP/3 over QUIC and
//! TFTP), including SOCKS5 UDP ASSOCIATE (RFC 1928 §7).
//!
//! [`UdpTransport`] mirrors the slice of [`std::net::UdpSocket`] those
//! backends use. [`DirectUdp`] is a thin wrapper over a real socket;
//! [`Socks5UdpTransport`] relays datagrams through a SOCKS5 proxy. The
//! load-bearing contract is that `recv_from` always returns the **real**
//! (decapsulated) peer address — TFTP's TID validation and QUIC's datagram
//! routing both depend on it.

use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::net::socks;

/// Largest SOCKS5 UDP request header: RSV(2) + FRAG(1) + ATYP(1) + IPv6(16) +
/// PORT(2).
const MAX_UDP_HEADER: usize = 22;

/// A datagram transport: send/recv to/from arbitrary peers, with the per-recv
/// peer always reported as the true source (decapsulated for SOCKS5).
pub(crate) trait UdpTransport: Send {
    fn send_to(&self, buf: &[u8], peer: SocketAddr) -> io::Result<usize>;
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()>;
    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()>;
    #[allow(dead_code)]
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

/// How a connector carries UDP datagrams (HTTP/3, TFTP). Returned by
/// [`crate::net::Connector::udp_proxy`]; a custom connector overrides that
/// method to opt into UDP.
pub enum UdpProxy {
    /// Direct UDP socket.
    Direct,
    /// Relay through a SOCKS5 proxy via UDP ASSOCIATE.
    Socks5 {
        host: String,
        port: u16,
        auth: Option<(String, String)>,
    },
    /// This transport cannot carry UDP (HTTP/HTTPS/SOCKS4 proxies, or a custom
    /// connector that didn't opt in). HTTP/3 and TFTP error in this case.
    Unsupported,
}

/// Build a UDP transport for `peer` according to the connector's UDP policy.
pub(crate) fn open_udp_transport(
    proxy: UdpProxy,
    peer: SocketAddr,
) -> Result<Box<dyn UdpTransport>> {
    match proxy {
        UdpProxy::Direct => Ok(Box::new(DirectUdp::bind_for(peer)?)),
        UdpProxy::Socks5 { host, port, auth } => {
            let auth_ref = auth.as_ref().map(|(u, p)| (u.as_str(), p.as_str()));
            Ok(Box::new(Socks5UdpTransport::connect(
                &host, port, auth_ref,
            )?))
        }
        UdpProxy::Unsupported => Err(Error::UnsupportedScheme(
            "this proxy cannot tunnel UDP; HTTP/3 and TFTP need a direct \
             connection or a SOCKS5 proxy"
                .into(),
        )),
    }
}

// ---------------------------------------------------------------------------
// Direct
// ---------------------------------------------------------------------------

/// A plain UDP socket.
pub(crate) struct DirectUdp {
    sock: UdpSocket,
}

impl DirectUdp {
    /// Bind a local socket of the same address family as `peer`.
    pub(crate) fn bind_for(peer: SocketAddr) -> io::Result<Self> {
        let bind = if peer.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        Ok(DirectUdp {
            sock: UdpSocket::bind(bind)?,
        })
    }
}

impl UdpTransport for DirectUdp {
    fn send_to(&self, buf: &[u8], peer: SocketAddr) -> io::Result<usize> {
        self.sock.send_to(buf, peer)
    }
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.sock.recv_from(buf)
    }
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.sock.set_read_timeout(dur)
    }
    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.sock.set_write_timeout(dur)
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.sock.local_addr()
    }
}

// ---------------------------------------------------------------------------
// SOCKS5 UDP ASSOCIATE
// ---------------------------------------------------------------------------

/// Relays datagrams through a SOCKS5 proxy. The TCP control connection
/// (`_control`) MUST stay open for the lifetime of the association — dropping
/// it tears the relay down (RFC 1928 §7).
pub(crate) struct Socks5UdpTransport {
    _control: TcpStream,
    relay: UdpSocket,
    relay_addr: SocketAddr,
}

impl Socks5UdpTransport {
    pub(crate) fn connect(host: &str, port: u16, auth: Option<(&str, &str)>) -> Result<Self> {
        let mut control = TcpStream::connect((host, port))?;
        control.set_read_timeout(Some(Duration::from_secs(30)))?;
        control.set_write_timeout(Some(Duration::from_secs(30)))?;
        socks::socks5_negotiate(&mut control, auth)?;
        // We don't know our own outbound UDP address yet, so request the
        // association with a wildcard DST (allowed by RFC 1928 §7).
        let mut relay_addr = socks::socks5_request(&mut control, 0x03, "0.0.0.0", 0, false)?;
        // A wildcard BND.ADDR means "same host as the control connection".
        if relay_addr.ip().is_unspecified() {
            let proxy_ip = control.peer_addr()?.ip();
            relay_addr = SocketAddr::new(proxy_ip, relay_addr.port());
        }
        let bind = if relay_addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let relay = UdpSocket::bind(bind)?;
        // Reset the control socket's timeouts now the handshake is done.
        control.set_read_timeout(None)?;
        control.set_write_timeout(None)?;
        Ok(Socks5UdpTransport {
            _control: control,
            relay,
            relay_addr,
        })
    }
}

impl UdpTransport for Socks5UdpTransport {
    fn send_to(&self, buf: &[u8], peer: SocketAddr) -> io::Result<usize> {
        let dgram = encode_udp_header(peer, buf);
        self.relay.send_to(&dgram, self.relay_addr)?;
        // Report the caller's payload length as "sent".
        Ok(buf.len())
    }
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut scratch = vec![0u8; buf.len().saturating_add(MAX_UDP_HEADER)];
        let (n, _from) = self.relay.recv_from(&mut scratch)?;
        let (src, data) = decode_udp_header(&scratch[..n])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let m = data.len().min(buf.len());
        buf[..m].copy_from_slice(&data[..m]);
        Ok((m, src))
    }
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.relay.set_read_timeout(dur)
    }
    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.relay.set_write_timeout(dur)
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.relay.local_addr()
    }
}

/// Build a SOCKS5 UDP request datagram: `RSV(2)=0 FRAG(1)=0 ATYP ADDR PORT
/// DATA` for destination `dst`.
fn encode_udp_header(dst: SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAX_UDP_HEADER + data.len());
    out.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV RSV FRAG
    match dst.ip() {
        IpAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(0x04);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&dst.port().to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// Parse a SOCKS5 UDP reply datagram, returning the decapsulated source
/// address and the payload slice. Rejects fragmentation (`FRAG != 0`) and a
/// domain ATYP (illegal from a relay).
fn decode_udp_header(buf: &[u8]) -> std::result::Result<(SocketAddr, &[u8]), String> {
    if buf.len() < 4 {
        return Err("socks5 udp: datagram too short".into());
    }
    if buf[2] != 0x00 {
        return Err("socks5 udp: fragmentation not supported".into());
    }
    let (ip, rest): (IpAddr, &[u8]) = match buf[3] {
        0x01 => {
            if buf.len() < 4 + 4 + 2 {
                return Err("socks5 udp: truncated IPv4 header".into());
            }
            let octets: [u8; 4] = buf[4..8].try_into().unwrap();
            (IpAddr::V4(octets.into()), &buf[8..])
        }
        0x04 => {
            if buf.len() < 4 + 16 + 2 {
                return Err("socks5 udp: truncated IPv6 header".into());
            }
            let octets: [u8; 16] = buf[4..20].try_into().unwrap();
            (IpAddr::V6(octets.into()), &buf[20..])
        }
        0x03 => return Err("socks5 udp: domain address not allowed in reply".into()),
        other => return Err(format!("socks5 udp: unknown ATYP {other:#04x}")),
    };
    let port = u16::from_be_bytes([rest[0], rest[1]]);
    Ok((SocketAddr::new(ip, port), &rest[2..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn header_roundtrip_ipv4() {
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);
        let dgram = encode_udp_header(dst, b"quic-bytes");
        assert_eq!(&dgram[0..4], &[0x00, 0x00, 0x00, 0x01]);
        let (src, data) = decode_udp_header(&dgram).unwrap();
        assert_eq!(src, dst);
        assert_eq!(data, b"quic-bytes");
    }

    #[test]
    fn header_roundtrip_ipv6() {
        let dst = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080);
        let dgram = encode_udp_header(dst, b"x");
        assert_eq!(dgram[3], 0x04);
        let (src, data) = decode_udp_header(&dgram).unwrap();
        assert_eq!(src, dst);
        assert_eq!(data, b"x");
    }

    #[test]
    fn decode_rejects_fragmentation() {
        let mut dgram =
            encode_udp_header(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1), b"d");
        dgram[2] = 0x01; // FRAG != 0
        assert!(decode_udp_header(&dgram).is_err());
    }

    #[test]
    fn decode_rejects_domain_atyp() {
        let dgram = [0x00, 0x00, 0x00, 0x03, 0x01, b'x', 0x00, 0x50];
        assert!(decode_udp_header(&dgram).is_err());
    }

    #[test]
    fn decode_rejects_truncated() {
        assert!(decode_udp_header(&[0x00, 0x00]).is_err());
        assert!(decode_udp_header(&[0x00, 0x00, 0x00, 0x01, 1, 2]).is_err());
    }

    /// End-to-end against a mock SOCKS5 UDP relay: negotiate + ASSOCIATE on the
    /// TCP control connection, then send one datagram and receive one back,
    /// asserting the payload round-trips and `recv_from` reports the
    /// *decapsulated* source the relay put in the reply header.
    #[test]
    fn socks5_udp_associate_roundtrip() {
        use std::io::{Read, Write};
        use std::net::{Ipv4Addr, TcpListener};
        use std::thread;

        let control = TcpListener::bind("127.0.0.1:0").unwrap();
        let control_addr = control.local_addr().unwrap();
        let relay = UdpSocket::bind("127.0.0.1:0").unwrap();
        let relay_addr = relay.local_addr().unwrap();

        // The "server" address the relay claims a reply came from.
        let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 4433);

        // Control-channel handler: greeting -> NO-AUTH, ASSOCIATE -> success
        // with BND = the relay's address, then hold the socket open.
        let ctrl = thread::spawn(move || {
            let (mut s, _) = control.accept().unwrap();
            let mut greet = [0u8; 3];
            s.read_exact(&mut greet).unwrap();
            s.write_all(&[0x05, 0x00]).unwrap();
            // ASSOCIATE request: VER CMD RSV ATYP(1) ADDR(4) PORT(2) = 10 bytes.
            let mut req = [0u8; 10];
            s.read_exact(&mut req).unwrap();
            assert_eq!(req[1], 0x03, "expected UDP ASSOCIATE");
            let mut reply = vec![0x05, 0x00, 0x00, 0x01];
            match relay_addr.ip() {
                IpAddr::V4(v4) => reply.extend_from_slice(&v4.octets()),
                IpAddr::V6(_) => unreachable!(),
            }
            reply.extend_from_slice(&relay_addr.port().to_be_bytes());
            s.write_all(&reply).unwrap();
            // Hold the control connection until the client drops it.
            let mut sink = [0u8; 1];
            let _ = s.read(&mut sink);
        });

        // Relay handler: receive one encapsulated datagram, verify the DST,
        // then reply with an encapsulated datagram sourced from `server`.
        let relay_thread = thread::spawn(move || {
            let mut buf = [0u8; 2048];
            let (n, client) = relay.recv_from(&mut buf).unwrap();
            let (dst, data) = decode_udp_header(&buf[..n]).unwrap();
            assert_eq!(dst, server);
            assert_eq!(data, b"ping");
            let out = encode_udp_header(server, b"pong");
            relay.send_to(&out, client).unwrap();
        });

        let t = Socks5UdpTransport::connect("127.0.0.1", control_addr.port(), None).unwrap();
        t.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        t.send_to(b"ping", server).unwrap();
        let mut buf = [0u8; 1024];
        let (n, src) = t.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"pong");
        assert_eq!(src, server, "recv_from must report the decapsulated source");

        drop(t); // closes the control connection
        relay_thread.join().unwrap();
        ctrl.join().unwrap();
    }
}

//! Byte-level SOCKS4/4a and SOCKS5/5h client handshakes.
//!
//! Each `*_connect` runs the handshake over an already-open bidirectional
//! stream and returns once the proxy has established a transparent tunnel to
//! the target — after which the stream is a plain byte pipe to `host:port`.
//! References: RFC 1928 (SOCKS5), RFC 1929 (username/password auth), and the
//! de-facto SOCKS4/4a specification.

use std::io::{Read, Write};
use std::net::{IpAddr, ToSocketAddrs};

use crate::error::{Error, Result};

/// Resolve `host` to an IPv4 literal for SOCKS4 (which is IPv4-only).
fn resolve_ipv4(host: &str, port: u16) -> Result<[u8; 4]> {
    for addr in (host, port).to_socket_addrs()? {
        if let IpAddr::V4(v4) = addr.ip() {
            return Ok(v4.octets());
        }
    }
    Err(Error::BadResponse(format!(
        "socks4: {host} has no IPv4 address (SOCKS4 is IPv4-only; use socks5)"
    )))
}

/// SOCKS4 / SOCKS4a `CONNECT`. With `remote_dns` (4a) the proxy resolves
/// `host`; otherwise it is resolved locally to an IPv4 literal.
pub(crate) fn socks4_connect<S: Read + Write>(
    stream: &mut S,
    host: &str,
    port: u16,
    user: &str,
    remote_dns: bool,
) -> Result<()> {
    let mut req = Vec::with_capacity(16 + host.len());
    req.push(0x04); // VN = SOCKS4
    req.push(0x01); // CD = CONNECT
    req.extend_from_slice(&port.to_be_bytes());
    if remote_dns {
        // SOCKS4a: DSTIP = 0.0.0.x (x != 0) signals "resolve HOSTNAME".
        req.extend_from_slice(&[0, 0, 0, 1]);
    } else {
        req.extend_from_slice(&resolve_ipv4(host, port)?);
    }
    req.extend_from_slice(user.as_bytes());
    req.push(0x00); // USERID terminator
    if remote_dns {
        req.extend_from_slice(host.as_bytes());
        req.push(0x00); // HOSTNAME terminator
    }
    stream.write_all(&req)?;
    stream.flush()?;

    let mut reply = [0u8; 8];
    stream.read_exact(&mut reply)?;
    if reply[0] != 0x00 {
        return Err(Error::BadResponse(format!(
            "socks4: unexpected reply version byte {:#04x}",
            reply[0]
        )));
    }
    match reply[1] {
        0x5A => Ok(()), // request granted
        0x5B => Err(Error::BadResponse(
            "socks4: request rejected or failed".into(),
        )),
        0x5C => Err(Error::BadResponse(
            "socks4: rejected (proxy could not reach client identd)".into(),
        )),
        0x5D => Err(Error::BadResponse(
            "socks4: rejected (identd authentication failed)".into(),
        )),
        other => Err(Error::BadResponse(format!(
            "socks4: unknown reply code {other:#04x}"
        ))),
    }
}

/// SOCKS5 / SOCKS5h `CONNECT` (RFC 1928) with optional username/password auth
/// (RFC 1929). With `remote_dns` (5h) the hostname is sent as a domain
/// (ATYP=3) for the proxy to resolve; otherwise it is resolved locally.
pub(crate) fn socks5_connect<S: Read + Write>(
    stream: &mut S,
    host: &str,
    port: u16,
    auth: Option<(&str, &str)>,
    remote_dns: bool,
) -> Result<()> {
    // Greeting: offer NO-AUTH, plus USERNAME/PASSWORD when we have creds.
    let greeting: &[u8] = if auth.is_some() {
        &[0x05, 0x02, 0x00, 0x02]
    } else {
        &[0x05, 0x01, 0x00]
    };
    stream.write_all(greeting)?;
    stream.flush()?;

    let mut sel = [0u8; 2];
    stream.read_exact(&mut sel)?;
    if sel[0] != 0x05 {
        return Err(Error::BadResponse(format!(
            "socks5: bad version {:#04x} in method selection",
            sel[0]
        )));
    }
    match sel[1] {
        0x00 => {} // no authentication required
        0x02 => {
            let (user, pass) = auth.ok_or_else(|| {
                Error::BadResponse("socks5: proxy requires auth but none was provided".into())
            })?;
            if user.len() > 255 || pass.len() > 255 {
                return Err(Error::BadResponse(
                    "socks5: username/password exceeds 255 bytes".into(),
                ));
            }
            let mut a = Vec::with_capacity(3 + user.len() + pass.len());
            a.push(0x01); // auth subnegotiation version
            a.push(user.len() as u8);
            a.extend_from_slice(user.as_bytes());
            a.push(pass.len() as u8);
            a.extend_from_slice(pass.as_bytes());
            stream.write_all(&a)?;
            stream.flush()?;
            let mut ar = [0u8; 2];
            stream.read_exact(&mut ar)?;
            if ar[0] != 0x01 || ar[1] != 0x00 {
                return Err(Error::BadResponse(
                    "socks5: username/password authentication failed".into(),
                ));
            }
        }
        0xFF => {
            return Err(Error::BadResponse(
                "socks5: proxy offered no acceptable authentication method".into(),
            ))
        }
        other => {
            return Err(Error::BadResponse(format!(
                "socks5: proxy selected unsupported method {other:#04x}"
            )))
        }
    }

    // CONNECT request: VER CMD RSV ATYP DST.ADDR DST.PORT.
    let mut req = vec![0x05u8, 0x01, 0x00];
    if remote_dns {
        if host.len() > 255 {
            return Err(Error::BadResponse(
                "socks5h: hostname exceeds 255 bytes".into(),
            ));
        }
        req.push(0x03); // ATYP = domain name
        req.push(host.len() as u8);
        req.extend_from_slice(host.as_bytes());
    } else {
        let addr = (host, port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| Error::InvalidUrl(host.to_string()))?;
        match addr.ip() {
            IpAddr::V4(v4) => {
                req.push(0x01);
                req.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                req.push(0x04);
                req.extend_from_slice(&v6.octets());
            }
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req)?;
    stream.flush()?;

    // Reply: VER REP RSV ATYP BND.ADDR BND.PORT. We must consume the variable
    // BND.ADDR exactly, by ATYP, so the stream is left at the payload.
    let mut head = [0u8; 4];
    stream.read_exact(&mut head)?;
    if head[0] != 0x05 {
        return Err(Error::BadResponse(format!(
            "socks5: bad version {:#04x} in connect reply",
            head[0]
        )));
    }
    if head[1] != 0x00 {
        return Err(Error::BadResponse(format!(
            "socks5: connect failed ({})",
            socks5_reply_msg(head[1])
        )));
    }
    let bnd_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l)?;
            l[0] as usize
        }
        other => {
            return Err(Error::BadResponse(format!(
                "socks5: unknown ATYP {other:#04x} in connect reply"
            )))
        }
    };
    let mut bnd = vec![0u8; bnd_len + 2]; // BND.ADDR + BND.PORT
    stream.read_exact(&mut bnd)?;
    Ok(())
}

/// Human-readable text for a SOCKS5 reply code (RFC 1928 §6).
pub(crate) fn socks5_reply_msg(code: u8) -> &'static str {
    match code {
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A fake stream: reads come from a scripted reply buffer, writes are
    /// captured for assertion.
    struct Mock {
        reply: Cursor<Vec<u8>>,
        written: Vec<u8>,
    }
    impl Mock {
        fn new(reply: Vec<u8>) -> Self {
            Mock {
                reply: Cursor::new(reply),
                written: Vec::new(),
            }
        }
    }
    impl Read for Mock {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.reply.read(buf)
        }
    }
    impl Write for Mock {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn socks4a_request_bytes_and_grant() {
        // Reply: VN=0, CD=0x5A granted, port + ip ignored.
        let mut m = Mock::new(vec![0x00, 0x5A, 0, 0, 0, 0, 0, 0]);
        socks4_connect(&mut m, "example.com", 443, "bob", true).unwrap();
        let w = &m.written;
        assert_eq!(w[0], 0x04);
        assert_eq!(w[1], 0x01);
        assert_eq!(&w[2..4], &443u16.to_be_bytes());
        assert_eq!(&w[4..8], &[0, 0, 0, 1]); // 4a sentinel
        assert_eq!(&w[8..11], b"bob");
        assert_eq!(w[11], 0x00);
        assert_eq!(&w[12..23], b"example.com");
        assert_eq!(w[23], 0x00);
    }

    #[test]
    fn socks4_rejected_is_error() {
        let mut m = Mock::new(vec![0x00, 0x5B, 0, 0, 0, 0, 0, 0]);
        let err = socks4_connect(&mut m, "127.0.0.1", 80, "", false).unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)));
    }

    #[test]
    fn socks5_no_auth_domain_connect() {
        // Method select: 0x05 0x00 ; connect reply: VER REP RSV ATYP=1 + 4+2 zero bytes.
        let mut reply = vec![0x05, 0x00];
        reply.extend_from_slice(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        let mut m = Mock::new(reply);
        socks5_connect(&mut m, "example.com", 80, None, true).unwrap();
        let w = &m.written;
        assert_eq!(&w[0..3], &[0x05, 0x01, 0x00]); // greeting (no auth)
                                                   // Then the CONNECT request.
        assert_eq!(&w[3..6], &[0x05, 0x01, 0x00]);
        assert_eq!(w[6], 0x03); // domain
        assert_eq!(w[7], 11); // len("example.com")
        assert_eq!(&w[8..19], b"example.com");
        assert_eq!(&w[19..21], &80u16.to_be_bytes());
    }

    #[test]
    fn socks5_userpass_success_then_ipv6_bnd() {
        // method=0x02, auth ok (0x01 0x00), connect reply with IPv6 BND (ATYP=4 → 16 bytes).
        let mut reply = vec![0x05, 0x02, 0x01, 0x00];
        reply.extend_from_slice(&[0x05, 0x00, 0x00, 0x04]);
        reply.extend_from_slice(&[0u8; 16 + 2]);
        let mut m = Mock::new(reply);
        socks5_connect(&mut m, "1.2.3.4", 8080, Some(("u", "p")), false).unwrap();
        let w = &m.written;
        // greeting offers both methods
        assert_eq!(&w[0..4], &[0x05, 0x02, 0x00, 0x02]);
        // auth block: ver, ulen, 'u', plen, 'p'
        assert_eq!(&w[4..9], &[0x01, 0x01, b'u', 0x01, b'p']);
        // connect with IPv4 literal (local DNS)
        assert_eq!(w[9], 0x05);
        assert_eq!(w[12], 0x01); // ATYP IPv4
        assert_eq!(&w[13..17], &[1, 2, 3, 4]);
    }

    #[test]
    fn socks5_auth_failure_is_error() {
        let reply = vec![0x05, 0x02, 0x01, 0x01]; // auth status != 0
        let mut m = Mock::new(reply);
        let err = socks5_connect(&mut m, "h", 1, Some(("u", "p")), true).unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)));
    }

    #[test]
    fn socks5_connect_refused_is_error() {
        let mut reply = vec![0x05, 0x00];
        reply.extend_from_slice(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]); // REP=5
        let mut m = Mock::new(reply);
        let err = socks5_connect(&mut m, "h", 1, None, true).unwrap_err();
        match err {
            Error::BadResponse(msg) => assert!(msg.contains("refused")),
            _ => panic!("expected BadResponse"),
        }
    }
}

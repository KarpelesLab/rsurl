//! Minimal TELNET (RFC 854) client.
//!
//! `telnet://host[:port]`. Optional input (from `-d`/`-T`/stdin) is sent after
//! connecting (with literal `0xFF` bytes doubled to `IAC IAC`, as RFC 854
//! requires); received data is returned with TELNET command sequences
//! stripped. Option negotiation is handled by refusing every option the server
//! offers or requests (answering `WILL` with `DONT` and `DO` with `WONT`), which
//! is enough for line-oriented banners and simple scripted exchanges. This is
//! not an interactive terminal.

use std::io::{Read, Write};

use crate::error::{Error, Result};
use crate::net::NetConfig;
use crate::url::Url;

const IAC: u8 = 255;
const DONT: u8 = 254;
const DO: u8 = 253;
const WONT: u8 = 252;
const WILL: u8 = 251;
const SB: u8 = 250;
const SE: u8 = 240;

/// Largest response we buffer (mirrors other protocols' 64 MiB cap).
const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

/// Where the receive-side parser is inside the TELNET command stream. Kept
/// across reads, so a command sequence split over two TCP segments (or two
/// 8 KiB reads) is still recognised instead of leaking into the data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Plain application data.
    Data,
    /// Saw `IAC`; the next byte is the command.
    Iac,
    /// Saw `IAC WILL|WONT|DO|DONT`; the next byte is the option.
    Opt(u8),
    /// Inside a subnegotiation (`IAC SB ...`), skipping until `IAC SE`.
    Sb,
    /// Saw `IAC` inside a subnegotiation.
    SbIac,
}

/// Incremental TELNET receive parser.
struct Parser {
    state: State,
}

impl Parser {
    fn new() -> Self {
        Parser { state: State::Data }
    }

    /// Consume `input`, appending application data to `out` and any
    /// negotiation replies (refusals) to `replies`.
    fn feed(&mut self, input: &[u8], out: &mut Vec<u8>, replies: &mut Vec<u8>) {
        for &b in input {
            self.state = match (self.state, b) {
                (State::Data, IAC) => State::Iac,
                (State::Data, _) => {
                    out.push(b);
                    State::Data
                }
                // `IAC IAC` is an escaped literal 0xFF data byte.
                (State::Iac, IAC) => {
                    out.push(IAC);
                    State::Data
                }
                (State::Iac, WILL | WONT | DO | DONT) => State::Opt(b),
                (State::Iac, SB) => State::Sb,
                // Any other two-byte command (NOP, GA, ...): ignore.
                (State::Iac, _) => State::Data,
                (State::Opt(cmd), opt) => {
                    match cmd {
                        // Refuse whatever the server offers or asks for. WONT
                        // and DONT only confirm the default (disabled) state,
                        // so they need no answer (RFC 1143).
                        WILL => replies.extend_from_slice(&[IAC, DONT, opt]),
                        DO => replies.extend_from_slice(&[IAC, WONT, opt]),
                        _ => {}
                    }
                    State::Data
                }
                (State::Sb, IAC) => State::SbIac,
                (State::Sb, _) => State::Sb,
                (State::SbIac, SE) => State::Data,
                // `IAC IAC` inside SB is escaped data; anything else, keep
                // skipping.
                (State::SbIac, _) => State::Sb,
            };
        }
    }
}

/// Escape outgoing data: every literal `0xFF` must be sent as `IAC IAC`, or
/// the server would parse it as the start of a command.
fn escape_iac(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    for &b in input {
        out.push(b);
        if b == IAC {
            out.push(IAC);
        }
    }
    out
}

/// Connect, send `input`, and return the received application data with TELNET
/// command bytes removed.
pub(crate) fn run(url: &Url, input: &[u8], cfg: &NetConfig) -> Result<Vec<u8>> {
    if url.scheme != "telnet" {
        return Err(Error::UnsupportedScheme(url.scheme.clone()));
    }
    let mut sock = cfg.connect(&url.host, url.port)?;
    if !input.is_empty() {
        sock.write_all(&escape_iac(input))?;
        sock.flush()?;
    }

    let mut out: Vec<u8> = Vec::new();
    let mut buf = [0u8; 8192];
    let mut parser = Parser::new();
    loop {
        let n = sock.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let mut replies: Vec<u8> = Vec::new();
        parser.feed(&buf[..n], &mut out, &mut replies);
        if !replies.is_empty() {
            sock.write_all(&replies)?;
            sock.flush()?;
        }
        if out.len() > MAX_RESPONSE_BYTES {
            return Err(Error::BadResponse(format!(
                "telnet: response exceeds {MAX_RESPONSE_BYTES} bytes"
            )));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iac_negotiation_is_stripped_and_refused() {
        // "Hi" + IAC WILL ECHO(1) + "!" + IAC IAC (literal 0xFF) + IAC DO 24.
        let data = [b'H', b'i', IAC, WILL, 1, b'!', IAC, IAC, IAC, DO, 24];
        let (mut out, mut replies) = (Vec::new(), Vec::new());
        Parser::new().feed(&data, &mut out, &mut replies);
        assert_eq!(out, vec![b'H', b'i', b'!', IAC]);
        assert_eq!(replies, vec![IAC, DONT, 1, IAC, WONT, 24]);
    }

    #[test]
    fn sequences_split_at_every_byte_boundary_parse_identically() {
        let data = [
            b'a', IAC, WILL, 3, b'b', IAC, SB, 24, 1, IAC, IAC, IAC, SE, b'c', IAC, IAC, b'd',
        ];
        let (mut want_out, mut want_rep) = (Vec::new(), Vec::new());
        Parser::new().feed(&data, &mut want_out, &mut want_rep);
        assert_eq!(want_out, vec![b'a', b'b', b'c', IAC, b'd']);
        assert_eq!(want_rep, vec![IAC, DONT, 3]);
        for split in 0..=data.len() {
            let mut p = Parser::new();
            let (mut out, mut rep) = (Vec::new(), Vec::new());
            p.feed(&data[..split], &mut out, &mut rep);
            p.feed(&data[split..], &mut out, &mut rep);
            assert_eq!(
                (out, rep),
                (want_out.clone(), want_rep.clone()),
                "split {split}"
            );
        }
    }

    #[test]
    fn escape_iac_doubles_ff() {
        assert_eq!(escape_iac(&[1, IAC, 2]), vec![1, IAC, IAC, 2]);
    }

    /// Drive the real `run()` against a server that deliberately splits IAC
    /// sequences across TCP writes, and check the wire in both directions.
    #[test]
    fn run_handles_split_sequences_and_escapes_input() {
        use std::net::TcpListener;
        use std::time::Duration;
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            s.set_nodelay(true).unwrap();
            let mut got = vec![0u8; 3];
            s.read_exact(&mut got).unwrap();
            for chunk in [
                &[b'x', IAC][..],
                &[WILL][..],
                &[1, b'y', IAC, SB][..],
                &[5, IAC][..],
                &[SE, b'z'][..],
            ] {
                s.write_all(chunk).unwrap();
                std::thread::sleep(Duration::from_millis(30));
            }
            s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut reply = [0u8; 3];
            s.read_exact(&mut reply).unwrap();
            (got, reply)
        });
        let url = Url::parse(&format!("telnet://127.0.0.1:{port}")).unwrap();
        let out = run(&url, &[b'q', IAC], &NetConfig::default()).unwrap();
        let (sent, reply) = h.join().unwrap();
        assert_eq!(out, b"xyz");
        assert_eq!(
            sent,
            vec![b'q', IAC, IAC],
            "0xFF must be doubled on the wire"
        );
        assert_eq!(reply, [IAC, DONT, 1]);
    }
}

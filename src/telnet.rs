//! Minimal TELNET (RFC 854) client.
//!
//! `telnet://host[:port]`. Optional input (from `-d`/`-T`/stdin) is sent after
//! connecting; received data is returned with TELNET command sequences
//! stripped. Option negotiation is handled by refusing every option (respond
//! `WONT`/`DONT`), which is enough for line-oriented banners and simple
//! scripted exchanges. This is not an interactive terminal.

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

/// Connect, send `input`, and return the received application data with TELNET
/// command bytes removed.
pub(crate) fn run(url: &Url, input: &[u8], cfg: &NetConfig) -> Result<Vec<u8>> {
    if url.scheme != "telnet" {
        return Err(Error::UnsupportedScheme(url.scheme.clone()));
    }
    let mut sock = cfg.connect(&url.host, url.port)?;
    if !input.is_empty() {
        sock.write_all(input)?;
        sock.flush()?;
    }

    let mut out: Vec<u8> = Vec::new();
    let mut buf = [0u8; 8192];
    // Pending negotiation responses to flush back to the server.
    loop {
        let n = sock.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let mut replies: Vec<u8> = Vec::new();
        let mut i = 0;
        while i < n {
            let b = buf[i];
            if b != IAC {
                out.push(b);
                i += 1;
                continue;
            }
            // IAC sequence.
            let cmd = match buf.get(i + 1) {
                Some(&c) => c,
                None => break, // truncated; next read continues
            };
            match cmd {
                IAC => {
                    // Escaped literal 0xFF data byte.
                    out.push(IAC);
                    i += 2;
                }
                WILL | WONT => {
                    // Refuse: respond DONT <opt>.
                    if let Some(&opt) = buf.get(i + 2) {
                        replies.extend_from_slice(&[IAC, DONT, opt]);
                        i += 3;
                    } else {
                        break;
                    }
                }
                DO | DONT => {
                    // Refuse: respond WONT <opt>.
                    if let Some(&opt) = buf.get(i + 2) {
                        replies.extend_from_slice(&[IAC, WONT, opt]);
                        i += 3;
                    } else {
                        break;
                    }
                }
                SB => {
                    // Skip subnegotiation until IAC SE.
                    let mut j = i + 2;
                    while j + 1 < n && !(buf[j] == IAC && buf[j + 1] == SE) {
                        j += 1;
                    }
                    i = j + 2;
                }
                _ => i += 2, // other 2-byte command, ignore
            }
        }
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

    // The same IAC-stripping loop `run` uses, exercised inline (the network
    // path is covered by an integration test).
    #[test]
    fn iac_negotiation_is_stripped_and_refused() {
        // "Hi" + IAC WILL ECHO(1) + "!" + IAC IAC (literal 0xFF) .
        let data = [b'H', b'i', IAC, WILL, 1, b'!', IAC, IAC];
        let mut out = Vec::new();
        let mut replies = Vec::new();
        let mut i = 0;
        while i < data.len() {
            let b = data[i];
            if b != IAC {
                out.push(b);
                i += 1;
                continue;
            }
            match data.get(i + 1).copied() {
                Some(IAC) => {
                    out.push(IAC);
                    i += 2;
                }
                Some(WILL) | Some(WONT) => {
                    replies.extend_from_slice(&[IAC, DONT, data[i + 2]]);
                    i += 3;
                }
                _ => i += 2,
            }
        }
        assert_eq!(out, vec![b'H', b'i', b'!', IAC]);
        assert_eq!(replies, vec![IAC, DONT, 1]);
    }
}

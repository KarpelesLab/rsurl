//! RTSP support (RFC 7826, also RFC 2326 for RTSP/1.0).
//!
//! RTSP is HTTP-like over TCP (default port 554) with a request/response
//! shape similar to HTTP/1.x but its own methods (DESCRIBE, SETUP, PLAY, ...).
//! URL: `rtsp://host[:554]/streamid`.
//!
//! This module currently implements only the most basic operation: a single
//! `DESCRIBE` request that returns the response body (typically an SDP
//! document describing the media streams available at that URL). It does not
//! implement the full session lifecycle (SETUP/PLAY/PAUSE/TEARDOWN),
//! interleaved RTP framing over the control connection, or any form of
//! authentication.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::url::Url;

const DEFAULT_USER_AGENT: &str = concat!("rsurl/", env!("CARGO_PKG_VERSION"));
const DEFAULT_PORT: u16 = 554;
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(60);

/// Default operation: issue an RTSP `DESCRIBE` and return the response body
/// (typically an SDP document).
pub fn fetch(url: &Url) -> Result<Vec<u8>> {
    let addr = format!("{}:{}", url.host, url.port);
    let sock = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| Error::InvalidUrl(url.host.clone()))?;
    // `url.host` and `url.path` are interpolated raw into the
    // `DESCRIBE <uri> RTSP/1.0` request line and the `Host`-style URI. A bare
    // CR, LF, NUL, or other control byte would let an attacker forge the
    // request line or inject extra headers, so reject them up front.
    reject_control_bytes(&url.host, "host")?;
    reject_control_bytes(&url.path, "path")?;

    let stream = TcpStream::connect_timeout(&sock, CONNECT_TIMEOUT)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;

    let request = build_describe_request(url);
    let mut writer = &stream;
    writer.write_all(request.as_bytes())?;
    writer.flush()?;

    let reader = BufReader::new(&stream);
    read_response_body(reader)
}

/// Reject any ASCII control byte (including CR, LF, and NUL) in a
/// URL-derived RTSP request field, returning [`Error::InvalidUrl`]. This
/// prevents request-line / header CRLF injection on the control connection.
fn reject_control_bytes(value: &str, field: &str) -> Result<()> {
    if value.bytes().any(|b| b.is_ascii_control()) {
        return Err(Error::InvalidUrl(format!("rtsp: control byte in {field}")));
    }
    Ok(())
}

/// Reconstruct the absolute request-URI for use on the RTSP request line.
///
/// This is `rtsp://<host>[:<port>]<path>` with userinfo stripped. The port
/// is omitted when it is the RTSP default (554), which matches what most
/// servers expect to see on the wire.
fn request_uri(url: &Url) -> String {
    if url.port == DEFAULT_PORT {
        format!("rtsp://{}{}", url.host, url.path)
    } else {
        format!("rtsp://{}:{}{}", url.host, url.port, url.path)
    }
}

/// Build a complete DESCRIBE request, including the trailing blank line.
fn build_describe_request(url: &Url) -> String {
    let uri = request_uri(url);
    format!(
        "DESCRIBE {uri} RTSP/1.0\r\n\
         CSeq: 1\r\n\
         Accept: application/sdp\r\n\
         User-Agent: {DEFAULT_USER_AGENT}\r\n\
         \r\n"
    )
}

/// Parse a status line of the form `RTSP/<ver> <status> <reason>`.
fn parse_status_line(line: &str) -> Result<(String, u16, String)> {
    let mut parts = line.splitn(3, ' ');
    let version = parts
        .next()
        .ok_or_else(|| Error::BadResponse(format!("missing version: {line:?}")))?
        .to_string();
    if !version.starts_with("RTSP/") {
        return Err(Error::BadResponse(format!("not RTSP: {version}")));
    }
    let status_str = parts
        .next()
        .ok_or_else(|| Error::BadResponse(format!("missing status: {line:?}")))?;
    let status: u16 = status_str
        .parse()
        .map_err(|_| Error::BadResponse(format!("bad status: {line:?}")))?;
    let reason = parts.next().unwrap_or("").to_string();
    Ok((version, status, reason))
}

/// Read a full RTSP response from `r` and return the body bytes. The status
/// line must be 2xx; headers are parsed until the blank line; the body is
/// then read using `Content-Length` (RTSP does not use chunked encoding).
fn read_response_body<R: Read>(reader: BufReader<R>) -> Result<Vec<u8>> {
    let mut r = reader;

    let mut status_line = String::new();
    let n = r.read_line(&mut status_line)?;
    if n == 0 {
        return Err(Error::UnexpectedEof);
    }
    let (_version, status, reason) = parse_status_line(status_line.trim_end_matches(['\r', '\n']))?;
    if !(200..300).contains(&status) {
        return Err(Error::BadResponse(format!("rtsp: {status} {reason}")));
    }

    let mut headers: Vec<(String, String)> = Vec::new();
    let mut header_bytes = 0usize;
    loop {
        let mut line = String::new();
        let n = r.read_line(&mut line)?;
        if n == 0 {
            return Err(Error::UnexpectedEof);
        }
        header_bytes += n;
        if header_bytes > MAX_HEADER_BYTES {
            return Err(Error::BadResponse("headers exceed 64 KiB".into()));
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        let (k, v) = trimmed
            .split_once(':')
            .ok_or_else(|| Error::BadResponse(format!("malformed header line: {trimmed:?}")))?;
        headers.push((k.trim().to_string(), v.trim().to_string()));
    }

    let content_length = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<u64>().ok())
        .unwrap_or(0);

    if content_length as usize > MAX_BODY_BYTES {
        return Err(Error::BadResponse(format!(
            "body too large: {content_length}"
        )));
    }

    let mut body = Vec::with_capacity(content_length as usize);
    if content_length > 0 {
        r.take(content_length).read_to_end(&mut body)?;
        if (body.len() as u64) < content_length {
            return Err(Error::UnexpectedEof);
        }
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn request_uri_default_port_is_omitted() {
        let u = url("rtsp://example.com/media.mp4");
        assert_eq!(request_uri(&u), "rtsp://example.com/media.mp4");
    }

    #[test]
    fn request_uri_keeps_non_default_port() {
        let u = url("rtsp://example.com:8554/stream");
        assert_eq!(request_uri(&u), "rtsp://example.com:8554/stream");
    }

    #[test]
    fn request_uri_strips_userinfo() {
        let u = url("rtsp://alice:secret@cam.local/axis-media/media.amp");
        assert_eq!(request_uri(&u), "rtsp://cam.local/axis-media/media.amp");
    }

    #[test]
    fn request_uri_preserves_query_in_path() {
        let u = url("rtsp://example.com/stream?token=abc");
        assert_eq!(request_uri(&u), "rtsp://example.com/stream?token=abc");
    }

    #[test]
    fn build_describe_request_shape() {
        let u = url("rtsp://example.com/foo");
        let req = build_describe_request(&u);
        assert!(req.starts_with("DESCRIBE rtsp://example.com/foo RTSP/1.0\r\n"));
        assert!(req.contains("\r\nCSeq: 1\r\n"));
        assert!(req.contains("\r\nAccept: application/sdp\r\n"));
        assert!(req.contains("\r\nUser-Agent: rsurl/"));
        assert!(req.ends_with("\r\n\r\n"));
    }

    #[test]
    fn reject_control_bytes_flags_crlf() {
        assert!(reject_control_bytes("exa\r\nmple.com", "host").is_err());
        assert!(reject_control_bytes("/path\nDESCRIBE", "path").is_err());
        assert!(reject_control_bytes("/path\rfoo", "path").is_err());
        // NUL is a control byte too.
        assert!(reject_control_bytes("ho\0st", "host").is_err());
        // Clean values pass.
        assert!(reject_control_bytes("example.com", "host").is_ok());
        assert!(reject_control_bytes("/axis-media/media.amp", "path").is_ok());
    }

    #[test]
    fn reject_control_bytes_returns_invalid_url() {
        let err = reject_control_bytes("a\r\nb", "host").unwrap_err();
        assert!(matches!(err, Error::InvalidUrl(_)));
    }

    #[test]
    fn parse_status_line_ok() {
        let (v, s, r) = parse_status_line("RTSP/1.0 200 OK").unwrap();
        assert_eq!(v, "RTSP/1.0");
        assert_eq!(s, 200);
        assert_eq!(r, "OK");
    }

    #[test]
    fn parse_status_line_no_reason() {
        let (_, s, r) = parse_status_line("RTSP/1.0 204").unwrap();
        assert_eq!(s, 204);
        assert_eq!(r, "");
    }

    #[test]
    fn parse_status_line_with_multiword_reason() {
        let (_, s, r) = parse_status_line("RTSP/1.0 404 Stream Not Found").unwrap();
        assert_eq!(s, 404);
        assert_eq!(r, "Stream Not Found");
    }

    #[test]
    fn parse_status_line_rejects_http() {
        assert!(parse_status_line("HTTP/1.1 200 OK").is_err());
    }

    #[test]
    fn parse_status_line_rejects_bad_status() {
        assert!(parse_status_line("RTSP/1.0 abc OK").is_err());
    }

    #[test]
    fn end_to_end_parses_sdp_body() {
        let sdp = "v=0\r\n\
                   o=- 0 0 IN IP4 127.0.0.1\r\n\
                   s=Demo\r\n\
                   t=0 0\r\n\
                   m=video 0 RTP/AVP 96\r\n";
        let response = format!(
            "RTSP/1.0 200 OK\r\n\
             CSeq: 1\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {sdp}",
            sdp.len()
        );
        let reader = BufReader::new(Cursor::new(response.into_bytes()));
        let body = read_response_body(reader).unwrap();
        assert_eq!(body, sdp.as_bytes());
    }

    #[test]
    fn end_to_end_rejects_non_2xx() {
        let response = b"RTSP/1.0 404 Not Found\r\n\
                         CSeq: 1\r\n\
                         Content-Length: 0\r\n\
                         \r\n";
        let reader = BufReader::new(Cursor::new(response.to_vec()));
        let err = read_response_body(reader).unwrap_err();
        match err {
            Error::BadResponse(msg) => assert!(msg.contains("404"), "got {msg:?}"),
            other => panic!("expected BadResponse, got {other:?}"),
        }
    }

    #[test]
    fn end_to_end_no_content_length_yields_empty_body() {
        // RTSP responses without Content-Length (e.g. simple ack of a method)
        // should still parse cleanly with an empty body.
        let response = b"RTSP/1.0 200 OK\r\n\
                         CSeq: 2\r\n\
                         \r\n";
        let reader = BufReader::new(Cursor::new(response.to_vec()));
        let body = read_response_body(reader).unwrap();
        assert!(body.is_empty());
    }

    #[test]
    fn end_to_end_unexpected_eof_in_body() {
        // Content-Length claims 100 bytes but stream ends after 5.
        let response = b"RTSP/1.0 200 OK\r\n\
                         Content-Length: 100\r\n\
                         \r\n\
                         short";
        let reader = BufReader::new(Cursor::new(response.to_vec()));
        let err = read_response_body(reader).unwrap_err();
        assert!(matches!(err, Error::UnexpectedEof));
    }

    #[test]
    fn end_to_end_unexpected_eof_before_status() {
        let reader = BufReader::new(Cursor::new(Vec::<u8>::new()));
        let err = read_response_body(reader).unwrap_err();
        assert!(matches!(err, Error::UnexpectedEof));
    }
}

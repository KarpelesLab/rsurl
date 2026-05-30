//! RTSP support (RFC 7826, also RFC 2326 for RTSP/1.0).
//!
//! RTSP is HTTP-like over TCP (default port 554) with a request/response
//! shape similar to HTTP/1.x but its own methods (DESCRIBE, SETUP, PLAY, ...).
//! URL: `rtsp://host[:554]/streamid`.
//!
//! This module implements the RTSP control-channel session lifecycle:
//! `OPTIONS`, `DESCRIBE`, `SETUP`, `PLAY`, and `TEARDOWN`. Requests share a
//! single TCP connection through the [`Session`] type, which tracks a
//! monotonically increasing `CSeq` (verified against each response) and the
//! `Session` id returned by `SETUP` (echoed back on `PLAY`/`TEARDOWN`). The
//! transport offered on `SETUP` is the widely supported interleaved form
//! `RTP/AVP/TCP;unicast;interleaved=0-1`.
//!
//! It does **not** implement interleaved RTP media reception over the control
//! connection, PAUSE/RECORD/GET_PARAMETER, or any form of authentication —
//! the goal here is a correct control-channel handshake (SETUP returns a
//! Session, PLAY succeeds with it), not media transport.

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

/// Default interleaved (RTP-over-TCP) transport offered on `SETUP`. The
/// control connection multiplexes channels 0 and 1; this is the form most
/// widely accepted by servers that don't want to negotiate UDP ports.
const DEFAULT_TRANSPORT: &str = "RTP/AVP/TCP;unicast;interleaved=0-1";

/// A parsed RTSP response: status line, headers, and the (possibly empty)
/// Content-Length-bounded body.
#[derive(Debug, Clone)]
pub struct RtspResponse {
    /// The protocol token from the status line, e.g. `RTSP/1.0`.
    pub version: String,
    /// Numeric status code (e.g. `200`).
    pub status: u16,
    /// Reason phrase (may be empty).
    pub reason: String,
    /// Response headers, in order, with names/values trimmed.
    pub headers: Vec<(String, String)>,
    /// Response body (empty when there is no `Content-Length`).
    pub body: Vec<u8>,
}

impl RtspResponse {
    /// First header value matching `name` (case-insensitive), trimmed.
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// An RTSP control-channel session over a single TCP connection.
///
/// Tracks the next `CSeq` to send (monotonically increasing, starting at 1)
/// and the `Session` id once `SETUP` has established one. Every response's
/// `CSeq` is parsed and verified against the request's; a mismatch is an
/// error.
pub struct Session {
    stream: TcpStream,
    /// Absolute request-URI used on every request line.
    uri: String,
    /// Next CSeq value to emit. Starts at 1, increments per request.
    cseq: u32,
    /// Session id captured from a `SETUP` response (timeout parameter
    /// stripped). Echoed on subsequent `PLAY`/`TEARDOWN`.
    session_id: Option<String>,
}

impl Session {
    /// Connect to the RTSP server identified by `url` and prepare a session.
    ///
    /// The host and path are validated for control bytes up front (see
    /// `reject_control_bytes`) so they cannot forge the request line or
    /// inject headers on the control connection.
    pub fn connect(url: &Url) -> Result<Self> {
        // `url.host` and `url.path` are interpolated raw into the request
        // line and the absolute URI. A bare CR, LF, NUL, or other control
        // byte would let an attacker forge the request line or inject extra
        // headers, so reject them up front.
        reject_control_bytes(&url.host, "host")?;
        reject_control_bytes(&url.path, "path")?;

        let addr = format!("{}:{}", url.host, url.port);
        let sock = addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| Error::InvalidUrl(url.host.clone()))?;
        let stream = TcpStream::connect_timeout(&sock, CONNECT_TIMEOUT)?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;

        Ok(Session {
            stream,
            uri: request_uri(url),
            cseq: 1,
            session_id: None,
        })
    }

    /// The session id established by `SETUP`, if any.
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    /// Send one request with `method` and `extra_headers` (each `(name,
    /// value)`), read the response, verify its `CSeq` matches the request's,
    /// and reject any non-2xx status. The session's CSeq counter advances by
    /// one on every call.
    fn request(&mut self, method: &str, extra_headers: &[(&str, String)]) -> Result<RtspResponse> {
        let cseq = self.cseq;
        self.cseq += 1;
        let request = build_request(method, &self.uri, cseq, extra_headers);

        let mut writer = &self.stream;
        writer.write_all(request.as_bytes())?;
        writer.flush()?;

        let reader = BufReader::new(&self.stream);
        let resp = read_response(reader)?;

        // Verify the echoed CSeq matches what we sent.
        let resp_cseq = resp
            .header("CSeq")
            .ok_or_else(|| Error::BadResponse("rtsp: response missing CSeq".into()))?;
        let resp_cseq: u32 = resp_cseq
            .trim()
            .parse()
            .map_err(|_| Error::BadResponse(format!("rtsp: bad CSeq: {resp_cseq:?}")))?;
        if resp_cseq != cseq {
            return Err(Error::BadResponse(format!(
                "rtsp: CSeq mismatch: sent {cseq}, got {resp_cseq}"
            )));
        }

        if !(200..300).contains(&resp.status) {
            return Err(Error::BadResponse(format!(
                "rtsp: {} {}",
                resp.status, resp.reason
            )));
        }
        Ok(resp)
    }

    /// `OPTIONS` — query the methods the server supports. No session needed.
    pub fn options(&mut self) -> Result<RtspResponse> {
        self.request("OPTIONS", &[])
    }

    /// `DESCRIBE` — fetch the media description (typically SDP).
    pub fn describe(&mut self) -> Result<RtspResponse> {
        self.request("DESCRIBE", &[("Accept", "application/sdp".to_string())])
    }

    /// `SETUP` — establish transport for the stream. Offers
    /// `DEFAULT_TRANSPORT` and captures the `Session` id from the response
    /// (stripping any `;timeout=` parameter) for later requests.
    pub fn setup(&mut self) -> Result<RtspResponse> {
        let resp = self.request("SETUP", &[("Transport", DEFAULT_TRANSPORT.to_string())])?;
        let session = resp
            .header("Session")
            .ok_or_else(|| Error::BadResponse("rtsp: SETUP response missing Session".into()))?;
        self.session_id = Some(parse_session_id(session).to_string());
        Ok(resp)
    }

    /// `PLAY` — start delivery of the stream. Requires a prior `SETUP`;
    /// echoes the captured `Session` id and requests the full timeline via
    /// `Range: npt=0.000-`.
    pub fn play(&mut self) -> Result<RtspResponse> {
        let session = self.session_id.clone().ok_or_else(|| {
            Error::BadResponse("rtsp: PLAY requires a SETUP session first".into())
        })?;
        self.request(
            "PLAY",
            &[("Session", session), ("Range", "npt=0.000-".to_string())],
        )
    }

    /// `TEARDOWN` — release the session. Requires a prior `SETUP`; echoes the
    /// captured `Session` id and clears it on success.
    pub fn teardown(&mut self) -> Result<RtspResponse> {
        let session = self.session_id.clone().ok_or_else(|| {
            Error::BadResponse("rtsp: TEARDOWN requires a SETUP session first".into())
        })?;
        let resp = self.request("TEARDOWN", &[("Session", session)])?;
        self.session_id = None;
        Ok(resp)
    }
}

/// Default operation: issue an RTSP `DESCRIBE` and return the response body
/// (typically an SDP document).
pub fn fetch(url: &Url) -> Result<Vec<u8>> {
    let mut session = Session::connect(url)?;
    session.describe().map(|r| r.body)
}

/// Run the RTSP `method` against `url` and return the response body that a
/// CLI should print.
///
/// `OPTIONS` and `DESCRIBE` are single requests. `SETUP`, `PLAY`, and
/// `TEARDOWN` require session state that cannot survive between one-shot CLI
/// processes, so selecting one of them runs the full handshake on a single
/// connection — `OPTIONS` → `DESCRIBE` → `SETUP` → `PLAY` (→ `TEARDOWN`) — and
/// returns the body of the named method's response. This keeps a one-shot
/// invocation honest: a `SETUP` only ever succeeds with a real session, and a
/// `PLAY` only ever runs after a `SETUP` returned one.
pub fn run_method(url: &Url, method: &str) -> Result<Vec<u8>> {
    let upper = method.to_ascii_uppercase();
    let mut session = Session::connect(url)?;
    match upper.as_str() {
        "OPTIONS" => session.options().map(|r| r.body),
        "DESCRIBE" => session.describe().map(|r| r.body),
        "SETUP" => {
            session.options()?;
            session.describe()?;
            session.setup().map(|r| r.body)
        }
        "PLAY" => {
            session.options()?;
            session.describe()?;
            session.setup()?;
            session.play().map(|r| r.body)
        }
        "TEARDOWN" => {
            session.options()?;
            session.describe()?;
            session.setup()?;
            session.play()?;
            session.teardown().map(|r| r.body)
        }
        other => Err(Error::BadResponse(format!(
            "rtsp: unsupported method {other:?} (expected OPTIONS, DESCRIBE, SETUP, PLAY, or TEARDOWN)"
        ))),
    }
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

/// Build a complete RTSP request for `method` against `uri` with the given
/// `cseq` and `extra_headers`, including the trailing blank line.
///
/// `CSeq` and `User-Agent` are always emitted; callers pass method-specific
/// headers (`Accept`, `Transport`, `Session`, `Range`, ...) via
/// `extra_headers`.
fn build_request(method: &str, uri: &str, cseq: u32, extra_headers: &[(&str, String)]) -> String {
    let mut req = format!(
        "{method} {uri} RTSP/1.0\r\n\
         CSeq: {cseq}\r\n"
    );
    for (k, v) in extra_headers {
        req.push_str(k);
        req.push_str(": ");
        req.push_str(v);
        req.push_str("\r\n");
    }
    req.push_str("User-Agent: ");
    req.push_str(DEFAULT_USER_AGENT);
    req.push_str("\r\n\r\n");
    req
}

/// Extract the session id from a `Session:` header value, dropping any
/// `;timeout=…` (or other `;`-separated) parameter. E.g.
/// `12345678;timeout=60` → `12345678`.
fn parse_session_id(value: &str) -> &str {
    value.split(';').next().unwrap_or(value).trim()
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

/// Read a full RTSP response from `r`: the status line, the headers (until the
/// blank line), and the `Content-Length`-bounded body (RTSP does not use
/// chunked encoding). Status validation and CSeq checks are the caller's job.
fn read_response<R: Read>(reader: BufReader<R>) -> Result<RtspResponse> {
    let mut r = reader;

    let mut status_line = String::new();
    let n = r.read_line(&mut status_line)?;
    if n == 0 {
        return Err(Error::UnexpectedEof);
    }
    let (version, status, reason) = parse_status_line(status_line.trim_end_matches(['\r', '\n']))?;

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
    Ok(RtspResponse {
        version,
        status,
        reason,
        headers,
        body,
    })
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

    // ---- build_request (generalized builder) ----------------------------

    #[test]
    fn build_request_describe_shape() {
        let req = build_request(
            "DESCRIBE",
            "rtsp://example.com/foo",
            1,
            &[("Accept", "application/sdp".to_string())],
        );
        assert!(req.starts_with("DESCRIBE rtsp://example.com/foo RTSP/1.0\r\n"));
        assert!(req.contains("\r\nCSeq: 1\r\n"));
        assert!(req.contains("\r\nAccept: application/sdp\r\n"));
        assert!(req.contains("\r\nUser-Agent: rsurl/"));
        assert!(req.ends_with("\r\n\r\n"));
    }

    #[test]
    fn build_request_emits_method_and_cseq() {
        let req = build_request("OPTIONS", "rtsp://h/s", 7, &[]);
        assert!(req.starts_with("OPTIONS rtsp://h/s RTSP/1.0\r\n"));
        assert!(req.contains("\r\nCSeq: 7\r\n"));
        // No extra headers means straight to User-Agent.
        assert!(!req.contains("Accept:"));
    }

    #[test]
    fn build_request_setup_includes_transport() {
        let req = build_request(
            "SETUP",
            "rtsp://h/s",
            2,
            &[("Transport", DEFAULT_TRANSPORT.to_string())],
        );
        assert!(req.starts_with("SETUP rtsp://h/s RTSP/1.0\r\n"));
        assert!(req.contains("\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n"));
    }

    #[test]
    fn build_request_play_includes_session_and_range() {
        let req = build_request(
            "PLAY",
            "rtsp://h/s",
            3,
            &[
                ("Session", "ABC123".to_string()),
                ("Range", "npt=0.000-".to_string()),
            ],
        );
        assert!(req.contains("\r\nSession: ABC123\r\n"));
        assert!(req.contains("\r\nRange: npt=0.000-\r\n"));
    }

    // ---- parse_session_id ------------------------------------------------

    #[test]
    fn parse_session_id_plain() {
        assert_eq!(parse_session_id("12345678"), "12345678");
    }

    #[test]
    fn parse_session_id_strips_timeout() {
        assert_eq!(parse_session_id("12345678;timeout=60"), "12345678");
    }

    #[test]
    fn parse_session_id_trims_whitespace() {
        assert_eq!(parse_session_id("  abc ; timeout=30 "), "abc");
    }

    // ---- reject_control_bytes -------------------------------------------

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

    // ---- parse_status_line ----------------------------------------------

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

    // ---- read_response ---------------------------------------------------

    #[test]
    fn read_response_parses_sdp_body() {
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
        let resp = read_response(reader).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.header("CSeq"), Some("1"));
        assert_eq!(resp.body, sdp.as_bytes());
    }

    #[test]
    fn read_response_no_content_length_yields_empty_body() {
        // RTSP responses without Content-Length (e.g. simple ack of a method)
        // should still parse cleanly with an empty body.
        let response = b"RTSP/1.0 200 OK\r\n\
                         CSeq: 2\r\n\
                         \r\n";
        let reader = BufReader::new(Cursor::new(response.to_vec()));
        let resp = read_response(reader).unwrap();
        assert!(resp.body.is_empty());
    }

    #[test]
    fn read_response_unexpected_eof_in_body() {
        // Content-Length claims 100 bytes but stream ends after 5.
        let response = b"RTSP/1.0 200 OK\r\n\
                         Content-Length: 100\r\n\
                         \r\n\
                         short";
        let reader = BufReader::new(Cursor::new(response.to_vec()));
        let err = read_response(reader).unwrap_err();
        assert!(matches!(err, Error::UnexpectedEof));
    }

    #[test]
    fn read_response_unexpected_eof_before_status() {
        let reader = BufReader::new(Cursor::new(Vec::<u8>::new()));
        let err = read_response(reader).unwrap_err();
        assert!(matches!(err, Error::UnexpectedEof));
    }

    // ---- Session-level behaviour over a paired in-memory socket ---------
    //
    // These spin up a TcpListener on loopback, hand the server side a scripted
    // sequence of responses, and drive a real `Session` against it. This lets
    // us exercise CSeq tracking, the Session header round-trip, and CSeq
    // mismatch handling without a live RTSP server.

    use std::net::TcpListener;
    use std::thread;

    /// Spawn a one-shot mock RTSP server that, for each incoming request line,
    /// reads the full request (headers up to the blank line, no body), then
    /// writes back the next canned response from `responses`. Returns the
    /// bound `Url` and the join handle which yields the concatenated raw
    /// request bytes the server saw.
    fn mock_server(responses: Vec<Vec<u8>>) -> (Url, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(sock.try_clone().unwrap());
            let mut seen = String::new();
            for resp in responses {
                // Read one request: lines until a blank line.
                loop {
                    let mut line = String::new();
                    let n = reader.read_line(&mut line).unwrap();
                    if n == 0 {
                        return seen;
                    }
                    seen.push_str(&line);
                    if line == "\r\n" || line == "\n" {
                        break;
                    }
                }
                sock.write_all(&resp).unwrap();
                sock.flush().unwrap();
            }
            seen
        });
        let u = url(&format!("rtsp://127.0.0.1:{port}/stream"));
        (u, handle)
    }

    #[test]
    fn session_describe_verifies_cseq() {
        let body = b"v=0\r\n";
        let resp = format!(
            "RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        let mut resp = resp;
        resp.extend_from_slice(body);
        let (u, handle) = mock_server(vec![resp]);
        let mut session = Session::connect(&u).unwrap();
        let r = session.describe().unwrap();
        assert_eq!(r.body, body);
        // CSeq counter advanced past 1.
        assert_eq!(session.cseq, 2);
        let seen = handle.join().unwrap();
        assert!(seen.starts_with("DESCRIBE rtsp://127.0.0.1"));
        assert!(seen.contains("\r\nCSeq: 1\r\n"));
    }

    #[test]
    fn session_cseq_increments_across_requests() {
        let r1 = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: DESCRIBE, SETUP, PLAY\r\n\r\n".to_vec();
        let r2 = b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Length: 0\r\n\r\n".to_vec();
        let (u, handle) = mock_server(vec![r1, r2]);
        let mut session = Session::connect(&u).unwrap();
        session.options().unwrap();
        session.describe().unwrap();
        assert_eq!(session.cseq, 3);
        let seen = handle.join().unwrap();
        assert!(seen.contains("OPTIONS rtsp://127.0.0.1"));
        assert!(seen.contains("\r\nCSeq: 1\r\n"));
        assert!(seen.contains("DESCRIBE rtsp://127.0.0.1"));
        assert!(seen.contains("\r\nCSeq: 2\r\n"));
    }

    #[test]
    fn session_setup_parses_session_id_stripping_timeout() {
        let resp = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\
                     Session: 12345678;timeout=60\r\n\
                     Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n\r\n"
            .to_vec();
        let (u, handle) = mock_server(vec![resp]);
        let mut session = Session::connect(&u).unwrap();
        let r = session.setup().unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(session.session_id(), Some("12345678"));
        let seen = handle.join().unwrap();
        assert!(seen.contains("SETUP rtsp://127.0.0.1"));
        assert!(seen.contains("\r\nTransport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n"));
    }

    #[test]
    fn session_play_includes_session_header() {
        let setup = b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nSession: SID42;timeout=60\r\n\r\n".to_vec();
        let play =
            b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nSession: SID42\r\nRTP-Info: url=...\r\n\r\n".to_vec();
        let (u, handle) = mock_server(vec![setup, play]);
        let mut session = Session::connect(&u).unwrap();
        session.setup().unwrap();
        session.play().unwrap();
        let seen = handle.join().unwrap();
        // The PLAY request must carry the Session id captured from SETUP.
        assert!(seen.contains("PLAY rtsp://127.0.0.1"));
        assert!(seen.contains("\r\nSession: SID42\r\n"));
        assert!(seen.contains("\r\nRange: npt=0.000-\r\n"));
    }

    #[test]
    fn session_rejects_cseq_mismatch() {
        // Server echoes the wrong CSeq (5 instead of 1).
        let resp = b"RTSP/1.0 200 OK\r\nCSeq: 5\r\nContent-Length: 0\r\n\r\n".to_vec();
        let (u, handle) = mock_server(vec![resp]);
        let mut session = Session::connect(&u).unwrap();
        let err = session.describe().unwrap_err();
        match err {
            Error::BadResponse(msg) => assert!(msg.contains("CSeq mismatch"), "got {msg:?}"),
            other => panic!("expected BadResponse, got {other:?}"),
        }
        let _ = handle.join();
    }

    #[test]
    fn session_rejects_missing_cseq() {
        let resp = b"RTSP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec();
        let (u, handle) = mock_server(vec![resp]);
        let mut session = Session::connect(&u).unwrap();
        let err = session.describe().unwrap_err();
        match err {
            Error::BadResponse(msg) => assert!(msg.contains("missing CSeq"), "got {msg:?}"),
            other => panic!("expected BadResponse, got {other:?}"),
        }
        let _ = handle.join();
    }

    #[test]
    fn session_rejects_non_2xx() {
        let resp = b"RTSP/1.0 404 Not Found\r\nCSeq: 1\r\nContent-Length: 0\r\n\r\n".to_vec();
        let (u, handle) = mock_server(vec![resp]);
        let mut session = Session::connect(&u).unwrap();
        let err = session.describe().unwrap_err();
        match err {
            Error::BadResponse(msg) => assert!(msg.contains("404"), "got {msg:?}"),
            other => panic!("expected BadResponse, got {other:?}"),
        }
        let _ = handle.join();
    }

    #[test]
    fn session_play_without_setup_errors() {
        // No server interaction needed: PLAY without a session id fails before
        // any request is sent. Use a listener so connect() succeeds.
        let (u, handle) = mock_server(vec![]);
        let mut session = Session::connect(&u).unwrap();
        let err = session.play().unwrap_err();
        match err {
            Error::BadResponse(msg) => assert!(msg.contains("requires a SETUP"), "got {msg:?}"),
            other => panic!("expected BadResponse, got {other:?}"),
        }
        drop(session);
        let _ = handle.join();
    }

    #[test]
    fn connect_rejects_control_bytes_in_path() {
        // A control byte in the path must be rejected before any socket use.
        let mut u = url("rtsp://example.com/stream");
        u.path = "/ev\r\nil".to_string();
        match Session::connect(&u) {
            Err(Error::InvalidUrl(_)) => {}
            Ok(_) => panic!("expected InvalidUrl, connect succeeded"),
            Err(other) => panic!("expected InvalidUrl, got {other:?}"),
        }
    }
}

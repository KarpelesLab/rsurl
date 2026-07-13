//! Sans-IO HTTP/1.1 client exchange: a pure state machine that encodes one
//! request and decodes one response. No sockets, no clock — driven by
//! [`crate::io`]'s blocking or async driver.
//!
//! It mirrors the framing rules of the legacy streaming path in [`crate::http`]
//! (`read_head`/`read_body`/`read_chunked`) byte-for-byte, and reuses that
//! module's validated parsers ([`parse_status_line`](crate::http::parse_status_line),
//! [`parse_content_length`](crate::http::parse_content_length)) so the
//! security-sensitive header logic is not duplicated. A buffered exchange
//! ([`ClientExchange::new`]) delivers the body whole on completion; a streaming
//! exchange ([`ClientExchange::new_streaming`]) emits the head and body
//! incrementally so a frontend can relay the body to a sink without buffering it.

use std::collections::VecDeque;

use crate::error::{Error, Result};
use crate::http::{parse_content_length, parse_status_line, MAX_BODY_BYTES, MAX_HEADER_BYTES};
use crate::io::Machine;

/// A decoded response head (status line + headers), matching the field shape the
/// legacy path assembles before publishing a `Response`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Http1Head {
    pub version: String,
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
}

/// Application-level outputs of a [`ClientExchange`].
///
/// A buffered exchange ([`ClientExchange::new`]) emits a single [`Event::Response`].
/// A streaming exchange ([`ClientExchange::new_streaming`]) instead emits
/// [`Event::Head`] once, then an [`Event::Body`] per decoded chunk as bytes
/// arrive, then [`Event::End`] — so a frontend can stream the body to a sink or
/// reader without buffering the whole response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Event {
    /// The full response: head plus the complete (still wire-encoded, i.e. not
    /// yet content-decoded) body. Emitted exactly once (buffered mode), then the
    /// machine finishes.
    Response { head: Http1Head, body: Vec<u8> },
    /// Streaming mode: the response head, emitted once as soon as it is parsed.
    Head(Http1Head),
    /// Streaming mode: a run of decoded (still wire-encoded) body bytes.
    Body(Vec<u8>),
    /// Streaming mode: the body is complete; the machine finishes.
    End,
}

/// How the response body is framed, decided from the head per RFC 9112.
enum BodyMode {
    /// No body at all (HEAD / 1xx / 204 / 304).
    None,
    /// `Content-Length: n` — exactly `n` bytes.
    Length(u64),
    /// `Transfer-Encoding: chunked`.
    Chunked,
    /// Neither — framed by connection close (read until EOF).
    Eof,
}

enum State {
    /// Accumulating the status line + header block (until the blank line).
    Head,
    /// Accumulating a length-delimited body of the given total size.
    Length(u64),
    /// Decoding a chunked body.
    Chunked(ChunkState),
    /// Reading until EOF.
    Eof,
    /// Complete — the `Response` event has been queued.
    Done,
}

/// Incremental chunked-decoder cursor. Mirrors [`crate::http`]'s `read_chunked`.
#[derive(Default)]
struct ChunkState {
    /// Bytes still expected in the current chunk's data (0 = expecting a size
    /// line next), plus the trailing CRLF when `crlf_pending`.
    remaining: u64,
    crlf_pending: bool,
    /// We have seen the terminating `0`-size chunk and are draining trailers.
    in_trailers: bool,
    trailer_bytes: usize,
}

/// A single sans-IO HTTP/1.1 request/response exchange.
pub(crate) struct ClientExchange {
    /// Request bytes still to be written (drained by [`Machine::poll_transmit`]).
    out: Vec<u8>,
    /// Uppercased method, to apply the "HEAD has no body" rule.
    method: String,
    /// Bytes received but not yet consumed by the current state.
    rx: Vec<u8>,
    state: State,
    head: Option<Http1Head>,
    body: Vec<u8>,
    /// Total body bytes accumulated so far. Tracked separately from `body.len()`
    /// because streaming mode drains `body` after each emit, yet `Length` framing
    /// and the size cap need the running received total.
    body_total: u64,
    events: VecDeque<Event>,
    /// Stream the response as incremental `Head`/`Body`/`End` events instead of
    /// one buffered `Response`.
    streaming: bool,
    /// In streaming mode, whether the one-shot `Head` event has been emitted.
    head_emitted: bool,
}

impl ClientExchange {
    /// Build an exchange that will send `request_bytes` (a fully-encoded HTTP/1.1
    /// request) and decode the response. `method` drives body-presence rules.
    pub(crate) fn new(method: &str, request_bytes: Vec<u8>) -> ClientExchange {
        ClientExchange::build(method, request_bytes, false)
    }

    /// Like [`new`](Self::new) but streams the response: the machine emits
    /// [`Event::Head`] once, an [`Event::Body`] per decoded chunk as bytes
    /// arrive, then [`Event::End`] — instead of one buffered [`Event::Response`].
    /// Pair with [`crate::io::blocking::drive_streaming_observed`] to deliver the
    /// body without buffering it whole.
    pub(crate) fn new_streaming(method: &str, request_bytes: Vec<u8>) -> ClientExchange {
        ClientExchange::build(method, request_bytes, true)
    }

    fn build(method: &str, request_bytes: Vec<u8>, streaming: bool) -> ClientExchange {
        ClientExchange {
            out: request_bytes,
            method: method.to_ascii_uppercase(),
            rx: Vec::new(),
            state: State::Head,
            head: None,
            body: Vec::new(),
            body_total: 0,
            events: VecDeque::new(),
            streaming,
            head_emitted: false,
        }
    }

    /// Encode a minimal HTTP/1.1 request line + header block (+ optional body).
    /// `headers` are sent verbatim in order; the caller is responsible for
    /// supplying `Host` and any framing headers. This is the Phase-1 subset;
    /// the legacy `write_request` (auth, cookies, expect-100, injection guards)
    /// is folded in at the cutover phase.
    pub(crate) fn encode_request(
        method: &str,
        target: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + body.len());
        out.extend_from_slice(method.as_bytes());
        out.push(b' ');
        out.extend_from_slice(target.as_bytes());
        out.extend_from_slice(b" HTTP/1.1\r\n");
        for (k, v) in headers {
            out.extend_from_slice(k.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(v.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(body);
        out
    }

    /// Try to make as much progress as possible with the bytes currently in
    /// `rx`. Returns once it needs more input, finishes, or errors.
    fn advance(&mut self) -> Result<()> {
        loop {
            match &mut self.state {
                State::Head => {
                    let Some(end) = find_header_end(&self.rx) else {
                        if self.rx.len() > MAX_HEADER_BYTES {
                            return Err(Error::BadResponse("headers exceed 64 KiB".into()));
                        }
                        return Ok(()); // need more bytes
                    };
                    let head_bytes: Vec<u8> = self.rx.drain(..end).collect();
                    let head = parse_head(&head_bytes)?;
                    let mode = body_mode(&self.method, &head, self.streaming)?;
                    self.head = Some(head);
                    self.state = match mode {
                        BodyMode::None => self.finish(),
                        BodyMode::Length(0) => self.finish(),
                        BodyMode::Length(n) => State::Length(n),
                        BodyMode::Chunked => State::Chunked(ChunkState::default()),
                        BodyMode::Eof => State::Eof,
                    };
                }
                State::Length(n) => {
                    let n = *n;
                    if self.body_total + (self.rx.len() as u64) >= n {
                        let need = (n - self.body_total) as usize;
                        self.body.extend(self.rx.drain(..need));
                        self.body_total += need as u64;
                        self.state = self.finish();
                    } else {
                        self.body_total += self.rx.len() as u64;
                        self.body.append(&mut self.rx);
                        return Ok(()); // need more bytes
                    }
                }
                State::Chunked(_) => {
                    if self.advance_chunked()? {
                        self.state = self.finish();
                    } else {
                        return Ok(()); // need more bytes
                    }
                }
                State::Eof => {
                    // Accumulate; completion happens on handle_eof. Streaming
                    // drains `body` to the sink each batch (O(1) memory), so the
                    // in-memory cap doesn't apply.
                    if !self.streaming
                        && self.body_total + (self.rx.len() as u64) > MAX_BODY_BYTES as u64
                    {
                        return Err(Error::BadResponse("body too large".into()));
                    }
                    self.body_total += self.rx.len() as u64;
                    self.body.append(&mut self.rx);
                    return Ok(());
                }
                State::Done => return Ok(()),
            }
        }
    }

    /// Decode chunked data already in `rx`. Returns `Ok(true)` when the
    /// terminating chunk + trailers are complete, `Ok(false)` when more bytes
    /// are needed. Mirrors [`crate::http`]'s `read_chunked` rules.
    fn advance_chunked(&mut self) -> Result<bool> {
        let State::Chunked(cs) = &mut self.state else {
            unreachable!("advance_chunked called off-state");
        };
        loop {
            if cs.crlf_pending {
                if self.rx.len() < 2 {
                    return Ok(false);
                }
                let crlf: Vec<u8> = self.rx.drain(..2).collect();
                if crlf != b"\r\n" {
                    return Err(Error::BadResponse("missing CRLF after chunk".into()));
                }
                cs.crlf_pending = false;
            }

            if cs.in_trailers {
                // Drain trailer lines until a blank line (or EOF handled elsewhere).
                let Some(nl) = self.rx.iter().position(|&b| b == b'\n') else {
                    if self.rx.len() > MAX_HEADER_BYTES {
                        return Err(Error::BadResponse("trailer block too large".into()));
                    }
                    return Ok(false);
                };
                let line: Vec<u8> = self.rx.drain(..=nl).collect();
                if trim_eol(&line).is_empty() {
                    return Ok(true); // end of trailers => body complete
                }
                cs.trailer_bytes = cs.trailer_bytes.saturating_add(line.len());
                if cs.trailer_bytes > MAX_HEADER_BYTES {
                    return Err(Error::BadResponse("trailer block too large".into()));
                }
                continue;
            }

            if cs.remaining > 0 {
                let take = (cs.remaining as usize).min(self.rx.len());
                if take == 0 {
                    return Ok(false);
                }
                self.body.extend(self.rx.drain(..take));
                self.body_total += take as u64;
                cs.remaining -= take as u64;
                if cs.remaining == 0 {
                    cs.crlf_pending = true;
                }
                continue;
            }

            // Expecting a chunk-size line.
            let Some(nl) = self.rx.iter().position(|&b| b == b'\n') else {
                if self.rx.len() > MAX_HEADER_BYTES {
                    return Err(Error::BadResponse("chunk size line too large".into()));
                }
                return Ok(false);
            };
            let line: Vec<u8> = self.rx.drain(..=nl).collect();
            let size = parse_chunk_size(&line)?;
            // Streaming drains `body` to the sink each batch, so a large
            // aggregate is fine there; buffered mode still caps memory.
            if !self.streaming && self.body_total.saturating_add(size) > MAX_BODY_BYTES as u64 {
                return Err(Error::BadResponse("body too large".into()));
            }
            if size == 0 {
                cs.in_trailers = true;
            } else {
                cs.remaining = size;
            }
        }
    }

    /// Queue the completion event(s) and return the `Done` state. Buffered mode
    /// emits one [`Event::Response`]; streaming mode flushes any pending
    /// `Head`/`Body` then emits [`Event::End`].
    fn finish(&mut self) -> State {
        if self.streaming {
            self.emit_streaming();
            self.events.push_back(Event::End);
        } else {
            let head = self.head.clone().expect("head set before finish");
            let body = std::mem::take(&mut self.body);
            self.events.push_back(Event::Response { head, body });
        }
        State::Done
    }

    /// Streaming mode only: emit the one-shot [`Event::Head`] once it is parsed,
    /// then drain whatever body bytes have accumulated so far as an
    /// [`Event::Body`]. Called after each input batch and from [`finish`].
    fn emit_streaming(&mut self) {
        if !self.head_emitted {
            if let Some(head) = self.head.clone() {
                self.events.push_back(Event::Head(head));
                self.head_emitted = true;
            }
        }
        if !self.body.is_empty() {
            let chunk = std::mem::take(&mut self.body);
            self.events.push_back(Event::Body(chunk));
        }
    }
}

impl Machine for ClientExchange {
    type Event = Event;

    fn handle_input(&mut self, wire: &[u8]) -> Result<usize> {
        if matches!(self.state, State::Done) {
            return Ok(0);
        }
        self.rx.extend_from_slice(wire);
        let before = self.rx.len();
        self.advance()?;
        // Streaming mode: surface the head and any body decoded this batch now,
        // so the driver can relay them before the response completes. (A no-op
        // once `advance` has already finished, which flushes via `finish`.)
        if self.streaming {
            self.emit_streaming();
        }
        // We always take ownership of the offered bytes into `rx`, so report the
        // whole slice as consumed (any unconsumed tail lives in `rx`).
        let _ = before;
        Ok(wire.len())
    }

    fn handle_eof(&mut self) -> Result<()> {
        match self.state {
            State::Eof => {
                // EOF *is* the body terminator here.
                self.body.append(&mut self.rx);
                self.state = self.finish();
                Ok(())
            }
            State::Done => Ok(()),
            // Head not yet complete, or a length/chunk body still expecting
            // bytes: a premature close.
            _ => Err(Error::UnexpectedEof),
        }
    }

    fn poll_transmit(&mut self, out: &mut Vec<u8>) -> bool {
        if self.out.is_empty() {
            return false;
        }
        out.append(&mut self.out);
        true
    }

    fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    fn is_finished(&self) -> bool {
        matches!(self.state, State::Done) && self.events.is_empty()
    }
}

/// Find the byte offset just past the end of the header block (the position
/// after the blank line), tolerating bare-LF line endings as the legacy
/// line-based reader does. Returns `None` if the block is incomplete.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    let crlf = find_sub(buf, b"\r\n\r\n").map(|i| i + 4);
    let lf = find_sub(buf, b"\n\n").map(|i| i + 2);
    match (crlf, lf) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn trim_eol(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && (line[end - 1] == b'\n' || line[end - 1] == b'\r') {
        end -= 1;
    }
    &line[..end]
}

/// Parse the status line + headers out of the raw head block (including the
/// terminating blank line). Reuses the legacy validated status-line parser.
fn parse_head(block: &[u8]) -> Result<Http1Head> {
    let text = String::from_utf8_lossy(block);
    let mut lines = text.split('\n');
    let status_line = lines.next().map(|l| l.trim_end_matches('\r')).unwrap_or("");
    let (version, status, reason) = parse_status_line(status_line)?;

    let mut headers: Vec<(String, String)> = Vec::new();
    let mut header_bytes = 0usize;
    for raw in lines {
        let line = raw.trim_end_matches('\r');
        if line.is_empty() {
            break; // blank line terminates the block
        }
        header_bytes += raw.len() + 1; // +1 for the consumed '\n'
        if header_bytes > MAX_HEADER_BYTES {
            return Err(Error::BadResponse("headers exceed 64 KiB".into()));
        }
        let (k, v) = line
            .split_once(':')
            .ok_or_else(|| Error::BadResponse(format!("malformed header line: {line:?}")))?;
        headers.push((k.trim().to_string(), v.trim().to_string()));
    }
    Ok(Http1Head {
        version,
        status,
        reason,
        headers,
    })
}

/// Decide body framing from method + head, applying RFC 9110/9112 rules
/// identically to [`crate::http`]'s `read_body`. `streaming` relaxes the
/// [`MAX_BODY_BYTES`] up-front Content-Length cap: a streaming exchange drains
/// the body to the caller's sink in O(1) memory, so the in-memory guard does
/// not apply (matching `send_streaming`'s documented contract).
fn body_mode(method: &str, head: &Http1Head, streaming: bool) -> Result<BodyMode> {
    let status = head.status;
    if method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&status)
        || status == 204
        || status == 304
    {
        return Ok(BodyMode::None);
    }

    let headers = &head.headers;
    let has_te = headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"));
    let has_cl = headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-length"));
    if has_te && has_cl {
        return Err(Error::BadResponse(
            "both Transfer-Encoding and Content-Length present".into(),
        ));
    }

    let chunked = headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("transfer-encoding") && v.eq_ignore_ascii_case("chunked")
    });
    if chunked {
        return Ok(BodyMode::Chunked);
    }
    // A non-chunked transfer-encoding we don't understand is unframable.
    if has_te {
        return Err(Error::BadResponse("unsupported Transfer-Encoding".into()));
    }

    match parse_content_length(headers)? {
        Some(len) => {
            if !streaming && len > MAX_BODY_BYTES as u64 {
                return Err(Error::BadResponse(format!("body too large: {len}")));
            }
            Ok(BodyMode::Length(len))
        }
        None => Ok(BodyMode::Eof),
    }
}

/// Parse a chunk-size line (`1*HEXDIG` with an optional `;ext`), matching
/// [`crate::http`]'s `read_chunked` validation.
fn parse_chunk_size(line: &[u8]) -> Result<u64> {
    let text = String::from_utf8_lossy(line);
    let size_str = text
        .trim_end_matches(['\r', '\n'])
        .split(';')
        .next()
        .unwrap_or("");
    let s = size_str.trim();
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::BadResponse(format!("bad chunk size: {size_str:?}")));
    }
    u64::from_str_radix(s, 16)
        .map_err(|_| Error::BadResponse(format!("bad chunk size: {size_str:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive an exchange by feeding the whole response in one shot, optionally
    /// signalling EOF, and return the single emitted event.
    fn decode(method: &str, response: &[u8], eof: bool) -> Result<Event> {
        let mut x = ClientExchange::new(method, Vec::new());
        x.handle_input(response)?;
        if eof {
            x.handle_eof()?;
        }
        x.poll_event().ok_or(Error::UnexpectedEof)
    }

    fn head_body(ev: Event) -> (Http1Head, Vec<u8>) {
        let Event::Response { head, body } = ev else {
            panic!("expected Response event, got {ev:?}");
        };
        (head, body)
    }

    #[test]
    fn request_encodes_minimal_get() {
        let bytes = ClientExchange::encode_request(
            "GET",
            "/path",
            &[("Host".into(), "example.com".into())],
            b"",
        );
        assert_eq!(bytes, b"GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n");
    }

    #[test]
    fn transmit_drains_request_once() {
        let mut x = ClientExchange::new("GET", b"GET / HTTP/1.1\r\n\r\n".to_vec());
        let mut out = Vec::new();
        assert!(x.poll_transmit(&mut out));
        assert_eq!(out, b"GET / HTTP/1.1\r\n\r\n");
        assert!(!x.poll_transmit(&mut out));
    }

    #[test]
    fn streaming_emits_head_then_body_chunks_then_end() {
        // A streaming exchange surfaces the head as soon as it is parsed, body
        // bytes as they arrive across separate input batches, and a final End.
        let mut x = ClientExchange::new_streaming("GET", Vec::new());
        x.handle_input(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhel")
            .unwrap();
        // First batch: head + the first body slice, no End yet.
        assert!(matches!(x.poll_event(), Some(Event::Head(h)) if h.status == 200));
        assert!(matches!(x.poll_event(), Some(Event::Body(b)) if b == b"hel"));
        assert!(x.poll_event().is_none());
        assert!(!x.is_finished());

        // Second batch completes the body; head is not re-emitted.
        x.handle_input(b"lo wor").unwrap();
        assert!(matches!(x.poll_event(), Some(Event::Body(b)) if b == b"lo wor"));
        assert!(x.poll_event().is_none());
        assert!(!x.is_finished());

        // Final batch reaches Content-Length → trailing body flush then End.
        x.handle_input(b"ld").unwrap();
        assert!(matches!(x.poll_event(), Some(Event::Body(b)) if b == b"ld"));
        assert!(matches!(x.poll_event(), Some(Event::End)));
        assert!(x.poll_event().is_none());
        assert!(x.is_finished());
    }

    #[test]
    fn streaming_accepts_content_length_over_buffered_cap() {
        // Regression: `send_streaming` drains the body to the caller's sink in
        // O(1) memory, so the buffered MAX_BODY_BYTES cap must NOT reject a
        // Content-Length larger than it (this used to fail up front).
        let huge = MAX_BODY_BYTES as u64 + 1;
        let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {huge}\r\n\r\n");
        let mut x = ClientExchange::new_streaming("GET", Vec::new());
        x.handle_input(head.as_bytes())
            .expect("streaming must not reject a large Content-Length");
        assert!(matches!(x.poll_event(), Some(Event::Head(h)) if h.status == 200));
        x.handle_input(b"abc").unwrap();
        assert!(matches!(x.poll_event(), Some(Event::Body(b)) if b == b"abc"));
        assert!(!x.is_finished());
    }

    #[test]
    fn buffered_still_rejects_content_length_over_cap() {
        // The buffered path accumulates the whole body in memory, so the cap
        // must still fire there.
        let huge = MAX_BODY_BYTES as u64 + 1;
        let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {huge}\r\n\r\n");
        let mut x = ClientExchange::new("GET", Vec::new());
        let err = x.handle_input(head.as_bytes());
        assert!(matches!(err, Err(Error::BadResponse(m)) if m.contains("body too large")));
    }

    #[test]
    fn streaming_chunked_body_decodes_across_batches() {
        let mut x = ClientExchange::new_streaming("GET", Vec::new());
        x.handle_input(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
            .unwrap();
        assert!(matches!(x.poll_event(), Some(Event::Head(h)) if h.status == 200));
        assert!(x.poll_event().is_none());

        x.handle_input(b"5\r\nhello\r\n").unwrap();
        assert!(matches!(x.poll_event(), Some(Event::Body(b)) if b == b"hello"));

        x.handle_input(b"6\r\n world\r\n0\r\n\r\n").unwrap();
        assert!(matches!(x.poll_event(), Some(Event::Body(b)) if b == b" world"));
        assert!(matches!(x.poll_event(), Some(Event::End)));
        assert!(x.is_finished());
    }

    #[test]
    fn streaming_eof_framed_body_flushes_then_ends() {
        let mut x = ClientExchange::new_streaming("GET", Vec::new());
        x.handle_input(b"HTTP/1.1 200 OK\r\n\r\nstreamed").unwrap();
        assert!(matches!(x.poll_event(), Some(Event::Head(_))));
        assert!(matches!(x.poll_event(), Some(Event::Body(b)) if b == b"streamed"));
        assert!(x.poll_event().is_none());

        x.handle_eof().unwrap();
        assert!(matches!(x.poll_event(), Some(Event::End)));
        assert!(x.is_finished());
    }

    #[test]
    fn content_length_body() {
        let (head, body) = head_body(
            decode(
                "GET",
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
                false,
            )
            .unwrap(),
        );
        assert_eq!(head.status, 200);
        assert_eq!(head.reason, "OK");
        assert_eq!(head.version, "HTTP/1.1");
        assert_eq!(body, b"hello");
    }

    #[test]
    fn content_length_short_then_eof_errors() {
        let mut x = ClientExchange::new("GET", Vec::new());
        x.handle_input(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel")
            .unwrap();
        assert!(x.poll_event().is_none()); // not complete yet
        assert!(matches!(x.handle_eof(), Err(Error::UnexpectedEof)));
    }

    #[test]
    fn chunked_body_reassembles() {
        let resp =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let (_h, body) = head_body(decode("GET", resp, false).unwrap());
        assert_eq!(body, b"hello world");
    }

    #[test]
    fn chunked_with_trailers() {
        let resp =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-T: 1\r\n\r\n";
        let (_h, body) = head_body(decode("GET", resp, false).unwrap());
        assert_eq!(body, b"abc");
    }

    #[test]
    fn eof_framed_body_completes_on_eof() {
        let (_h, body) =
            head_body(decode("GET", b"HTTP/1.1 200 OK\r\n\r\nstreamed bytes", true).unwrap());
        assert_eq!(body, b"streamed bytes");
    }

    #[test]
    fn head_response_has_no_body() {
        // Body bytes after the head must be ignored for a HEAD request.
        let (_h, body) = head_body(
            decode(
                "HEAD",
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
                false,
            )
            .unwrap(),
        );
        assert!(body.is_empty());
    }

    #[test]
    fn status_204_has_no_body() {
        let (_h, body) =
            head_body(decode("GET", b"HTTP/1.1 204 No Content\r\n\r\n", false).unwrap());
        assert!(body.is_empty());
    }

    #[test]
    fn te_and_cl_together_is_rejected() {
        let r = ClientExchange::new("GET", Vec::new());
        let mut x = r;
        let err = x
            .handle_input(
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nhello",
            )
            .unwrap_err();
        assert!(matches!(err, Error::BadResponse(_)));
    }

    #[test]
    fn byte_at_a_time_feed_matches_one_shot() {
        // Drip a chunked response one byte per handle_input call.
        let resp: &[u8] =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let mut x = ClientExchange::new("GET", Vec::new());
        for b in resp {
            x.handle_input(&[*b]).unwrap();
        }
        let (head, body) = head_body(x.poll_event().expect("complete"));
        assert_eq!(head.status, 200);
        assert_eq!(body, b"hello");
        assert!(x.is_finished());
    }

    #[test]
    fn bare_lf_header_endings_tolerated() {
        let (head, body) =
            head_body(decode("GET", b"HTTP/1.1 200 OK\nContent-Length: 2\n\nhi", false).unwrap());
        assert_eq!(head.status, 200);
        assert_eq!(body, b"hi");
    }
}

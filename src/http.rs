use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::url::Url;

const DEFAULT_USER_AGENT: &str = concat!("curlrs/", env!("CARGO_PKG_VERSION"));
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 256 * 1024 * 1024;

/// An HTTP request being constructed.
#[derive(Debug, Clone)]
pub struct Request {
    method: String,
    url: Url,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    connect_timeout: Option<Duration>,
    read_timeout: Option<Duration>,
}

impl Request {
    pub fn new(method: &str, url: &str) -> Result<Self> {
        Ok(Request {
            method: method.to_ascii_uppercase(),
            url: Url::parse(url)?,
            headers: Vec::new(),
            body: Vec::new(),
            connect_timeout: Some(Duration::from_secs(30)),
            read_timeout: Some(Duration::from_secs(60)),
        })
    }

    pub fn get(url: &str) -> Result<Self> {
        Self::new("GET", url)
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    pub fn body<B: Into<Vec<u8>>>(mut self, body: B) -> Self {
        self.body = body.into();
        self
    }

    pub fn url(&self) -> &Url {
        &self.url
    }

    pub fn send(self) -> Result<Response> {
        match self.url.scheme.as_str() {
            "http" => send_http(self),
            "https" => Err(Error::UnsupportedScheme(
                "https (TLS via purecrypto not wired in yet)".into(),
            )),
            other => Err(Error::UnsupportedScheme(other.to_string())),
        }
    }
}

/// A complete HTTP response.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub reason: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    /// Returns the first value of a header, case-insensitive.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn send_http(req: Request) -> Result<Response> {
    let addr = format!("{}:{}", req.url.host, req.url.port);
    let stream = match req.connect_timeout {
        Some(t) => {
            let addrs: Vec<_> = std::net::ToSocketAddrs::to_socket_addrs(&addr)?.collect();
            let first = addrs
                .into_iter()
                .next()
                .ok_or_else(|| Error::InvalidUrl(req.url.host.clone()))?;
            TcpStream::connect_timeout(&first, t)?
        }
        None => TcpStream::connect(&addr)?,
    };
    stream.set_read_timeout(req.read_timeout)?;
    stream.set_write_timeout(req.read_timeout)?;

    write_request(&stream, &req)?;
    read_response(stream, &req.method)
}

fn write_request<W: Write>(mut w: W, req: &Request) -> Result<()> {
    let host_header = if (req.url.scheme == "http" && req.url.port == 80)
        || (req.url.scheme == "https" && req.url.port == 443)
    {
        req.url.host.clone()
    } else {
        format!("{}:{}", req.url.host, req.url.port)
    };

    let mut buf = Vec::with_capacity(256);
    write!(&mut buf, "{} {} HTTP/1.1\r\n", req.method, req.url.path)?;
    write!(&mut buf, "Host: {host_header}\r\n")?;

    let mut have_ua = false;
    let mut have_accept = false;
    let mut have_clen = false;
    for (k, v) in &req.headers {
        if k.eq_ignore_ascii_case("user-agent") {
            have_ua = true;
        }
        if k.eq_ignore_ascii_case("accept") {
            have_accept = true;
        }
        if k.eq_ignore_ascii_case("content-length") {
            have_clen = true;
        }
        write!(&mut buf, "{k}: {v}\r\n")?;
    }
    if !have_ua {
        write!(&mut buf, "User-Agent: {DEFAULT_USER_AGENT}\r\n")?;
    }
    if !have_accept {
        write!(&mut buf, "Accept: */*\r\n")?;
    }
    if !req.body.is_empty() && !have_clen {
        write!(&mut buf, "Content-Length: {}\r\n", req.body.len())?;
    }
    write!(&mut buf, "Connection: close\r\n\r\n")?;

    w.write_all(&buf)?;
    if !req.body.is_empty() {
        w.write_all(&req.body)?;
    }
    w.flush()?;
    Ok(())
}

fn read_response<R: Read>(stream: R, method: &str) -> Result<Response> {
    let mut r = BufReader::new(stream);

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

    let body = read_body(&mut r, &headers, &version, status, method)?;

    Ok(Response {
        status,
        reason,
        version,
        headers,
        body,
    })
}

fn parse_status_line(line: &str) -> Result<(String, u16, String)> {
    let mut parts = line.splitn(3, ' ');
    let version = parts
        .next()
        .ok_or_else(|| Error::BadResponse(format!("missing version: {line:?}")))?
        .to_string();
    if !version.starts_with("HTTP/") {
        return Err(Error::BadResponse(format!("not HTTP: {version}")));
    }
    let status: u16 = parts
        .next()
        .ok_or_else(|| Error::BadResponse(format!("missing status: {line:?}")))?
        .parse()
        .map_err(|_| Error::BadResponse(format!("bad status: {line:?}")))?;
    let reason = parts.next().unwrap_or("").to_string();
    Ok((version, status, reason))
}

fn read_body<R: BufRead>(
    r: &mut R,
    headers: &[(String, String)],
    _version: &str,
    status: u16,
    method: &str,
) -> Result<Vec<u8>> {
    // RFC 9110: HEAD responses never have a body, nor do these statuses.
    if method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&status)
        || status == 204
        || status == 304
    {
        return Ok(Vec::new());
    }

    let chunked = headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.eq_ignore_ascii_case("chunked"));
    if chunked {
        return read_chunked(r);
    }

    let content_length = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<u64>().ok());

    let mut body = Vec::new();
    match content_length {
        Some(len) => {
            if len as usize > MAX_BODY_BYTES {
                return Err(Error::BadResponse(format!("body too large: {len}")));
            }
            body.reserve(len as usize);
            r.take(len).read_to_end(&mut body)?;
            if (body.len() as u64) < len {
                return Err(Error::UnexpectedEof);
            }
        }
        None => {
            // No content-length, no chunked — read until EOF (Connection: close).
            r.take(MAX_BODY_BYTES as u64).read_to_end(&mut body)?;
        }
    }
    Ok(body)
}

fn read_chunked<R: BufRead>(r: &mut R) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let mut size_line = String::new();
        let n = r.read_line(&mut size_line)?;
        if n == 0 {
            return Err(Error::UnexpectedEof);
        }
        let size_str = size_line
            .trim_end_matches(['\r', '\n'])
            .split(';')
            .next()
            .unwrap_or("");
        let size = usize::from_str_radix(size_str.trim(), 16)
            .map_err(|_| Error::BadResponse(format!("bad chunk size: {size_str:?}")))?;
        if body.len().saturating_add(size) > MAX_BODY_BYTES {
            return Err(Error::BadResponse("body too large".into()));
        }
        if size == 0 {
            // Consume trailers until empty line.
            loop {
                let mut t = String::new();
                let n = r.read_line(&mut t)?;
                if n == 0 || t.trim_end_matches(['\r', '\n']).is_empty() {
                    break;
                }
            }
            break;
        }
        let start = body.len();
        body.resize(start + size, 0);
        r.read_exact(&mut body[start..])?;
        let mut crlf = [0u8; 2];
        r.read_exact(&mut crlf)?;
        if &crlf != b"\r\n" {
            return Err(Error::BadResponse("missing CRLF after chunk".into()));
        }
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status_line_ok() {
        let (v, s, r) = parse_status_line("HTTP/1.1 200 OK").unwrap();
        assert_eq!(v, "HTTP/1.1");
        assert_eq!(s, 200);
        assert_eq!(r, "OK");
    }

    #[test]
    fn parses_status_line_no_reason() {
        let (_, s, r) = parse_status_line("HTTP/1.0 204").unwrap();
        assert_eq!(s, 204);
        assert_eq!(r, "");
    }

    #[test]
    fn rejects_non_http() {
        assert!(parse_status_line("RTSP/1.0 200 OK").is_err());
    }
}

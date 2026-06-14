use std::fmt;
use std::io;

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during a rsurl request.
#[derive(Debug)]
pub enum Error {
    /// URL was syntactically malformed (bad scheme, missing host, etc.).
    InvalidUrl(String),
    /// The URL's scheme is recognized but not yet implemented (e.g. https, ftp).
    UnsupportedScheme(String),
    /// Network or I/O failure.
    Io(io::Error),
    /// Server sent something that isn't valid HTTP/1.x.
    BadResponse(String),
    /// Server closed the connection before sending a complete response.
    UnexpectedEof,
    /// The HTTP/2 backend tried to negotiate ALPN "h2" but the server
    /// selected a different protocol (or none). Used as an internal
    /// signal so the HTTPS dispatcher can fall back to HTTP/1.1 in Auto
    /// mode; surfaced to callers only under `--http2`.
    H2NotNegotiated,
    /// An SSH-layer failure (connect, host-key verification, authentication,
    /// SFTP/SCP transfer). Carries a human-readable description; never the
    /// password or key material.
    Ssh(String),
    /// Failed to decode a response body — an unsupported `Content-Type`
    /// charset ([`crate::Response::text`]) or a deserialization failure
    /// ([`crate::Response::json`]).
    Decode(String),
    /// [`crate::Response::error_for_status`] was called on a response whose
    /// HTTP status was an error (>= 400). Carries the status and reason phrase.
    Status { code: u16, reason: String },
    /// The transfer was cancelled via its [`crate::CancelToken`] (a navigation
    /// cancel, `fetch` abort, or stop button). The connection is torn down.
    Cancelled,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidUrl(u) => write!(f, "invalid URL: {u}"),
            Error::UnsupportedScheme(s) => write!(f, "unsupported scheme: {s}"),
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::BadResponse(m) => write!(f, "bad response: {m}"),
            Error::UnexpectedEof => write!(f, "unexpected end of response"),
            Error::H2NotNegotiated => write!(f, "server did not select ALPN \"h2\""),
            Error::Ssh(m) => write!(f, "ssh error: {m}"),
            Error::Decode(m) => write!(f, "decode error: {m}"),
            Error::Status { code, reason } => {
                if reason.is_empty() {
                    write!(f, "HTTP status {code}")
                } else {
                    write!(f, "HTTP status {code} {reason}")
                }
            }
            Error::Cancelled => write!(f, "transfer cancelled"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

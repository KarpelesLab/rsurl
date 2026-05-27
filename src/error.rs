use std::fmt;
use std::io;

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during a curlrs request.
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
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidUrl(u) => write!(f, "invalid URL: {u}"),
            Error::UnsupportedScheme(s) => write!(f, "unsupported scheme: {s}"),
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::BadResponse(m) => write!(f, "bad response: {m}"),
            Error::UnexpectedEof => write!(f, "unexpected end of response"),
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

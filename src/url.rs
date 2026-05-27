use crate::error::{Error, Result};

/// Minimal parsed URL. Only the fields we need for HTTP today.
///
/// Userinfo, fragments, and percent-decoding are intentionally absent; this
/// will grow as we add support for the things curl supports. Query string is
/// kept attached to `path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    /// Path including the query string, always starting with `/`.
    pub path: String,
}

impl Url {
    pub fn parse(s: &str) -> Result<Self> {
        let (scheme, rest) = s
            .split_once("://")
            .ok_or_else(|| Error::InvalidUrl(s.to_string()))?;
        if scheme.is_empty() {
            return Err(Error::InvalidUrl(s.to_string()));
        }
        let scheme = scheme.to_ascii_lowercase();

        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        if authority.is_empty() {
            return Err(Error::InvalidUrl(s.to_string()));
        }

        // Strip optional fragment from path.
        let path = match path.find('#') {
            Some(i) => &path[..i],
            None => path,
        };

        let default_port = match scheme.as_str() {
            "http" => 80,
            "https" => 443,
            "ftp" => 21,
            "ftps" => 990,
            _ => return Err(Error::UnsupportedScheme(scheme)),
        };

        let (host, port) = match authority.rfind(':') {
            Some(i) if !authority[..i].contains(']') => {
                let h = &authority[..i];
                let p: u16 = authority[i + 1..]
                    .parse()
                    .map_err(|_| Error::InvalidUrl(s.to_string()))?;
                (h, p)
            }
            _ => (authority, default_port),
        };

        if host.is_empty() {
            return Err(Error::InvalidUrl(s.to_string()));
        }

        Ok(Url {
            scheme,
            host: host.to_string(),
            port,
            path: path.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http() {
        let u = Url::parse("http://example.com/foo?bar=1").unwrap();
        assert_eq!(u.scheme, "http");
        assert_eq!(u.host, "example.com");
        assert_eq!(u.port, 80);
        assert_eq!(u.path, "/foo?bar=1");
    }

    #[test]
    fn parses_https_with_port() {
        let u = Url::parse("https://example.com:8443").unwrap();
        assert_eq!(u.scheme, "https");
        assert_eq!(u.port, 8443);
        assert_eq!(u.path, "/");
    }

    #[test]
    fn rejects_no_scheme() {
        assert!(Url::parse("example.com").is_err());
    }

    #[test]
    fn strips_fragment() {
        let u = Url::parse("http://x/y#frag").unwrap();
        assert_eq!(u.path, "/y");
    }
}

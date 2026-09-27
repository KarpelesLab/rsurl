// On wasm the browser parses/resolves URLs itself, so several of these helpers
// are unused there (only `Url::parse` is reachable via `aio`). They stay for the
// native protocol backends; silence the dead-code lint on wasm only.
#![cfg_attr(target_arch = "wasm32", allow(dead_code))]

use crate::error::{Error, Result};

/// Minimal parsed URL. Only the fields we need for the protocols we speak.
///
/// Userinfo (user:pass@) is captured in `userinfo` for protocols that need
/// auth, but not percent-decoded. Fragments are stripped. Query strings stay
/// attached to `path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub scheme: String,
    /// `user[:pass]` from before the `@` in the authority, if present.
    pub userinfo: Option<String>,
    pub host: String,
    pub port: u16,
    /// Path including the query string, always starting with `/` (except for
    /// schemes like `dict:` and `gopher:` where the path can be a single
    /// token). For `file://` URLs, this is the absolute filesystem path.
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

        // The authority ends at the FIRST of `/`, `?`, or `#` (RFC 3986 §3.2 /
        // WHATWG / curl). Terminating only on `/` would let a `?` or `#` smuggle
        // an `@` into what `rfind('@')` then treats as the authority, so that
        // `http://expected.com?x=@attacker.com` resolves to host `attacker.com`
        // (NET-1: authority confusion / SSRF / host-allowlist bypass). Whatever
        // follows the delimiter (the `/`, `?`, or `#` and the rest) is the path
        // and keeps its query/fragment for the downstream handling below.
        let (authority, path) = match rest.find(['/', '?', '#']) {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };

        // `file://` is special: no host, the path is everything after `file://`.
        // The only authority accepted is empty or `localhost` (RFC 8089 §2 /
        // curl), and the scheme matches case-insensitively (`FILE:///x`).
        if scheme == "file" {
            let path = match rest.strip_prefix("localhost") {
                Some(p) if p.starts_with('/') => p,
                _ => rest,
            };
            if !path.starts_with('/') {
                return Err(Error::InvalidUrl(s.to_string()));
            }
            let path = match path.find('#') {
                Some(i) => &path[..i],
                None => path,
            };
            return Ok(Url {
                scheme,
                userinfo: None,
                host: String::new(),
                port: 0,
                path: path.to_string(),
            });
        }

        if authority.is_empty() {
            return Err(Error::InvalidUrl(s.to_string()));
        }

        // Strip optional fragment from path. A query- or fragment-only
        // reference (`http://h?x=1`, `http://h#f`) still needs the root path,
        // otherwise the request line would read `GET ?x=1` / `GET  HTTP/1.1`.
        let path = match path.find('#') {
            Some(i) => &path[..i],
            None => path,
        };
        let path = if path.starts_with('/') {
            // RFC 3986 §5.2.4 / curl (without `--path-as-is`): resolve `.` and
            // `..` segments so they never reach the server.
            remove_dot_segments(path)
        } else {
            format!("/{path}")
        };
        let path = path.as_str();

        let default_port =
            default_port(&scheme).ok_or_else(|| Error::UnsupportedScheme(scheme.clone()))?;

        let (userinfo, hostport) = match authority.rfind('@') {
            Some(i) => (Some(authority[..i].to_string()), &authority[i + 1..]),
            None => (None, authority),
        };

        // Split host from an optional `:port`. IPv6 literals are bracketed
        // (`[::1]`) so a `:` inside the brackets is not a port separator; only
        // a `:` *after* the closing `]` is. A bare `[` with no matching `]` is
        // a malformed authority and is rejected. The brackets are retained in
        // the stored `host` because every transport/`Host:`-header construction
        // in the crate concatenates `host` directly and an IPv6 literal needs
        // them to remain unambiguous.
        let (host, port, bracketed) = if let Some(close) = hostport.find(']') {
            if !hostport.starts_with('[') {
                return Err(Error::InvalidUrl(s.to_string()));
            }
            // Authority after the `]` is either empty or `:port`.
            let after = &hostport[close + 1..];
            let port = if after.is_empty() {
                default_port
            } else if let Some(p) = after.strip_prefix(':') {
                parse_port(p, default_port).ok_or_else(|| Error::InvalidUrl(s.to_string()))?
            } else {
                return Err(Error::InvalidUrl(s.to_string()));
            };
            // The bracket contents must be a real IPv6 address (optionally with
            // a `%25`-encoded zone ID); `[evil.com]` is not a host.
            if ipv6_literal(&hostport[1..close]).is_none() {
                return Err(Error::InvalidUrl(s.to_string()));
            }
            (&hostport[..=close], port, true)
        } else if hostport.starts_with('[') {
            // Opening bracket with no closing one — unterminated IPv6 literal.
            return Err(Error::InvalidUrl(s.to_string()));
        } else {
            match hostport.rfind(':') {
                Some(i) => {
                    let h = &hostport[..i];
                    let p = parse_port(&hostport[i + 1..], default_port)
                        .ok_or_else(|| Error::InvalidUrl(s.to_string()))?;
                    (h, p, false)
                }
                None => (hostport, default_port, false),
            }
        };

        if host.is_empty() {
            return Err(Error::InvalidUrl(s.to_string()));
        }

        // Port 0 is the kernel's "pick any" sentinel — never a real
        // destination — so reject it rather than silently dialling it.
        if port == 0 {
            return Err(Error::InvalidUrl(s.to_string()));
        }

        // The host, userinfo, and path are written verbatim into the request
        // line and the `Host:` header. A control char, DEL, or raw space in any
        // of them would let an attacker splice in extra header lines (CRLF
        // injection / request smuggling), so reject them outright.
        reject_forbidden(host, s)?;
        // Parser-differential / host-confusion hardening: a backslash is
        // treated like `/` by some resolvers and agents, and a literal `%`
        // is meaningless in a host here (no host percent-decoding happens).
        // Either one in a reg-name/IPv4 host lets a crafted authority split
        // differently across components (e.g. `allowed.example\@evil.example`),
        // so reject both. This does NOT apply to bracketed IPv6 literals,
        // whose zone IDs legitimately use `%`.
        if !bracketed && host.bytes().any(|b| b == b'\\' || b == b'%') {
            return Err(Error::InvalidUrl(s.to_string()));
        }
        if let Some(info) = &userinfo {
            reject_forbidden(info, s)?;
            // A backslash anywhere in the authority is the host-confusion
            // bait: agents that fold `\` into `/` reparse the authority so
            // that the text before the `\@` becomes the host. Because we
            // split userinfo with `rfind('@')`, such a backslash lands here
            // rather than in `host`, so reject it in the userinfo too.
            if info.bytes().any(|b| b == b'\\') {
                return Err(Error::InvalidUrl(s.to_string()));
            }
        }
        reject_forbidden(path, s)?;

        Ok(Url {
            scheme,
            userinfo,
            host: host.to_string(),
            port,
            path: path.to_string(),
        })
    }

    /// The host in the form a resolver, socket, or TLS stack expects: an IPv6
    /// literal loses its URL brackets (`[::1]` → `::1`); every other host is
    /// returned unchanged. [`Url::host`] keeps the brackets for the `Host:`
    /// header and request authority.
    pub fn host_unbracketed(&self) -> &str {
        unbracket(&self.host)
    }

    /// True if this scheme runs over TLS at the transport layer.
    pub fn is_tls(&self) -> bool {
        matches!(
            self.scheme.as_str(),
            "https" | "ftps" | "imaps" | "pop3s" | "ldaps" | "gophers" | "mqtts" | "wss"
        )
    }

    /// Normalise the host to its ASCII/punycode (IDN, UTS-46) form when
    /// `enabled`. Idempotent and a no-op for ASCII hosts (IPv4, bracketed
    /// IPv6, already-punycode names), when disabled, or when the crate is built
    /// without the `idn` feature. Returns an error only for an undecodable
    /// internationalised host. See the crate-internal `idn` module.
    pub fn set_idn(&mut self, enabled: bool) -> Result<()> {
        self.host = crate::idn::to_ascii(&self.host, enabled)?;
        Ok(())
    }
}

/// Resolve a redirect target per RFC 3986 §5.2 (the cases that show up in
/// real `Location:` headers, RFC 9110 §10.2.2): an absolute URL, a
/// network-path reference (`//host/...`), an absolute path (`/foo`), a
/// relative path (`foo/bar`, `../x`), a query-only reference (`?q=1`, which
/// keeps the base path), or a fragment-only reference (the base document).
/// Fragments are dropped, dot segments are removed (by [`Url::parse`]), and
/// raw spaces or non-ASCII bytes in the path/query are percent-encoded (as
/// curl does) instead of failing the redirect.
pub(crate) fn resolve(base: &Url, location: &str) -> Result<Url> {
    let loc = location.trim();
    if loc.is_empty() {
        return Err(Error::InvalidUrl("empty Location".to_string()));
    }

    // Absolute URL: scheme://...
    if let Some(idx) = loc.find("://") {
        let scheme = &loc[..idx];
        let ok = !scheme.is_empty()
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.');
        if ok {
            let after = idx + 3;
            let auth_end = loc[after..]
                .find(['/', '?', '#'])
                .map_or(loc.len(), |i| after + i);
            let composed = format!("{}{}", &loc[..auth_end], encode_loose(&loc[auth_end..]));
            return Url::parse(&composed);
        }
    }

    // Network-path reference: //host/path — inherit the base scheme.
    if let Some(rest) = loc.strip_prefix("//") {
        let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let composed = format!(
            "{}://{}{}",
            base.scheme,
            &rest[..auth_end],
            encode_loose(&rest[auth_end..])
        );
        return Url::parse(&composed);
    }

    // Strip any fragment from the location before composing.
    let loc_no_frag = match loc.find('#') {
        Some(i) => &loc[..i],
        None => loc,
    };
    let loc_no_frag = encode_loose(loc_no_frag);

    let default_p = default_port(&base.scheme).unwrap_or(0);
    let needs_port = base.port != default_p;
    let authority = if needs_port {
        format!("{}:{}", base.host, base.port)
    } else {
        base.host.clone()
    };

    let base_path = base.path.as_str();
    let base_path_no_query = base_path.split_once('?').map_or(base_path, |(p, _)| p);

    // Fragment-only reference (`#frag`): the base document itself.
    if loc_no_frag.is_empty() {
        let composed = format!("{}://{}{}", base.scheme, authority, base_path);
        return Url::parse(&composed);
    }

    // Query-only reference (`?q=1`): keep the base path, replace the query
    // (RFC 3986 §5.2.2 — not the base *directory*).
    if loc_no_frag.starts_with('?') {
        let composed = format!(
            "{}://{}{}{}",
            base.scheme, authority, base_path_no_query, loc_no_frag
        );
        return Url::parse(&composed);
    }

    // Absolute-path reference: /foo?bar
    if loc_no_frag.starts_with('/') {
        let composed = format!("{}://{}{}", base.scheme, authority, loc_no_frag);
        return Url::parse(&composed);
    }

    // Relative path: merge with the base directory (RFC 3986 §5.2.3); `parse`
    // then removes dot segments (§5.2.4).
    let dir = match base_path_no_query.rfind('/') {
        Some(i) => &base_path_no_query[..=i],
        None => "/",
    };
    let composed = format!("{}://{}{}{}", base.scheme, authority, dir, loc_no_frag);
    Url::parse(&composed)
}

/// Percent-encode the bytes a lenient `Location:` may carry raw but a request
/// line cannot: space and non-ASCII. Control bytes are deliberately left
/// alone so [`Url::parse`] still rejects them (header-injection guard).
fn encode_loose(s: &str) -> std::borrow::Cow<'_, str> {
    if !s.bytes().any(|b| b == b' ' || b >= 0x80) {
        return std::borrow::Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for &b in s.as_bytes() {
        if b == b' ' || b >= 0x80 {
            out.push_str(&format!("%{b:02X}"));
        } else {
            out.push(b as char);
        }
    }
    std::borrow::Cow::Owned(out)
}

/// RFC 3986 §5.2.4 `remove_dot_segments` for an absolute path (starting with
/// `/`), leaving any `?query` untouched: `/a/b/../c/./d` → `/a/c/d`. A
/// trailing `.`/`..` keeps the directory's trailing slash, and `..` never
/// climbs above the root.
pub(crate) fn remove_dot_segments(path_and_query: &str) -> String {
    let (path, query) = match path_and_query.find('?') {
        Some(i) => path_and_query.split_at(i),
        None => (path_and_query, ""),
    };
    if !path.split('/').any(|seg| seg == "." || seg == "..") {
        return path_and_query.to_string();
    }
    let segs: Vec<&str> = path.split('/').skip(1).collect();
    let last = segs.len().saturating_sub(1);
    let mut out: Vec<&str> = Vec::with_capacity(segs.len());
    for (i, seg) in segs.iter().enumerate() {
        let dot = *seg == "." || *seg == "..";
        if *seg == ".." {
            out.pop();
        } else if !dot {
            out.push(seg);
        }
        if dot && i == last {
            out.push("");
        }
    }
    format!("/{}{}", out.join("/"), query)
}

/// Parse an authority port: ASCII digits only (so no `+80`) and no overflow.
/// An empty port (`http://h:/`) means the scheme default, like curl.
fn parse_port(p: &str, default_port: u16) -> Option<u16> {
    if p.is_empty() {
        return Some(default_port);
    }
    if !p.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    p.parse().ok()
}

/// `host` without the URL brackets of an IPv6 literal (`[::1]` → `::1`,
/// `[fe80::1%25en0]` → `fe80::1%25en0`). Any other host is returned as is.
pub(crate) fn unbracket(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

/// Parse the inside of an IPv6 literal (no brackets) with an optional zone ID
/// (`fe80::1%25en0`, RFC 6874; a bare `%en0` is tolerated too). Returns the
/// address and the zone text, or `None` if it is not a valid IPv6 literal.
pub(crate) fn ipv6_literal(inner: &str) -> Option<(std::net::Ipv6Addr, Option<&str>)> {
    let (addr, zone) = match inner.find('%') {
        Some(i) => {
            let z = &inner[i + 1..];
            let z = z.strip_prefix("25").filter(|z| !z.is_empty()).unwrap_or(z);
            let zone_ok = !z.is_empty()
                && z.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'));
            if !zone_ok {
                return None;
            }
            (&inner[..i], Some(z))
        }
        None => (inner, None),
    };
    addr.parse().ok().map(|a| (a, zone))
}

/// If `host` (bracketed or not) is an IP literal, its socket address without
/// any DNS lookup. A numeric IPv6 zone ID becomes the scope ID; an
/// interface-name zone cannot be mapped portably and yields `None`.
pub(crate) fn ip_literal_addr(host: &str, port: u16) -> Option<std::net::SocketAddr> {
    use std::net::{SocketAddr, SocketAddrV6};
    let h = unbracket(host);
    if let Ok(ip) = h.parse::<std::net::IpAddr>() {
        return Some(SocketAddr::new(ip, port));
    }
    let (ip, zone) = ipv6_literal(h)?;
    let scope = match zone {
        Some(z) => z.parse().ok()?,
        None => 0,
    };
    Some(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, scope)))
}

/// Percent-decode `s` (RFC 3986 §2.1) to a string; `%XX` with invalid hex is
/// kept verbatim and invalid UTF-8 is replaced lossily. `+` is not special.
pub(crate) fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = |c: u8| (c as char).to_digit(16);
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Format `host:port` for a request authority or `CONNECT` line, bracketing a
/// bare IPv6 literal (`::1` → `[::1]:443`).
pub(crate) fn authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Reject any field destined for the request line / `Host:` header that
/// carries a byte capable of forging a header boundary or otherwise corrupting
/// the wire framing: ASCII control chars (`< 0x20`, which includes CR and LF),
/// DEL (`0x7f`), and a raw space.
fn reject_forbidden(field: &str, original: &str) -> Result<()> {
    if field.bytes().any(|b| b < 0x20 || b == 0x7f || b == b' ') {
        return Err(Error::InvalidUrl(original.to_string()));
    }
    Ok(())
}

/// Default port for every scheme rsurl knows about. Returning `None` means
/// the scheme is not recognized at all (URL parsing will reject it).
fn default_port(scheme: &str) -> Option<u16> {
    Some(match scheme {
        "http" | "ws" => 80,
        "https" | "wss" => 443,
        "ftp" => 21,
        "ftps" => 990,
        "dict" => 2628,
        "gopher" | "gophers" => 70,
        "imap" => 143,
        "imaps" => 993,
        "ldap" => 389,
        "ldaps" => 636,
        "mqtt" => 1883,
        "mqtts" => 8883,
        "pop3" => 110,
        "pop3s" => 995,
        "smtp" => 25,
        "smtps" => 465,
        "telnet" => 23,
        "rtsp" => 554,
        "tftp" => 69,
        "sftp" | "scp" => 22,
        _ => return None,
    })
}

/// Split a `user[:pass]` userinfo string on the first `:` into `(user, pass)`.
/// A missing password becomes an empty string. Shared by the protocol modules
/// that take credentials from the URL userinfo (imap, pop3).
pub(crate) fn split_userinfo(s: &str) -> (&str, &str) {
    match s.find(':') {
        Some(i) => (&s[..i], &s[i + 1..]),
        None => (s, ""),
    }
}

/// The first illegal control byte in `s`, if any: an ASCII control (`< 0x20`,
/// which covers CR, LF, and NUL) or `DEL` (`0x7f`). The single definition of
/// "illegal control byte" shared by the line-oriented protocol backends, which
/// must reject such bytes in URL-derived fields before interpolating them into
/// a command (request-smuggling / header-injection guard).
pub(crate) fn first_control_byte(s: &str) -> Option<u8> {
    s.bytes().find(|b| *b < 0x20 || *b == 0x7f)
}

/// Reject `s` if it carries an illegal control byte (see [`first_control_byte`]),
/// with a `proto: what contains ...` [`Error::BadResponse`]. `proto` names the
/// scheme (e.g. `"ftp"`) and `what` the field, for the error message. Protocols
/// using a different error variant (e.g. SSH) call [`first_control_byte`]
/// directly.
pub(crate) fn reject_ctl(proto: &str, what: &str, s: &str) -> Result<()> {
    match first_control_byte(s) {
        Some(b) => Err(Error::BadResponse(format!(
            "{proto}: {what} contains illegal control byte {b:#04x}"
        ))),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_userinfo_splits_on_first_colon() {
        assert_eq!(split_userinfo("alice:secret"), ("alice", "secret"));
        assert_eq!(split_userinfo("alice"), ("alice", ""));
        assert_eq!(split_userinfo("alice:"), ("alice", ""));
        assert_eq!(split_userinfo(":only-pass"), ("", "only-pass"));
        assert_eq!(split_userinfo("alice:s:e:c"), ("alice", "s:e:c"));
    }

    #[test]
    fn parses_http() {
        let u = Url::parse("http://example.com/foo?bar=1").unwrap();
        assert_eq!(u.scheme, "http");
        assert_eq!(u.host, "example.com");
        assert_eq!(u.port, 80);
        assert_eq!(u.path, "/foo?bar=1");
        assert_eq!(u.userinfo, None);
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

    #[test]
    fn parses_userinfo() {
        let u = Url::parse("ftp://alice:secret@ftp.example.com/pub/").unwrap();
        assert_eq!(u.scheme, "ftp");
        assert_eq!(u.userinfo.as_deref(), Some("alice:secret"));
        assert_eq!(u.host, "ftp.example.com");
        assert_eq!(u.port, 21);
        assert_eq!(u.path, "/pub/");
    }

    #[test]
    fn parses_file_url() {
        let u = Url::parse("file:///etc/hosts").unwrap();
        assert_eq!(u.scheme, "file");
        assert_eq!(u.host, "");
        assert_eq!(u.path, "/etc/hosts");
    }

    #[test]
    fn default_ports_cover_all_protocols() {
        for scheme in [
            "http", "https", "ftp", "ftps", "dict", "gopher", "gophers", "imap", "imaps", "ldap",
            "ldaps", "mqtt", "mqtts", "pop3", "pop3s", "rtsp", "tftp", "ws", "wss", "sftp", "scp",
        ] {
            let url = format!("{scheme}://example.com");
            let u = Url::parse(&url).unwrap_or_else(|e| panic!("scheme {scheme}: {e}"));
            assert_ne!(u.port, 0, "scheme {scheme} got port 0");
        }
    }

    #[test]
    fn resolve_absolute_url() {
        let base = Url::parse("http://a.example/foo").unwrap();
        let r = resolve(&base, "https://b.example/bar").unwrap();
        assert_eq!(r.scheme, "https");
        assert_eq!(r.host, "b.example");
        assert_eq!(r.path, "/bar");
    }

    #[test]
    fn resolve_protocol_relative() {
        let base = Url::parse("https://a.example/foo").unwrap();
        let r = resolve(&base, "//c.example/baz").unwrap();
        assert_eq!(r.scheme, "https");
        assert_eq!(r.host, "c.example");
        assert_eq!(r.path, "/baz");
    }

    #[test]
    fn resolve_absolute_path() {
        let base = Url::parse("http://a.example/foo/bar?q=1").unwrap();
        let r = resolve(&base, "/quux").unwrap();
        assert_eq!(r.scheme, "http");
        assert_eq!(r.host, "a.example");
        assert_eq!(r.path, "/quux");
    }

    #[test]
    fn resolve_relative_path() {
        let base = Url::parse("http://a.example/foo/bar").unwrap();
        let r = resolve(&base, "baz").unwrap();
        assert_eq!(r.path, "/foo/baz");
    }

    #[test]
    fn resolve_relative_path_trailing_slash() {
        let base = Url::parse("http://a.example/foo/").unwrap();
        let r = resolve(&base, "baz").unwrap();
        assert_eq!(r.path, "/foo/baz");
    }

    #[test]
    fn resolve_preserves_nonstandard_port() {
        let base = Url::parse("http://a.example:8080/x").unwrap();
        let r = resolve(&base, "/y").unwrap();
        assert_eq!(r.host, "a.example");
        assert_eq!(r.port, 8080);
        assert_eq!(r.path, "/y");
    }

    #[test]
    fn resolve_strips_location_fragment() {
        let base = Url::parse("http://a.example/").unwrap();
        let r = resolve(&base, "/path#frag").unwrap();
        assert_eq!(r.path, "/path");
    }

    #[test]
    fn resolve_strips_base_query_for_relative() {
        // Relative reference should not pick up the base's query string.
        let base = Url::parse("http://a.example/foo?x=1").unwrap();
        let r = resolve(&base, "bar").unwrap();
        assert_eq!(r.path, "/bar");
    }

    #[test]
    fn resolve_rejects_empty() {
        let base = Url::parse("http://a.example/").unwrap();
        assert!(resolve(&base, "").is_err());
    }

    #[test]
    fn parses_ipv6_literal_with_port() {
        let u = Url::parse("http://[::1]:8080/x").unwrap();
        assert_eq!(u.host, "[::1]");
        assert_eq!(u.port, 8080);
        assert_eq!(u.path, "/x");
    }

    #[test]
    fn parses_ipv6_literal_default_port() {
        let u = Url::parse("http://[::1]/x").unwrap();
        assert_eq!(u.host, "[::1]");
        assert_eq!(u.port, 80);
    }

    #[test]
    fn rejects_unterminated_ipv6_literal() {
        assert!(Url::parse("http://[::1/x").is_err());
        assert!(Url::parse("http://[::1").is_err());
    }

    #[test]
    fn rejects_bracket_without_leading_bracket() {
        // `a]b:80` — a stray `]` with no opening bracket is malformed.
        assert!(Url::parse("http://a]b:80/x").is_err());
    }

    #[test]
    fn rejects_port_zero() {
        assert!(Url::parse("http://example.com:0/").is_err());
        assert!(Url::parse("http://[::1]:0/").is_err());
    }

    #[test]
    fn rejects_control_char_in_host() {
        // Raw CR/LF or other control bytes in the host would let a crafted URL
        // splice extra header lines into the request.
        assert!(Url::parse("http://exa\rmple.com/").is_err());
        assert!(Url::parse("http://exa\nmple.com/").is_err());
        assert!(Url::parse("http://exa\x00mple.com/").is_err());
    }

    #[test]
    fn rejects_space_in_host() {
        assert!(Url::parse("http://exa mple.com/").is_err());
    }

    #[test]
    fn rejects_backslash_in_host() {
        // A backslash in a reg-name host is treated like `/` by some agents,
        // enabling authority confusion — reject it.
        assert!(Url::parse("http://a\\b.com/").is_err());
        assert!(Url::parse("http://allowed\\@evil.com/").is_err());
    }

    #[test]
    fn rejects_percent_in_host() {
        // A literal `%` in a reg-name host is meaningless (no host
        // percent-decoding happens) and aids parser-differential attacks.
        assert!(Url::parse("http://ho%73t.com/").is_err());
    }

    #[test]
    fn allows_normal_host_with_port() {
        let u = Url::parse("http://host.example:8080/p").unwrap();
        assert_eq!(u.host, "host.example");
        assert_eq!(u.port, 8080);
        assert_eq!(u.path, "/p");
    }

    #[test]
    fn ipv6_literal_unaffected_by_host_denylist() {
        // The backslash/percent rejection must not touch bracketed IPv6.
        let u = Url::parse("http://[::1]:8080/").unwrap();
        assert_eq!(u.host, "[::1]");
        assert_eq!(u.port, 8080);
        assert_eq!(u.path, "/");
    }

    #[test]
    fn rejects_control_char_in_path() {
        assert!(Url::parse("http://example.com/foo\r\nX: y").is_err());
        assert!(Url::parse("http://example.com/foo bar").is_err());
        assert!(Url::parse("http://example.com/foo\x7f").is_err());
    }

    #[test]
    fn rejects_control_char_in_userinfo() {
        assert!(Url::parse("http://us\rer:pass@example.com/").is_err());
    }

    #[test]
    fn resolve_rejects_injected_location() {
        // A `Location:` value carrying a control char must be rejected when it
        // is reparsed, closing the redirect-borne injection path.
        let base = Url::parse("http://a.example/").unwrap();
        assert!(resolve(&base, "http://evil\r\nX: y/").is_err());
        assert!(resolve(&base, "/foo\r\nX: y").is_err());
    }

    #[test]
    fn authority_ends_at_query_not_at_userinfo_at() {
        // NET-1: a `?` must terminate the authority before `rfind('@')` runs,
        // so the `@` lives in the query and cannot hijack the host.
        let u = Url::parse("http://expected.com?x=@attacker.com").unwrap();
        assert_eq!(u.host, "expected.com");
        assert_eq!(u.userinfo, None);
        assert_eq!(u.path, "/?x=@attacker.com");
    }

    #[test]
    fn authority_ends_at_fragment_not_at_userinfo_at() {
        // NET-1: a `#` must terminate the authority too; the fragment (with its
        // `@`) is then stripped and the host stays `expected.com`.
        let u = Url::parse("http://expected.com#@attacker.com/").unwrap();
        assert_eq!(u.host, "expected.com");
        assert_eq!(u.userinfo, None);
        assert_eq!(u.path, "/");
    }

    #[test]
    fn userinfo_host_path_query_fragment_all_parse() {
        let u = Url::parse("http://user:pass@host/path?q#f").unwrap();
        assert_eq!(u.userinfo.as_deref(), Some("user:pass"));
        assert_eq!(u.host, "host");
        assert_eq!(u.port, 80);
        assert_eq!(u.path, "/path?q");
    }

    #[test]
    fn normal_url_with_query_and_fragment_unchanged() {
        let u = Url::parse("http://h/p?a=b#frag").unwrap();
        assert_eq!(u.host, "h");
        assert_eq!(u.path, "/p?a=b");
        assert_eq!(u.userinfo, None);
    }

    #[test]
    fn is_tls_classification() {
        for s in [
            "https", "ftps", "imaps", "pop3s", "ldaps", "gophers", "mqtts", "wss",
        ] {
            let u = Url::parse(&format!("{s}://h")).unwrap();
            assert!(u.is_tls(), "{s} should be tls");
        }
        for s in [
            "http", "ftp", "imap", "pop3", "ldap", "gopher", "mqtt", "ws", "dict", "tftp", "rtsp",
        ] {
            let u = Url::parse(&format!("{s}://h")).unwrap();
            assert!(!u.is_tls(), "{s} should not be tls");
        }
    }

    #[cfg(feature = "idn")]
    #[test]
    fn set_idn_punycodes_unicode_host() {
        let mut u = Url::parse("http://münchen.de/weiß").unwrap();
        u.set_idn(true).unwrap();
        assert_eq!(u.host, "xn--mnchen-3ya.de");
        // Only the host is normalised; the path is left as parsed.
        assert_eq!(u.path, "/weiß");
    }

    #[test]
    fn set_idn_disabled_leaves_host_raw() {
        let mut u = Url::parse("http://münchen.de/").unwrap();
        u.set_idn(false).unwrap();
        assert_eq!(u.host, "münchen.de");
    }

    #[test]
    fn set_idn_is_noop_for_ascii_and_ip_hosts() {
        for (raw, host) in [
            ("http://example.com/", "example.com"),
            ("http://127.0.0.1:8080/", "127.0.0.1"),
            ("http://[::1]:8080/", "[::1]"),
            ("http://xn--mnchen-3ya.de/", "xn--mnchen-3ya.de"),
        ] {
            let mut u = Url::parse(raw).unwrap();
            u.set_idn(true).unwrap();
            assert_eq!(u.host, host, "ASCII/IP host must be unchanged: {raw}");
        }
    }

    /// A query- or fragment-only reference must still produce a root path, or
    /// the request line becomes `GET ?x=1 HTTP/1.1` / `GET  HTTP/1.1`.
    #[test]
    fn query_or_fragment_only_url_gets_root_path() {
        assert_eq!(Url::parse("http://h?x=1").unwrap().path, "/?x=1");
        assert_eq!(Url::parse("http://h#frag").unwrap().path, "/");
        assert_eq!(Url::parse("http://h:8080?a=b#c").unwrap().path, "/?a=b");
    }

    /// RFC 3986 §5.2.4 dot-segment removal (curl does it unless --path-as-is).
    #[test]
    fn dot_segments_are_removed_from_path() {
        let cases = [
            ("http://h/a/b/../c/./d", "/a/c/d"),
            ("http://h/a/b/..", "/a/"),
            ("http://h/a/b/.", "/a/b/"),
            ("http://h/../../x", "/x"),
            ("http://h/..", "/"),
            ("http://h/a/./", "/a/"),
            // Only whole segments are dots; the query is untouched.
            ("http://h/a/..b/.c?q=/../x", "/a/..b/.c?q=/../x"),
            ("http://h/a/../b?x=../y", "/b?x=../y"),
            // Empty segments are preserved.
            ("http://h/a//b/../c", "/a//c"),
        ];
        for (raw, path) in cases {
            assert_eq!(Url::parse(raw).unwrap().path, path, "{raw}");
        }
    }

    #[test]
    fn resolve_query_only_keeps_base_path() {
        let base = Url::parse("http://h/list/items?page=1").unwrap();
        assert_eq!(
            resolve(&base, "?page=2").unwrap().path,
            "/list/items?page=2"
        );
    }

    #[test]
    fn resolve_fragment_only_is_base_document() {
        let base = Url::parse("http://h/foo/bar?x=1").unwrap();
        assert_eq!(resolve(&base, "#frag").unwrap().path, "/foo/bar?x=1");
    }

    #[test]
    fn resolve_removes_dot_segments() {
        let base = Url::parse("http://h/a/b/c").unwrap();
        assert_eq!(resolve(&base, "../x").unwrap().path, "/a/x");
        assert_eq!(resolve(&base, "./y").unwrap().path, "/a/b/y");
        assert_eq!(resolve(&base, "../../../../z").unwrap().path, "/z");
        assert_eq!(resolve(&base, "/p/../q").unwrap().path, "/q");
        assert_eq!(resolve(&base, "..").unwrap().path, "/a/");
    }

    /// RFC 3986 §5.4.1 normal examples that apply to HTTP redirects.
    #[test]
    fn resolve_rfc3986_normal_examples() {
        let base = Url::parse("http://a/b/c/d;p?q").unwrap();
        let cases = [
            ("g", "/b/c/g"),
            ("./g", "/b/c/g"),
            ("g/", "/b/c/g/"),
            ("/g", "/g"),
            ("?y", "/b/c/d;p?y"),
            ("g?y", "/b/c/g?y"),
            ("#s", "/b/c/d;p?q"),
            ("g#s", "/b/c/g"),
            (";x", "/b/c/;x"),
            (".", "/b/c/"),
            ("./", "/b/c/"),
            ("..", "/b/"),
            ("../", "/b/"),
            ("../g", "/b/g"),
            ("../..", "/"),
            ("../../g", "/g"),
        ];
        for (reference, path) in cases {
            let r = resolve(&base, reference).unwrap();
            assert_eq!(r.host, "a", "{reference}");
            assert_eq!(r.path, path, "{reference}");
        }
    }

    /// curl percent-encodes a raw space (and 8-bit bytes) in a redirect
    /// target instead of failing; control bytes stay rejected.
    #[test]
    fn resolve_percent_encodes_space_and_non_ascii() {
        let base = Url::parse("http://h/dir/").unwrap();
        assert_eq!(resolve(&base, "a b").unwrap().path, "/dir/a%20b");
        assert_eq!(resolve(&base, "/é").unwrap().path, "/%C3%A9");
        let abs = resolve(&base, "http://o.example/x y?q=1 2").unwrap();
        assert_eq!(abs.host, "o.example");
        assert_eq!(abs.path, "/x%20y?q=1%202");
        assert!(resolve(&base, "/a\r\nX: y").is_err());
    }

    #[test]
    fn empty_port_means_default_and_plus_sign_is_rejected() {
        assert_eq!(Url::parse("http://h:/").unwrap().port, 80);
        assert_eq!(Url::parse("https://[::1]:/").unwrap().port, 443);
        assert!(Url::parse("http://h:+80/").is_err());
        assert!(Url::parse("http://h:-1/").is_err());
        assert!(Url::parse("http://h:65536/").is_err());
        assert!(Url::parse("http://[::1]:+80/").is_err());
    }

    #[test]
    fn bracketed_host_must_be_ipv6() {
        assert!(Url::parse("http://[evil.com]/").is_err());
        assert!(Url::parse("http://[127.0.0.1]/").is_err());
        assert!(Url::parse("http://[]/").is_err());
        assert!(Url::parse("http://[::1%]/").is_err());
        assert!(Url::parse("http://[::1%25a/b]/").is_err());
        let u = Url::parse("http://[fe80::1%25en0]:8080/").unwrap();
        assert_eq!(u.host, "[fe80::1%25en0]");
        assert_eq!(u.host_unbracketed(), "fe80::1%25en0");
        assert_eq!(Url::parse("http://[2001:db8::1]/").unwrap().port, 80);
    }

    #[test]
    fn scheme_is_case_insensitive_including_file() {
        assert_eq!(Url::parse("HTTP://h/").unwrap().scheme, "http");
        let f = Url::parse("FILE:///tmp/x").unwrap();
        assert_eq!(f.scheme, "file");
        assert_eq!(f.path, "/tmp/x");
    }

    #[test]
    fn file_url_accepts_localhost_authority_only() {
        assert_eq!(
            Url::parse("file://localhost/etc/hosts").unwrap().path,
            "/etc/hosts"
        );
        assert_eq!(Url::parse("file:///etc/hosts").unwrap().path, "/etc/hosts");
        assert!(Url::parse("file://otherhost/etc/hosts").is_err());
    }

    #[test]
    fn unbracket_and_ip_literal_helpers() {
        assert_eq!(unbracket("[::1]"), "::1");
        assert_eq!(unbracket("example.com"), "example.com");
        assert_eq!(
            ip_literal_addr("[::1]", 80),
            Some("[::1]:80".parse().unwrap())
        );
        assert_eq!(
            ip_literal_addr("10.0.0.1", 81),
            Some("10.0.0.1:81".parse().unwrap())
        );
        assert_eq!(ip_literal_addr("example.com", 80), None);
        // Interface-name zones cannot be mapped portably.
        assert_eq!(ip_literal_addr("[fe80::1%25en0]", 80), None);
        assert_eq!(authority("::1", 443), "[::1]:443");
        assert_eq!(authority("[::1]", 443), "[::1]:443");
        assert_eq!(authority("h", 80), "h:80");
    }

    #[test]
    fn percent_decode_basic() {
        assert_eq!(percent_decode("p%40ss%3Aw"), "p@ss:w");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz%4"), "%zz%4");
        assert_eq!(percent_decode("a+b"), "a+b");
    }
}

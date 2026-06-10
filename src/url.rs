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
        if scheme == "file" {
            let path = match s.strip_prefix("file://") {
                Some(p) if p.starts_with('/') => p.to_string(),
                Some(_) | None => return Err(Error::InvalidUrl(s.to_string())),
            };
            let path = match path.find('#') {
                Some(i) => path[..i].to_string(),
                None => path,
            };
            return Ok(Url {
                scheme,
                userinfo: None,
                host: String::new(),
                port: 0,
                path,
            });
        }

        if authority.is_empty() {
            return Err(Error::InvalidUrl(s.to_string()));
        }

        // Strip optional fragment from path.
        let path = match path.find('#') {
            Some(i) => &path[..i],
            None => path,
        };

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
                p.parse().map_err(|_| Error::InvalidUrl(s.to_string()))?
            } else {
                return Err(Error::InvalidUrl(s.to_string()));
            };
            (&hostport[..=close], port, true)
        } else if hostport.starts_with('[') {
            // Opening bracket with no closing one — unterminated IPv6 literal.
            return Err(Error::InvalidUrl(s.to_string()));
        } else {
            match hostport.rfind(':') {
                Some(i) => {
                    let h = &hostport[..i];
                    let p: u16 = hostport[i + 1..]
                        .parse()
                        .map_err(|_| Error::InvalidUrl(s.to_string()))?;
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

/// Resolve a redirect target. `location` may be an absolute URL, a
/// protocol-relative reference (`//host/...`), an absolute path (`/foo`), or
/// a relative path (`foo/bar`); we cover the cases that show up in real
/// `Location:` headers per RFC 9110 §10.2.2. Any fragment on `location` is
/// stripped before reparsing.
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
            return Url::parse(loc);
        }
    }

    // Protocol-relative: //host/path — inherit the base scheme.
    if let Some(rest) = loc.strip_prefix("//") {
        let composed = format!("{}://{}", base.scheme, rest);
        return Url::parse(&composed);
    }

    // Strip any fragment from the location before composing.
    let loc_no_frag = match loc.find('#') {
        Some(i) => &loc[..i],
        None => loc,
    };

    let default_p = default_port(&base.scheme).unwrap_or(0);
    let needs_port = base.port != default_p;
    let authority = if needs_port {
        format!("{}:{}", base.host, base.port)
    } else {
        base.host.clone()
    };

    // Absolute-path reference: /foo?bar
    if loc_no_frag.starts_with('/') {
        let composed = format!("{}://{}{}", base.scheme, authority, loc_no_frag);
        return Url::parse(&composed);
    }

    // Relative path. Drop everything after the last '/' in the base path,
    // then append. RFC 3986 §5.2.3 — also strip the base's query first.
    let base_path = base.path.as_str();
    let base_path_no_query = match base_path.find('?') {
        Some(i) => &base_path[..i],
        None => base_path,
    };
    let dir = match base_path_no_query.rfind('/') {
        Some(i) => &base_path_no_query[..=i],
        None => "/",
    };
    let composed = format!("{}://{}{}{}", base.scheme, authority, dir, loc_no_frag);
    Url::parse(&composed)
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
        assert_eq!(u.path, "?x=@attacker.com");
    }

    #[test]
    fn authority_ends_at_fragment_not_at_userinfo_at() {
        // NET-1: a `#` must terminate the authority too; the fragment (with its
        // `@`) is then stripped and the host stays `expected.com`.
        let u = Url::parse("http://expected.com#@attacker.com/").unwrap();
        assert_eq!(u.host, "expected.com");
        assert_eq!(u.userinfo, None);
        assert_eq!(u.path, "");
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
}

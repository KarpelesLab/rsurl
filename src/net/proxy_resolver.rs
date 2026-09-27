//! Per-request proxy selection.
//!
//! [`crate::Request::proxy`] sets one fixed proxy. For dynamic selection — a
//! system proxy, environment variables, or a PAC script — attach a
//! [`ProxyResolver`] with [`crate::Request::proxy_resolver`]; rsurl consults it
//! once per request (for the request URL) when no explicit proxy/connector is
//! set, and applies whatever it returns.
//!
//! [`from_env`] is a ready-made resolver that mirrors curl's environment-proxy
//! behaviour (`http_proxy` / `HTTPS_PROXY` / `ALL_PROXY` / `NO_PROXY`; the
//! upper-case `HTTP_PROXY` is ignored, as in curl, to avoid "httpoxy"). A PAC
//! engine can be wrapped behind the same trait by the embedder (rsurl ships the
//! hook, not a JavaScript interpreter).

use crate::url::Url;

/// What a [`ProxyResolver`] decided for a URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyChoice {
    /// Connect directly, no proxy.
    Direct,
    /// Route through this proxy (a curl-style proxy URL, e.g.
    /// `http://host:8080`, `socks5://host:1080`).
    Proxy(String),
}

/// Chooses a proxy per request URL. Must be `Send + Sync` (a request may run on
/// any thread) and `Debug` (so a [`crate::Request`] holding one stays `Debug`).
pub trait ProxyResolver: Send + Sync + std::fmt::Debug {
    /// Decide how to reach `url`.
    fn resolve(&self, url: &Url) -> ProxyChoice;
}

/// Environment-variable proxy resolver (curl semantics):
///
/// * `no_proxy` / `NO_PROXY` (lower-case preferred) → [`ProxyChoice::Direct`]
///   for matching hosts; see the entry syntax on
///   [`Client::no_proxy`](crate::Client::no_proxy).
/// * `<scheme>_proxy` for the URL's scheme (`ws`/`wss` use the `http`/`https`
///   variables), else `all_proxy`. Each is read lower-case first, then
///   upper-case — except `HTTP_PROXY`, which is **never** read: under CGI a
///   client-supplied `Proxy:` request header arrives as `HTTP_PROXY`, so
///   honouring it would let a remote client choose the proxy ("httpoxy",
///   CVE-2016-5385). curl ignores it for the same reason.
#[derive(Debug, Clone, Default)]
pub struct EnvProxyResolver;

fn env_any<S: AsRef<str>>(names: &[S]) -> Option<String> {
    names
        .iter()
        .find_map(|n| std::env::var(n.as_ref()).ok().filter(|v| !v.is_empty()))
}

/// The `<scheme>_proxy` variable names to consult for `scheme`, in order.
fn scheme_proxy_vars(scheme: &str) -> Vec<String> {
    let scheme = match scheme.to_ascii_lowercase().as_str() {
        "ws" => "http".to_string(),
        "wss" => "https".to_string(),
        other => other.to_string(),
    };
    let lower = format!("{scheme}_proxy");
    if scheme == "http" {
        // httpoxy: only the lower-case form, which a CGI header cannot set.
        vec![lower]
    } else {
        let upper = lower.to_ascii_uppercase();
        vec![lower, upper]
    }
}

impl ProxyResolver for EnvProxyResolver {
    fn resolve(&self, url: &Url) -> ProxyChoice {
        if let Some(no) = env_any(&["no_proxy", "NO_PROXY"]) {
            if no_proxy_matches(no.split(','), &url.host) {
                return ProxyChoice::Direct;
            }
        }
        match env_any(&scheme_proxy_vars(&url.scheme))
            .or_else(|| env_any(&["all_proxy", "ALL_PROXY"]))
        {
            Some(spec) => ProxyChoice::Proxy(spec),
            None => ProxyChoice::Direct,
        }
    }
}

/// A [`ProxyResolver`] that reads the standard proxy environment variables
/// (`http_proxy` / `HTTPS_PROXY` / `ALL_PROXY`, with `NO_PROXY` bypass) the way
/// curl does — see [`EnvProxyResolver`].
pub fn from_env() -> EnvProxyResolver {
    EnvProxyResolver
}

/// curl's `NO_PROXY` matching: does `host` match any of `entries`?
///
/// * `*` alone matches every host.
/// * For a host name, an entry matches the name itself or any subdomain of it,
///   case-insensitively; a leading or trailing `.` on the entry is ignored.
/// * For an IP-literal host (IPv6 with or without URL brackets), only IP
///   entries can match: an exact address, or a CIDR block (`10.0.0.0/8`,
///   `fc00::/7`). IPs are never suffix-matched, so `2.3.4` does not bypass the
///   proxy for `1.2.3.4`.
pub(crate) fn no_proxy_matches<'a, I>(entries: I, host: &str) -> bool
where
    I: IntoIterator<Item = &'a str>,
{
    let host_ip = crate::url::ip_literal_addr(host, 0).map(|a| a.ip());
    let host = crate::url::unbracket(host)
        .trim_end_matches('.')
        .to_ascii_lowercase();
    entries.into_iter().any(|entry| {
        let entry = entry.trim();
        if entry == "*" {
            return true;
        }
        let entry = crate::url::unbracket(entry);
        if entry.is_empty() {
            return false;
        }
        match host_ip {
            Some(ip) => match entry.split_once('/') {
                Some((net, bits)) => cidr_contains(net, bits, ip),
                None => entry.parse::<std::net::IpAddr>().is_ok_and(|e| e == ip),
            },
            None => {
                let e = entry
                    .trim_start_matches('.')
                    .trim_end_matches('.')
                    .to_ascii_lowercase();
                !e.is_empty()
                    && (host == e
                        || (host.len() > e.len()
                            && host.ends_with(&e)
                            && host.as_bytes()[host.len() - e.len() - 1] == b'.'))
            }
        }
    })
}

/// Whether `ip` falls inside the CIDR block `net/bits` (same family only).
fn cidr_contains(net: &str, bits: &str, ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    let Ok(bits) = bits.parse::<u32>() else {
        return false;
    };
    match (crate::url::unbracket(net).parse::<IpAddr>(), ip) {
        (Ok(IpAddr::V4(n)), IpAddr::V4(h)) if bits <= 32 => {
            let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
            u32::from(n) & mask == u32::from(h) & mask
        }
        (Ok(IpAddr::V6(n)), IpAddr::V6(h)) if bits <= 128 => {
            let mask = u128::MAX.checked_shl(128 - bits).unwrap_or(0);
            u128::from(n) & mask == u128::from(h) & mask
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Static(ProxyChoice);
    impl ProxyResolver for Static {
        fn resolve(&self, _url: &Url) -> ProxyChoice {
            self.0.clone()
        }
    }

    /// httpoxy: the upper-case `HTTP_PROXY` (settable by a CGI client via a
    /// `Proxy:` header) must never be consulted; other schemes accept both.
    #[test]
    fn scheme_vars_skip_uppercase_http_proxy() {
        assert_eq!(scheme_proxy_vars("http"), vec!["http_proxy"]);
        assert_eq!(scheme_proxy_vars("ws"), vec!["http_proxy"]);
        assert_eq!(
            scheme_proxy_vars("HTTPS"),
            vec!["https_proxy", "HTTPS_PROXY"]
        );
        assert_eq!(scheme_proxy_vars("wss"), vec!["https_proxy", "HTTPS_PROXY"]);
        assert_eq!(scheme_proxy_vars("ftp"), vec!["ftp_proxy", "FTP_PROXY"]);
    }

    #[test]
    fn no_proxy_host_suffix_rules() {
        let m = |list: &str, host: &str| no_proxy_matches(list.split(','), host);
        assert!(m("example.com", "example.com"));
        assert!(m("example.com", "a.b.example.com"));
        assert!(m(".example.com", "example.com"));
        assert!(m("EXAMPLE.com.", "www.Example.COM"));
        assert!(!m("example.com", "notexample.com"));
        assert!(!m("example.com", "example.com.evil.net"));
        assert!(m(" foo , *", "anything"));
        assert!(!m("", "anything"));
        assert!(!m(" , ", "anything"));
    }

    #[test]
    fn no_proxy_ip_hosts_match_exactly_or_by_cidr() {
        let m = |list: &str, host: &str| no_proxy_matches(list.split(','), host);
        // No suffix matching for IPs.
        assert!(!m("2.3.4", "1.2.3.4"));
        assert!(!m("3.4", "1.2.3.4"));
        assert!(m("1.2.3.4", "1.2.3.4"));
        // CIDR, both families.
        assert!(m("10.0.0.0/8", "10.200.3.4"));
        assert!(!m("10.0.0.0/8", "11.0.0.1"));
        assert!(m("192.168.1.0/24", "192.168.1.77"));
        assert!(m("0.0.0.0/0", "8.8.8.8"));
        assert!(m("fc00::/7", "[fd12::1]"));
        assert!(!m("fc00::/7", "[2001:db8::1]"));
        assert!(!m("10.0.0.0/8", "[::1]"));
        assert!(!m("10.0.0.0/99", "10.0.0.1"));
        // IPv6 matches bracket-insensitively on either side.
        assert!(m("::1", "[::1]"));
        assert!(m("[::1]", "[::1]"));
        assert!(m("[::1]", "::1"));
        // A CIDR entry never matches a host name.
        assert!(!m("10.0.0.0/8", "10.example"));
    }

    #[test]
    fn static_resolver_returns_choice() {
        let u = Url::parse("http://example.com/").unwrap();
        assert_eq!(Static(ProxyChoice::Direct).resolve(&u), ProxyChoice::Direct);
        assert_eq!(
            Static(ProxyChoice::Proxy("http://p:8080".into())).resolve(&u),
            ProxyChoice::Proxy("http://p:8080".into())
        );
    }
}

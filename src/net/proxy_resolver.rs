//! Per-request proxy selection.
//!
//! [`crate::Request::proxy`] sets one fixed proxy. For dynamic selection — a
//! system proxy, environment variables, or a PAC script — attach a
//! [`ProxyResolver`] with [`crate::Request::proxy_resolver`]; rsurl consults it
//! once per request (for the request URL) when no explicit proxy/connector is
//! set, and applies whatever it returns.
//!
//! [`from_env`] is a ready-made resolver that mirrors curl's environment-proxy
//! behaviour (`HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` / `NO_PROXY`). A PAC
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
/// * `NO_PROXY` (case-insensitive suffix match, `*` = everything) → [`ProxyChoice::Direct`].
/// * `<scheme>_PROXY` (`HTTP_PROXY` / `HTTPS_PROXY`) for the URL's scheme, else
///   `ALL_PROXY`. Both upper- and lower-case names are checked.
#[derive(Debug, Clone, Default)]
pub struct EnvProxyResolver;

fn env_any(names: &[&str]) -> Option<String> {
    names
        .iter()
        .find_map(|n| std::env::var(n).ok().filter(|v| !v.is_empty()))
}

impl ProxyResolver for EnvProxyResolver {
    fn resolve(&self, url: &Url) -> ProxyChoice {
        // NO_PROXY bypass list (suffix match, like curl / the existing
        // `Request::no_proxy`).
        if let Some(no) = env_any(&["NO_PROXY", "no_proxy"]) {
            let host = url.host.to_ascii_lowercase();
            for entry in no.split(',').map(|e| e.trim()).filter(|e| !e.is_empty()) {
                if entry == "*" {
                    return ProxyChoice::Direct;
                }
                let suffix = entry.trim_start_matches('.').to_ascii_lowercase();
                if host == suffix || host.ends_with(&format!(".{suffix}")) {
                    return ProxyChoice::Direct;
                }
            }
        }
        let scheme_var = if url.scheme.eq_ignore_ascii_case("https") {
            env_any(&["HTTPS_PROXY", "https_proxy"])
        } else {
            env_any(&["HTTP_PROXY", "http_proxy"])
        };
        match scheme_var.or_else(|| env_any(&["ALL_PROXY", "all_proxy"])) {
            Some(spec) => ProxyChoice::Proxy(spec),
            None => ProxyChoice::Direct,
        }
    }
}

/// A [`ProxyResolver`] that reads the standard proxy environment variables
/// (`HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY`, with `NO_PROXY` bypass).
pub fn from_env() -> EnvProxyResolver {
    EnvProxyResolver
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

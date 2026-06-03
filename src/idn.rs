//! IDN (Internationalized Domain Name) host normalisation.
//!
//! Converts a Unicode hostname to its ASCII/punycode form per UTS-46 (e.g.
//! `münchen.de` → `xn--mnchen-3ya.de`) so it can be used for DNS resolution,
//! the HTTP `Host:` header, and TLS SNI — all of which expect ASCII.
//!
//! Gated by the `idn` Cargo feature (on by default). Without the feature the
//! `idna` dependency and its Unicode tables are dropped and [`to_ascii`] is a
//! pure passthrough, so a Unicode host flows through unchanged (and typically
//! fails to resolve) — the correct "no IDN compiled" behaviour.

use crate::error::Result;
#[cfg(feature = "idn")]
use crate::error::Error;

/// Return the ASCII/punycode form of `host` when `enabled` and the host is
/// non-ASCII; otherwise return `host` unchanged.
///
/// Idempotent: an already-ASCII host (IPv4 literal, bracketed IPv6, `localhost`,
/// an already-punycode name, or any plain ASCII name) is never handed to the
/// IDNA encoder and comes back byte-identical. The disabled path and the
/// feature-off build are likewise plain passthroughs.
pub(crate) fn to_ascii(host: &str, enabled: bool) -> Result<String> {
    #[cfg(feature = "idn")]
    if enabled && !host.is_ascii() {
        return idna::domain_to_ascii(host)
            .map_err(|_| Error::InvalidUrl(format!("invalid IDN host: {host}")));
    }
    let _ = enabled;
    Ok(host.to_string())
}

#[cfg(test)]
mod tests {
    use super::to_ascii;

    #[test]
    fn ascii_hosts_pass_through_unchanged() {
        for h in [
            "example.com",
            "127.0.0.1",
            "[::1]",
            "xn--mnchen-3ya.de", // already punycode
            "localhost",
            "Example.COM", // case preserved: ASCII never touches idna
        ] {
            assert_eq!(to_ascii(h, true).unwrap(), h, "ASCII host must be untouched: {h}");
        }
    }

    #[cfg(feature = "idn")]
    #[test]
    fn unicode_host_is_punycoded_when_enabled() {
        assert_eq!(to_ascii("münchen.de", true).unwrap(), "xn--mnchen-3ya.de");
        assert_eq!(to_ascii("☃.net", true).unwrap(), "xn--n3h.net");
    }

    #[test]
    fn disabled_leaves_unicode_raw() {
        assert_eq!(to_ascii("münchen.de", false).unwrap(), "münchen.de");
    }
}

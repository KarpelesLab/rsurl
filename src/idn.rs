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
        let ascii = idna::domain_to_ascii(host)
            .map_err(|_| Error::InvalidUrl(format!("invalid IDN host: {host}")))?;
        // UTS-46 / `domain_to_ascii` runs with UseSTD3ASCIIRules=false, so it
        // happily maps fullwidth/compatibility code points onto ASCII
        // authority delimiters (e.g. U+FF20 `＠` → `@`, U+FF0F `／` → `/`,
        // U+FF1A `：` → `:`). That output is written straight back into
        // `Url::host` AFTER parse-time validation, so without re-checking it an
        // attacker can smuggle a delimiter past the parser and trigger
        // origin/host confusion (DNS, SNI, `Host:` header, proxy request line,
        // pool key). A legitimate punycode/ASCII hostname is only letters,
        // digits, hyphens, and dots — none of the bytes below — so reject any
        // encoded output that still carries one. This branch never sees a
        // bracketed IPv6 literal (those are ASCII and skip the encoder), so
        // rejecting `:` here is safe.
        if ascii.bytes().any(|b| {
            b < 0x20
                || matches!(b, 0x7f | b' ' | b'/' | b'\\' | b'@' | b':' | b'?' | b'#' | b'%')
        }) {
            return Err(Error::InvalidUrl(format!(
                "IDN host encodes to a forbidden authority delimiter: {host}"
            )));
        }
        return Ok(ascii);
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

    /// UTS-46 with UseSTD3ASCIIRules=false maps fullwidth/compatibility code
    /// points onto ASCII authority delimiters. Each of these must be rejected
    /// after IDN encoding so the delimiter cannot be smuggled past parse-time
    /// host validation (origin/host-confusion hardening).
    #[cfg(feature = "idn")]
    #[test]
    fn rejects_idn_authority_delimiter_injection() {
        for input in [
            "＠evil.com",          // U+FF20 -> '@'
            "good.com／../evil.com", // U+FF0F -> '/'
            "good.com：8080",       // U+FF1A -> ':'
            "evil＃.com",           // U+FF03 -> '#'
            "x？y.com",             // U+FF1F -> '?'
        ] {
            assert!(
                to_ascii(input, true).is_err(),
                "IDN delimiter injection must be rejected: {input:?}"
            );
        }
    }

    /// The guard must not break legitimate internationalised or ASCII hosts.
    #[cfg(feature = "idn")]
    #[test]
    fn legitimate_hosts_still_succeed_after_guard() {
        assert_eq!(to_ascii("münchen.de", true).unwrap(), "xn--mnchen-3ya.de");
        // Already-ASCII host is untouched.
        assert_eq!(to_ascii("example.com", true).unwrap(), "example.com");
    }
}

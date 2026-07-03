//! HTTP Digest access authentication (RFC 7616 / RFC 2617).
//!
//! Given a `WWW-Authenticate: Digest ...` challenge and credentials, build the
//! matching `Authorization: Digest ...` header. Supports `MD5`, `SHA-256`, and
//! their `-sess` variants, and `qop=auth` (the common case); `auth-int` and
//! userhash are not implemented (we fall back to the no-qop form if `auth`
//! isn't offered).

use std::collections::HashMap;

/// Build the `Authorization: Digest ...` value, or `None` if the challenge is
/// missing required fields.
pub(crate) fn authorization(
    user: &str,
    pass: &str,
    method: &str,
    uri: &str,
    challenge: &str,
) -> Option<String> {
    let body = challenge.trim().strip_prefix("Digest").or_else(|| {
        // Case-insensitive scheme prefix.
        challenge
            .trim()
            .get(..6)
            .filter(|s| s.eq_ignore_ascii_case("Digest"))
            .map(|_| &challenge.trim()[6..])
    })?;
    let p = parse_params(body);
    let realm = p.get("realm")?;
    let nonce = p.get("nonce")?;
    // Fail closed on attacker-controlled challenge values that would break out
    // of the quoted-string params we emit (a `"` in realm could forge
    // auth-params). RFC 7616 quoted strings can't carry these unescaped, and
    // we'd rather refuse than risk header injection — see `is_safe_quoted`.
    if !is_safe_quoted(realm) || !is_safe_quoted(nonce) {
        return None;
    }

    // Recognise exactly the algorithms we implement, case-insensitively. An
    // unknown token (typo, attacker-chosen, or an algorithm we don't support
    // such as SHA-512-256) must FAIL CLOSED rather than silently degrade to
    // MD5 while echoing the server's algorithm string in the header.
    let raw_alg = p.get("algorithm").map(String::as_str);
    let (algorithm, use_sha, sess) = match raw_alg {
        None => ("MD5", false, false),
        Some(a) if a.eq_ignore_ascii_case("MD5") => ("MD5", false, false),
        Some(a) if a.eq_ignore_ascii_case("MD5-sess") => ("MD5-sess", false, true),
        Some(a) if a.eq_ignore_ascii_case("SHA-256") => ("SHA-256", true, false),
        Some(a) if a.eq_ignore_ascii_case("SHA-256-sess") => ("SHA-256-sess", true, true),
        Some(_) => return None,
    };
    // qop: pick "auth" if offered.
    let qop_auth = p
        .get("qop")
        .map(|q| q.split(',').any(|t| t.trim().eq_ignore_ascii_case("auth")))
        .unwrap_or(false);

    let h = |s: &str| -> String {
        if use_sha {
            hex(&purecrypto::hash::sha256(s.as_bytes()))
        } else {
            hex(&purecrypto::hash::md5(s.as_bytes()))
        }
    };

    let cnonce = hex(&rand_bytes());
    let nc = "00000001";
    let mut ha1 = h(&format!("{user}:{realm}:{pass}"));
    if sess {
        ha1 = h(&format!("{ha1}:{nonce}:{cnonce}"));
    }
    let ha2 = h(&format!("{method}:{uri}"));
    let response = if qop_auth {
        h(&format!("{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}"))
    } else {
        h(&format!("{ha1}:{nonce}:{ha2}"))
    };

    let mut out = format!(
        "Digest username=\"{user}\", realm=\"{realm}\", nonce=\"{nonce}\", \
         uri=\"{uri}\", response=\"{response}\""
    );
    if let Some(opaque) = p.get("opaque") {
        // Same quoted-string break-out hazard as realm/nonce.
        if !is_safe_quoted(opaque) {
            return None;
        }
        out.push_str(&format!(", opaque=\"{opaque}\""));
    }
    if raw_alg.is_some() {
        // Echo the algorithm we actually selected (a recognised token), never
        // the raw challenge string.
        out.push_str(&format!(", algorithm={algorithm}"));
    }
    if qop_auth {
        out.push_str(&format!(", qop=auth, nc={nc}, cnonce=\"{cnonce}\""));
    }
    Some(out)
}

/// Parse `key=value` / `key="value"` pairs (comma-separated, quote-aware).
fn parse_params(s: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Skip separators/whitespace.
        while i < bytes.len() && (bytes[i] == b',' || bytes[i].is_ascii_whitespace()) {
            i += 1;
        }
        // Key.
        let key_start = i;
        while i < bytes.len() && bytes[i] != b'=' && bytes[i] != b',' {
            i += 1;
        }
        let key = s[key_start..i].trim().to_ascii_lowercase();
        if i >= bytes.len() || bytes[i] != b'=' {
            if !key.is_empty() {
                map.insert(key, String::new());
            }
            continue;
        }
        i += 1; // skip '='
                // Value: quoted or token.
        let value = if i < bytes.len() && bytes[i] == b'"' {
            i += 1;
            let start = i;
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 1;
                }
                i += 1;
            }
            let v = s[start..i.min(bytes.len())].to_string();
            if i < bytes.len() {
                i += 1; // closing quote
            }
            v
        } else {
            let start = i;
            while i < bytes.len() && bytes[i] != b',' {
                i += 1;
            }
            s[start..i].trim().to_string()
        };
        if !key.is_empty() {
            map.insert(key, value);
        }
    }
    map
}

/// `true` if `v` is safe to interpolate verbatim into a `"..."` auth-param.
/// We reject the characters that could break out of (or corrupt) the quoted
/// string — `"` and `\` (escape/quote chars) and the control bytes CR, LF, NUL
/// — so an attacker-controlled `realm`/`nonce`/`opaque` can't forge additional
/// auth-params or split the header.
fn is_safe_quoted(v: &str) -> bool {
    !v.bytes()
        .any(|b| b == b'"' || b == b'\\' || b == b'\r' || b == b'\n' || b == 0)
}

/// Lowercase hex encoding, shared with `sigv4`.
pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// 8 random bytes for the client nonce. Falls back to a fixed value only if the
/// OS RNG is unreadable (extremely rare); the cnonce is not a secret, just
/// unique-per-request, so a degraded value never weakens credential secrecy.
fn rand_bytes() -> [u8; 8] {
    use purecrypto::rng::{OsRng, RngCore};
    let mut out = [0u8; 8];
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        OsRng.fill_bytes(&mut out);
    }))
    .is_err()
    {
        out = *b"rsurlcli";
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_quoted_and_token_params() {
        let p = parse_params(
            " realm=\"test\", qop=\"auth,auth-int\", nonce=\"abc\", algorithm=MD5, stale=false",
        );
        assert_eq!(p.get("realm").unwrap(), "test");
        assert_eq!(p.get("qop").unwrap(), "auth,auth-int");
        assert_eq!(p.get("nonce").unwrap(), "abc");
        assert_eq!(p.get("algorithm").unwrap(), "MD5");
        assert_eq!(p.get("stale").unwrap(), "false");
    }

    #[test]
    fn rfc2617_md5_response() {
        // RFC 2617 §3.5 worked example.
        let chal = "Digest realm=\"testrealm@host.com\", qop=\"auth,auth-int\", \
                    nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", \
                    opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";
        // Force the known cnonce/nc by checking structure rather than the exact
        // response (cnonce is random); assert the header is well-formed.
        let h = authorization("Mufasa", "Circle Of Life", "GET", "/dir/index.html", chal)
            .expect("digest header");
        assert!(h.starts_with("Digest username=\"Mufasa\""));
        assert!(h.contains("realm=\"testrealm@host.com\""));
        assert!(h.contains("qop=auth"));
        assert!(h.contains("uri=\"/dir/index.html\""));
        assert!(h.contains("response=\""));
        assert!(h.contains("opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""));
    }

    #[test]
    fn unknown_algorithm_fails_closed() {
        // SHA-512-256 is a real RFC 7616 algorithm we do NOT implement; it must
        // not silently degrade to MD5.
        let chal = "Digest realm=\"r\", nonce=\"n\", algorithm=SHA-512-256";
        assert!(authorization("u", "p", "GET", "/", chal).is_none());
        // A bogus/typo token likewise fails closed.
        let chal2 = "Digest realm=\"r\", nonce=\"n\", algorithm=MD6";
        assert!(authorization("u", "p", "GET", "/", chal2).is_none());
    }

    #[test]
    fn sha256_algorithm_echoed_as_selected() {
        let chal = "Digest realm=\"r\", nonce=\"n\", algorithm=sha-256";
        let h = authorization("u", "p", "GET", "/", chal).unwrap();
        // The emitted token reflects the selected algorithm (canonical form),
        // not the raw lowercase challenge string.
        assert!(h.contains("algorithm=SHA-256"), "got: {h}");
    }

    #[test]
    fn quoted_value_breakout_rejected() {
        // A `"` in realm could otherwise forge auth-params.
        let chal = "Digest realm=\"r\\\"x\", nonce=\"n\"";
        assert!(authorization("u", "p", "GET", "/", chal).is_none());
        // CRLF in nonce would split the header.
        let chal2 = "Digest realm=\"r\", nonce=\"n\r\nX: y\"";
        assert!(authorization("u", "p", "GET", "/", chal2).is_none());
    }

    #[test]
    fn no_qop_form() {
        let chal = "Digest realm=\"r\", nonce=\"n\"";
        let h = authorization("u", "p", "GET", "/", chal).unwrap();
        assert!(h.contains("response=\""));
        assert!(!h.contains("qop="));
        // Verify the no-qop response = MD5(HA1:nonce:HA2).
        let ha1 = hex(&purecrypto::hash::md5(b"u:r:p"));
        let ha2 = hex(&purecrypto::hash::md5(b"GET:/"));
        let want = hex(&purecrypto::hash::md5(format!("{ha1}:n:{ha2}").as_bytes()));
        assert!(h.contains(&format!("response=\"{want}\"")));
    }
}

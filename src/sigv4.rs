//! AWS Signature Version 4 request signing (curl `--aws-sigv4`).
//!
//! Produces the `Authorization`, `X-Amz-Date`, and `X-Amz-Content-Sha256`
//! headers for a request, signing the host / date / content-hash header set
//! (the minimal set AWS requires). The canonical query string and path follow
//! AWS's URI-encoding rules (see [`canonical_query`] / [`canonical_path`]).
//!
//! Signing happens per outgoing request, at send time (see
//! `Request::apply_aws_sigv4`), so it covers the final IDN-normalised host, the
//! `host:port` authority actually sent, the effective method, and each
//! redirect hop — like curl, which signs every request it sends.

use crate::digest::hex;
use purecrypto::hash::{sha256, HmacSha256};

/// Current UTC time as an AWS `YYYYMMDDTHHMMSSZ` timestamp.
pub(crate) fn amz_date_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    epoch_to_amzdate(secs)
}

/// Format a Unix epoch as `YYYYMMDDTHHMMSSZ` (UTC).
fn epoch_to_amzdate(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let rem = (secs % 86400) as i64;
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}{m:02}{d:02}T{hh:02}{mm:02}{ss:02}Z")
}

/// The caller's `--aws-sigv4` request, kept on the `Request` so every hop is
/// signed at send time. `Debug` redacts the secret key.
#[derive(Clone)]
pub(crate) struct SigV4Spec {
    /// curl-style `provider1[:provider2[:region[:service]]]`.
    pub spec: String,
    pub access_key: String,
    pub secret_key: String,
}

impl std::fmt::Debug for SigV4Spec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigV4Spec")
            .field("spec", &self.spec)
            .field("access_key", &self.access_key)
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

impl SigV4Spec {
    /// `(region, service)` from the spec, defaulting to the host's 2nd/1st
    /// labels (else `us-east-1`/`s3`), as curl does.
    pub(crate) fn region_service(&self, host: &str) -> (String, String) {
        let parts: Vec<&str> = self.spec.split(':').collect();
        let labels: Vec<&str> = host.split('.').collect();
        let region = parts
            .get(2)
            .filter(|s| !s.is_empty())
            .copied()
            .or_else(|| labels.get(1).copied())
            .unwrap_or("us-east-1");
        let service = parts
            .get(3)
            .filter(|s| !s.is_empty())
            .copied()
            .or_else(|| labels.first().copied())
            .unwrap_or("s3");
        (region.to_string(), service.to_string())
    }
}

/// Signing parameters parsed from `--aws-sigv4` plus the `-u` credentials.
pub(crate) struct SigV4<'a> {
    pub access_key: &'a str,
    pub secret_key: &'a str,
    pub region: &'a str,
    pub service: &'a str,
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    HmacSha256::mac(key, data).as_ref().to_vec()
}

/// AWS `UriEncode`: every byte except the unreserved set `A-Za-z0-9-_.~` is
/// `%XX`-encoded with uppercase hex; `/` is kept only when `keep_slash`.
fn aws_uri_encode(bytes: &[u8], keep_slash: bool, out: &mut String) {
    for &b in bytes {
        if b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'_' | b'.' | b'~')
            || (keep_slash && b == b'/')
        {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
}

/// Decode `%XX` escapes (a malformed escape is kept literally) — the query
/// arrives as it appears on the wire and must be re-encoded canonically.
fn percent_decode(s: &str) -> Vec<u8> {
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
    out
}

/// Canonical query string (AWS SigV4): each parameter's name and value are
/// decoded and re-encoded with [`aws_uri_encode`], a value-less parameter
/// (`?acl`, `?uploads`) becomes `name=`, and the pairs are sorted by name then
/// value (on the encoded form, i.e. by byte order).
fn canonical_query(query: &str) -> String {
    let mut pairs: Vec<(String, String)> = query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            let mut ek = String::new();
            aws_uri_encode(&percent_decode(k), false, &mut ek);
            let mut ev = String::new();
            aws_uri_encode(&percent_decode(v), false, &mut ev);
            (ek, ev)
        })
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Canonical URI path. S3 signs the path as sent (single encoding, no
/// normalisation); every other service URI-encodes the already-encoded path
/// once more (AWS's documented double encoding), matching curl.
fn canonical_path(path: &str, service: &str) -> String {
    let path = if path.is_empty() { "/" } else { path };
    if service.eq_ignore_ascii_case("s3") {
        return path.to_string();
    }
    let mut out = String::with_capacity(path.len());
    aws_uri_encode(path.as_bytes(), true, &mut out);
    out
}

/// Sign the request, returning the headers to add. `amz_date` is
/// `YYYYMMDDTHHMMSSZ`; `payload` is the request body (empty for GET).
pub(crate) fn sign(
    cfg: &SigV4,
    method: &str,
    host: &str,
    path: &str,
    query: &str,
    payload: &[u8],
    amz_date: &str,
) -> Vec<(String, String)> {
    let date = &amz_date[..8.min(amz_date.len())];
    let payload_hash = hex(&sha256(payload));
    let canonical_headers =
        format!("host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n");
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let canonical_path = canonical_path(path, cfg.service);
    let canonical_request = format!(
        "{method}\n{canonical_path}\n{}\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
        canonical_query(query)
    );
    let scope = format!("{date}/{}/{}/aws4_request", cfg.region, cfg.service);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex(&sha256(canonical_request.as_bytes()))
    );
    let k_date = hmac(
        format!("AWS4{}", cfg.secret_key).as_bytes(),
        date.as_bytes(),
    );
    let k_region = hmac(&k_date, cfg.region.as_bytes());
    let k_service = hmac(&k_region, cfg.service.as_bytes());
    let k_signing = hmac(&k_service, b"aws4_request");
    let signature = hex(&hmac(&k_signing, string_to_sign.as_bytes()));
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, \
         Signature={signature}",
        cfg.access_key
    );
    vec![
        ("X-Amz-Date".to_string(), amz_date.to_string()),
        ("X-Amz-Content-Sha256".to_string(), payload_hash),
        ("Authorization".to_string(), auth),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SigV4<'static> {
        SigV4 {
            access_key: "AKIDEXAMPLE",
            secret_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            region: "us-east-1",
            service: "s3",
        }
    }

    #[test]
    fn sigv4_structure_and_scope() {
        let h = sign(
            &cfg(),
            "GET",
            "example.amazonaws.com",
            "/",
            "",
            b"",
            "20150830T123600Z",
        );
        let auth = &h.iter().find(|(k, _)| k == "Authorization").unwrap().1;
        assert!(auth.starts_with("AWS4-HMAC-SHA256 "));
        assert!(auth.contains("Credential=AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request"));
        assert!(auth.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"));
        // Signature is 64 lowercase hex chars.
        let sig = auth.rsplit("Signature=").next().unwrap();
        assert_eq!(sig.len(), 64);
        assert!(sig.bytes().all(|b| b.is_ascii_hexdigit()));
        // The other headers are present.
        assert!(h.iter().any(|(k, _)| k == "X-Amz-Date"));
        assert!(h.iter().any(|(k, _)| k == "X-Amz-Content-Sha256"));
    }

    #[test]
    fn sigv4_is_deterministic_and_key_sensitive() {
        let a = sign(
            &cfg(),
            "GET",
            "h",
            "/p",
            "b=2&a=1",
            b"x",
            "20150830T123600Z",
        );
        let b = sign(
            &cfg(),
            "GET",
            "h",
            "/p",
            "b=2&a=1",
            b"x",
            "20150830T123600Z",
        );
        assert_eq!(a, b, "same inputs must produce the same signature");
        let mut other = cfg();
        other.secret_key = "different-secret-key";
        let c = sign(
            &other,
            "GET",
            "h",
            "/p",
            "b=2&a=1",
            b"x",
            "20150830T123600Z",
        );
        assert_ne!(a, c, "a different secret must change the signature");
    }

    #[test]
    fn canonical_query_is_sorted() {
        assert_eq!(canonical_query("b=2&a=1&c=3"), "a=1&b=2&c=3");
        assert_eq!(canonical_query(""), "");
    }

    #[test]
    fn canonical_query_follows_aws_rules() {
        // Value-less parameters sign as `name=`.
        assert_eq!(canonical_query("uploads"), "uploads=");
        assert_eq!(canonical_query("acl&b=1"), "acl=&b=1");
        // Sorted by name, then value — not by the whole `k=v` string, where
        // `a-b=1` would wrongly sort before `a=2` ('-' < '=').
        assert_eq!(canonical_query("a=2&a-b=1&a=1"), "a=1&a=2&a-b=1");
        // Re-encoded canonically: unreserved kept, others %XX uppercase, and a
        // `+`/space/lowercase escape normalised.
        assert_eq!(
            canonical_query("k=a%2fb&x=h%c3%a9 y+z&t=~_.-"),
            "k=a%2Fb&t=~_.-&x=h%C3%A9%20y%2Bz"
        );
    }

    #[test]
    fn canonical_path_double_encodes_except_s3() {
        assert_eq!(canonical_path("/a%20b/c", "s3"), "/a%20b/c");
        assert_eq!(canonical_path("/a%20b/c", "execute-api"), "/a%2520b/c");
        assert_eq!(canonical_path("", "s3"), "/");
    }

    /// AWS S3 SigV4 documentation known-answer vectors ("Signature Calculations
    /// for the Authorization Header", header-based auth examples).
    fn s3_doc_cfg() -> SigV4<'static> {
        SigV4 {
            access_key: "AKIAIOSFODNN7EXAMPLE",
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            region: "us-east-1",
            service: "s3",
        }
    }

    fn signature(h: &[(String, String)]) -> String {
        let auth = &h.iter().find(|(k, _)| k == "Authorization").unwrap().1;
        auth.rsplit("Signature=").next().unwrap().to_string()
    }

    #[test]
    fn sigv4_known_answer_get_bucket_lifecycle() {
        // GET /?lifecycle — exercises the value-less `lifecycle=` parameter.
        let h = sign(
            &s3_doc_cfg(),
            "GET",
            "examplebucket.s3.amazonaws.com",
            "/",
            "lifecycle",
            b"",
            "20130524T000000Z",
        );
        assert_eq!(
            signature(&h),
            "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"
        );
    }

    #[test]
    fn sigv4_known_answer_list_objects() {
        // GET /?max-keys=2&prefix=J
        let h = sign(
            &s3_doc_cfg(),
            "GET",
            "examplebucket.s3.amazonaws.com",
            "/",
            "max-keys=2&prefix=J",
            b"",
            "20130524T000000Z",
        );
        assert_eq!(
            signature(&h),
            "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
        );
    }
}

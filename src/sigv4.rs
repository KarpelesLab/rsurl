//! AWS Signature Version 4 request signing (curl `--aws-sigv4`).
//!
//! Produces the `Authorization`, `X-Amz-Date`, and `X-Amz-Content-Sha256`
//! headers for a request, signing the host / date / content-hash header set
//! (the minimal set AWS requires). Query strings are canonicalised by sorting
//! already-encoded `key=value` pairs.

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

/// Canonical query string: sort the (already percent-encoded) `k=v` pairs.
fn canonical_query(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }
    let mut parts: Vec<&str> = query.split('&').filter(|p| !p.is_empty()).collect();
    parts.sort_unstable();
    parts.join("&")
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
    let canonical_path = if path.is_empty() { "/" } else { path };
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
}

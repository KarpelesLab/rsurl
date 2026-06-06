//! Backend-neutral TLS client-auth and public-key-pinning helpers.
//!
//! Both TLS backends (`purecrypto` and `rustls`) share the pieces in here:
//!
//! * **`--pinnedpubkey` parsing + checking** ([`parse_pinned_pubkey`],
//!   [`spki_pin_matches`]). curl pins the SHA-256 of the server leaf
//!   certificate's DER `SubjectPublicKeyInfo`; we extract the SPKI via
//!   `purecrypto::x509` (always a dependency, regardless of which TLS backend
//!   is active) so the check is identical on both backends.
//! * **Client identity parsing** for the purecrypto backend
//!   ([`load_cert_chain`], [`parse_signing_key`]). The rustls backend uses
//!   `rustls-pemfile` for its own DER, but reuses the pin logic here.
//!
//! Everything here is a small, pure function so it can be unit-tested without
//! standing up a TLS server.

use crate::error::{Error, Result};

// The purecrypto backend uses its own `SigningKey` enum; the cert-chain /
// key-parsing helpers below are only compiled for that backend (the rustls
// backend parses its own DER via `rustls-pemfile`). The pin / SPKI helpers and
// the base64 decoder are always compiled — both backends share them.
#[cfg(all(feature = "purecrypto-tls", not(feature = "rustls-tls")))]
use purecrypto::tls::SigningKey;

/// Parse curl's `--pinnedpubkey` value into a list of 32-byte SHA-256 pins.
///
/// The accepted form is `sha256//BASE64[;sha256//BASE64...]` — one or more
/// `;`-separated entries, each a `sha256//` prefix followed by the standard
/// (RFC 4648) base64 of a 32-byte hash. Any other hash algorithm, a missing
/// prefix, bad base64, or a decoded length other than 32 bytes is rejected
/// with a clear [`Error::BadResponse`].
///
/// curl also accepts a bare `<file>` (a PEM/DER public-key file) instead of
/// `sha256//` hashes; that form is intentionally not supported here — a value
/// that does not start with `sha256//` is rejected so the user is not silently
/// left unpinned.
pub fn parse_pinned_pubkey(spec: &str) -> Result<Vec<[u8; 32]>> {
    let mut pins = Vec::new();
    for raw in spec.split(';') {
        let entry = raw.trim();
        if entry.is_empty() {
            continue;
        }
        let Some(b64) = entry.strip_prefix("sha256//") else {
            // Either a different digest (`sha384//...`) or a bare file path.
            if entry.contains("//") {
                return Err(Error::BadResponse(format!(
                    "pinned public key: only sha256// hashes are supported, got {entry:?}"
                )));
            }
            return Err(Error::BadResponse(format!(
                "pinned public key: a public-key file ({entry:?}) is not supported; \
                 use the sha256//BASE64 form"
            )));
        };
        let bytes = base64_decode(b64).ok_or_else(|| {
            Error::BadResponse(format!("pinned public key: invalid base64 in {entry:?}"))
        })?;
        let hash: [u8; 32] = bytes.try_into().map_err(|_| {
            Error::BadResponse(format!(
                "pinned public key: sha256 hash must decode to 32 bytes in {entry:?}"
            ))
        })?;
        pins.push(hash);
    }
    if pins.is_empty() {
        return Err(Error::BadResponse(
            "pinned public key: no sha256// hashes found".into(),
        ));
    }
    Ok(pins)
}

/// Return `true` if the SHA-256 of `leaf_der`'s `SubjectPublicKeyInfo` matches
/// at least one entry in `pins`. An empty `pins` slice means "no pinning was
/// requested" and is reported as a match (the caller should not call this with
/// an empty list, but treating it as success keeps the contract obvious).
///
/// A leaf certificate that cannot be parsed, or whose public key cannot be
/// extracted, fails the check (returns `false`) — a malformed leaf must never
/// satisfy a pin.
pub fn spki_pin_matches(leaf_der: &[u8], pins: &[[u8; 32]]) -> bool {
    if pins.is_empty() {
        return true;
    }
    let Some(got) = leaf_spki_sha256(leaf_der) else {
        return false;
    };
    pins.contains(&got)
}

/// Compute SHA-256 of a leaf certificate's DER `SubjectPublicKeyInfo`, or
/// `None` if the cert / public key cannot be parsed. Shared by both backends'
/// pin check (purecrypto's x509 parser is always linked).
pub fn leaf_spki_sha256(leaf_der: &[u8]) -> Option<[u8; 32]> {
    let cert = purecrypto::x509::Certificate::from_der(leaf_der.to_vec()).ok()?;
    let pubkey = cert.subject_public_key().ok()?;
    let spki = pubkey.to_spki_der();
    Some(purecrypto::hash::sha256(&spki))
}

/// Load a PEM certificate chain (one or more `CERTIFICATE` blocks, leaf first)
/// into DER, mirroring purecrypto's own `s_client` loader. Used by the
/// purecrypto backend for `-E`/`--cert` in PEM form.
#[cfg(all(feature = "purecrypto-tls", not(feature = "rustls-tls")))]
pub fn load_cert_chain(pem: &str) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    for block in crate::tls::pc_roots::pem_blocks(pem) {
        let cert = purecrypto::x509::Certificate::from_pem(&block)
            .map_err(|e| Error::BadResponse(format!("client cert: cannot parse PEM: {e:?}")))?;
        out.push(cert.to_der().to_vec());
    }
    if out.is_empty() {
        return Err(Error::BadResponse(
            "client cert: file contains no CERTIFICATE blocks".into(),
        ));
    }
    Ok(out)
}

/// Load a single DER certificate as a one-entry chain (curl `--cert-type DER`).
#[cfg(all(feature = "purecrypto-tls", not(feature = "rustls-tls")))]
pub fn load_cert_chain_der(der: &[u8]) -> Result<Vec<Vec<u8>>> {
    // Validate it parses as an X.509 cert so a bad file fails early rather
    // than during the handshake.
    purecrypto::x509::Certificate::from_der(der.to_vec())
        .map_err(|e| Error::BadResponse(format!("client cert: cannot parse DER cert: {e:?}")))?;
    Ok(vec![der.to_vec()])
}

/// Parse a PEM private key into a purecrypto [`SigningKey`], trying Ed25519,
/// ECDSA, then RSA — the same order purecrypto's `s_client` uses. When `pass`
/// is set, the encrypted PKCS#8 variants are tried first (Ed25519 / RSA;
/// purecrypto exposes no encrypted-ECDSA loader, so an encrypted ECDSA key is
/// reported as unsupported).
#[cfg(all(feature = "purecrypto-tls", not(feature = "rustls-tls")))]
pub fn parse_signing_key(pem: &str, pass: Option<&str>) -> Result<SigningKey> {
    use purecrypto::ec::{BoxedEcdsaPrivateKey, Ed25519PrivateKey};
    use purecrypto::rsa::BoxedRsaPrivateKey;

    if let Some(pass) = pass {
        let p = pass.as_bytes();
        if let Ok(k) = Ed25519PrivateKey::from_pkcs8_pem_encrypted(pem, p) {
            return Ok(SigningKey::Ed25519(k));
        }
        if let Ok(k) = BoxedRsaPrivateKey::from_pkcs8_pem_encrypted(pem, p) {
            return Ok(SigningKey::Rsa(k));
        }
        // Fall through: the key may be an *unencrypted* PEM with a redundant
        // `--pass` (curl tolerates that), so try the plain loaders below too.
    }

    if let Ok(k) = Ed25519PrivateKey::from_pkcs8_pem(pem) {
        return Ok(SigningKey::Ed25519(k));
    }
    if let Ok(k) = BoxedEcdsaPrivateKey::from_sec1_pem(pem) {
        return Ok(SigningKey::Ecdsa(k));
    }
    if let Ok(k) = BoxedRsaPrivateKey::from_pkcs1_pem(pem) {
        return Ok(SigningKey::Rsa(k));
    }
    if let Ok(k) = BoxedRsaPrivateKey::from_pkcs8_pem(pem) {
        return Ok(SigningKey::Rsa(k));
    }

    Err(Error::BadResponse(
        if pass.is_some() {
            "client key: could not parse key (wrong --pass, or an encrypted ECDSA key, \
             which is unsupported); expected Ed25519/RSA PKCS#8 (optionally encrypted), \
             ECDSA SEC1, or RSA PKCS#1 PEM"
        } else {
            "client key: could not parse key; expected Ed25519 (PKCS#8), ECDSA (SEC1), \
             or RSA (PKCS#1 or PKCS#8) PEM, or use --pass for an encrypted key"
        }
        .into(),
    ))
}

/// Parse a DER private key (curl `--key-type DER`). Tries Ed25519, ECDSA SEC1,
/// then RSA (PKCS#8, then PKCS#1). Encrypted DER (PKCS#8) is supported for
/// Ed25519/RSA when `pass` is given.
#[cfg(all(feature = "purecrypto-tls", not(feature = "rustls-tls")))]
pub fn parse_signing_key_der(der: &[u8], pass: Option<&str>) -> Result<SigningKey> {
    use purecrypto::ec::{BoxedEcdsaPrivateKey, Ed25519PrivateKey};
    use purecrypto::rsa::BoxedRsaPrivateKey;

    if let Some(pass) = pass {
        let p = pass.as_bytes();
        if let Ok(k) = Ed25519PrivateKey::from_pkcs8_der_encrypted(der, p) {
            return Ok(SigningKey::Ed25519(k));
        }
        if let Ok(k) = BoxedRsaPrivateKey::from_pkcs8_der_encrypted(der, p) {
            return Ok(SigningKey::Rsa(k));
        }
    }

    if let Ok(k) = Ed25519PrivateKey::from_pkcs8_der(der) {
        return Ok(SigningKey::Ed25519(k));
    }
    if let Ok(k) = BoxedEcdsaPrivateKey::from_sec1_der(der) {
        return Ok(SigningKey::Ecdsa(k));
    }
    if let Ok(k) = BoxedRsaPrivateKey::from_pkcs8_der(der) {
        return Ok(SigningKey::Rsa(k));
    }
    if let Ok(k) = BoxedRsaPrivateKey::from_pkcs1_der(der) {
        return Ok(SigningKey::Rsa(k));
    }

    Err(Error::BadResponse(
        "client key (DER): could not parse; expected Ed25519/RSA PKCS#8 \
         (optionally encrypted), ECDSA SEC1, or RSA PKCS#1"
            .into(),
    ))
}

/// Decode standard (RFC 4648) base64, ignoring ASCII whitespace and an
/// optional trailing `=` pad. Returns `None` on any invalid character or a
/// truncated final group. Small and self-contained so the pin parser has no
/// new dependency.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut quad = [0u8; 4];
    let mut qn = 0usize;
    let mut out = Vec::new();
    let mut pad = 0usize;
    let mut ended = false;
    for &b in input.as_bytes() {
        if b.is_ascii_whitespace() {
            continue;
        }
        if ended {
            // No data may follow padding.
            return None;
        }
        if b == b'=' {
            pad += 1;
            quad[qn] = 0;
            qn += 1;
        } else {
            if pad != 0 {
                return None; // data after a '=' within the same group
            }
            quad[qn] = val(b)?;
            qn += 1;
        }
        if qn == 4 {
            out.push((quad[0] << 2) | (quad[1] >> 4));
            if pad < 2 {
                out.push((quad[1] << 4) | (quad[2] >> 2));
            }
            if pad < 1 {
                out.push((quad[2] << 6) | quad[3]);
            }
            if pad > 0 {
                ended = true;
            }
            qn = 0;
            pad = 0;
        }
    }
    // A leftover partial group (qn != 0) is invalid for canonical base64.
    if qn != 0 {
        return None;
    }
    Some(out)
}

/// Build a deterministic self-signed Ed25519 leaf certificate (DER) plus its
/// PEM PKCS#8 private key. Shared test fixture for this module and the
/// `http` module's `tls_opts_from` test.
#[cfg(test)]
pub(crate) fn tests_support_ed25519_leaf() -> (Vec<u8>, String) {
    use purecrypto::ec::Ed25519PrivateKey;
    use purecrypto::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};

    let key = Ed25519PrivateKey::from_bytes([7u8; 32]);
    let dn = DistinguishedName::common_name("rsurl-test");
    let validity = Validity::new(
        Time::utc(2020, 1, 1, 0, 0, 0),
        Time::utc(2099, 1, 1, 0, 0, 0),
    );
    let signer = CertSigner::Ed25519(&key);
    let cert = Certificate::self_signed_general(&signer, &dn, &validity, 1, false, &["localhost"])
        .expect("self-signed cert");
    (cert.to_der().to_vec(), key.to_pkcs8_pem())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip_and_padding() {
        // "hello" => aGVsbG8=
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        // "" => ""
        assert_eq!(base64_decode("").unwrap(), b"");
        // 32-byte all-zero hash, base64 of 32 zero bytes is 44 chars ending "=".
        let z = base64_decode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        assert_eq!(z.len(), 32);
        assert!(z.iter().all(|&b| b == 0));
        // whitespace is ignored
        assert_eq!(base64_decode("aGVs bG8=\n").unwrap(), b"hello");
        // invalid char / bad padding
        assert!(base64_decode("aGVsbG8*").is_none());
        assert!(base64_decode("aGVsbG8=X").is_none());
        assert!(base64_decode("aGV").is_none()); // truncated group
    }

    #[test]
    fn pin_parser_accepts_single_and_multiple() {
        let one = "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let pins = parse_pinned_pubkey(one).unwrap();
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0], [0u8; 32]);

        let two = format!("{one};{one}");
        let pins = parse_pinned_pubkey(&two).unwrap();
        assert_eq!(pins.len(), 2);

        // Trailing semicolon / whitespace tolerated.
        let pins = parse_pinned_pubkey(&format!("  {one} ; ")).unwrap();
        assert_eq!(pins.len(), 1);
    }

    #[test]
    fn pin_parser_rejects_bad_input() {
        // Wrong algorithm.
        assert!(
            parse_pinned_pubkey("sha384//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").is_err()
        );
        // Bare file path.
        assert!(parse_pinned_pubkey("/etc/keys/pub.pem").is_err());
        // Bad base64.
        assert!(parse_pinned_pubkey("sha256//not*base64").is_err());
        // Wrong decoded length (16 bytes, not 32).
        assert!(parse_pinned_pubkey("sha256//AAAAAAAAAAAAAAAAAAAAAA==").is_err());
        // Empty.
        assert!(parse_pinned_pubkey("").is_err());
        assert!(parse_pinned_pubkey(";;").is_err());
    }

    #[test]
    fn empty_pins_is_a_match() {
        assert!(spki_pin_matches(b"whatever", &[]));
    }

    #[test]
    fn unparseable_leaf_never_matches() {
        let pins = [[0u8; 32]];
        assert!(!spki_pin_matches(b"not a cert", &pins));
    }

    use super::tests_support_ed25519_leaf as test_ed25519_leaf;

    #[test]
    fn spki_extraction_and_pin_match() {
        let (leaf_der, _key_pem) = test_ed25519_leaf();

        // The pin is the SHA-256 of the leaf's SPKI; recompute it the same way
        // the runtime does and assert it both extracts and matches.
        let pin = leaf_spki_sha256(&leaf_der).expect("extract SPKI hash");
        assert!(spki_pin_matches(&leaf_der, &[pin]));

        // A wrong pin must not match; a list containing the right pin does.
        let wrong = [0xABu8; 32];
        assert!(!spki_pin_matches(&leaf_der, &[wrong]));
        assert!(spki_pin_matches(&leaf_der, &[wrong, pin]));
    }

    #[cfg(all(feature = "purecrypto-tls", not(feature = "rustls-tls")))]
    #[test]
    fn parse_ed25519_key_pem() {
        let (_leaf, key_pem) = test_ed25519_leaf();
        // The generated key is an unencrypted Ed25519 PKCS#8 PEM.
        let key = parse_signing_key(&key_pem, None).expect("parse Ed25519 key");
        assert!(matches!(key, SigningKey::Ed25519(_)));
        // A bogus PEM must error rather than silently succeed.
        assert!(parse_signing_key(
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----",
            None
        )
        .is_err());
    }

    #[cfg(all(feature = "purecrypto-tls", not(feature = "rustls-tls")))]
    #[test]
    fn cert_chain_from_pem_round_trips() {
        use purecrypto::x509::Certificate;
        let (leaf_der, _key) = test_ed25519_leaf();
        let pem = Certificate::from_der(leaf_der.clone()).unwrap().to_pem();
        let chain = load_cert_chain(&pem).expect("load chain");
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0], leaf_der);
        // DER loader yields the same single-entry chain.
        let chain_der = load_cert_chain_der(&leaf_der).expect("load DER chain");
        assert_eq!(chain_der[0], leaf_der);
    }
}

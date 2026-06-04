//! Universal "give me the bytes" entry point that dispatches on URL scheme.
//!
//! This is the API the CLI uses for non-HTTP URLs and the natural front door
//! for callers that just want curl-like behavior across many protocols.
//!
//! For HTTP/HTTPS, prefer [`crate::Request`] / [`crate::get`] directly —
//! they expose status, headers, and the full response model. `transfer`
//! discards everything except the body for those schemes.

use crate::error::{Error, Result};
use crate::url::Url;

/// Run the default operation for the URL's scheme and return its payload.
///
/// International (IDN) hostnames are normalised to ASCII/punycode here (curl's
/// default). To opt out, parse with [`Url::parse`], call
/// [`Url::set_idn(false)`](Url::set_idn), and use [`transfer_url`].
pub fn transfer(url_str: &str) -> Result<Vec<u8>> {
    let mut url = Url::parse(url_str)?;
    url.set_idn(true)?;
    transfer_url(&url)
}

/// Same as [`transfer`] but starts from an already-parsed URL.
///
/// The host is used as given — apply [`Url::set_idn`] first if you want IDN
/// normalisation (or call [`transfer`], which does it for you).
pub fn transfer_url(url: &Url) -> Result<Vec<u8>> {
    transfer_url_with(url, &crate::net::NetConfig::default())
}

/// `transfer_url` with an explicit network configuration (connector / proxy).
/// Used by [`crate::Client`]; the public [`transfer_url`] is the default-config
/// wrapper. `sftp`/`scp` (SSH) and `file` ignore the connector in this
/// milestone; `tftp` gains UDP-proxy support in a later phase.
pub(crate) fn transfer_url_with(url: &Url, cfg: &crate::net::NetConfig) -> Result<Vec<u8>> {
    match url.scheme.as_str() {
        "http" | "https" => crate::Request::get(&format!(
            "{}://{}{}{}",
            url.scheme,
            url.host,
            if (url.scheme == "http" && url.port == 80)
                || (url.scheme == "https" && url.port == 443)
            {
                String::new()
            } else {
                format!(":{}", url.port)
            },
            url.path
        ))?
        .connector(cfg.connector.clone())
        .verify_tls(cfg.verify)
        .send()
        .map(|r| r.body),
        "ftp" | "ftps" => crate::ftp::fetch_with(url, cfg),
        "dict" => crate::dict::fetch_with(url, cfg),
        "file" => crate::file::fetch(url),
        "gopher" | "gophers" => crate::gopher::fetch_with(url, cfg),
        "imap" | "imaps" => crate::imap::fetch_with(url, cfg),
        "ldap" | "ldaps" => crate::ldap::fetch_with(url, cfg),
        "mqtt" | "mqtts" => crate::mqtt::fetch_with(url, cfg),
        "pop3" | "pop3s" => crate::pop3::fetch_with(url, cfg),
        "rtsp" => crate::rtsp::fetch_with(url, cfg),
        "sftp" | "scp" => {
            // Library default: derive the user from the URL/`$USER`, take any
            // password from the URL userinfo, and use TOFU known_hosts (no
            // `-k`). The CLI calls `ssh::fetch_traced` directly so it can also
            // thread `-u`, `--key`, and `-k`. SSH does not honor a custom
            // connector yet.
            let user = crate::ssh::resolve_user(url, None)?;
            let (_, password) = crate::ssh::userinfo_password(url);
            let opts = crate::ssh::SshOptions {
                password,
                ..Default::default()
            };
            crate::ssh::fetch(url, &opts, &user)
        }
        "tftp" => crate::tftp::fetch_with(url, cfg),
        "ws" | "wss" => crate::websocket::fetch_with(url, cfg),
        other => Err(Error::UnsupportedScheme(other.to_string())),
    }
}

/// Like [`transfer_url_with`], but stream the payload to `sink` and return the
/// byte count. Schemes with a streaming backend (currently FTP/FTPS) copy the
/// data channel straight through; every other scheme falls back to fetching
/// the whole body and writing it once, so behavior is identical either way.
pub(crate) fn transfer_url_to_with(
    url: &Url,
    cfg: &crate::net::NetConfig,
    sink: &mut dyn std::io::Write,
) -> Result<u64> {
    match url.scheme.as_str() {
        "ftp" | "ftps" => crate::ftp::fetch_to_with(url, cfg, sink),
        "file" => crate::file::fetch_to(url, sink),
        _ => {
            let bytes = transfer_url_with(url, cfg)?;
            sink.write_all(&bytes)?;
            Ok(bytes.len() as u64)
        }
    }
}

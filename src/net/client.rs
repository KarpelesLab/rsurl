//! [`Client`]: a reusable handle that carries network configuration (a
//! [`Connector`], proxy choice, timeouts, TLS/IDN options) and applies it to
//! every request it makes. The crate's free functions (`get`, `transfer`, …)
//! are thin wrappers over a default `Client`.

use std::sync::Arc;
use std::time::Duration;

use crate::error::Result;
use crate::net::stream::NetStream;
use crate::net::{connector_from_proxy_url, Connector, DirectConnector};
use crate::url::Url;

/// Internal bundle of network settings handed to the protocol backends so they
/// dial through the configured transport.
pub(crate) struct NetConfig {
    pub(crate) connector: Arc<dyn Connector>,
    pub(crate) connect_timeout: Option<Duration>,
    /// Verify TLS certificates (consumed by the HTTP arm of `transfer_url`).
    pub(crate) verify: bool,
    /// Try `EPSV` before `PASV` for FTP passive data connections. Cleared by
    /// curl's `--disable-epsv`; the FTP backend then goes straight to `PASV`.
    pub(crate) ftp_use_epsv: bool,
    /// Create missing directory components of an FTP upload path with `MKD`
    /// before `STOR`/`APPE` (curl `--ftp-create-dirs`).
    pub(crate) ftp_create_dirs: bool,
    /// Use active-mode FTP data connections (`EPRT`/`PORT`; the server dials
    /// back) instead of passive (curl `-P`/`--ftp-port`). Direct-only.
    pub(crate) ftp_active: bool,
    /// Require TLS for mail protocols (curl `--ssl-reqd`): smtp/imap/pop3 must
    /// upgrade to TLS (STARTTLS/STLS) before any credential or message data is
    /// sent over the connection. A plaintext scheme whose server does not offer
    /// the upgrade is rejected rather than transmitting in the clear. Implicit-
    /// TLS schemes (smtps/imaps/pop3s) already satisfy this.
    pub(crate) require_tls: bool,
}

impl Default for NetConfig {
    fn default() -> Self {
        NetConfig {
            connector: Arc::new(DirectConnector),
            connect_timeout: Some(Duration::from_secs(30)),
            verify: true,
            ftp_use_epsv: true,
            ftp_create_dirs: false,
            ftp_active: false,
            require_tls: false,
        }
    }
}

impl NetConfig {
    /// Dial `host:port` through the configured connector.
    pub(crate) fn connect(&self, host: &str, port: u16) -> Result<Box<dyn NetStream>> {
        self.connector.connect(host, port, self.connect_timeout)
    }
}

/// A configured client. Build one, set a proxy or custom [`Connector`] and any
/// defaults, then drive requests across any supported scheme.
///
/// ```no_run
/// let client = rsurl::Client::new().proxy("socks5h://127.0.0.1:1080").unwrap();
/// let body = client.transfer("https://example.com/").unwrap();
/// # let _ = body;
/// ```
///
/// # Sharing across threads (connection reuse)
///
/// `Client` is `Send + Sync` and cheap to [`Clone`] (it is just configuration),
/// so wrap it in an [`Arc`] and share it. **Keep-alive connection reuse does
/// not depend on holding one `Client`**, though: rsurl's HTTP/1.1 and HTTP/2
/// idle-connection pools are *process-global*, so back-to-back requests to the
/// same `host:port` — whether issued through one `Client`, several, or the
/// free functions — reuse a warm connection automatically (TLS posture
/// permitting). Fanning N requests at one host across a thread pool therefore
/// reuses connections rather than dialing N times.
///
/// ```no_run
/// use std::sync::Arc;
/// let client = Arc::new(rsurl::Client::new());
/// let handles: Vec<_> = (0..16)
///     .map(|_| {
///         let c = Arc::clone(&client);
///         std::thread::spawn(move || c.get("https://api.example.com/ping"))
///     })
///     .collect();
/// for h in handles { let _ = h.join().unwrap(); }
/// ```
///
/// For many requests to a *single* `https://` host, prefer
/// [`send_multiplexed`](crate::send_multiplexed): one HTTP/2 connection carries
/// every request as a concurrent stream, beating N separate connections.
#[derive(Clone)]
pub struct Client {
    connector: Arc<dyn Connector>,
    connect_timeout: Option<Duration>,
    read_timeout: Option<Duration>,
    verify: bool,
    idn: bool,
    no_proxy: Vec<String>,
    ftp_use_epsv: bool,
    ftp_create_dirs: bool,
    ftp_active: bool,
    require_tls: bool,
}

impl Default for Client {
    fn default() -> Self {
        Client {
            connector: Arc::new(DirectConnector),
            connect_timeout: Some(Duration::from_secs(30)),
            read_timeout: Some(Duration::from_secs(60)),
            verify: true,
            idn: true,
            no_proxy: Vec::new(),
            ftp_use_epsv: true,
            ftp_create_dirs: false,
            ftp_active: false,
            require_tls: false,
        }
    }
}

impl Client {
    /// A client with default settings (direct transport, verification on).
    pub fn new() -> Self {
        Self::default()
    }

    /// Route through a proxy given a curl-style URL (`http`, `https`,
    /// `socks4`, `socks4a`, `socks5`, `socks5h`). See
    /// [`connector_from_proxy_url`].
    pub fn proxy(mut self, spec: &str) -> Result<Self> {
        self.connector = connector_from_proxy_url(spec)?;
        Ok(self)
    }

    /// Use a caller-supplied transport. See [`Connector`].
    pub fn connector(mut self, connector: Arc<dyn Connector>) -> Self {
        self.connector = connector;
        self
    }

    /// Connect-phase timeout (default 30 s). `None` disables it.
    pub fn connect_timeout(mut self, d: Option<Duration>) -> Self {
        self.connect_timeout = d;
        self
    }

    /// Per-read inactivity timeout for the requests this client builds (default
    /// 60 s — so a stalled peer can't hang forever). `None` blocks
    /// indefinitely. See [`Request::read_timeout`](crate::Request::read_timeout).
    pub fn read_timeout(mut self, d: Option<Duration>) -> Self {
        self.read_timeout = d;
        self
    }

    /// Verify TLS certificates (default `true`; `false` is curl's `-k`).
    pub fn verify_tls(mut self, on: bool) -> Self {
        self.verify = on;
        self
    }

    /// Normalize IDN hostnames to punycode (default `true`).
    pub fn idn(mut self, on: bool) -> Self {
        self.idn = on;
        self
    }

    /// Try `EPSV` before `PASV` for FTP passive data connections (default
    /// `true`). Pass `false` for curl's `--disable-epsv`.
    pub fn ftp_use_epsv(mut self, on: bool) -> Self {
        self.ftp_use_epsv = on;
        self
    }

    /// Create missing directories of an FTP upload path before storing (curl
    /// `--ftp-create-dirs`). Default `false`.
    pub fn ftp_create_dirs(mut self, on: bool) -> Self {
        self.ftp_create_dirs = on;
        self
    }

    /// Use active-mode FTP data connections (curl `-P`/`--ftp-port`): the
    /// server dials back to us instead of us dialing it. Direct-only (a proxy
    /// can't accept the callback). Default `false` (passive).
    pub fn ftp_active(mut self, on: bool) -> Self {
        self.ftp_active = on;
        self
    }

    /// Require TLS for mail protocols (curl `--ssl-reqd`). When `true`,
    /// smtp/imap/pop3 transfers must negotiate STARTTLS/STLS before any
    /// credentials or data are sent; if the server does not offer the upgrade
    /// the transfer fails rather than continuing in cleartext. Implicit-TLS
    /// schemes (smtps/imaps/pop3s) already satisfy it. Default `false`.
    pub fn require_tls(mut self, on: bool) -> Self {
        self.require_tls = on;
        self
    }

    /// Replace the no-proxy host-suffix list (curl `NO_PROXY`).
    pub fn no_proxy<I, S>(mut self, entries: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.no_proxy = entries.into_iter().map(Into::into).collect();
        self
    }

    /// True if `host` matches the no-proxy list (suffix match, or `*`).
    fn host_bypassed(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        self.no_proxy.iter().any(|e| {
            let e = e.trim().to_ascii_lowercase();
            e == "*" || host == e || host.ends_with(&format!(".{e}"))
        })
    }

    /// The connector to use for `host` — the configured one, or a direct dial
    /// if the host is in the no-proxy list.
    fn effective_connector(&self, host: &str) -> Arc<dyn Connector> {
        if self.host_bypassed(host) {
            Arc::new(DirectConnector)
        } else {
            self.connector.clone()
        }
    }

    fn net_config_for(&self, host: &str) -> NetConfig {
        NetConfig {
            connector: self.effective_connector(host),
            connect_timeout: self.connect_timeout,
            verify: self.verify,
            ftp_use_epsv: self.ftp_use_epsv,
            ftp_create_dirs: self.ftp_create_dirs,
            ftp_active: self.ftp_active,
            require_tls: self.require_tls,
        }
    }

    /// Build an HTTP [`Request`](crate::Request) pre-seeded with this client's
    /// transport and defaults.
    pub fn request(&self, method: &str, url: &str) -> Result<crate::Request> {
        let mut r = crate::Request::new(method, url)?
            .verify_tls(self.verify)
            .idn(self.idn);
        let host = r.url().host.clone();
        r = r
            .connector(self.effective_connector(&host))
            .read_timeout(self.read_timeout);
        if let Some(t) = self.connect_timeout {
            r = r.connect_timeout(t);
        }
        Ok(r)
    }

    /// Perform an HTTP GET.
    pub fn get(&self, url: &str) -> Result<crate::Response> {
        self.request("GET", url)?.send()
    }

    /// Open a persistent WebSocket connection (`ws://` or `wss://`) over this
    /// client's transport, honouring its connect/read timeouts, proxy, IDN, and
    /// TLS-verification settings. The returned
    /// [`WebSocket`](crate::websocket::WebSocket) exchanges messages over the
    /// lifetime of the connection — see its docs for the send/recv API.
    pub fn websocket(&self, url: &str) -> Result<crate::websocket::WebSocket> {
        let mut url = Url::parse(url)?;
        url.set_idn(self.idn)?;
        self.websocket_url(&url)
    }

    /// Like [`Client::websocket`] but from an already-parsed [`Url`] (IDN
    /// normalization is the caller's responsibility, e.g. via
    /// [`Url::set_idn`]). Used by the CLI, which parses the URL once up front.
    pub fn websocket_url(&self, url: &Url) -> Result<crate::websocket::WebSocket> {
        let cfg = self.net_config_for(&url.host);
        crate::websocket::WebSocket::open(url, &cfg, self.read_timeout)
    }

    /// Run the default operation for the URL's scheme and return its payload,
    /// dialing through this client's transport. Mirrors [`crate::transfer`].
    pub fn transfer(&self, url_str: &str) -> Result<Vec<u8>> {
        let mut url = Url::parse(url_str)?;
        url.set_idn(self.idn)?;
        self.transfer_url(&url)
    }

    /// Like [`Client::transfer`] but from an already-parsed URL.
    pub fn transfer_url(&self, url: &Url) -> Result<Vec<u8>> {
        crate::transfer::transfer_url_with(url, &self.net_config_for(&url.host))
    }

    /// Stream the payload for `url` to `sink`, returning the byte count.
    /// FTP/FTPS copy the data channel straight through (no full-body buffer);
    /// other schemes fetch then write, so the result is identical.
    pub fn transfer_url_to(&self, url: &Url, sink: &mut dyn std::io::Write) -> Result<u64> {
        crate::transfer::transfer_url_to_with(url, &self.net_config_for(&url.host), sink)
    }

    /// Upload `body` to an FTP/FTPS `url` via `STOR` (with optional `REST`
    /// resume), honoring this client's proxy and `--ftp-create-dirs`.
    pub fn ftp_store(&self, url: &Url, body: &[u8], resume_at: Option<u64>) -> Result<()> {
        crate::ftp::store_with(url, body, resume_at, &self.net_config_for(&url.host))
    }

    /// Upload `body` to an FTP/FTPS `url` via `APPE` (append), honoring this
    /// client's proxy and `--ftp-create-dirs`.
    pub fn ftp_append(&self, url: &Url, body: &[u8]) -> Result<()> {
        crate::ftp::append_with(url, body, &self.net_config_for(&url.host))
    }

    /// Send a message over SMTP/SMTPS (curl `--mail-from`/`--mail-rcpt` + body).
    pub fn smtp_send(
        &self,
        url: &Url,
        body: &[u8],
        from: &str,
        rcpts: &[String],
        user: Option<&str>,
        pass: Option<&str>,
    ) -> Result<()> {
        let opts = crate::smtp::SmtpOptions {
            from,
            rcpts,
            user,
            pass,
        };
        crate::smtp::send(url, body, &opts, &self.net_config_for(&url.host))
    }

    /// TELNET: send `input`, return the received data (curl `telnet://`).
    pub fn telnet(&self, url: &Url, input: &[u8]) -> Result<Vec<u8>> {
        crate::telnet::run(url, input, &self.net_config_for(&url.host))
    }
}

#[cfg(test)]
mod tests {
    use super::Client;

    /// `Client` must stay `Send + Sync` so it can be wrapped in an `Arc` and
    /// shared across threads (documented contract). A compile-time check.
    #[test]
    fn client_is_send_sync_and_clone() {
        fn assert_send_sync<T: Send + Sync + Clone>() {}
        assert_send_sync::<Client>();
    }
}

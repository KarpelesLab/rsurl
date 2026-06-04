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
}

impl Default for NetConfig {
    fn default() -> Self {
        NetConfig {
            connector: Arc::new(DirectConnector),
            connect_timeout: Some(Duration::from_secs(30)),
            verify: true,
            ftp_use_epsv: true,
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
#[derive(Clone)]
pub struct Client {
    connector: Arc<dyn Connector>,
    connect_timeout: Option<Duration>,
    verify: bool,
    idn: bool,
    no_proxy: Vec<String>,
    ftp_use_epsv: bool,
}

impl Default for Client {
    fn default() -> Self {
        Client {
            connector: Arc::new(DirectConnector),
            connect_timeout: Some(Duration::from_secs(30)),
            verify: true,
            idn: true,
            no_proxy: Vec::new(),
            ftp_use_epsv: true,
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

    /// Connect-phase timeout. `None` disables it.
    pub fn connect_timeout(mut self, d: Option<Duration>) -> Self {
        self.connect_timeout = d;
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
        }
    }

    /// Build an HTTP [`Request`](crate::Request) pre-seeded with this client's
    /// transport and defaults.
    pub fn request(&self, method: &str, url: &str) -> Result<crate::Request> {
        let mut r = crate::Request::new(method, url)?
            .verify_tls(self.verify)
            .idn(self.idn);
        let host = r.url().host.clone();
        r = r.connector(self.effective_connector(&host));
        if let Some(t) = self.connect_timeout {
            r = r.connect_timeout(t);
        }
        Ok(r)
    }

    /// Perform an HTTP GET.
    pub fn get(&self, url: &str) -> Result<crate::Response> {
        self.request("GET", url)?.send()
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

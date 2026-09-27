//! [`Client`]: a reusable handle that carries network configuration (a
//! [`Connector`], proxy choice, timeouts, TLS/IDN options) and applies it to
//! every request it makes. The crate's free functions (`get`, `transfer`, …)
//! are thin wrappers over a default `Client`.

use std::sync::Arc;
use std::time::Duration;

use crate::error::Result;
use crate::net::connector::ProxySpec;
use crate::net::stream::NetStream;
use crate::net::{Connector, DirectConnector};
use crate::url::Url;

/// Internal bundle of network settings handed to the protocol backends so they
/// dial through the configured transport.
pub(crate) struct NetConfig {
    pub(crate) connector: Arc<dyn Connector>,
    pub(crate) connect_timeout: Option<Duration>,
    /// TLS settings (`-k`, `--cacert`, `-E`, `--pinnedpubkey`, ...) for every
    /// TLS leg: ftps/imaps/smtps/... and STARTTLS upgrades, plus the HTTP arm
    /// of `transfer_url`. Use [`NetConfig::tls_connect`].
    pub(crate) tls: crate::tls::TlsSettings,
    /// Per-read inactivity timeout for the protocol sockets. `None` blocks
    /// indefinitely; see [`NetConfig::io_timeout`].
    pub(crate) read_timeout: Option<Duration>,
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
            tls: crate::tls::TlsSettings::default(),
            read_timeout: Some(DEFAULT_READ_TIMEOUT),
            ftp_use_epsv: true,
            ftp_create_dirs: false,
            ftp_active: false,
            require_tls: false,
        }
    }
}

/// Default per-read inactivity timeout (curl has none, but a stalled peer
/// must not hang a library caller forever).
pub(crate) const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(60);

impl NetConfig {
    /// Dial `host:port` through the configured connector.
    pub(crate) fn connect(&self, host: &str, port: u16) -> Result<Box<dyn NetStream>> {
        self.connector.connect(host, port, self.connect_timeout)
    }

    /// TLS-handshake `transport` for `host` with this config's TLS settings
    /// (verification, CA, client cert, pins, CRL, versions, ciphers).
    pub(crate) fn tls_connect<S: std::io::Read + std::io::Write>(
        &self,
        transport: S,
        host: &str,
    ) -> Result<crate::tls::TlsStream<S>> {
        self.tls.connect(transport, host)
    }

    /// The per-read socket timeout to apply to protocol connections.
    pub(crate) fn io_timeout(&self) -> Option<Duration> {
        self.read_timeout
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
    /// Set by [`Client::proxy`]. HTTP requests carry it (plus the no-proxy
    /// list) so the bypass decision is re-made for every redirect hop, for
    /// every proxy kind; the connector is built on demand so it picks up the
    /// `proxy_*` TLS settings whatever the builder order.
    proxy: Option<ProxySpec>,
    /// TLS settings for an `https://` proxy (curl `--proxy-*`), independent
    /// of `tls` (the origin's).
    proxy_tls: crate::tls::TlsSettings,
    connect_timeout: Option<Duration>,
    read_timeout: Option<Duration>,
    tls: crate::tls::TlsSettings,
    idn: bool,
    no_proxy: Vec<String>,
    ftp_use_epsv: bool,
    ftp_create_dirs: bool,
    ftp_active: bool,
    require_tls: bool,
    decompress: bool,
}

impl Default for Client {
    fn default() -> Self {
        Client {
            connector: Arc::new(DirectConnector),
            proxy: None,
            proxy_tls: crate::tls::TlsSettings::default(),
            connect_timeout: Some(Duration::from_secs(30)),
            read_timeout: Some(DEFAULT_READ_TIMEOUT),
            tls: crate::tls::TlsSettings::default(),
            idn: true,
            no_proxy: Vec::new(),
            ftp_use_epsv: true,
            ftp_create_dirs: false,
            ftp_active: false,
            require_tls: false,
            decompress: true,
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
    /// [`connector_from_proxy_url`](crate::net::connector_from_proxy_url).
    ///
    /// The [`no_proxy`](Self::no_proxy) list is re-checked on every HTTP
    /// redirect hop for every proxy kind, and an `https://` proxy is verified
    /// with the `proxy_*` TLS settings (e.g.
    /// [`proxy_ca_bundle`](Self::proxy_ca_bundle)), never the origin's.
    pub fn proxy(mut self, spec: &str) -> Result<Self> {
        self.proxy = Some(ProxySpec::parse(spec)?);
        self.connector = Arc::new(DirectConnector);
        Ok(self)
    }

    /// Use a caller-supplied transport. See [`Connector`].
    pub fn connector(mut self, connector: Arc<dyn Connector>) -> Self {
        self.connector = connector;
        self.proxy = None;
        self
    }

    crate::tls::proxy_tls_builder_methods!();

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
        self.tls.verify = on;
        self
    }

    /// Trust the CA bundle (PEM) at `path` instead of the system roots (curl
    /// `--cacert`). Applies to every TLS protocol this client drives.
    pub fn ca_bundle(mut self, path: &str) -> Self {
        self.tls.ca_bundle = Some(path.to_string());
        self
    }

    /// Additionally trust every CA certificate in `dir` (curl `--capath`).
    pub fn ca_path(mut self, dir: &str) -> Self {
        self.tls.ca_path = Some(dir.to_string());
        self
    }

    /// Check server chains against the CRL in `path` (curl `--crlfile`).
    pub fn crl_file(mut self, path: &str) -> Self {
        self.tls.crl_file = Some(path.to_string());
        self
    }

    /// Present the client certificate at `path` (curl `-E`/`--cert`).
    pub fn client_cert(mut self, path: &str) -> Self {
        self.tls.client_cert = Some(path.to_string());
        self
    }

    /// Client private key at `path` (curl `--key`).
    pub fn client_key(mut self, path: &str) -> Self {
        self.tls.client_key = Some(path.to_string());
        self
    }

    /// Passphrase for an encrypted client key (curl `--pass`).
    pub fn client_key_pass(mut self, pass: &str) -> Self {
        self.tls.client_key_pass = Some(pass.to_string());
        self
    }

    /// Treat the client certificate file as DER (curl `--cert-type DER`).
    pub fn cert_type_der(mut self, der: bool) -> Self {
        self.tls.cert_is_der = der;
        self
    }

    /// Treat the client key file as DER (curl `--key-type DER`).
    pub fn key_type_der(mut self, der: bool) -> Self {
        self.tls.key_is_der = der;
        self
    }

    /// Pin the server public key (curl `--pinnedpubkey`,
    /// `sha256//BASE64[;...]`); a mismatch fails the handshake.
    pub fn pinned_pubkey(mut self, spec: &str) -> Self {
        self.tls.pinned_pubkey = Some(spec.to_string());
        self
    }

    /// Restrict TLS ≤ 1.2 cipher suites (curl `--ciphers`).
    pub fn ciphers(mut self, list: &str) -> Self {
        self.tls.ciphers = Some(list.to_string());
        self
    }

    /// Restrict TLS 1.3 cipher suites (curl `--tls13-ciphers`).
    pub fn tls13_ciphers(mut self, list: &str) -> Self {
        self.tls.tls13_ciphers = Some(list.to_string());
        self
    }

    /// Minimum acceptable TLS version (curl `--tlsv1.x`).
    pub fn tls_min_version(mut self, v: crate::tls::ProtocolVersion) -> Self {
        self.tls.min_version = Some(v);
        self
    }

    /// Maximum acceptable TLS version (curl `--tls-max`).
    pub fn tls_max_version(mut self, v: crate::tls::ProtocolVersion) -> Self {
        self.tls.max_version = Some(v);
        self
    }

    /// Normalize IDN hostnames to punycode (default `true`).
    pub fn idn(mut self, on: bool) -> Self {
        self.idn = on;
        self
    }

    /// Transparently decompress `Content-Encoding` response bodies for the HTTP
    /// requests this client builds (default `true`, matching curl). Pass `false`
    /// to leave compressed bodies as raw wire bytes with the `Content-Encoding`
    /// header intact, so the caller can apply its own content-coding policy.
    /// See [`Request::decompress`](crate::Request::decompress).
    pub fn decompress(mut self, on: bool) -> Self {
        self.decompress = on;
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

    /// Replace the no-proxy list (curl `NO_PROXY`). Each entry is `*` (every
    /// host), a host name matching itself and its subdomains
    /// (case-insensitive; a leading `.` is optional), or — for IP-literal
    /// hosts — an exact IP or a CIDR block such as `10.0.0.0/8` or `fc00::/7`.
    pub fn no_proxy<I, S>(mut self, entries: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.no_proxy = entries.into_iter().map(Into::into).collect();
        self
    }

    /// True if `host` matches the no-proxy list (curl semantics).
    fn host_bypassed(&self, host: &str) -> bool {
        crate::net::no_proxy_matches(self.no_proxy.iter().map(String::as_str), host)
    }

    /// The connector to use for `host` — the configured one, or a direct dial
    /// if the host is in the no-proxy list.
    fn effective_connector(&self, host: &str) -> Arc<dyn Connector> {
        if self.host_bypassed(host) {
            Arc::new(DirectConnector)
        } else if let Some(p) = &self.proxy {
            p.connector(&self.proxy_tls)
        } else {
            self.connector.clone()
        }
    }

    fn net_config_for(&self, host: &str) -> NetConfig {
        NetConfig {
            connector: self.effective_connector(host),
            connect_timeout: self.connect_timeout,
            tls: self.tls.clone(),
            read_timeout: self.read_timeout,
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
            .with_tls_settings(&self.tls)
            .idn(self.idn)
            .decompress(self.decompress);
        r.proxy_tls = self.proxy_tls.clone();
        r = match &self.proxy {
            // The proxy travels as the request's own proxy + no-proxy list, so
            // the bypass is decided per hop (for http, https and socks proxies
            // alike): a redirect from a no-proxy host to an external one still
            // goes through the proxy, and vice versa.
            Some(p) => {
                r.set_proxy_spec(p.clone());
                r.no_proxy(self.no_proxy.clone())
            }
            None => {
                let host = r.url().host.clone();
                r.connector(self.effective_connector(&host))
            }
        };
        r = r.read_timeout(self.read_timeout);
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
        crate::websocket::WebSocket::open(url, &cfg, self.read_timeout, &[])
    }

    /// Like [`Client::websocket`] but offers `subprotocols` in the
    /// `Sec-WebSocket-Protocol` handshake header; the server's selection is
    /// readable via [`WebSocket::subprotocol`](crate::websocket::WebSocket::subprotocol).
    pub fn websocket_with_subprotocols(
        &self,
        url: &str,
        subprotocols: &[&str],
    ) -> Result<crate::websocket::WebSocket> {
        let mut url = Url::parse(url)?;
        url.set_idn(self.idn)?;
        let cfg = self.net_config_for(&url.host);
        let protos: Vec<String> = subprotocols.iter().map(|s| s.to_string()).collect();
        crate::websocket::WebSocket::open(&url, &cfg, self.read_timeout, &protos)
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

    /// Upload `body` to a `tftp://` URL (RFC 1350 WRQ) through this client's
    /// transport: a SOCKS5 proxy is honoured and the socket family follows the
    /// server's address (IPv6 works).
    pub fn tftp_store(&self, url: &Url, body: &[u8]) -> Result<()> {
        crate::tftp::store_with(url, body, &self.net_config_for(&url.host))
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

    /// Publish `payload` to an `mqtt`/`mqtts` `url` (curl `-d`/`-T` on an MQTT
    /// URL), honoring this client's proxy / custom connector.
    pub fn mqtt_publish(&self, url: &Url, payload: &[u8], qos: u8) -> Result<()> {
        crate::mqtt::publish_with(url, payload, qos, &self.net_config_for(&url.host))
    }

    /// TELNET: send `input`, return the received data (curl `telnet://`).
    pub fn telnet(&self, url: &Url, input: &[u8]) -> Result<Vec<u8>> {
        crate::telnet::run(url, input, &self.net_config_for(&url.host))
    }
}

#[cfg(test)]
mod tests {
    use super::{Client, NetConfig, DEFAULT_READ_TIMEOUT};
    use std::time::Duration;

    /// `Client` must stay `Send + Sync` so it can be wrapped in an `Arc` and
    /// shared across threads (documented contract). A compile-time check.
    #[test]
    fn client_is_send_sync_and_clone() {
        fn assert_send_sync<T: Send + Sync + Clone>() {}
        assert_send_sync::<Client>();
    }

    /// `host_bypassed` must treat a leading dot on a no-proxy entry as cosmetic
    /// (`.example.com` == `example.com`), matching curl and the env-var path.
    /// Regression test: a leading-dot entry used to fail to bypass subdomains.
    #[test]
    fn no_proxy_matches_leading_dot_apex_suffix_and_wildcard() {
        let c = Client::new().no_proxy([".example.com"]);
        assert!(c.host_bypassed("foo.example.com"));
        assert!(c.host_bypassed("example.com"));
        assert!(c.host_bypassed("EXAMPLE.COM")); // case-insensitive
        assert!(!c.host_bypassed("notexample.com"));
        assert!(!c.host_bypassed("example.com.evil.com"));

        // Entry without a leading dot behaves the same.
        let c = Client::new().no_proxy(["example.com"]);
        assert!(c.host_bypassed("foo.example.com"));
        assert!(c.host_bypassed("example.com"));

        // Wildcard bypasses everything.
        assert!(Client::new().no_proxy(["*"]).host_bypassed("anything.test"));

        // IP hosts: exact or CIDR only, bracket-insensitive for IPv6.
        let c = Client::new().no_proxy(["2.3.4", "10.0.0.0/8", "::1"]);
        assert!(!c.host_bypassed("1.2.3.4"));
        assert!(c.host_bypassed("10.9.8.7"));
        assert!(c.host_bypassed("[::1]"));
    }

    /// With an HTTP proxy, the no-proxy decision must be made per request hop
    /// (by the `Request`), not frozen from the first URL: the request carries
    /// the proxy and the list instead of a pre-chosen direct connector.
    #[test]
    fn http_proxy_bypass_is_decided_per_hop() {
        let c = Client::new()
            .proxy("http://proxy.example:3128")
            .unwrap()
            .no_proxy(["internal.example"]);
        let r = c.request("GET", "http://internal.example/").unwrap();
        assert!(r.connector.is_direct());
        let p = r.proxy.as_ref().expect("proxy kept on the request");
        assert_eq!((p.host.as_str(), p.port), ("proxy.example", 3128));
        assert!(crate::http::proxy_bypassed(&r));
        // The same request after a redirect to an external host is proxied.
        let mut hop = r.clone();
        hop.url = crate::url::Url::parse("http://external.example/").unwrap();
        assert!(!crate::http::proxy_bypassed(&hop));

        // A custom connector replaces the HTTP proxy entirely.
        let c = c.connector(std::sync::Arc::new(crate::net::DirectConnector));
        assert!(c.request("GET", "http://x/").unwrap().proxy.is_none());
    }

    /// SOCKS and `https://` proxies are also re-decided per hop: the request
    /// keeps the proxy spec and picks a direct dial only for no-proxy hosts.
    /// The proxy's TLS settings travel separately from the origin's.
    #[test]
    fn socks_and_https_proxy_bypass_is_decided_per_hop() {
        for spec in ["socks5h://proxy.example:1080", "https://proxy.example:443"] {
            let c = Client::new()
                .proxy(spec)
                .unwrap()
                .no_proxy(["internal.example"])
                .verify_tls(false)
                .proxy_ca_bundle("/proxy-ca.pem");
            let mut r = c.request("GET", "http://internal.example/").unwrap();
            assert!(r.proxy.is_none(), "{spec}");
            assert!(r.proxy_spec.is_some(), "{spec}");
            assert!(
                !r.verify_tls && r.proxy_tls.verify,
                "{spec}: -k is origin-only"
            );
            assert_eq!(r.proxy_tls.ca_bundle.as_deref(), Some("/proxy-ca.pem"));
            r.select_hop_connector();
            assert!(
                r.connector.is_direct(),
                "{spec}: no-proxy host dials direct"
            );
            r.url = crate::url::Url::parse("http://external.example/").unwrap();
            r.select_hop_connector();
            assert!(!r.connector.is_direct(), "{spec}: external host is proxied");
        }
        // Non-HTTP protocols pick the connector per host too.
        let c = Client::new()
            .proxy("socks5://p:1080")
            .unwrap()
            .no_proxy(["internal.example"]);
        assert!(c.net_config_for("internal.example").connector.is_direct());
        assert!(!c.net_config_for("external.example").connector.is_direct());
    }

    /// Serve one `gophers://` request with the rustls test cert (a `localhost`
    /// leaf under the test CA), answering `hello` and closing cleanly.
    #[cfg(feature = "rustls-tls")]
    fn serve_gophers_once() -> u16 {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let Ok((mut sock, _)) = listener.accept() else {
                return;
            };
            let cfg = crate::proto::tls::rustls_tests::server_config();
            let mut server = rustls::ServerConnection::new(cfg).unwrap();
            {
                let mut tls = rustls::Stream::new(&mut server, &mut sock);
                let mut byte = [0u8; 1];
                let mut line = Vec::new();
                while tls.read(&mut byte).map(|n| n == 1).unwrap_or(false) {
                    line.push(byte[0]);
                    if line.ends_with(b"\r\n") {
                        break;
                    }
                }
                let _ = tls.write_all(b"hello");
                tls.conn.send_close_notify();
                let _ = tls.flush();
            }
            crate::test_support::graceful_close(&mut sock);
        });
        port
    }

    /// The non-HTTP protocols honour the client's TLS settings: an unknown CA
    /// fails by default, `-k` or `--cacert` makes it work, and a wrong
    /// `--pinnedpubkey` fails even with `-k` (previously every non-HTTP TLS leg
    /// hard-coded default verification and ignored all of these).
    #[cfg(feature = "rustls-tls")]
    #[test]
    fn non_http_tls_honours_client_tls_settings() {
        let url = |port: u16| format!("gophers://localhost:{port}/");

        let port = serve_gophers_once();
        assert!(
            Client::new().transfer(&url(port)).is_err(),
            "untrusted test CA must be rejected by default"
        );

        let port = serve_gophers_once();
        let body = Client::new()
            .verify_tls(false)
            .transfer(&url(port))
            .unwrap();
        assert_eq!(body, b"hello");

        let dir = std::env::temp_dir().join(format!("rsurl-ca-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ca = dir.join("ca.pem");
        std::fs::write(&ca, crate::proto::tls::rustls_tests::CA_CERT_PEM).unwrap();
        let port = serve_gophers_once();
        let body = Client::new()
            .ca_bundle(ca.to_str().unwrap())
            .transfer(&url(port))
            .unwrap();
        assert_eq!(body, b"hello");

        let port = serve_gophers_once();
        let wrong_pin = "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        assert!(
            Client::new()
                .verify_tls(false)
                .pinned_pubkey(wrong_pin)
                .transfer(&url(port))
                .is_err(),
            "a pin mismatch must fail even with -k"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn net_config_carries_tls_settings_and_read_timeout() {
        let c = Client::new()
            .verify_tls(false)
            .ca_bundle("/ca.pem")
            .pinned_pubkey("sha256//x")
            .read_timeout(Some(Duration::from_secs(7)));
        let cfg = c.net_config_for("example.com");
        assert!(!cfg.tls.verify);
        assert_eq!(cfg.tls.ca_bundle.as_deref(), Some("/ca.pem"));
        assert_eq!(cfg.tls.pinned_pubkey.as_deref(), Some("sha256//x"));
        assert_eq!(cfg.io_timeout(), Some(Duration::from_secs(7)));
        assert_eq!(
            NetConfig::default().io_timeout(),
            Some(DEFAULT_READ_TIMEOUT)
        );
    }
}

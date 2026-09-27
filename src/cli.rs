//! rsurl CLI — a (deliberately limited) curl-compatible front-end.
//!
//! Supported options at this milestone:
//!
//!     -o, --output <file>      write body to file instead of stdout
//!     -O, --remote-name        save body under the URL's last path segment
//!     -i, --include            include response headers in the output
//!     -I, --head               issue HEAD instead of GET
//!     -v, --verbose            print request/response headers to stderr
//!     -s, --silent             suppress error messages
//!     -X, --request <method>   override HTTP method; for rtsp:// selects the
//!                              RTSP method (OPTIONS/DESCRIBE/SETUP/PLAY/TEARDOWN)
//!     -H, --header <line>      add a request header (repeatable)
//!     -d, --data <body>        POST body (urlencoded); @file reads from disk
//!         --data-raw <body>    like -d but no @file interpretation
//!         --data-binary <body> like -d but no newline stripping when @file
//!         --data-urlencode <s> URL-encode <s> before sending; @file allowed
//!     -F, --form <name=value>  add a multipart/form-data part. The value may
//!                              be @file (file upload) or <file (read field
//!                              value from file). Modifiers: ;type=, ;filename=,
//!                              ;headers=@hdrfile.
//!         --form-string <n=v>  like -F but the value is always literal
//!         --form-escape        percent-encode field names/filenames per
//!                              RFC 7578 §4.2 instead of backslash-escaping
//!     -T, --upload-file <f>    upload the file (HTTP PUT, FTP/FTPS STOR, TFTP
//!                              WRQ, MQTT PUBLISH, or SFTP/SCP write)
//!         --key <file>         SSH private-key identity for sftp://, scp://
//!                              public-key auth (repeatable; curl's --key)
//!     -C, --continue-at <off>  resume at byte <off> (FTP REST; '-C -' resumes HTTP)
//!     -a, --append             FTP/FTPS upload: append (APPE) instead of STOR
//!     -A, --user-agent <ua>    set User-Agent
//!     -e, --referer <ref>      set Referer
//!     -L, --location           follow 3xx redirects
//!         --max-redirs <n>     cap on redirect hops (default 50)
//!     -u, --user <user:pass>   HTTP Basic auth credentials
//!     -k, --insecure           don't verify the TLS certificate chain
//!         --cacert <file>      PEM bundle to use instead of system trust
//!         --no-idn             don't convert international (IDN) hostnames to punycode
//!         --max-time <secs>    cap on the whole operation's wall time
//!         --connect-timeout    cap on the TCP connect step
//!         --http2              require HTTP/2 (ALPN h2); error if unavailable
//!         --http1.1            force HTTP/1.1 (alias: --http1)
//!         --http3              try HTTP/3 (QUIC), fall back to h2/1.1
//!         --http3-only         require HTTP/3 (QUIC); no fallback
//!     -b, --cookie <data>      cookies: "k=v[; k=v]" or a Netscape file path
//!     -c, --cookie-jar <file>  write all known cookies to <file> on exit
//!     -x, --proxy <url>        outbound HTTP proxy (e.g. http://host:port)
//!         --proxy-user <u:p>   credentials for the proxy
//!         --noproxy <hosts>    comma-list of host suffixes that bypass it
//!     -h, --help               print help
//!     -V, --version            print version

use std::fs::File;
use std::io::{self, IsTerminal, Read, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use rsurl::{CookieJar, HttpVersionPref, Request, Response, Url};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// One `-o <file>` or `-O` on the command line. curl pairs these with URLs
/// positionally: the N-th URL uses the N-th output option (see
/// [`Args::for_url`]).
#[derive(Debug, Clone, PartialEq)]
enum OutputSpec {
    File(String),
    Remote,
}

/// `--proxy-insecure`, `--proxy-cacert`, ... (see [`Args::proxy_tls`]).
#[derive(Default, Clone)]
struct ProxyTlsArgs {
    insecure: bool,
    cacert: Option<String>,
    capath: Option<String>,
    crlfile: Option<String>,
    /// `--proxy-cert <file[:password]>`.
    cert: Option<String>,
    key: Option<String>,
    pass: Option<String>,
    cert_type_der: bool,
    key_type_der: bool,
    pinned_pubkey: Option<String>,
    ciphers: Option<String>,
    tls13_ciphers: Option<String>,
    tls_min: Option<rsurl::tls::ProtocolVersion>,
    tls_max: Option<rsurl::tls::ProtocolVersion>,
}

/// Apply [`ProxyTlsArgs`] to a builder with the `proxy_*` TLS methods
/// (`rsurl::Request` and `rsurl::Client` share the same names).
macro_rules! apply_proxy_tls {
    ($b:expr, $p:expr) => {{
        let p: &ProxyTlsArgs = $p;
        let mut b = $b;
        if p.insecure {
            b = b.proxy_verify_tls(false);
        }
        if let Some(v) = &p.cacert {
            b = b.proxy_ca_bundle(v);
        }
        if let Some(v) = &p.capath {
            b = b.proxy_ca_path(v);
        }
        if let Some(v) = &p.crlfile {
            b = b.proxy_crl_file(v);
        }
        if let Some(cert) = &p.cert {
            let (cert_path, inline_pass) = split_cert_pass(cert);
            b = b
                .proxy_client_cert(cert_path)
                .proxy_cert_type_der(p.cert_type_der)
                .proxy_key_type_der(p.key_type_der);
            if let Some(k) = &p.key {
                b = b.proxy_client_key(k);
            }
            if let Some(pass) = p.pass.as_deref().or(inline_pass) {
                b = b.proxy_client_key_pass(pass);
            }
        }
        if let Some(v) = &p.pinned_pubkey {
            b = b.proxy_pinned_pubkey(v);
        }
        if let Some(v) = &p.ciphers {
            b = b.proxy_ciphers(v);
        }
        if let Some(v) = &p.tls13_ciphers {
            b = b.proxy_tls13_ciphers(v);
        }
        if let Some(v) = p.tls_min {
            b = b.proxy_tls_min_version(v);
        }
        if let Some(v) = p.tls_max {
            b = b.proxy_tls_max_version(v);
        }
        b
    }};
}

#[derive(Default, Clone)]
struct Args {
    urls: Vec<String>,
    /// The output file for the transfer being run (resolved per URL from
    /// `outputs` by [`Args::for_url`]; after parsing it holds the last `-o`).
    output: Option<String>,
    /// Every `-o`/`-O`, in command-line order.
    outputs: Vec<OutputSpec>,
    /// `--remote-name-all`: `-O` for every URL that has no `-o`/`-O` of its own.
    remote_name_all: bool,
    include_headers: bool,
    head: bool,
    verbose: bool,
    /// Count of `-v` flags: 1 = verbose, 2+ = extra (e.g. per-peer torrent
    /// diagnostics). `verbose` stays `true` whenever this is ≥ 1.
    verbosity: u8,
    silent: bool,
    method: Option<String>,
    headers: Vec<(String, String)>,
    /// Lower-cased names from `-H "Name:"` (no value): curl's "don't send the
    /// header you would add yourself" form.
    removed_headers: Vec<String>,
    /// `--url-query <data>` parts, appended to the URL's query string.
    url_queries: Vec<String>,
    /// One entry per `-d` / `--data-raw` / `--data-binary` / `--data-urlencode`
    /// on the command line, in order. Final body is the concatenation of
    /// each part's encoded bytes joined with `b"&"`. See [`DataPart`] and
    /// [`assemble_form_body`].
    data_parts: Vec<DataPart>,
    /// One entry per `--json` flag, in order. The body is the verbatim
    /// concatenation of every part (each may be `@file`); it also sets
    /// `Content-Type` and `Accept` to `application/json`.
    json_parts: Vec<String>,
    user_agent: Option<String>,
    referer: Option<String>,
    /// Most recent HTTP version flag (--http2, --http1.1, --http3,
    /// --http3-only) seen on the CLI.
    /// `None` means "Auto" — the library decides via ALPN. Last one wins,
    /// matching curl.
    http_version: Option<HttpVersionPref>,
    follow_redirects: bool,
    max_redirs: Option<u32>,
    basic_auth: Option<(String, String)>,
    insecure: bool,
    /// `--no-idn`: do not convert international (IDN) hostnames to punycode.
    no_idn: bool,
    cacert: Option<String>,
    /// `-m`/`--max-time` and `--connect-timeout`, in (possibly fractional)
    /// seconds like curl.
    max_time: Option<Duration>,
    connect_timeout: Option<Duration>,
    remote_name: bool,
    /// Argument to `-b`/`--cookie`. Either explicit `k=v[; k=v]...` cookie
    /// data (detected by the presence of `=`) or a Netscape `cookies.txt`
    /// file path. Mirrors curl's behaviour.
    cookie_in: Option<String>,
    /// Argument to `-c`/`--cookie-jar`. After all transfers complete, the
    /// jar is written to this path in Netscape `cookies.txt` format.
    cookie_jar: Option<String>,
    /// `-j`/`--junk-session-cookies`: drop session cookies (no expiry) from
    /// the cookie file(s) read at start-up, as if a new session began.
    junk_session_cookies: bool,
    /// `-x`/`--proxy <url>` — outbound HTTP proxy. Bare `host:port` is
    /// treated as `http://`. Empty string explicitly disables any env-var
    /// proxy (matches curl's `-x ""`).
    proxy: Option<String>,
    /// `--proxy-user <user:pass>` — overrides any credentials embedded in
    /// the proxy URL.
    proxy_user: Option<(String, String)>,
    /// `--noproxy <hosts>` — comma-separated host suffixes that bypass
    /// the proxy. A single `*` bypasses everything.
    noproxy: Option<String>,
    /// One entry per `-F`/`--form`/`--form-string`. Parsed at CLI time
    /// (curl-style `name=value;type=…;filename=…;headers=@…`) and joined
    /// into a `multipart/form-data` body in [`build_multipart_body`].
    form_parts: Vec<FormPart>,
    /// `--form-escape`: percent-encode field names and filenames per
    /// RFC 7578 §4.2 instead of curl's historical backslash-escape.
    form_escape: bool,
    /// `-T`/`--upload-file <file>` — PUT the file as the request body,
    /// default `Content-Type: application/octet-stream`.
    upload_file: Option<String>,
    /// `-C`/`--continue-at <offset>` — resume a transfer at byte `offset`.
    /// For FTP uploads this sends `REST <offset>` before `STOR`.
    continue_at: Option<u64>,
    /// `-C -` — automatic resume: for an HTTP download, continue an existing
    /// `<name>.rsurlpart` via a Range request and finalise it on completion.
    continue_resume: bool,
    /// `-a`/`--append` — for FTP/FTPS uploads (`-T`), append to the remote file
    /// via `APPE` instead of replacing it via `STOR`. A no-op for non-FTP
    /// uploads, matching curl (whose `-a` only applies to FTP/FTPS/SFTP).
    /// `APPE` negotiates no offset, so it takes precedence over `-C`/REST.
    append: bool,
    /// `--key <file>` — SSH private-key identity file(s) for `sftp://`/`scp://`
    /// public-key auth (curl's `--key`). Repeatable. When empty, the default
    /// keys under `~/.ssh` (`id_ed25519`, `id_ecdsa`, `id_rsa`) are probed.
    /// Note: curl's `-i` is `--include` here, so the SSH identity flag is the
    /// long form `--key` only (no `-i` alias, to avoid the collision).
    ssh_keys: Vec<String>,
    /// `-f`/`--fail`: on HTTP >= 400, emit no body and exit 22.
    fail: bool,
    /// `-S`/`--show-error`: show errors even under `-s`.
    show_error: bool,
    /// `-G`/`--get`: move `-d` data into the URL query and use GET.
    get: bool,
    /// `-r`/`--range <range>`: byte range (`Range: bytes=<range>`).
    range: Option<String>,
    /// `--compressed`: advertise `Accept-Encoding` (we decode transparently).
    compressed: bool,
    /// `-D`/`--dump-header <file>`: write response headers to this file.
    dump_header: Option<String>,
    /// `-R`/`--remote-time`: set the output file's mtime from `Last-Modified`.
    remote_time: bool,
    /// `--create-dirs`: create missing parent directories of `-o`.
    create_dirs: bool,
    /// `--remove-on-error`: delete a partial `-o`/`-O` file if the transfer fails.
    remove_on_error: bool,
    /// `--no-clobber`: never overwrite an existing `-o`/`-O` file; pick a free
    /// `.1`, `.2`, ... suffix instead (curl semantics).
    no_clobber: bool,
    /// `--disable-epsv`: for FTP, skip `EPSV` and use `PASV` directly.
    disable_epsv: bool,
    /// `--ssl-reqd`: require TLS for mail (smtp/imap/pop3) — the connection must
    /// upgrade via STARTTLS/STLS before credentials or data are sent, else fail.
    ssl_reqd: bool,
    /// `--ftp-create-dirs`: create missing remote directories before an FTP
    /// upload.
    ftp_create_dirs: bool,
    /// `-P`/`--ftp-port <addr>`: use active-mode FTP. The address argument is
    /// accepted for curl compatibility; rsurl uses the control connection's
    /// local IP as the callback address regardless.
    ftp_port: Option<String>,
    /// `--max-filesize <bytes>`: refuse a download larger than this.
    max_filesize: Option<u64>,
    /// `-w`/`--write-out <format>`: print a formatted summary after transfer.
    write_out: Option<String>,
    /// `-n`/`--netrc` (or `--netrc-file <path>`): read credentials from a
    /// netrc file when no `-u` is given.
    netrc: bool,
    netrc_file: Option<String>,
    /// `-J`/`--remote-header-name`: with `-O`, name the saved file from the
    /// response `Content-Disposition` header.
    remote_header_name: bool,
    /// `--retry <n>`: retry a failed transfer up to `n` times.
    retry: u32,
    /// `-4`/`-6`: force the connection's address family.
    ipv4: bool,
    ipv6: bool,
    /// `--resolve <host:port:addr>`: static DNS overrides.
    resolve: Vec<(String, u16, std::net::IpAddr)>,
    /// `-#`/`--progress-bar`: accepted; rsurl buffers the body, so there is no
    /// live progress to render — this is a no-op.
    progress_bar: bool,
    /// `-E`/`--cert <file[:password]>`: client certificate for mutual TLS. An
    /// inline `:password` (after the path) is the key passphrase, same as
    /// `--pass`. The key may be in this file or in a separate `--key` file.
    cert: Option<String>,
    /// `--key <file>`: the client private key, when not embedded in `--cert`.
    key_file: Option<String>,
    /// `--pass <phrase>`: passphrase for an encrypted `--key`/`--cert` key.
    key_pass: Option<String>,
    /// `--cert-type <PEM|DER>` / `--key-type <PEM|DER>`: encoding of the cert /
    /// key files. Default PEM. `true` means DER.
    cert_type_der: bool,
    key_type_der: bool,
    /// `--pinnedpubkey <sha256//BASE64[;...]>`: pin the server's public key.
    pinned_pubkey: Option<String>,
    /// `--capath <dir>`: trust additional CA certs from every file in `dir`.
    capath: Option<String>,
    /// `--crlfile <file>`: CRL to check the server chain against (honored on
    /// the default purecrypto-tls backend; the rustls backend errors).
    crl_file: Option<String>,
    /// `--ciphers <list>` (TLS≤1.2) / `--tls13-ciphers <list>` (TLS 1.3):
    /// restrict the offered cipher suites (honored on purecrypto-tls).
    ciphers: Option<String>,
    tls13_ciphers: Option<String>,
    /// curl's `--proxy-*` TLS family: settings for the TLS session to an
    /// `https://` proxy, independent of the origin's (`-k` does not relax the
    /// proxy check and `--proxy-insecure` does not relax the origin's).
    proxy_tls: ProxyTlsArgs,
    /// Recognized-but-not-yet-enforced flags, kept so curl scripts/config files
    /// don't hard-fail. `--limit-rate`/`-y`/`-Y` need streaming downloads
    /// (enforced on the file-download path). We warn when they are no-ops.
    limit_rate: Option<String>,
    speed_limit: Option<String>,
    speed_time: Option<String>,
    /// `-z`/`--time-cond <date|file>`: conditional GET. A leading `-` flips to
    /// If-Unmodified-Since; a value naming an existing file uses its mtime.
    time_cond: Option<String>,
    /// `--output-dir <dir>`: directory prepended to `-o`/`-O` output names.
    output_dir: Option<String>,
    /// `--fail-with-body`: like `-f` (exit 22 on >=400) but still write the body.
    fail_with_body: bool,
    /// `--proto <spec>`: restrict which schemes the initial URL may use.
    proto: Option<String>,
    /// `--proto-default <scheme>`: scheme for URLs given without one.
    proto_default: Option<String>,
    /// `-e`/`--referer` `;auto`: send Referer from the previous URL on redirect.
    auto_referer: bool,
    /// `--retry-delay <s>`: fixed delay between retries (else exponential).
    retry_delay: Option<u64>,
    /// `--retry-max-time <s>`: cap on total time spent retrying.
    retry_max_time: Option<u64>,
    /// `--retry-connrefused`: also retry on connection-refused.
    retry_connrefused: bool,
    /// `--retry-all-errors`: retry on any error.
    retry_all_errors: bool,
    /// `-g`/`--globoff`: disable URL globbing (`{}`/`[]` taken literally).
    globoff: bool,
    /// `--location-trusted`: keep credentials across cross-host redirects.
    location_trusted: bool,
    /// `--post301`/`--post302`/`--post303`: keep POST on that redirect status.
    post301: bool,
    post302: bool,
    post303: bool,
    /// `--connect-to <h1:p1:h2:p2>`: dial h2:p2 for requests to h1:p1.
    connect_to: Vec<(String, u16, String, u16)>,
    /// `--unix-socket <path>`: route the connection through a Unix socket.
    unix_socket: Option<String>,
    /// `--tlsv1.x` / `--tls-max`: TLS version floor / ceiling.
    tls_min: Option<rsurl::tls::ProtocolVersion>,
    tls_max: Option<rsurl::tls::ProtocolVersion>,
    /// `--mail-from <addr>` / `--mail-rcpt <addr>`: SMTP envelope.
    mail_from: Option<String>,
    mail_rcpt: Vec<String>,
    /// `--digest`: use HTTP Digest auth with the `-u` credentials.
    digest: bool,
    /// `--oauth2-bearer <token>`: send `Authorization: Bearer <token>`.
    bearer: Option<String>,
    /// `--aws-sigv4 <provider...>`: sign the request with AWS Signature V4.
    aws_sigv4: Option<String>,
    /// `-Z`/`--parallel`: run this invocation's transfers concurrently.
    parallel: bool,
    /// `--parallel-max <n>`: cap on concurrent transfers (default 50).
    parallel_max: Option<usize>,
    /// `--parallel-segments <n>`: download a single `-o`/`-O` file over `n`
    /// concurrent HTTP range requests (segmented download). rsurl extension.
    parallel_segments: Option<usize>,
    /// `--torrent`: treat the source (a `.torrent` path/URL, or a magnet link)
    /// as torrent metainfo and download its contents.
    torrent: bool,
    /// `--listen-port <p>`: port advertised to peers/trackers for BitTorrent.
    /// `0` binds any free port; the chosen one is reported and announced.
    listen_port: Option<u16>,
    /// `--bt-peer <ip:port>` (repeatable): add a peer directly (besides those
    /// from trackers).
    bt_peers: Vec<String>,
    /// `--no-dht`: disable the DHT peer-discovery fallback for torrents.
    no_dht: bool,
    /// `--seed`: after a torrent download completes, keep seeding.
    seed: bool,
    /// `--share-ratio <r>`: seed after completion until uploaded/downloaded
    /// reaches `r`, then exit.
    share_ratio: Option<f64>,
    /// `--recheck`: on a torrent resume, re-hash on-disk data against the piece
    /// table instead of trusting the saved resume bitfield.
    recheck: bool,
    /// `--bt-info`: print decoded torrent metadata as JSON to stdout, then exit.
    bt_info: bool,
    /// `--bt-save-torrent`: write a `.torrent` (to `-o`, else stdout), then exit.
    bt_save_torrent: bool,
    /// `--bt-file <N|path>`: download just one file of a multi-file torrent into
    /// `-o` (1-based index, or a matching path).
    bt_file: Option<String>,
    /// `--bt-concat`: download a multi-file torrent as one concatenated file.
    bt_concat: bool,
}

impl Args {
    /// The option set for the `idx`-th URL of this operation: curl uses the
    /// `idx`-th `-o`/`-O` for it, and URLs beyond the last output option go
    /// to stdout (or get `-O` semantics under `--remote-name-all`).
    fn for_url(&self, idx: usize) -> Args {
        let mut a = self.clone();
        match self.outputs.get(idx) {
            Some(OutputSpec::File(f)) => {
                a.output = Some(f.clone());
                a.remote_name = false;
            }
            Some(OutputSpec::Remote) => {
                a.output = None;
                a.remote_name = true;
            }
            None => {
                a.output = None;
                a.remote_name = self.remote_name_all;
            }
        }
        a
    }

    /// Whether `-H "Name:"` asked to suppress the header `name`.
    fn header_removed(&self, name: &str) -> bool {
        self.removed_headers
            .iter()
            .any(|h| h.eq_ignore_ascii_case(name))
    }

    /// Whether a `-H` supplies the header `name` itself.
    fn has_header(&self, name: &str) -> bool {
        self.headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case(name))
    }
}

/// One body chunk supplied on the command line via `-d` and friends.
///
/// Curl semantics — kept here as documentation because they vary subtly
/// between flags:
///
/// * `-d` / `--data` — value goes verbatim **unless** it starts with `@`,
///   in which case the rest is a file path. File contents are read and
///   every CR (`\r`), LF (`\n`), and NUL byte is stripped — curl's
///   historical behaviour for "post a file as a form value".
/// * `--data-raw` — same as `-d` minus the `@file` magic. The leading
///   `@` is taken literally. This is what you reach for when posting
///   user-controlled strings that may legitimately start with `@`.
/// * `--data-binary` — `@file` allowed but **no** newline stripping. Use
///   this for actual binary payloads (or text whose newlines matter).
/// * `--data-urlencode` — five sub-forms, parsed in [`encode_urlencoded`]:
///   `content`, `=content`, `name=content`, `@file`, `name@file`.
///
/// Multiple data flags accumulate; the final body joins each part with
/// `&`. The Content-Type defaults to `application/x-www-form-urlencoded`
/// across the whole assembly.
#[derive(Debug, Clone)]
enum DataPart {
    /// `-d` / `--data` (`at_file_ok = true`, strips CR/LF/NUL when reading)
    /// or `--data-raw` (`at_file_ok = false`).
    Plain { value: String, at_file_ok: bool },
    /// `--data-binary`. `@file` reads the file as-is, no stripping.
    Binary { value: String },
    /// `--data-urlencode`. Parsed against the five curl sub-forms.
    UrlEncoded { value: String },
}

/// One curl-style `name=value;type=…;filename=…;headers=@…` form part.
///
/// Parsed once at CLI time by [`form_parser::parse`] (or constructed directly
/// for `--form-string`, which skips all magic) and consumed by
/// [`build_multipart_body`] when assembling the wire-level multipart body.
#[derive(Debug, Clone)]
struct FormPart {
    name: String,
    body: FormBody,
    extras: Vec<FormExtra>,
}

/// Where the bytes for a [`FormPart`] come from.
#[derive(Debug, Clone)]
enum FormBody {
    /// `-F name=value` — literal value inline. `@`/`<` magic was already
    /// resolved at parse time; this variant means "the value is the bytes".
    Literal(String),
    /// `-F name=@path` — file upload. `Content-Disposition` includes
    /// `filename="<basename>"` unless overridden by a `;filename=` modifier.
    File(String),
    /// `-F name=<path` — field part with the file's contents as the
    /// value. Unlike `File`, this does **not** add a `filename=` attribute,
    /// so the recipient sees it as a plain form field, not an upload.
    FileAsField(String),
    /// `--form-string name=value` — like `Literal`, except parsing of the
    /// `;modifier=` syntax is also disabled, so the value may contain
    /// arbitrary `@`, `<`, `;`, or `"`. Kept distinct from `Literal` mainly
    /// so the parse step can short-circuit; once we're building the body,
    /// it behaves exactly like `Literal` with no extras.
    LiteralStrict(String),
}

/// One `;`-separated modifier on a `-F` part.
#[derive(Debug, Clone)]
enum FormExtra {
    /// `;type=mime/type` — emitted as `Content-Type: <…>` on the part.
    Type(String),
    /// `;filename=other.ext` — overrides the basename from `@path`. For
    /// `Literal`-bodied parts, presence of this modifier promotes the part
    /// to a file-upload shape (Content-Disposition gains `filename=`).
    Filename(String),
    /// `;headers=@hdrfile` — read additional headers (one `Name: value`
    /// per line) from a file and emit them on the part. Curl-compatible.
    HeadersFile(String),
}

pub fn main() -> ExitCode {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    // Expand bundled short flags (-sS → -s -S) and attached values
    // (-ofile → -o file) so the rest of the pipeline sees one option per token.
    let raw = expand_short_bundles(&raw);
    // -K/--config: splice config-file options into the argument stream.
    let expanded = match expand_config(&raw, 0) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("rsurl: {e}");
            return ExitCode::from(2);
        }
    };
    // --next / -: separate independent operations, each with its own options.
    let segments = split_operations(&expanded);
    let mut ops: Vec<Args> = Vec::with_capacity(segments.len());
    for seg in &segments {
        match parse_args(seg) {
            Ok(a) => ops.push(a),
            Err(e) => {
                eprintln!("rsurl: {e}");
                eprintln!("try 'rsurl --help'");
                return ExitCode::from(2);
            }
        }
    }

    if ops.iter().all(|a| a.urls.is_empty()) {
        print_usage();
        return ExitCode::from(2);
    }

    warn_unsupported(&ops);

    // -Z/--parallel: run the transfers concurrently. We only parallelize when
    // no cookie engine is in play (a shared jar would need locking and -c
    // writes can't run from multiple threads); otherwise we fall through to the
    // sequential path.
    let uses_cookies = ops
        .iter()
        .any(|a| a.cookie_in.is_some() || a.cookie_jar.is_some());
    if ops.iter().any(|a| a.parallel) && !uses_cookies {
        return ExitCode::from(run_parallel(&ops));
    }

    // One cookie jar shared across all operations (curl carries it over
    // --next). Build it from the first operation that configures cookies.
    let jar_op = ops
        .iter()
        .find(|a| a.cookie_in.is_some() || a.cookie_jar.is_some())
        .unwrap_or(&ops[0]);
    let mut jar: Option<CookieJar> = match build_initial_jar(jar_op) {
        Ok(j) => j,
        Err(e) => {
            if show_errors(jar_op) {
                eprintln!("rsurl: {e}");
            }
            return ExitCode::from(2);
        }
    };

    // Run each operation's URLs; remember the last non-zero exit code.
    // URL globbing ({a,b} / [1-100]) expands one URL into many transfers,
    // unless -g/--globoff is set; `#N` in -o names picks the N-th glob value.
    let mut last_failure: u8 = 0;
    for job in jobs(&ops) {
        let code = match job {
            Job::Run { op, url, caps } => run_job(&op, &url, &caps, jar.as_mut()),
            Job::Fail(code) => code,
        };
        if code != 0 {
            last_failure = code;
        }
    }

    // Final jar save, to the first operation that asked for one.
    if let (Some(j), Some(op)) = (jar.as_ref(), ops.iter().find(|a| a.cookie_jar.is_some())) {
        let path = op.cookie_jar.as_deref().unwrap();
        if let Err(e) = j.save_netscape(path) {
            if show_errors(op) {
                eprintln!("rsurl: writing cookie jar {path}: {e}");
            }
            if last_failure == 0 {
                last_failure = 23;
            }
        }
    }
    ExitCode::from(last_failure)
}

/// Warn (once) about recognized flags that aren't yet enforced, so users
/// aren't misled into thinking a limit/cert is active. Silenced by `-s`
/// (without `-S`), like other diagnostics.
/// True when the HTTP body will be streamed straight to a file: a file output
/// (not a TTY, so no escape-guard needed), no header-inclusion, and no
/// status-gated body suppression. This is the path that enforces
/// `--limit-rate`, `-y/-Y`, `-#`, and an early `--max-filesize` abort.
fn streams_to_file(args: &Args) -> bool {
    let output_is_file = args.remote_name || args.output.as_deref().is_some_and(|p| p != "-");
    output_is_file
        && !args.include_headers
        && !args.fail
        && !args.fail_with_body
        && !args.remote_header_name // -J needs the response head for the name
        && !args.digest // Digest needs the buffered 401-retry path
        && args.dump_header.is_none()
}

fn warn_unsupported(ops: &[Args]) {
    if !ops.iter().any(show_errors) {
        return;
    }
    // --limit-rate, -#, and -y/-Y are enforced on the streaming file-download
    // path (-o FILE / -O); they are no-ops only when the body isn't streamed
    // (stdout, -i, -f, ...). Warn only for ops that won't take that path.
    if ops
        .iter()
        .any(|a| (a.speed_limit.is_some() || a.speed_time.is_some()) && !streams_to_file(a))
    {
        eprintln!(
            "rsurl: warning: -y/-Y speed limits are enforced only for file downloads \
             (-o FILE / -O)"
        );
    }
}

/// Split a `-E cert[:password]` value into the cert path and optional inline
/// passphrase, matching curl: the password starts after the first `:`, except
/// a `:` immediately following a single leading letter is treated as a Windows
/// drive-letter separator (`C:\path`) and not a delimiter. Returns
/// `(cert_path, password)`.
fn split_cert_pass(s: &str) -> (&str, Option<&str>) {
    let bytes = s.as_bytes();
    // Find the first ':' that isn't the drive-letter colon at index 1.
    let mut idx = None;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b':' {
            let is_drive = i == 1 && bytes[0].is_ascii_alphabetic();
            if !is_drive {
                idx = Some(i);
                break;
            }
        }
    }
    match idx {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    }
}

/// Parse a curl `--cert-type`/`--key-type` value. Returns `true` for `DER`,
/// `false` for `PEM` (the default). curl also accepts `ENG`/`P12`, which we do
/// not support (no engine, no PKCS#12) — reject them with a clear message
/// rather than silently treating them as PEM.
fn parse_cert_type(v: &str, flag: &str) -> Result<bool, String> {
    match v.to_ascii_uppercase().as_str() {
        "PEM" => Ok(false),
        "DER" => Ok(true),
        other => Err(format!(
            "{flag}: unsupported type {other:?}; only PEM and DER are supported"
        )),
    }
}

/// Suffix of the error [`next_val`] returns for an option missing its value.
const MISSING_VALUE: &str = " requires a value";

/// Whether option `opt` (`-x` or `--long`) consumes the next token as its
/// value. Answered by the parser itself — an option that takes a value fails
/// with [`MISSING_VALUE`] when given alone — so this can never drift from the
/// options `parse_args` actually knows. `-K`/`--config` are consumed earlier,
/// by [`expand_config`].
fn option_takes_value(opt: &str) -> bool {
    match opt {
        // These print and exit instead of returning; they take no value.
        "-h" | "--help" | "-V" | "--version" => false,
        "-K" | "--config" => true,
        _ => matches!(
            parse_args(&[opt.to_string()]),
            Err(e) if e.strip_prefix(opt) == Some(MISSING_VALUE)
        ),
    }
}

/// Expand bundled short options the way getopt/curl do: `-sSv` → `-s -S -v`,
/// `-ofile` → `-o file`, `-sSofile` → `-s -S -o file`. Only tokens in option
/// position are touched: the value of an option that takes one (`-d -x=1`,
/// `-H "-Foo: bar"`, `-w -%{http_code}`) passes through verbatim, as does
/// everything after `--`. Long options and bare `-` pass through unchanged.
fn expand_short_bundles(tokens: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = tokens.iter();
    while let Some(t) = it.next() {
        if t == "--" {
            out.push(t.clone());
            out.extend(it.cloned());
            break;
        }
        if t.starts_with("--") {
            out.push(t.clone());
            if option_takes_value(t) {
                out.extend(it.next().cloned());
            }
            continue;
        }
        if t.len() < 2 || !t.starts_with('-') {
            out.push(t.clone());
            continue;
        }
        let chars: Vec<char> = t[1..].chars().collect();
        let mut needs_value = false;
        for (i, c) in chars.iter().enumerate() {
            let opt = format!("-{c}");
            let takes = option_takes_value(&opt);
            out.push(opt);
            if takes {
                let rest: String = chars[i + 1..].iter().collect();
                if rest.is_empty() {
                    needs_value = true; // value is the next argv token
                } else {
                    out.push(rest); // attached value
                }
                break;
            }
        }
        if needs_value {
            out.extend(it.next().cloned());
        }
    }
    out
}

/// A URL glob is a sequence of literal runs and brace/bracket sets. Ranges are
/// kept symbolic (start/step/count) so a huge `[1-100000000000]` costs nothing
/// until iterated.
#[derive(Debug, Clone, PartialEq)]
enum GlobSeg {
    Lit(String),
    List(Vec<String>),
    Num {
        start: u64,
        step: u64,
        count: u64,
        width: usize,
    },
    Alpha {
        start: u32,
        step: u32,
        count: u64,
    },
}

impl GlobSeg {
    /// Number of alternatives (1 for a literal).
    fn len(&self) -> u64 {
        match self {
            GlobSeg::Lit(_) => 1,
            GlobSeg::List(v) => v.len() as u64,
            GlobSeg::Num { count, .. } | GlobSeg::Alpha { count, .. } => *count,
        }
    }

    /// The `i`-th alternative (`i < len()`).
    fn item(&self, i: u64) -> String {
        match self {
            GlobSeg::Lit(s) => s.clone(),
            GlobSeg::List(v) => v[i as usize].clone(),
            GlobSeg::Num {
                start, step, width, ..
            } => format!("{:0width$}", start + i * step, width = *width),
            GlobSeg::Alpha { start, step, .. } => {
                char::from_u32(start + i as u32 * step).map_or_else(String::new, String::from)
            }
        }
    }
}

/// Upper bound on the transfers one globbed URL may expand to. curl refuses
/// absurd globs too; this keeps a typo'd range from looping (near) forever.
const MAX_GLOB_URLS: u64 = 10_000_000;

/// Lazily yields every `(url, captures)` combination of a parsed glob, in
/// curl's order (rightmost set varies fastest).
struct GlobIter {
    segs: Vec<GlobSeg>,
    idx: Vec<u64>,
    done: bool,
}

impl Iterator for GlobIter {
    type Item = (String, Vec<String>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let mut url = String::new();
        let mut caps = Vec::new();
        for (seg, &i) in self.segs.iter().zip(&self.idx) {
            let v = seg.item(i);
            url.push_str(&v);
            if !matches!(seg, GlobSeg::Lit(_)) {
                caps.push(v);
            }
        }
        // Advance the odometer.
        self.done = true;
        for k in (0..self.segs.len()).rev() {
            self.idx[k] += 1;
            if self.idx[k] < self.segs[k].len() {
                self.done = false;
                break;
            }
            self.idx[k] = 0;
        }
        Some((url, caps))
    }
}

/// Whether a `[...]` body is an IPv6 literal (`[::1]`, `[fe80::1%25eth0]`)
/// rather than a range; curl leaves those alone so `http://[::1]:8080/` works
/// without `-g`.
fn is_ipv6_literal(body: &str) -> bool {
    let addr = body.split('%').next().unwrap_or(body);
    addr.contains(':') && addr.parse::<std::net::Ipv6Addr>().is_ok()
}

/// Parse curl-style URL globs: `{a,b,c}` alternation and `[1-100]` / `[a-z]`
/// ranges with an optional `:step`. `\{`/`\[` escape a literal. Returns the
/// segment list, or an error for a malformed glob.
fn parse_glob(url: &str) -> Result<Vec<GlobSeg>, String> {
    let mut segs = Vec::new();
    let mut lit = String::new();
    let chars: Vec<char> = url.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '\\' if i + 1 < chars.len() => {
                lit.push(chars[i + 1]);
                i += 2;
            }
            '{' => {
                let close = find_close(&chars, i, '{', '}')
                    .ok_or_else(|| format!("unmatched '{{' in URL glob: {url:?}"))?;
                let inner: String = chars[i + 1..close].iter().collect();
                let items: Vec<String> = inner.split(',').map(|s| s.to_string()).collect();
                if !lit.is_empty() {
                    segs.push(GlobSeg::Lit(std::mem::take(&mut lit)));
                }
                segs.push(GlobSeg::List(items));
                i = close + 1;
            }
            '[' => {
                let close = find_close(&chars, i, '[', ']')
                    .ok_or_else(|| format!("unmatched '[' in URL glob: {url:?}"))?;
                let inner: String = chars[i + 1..close].iter().collect();
                if is_ipv6_literal(&inner) {
                    lit.extend(&chars[i..=close]);
                    i = close + 1;
                    continue;
                }
                let seg = expand_range(&inner)
                    .ok_or_else(|| format!("bad range '[{inner}]' in URL glob"))?;
                if !lit.is_empty() {
                    segs.push(GlobSeg::Lit(std::mem::take(&mut lit)));
                }
                segs.push(seg);
                i = close + 1;
            }
            c => {
                lit.push(c);
                i += 1;
            }
        }
    }
    if !lit.is_empty() {
        segs.push(GlobSeg::Lit(lit));
    }
    Ok(segs)
}

fn find_close(chars: &[char], open_at: usize, open: char, close: char) -> Option<usize> {
    let mut depth = 0;
    for (k, &c) in chars.iter().enumerate().skip(open_at) {
        if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                return Some(k);
            }
        }
    }
    None
}

/// Parse a `[...]` range body: `1-100`, `001-100`, `a-z`, each with optional
/// `:step`. A reversed range (`[5-1]`, `[z-a]`) is malformed, as in curl.
fn expand_range(body: &str) -> Option<GlobSeg> {
    let (range, step) = match body.split_once(':') {
        Some((r, s)) => (r, s.parse::<u64>().ok().filter(|&s| s > 0)?),
        None => (body, 1),
    };
    let (start, end) = range.split_once('-')?;
    // Numeric range (with optional zero-padding to the start's width).
    if let (Ok(a), Ok(b)) = (start.parse::<u64>(), end.parse::<u64>()) {
        if a > b {
            return None;
        }
        let width = if start.starts_with('0') && start.len() > 1 {
            start.len()
        } else {
            0
        };
        return Some(GlobSeg::Num {
            start: a,
            step,
            count: (b - a) / step + 1,
            width,
        });
    }
    // Single-char alpha range.
    let (sc, ec) = (start.chars().next()?, end.chars().next()?);
    if start.chars().count() == 1 && end.chars().count() == 1 && sc <= ec {
        let step = u32::try_from(step).ok()?;
        return Some(GlobSeg::Alpha {
            start: sc as u32,
            step,
            count: u64::from((ec as u32 - sc as u32) / step + 1),
        });
    }
    None
}

/// Expand a URL's globs lazily into concrete `(url, captures)` pairs.
/// `captures[k]` is the chosen value of the k-th set, for `#N` output-name
/// substitution. Errors on a malformed glob or one expanding to more than
/// [`MAX_GLOB_URLS`] URLs.
fn glob_expand(url: &str) -> Result<GlobIter, String> {
    let segs = parse_glob(url)?;
    let total = segs
        .iter()
        .try_fold(1u64, |acc, s| acc.checked_mul(s.len()))
        .filter(|&n| n <= MAX_GLOB_URLS)
        .ok_or_else(|| format!("URL glob expands to too many URLs (max {MAX_GLOB_URLS})"))?;
    Ok(GlobIter {
        idx: vec![0; segs.len()],
        done: total == 0,
        segs,
    })
}

/// Whether URL globbing must be skipped for this operation's source. Globbing
/// (`{a,b}`/`[1-9]`, with `\` as the escape char) is a URL feature; a BitTorrent
/// source may instead be a local `.torrent` path — on Windows its backslashes
/// would be eaten as glob escapes — or a magnet link, neither of which is a URL
/// to expand. An `http(s)://` torrent URL still globs normally.
fn glob_disabled(op: &Args, url: &str) -> bool {
    // Any torrent-routing flag (matching process_url's dispatch) may take a
    // local `.torrent` path rather than a URL.
    let torrent_source =
        op.torrent || op.bt_info || op.bt_save_torrent || op.bt_file.is_some() || op.bt_concat;
    op.globoff
        || url.starts_with("magnet:")
        || (torrent_source && !url.starts_with("http://") && !url.starts_with("https://"))
}

/// Substitute `#1`..`#9` in an output-name template with glob captures.
fn apply_glob_output(template: &str, caps: &[String]) -> String {
    if caps.is_empty() || !template.contains('#') {
        return template.to_string();
    }
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '#' {
            if let Some(d) = chars.peek().and_then(|d| d.to_digit(10)) {
                chars.next();
                let idx = d as usize;
                if idx >= 1 && idx <= caps.len() {
                    out.push_str(&caps[idx - 1]);
                    continue;
                }
            }
        }
        out.push(c);
    }
    out
}

/// Run all operations' (glob-expanded) URLs concurrently (-Z/--parallel),
/// bounded by --parallel-max (default 50). No shared cookie jar (the caller
/// only routes here when cookies aren't in use). Returns the last non-zero
/// exit code, or 0.
fn run_parallel(ops: &[Args]) -> u8 {
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::sync::Mutex;

    let max = ops
        .iter()
        .filter_map(|a| a.parallel_max)
        .max()
        .unwrap_or(50)
        .max(1);
    // Jobs are pulled lazily from one shared queue so a large glob is never
    // materialised; each worker takes the next job when it is free.
    let queue = Mutex::new(jobs(ops).peekable());
    if queue.lock().map(|mut q| q.peek().is_none()).unwrap_or(true) {
        return 0;
    }
    let worst = AtomicU8::new(0);
    std::thread::scope(|s| {
        for _ in 0..max {
            // The lock guard is consumed inside `and_then`, so it is released
            // before the transfer runs.
            s.spawn(|| {
                while let Some(job) = queue.lock().ok().and_then(|mut q| q.next()) {
                    let code = match job {
                        Job::Run { op, url, caps } => run_job(&op, &url, &caps, None),
                        Job::Fail(code) => code,
                    };
                    if code != 0 {
                        worst.store(code, Ordering::Relaxed);
                    }
                }
            });
        }
    });
    worst.load(Ordering::Relaxed)
}

/// One unit of work from the command line: a concrete (glob-expanded) URL with
/// the option set that applies to it, or an error exit code for a URL that
/// could not be expanded (already reported).
enum Job {
    Run {
        op: Box<Args>,
        url: String,
        caps: Vec<String>,
    },
    Fail(u8),
}

/// Every transfer the operations ask for, lazily: each URL gets its own
/// positional `-o`/`-O` ([`Args::for_url`]) and is glob-expanded unless
/// globbing is off for it.
fn jobs(ops: &[Args]) -> Box<dyn Iterator<Item = Job> + Send + '_> {
    Box::new(ops.iter().flat_map(|op| {
        op.urls.iter().enumerate().flat_map(move |(i, url)| {
            let op = Box::new(op.for_url(i));
            let it: Box<dyn Iterator<Item = Job> + Send> = if glob_disabled(&op, url) {
                Box::new(std::iter::once(Job::Run {
                    op,
                    url: url.clone(),
                    caps: Vec::new(),
                }))
            } else {
                match glob_expand(url) {
                    Ok(g) => Box::new(g.map(move |(url, caps)| Job::Run {
                        op: op.clone(),
                        url,
                        caps,
                    })),
                    Err(e) => {
                        if show_errors(&op) {
                            eprintln!("rsurl: {e}");
                        }
                        Box::new(std::iter::once(Job::Fail(3)))
                    }
                }
            };
            it
        })
    }))
}

/// Run one job's transfer, substituting glob captures into a `#N` output name.
fn run_job(op: &Args, url: &str, caps: &[String], jar: Option<&mut CookieJar>) -> u8 {
    if !caps.is_empty() && op.output.as_ref().is_some_and(|o| o.contains('#')) {
        let mut op2 = op.clone();
        op2.output = op.output.as_ref().map(|o| apply_glob_output(o, caps));
        process_url(url, &op2, jar)
    } else {
        process_url(url, op, jar)
    }
}

/// Split a token stream into independent operations at `--next` / `-:`.
fn split_operations(toks: &[String]) -> Vec<Vec<String>> {
    let mut segs: Vec<Vec<String>> = vec![Vec::new()];
    let mut it = toks.iter();
    while let Some(t) = it.next() {
        if t == "--next" || t == "-:" {
            segs.push(Vec::new());
        } else if t == "--" {
            // End of options: the rest are URLs of the current operation.
            let seg = segs.last_mut().unwrap();
            seg.push(t.clone());
            seg.extend(it.by_ref().cloned());
        } else {
            segs.last_mut().unwrap().push(t.clone());
        }
    }
    segs
}

/// Recursively expand `-K`/`--config <file>` into the token stream. Each config
/// line is `option [= | : | space] value` (curl format); `#` starts a comment,
/// option names need no leading dashes.
fn expand_config(toks: &[String], depth: u32) -> Result<Vec<String>, String> {
    if depth > 16 {
        return Err("config files nested too deeply".into());
    }
    let mut out = Vec::new();
    let mut it = toks.iter();
    while let Some(t) = it.next() {
        if t == "--" {
            out.push(t.clone());
            out.extend(it.by_ref().cloned());
        } else if t == "-K" || t == "--config" {
            let path = it
                .next()
                .ok_or_else(|| "--config requires a file".to_string())?;
            // `-K -` reads the config from stdin, like curl.
            let bytes = read_local(path).map_err(|e| format!("config file {path}: {e}"))?;
            let text = String::from_utf8_lossy(&bytes);
            let inner = expand_config(&expand_short_bundles(&parse_config_text(&text)), depth + 1)?;
            out.extend(inner);
        } else {
            out.push(t.clone());
        }
    }
    Ok(out)
}

/// Tokenize a curl-style config file into CLI arguments.
fn parse_config_text(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (opt, val) = match line.find(|c: char| c.is_whitespace() || c == '=' || c == ':') {
            Some(i) => {
                let rest = line[i..]
                    .trim_start()
                    .strip_prefix(['=', ':'])
                    .unwrap_or_else(|| line[i..].trim_start())
                    .trim_start();
                (&line[..i], Some(rest))
            }
            None => (line, None),
        };
        let opt_norm = if opt.starts_with('-') {
            opt.to_string()
        } else if opt.chars().count() == 1 {
            format!("-{opt}")
        } else {
            format!("--{opt}")
        };
        out.push(opt_norm);
        if let Some(v) = val.filter(|v| !v.is_empty()) {
            let v = v
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .unwrap_or(v);
            out.push(v.to_string());
        }
    }
    out
}

/// Build the initial jar from `-b`/`-c`.
///
/// * Neither flag → `None`.
/// * `-b k=v[; k=v]...` (contains `=`) → empty jar; the explicit cookies
///   are applied per-URL in [`process_url`] so each one gets the right host.
/// * `-b <file>` (no `=`) → load Netscape file. Missing file is silently
///   accepted (matches curl: a fresh jar that will be written by `-c`).
/// * `-c <file>` alone → empty jar; cookies received during the run are
///   saved at the end.
fn build_initial_jar(args: &Args) -> Result<Option<CookieJar>, String> {
    if args.cookie_in.is_none() && args.cookie_jar.is_none() {
        return Ok(None);
    }
    let mut jar = match args.cookie_in.as_deref() {
        Some(s) if !s.contains('=') => CookieJar::load_netscape_or_empty(s)
            .map_err(|e| format!("reading cookie file {s}: {e}"))?,
        _ => CookieJar::new(),
    };
    // If only `-c` was given (no `-b`), and the destination already exists,
    // curl pre-populates the jar from it so cookies aren't dropped. We
    // mirror that by reading the file when it's there — missing is fine.
    if args.cookie_in.is_none() {
        if let Some(path) = args.cookie_jar.as_deref() {
            jar = CookieJar::load_netscape_or_empty(path)
                .map_err(|e| format!("reading cookie file {path}: {e}"))?;
        }
    }
    if args.junk_session_cookies {
        drop_session_cookies(&mut jar);
    }
    Ok(Some(jar))
}

/// `-j`: forget every session cookie (one with no expiry) loaded from disk.
fn drop_session_cookies(jar: &mut CookieJar) {
    let session: Vec<(String, String, String)> = jar
        .iter()
        .filter(|c| c.expires.is_none())
        .map(|c| (c.name.clone(), c.domain.clone(), c.path.clone()))
        .collect();
    for (name, domain, path) in session {
        jar.remove(&name, &domain, &path);
    }
}

/// Decide which proxy URL applies to this request. Precedence (highest
/// first), matching curl:
///   1. `-x`/`--proxy` on the command line; an empty string explicitly
///      means "no proxy", even if env vars are set.
///   2. `HTTPS_PROXY` (case-insensitive) when the target is `https://`.
///   3. `HTTP_PROXY` (case-insensitive) when the target is `http://` —
///      but **only the lowercase** `http_proxy` env var to match curl's
///      CGI-confusion mitigation (uppercase `HTTP_PROXY` can be set by
///      remote clients via the `Proxy:` header).
///   4. `ALL_PROXY` / `all_proxy` as a catch-all.
///
/// Returns `None` if no proxy applies.
fn resolve_proxy_spec(url: &Url, args: &Args) -> Option<String> {
    if let Some(spec) = &args.proxy {
        if spec.is_empty() {
            return None;
        }
        return Some(spec.clone());
    }
    // Helper that reads an env var, trying the uppercase form, then the
    // lowercase form. Empty values count as unset.
    let read = |upper: &str, lower: &str| -> Option<String> {
        for k in [upper, lower] {
            if let Ok(v) = std::env::var(k) {
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
        None
    };
    let scheme_proxy = match url.scheme.as_str() {
        "https" => read("HTTPS_PROXY", "https_proxy"),
        // Avoid uppercase HTTP_PROXY (curl historical caveat — see doc above)
        "http" => match std::env::var("http_proxy") {
            Ok(v) if !v.is_empty() => Some(v),
            _ => None,
        },
        _ => None,
    };
    scheme_proxy.or_else(|| read("ALL_PROXY", "all_proxy"))
}

/// Resolve the no-proxy list: explicit `--noproxy` wins; otherwise we
/// look at `NO_PROXY` / `no_proxy`. Empty string means "no bypass set".
fn resolve_noproxy(args: &Args) -> Option<String> {
    if let Some(v) = &args.noproxy {
        return Some(v.clone());
    }
    for k in ["NO_PROXY", "no_proxy"] {
        if let Ok(v) = std::env::var(k) {
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

/// Apply explicit `-b "k=v; k2=v2"` cookies to the jar for `request_url`'s
/// host. Curl's behaviour is that command-line cookies are session-only and
/// apply on the requests issued by that invocation; we keep that by routing
/// through [`CookieJar::add_explicit`].
fn apply_explicit_cookies(jar: &mut CookieJar, data: &str, request_url: &Url) {
    for pair in data.split(';') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        if let Some((k, v)) = pair.split_once('=') {
            let k = k.trim();
            let v = v.trim();
            if !k.is_empty() {
                jar.add_explicit(k, v, request_url);
            }
        }
    }
}

/// Read a local input file named on the command line; `-` means stdin, as in
/// curl (`-d @-`, `--data-binary @-`, `-T -`, `-F f=@-`, `-K -`). Stdin can
/// only be consumed once, so its contents are cached for every later `-` use.
fn read_local(path: &str) -> io::Result<Vec<u8>> {
    static STDIN: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    if path == "-" {
        let data = STDIN.get_or_init(|| {
            let mut buf = Vec::new();
            let _ = io::stdin().lock().read_to_end(&mut buf);
            buf
        });
        return Ok(data.clone());
    }
    std::fs::read(path)
}

/// Read the file at `path`, returning its bytes. Used by `-d @file`,
/// `--data-binary @file`, and `--data-urlencode @file`.
fn read_at_file(path: &str) -> Result<Vec<u8>, String> {
    read_local(path).map_err(|e| format!("can't read {path:?}: {e}"))
}

/// Strip every CR (`\r`), LF (`\n`), and NUL (`\0`) byte from `data`.
/// Matches curl's `-d @file` newline-stripping behaviour, which exists so
/// that copying a multi-line config value into a form field doesn't
/// accidentally embed line breaks.
fn strip_newlines(data: Vec<u8>) -> Vec<u8> {
    data.into_iter()
        .filter(|&b| b != b'\r' && b != b'\n' && b != 0)
        .collect()
}

/// Percent-encode `bytes` per `application/x-www-form-urlencoded`: unreserved
/// chars (alnum, `-`, `.`, `_`, `~`) pass through, space becomes `+`, and
/// everything else becomes `%HH` with uppercase hex. Matches curl's
/// `--data-urlencode` encoder.
fn percent_encode_form(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push('+'),
            _ => write!(out, "%{b:02X}").expect("write to String"),
        }
    }
    out
}

/// Resolve one `--data-urlencode` argument against curl's five sub-forms
/// and return the bytes to splice into the body (without any join glue).
///
/// | Input            | Output                                                |
/// |------------------|-------------------------------------------------------|
/// | `content`        | `percent(content)`                                    |
/// | `=content`       | `percent(content)` (leading `=` strips into empty name) |
/// | `name=content`   | `name=percent(content)` (name kept verbatim)          |
/// | `@file`          | `percent(read(file))`                                 |
/// | `name@file`      | `name=percent(read(file))`                            |
///
/// Note that for the `name=` and `name@` forms, the name itself is **not**
/// encoded — this matches curl. Callers who need an encoded name must
/// either pre-encode it or use `=content` and append `name=` manually.
fn encode_urlencoded(spec: &str) -> Result<Vec<u8>, String> {
    // Split into (name_prefix, body_bytes). Look for the first `=` or `@`
    // that determines the form. `=` takes precedence over `@`.
    if let Some(eq) = spec.find('=') {
        let (name, rest) = spec.split_at(eq);
        let value = &rest[1..]; // drop the '='
        let encoded = percent_encode_form(value.as_bytes());
        if name.is_empty() {
            return Ok(encoded.into_bytes());
        }
        return Ok(format!("{name}={encoded}").into_bytes());
    }
    if let Some(at) = spec.find('@') {
        let (name, rest) = spec.split_at(at);
        let path = &rest[1..]; // drop the '@'
        let bytes = read_at_file(path)?;
        let encoded = percent_encode_form(&bytes);
        if name.is_empty() {
            return Ok(encoded.into_bytes());
        }
        return Ok(format!("{name}={encoded}").into_bytes());
    }
    Ok(percent_encode_form(spec.as_bytes()).into_bytes())
}

/// curl-style `-F name=value[;mod=…]` parser.
///
/// Quoting rules (matching curl): the *value* (the part after the first `=`)
/// may be wrapped in `"…"` to embed a literal `;` or `"`; inside the quotes,
/// `\"` is a literal `"` and `\\` is a literal `\`. Modifier values follow
/// the same rules. Top-level `;` outside quotes separates the value from
/// modifiers. The name itself is **not** quoted (curl rejects quoted names).
mod form_parser {
    use super::{FormBody, FormExtra, FormPart};

    /// Parse one `-F`/`--form` argument into a [`FormPart`].
    pub(super) fn parse(spec: &str) -> Result<FormPart, String> {
        let eq = spec.find('=').ok_or_else(|| {
            format!("-F: expected 'name=value', got {spec:?} (use --form-string for literal '=')")
        })?;
        let name = spec[..eq].to_string();
        if name.is_empty() {
            return Err(format!("-F: empty field name: {spec:?}"));
        }
        let rest = &spec[eq + 1..];
        let mut tokens = split_semi(rest);
        // First token is always the value; remaining tokens are modifiers.
        let raw_value = tokens.remove(0);
        let body = classify_body(&raw_value);
        let mut extras = Vec::new();
        for tok in tokens {
            extras.push(classify_extra(&tok)?);
        }
        Ok(FormPart { name, body, extras })
    }

    /// `@file` → [`FormBody::File`]; `<file` → [`FormBody::FileAsField`];
    /// anything else → [`FormBody::Literal`]. The `@`/`<` discriminator is
    /// checked on the *unquoted* string, so `"@notafile"` is taken literally.
    fn classify_body(token: &str) -> FormBody {
        // Quoting was already resolved by split_semi; if the original token
        // was a quoted literal, the `@`/`<` is now plain text — which is
        // what we want. The discriminator only applies to bare strings.
        // We approximate this by remembering whether the leading char was
        // already inside quotes via the convention: split_semi returns the
        // unquoted bytes, but it cannot signal "was-quoted". To preserve
        // curl behaviour, classify only on the bare token; users who want
        // a literal `@` value should use `--form-string`.
        if let Some(p) = token.strip_prefix('@') {
            FormBody::File(p.to_string())
        } else if let Some(p) = token.strip_prefix('<') {
            FormBody::FileAsField(p.to_string())
        } else {
            FormBody::Literal(token.to_string())
        }
    }

    fn classify_extra(token: &str) -> Result<FormExtra, String> {
        let (k, v) = token
            .split_once('=')
            .ok_or_else(|| format!("-F: malformed modifier {token:?} (expected key=value)"))?;
        let k = k.trim();
        let v = v.to_string();
        match k.to_ascii_lowercase().as_str() {
            "type" => Ok(FormExtra::Type(v)),
            "filename" => Ok(FormExtra::Filename(v)),
            "headers" => {
                let path = v
                    .strip_prefix('@')
                    .ok_or_else(|| format!("-F: ;headers= must be @file (got {token:?})"))?;
                Ok(FormExtra::HeadersFile(path.to_string()))
            }
            _ => Err(format!("-F: unknown modifier {k:?}")),
        }
    }

    /// Split `s` on top-level `;`, with `"…"` segments protected from the
    /// split. Inside quotes, `\"` is `"` and `\\` is `\` (every other
    /// backslash is kept literal). Outer quotes are stripped on return.
    fn split_semi(s: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur = String::new();
        let mut chars = s.chars().peekable();
        let mut in_quote = false;
        while let Some(c) = chars.next() {
            if in_quote {
                match c {
                    '"' => in_quote = false,
                    '\\' => match chars.peek() {
                        Some('"') => {
                            cur.push('"');
                            chars.next();
                        }
                        Some('\\') => {
                            cur.push('\\');
                            chars.next();
                        }
                        _ => cur.push('\\'),
                    },
                    _ => cur.push(c),
                }
            } else {
                match c {
                    '"' => in_quote = true,
                    ';' => out.push(std::mem::take(&mut cur)),
                    _ => cur.push(c),
                }
            }
        }
        out.push(cur);
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn simple_literal() {
            let p = parse("foo=bar").unwrap();
            assert_eq!(p.name, "foo");
            assert!(matches!(&p.body, FormBody::Literal(v) if v == "bar"));
            assert!(p.extras.is_empty());
        }

        #[test]
        fn at_file_is_file_upload() {
            let p = parse("upload=@/tmp/x.bin").unwrap();
            assert!(matches!(&p.body, FormBody::File(v) if v == "/tmp/x.bin"));
        }

        #[test]
        fn lt_file_is_field_from_file() {
            let p = parse("note=</tmp/x.txt").unwrap();
            assert!(matches!(&p.body, FormBody::FileAsField(v) if v == "/tmp/x.txt"));
        }

        #[test]
        fn quoted_value_with_semicolon() {
            let p = parse(r#"k="a;b;c""#).unwrap();
            assert!(matches!(&p.body, FormBody::Literal(v) if v == "a;b;c"));
        }

        #[test]
        fn quoted_value_with_escapes() {
            let p = parse(r#"k="he said \"hi\" \\""#).unwrap();
            assert!(matches!(&p.body, FormBody::Literal(v) if v == r#"he said "hi" \"#));
        }

        #[test]
        fn modifiers_type_filename_headers() {
            let p = parse("f=@x;type=application/json;filename=other.json;headers=@hdrs").unwrap();
            assert!(matches!(&p.body, FormBody::File(p) if p == "x"));
            assert_eq!(p.extras.len(), 3);
            assert!(matches!(&p.extras[0], FormExtra::Type(v) if v == "application/json"));
            assert!(matches!(&p.extras[1], FormExtra::Filename(v) if v == "other.json"));
            assert!(matches!(&p.extras[2], FormExtra::HeadersFile(v) if v == "hdrs"));
        }

        #[test]
        fn empty_name_rejected() {
            assert!(parse("=value").is_err());
        }

        #[test]
        fn missing_eq_rejected() {
            assert!(parse("foo").is_err());
        }

        #[test]
        fn unknown_modifier_rejected() {
            assert!(parse("foo=bar;weird=baz").is_err());
        }

        #[test]
        fn headers_missing_at_rejected() {
            assert!(parse("foo=bar;headers=hdrs").is_err());
        }
    }
}

/// Inline multipart/form-data encoder for `-F` parts. Curl-compatible wire
/// format; the only deviation worth flagging is that we generate the
/// boundary ourselves (no caller override yet), prefixed with
/// `----rsurl-boundary-` so verbose traces are easy to grep.
mod multipart {
    use super::{FormBody, FormExtra, FormPart};

    /// Build the body and return `(boundary, bytes)`. The boundary string
    /// is what goes into `Content-Type: multipart/form-data; boundary=<…>`.
    pub(super) fn build(parts: &[FormPart], escape: bool) -> Result<(String, Vec<u8>), String> {
        let boundary = make_boundary();
        let mut out = Vec::new();
        for part in parts {
            out.extend_from_slice(b"--");
            out.extend_from_slice(boundary.as_bytes());
            out.extend_from_slice(b"\r\n");
            write_part(part, escape, &mut out)?;
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"--");
        out.extend_from_slice(boundary.as_bytes());
        out.extend_from_slice(b"--\r\n");
        Ok((boundary, out))
    }

    fn write_part(part: &FormPart, escape: bool, out: &mut Vec<u8>) -> Result<(), String> {
        // Decide what filename (if any) goes on Content-Disposition, and
        // what bytes form the body. `<file` parts get no filename even
        // though they read from a file — that's how curl distinguishes a
        // form *field* from a form *upload*.
        let (bytes, default_filename, is_upload): (Vec<u8>, Option<String>, bool) = match &part.body
        {
            FormBody::Literal(s) | FormBody::LiteralStrict(s) => {
                (s.as_bytes().to_vec(), None, false)
            }
            FormBody::File(path) => {
                let bytes =
                    super::read_local(path).map_err(|e| format!("-F: can't read {path:?}: {e}"))?;
                let name = std::path::Path::new(path)
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.clone());
                (bytes, Some(name), true)
            }
            FormBody::FileAsField(path) => {
                let bytes =
                    super::read_local(path).map_err(|e| format!("-F: can't read {path:?}: {e}"))?;
                (bytes, None, false)
            }
        };

        // Modifier overrides.
        let mut ctype: Option<&str> = None;
        let mut filename: Option<String> = default_filename;
        let mut extra_headers: Vec<u8> = Vec::new();
        let mut promote_to_upload = is_upload;
        for ex in &part.extras {
            match ex {
                FormExtra::Type(t) => ctype = Some(t),
                FormExtra::Filename(f) => {
                    filename = Some(f.clone());
                    // Setting filename on a literal-bodied part is how curl
                    // promotes "this is text" to "this is a named upload".
                    promote_to_upload = true;
                }
                FormExtra::HeadersFile(path) => {
                    let raw = std::fs::read(path)
                        .map_err(|e| format!("-F: can't read headers file {path:?}: {e}"))?;
                    // Trim outer whitespace per line, ignore blank lines,
                    // keep curl's permissive behaviour (no header parsing).
                    for line in raw.split(|b| *b == b'\n') {
                        let mut l = line;
                        if l.last() == Some(&b'\r') {
                            l = &l[..l.len() - 1];
                        }
                        if l.is_empty() {
                            continue;
                        }
                        extra_headers.extend_from_slice(l);
                        extra_headers.extend_from_slice(b"\r\n");
                    }
                }
            }
        }

        // Content-Disposition header.
        out.extend_from_slice(b"Content-Disposition: form-data; name=\"");
        out.extend_from_slice(encode_attr(&part.name, escape).as_bytes());
        out.extend_from_slice(b"\"");
        if promote_to_upload || filename.is_some() {
            if let Some(fname) = filename.as_deref() {
                out.extend_from_slice(b"; filename=\"");
                out.extend_from_slice(encode_attr(fname, escape).as_bytes());
                out.extend_from_slice(b"\"");
            }
        }
        out.extend_from_slice(b"\r\n");

        // Content-Type: explicit > default-for-upload > none.
        if let Some(t) = ctype {
            out.extend_from_slice(b"Content-Type: ");
            out.extend_from_slice(t.as_bytes());
            out.extend_from_slice(b"\r\n");
        } else if promote_to_upload {
            // Curl's default for a file part with no ;type=.
            out.extend_from_slice(b"Content-Type: application/octet-stream\r\n");
        }

        // Extra headers from ;headers=@file.
        out.extend_from_slice(&extra_headers);

        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&bytes);
        Ok(())
    }

    /// Encode `s` for use inside a `Content-Disposition` attribute value.
    /// With `escape == true` we percent-encode the RFC 7578 §4.2 reserved
    /// bytes; without it (curl-historical default) we backslash-escape `"`
    /// and `\` and pass through CR/LF (which is wrong on the wire but
    /// curl-compatible).
    fn encode_attr(s: &str, escape: bool) -> String {
        if escape {
            let mut out = String::with_capacity(s.len());
            for b in s.bytes() {
                match b {
                    b'\r' => out.push_str("%0D"),
                    b'\n' => out.push_str("%0A"),
                    b'"' => out.push_str("%22"),
                    b'\\' => out.push_str("%5C"),
                    _ => out.push(b as char),
                }
            }
            out
        } else {
            let mut out = String::with_capacity(s.len());
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    _ => out.push(c),
                }
            }
            out
        }
    }

    /// 8 bytes of randomness → 16 hex chars, prefixed for greppability.
    /// Falls back to a time-based mix if `/dev/urandom` is unreachable so
    /// the CLI still works on stripped-down container images.
    fn make_boundary() -> String {
        let mut buf = [0u8; 8];
        let ok = std::fs::File::open("/dev/urandom")
            .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut buf))
            .is_ok();
        if !ok {
            use std::time::{SystemTime, UNIX_EPOCH};
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            for (i, b) in buf.iter_mut().enumerate() {
                *b = ((nanos >> (i * 8)) & 0xFF) as u8;
            }
        }
        let mut hex = String::with_capacity(16 + 19);
        hex.push_str("----rsurl-boundary-");
        for b in buf {
            use std::fmt::Write;
            write!(hex, "{b:02x}").expect("write to String");
        }
        hex
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn literal_part_round_trip() {
            let parts = vec![FormPart {
                name: "k".into(),
                body: FormBody::Literal("v".into()),
                extras: vec![],
            }];
            let (b, bytes) = build(&parts, false).unwrap();
            let text = String::from_utf8(bytes).unwrap();
            assert!(text.contains(&format!("--{b}\r\n")));
            assert!(text.contains("Content-Disposition: form-data; name=\"k\"\r\n"));
            assert!(!text.contains("filename="));
            assert!(text.contains("\r\n\r\nv\r\n"));
            assert!(text.ends_with(&format!("--{b}--\r\n")));
        }

        #[test]
        fn file_part_gets_filename_and_octet_stream() {
            let mut tmp = std::env::temp_dir();
            tmp.push(format!("rsurl-mp-{}.bin", std::process::id()));
            std::fs::write(&tmp, b"FILEBYTES").unwrap();
            let path = tmp.to_string_lossy().into_owned();
            let basename = tmp.file_name().unwrap().to_string_lossy().into_owned();
            let parts = vec![FormPart {
                name: "u".into(),
                body: FormBody::File(path),
                extras: vec![],
            }];
            let (_, bytes) = build(&parts, false).unwrap();
            let _ = std::fs::remove_file(&tmp);
            let text = String::from_utf8(bytes).unwrap();
            assert!(text.contains(&format!(
                "Content-Disposition: form-data; name=\"u\"; filename=\"{basename}\"\r\n"
            )));
            assert!(text.contains("Content-Type: application/octet-stream\r\n"));
            assert!(text.contains("\r\n\r\nFILEBYTES\r\n"));
        }

        #[test]
        fn type_filename_extras_take_effect() {
            let parts = vec![FormPart {
                name: "x".into(),
                body: FormBody::Literal("body".into()),
                extras: vec![
                    FormExtra::Type("application/json".into()),
                    FormExtra::Filename("over.json".into()),
                ],
            }];
            let (_, bytes) = build(&parts, false).unwrap();
            let text = String::from_utf8(bytes).unwrap();
            assert!(text.contains("name=\"x\"; filename=\"over.json\"\r\n"));
            assert!(text.contains("Content-Type: application/json\r\n"));
        }

        #[test]
        fn form_escape_uses_percent_encoding() {
            let parts = vec![FormPart {
                name: "weird\"name".into(),
                body: FormBody::Literal("v".into()),
                extras: vec![],
            }];
            let (_, bytes) = build(&parts, true).unwrap();
            let text = String::from_utf8(bytes).unwrap();
            assert!(text.contains("name=\"weird%22name\""), "got: {text}");
        }

        #[test]
        fn default_backslash_escape_preserves_curl_behaviour() {
            let parts = vec![FormPart {
                name: "weird\"name".into(),
                body: FormBody::Literal("v".into()),
                extras: vec![],
            }];
            let (_, bytes) = build(&parts, false).unwrap();
            let text = String::from_utf8(bytes).unwrap();
            assert!(text.contains(r#"name="weird\"name""#), "got: {text}");
        }
    }
}

/// `(body_bytes, content_type, default_method)` — what the body-assembly
/// functions return so the caller can both set the body and pick a method.
type AssembledBody = (Vec<u8>, String, &'static str);

/// Build the upload body for `-T`/`--upload-file`. Reads the file fully into
/// memory (matches the HTTP layer's `Vec<u8>`-based body API) and returns
/// it with the curl-default `application/octet-stream` Content-Type and
/// `PUT` method.
fn build_upload_body(path: &str) -> Result<AssembledBody, String> {
    let bytes = read_local(path).map_err(|e| format!("-T: can't read {path:?}: {e}"))?;
    Ok((bytes, "application/octet-stream".into(), "PUT"))
}

/// Build the multipart body for `-F`/`--form` parts. Returns
/// `(bytes, content_type, method)` where `content_type` carries the
/// generated boundary string.
fn build_multipart_body(parts: &[FormPart], escape: bool) -> Result<AssembledBody, String> {
    let (boundary, bytes) = multipart::build(parts, escape)?;
    let ctype = format!("multipart/form-data; boundary={boundary}");
    Ok((bytes, ctype, "POST"))
}

/// Top-level body chooser. At most one of `{upload_file, form_parts,
/// data_parts}` may be non-empty; the curl-canonical exit-code-2 message is
/// returned otherwise. The returned `default_method` is what the request
/// uses if the user didn't pass `-X` or `-I`.
fn assemble_request_body(args: &Args) -> Result<Option<AssembledBody>, String> {
    let n = (!args.data_parts.is_empty()) as u8
        + (!args.form_parts.is_empty()) as u8
        + args.upload_file.is_some() as u8
        + (!args.json_parts.is_empty()) as u8;
    if n > 1 {
        return Err(
            "-d/--data, -F/--form, -T/--upload-file, and --json are mutually exclusive".into(),
        );
    }
    if let Some(path) = &args.upload_file {
        return build_upload_body(path).map(Some);
    }
    // --json: verbatim concatenation of every part (each may be @file), sent as
    // application/json. The matching Accept header is added by the caller.
    if !args.json_parts.is_empty() {
        let mut out: Vec<u8> = Vec::new();
        for v in &args.json_parts {
            if let Some(path) = v.strip_prefix('@') {
                out.extend_from_slice(&read_at_file(path)?);
            } else {
                out.extend_from_slice(v.as_bytes());
            }
        }
        return Ok(Some((out, "application/json".into(), "POST")));
    }
    if !args.form_parts.is_empty() {
        return build_multipart_body(&args.form_parts, args.form_escape).map(Some);
    }
    if let Some(bytes) = assemble_form_body(&args.data_parts)? {
        return Ok(Some((
            bytes,
            "application/x-www-form-urlencoded".into(),
            "POST",
        )));
    }
    Ok(None)
}

/// Resolve every `DataPart` into bytes and join with `&`. Returns
/// `Ok(None)` if no data flags were given; `Ok(Some(bytes))` otherwise.
/// File-read errors become a printable string for the caller.
fn assemble_form_body(parts: &[DataPart]) -> Result<Option<Vec<u8>>, String> {
    if parts.is_empty() {
        return Ok(None);
    }
    let mut out: Vec<u8> = Vec::new();
    for part in parts {
        if !out.is_empty() {
            out.push(b'&');
        }
        match part {
            DataPart::Plain { value, at_file_ok } => {
                if *at_file_ok {
                    if let Some(path) = value.strip_prefix('@') {
                        out.extend_from_slice(&strip_newlines(read_at_file(path)?));
                        continue;
                    }
                }
                out.extend_from_slice(value.as_bytes());
            }
            DataPart::Binary { value } => {
                if let Some(path) = value.strip_prefix('@') {
                    out.extend_from_slice(&read_at_file(path)?);
                } else {
                    out.extend_from_slice(value.as_bytes());
                }
            }
            DataPart::UrlEncoded { value } => {
                out.extend_from_slice(&encode_urlencoded(value)?);
            }
        }
    }
    Ok(Some(out))
}

fn process_url(url: &str, args: &Args, mut jar: Option<&mut CookieJar>) -> u8 {
    // BitTorrent: a magnet link, `--torrent`, or any torrent-specific flag.
    // Routed before URL parsing because the source may be a local `.torrent`
    // path (not a URL) and magnet links have no `://` authority.
    if args.torrent
        || url.starts_with("magnet:")
        || args.bt_info
        || args.bt_save_torrent
        || args.bt_file.is_some()
        || args.bt_concat
    {
        #[cfg(feature = "bittorrent")]
        {
            return run_bittorrent(url, args);
        }
        #[cfg(not(feature = "bittorrent"))]
        {
            if show_errors(args) {
                eprintln!("rsurl: this build has no BitTorrent support");
            }
            return 2;
        }
    }

    // A URL given without a scheme defaults to --proto-default (or http),
    // matching curl's "curl example.com" behaviour.
    let scheme_defaulted;
    let url: &str = if url.contains("://") {
        url
    } else {
        let scheme = args.proto_default.as_deref().unwrap_or("http");
        scheme_defaulted = format!("{scheme}://{url}");
        &scheme_defaulted
    };
    // --url-query: append each part to the query string.
    let url_with_query;
    let url: &str = if args.url_queries.is_empty() {
        url
    } else {
        match append_url_queries(url, &args.url_queries) {
            Ok(u) => {
                url_with_query = u;
                &url_with_query
            }
            Err(e) => {
                if show_errors(args) {
                    eprintln!("rsurl: --url-query: {e}");
                }
                return 26; // CURLE_READ_ERROR (an unreadable @file)
            }
        }
    };
    let mut parsed_url = match Url::parse(url) {
        Ok(u) => u,
        Err(e) => {
            if show_errors(args) {
                eprintln!("rsurl: {e}");
            }
            return 3;
        }
    };
    // Normalise the host to ASCII/punycode (IDN) unless `--no-idn`. Done once
    // here so non-HTTP dispatch, proxy-bypass matching, and `-O` output naming
    // all see the same host the connection will use. (The HTTP path re-parses
    // the URL string in `Request::new`, so it also gets `req.idn(...)` below.)
    if let Err(e) = parsed_url.set_idn(!args.no_idn) {
        if show_errors(args) {
            eprintln!("rsurl: {e}");
        }
        return 3;
    }
    // --proto: restrict which schemes the initial URL may use.
    if let Some(spec) = &args.proto {
        if !proto_allowed(&parsed_url.scheme, spec) {
            if show_errors(args) {
                eprintln!(
                    "rsurl: protocol \"{}\" not permitted by --proto",
                    parsed_url.scheme
                );
            }
            return 1;
        }
    }

    // Non-HTTP schemes go through the generic transfer dispatcher; HTTP-only
    // options (-X, -H, -d, ...) are ignored for them in this milestone.
    if !matches!(parsed_url.scheme.as_str(), "http" | "https") {
        // `-u user:pass` applies to the login-based protocols too (curl), and
        // overrides any URL userinfo. Their backends read (and percent-decode)
        // the URL userinfo, so re-encode the credentials into it.
        apply_cli_credentials(&mut parsed_url, args);
        // WebSocket: persistent, interactive-ish client (curl never built its
        // CLI side). Send `-d`/piped-stdin messages, print received ones.
        if matches!(parsed_url.scheme.as_str(), "ws" | "wss") {
            return run_websocket(&parsed_url, args);
        }
        // RTSP honours `-X`/`--request` to select the control method
        // (OPTIONS/DESCRIBE/SETUP/PLAY/TEARDOWN); default is DESCRIBE.
        if parsed_url.scheme == "rtsp" {
            return run_rtsp(&parsed_url, args);
        }
        if matches!(parsed_url.scheme.as_str(), "smtp" | "smtps") {
            return run_smtp(&parsed_url, args);
        }
        if parsed_url.scheme == "telnet" {
            return run_telnet(&parsed_url, args);
        }
        // MQTT: a request body (`-d`/`--data*` or `-T`) switches from the
        // default subscribe (`run_transfer`) to publish, matching curl. With
        // no body we fall through to the subscribe transfer below.
        if matches!(parsed_url.scheme.as_str(), "mqtt" | "mqtts")
            && (!args.data_parts.is_empty() || args.upload_file.is_some())
        {
            return run_mqtt_publish(&parsed_url, args);
        }
        if let Some(path) = &args.upload_file {
            // FTP/FTPS upload: -T <file> ftp://host/remote → STOR (with REST
            // resume when -C <offset> is given). Other non-HTTP schemes don't
            // support upload yet.
            if matches!(parsed_url.scheme.as_str(), "ftp" | "ftps") {
                return run_ftp_upload(&parsed_url, path, args);
            }
            // TFTP upload: -T <file> tftp://host/remote → WRQ.
            if parsed_url.scheme == "tftp" {
                return run_tftp_upload(&parsed_url, path, args);
            }
            // SFTP/SCP upload: -T <file> sftp|scp://host/remote.
            if matches!(parsed_url.scheme.as_str(), "sftp" | "scp") {
                #[cfg(feature = "ssh")]
                {
                    return run_ssh_upload(&parsed_url, path, args);
                }
                #[cfg(not(feature = "ssh"))]
                {
                    if show_errors(args) {
                        eprintln!("rsurl: this build has no SSH (sftp/scp) support");
                    }
                    return 2;
                }
            }
            if show_errors(args) {
                eprintln!(
                    "rsurl: -T is only supported for HTTP(S), FTP(S), TFTP, and SFTP/SCP URLs in this build"
                );
            }
            return 2;
        }
        // SFTP/SCP download: connect, auth, fetch the remote path. Threads
        // -u/userinfo password, --key identities, and -k into SshOptions, and
        // emits the verbose SSH trace under -v.
        if matches!(parsed_url.scheme.as_str(), "sftp" | "scp") {
            #[cfg(feature = "ssh")]
            {
                return run_ssh(&parsed_url, args);
            }
            #[cfg(not(feature = "ssh"))]
            {
                if show_errors(args) {
                    eprintln!("rsurl: this build has no SSH (sftp/scp) support");
                }
                return 2;
            }
        }
        // Any non-HTTP download to a file goes through the streaming sink, which
        // enforces --limit-rate / -# / --max-filesize / -y / -Y /
        // --remove-on-error and supports -w. FTP/FTPS and file:// truly stream
        // (no full-body buffer); the rest fetch-then-write through the sink.
        let to_file = args.remote_name || args.output.as_deref().is_some_and(|p| p != "-");
        if to_file {
            return run_stream_download(&parsed_url, args);
        }
        return run_transfer(&parsed_url, args);
    }

    // Assemble the body up front so we know whether to default the method
    // (PUT for `-T`, POST for `-d`/`-F`). Errors from file I/O or mutually
    // exclusive flag combos surface as exit code 2 ("usage").
    let mut assembled = match assemble_request_body(args) {
        Ok(b) => b,
        Err(e) => {
            if show_errors(args) {
                eprintln!("rsurl: {e}");
            }
            return 2;
        }
    };

    // `-G`/`--get`: fold urlencoded `-d` data into the URL query and send a
    // bodyless GET (curl semantics; multipart/`-F` is left untouched).
    let mut url_owned = url.to_string();
    if args.get {
        if let Some((bytes, ctype, _)) = &assembled {
            if ctype.starts_with("application/x-www-form-urlencoded") {
                let q = String::from_utf8_lossy(bytes);
                if !q.is_empty() {
                    url_owned.push(if url_owned.contains('?') { '&' } else { '?' });
                    url_owned.push_str(&q);
                }
                assembled = None;
            }
        }
    }

    let method = args.method.clone().unwrap_or_else(|| {
        if args.head {
            "HEAD".to_string()
        } else if args.get {
            "GET".to_string()
        } else if let Some((_, _, m)) = &assembled {
            (*m).to_string()
        } else {
            "GET".to_string()
        }
    });

    let mut req = match Request::new(&method, &url_owned) {
        Ok(r) => r,
        Err(e) => {
            if show_errors(args) {
                eprintln!("rsurl: {e}");
            }
            return 3;
        }
    };

    for (k, v) in &args.headers {
        req = req.header(k, v);
    }
    // Headers the CLI generates itself (from -A, -e, --json, ...). curl sends
    // each only when no -H supplies it and no `-H "Name:"` removed it.
    let mut added: Vec<&'static str> = Vec::new();
    if let Some(ua) = &args.user_agent {
        req = add_header(req, args, &mut added, "User-Agent", ua);
    }
    if let Some(rf) = &args.referer {
        req = add_header(req, args, &mut added, "Referer", rf);
    }
    if args.auto_referer {
        req = req.auto_referer(true);
    }
    // -z/--time-cond: If-Modified-Since (or If-Unmodified-Since for a leading
    // '-'); a value naming an existing file uses its mtime.
    if let Some(tc) = &args.time_cond {
        if let Some((hdr, date)) = time_cond_header(tc) {
            req = add_header(req, args, &mut added, hdr, &date);
        } else if show_errors(args) {
            eprintln!("rsurl: warning: could not parse --time-cond {tc:?}");
        }
    }
    // `--compressed`: advertise codecs we transparently decode. (We always
    // decode a compressed response; this just asks the server to send one.)
    if args.compressed {
        req = add_header(
            req,
            args,
            &mut added,
            "Accept-Encoding",
            "gzip, deflate, br, zstd",
        );
    } else if args.has_header("accept-encoding") {
        // Without --compressed curl never decodes: a caller who asked for an
        // encoding with their own -H gets the raw encoded bytes.
        req = req.decompress(false);
    }
    // `--json`: also request a JSON response (curl sets Accept too). The
    // Content-Type is applied via the assembled body's content type below.
    if !args.json_parts.is_empty() {
        req = add_header(req, args, &mut added, "Accept", "application/json");
    }
    // `-r`/`--range`: a bare range becomes `bytes=<range>`.
    if let Some(r) = &args.range {
        let v = if r.contains('=') {
            r.clone()
        } else {
            format!("bytes={r}")
        };
        req = add_header(req, args, &mut added, "Range", &v);
    }
    if let Some((body_bytes, ctype, _method)) = assembled {
        req = add_header(req, args, &mut added, "Content-Type", &ctype);
        req = req.body(body_bytes);
    }
    match args.http_version {
        Some(HttpVersionPref::Http2Only) => req = req.http2_only(),
        Some(HttpVersionPref::Http11Only) => req = req.http11_only(),
        Some(HttpVersionPref::Http3) => req = req.http3(),
        Some(HttpVersionPref::Http3Only) => req = req.http3_only(),
        Some(HttpVersionPref::Auto) | None => {}
    }

    if args.follow_redirects {
        req = req.follow_redirects(true);
        // curl sends a -X method on every request, redirects included: it
        // never rewrites it to GET on a 301/302/303.
        if args.method.is_some() {
            for status in [301, 302, 303] {
                req = req.keep_post_on(status);
            }
        }
    }
    if let Some(n) = args.max_redirs {
        req = req.max_redirs(n);
    }
    if args.location_trusted {
        req = req.redirect_trusted(true);
    }
    if args.post301 {
        req = req.keep_post_on(301);
    }
    if args.post302 {
        req = req.keep_post_on(302);
    }
    if args.post303 {
        req = req.keep_post_on(303);
    }
    for (fh, fp, th, tp) in &args.connect_to {
        req = req.connect_to(fh, *fp, th, *tp);
    }
    if let Some(path) = &args.unix_socket {
        #[cfg(unix)]
        {
            req = req.connector(std::sync::Arc::new(rsurl::net::UnixConnector {
                path: path.into(),
            }));
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            if show_errors(args) {
                eprintln!("rsurl: --unix-socket is not supported on this platform");
            }
            return 2;
        }
    }
    if let Some((u, p)) = &args.basic_auth {
        req = req.basic_auth(u, p);
    } else if args.netrc && parsed_url.userinfo.is_none() {
        // -n/--netrc: pull credentials for this host from the netrc file when
        // neither -u nor URL userinfo supplied them.
        if let Some((u, p)) = netrc_credentials(args, &parsed_url.host) {
            req = req.basic_auth(&u, &p);
        }
    }
    if args.insecure {
        req = req.verify_tls(false);
    }
    if let Some(v) = args.tls_min {
        req = req.tls_min_version(v);
    }
    if let Some(v) = args.tls_max {
        req = req.tls_max_version(v);
    }
    if args.digest {
        req = req.digest_auth(true);
    }
    if let Some(token) = &args.bearer {
        req = add_header(
            req,
            args,
            &mut added,
            "Authorization",
            &format!("Bearer {token}"),
        );
    }
    if let (Some(spec), Some((ak, sk))) = (&args.aws_sigv4, &args.basic_auth) {
        req = req.aws_sigv4(spec, ak, sk);
    }
    if args.no_idn {
        req = req.idn(false);
    }
    if let Some(path) = &args.cacert {
        req = req.ca_bundle(path);
    }
    if let Some(dir) = &args.capath {
        req = req.ca_path(dir);
    }
    if let Some(spec) = &args.pinned_pubkey {
        req = req.pinned_pubkey(spec);
    }
    if let Some(path) = &args.crl_file {
        req = req.crl_file(path);
    }
    if let Some(list) = &args.ciphers {
        req = req.ciphers(list);
    }
    if let Some(list) = &args.tls13_ciphers {
        req = req.tls13_ciphers(list);
    }
    if let Some(cert) = &args.cert {
        // curl allows an inline `-E cert:password`. Split on the first ':'
        // that isn't part of a Windows drive letter; on Unix a bare first ':'
        // separates the password. An explicit --pass overrides the inline one.
        let (cert_path, inline_pass) = split_cert_pass(cert);
        req = req.client_cert(cert_path);
        if let Some(key) = &args.key_file {
            req = req.client_key(key);
        }
        if let Some(pass) = args.key_pass.as_deref().or(inline_pass) {
            req = req.client_key_pass(pass);
        }
        if args.cert_type_der {
            req = req.cert_type_der(true);
        }
        if args.key_type_der {
            req = req.key_type_der(true);
        }
    }
    if let Some(d) = args.max_time {
        req = req.max_time(d);
    }
    if let Some(d) = args.connect_timeout {
        req = req.connect_timeout(d);
    }
    // -6 wins if both -4 and -6 are given (last-wins is curl's rule, but both
    // set is degenerate; prefer v6 to match curl's IPRESOLVE precedence).
    if args.ipv6 {
        req = req.ipv6();
    } else if args.ipv4 {
        req = req.ipv4();
    }
    for (h, p, ip) in &args.resolve {
        req = req.resolve_addr(h, *p, *ip);
    }
    // `-H "Name:"` naming a header the library adds on its own (User-Agent,
    // Accept, Accept-Encoding, Authorization from credentials) can only be
    // honoured in strict-headers mode, which drops them all; re-add the ones
    // that were not removed so nothing else changes.
    if ["user-agent", "accept", "accept-encoding", "authorization"]
        .iter()
        .any(|n| args.header_removed(n))
    {
        req = req.strict_headers(true);
        let ua = format!("rsurl/{VERSION}");
        req = add_header(req, args, &mut added, "User-Agent", &ua);
        req = add_header(req, args, &mut added, "Accept", "*/*");
        req = add_header(req, args, &mut added, "Accept-Encoding", "gzip, deflate");
        if !args.digest && args.aws_sigv4.is_none() {
            if let Some(creds) = basic_credentials(&parsed_url, args) {
                let value = format!("Basic {}", base64_encode(creds.as_bytes()));
                req = add_header(req, args, &mut added, "Authorization", &value);
            }
        }
    }
    if parsed_url.scheme == "https" {
        if let Some(code) = check_tls_files(args) {
            return code;
        }
    }
    if let Some(code) = check_proxy_tls_files(args) {
        return code;
    }

    // Proxy: explicit `-x` wins over env vars; `-x ""` disables both.
    let proxy_spec = resolve_proxy_spec(&parsed_url, args);
    if let Some(spec) = proxy_spec {
        req = match req.proxy(&spec) {
            Ok(r) => r,
            Err(e) => {
                if show_errors(args) {
                    eprintln!("rsurl: --proxy: {e}");
                }
                return 5;
            }
        };
        if let Some((u, p)) = &args.proxy_user {
            req = match req.proxy_user(u, p) {
                Ok(r) => r,
                Err(e) => {
                    if show_errors(args) {
                        eprintln!("rsurl: --proxy-user: {e}");
                    }
                    return 5;
                }
            };
        }
    }
    if let Some(list) = resolve_noproxy(args) {
        req = req.no_proxy(list.split(',').map(str::trim).filter(|s| !s.is_empty()));
    }
    req = apply_proxy_tls!(req, &args.proxy_tls);

    // If `-b "k=v"` was given, apply those cookies to the jar against the
    // current URL before issuing the request. This must happen before the
    // send_*_with_jar call below, which moves the jar reference.
    if let (Some(j), Some(data)) = (jar.as_deref_mut(), args.cookie_in.as_deref()) {
        if data.contains('=') {
            apply_explicit_cookies(j, data, &parsed_url);
        }
    }

    // -C <offset>, or -C - against an existing output file: curl-style resume
    // with a Range request, appending to the output.
    if args.upload_file.is_none() && args.range.is_none() {
        if let Some(offset) = resume_offset(&parsed_url, args) {
            return run_http_resume(req, &parsed_url, args, jar, offset);
        }
    }

    // Stream the body straight to a file when that's safe and useful: a file
    // output (not a TTY, so no escape-guard needed), no header-inclusion, and
    // no status-gated body suppression. This is the path that enforces
    // --limit-rate, -# progress, and an early --max-filesize abort.
    if streams_to_file(args) {
        // Resolve the concrete output file the library download engine needs.
        let name = if args.remote_name {
            match remote_name_from_url(&parsed_url) {
                Ok(n) => n,
                Err(e) => {
                    if show_errors(args) {
                        eprintln!("rsurl: {e}");
                    }
                    return 23;
                }
            }
        } else {
            args.output.clone().unwrap_or_default()
        };
        let concrete = !name.is_empty() && name != "-";
        let workers = args.parallel_segments.unwrap_or(1).min(MAX_SEGMENTS);
        // `-C -` and `--parallel-segments` both run on the library engine (range
        // + validator handling, retry, streaming chunks, atomic finalize). A
        // resumable transfer uses fixed chunks; a bare parallel one splits into
        // N equal segments. Everything else is a plain in-place download.
        if concrete && args.continue_resume {
            let plan = if parallel_segments_eligible(args) {
                SegmentPlan::FixedChunks {
                    size: RESUME_CHUNK,
                    workers,
                }
            } else {
                SegmentPlan::Single
            };
            return run_library_download(&req, &parsed_url, args, &name, jar, plan);
        }
        if concrete && parallel_segments_eligible(args) {
            return run_library_download(
                &req,
                &parsed_url,
                args,
                &name,
                jar,
                SegmentPlan::EqualSegments {
                    count: workers.saturating_mul(SEGMENT_OVERSUBSCRIBE),
                    workers,
                },
            );
        }
        return run_http_download(req, &parsed_url, args, jar);
    }
    // Likewise stream a body bound for stdout rather than holding all of it in
    // memory (and enforce --max-filesize as it arrives).
    if streams_to_stdout(args) {
        return run_http_download(req, &parsed_url, args, jar);
    }

    let started = std::time::Instant::now();
    let mut jar = jar;
    let mut attempt = 0u32;
    let resp = loop {
        let attempt_req = req.clone();
        let result = match (jar.as_deref_mut(), args.verbose) {
            (Some(j), true) => {
                let mut err = io::stderr().lock();
                attempt_req.send_traced_with_jar(j, &mut err)
            }
            (Some(j), false) => attempt_req.send_with_jar(j),
            (None, true) => {
                let mut err = io::stderr().lock();
                attempt_req.send_traced(&mut err)
            }
            (None, false) => attempt_req.send(),
        };
        // Stop retrying once --retry-max-time elapses.
        let within_budget = args
            .retry_max_time
            .is_none_or(|m| started.elapsed().as_secs() < m);
        match result {
            // A transient HTTP status is retried up to `--retry` times.
            Ok(r) if is_retryable_status(r.status) && attempt < args.retry && within_budget => {
                attempt += 1;
                if show_errors(args) {
                    eprintln!(
                        "rsurl: transient HTTP {} — retry {}/{}",
                        r.status, attempt, args.retry
                    );
                }
                std::thread::sleep(next_retry_delay(attempt, args));
            }
            Ok(r) => break r,
            Err(e) if attempt < args.retry && within_budget && should_retry_err(&e, args) => {
                attempt += 1;
                if show_errors(args) {
                    eprintln!("rsurl: {e} — retry {}/{}", attempt, args.retry);
                }
                std::thread::sleep(next_retry_delay(attempt, args));
            }
            Err(e) => {
                if show_errors(args) {
                    eprintln!("rsurl: {e}");
                }
                let code = transfer_exit_code(&e);
                write_out_failure(&parsed_url, args, started.elapsed(), code, &e.to_string());
                return code;
            }
        }
    };
    let time_total = started.elapsed();

    // --max-filesize: reject when the server declares (Content-Length) or
    // delivers a body larger than the cap.
    if let Some(max) = args.max_filesize {
        let declared = resp
            .header("content-length")
            .and_then(|v| v.trim().parse::<u64>().ok());
        if declared.is_some_and(|n| n > max) || resp.body.len() as u64 > max {
            if show_errors(args) {
                eprintln!("rsurl: Maximum file size exceeded");
            }
            return 63;
        }
    }

    // -D/--dump-header: write the response headers out before the body.
    if let Some(path) = &args.dump_header {
        if let Err(e) = dump_headers(&resp, path) {
            if show_errors(args) {
                eprintln!("rsurl: dump-header {path}: {e}");
            }
            return 23;
        }
    }

    // --fail-with-body / -f/--fail: exit 22 on an HTTP error; the former still
    // writes the body. (Without either, curl exits 0 even on 4xx/5xx.)
    if (args.fail_with_body || args.fail) && resp.status >= 400 {
        let msg = format!(
            "The requested URL returned error: {} {}",
            resp.status, resp.reason
        );
        if show_errors(args) {
            eprintln!("rsurl: {msg}");
        }
        if args.fail_with_body {
            let _ = write_output(&resp, &parsed_url, args);
        }
        let size = resp.body.len() as u64;
        run_write_out_code(&resp, &parsed_url, args, time_total, size, 22, &msg);
        return 22;
    }

    let written = match write_output(&resp, &parsed_url, args) {
        Ok(p) => p,
        Err(e) => {
            // The binary-to-terminal refusal already printed curl's warning.
            if show_errors(args) && e.to_string() != BINARY_TO_TTY {
                eprintln!("rsurl: write error: {e}");
            }
            let msg = e.to_string();
            run_write_out_code(&resp, &parsed_url, args, time_total, 0, 23, &msg);
            return 23;
        }
    };

    // -R/--remote-time: stamp the saved file's mtime from Last-Modified.
    if args.remote_time {
        if let Some(path) = &written {
            set_remote_time(&resp, path);
        }
    }

    run_write_out(&resp, &parsed_url, args, time_total, resp.body.len() as u64);
    0
}

/// Append a header the CLI generates unless a `-H` supplies it, `-H "Name:"`
/// removed it, or it was already added; records it in `added`.
fn add_header(
    req: Request,
    args: &Args,
    added: &mut Vec<&'static str>,
    name: &'static str,
    value: &str,
) -> Request {
    if args.header_removed(name)
        || args.has_header(name)
        || added.iter().any(|n| n.eq_ignore_ascii_case(name))
    {
        return req;
    }
    added.push(name);
    req.header(name, value)
}

/// The `user:password` Basic credentials for this request: `-u`, else
/// `-n`/netrc, else the URL's userinfo — the same precedence the library uses.
fn basic_credentials(url: &Url, args: &Args) -> Option<String> {
    let (u, p) = if let Some((u, p)) = &args.basic_auth {
        (u.clone(), p.clone())
    } else if let Some(info) = url.userinfo.as_deref() {
        match info.split_once(':') {
            Some((u, p)) => (u.to_string(), p.to_string()),
            None => (info.to_string(), String::new()),
        }
    } else if args.netrc {
        netrc_credentials(args, &url.host)?
    } else {
        return None;
    };
    (!u.is_empty() || !p.is_empty()).then(|| format!("{u}:{p}"))
}

/// Standard (padded) base64, for a hand-built `Authorization: Basic`.
fn base64_encode(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for c in input.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for (i, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            if i <= c.len() {
                out.push(T[(n >> shift & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Append `--url-query` parts to `url`'s query (before any fragment). Each
/// part uses `--data-urlencode` syntax; a leading `+` sends it verbatim.
fn append_url_queries(url: &str, parts: &[String]) -> Result<String, String> {
    let mut encoded = Vec::with_capacity(parts.len());
    for part in parts {
        encoded.push(match part.strip_prefix('+') {
            Some(raw) => raw.to_string(),
            None => String::from_utf8_lossy(&encode_urlencoded(part)?).into_owned(),
        });
    }
    let query = encoded.join("&");
    let (base, frag) = match url.split_once('#') {
        Some((b, f)) => (b, Some(f)),
        None => (url, None),
    };
    let mut out = base.to_string();
    if !query.is_empty() {
        if !out.contains('?') {
            out.push('?');
        } else if !out.ends_with('?') && !out.ends_with('&') {
            out.push('&');
        }
        out.push_str(&query);
    }
    if let Some(f) = frag {
        out.push('#');
        out.push_str(f);
    }
    Ok(out)
}

/// Fail early, with curl's exit codes, when a TLS input file named on the
/// command line can't be read: `--cacert`/`--capath` (77), `-E`/`--key` (58),
/// `--crlfile` (82). Otherwise the transfer would fail later with a generic
/// I/O error.
fn check_tls_files(args: &Args) -> Option<u8> {
    let unreadable = |p: &str| File::open(p).is_err();
    let fail = |what: &str, path: &str, code: u8| {
        if show_errors(args) {
            eprintln!("rsurl: error setting {what} {path:?}: cannot read it");
        }
        Some(code)
    };
    if let Some(p) = args.cacert.as_deref().filter(|p| unreadable(p)) {
        return fail("certificate file", p, 77);
    }
    if let Some(p) = args.capath.as_deref().filter(|p| !Path::new(p).is_dir()) {
        return fail("certificate directory", p, 77);
    }
    if let Some(cert) = &args.cert {
        let (path, _) = split_cert_pass(cert);
        if unreadable(path) {
            return fail("client certificate", path, 58);
        }
        if let Some(k) = args.key_file.as_deref().filter(|p| unreadable(p)) {
            return fail("private key file", k, 58);
        }
    }
    if let Some(p) = args.crl_file.as_deref().filter(|p| unreadable(p)) {
        return fail("CRL file", p, 82);
    }
    None
}

/// [`check_tls_files`] for the `--proxy-*` TLS files. Same exit codes.
fn check_proxy_tls_files(args: &Args) -> Option<u8> {
    let p = &args.proxy_tls;
    let unreadable = |p: &str| File::open(p).is_err();
    let fail = |what: &str, path: &str, code: u8| {
        if show_errors(args) {
            eprintln!("rsurl: error setting proxy {what} {path:?}: cannot read it");
        }
        Some(code)
    };
    if let Some(f) = p.cacert.as_deref().filter(|f| unreadable(f)) {
        return fail("certificate file", f, 77);
    }
    if let Some(d) = p.capath.as_deref().filter(|d| !Path::new(d).is_dir()) {
        return fail("certificate directory", d, 77);
    }
    if let Some(cert) = &p.cert {
        let (path, _) = split_cert_pass(cert);
        if unreadable(path) {
            return fail("client certificate", path, 58);
        }
        if let Some(k) = p.key.as_deref().filter(|f| unreadable(f)) {
            return fail("private key file", k, 58);
        }
    }
    if let Some(f) = p.crlfile.as_deref().filter(|f| unreadable(f)) {
        return fail("CRL file", f, 82);
    }
    None
}

/// Parse a `--tls-max` / `--proxy-tls-max` version argument.
fn parse_tls_max(v: &str, flag: &str) -> Result<rsurl::tls::ProtocolVersion, String> {
    Ok(match v {
        "1.3" => rsurl::tls::ProtocolVersion::TLSv1_3,
        "1.0" | "1.1" | "1.2" => rsurl::tls::ProtocolVersion::TLSv1_2,
        other => return Err(format!("{flag}: unsupported version {other:?}")),
    })
}

fn parse_args(raw: &[String]) -> Result<Args, String> {
    let mut a = Args::default();
    let mut it = raw.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("rsurl {VERSION}");
                std::process::exit(0);
            }
            "-o" | "--output" => {
                let v = next_val(&mut it, arg)?;
                a.outputs.push(OutputSpec::File(v.clone()));
                a.output = Some(v);
            }
            "--remote-name-all" => a.remote_name_all = true,
            "--url-query" => a.url_queries.push(next_val(&mut it, arg)?),
            // End of options: every remaining token is a URL (curl/getopt).
            "--" => {
                a.urls.extend(it.by_ref().cloned());
                break;
            }
            "-i" | "--include" => a.include_headers = true,
            "-I" | "--head" => {
                a.head = true;
                a.include_headers = true;
            }
            "-v" | "--verbose" => {
                a.verbose = true;
                a.verbosity = a.verbosity.saturating_add(1);
            }
            "-s" | "--silent" => a.silent = true,
            "-X" | "--request" => a.method = Some(next_val(&mut it, arg)?),
            "-H" | "--header" => {
                let h = next_val(&mut it, arg)?;
                match parse_header_arg(&h)? {
                    HeaderArg::Set(k, v) => a.headers.push((k, v)),
                    HeaderArg::Remove(k) => a.removed_headers.push(k.to_ascii_lowercase()),
                }
            }
            "-d" | "--data" | "--data-ascii" => a.data_parts.push(DataPart::Plain {
                value: next_val(&mut it, arg)?,
                at_file_ok: true,
            }),
            "--remove-on-error" => a.remove_on_error = true,
            "--no-clobber" => a.no_clobber = true,
            "--disable-epsv" => a.disable_epsv = true,
            "--ssl-reqd" => a.ssl_reqd = true,
            "--ftp-create-dirs" => a.ftp_create_dirs = true,
            "-P" | "--ftp-port" => a.ftp_port = Some(next_val(&mut it, arg)?),
            // We always use passive mode (active/PORT is unimplemented), so
            // --ftp-pasv and re-enabling EPSV are accepted as confirmations.
            "--ftp-pasv" => {}
            "--epsv" => a.disable_epsv = false,
            // Confirmations of behavior rsurl already implements (honest no-ops,
            // not stubs): Basic is the default auth when -u is given, and for a
            // direct FTP dial we always ignore the PASV-advertised IP (SSRF
            // guard) — exactly what --ftp-skip-pasv-ip requests.
            "--basic" | "--ftp-skip-pasv-ip" => {}
            "--json" => a.json_parts.push(next_val(&mut it, arg)?),
            "--oauth2-bearer" => a.bearer = Some(next_val(&mut it, arg)?),
            "--aws-sigv4" => a.aws_sigv4 = Some(next_val(&mut it, arg)?),
            "--data-raw" => a.data_parts.push(DataPart::Plain {
                value: next_val(&mut it, arg)?,
                at_file_ok: false,
            }),
            "--data-binary" => a.data_parts.push(DataPart::Binary {
                value: next_val(&mut it, arg)?,
            }),
            "--data-urlencode" => a.data_parts.push(DataPart::UrlEncoded {
                value: next_val(&mut it, arg)?,
            }),
            "-F" | "--form" => {
                let v = next_val(&mut it, arg)?;
                a.form_parts.push(form_parser::parse(&v)?);
            }
            "--form-string" => {
                // No `@`/`<`/`;` magic: the whole right-hand side is the
                // literal value, and the part carries no extras.
                let v = next_val(&mut it, arg)?;
                let eq = v
                    .find('=')
                    .ok_or_else(|| format!("--form-string: expected 'name=value', got {v:?}"))?;
                let name = v[..eq].to_string();
                if name.is_empty() {
                    return Err(format!("--form-string: empty field name: {v:?}"));
                }
                let value = v[eq + 1..].to_string();
                a.form_parts.push(FormPart {
                    name,
                    body: FormBody::LiteralStrict(value),
                    extras: vec![],
                });
            }
            "--form-escape" => a.form_escape = true,
            "-T" | "--upload-file" => a.upload_file = Some(next_val(&mut it, arg)?),
            "-C" | "--continue-at" => {
                let v = next_val(&mut it, arg)?;
                if v == "-" {
                    a.continue_resume = true;
                } else {
                    a.continue_at = Some(
                        v.parse::<u64>()
                            .map_err(|_| format!("-C/--continue-at: not a byte offset: {v:?}"))?,
                    );
                }
            }
            "-a" | "--append" => a.append = true,
            "--key" => {
                // curl's `--key` is the "private key file", used both for SSH
                // public-key auth (sftp://, scp://) and as the TLS client key
                // (with `-E`). Record it for both; the request path picks the
                // one relevant to its scheme.
                let path = next_val(&mut it, arg)?;
                a.key_file = Some(path.clone());
                a.ssh_keys.push(path);
            }
            "-A" | "--user-agent" => a.user_agent = Some(next_val(&mut it, arg)?),
            "-e" | "--referer" => {
                let v = next_val(&mut it, arg)?;
                // curl: a trailing ";auto" enables auto-referer on redirect;
                // the part before it (if any) is the initial Referer.
                let (head, auto) = match v.strip_suffix(";auto") {
                    Some(h) => (h, true),
                    None => (v.as_str(), false),
                };
                a.auto_referer = a.auto_referer || auto;
                if !head.is_empty() {
                    a.referer = Some(head.to_string());
                }
            }
            "-z" | "--time-cond" => a.time_cond = Some(next_val(&mut it, arg)?),
            "--output-dir" => a.output_dir = Some(next_val(&mut it, arg)?),
            "--fail-with-body" => a.fail_with_body = true,
            "--proto" => a.proto = Some(next_val(&mut it, arg)?),
            "--proto-default" => a.proto_default = Some(next_val(&mut it, arg)?),
            "--http2" => a.http_version = Some(HttpVersionPref::Http2Only),
            // curl also accepts `--http1` as a shorthand for `--http1.1`.
            "--http1.1" | "--http1" => a.http_version = Some(HttpVersionPref::Http11Only),
            "--http3" => a.http_version = Some(HttpVersionPref::Http3),
            "--http3-only" => a.http_version = Some(HttpVersionPref::Http3Only),
            "-L" | "--location" => a.follow_redirects = true,
            "--max-redirs" => {
                let v = next_val(&mut it, arg)?;
                a.max_redirs = Some(
                    v.parse::<u32>()
                        .map_err(|_| format!("--max-redirs: not a number: {v:?}"))?,
                );
            }
            "-u" | "--user" => {
                let v = next_val(&mut it, arg)?;
                // curl: split on first ':'; missing colon means whole string
                // is the username and password is empty.
                let (u, p) = match v.split_once(':') {
                    Some((u, p)) => (u.to_string(), p.to_string()),
                    None => (v.clone(), String::new()),
                };
                a.basic_auth = Some((u, p));
            }
            "-k" | "--insecure" => a.insecure = true,
            "--tlsv1" | "--tlsv1.0" | "--tlsv1.1" | "--tlsv1.2" => {
                a.tls_min = Some(rsurl::tls::ProtocolVersion::TLSv1_2)
            }
            "--tlsv1.3" => a.tls_min = Some(rsurl::tls::ProtocolVersion::TLSv1_3),
            "--mail-from" => a.mail_from = Some(next_val(&mut it, arg)?),
            "--mail-rcpt" => a.mail_rcpt.push(next_val(&mut it, arg)?),
            "--digest" => a.digest = true,
            "-Z" | "--parallel" => a.parallel = true,
            "--parallel-max" => {
                a.parallel_max = Some(
                    next_val(&mut it, arg)?
                        .parse()
                        .map_err(|_| "--parallel-max requires a number".to_string())?,
                )
            }
            "--parallel-segments" => {
                // Optional count; defaults to 4. Only consume the next token if
                // it parses as a number (otherwise it's the URL / next flag).
                let n = match it.clone().next().and_then(|s| s.parse::<usize>().ok()) {
                    Some(v) => {
                        it.next();
                        v
                    }
                    None => 4,
                };
                a.parallel_segments = Some(n);
            }
            "--torrent" => a.torrent = true,
            "--listen-port" => {
                a.listen_port = Some(
                    next_val(&mut it, arg)?
                        .parse()
                        .map_err(|_| "--listen-port requires a port number".to_string())?,
                )
            }
            "--bt-peer" => a.bt_peers.push(next_val(&mut it, arg)?),
            "--no-dht" => a.no_dht = true,
            "--seed" => a.seed = true,
            "--recheck" => a.recheck = true,
            "--bt-info" => a.bt_info = true,
            "--bt-save-torrent" => a.bt_save_torrent = true,
            "--bt-file" => a.bt_file = Some(next_val(&mut it, arg)?),
            "--bt-concat" => a.bt_concat = true,
            "--share-ratio" => {
                a.share_ratio = Some(
                    next_val(&mut it, arg)?
                        .parse()
                        .map_err(|_| "--share-ratio requires a number".to_string())?,
                )
            }
            "--tls-max" => a.tls_max = Some(parse_tls_max(&next_val(&mut it, arg)?, arg)?),
            // The `--proxy-*` TLS family: the session to an `https://` proxy.
            "--proxy-insecure" => a.proxy_tls.insecure = true,
            "--proxy-cacert" => a.proxy_tls.cacert = Some(next_val(&mut it, arg)?),
            "--proxy-capath" => a.proxy_tls.capath = Some(next_val(&mut it, arg)?),
            "--proxy-crlfile" => a.proxy_tls.crlfile = Some(next_val(&mut it, arg)?),
            "--proxy-cert" => a.proxy_tls.cert = Some(next_val(&mut it, arg)?),
            "--proxy-key" => a.proxy_tls.key = Some(next_val(&mut it, arg)?),
            "--proxy-pass" => a.proxy_tls.pass = Some(next_val(&mut it, arg)?),
            "--proxy-cert-type" => {
                a.proxy_tls.cert_type_der = parse_cert_type(&next_val(&mut it, arg)?, arg)?
            }
            "--proxy-key-type" => {
                a.proxy_tls.key_type_der = parse_cert_type(&next_val(&mut it, arg)?, arg)?
            }
            "--proxy-pinnedpubkey" => a.proxy_tls.pinned_pubkey = Some(next_val(&mut it, arg)?),
            "--proxy-ciphers" => a.proxy_tls.ciphers = Some(next_val(&mut it, arg)?),
            "--proxy-tls13-ciphers" => a.proxy_tls.tls13_ciphers = Some(next_val(&mut it, arg)?),
            "--proxy-tlsv1" | "--proxy-tlsv1.0" | "--proxy-tlsv1.1" | "--proxy-tlsv1.2" => {
                a.proxy_tls.tls_min = Some(rsurl::tls::ProtocolVersion::TLSv1_2)
            }
            "--proxy-tlsv1.3" => a.proxy_tls.tls_min = Some(rsurl::tls::ProtocolVersion::TLSv1_3),
            "--proxy-tls-max" => {
                a.proxy_tls.tls_max = Some(parse_tls_max(&next_val(&mut it, arg)?, arg)?)
            }
            "--no-idn" => a.no_idn = true,
            "--cacert" => a.cacert = Some(next_val(&mut it, arg)?),
            "-m" | "--max-time" => a.max_time = parse_seconds(&next_val(&mut it, arg)?, arg)?,
            "--connect-timeout" => {
                a.connect_timeout = parse_seconds(&next_val(&mut it, arg)?, arg)?
            }
            "-O" | "--remote-name" => {
                a.outputs.push(OutputSpec::Remote);
                a.remote_name = true;
            }
            "-b" | "--cookie" => a.cookie_in = Some(next_val(&mut it, arg)?),
            "-c" | "--cookie-jar" => a.cookie_jar = Some(next_val(&mut it, arg)?),
            "-j" | "--junk-session-cookies" => a.junk_session_cookies = true,
            "-x" | "--proxy" => a.proxy = Some(next_val(&mut it, arg)?),
            // curl shorthands that pin the proxy scheme.
            "--socks4" => a.proxy = Some(format!("socks4://{}", next_val(&mut it, arg)?)),
            "--socks4a" => a.proxy = Some(format!("socks4a://{}", next_val(&mut it, arg)?)),
            "--socks5" => a.proxy = Some(format!("socks5://{}", next_val(&mut it, arg)?)),
            "--socks5-hostname" => a.proxy = Some(format!("socks5h://{}", next_val(&mut it, arg)?)),
            "-U" | "--proxy-user" => {
                let v = next_val(&mut it, arg)?;
                let (u, p) = match v.split_once(':') {
                    Some((u, p)) => (u.to_string(), p.to_string()),
                    None => (v.clone(), String::new()),
                };
                a.proxy_user = Some((u, p));
            }
            "--noproxy" => a.noproxy = Some(next_val(&mut it, arg)?),
            "--url" => a.urls.push(next_val(&mut it, arg)?),
            "-f" | "--fail" => a.fail = true,
            "-S" | "--show-error" => a.show_error = true,
            "-G" | "--get" => a.get = true,
            "-r" | "--range" => a.range = Some(next_val(&mut it, arg)?),
            "--compressed" => a.compressed = true,
            "-D" | "--dump-header" => a.dump_header = Some(next_val(&mut it, arg)?),
            "-R" | "--remote-time" => a.remote_time = true,
            "--create-dirs" => a.create_dirs = true,
            "--max-filesize" => {
                a.max_filesize = Some(
                    next_val(&mut it, arg)?
                        .parse()
                        .map_err(|_| "--max-filesize requires a byte count".to_string())?,
                )
            }
            "-w" | "--write-out" => a.write_out = Some(next_val(&mut it, arg)?),
            "-n" | "--netrc" => a.netrc = true,
            "--netrc-file" => {
                a.netrc_file = Some(next_val(&mut it, arg)?);
                a.netrc = true;
            }
            "-J" | "--remote-header-name" => a.remote_header_name = true,
            "--retry" => {
                a.retry = next_val(&mut it, arg)?
                    .parse()
                    .map_err(|_| "--retry requires a count".to_string())?
            }
            "--retry-delay" => {
                a.retry_delay = Some(
                    next_val(&mut it, arg)?
                        .parse()
                        .map_err(|_| "--retry-delay requires seconds".to_string())?,
                )
            }
            "--retry-max-time" => {
                a.retry_max_time = Some(
                    next_val(&mut it, arg)?
                        .parse()
                        .map_err(|_| "--retry-max-time requires seconds".to_string())?,
                )
            }
            "--retry-connrefused" => a.retry_connrefused = true,
            "--retry-all-errors" => a.retry_all_errors = true,
            "-g" | "--globoff" => a.globoff = true,
            "--unix-socket" | "--abstract-unix-socket" => {
                a.unix_socket = Some(next_val(&mut it, arg)?)
            }
            "--location-trusted" => {
                a.follow_redirects = true;
                a.location_trusted = true;
            }
            "--post301" => a.post301 = true,
            "--post302" => a.post302 = true,
            "--post303" => a.post303 = true,
            "--connect-to" => {
                let spec = next_val(&mut it, arg)?;
                let p: Vec<&str> = spec.split(':').collect();
                if p.len() != 4 {
                    return Err(format!(
                        "--connect-to expects HOST1:PORT1:HOST2:PORT2: {spec:?}"
                    ));
                }
                let port = |s: &str, what: &str| -> Result<u16, String> {
                    if s.is_empty() {
                        Ok(0)
                    } else {
                        s.parse()
                            .map_err(|_| format!("--connect-to: bad {what} in {spec:?}"))
                    }
                };
                a.connect_to.push((
                    p[0].to_string(),
                    port(p[1], "PORT1")?,
                    p[2].to_string(),
                    port(p[3], "PORT2")?,
                ));
            }
            "-4" | "--ipv4" => a.ipv4 = true,
            "-6" | "--ipv6" => a.ipv6 = true,
            "-#" | "--progress-bar" => a.progress_bar = true,
            "-E" | "--cert" => a.cert = Some(next_val(&mut it, arg)?),
            "--pass" => a.key_pass = Some(next_val(&mut it, arg)?),
            "--cert-type" => a.cert_type_der = parse_cert_type(&next_val(&mut it, arg)?, arg)?,
            "--key-type" => a.key_type_der = parse_cert_type(&next_val(&mut it, arg)?, arg)?,
            "--pinnedpubkey" => a.pinned_pubkey = Some(next_val(&mut it, arg)?),
            "--capath" => a.capath = Some(next_val(&mut it, arg)?),
            "--crlfile" => a.crl_file = Some(next_val(&mut it, arg)?),
            "--limit-rate" => a.limit_rate = Some(next_val(&mut it, arg)?),
            "-Y" | "--speed-limit" => a.speed_limit = Some(next_val(&mut it, arg)?),
            "-y" | "--speed-time" => a.speed_time = Some(next_val(&mut it, arg)?),
            "--resolve" => {
                let spec = next_val(&mut it, arg)?;
                let mut parts = spec.splitn(3, ':');
                let host = parts
                    .next()
                    .filter(|h| !h.is_empty())
                    .ok_or_else(|| format!("--resolve: missing host in {spec:?}"))?
                    .trim_start_matches(['+', '-']);
                let port: u16 = parts
                    .next()
                    .and_then(|p| p.parse().ok())
                    .ok_or_else(|| format!("--resolve: bad port in {spec:?}"))?;
                let addr_s = parts
                    .next()
                    .ok_or_else(|| format!("--resolve: missing address in {spec:?}"))?;
                let addr_s = addr_s.trim().trim_start_matches('[').trim_end_matches(']');
                let ip: std::net::IpAddr = addr_s
                    .parse()
                    .map_err(|_| format!("--resolve: bad IP {addr_s:?}"))?;
                a.resolve.push((host.to_string(), port, ip));
            }
            // Accepted for curl compatibility — genuine no-ops for rsurl, so
            // accepting them silently is honest (not a misleading stub):
            //   -q             : we never read a curlrc, so "no config" is the default.
            //   --no-progress-meter / --styled-output[/--no-]: we render neither by default.
            //   -N/--no-buffer : output is already streamed/flushed, not buffered.
            "-q"
            | "--disable"
            | "-N"
            | "--no-buffer"
            | "--no-progress-meter"
            | "--styled-output"
            | "--no-styled-output" => {}
            // TLS knobs neither backend can honour. Fail loudly rather than
            // silently ignore, so a user is never misled into thinking a
            // cipher restriction / revocation check is in effect.
            //   --ciphers / --tls13-ciphers : no per-cipher selection API in
            //     purecrypto or rustls (both pick a safe suite set internally).
            //   --cert-status (OCSP must-staple) : rsurl does not request or
            //     require an OCSP staple.
            "--ciphers" => a.ciphers = Some(next_val(&mut it, arg)?),
            "--tls13-ciphers" => a.tls13_ciphers = Some(next_val(&mut it, arg)?),
            "--cert-status" => {
                return Err(
                    "--cert-status: OCSP-staple validation is not implemented (rsurl does not \
                     request or require a stapled response)"
                        .to_string(),
                );
            }
            s if s.starts_with("--") => return Err(format!("unknown option: {s}")),
            s if s.starts_with('-') && s.len() > 1 => return Err(format!("unknown option: {s}")),
            _ => {
                a.urls.push(arg.clone());
            }
        }
    }
    Ok(a)
}

/// Whether to print error messages: always, unless `-s` is set without `-S`.
fn show_errors(args: &Args) -> bool {
    !args.silent || args.show_error
}

/// HTTP statuses curl's `--retry` treats as transient.
fn is_retryable_status(status: u16) -> bool {
    matches!(status, 408 | 429 | 500 | 502 | 503 | 504)
}

/// Exponential backoff (base 1s, capped at 60s), like curl's default.
fn retry_delay(attempt: u32) -> std::time::Duration {
    let secs = 1u64
        .checked_shl(attempt.saturating_sub(1))
        .unwrap_or(60)
        .min(60);
    std::time::Duration::from_secs(secs)
}

/// The delay before the next retry: `--retry-delay` if set, else exponential.
fn next_retry_delay(attempt: u32, args: &Args) -> std::time::Duration {
    match args.retry_delay {
        Some(s) => std::time::Duration::from_secs(s),
        None => retry_delay(attempt),
    }
}

/// Map a transfer error to curl's documented exit code. Covers the cases curl
/// distinguishes for network transfers; unclassifiable failures fall back to 7
/// ("failed to connect"), curl's own catch-all for transport trouble.
fn transfer_exit_code(e: &rsurl::Error) -> u8 {
    use std::io::ErrorKind;
    match e {
        rsurl::Error::InvalidUrl(_) => 3,        // CURLE_URL_MALFORMAT
        rsurl::Error::UnsupportedScheme(_) => 1, // CURLE_UNSUPPORTED_PROTOCOL
        rsurl::Error::UnexpectedEof => 52,       // CURLE_GOT_NOTHING
        rsurl::Error::Ssh(_) => 79,              // CURLE_SSH
        rsurl::Error::H2NotNegotiated => 7,
        // Library-API conveniences; they don't arise from the CLI transfer
        // path, but the match must stay exhaustive.
        rsurl::Error::Decode(_) => 23,
        rsurl::Error::Status { code, .. } => {
            if *code >= 400 {
                22 // CURLE_HTTP_RETURNED_ERROR
            } else {
                7
            }
        }
        rsurl::Error::BadResponse(m) if tls_exit_code(m).is_some() => tls_exit_code(m).unwrap(),
        rsurl::Error::Io(io) if tls_exit_code(&io.to_string()).is_some() => {
            tls_exit_code(&io.to_string()).unwrap()
        }
        rsurl::Error::BadResponse(m) => {
            let m = m.to_ascii_lowercase();
            if m.contains("timed out") {
                28 // CURLE_OPERATION_TIMEDOUT
            } else if m.contains("redirect") {
                47 // CURLE_TOO_MANY_REDIRECTS
            } else {
                8 // CURLE_WEIRD_SERVER_REPLY
            }
        }
        rsurl::Error::Io(io) => match io.kind() {
            // A unix socket read timeout surfaces as EAGAIN (`WouldBlock`).
            ErrorKind::TimedOut | ErrorKind::WouldBlock => 28,
            ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted => 7,
            // std has no stable "name resolution failed" kind; the OS resolver
            // surfaces it in the message ("failed to lookup address ...").
            _ if io.to_string().contains("failed to lookup") => 6, // CURLE_COULDNT_RESOLVE_HOST
            _ => 7,                                                // CURLE_COULDNT_CONNECT
        },
        // The CLI never attaches a cancel token, so this is unreachable in
        // practice; map to curl's "aborted by callback" for completeness.
        rsurl::Error::Cancelled => 42, // CURLE_ABORTED_BY_CALLBACK
    }
}

/// curl's TLS exit codes, recovered from the error text the TLS layers
/// produce: 35 handshake failure, 60 peer certificate not trusted, 58 local
/// client certificate/key problem, 77 CA bundle problem, 82 CRL problem, 59
/// cipher selection, 90 pinned-key mismatch. `None` for non-TLS errors.
fn tls_exit_code(msg: &str) -> Option<u8> {
    let m = msg.to_ascii_lowercase();
    if m.contains("pinned public key does not match") {
        return Some(90); // CURLE_SSL_PINNEDPUBKEYNOTMATCH
    }
    if m.contains("no usable ca certificates") || m.starts_with("pem parse error in") {
        return Some(77); // CURLE_SSL_CACERT_BADFILE
    }
    if m.starts_with("client cert") || m.starts_with("client key") {
        return Some(58); // CURLE_SSL_CERTPROBLEM
    }
    if m.starts_with("--crlfile") {
        return Some(82); // CURLE_SSL_CRL_BADFILE
    }
    if m.starts_with("cipher ") || m.starts_with("cipher list") {
        return Some(59); // CURLE_SSL_CIPHER
    }
    if m.contains("subject alternative name") || m.contains("rejected by verify callback") {
        return Some(60); // CURLE_PEER_FAILED_VERIFICATION
    }
    let alert = m.strip_prefix("tls: ")?;
    let cert_problem = [
        "certificate",
        "unknownca",
        "unknown ca",
        "unknownissuer",
        "notvalidforname",
        "expired",
    ]
    .iter()
    .any(|k| alert.contains(k));
    Some(if cert_problem { 60 } else { 35 }) // else CURLE_SSL_CONNECT_ERROR
}

/// Whether a transport error is retryable. curl retries timeouts by default;
/// connection-refused only with `--retry-connrefused`; everything with
/// `--retry-all-errors`.
fn should_retry_err(e: &rsurl::Error, args: &Args) -> bool {
    if args.retry_all_errors {
        return true;
    }
    match e {
        rsurl::Error::Io(io) => {
            let k = io.kind();
            matches!(
                k,
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ) || (args.retry_connrefused && k == std::io::ErrorKind::ConnectionRefused)
        }
        rsurl::Error::UnexpectedEof => true,
        _ => false,
    }
}

/// Resolve credentials for `host` from the netrc file (`--netrc-file` or
/// `~/.netrc`). Returns `None` if no file or no matching entry.
fn netrc_credentials(args: &Args, host: &str) -> Option<(String, String)> {
    let path: std::path::PathBuf = match &args.netrc_file {
        Some(p) => p.into(),
        None => {
            let home = std::env::var_os("HOME")?;
            let mut p = std::path::PathBuf::from(home);
            p.push(".netrc");
            p
        }
    };
    let text = std::fs::read_to_string(&path).ok()?;
    netrc_lookup(&text, host)
}

/// Parse netrc text and return `(login, password)` for `host`, falling back to
/// a `default` entry. Handles `machine`/`login`/`password`/`default`, skips
/// `account`/`macdef` argument tokens.
fn netrc_lookup(text: &str, host: &str) -> Option<(String, String)> {
    let mut toks = text.split_whitespace();
    // (machine-name, login, password); "\0default" marks the default entry.
    let mut entries: Vec<(String, Option<String>, Option<String>)> = Vec::new();
    while let Some(t) = toks.next() {
        match t {
            "machine" => {
                if let Some(n) = toks.next() {
                    entries.push((n.to_string(), None, None));
                }
            }
            "default" => entries.push(("\0default".to_string(), None, None)),
            "login" => {
                if let (Some(v), Some(e)) = (toks.next(), entries.last_mut()) {
                    e.1 = Some(v.to_string());
                }
            }
            "password" => {
                if let (Some(v), Some(e)) = (toks.next(), entries.last_mut()) {
                    e.2 = Some(v.to_string());
                }
            }
            "account" | "macdef" => {
                let _ = toks.next();
            }
            _ => {}
        }
    }
    let pick = |e: &(String, Option<String>, Option<String>)| {
        (
            e.1.clone().unwrap_or_default(),
            e.2.clone().unwrap_or_default(),
        )
    };
    entries
        .iter()
        .find(|e| e.0.eq_ignore_ascii_case(host))
        .or_else(|| entries.iter().find(|e| e.0 == "\0default"))
        .map(pick)
}

/// `-J`/`--remote-header-name`: extract a safe basename from the response
/// `Content-Disposition`. The RFC 6266 `filename*=` form (RFC 8187: a
/// `charset'lang'` prefix, then percent-encoding) wins over plain `filename=`
/// wherever it appears. Only the last path component is kept (`/`, `\` and
/// `:` all separate), and
/// `.`/`..`, empty names, control characters, and Windows device names
/// (`CON`, `NUL`, `COM1`, `lpt1.txt`, ...) are rejected so a server can't pick
/// the directory or a device. `None` falls back to the URL's name.
fn content_disposition_filename(resp: &Response) -> Option<String> {
    let cd = resp.header("content-disposition")?;
    let mut plain = None;
    let mut extended = None;
    for (key, value) in content_disposition_params(cd) {
        if key.eq_ignore_ascii_case("filename*") {
            extended = extended.or_else(|| decode_ext_value(&value));
        } else if key.eq_ignore_ascii_case("filename") {
            plain = plain.or(Some(value));
        }
    }
    safe_basename(&extended.or(plain)?)
}

/// Split a `Content-Disposition` value into its `key=value` parameters,
/// honouring quoted strings (which may contain `;` and `\"` escapes).
fn content_disposition_params(cd: &str) -> Vec<(String, String)> {
    let mut params = Vec::new();
    let mut chars = cd.chars().peekable();
    // Skip the disposition type.
    for c in chars.by_ref() {
        if c == ';' {
            break;
        }
    }
    loop {
        let key: String = chars
            .by_ref()
            .take_while(|&c| c != '=')
            .collect::<String>()
            .trim()
            .to_string();
        if key.is_empty() {
            break;
        }
        while chars.next_if(|c| c.is_whitespace()).is_some() {}
        let mut value = String::new();
        if chars.next_if_eq(&'"').is_some() {
            while let Some(c) = chars.next() {
                match c {
                    '\\' => value.extend(chars.next()),
                    '"' => break,
                    c => value.push(c),
                }
            }
            for c in chars.by_ref() {
                if c == ';' {
                    break;
                }
            }
        } else {
            for c in chars.by_ref() {
                if c == ';' {
                    break;
                }
                value.push(c);
            }
            value = value.trim().to_string();
        }
        params.push((key, value));
    }
    params
}

/// Decode an RFC 8187 ext-value (`UTF-8'en'na%C3%AFve.txt`). UTF-8 and
/// ISO-8859-1 are the charsets the RFC requires; anything else is ignored.
fn decode_ext_value(v: &str) -> Option<String> {
    let mut it = v.splitn(3, '\'');
    let charset = it.next()?.trim();
    let _lang = it.next()?;
    let encoded = it.next()?;
    let mut bytes = Vec::with_capacity(encoded.len());
    let raw = encoded.as_bytes();
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'%' {
            let hex = raw.get(i + 1..i + 3)?;
            let hex = std::str::from_utf8(hex).ok()?;
            bytes.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            bytes.push(raw[i]);
            i += 1;
        }
    }
    if charset.eq_ignore_ascii_case("utf-8") {
        String::from_utf8(bytes).ok()
    } else if charset.eq_ignore_ascii_case("iso-8859-1") {
        Some(bytes.into_iter().map(char::from).collect())
    } else {
        None
    }
}

/// The last path component of a server-supplied file name, if it is safe to
/// create in the current directory on any platform.
fn safe_basename(name: &str) -> Option<String> {
    // `:` too: on Windows `C:name` is drive-relative and `name:x` an alternate
    // data stream.
    let base = name.rsplit(['/', '\\', ':']).next()?.trim();
    if base.is_empty() || base == "." || base == ".." || base.chars().any(char::is_control) {
        return None;
    }
    // Windows reserves these device names, with or without an extension.
    let stem = base.split('.').next().unwrap_or(base).trim_end();
    let upper = stem.to_ascii_uppercase();
    let is_device = matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((upper.starts_with("COM") || upper.starts_with("LPT"))
            && upper.len() == 4
            && matches!(upper.as_bytes()[3], b'1'..=b'9'));
    (!is_device).then(|| base.to_string())
}

fn next_val(it: &mut std::slice::Iter<'_, String>, flag: &str) -> Result<String, String> {
    it.next()
        .cloned()
        .ok_or_else(|| format!("{flag}{MISSING_VALUE}"))
}

/// Parse a curl time value: seconds, possibly fractional (`2.5`, `0.25`).
/// Zero means "no limit", as in curl.
fn parse_seconds(v: &str, flag: &str) -> Result<Option<Duration>, String> {
    let secs: f64 = v
        .trim()
        .parse()
        .map_err(|_| format!("{flag}: not a number: {v:?}"))?;
    let d = Duration::try_from_secs_f64(secs).map_err(|_| format!("{flag}: bad duration {v:?}"))?;
    Ok((!d.is_zero()).then_some(d))
}

/// What one `-H` argument asks for.
#[derive(Debug, PartialEq)]
enum HeaderArg {
    /// `Name: value` — send it. `Name;` sends `Name` with an empty value.
    Set(String, String),
    /// `Name:` with no value — don't send the header rsurl would add itself.
    Remove(String),
}

/// Parse a `-H` value with curl's three forms: `Name: value`, `Name:` (remove
/// an internally generated header) and `Name;` (send it empty).
fn parse_header_arg(h: &str) -> Result<HeaderArg, String> {
    let bad = || format!("malformed header: {h:?}");
    match h.split_once(':') {
        Some((k, v)) => {
            let k = k.trim();
            if k.is_empty() {
                return Err(bad());
            }
            let v = v.trim();
            Ok(if v.is_empty() {
                HeaderArg::Remove(k.to_string())
            } else {
                HeaderArg::Set(k.to_string(), v.to_string())
            })
        }
        None => match h.trim_end().strip_suffix(';') {
            Some(k) if !k.trim().is_empty() && !k.contains(';') => {
                Ok(HeaderArg::Set(k.trim().to_string(), String::new()))
            }
            _ => Err(bad()),
        },
    }
}

/// Upload a local file to an `ftp://`/`ftps://` URL. By default this is `STOR`
/// (replace/create); with `-C <offset>` the local source is seeked past
/// `offset` bytes and a `REST <offset>` is sent so the server resumes from
/// there. With `-a`/`--append` it's `APPE` instead, which appends the whole
/// file to the remote — `APPE` negotiates no offset, so `-a` takes precedence
/// over `-C` (any `-C` is ignored and the full file is streamed). Returns a
/// curl-style exit code (0 ok, 7 on transfer error, 26 on local-read error).
fn run_ftp_upload(url: &Url, path: &str, args: &Args) -> u8 {
    let bytes = match read_local(path) {
        Ok(b) => b,
        Err(e) => {
            if show_errors(args) {
                eprintln!("rsurl: -T: can't read {path:?}: {e}");
            }
            return 26;
        }
    };
    // Build a client so the upload honors -x proxy and --ftp-create-dirs.
    let client = match transfer_client(url, args) {
        Ok(c) => c,
        Err(e) => {
            if show_errors(args) {
                eprintln!("rsurl: --proxy: {e}");
            }
            return 5;
        }
    };

    // APPE wins over REST: append always streams the whole file and lets the
    // server tack it onto whatever is already there, so -C is ignored here.
    let result = if args.append {
        client.ftp_append(url, &bytes)
    } else {
        // For REST resume, only the tail past `offset` is streamed; the server
        // already holds the first `offset` bytes.
        let (body, resume_at): (&[u8], Option<u64>) = match args.continue_at {
            Some(off) => {
                let off_usize = off as usize;
                if off_usize > bytes.len() {
                    if show_errors(args) {
                        eprintln!(
                            "rsurl: -C {off}: offset is past the end of {path:?} ({} bytes)",
                            bytes.len()
                        );
                    }
                    return 2;
                }
                (&bytes[off_usize..], Some(off))
            }
            None => (&bytes[..], None),
        };
        client.ftp_store(url, body, resume_at)
    };

    match result {
        Ok(()) => 0,
        Err(e) => {
            if show_errors(args) {
                eprintln!("rsurl: {e}");
            }
            transfer_exit_code(&e)
        }
    }
}

/// Upload a local file to a `tftp://` URL via WRQ (RFC 1350 write side).
/// Returns a curl-style exit code (0 ok, 7 on transfer error, 26 on
/// local-read error).
fn run_tftp_upload(url: &Url, path: &str, args: &Args) -> u8 {
    let bytes = match read_local(path) {
        Ok(b) => b,
        Err(e) => {
            if show_errors(args) {
                eprintln!("rsurl: -T: can't read {path:?}: {e}");
            }
            return 26;
        }
    };

    // Through a client so `-x` (SOCKS5) and IPv6 servers work for uploads too.
    let client = match transfer_client(url, args) {
        Ok(c) => c,
        Err(e) => {
            if show_errors(args) {
                eprintln!("rsurl: {e}");
            }
            return 5;
        }
    };
    match client.tftp_store(url, &bytes) {
        Ok(()) => 0,
        Err(e) => {
            if show_errors(args) {
                eprintln!("rsurl: {e}");
            }
            7
        }
    }
}

/// Build the [`rsurl::ssh::SshOptions`] for an `sftp://`/`scp://` transfer from
/// the parsed CLI args and URL. The password comes from the URL userinfo, else
/// the `-u` password half; identities from `--key` (else default `~/.ssh`
/// keys); `-k` toggles accept-any host keys. An encrypted-key passphrase reuses
/// the `-u` password if one was given (a one-shot CLI can't prompt). Returns
/// `(options, user)`; a missing user is a fatal usage error (curl-style code 2).
#[cfg(feature = "ssh")]
fn build_ssh_options(url: &Url, args: &Args) -> Result<(rsurl::ssh::SshOptions, String), String> {
    let (_, url_pass) = rsurl::ssh::userinfo_password(url);
    // -u user:pass — the password half feeds both password auth and the
    // encrypted-key passphrase. The user half feeds resolve_user.
    let (cli_user, cli_pass) = match &args.basic_auth {
        Some((u, p)) => (
            (!u.is_empty()).then(|| u.clone()),
            (!p.is_empty()).then(|| p.clone()),
        ),
        None => (None, None),
    };
    let password = url_pass.or(cli_pass);
    let user = rsurl::ssh::resolve_user(url, cli_user.as_deref()).map_err(|e| e.to_string())?;
    let opts = rsurl::ssh::SshOptions {
        password: password.clone(),
        identity_files: args.ssh_keys.iter().map(std::path::PathBuf::from).collect(),
        key_passphrase: password,
        insecure: args.insecure,
        known_hosts_path: None,
        timeout: args.max_time,
    };
    Ok((opts, user))
}

/// Download an `sftp://`/`scp://` URL and write the bytes to `-o`/stdout (or
/// `-O`). Mirrors [`run_transfer`] but threads SSH auth options and, under
/// `-v`, prints the SSH trace to stderr. Exit codes: 0 ok, 2 usage, 7 transfer.
#[cfg(feature = "ssh")]
fn run_ssh(url: &Url, args: &Args) -> u8 {
    let (opts, user) = match build_ssh_options(url, args) {
        Ok(x) => x,
        Err(e) => {
            if show_errors(args) {
                eprintln!("rsurl: {e}");
            }
            return 2;
        }
    };
    let result = if args.verbose {
        let mut err = io::stderr().lock();
        rsurl::ssh::fetch_traced(url, &opts, &user, Some(&mut err))
    } else {
        rsurl::ssh::fetch(url, &opts, &user)
    };
    match result {
        Ok(bytes) => {
            let mut out: Box<dyn Write> = if args.remote_name {
                match remote_name_from_url(url) {
                    Ok(name) => match File::create(&name) {
                        Ok(f) => Box::new(f),
                        Err(e) => {
                            if show_errors(args) {
                                eprintln!("rsurl: open {name}: {e}");
                            }
                            return 23;
                        }
                    },
                    Err(e) => {
                        if show_errors(args) {
                            eprintln!("rsurl: {e}");
                        }
                        return 23;
                    }
                }
            } else {
                match &args.output {
                    Some(path) if path != "-" => match create_output_file(path, args) {
                        Ok(f) => Box::new(f),
                        Err(e) => {
                            if show_errors(args) {
                                eprintln!("rsurl: open {path}: {e}");
                            }
                            return 23;
                        }
                    },
                    _ => Box::new(io::stdout().lock()),
                }
            };
            if let Err(e) = out.write_all(&bytes) {
                if show_errors(args) {
                    eprintln!("rsurl: write error: {e}");
                }
                return 23;
            }
            0
        }
        Err(e) => {
            if show_errors(args) {
                eprintln!("rsurl: {e}");
            }
            7
        }
    }
}

/// Upload a local file to an `sftp://`/`scp://` URL. Reads the whole file into
/// memory (matching the other `-T` paths), then writes it remotely. `-v` prints
/// the SSH trace. Exit codes: 0 ok, 2 usage, 7 transfer, 26 local-read error.
#[cfg(feature = "ssh")]
fn run_ssh_upload(url: &Url, path: &str, args: &Args) -> u8 {
    let bytes = match read_local(path) {
        Ok(b) => b,
        Err(e) => {
            if show_errors(args) {
                eprintln!("rsurl: -T: can't read {path:?}: {e}");
            }
            return 26;
        }
    };
    let (opts, user) = match build_ssh_options(url, args) {
        Ok(x) => x,
        Err(e) => {
            if show_errors(args) {
                eprintln!("rsurl: {e}");
            }
            return 2;
        }
    };
    let result = if args.verbose {
        let mut err = io::stderr().lock();
        rsurl::ssh::upload_traced(url, &bytes, &opts, &user, Some(&mut err))
    } else {
        rsurl::ssh::upload(url, &bytes, &opts, &user)
    };
    match result {
        Ok(()) => 0,
        Err(e) => {
            if show_errors(args) {
                eprintln!("rsurl: {e}");
            }
            7
        }
    }
}

/// Publish to an `mqtt://`/`mqtts://` URL. The payload comes from `-T <file>`
/// (read whole) or from `-d`/`--data*` (assembled like an HTTP form body); the
/// two are mutually exclusive, matching curl. The topic is the URL path. We
/// publish at QoS 0 to match curl's default. Exit codes: 0 ok, 7 on transfer
/// error, 26 on local-read error, 2 on a usage/flag-combination error.
fn run_mqtt_publish(url: &Url, args: &Args) -> u8 {
    if args.upload_file.is_some() && !args.data_parts.is_empty() {
        if show_errors(args) {
            eprintln!("rsurl: -d/--data and -T/--upload-file are mutually exclusive");
        }
        return 2;
    }

    let payload: Vec<u8> = if let Some(path) = &args.upload_file {
        match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                if show_errors(args) {
                    eprintln!("rsurl: -T: can't read {path:?}: {e}");
                }
                return 26;
            }
        }
    } else {
        match assemble_form_body(&args.data_parts) {
            Ok(Some(b)) => b,
            Ok(None) => Vec::new(),
            Err(e) => {
                if show_errors(args) {
                    eprintln!("rsurl: {e}");
                }
                return 2;
            }
        }
    };

    // Build a client so `-x`/`--noproxy` are honoured, matching the subscribe
    // path (`run_transfer`) and every other non-HTTP scheme.
    let client = match transfer_client(url, args) {
        Ok(c) => c,
        Err(e) => {
            if show_errors(args) {
                eprintln!("rsurl: --proxy: {e}");
            }
            return 5;
        }
    };
    // curl publishes at QoS 0 by default. The protocol layer supports QoS 1
    // (PUBLISH then wait for PUBACK); there is no CLI flag to select it yet.
    match client.mqtt_publish(url, &payload, 0) {
        Ok(()) => 0,
        Err(e) => {
            if show_errors(args) {
                eprintln!("rsurl: {e}");
            }
            7
        }
    }
}

/// Drive an RTSP control-channel session. `-X`/`--request` selects the method
/// (default `DESCRIBE`). `OPTIONS`/`DESCRIBE` are single requests; selecting
/// `SETUP`/`PLAY`/`TEARDOWN` runs the full handshake on one connection
/// (`OPTIONS` → `DESCRIBE` → `SETUP` → ...) since a one-shot CLI process can't
/// carry session state between invocations — see [`rsurl::rtsp::run_method`].
/// The named method's response body is written like any other transfer.
fn run_rtsp(url: &Url, args: &Args) -> u8 {
    let method = args.method.as_deref().unwrap_or("DESCRIBE");
    match rsurl::rtsp::run_method(url, method) {
        Ok(bytes) => {
            let mut out: Box<dyn Write> = match &args.output {
                Some(path) if path != "-" => match create_output_file(path, args) {
                    Ok(f) => Box::new(f),
                    Err(e) => {
                        if show_errors(args) {
                            eprintln!("rsurl: open {path}: {e}");
                        }
                        return 23;
                    }
                },
                _ => Box::new(io::stdout().lock()),
            };
            if let Err(e) = out.write_all(&bytes) {
                if show_errors(args) {
                    eprintln!("rsurl: write error: {e}");
                }
                return 23;
            }
            0
        }
        Err(e) => {
            if show_errors(args) {
                eprintln!("rsurl: {e}");
            }
            7
        }
    }
}

/// Schemes whose backend authenticates with the URL userinfo, and so take
/// `-u user:pass` (curl applies `-u` to all of them).
const USERINFO_SCHEMES: &[&str] = &[
    "ftp", "ftps", "imap", "imaps", "pop3", "pop3s", "smtp", "smtps", "ldap", "ldaps", "mqtt",
    "mqtts",
];

/// Put `-u user:pass` into `url`'s userinfo (percent-encoded, as the backends
/// decode it) for the login-based non-HTTP schemes, replacing any userinfo
/// the URL carried — curl's precedence.
fn apply_cli_credentials(url: &mut Url, args: &Args) {
    let Some((user, pass)) = &args.basic_auth else {
        return;
    };
    if !USERINFO_SCHEMES.contains(&url.scheme.as_str()) {
        return;
    }
    let mut ui = pct_encode_userinfo(user);
    if !pass.is_empty() {
        ui.push(':');
        ui.push_str(&pct_encode_userinfo(pass));
    }
    url.userinfo = Some(ui);
}

/// Percent-encode everything but RFC 3986 unreserved characters, so `:`,
/// `@`, `%` and control bytes in a credential survive the userinfo round-trip.
fn pct_encode_userinfo(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Split URL userinfo into percent-decoded `(user, password)`.
fn decoded_userinfo(ui: &str) -> (String, Option<String>) {
    let decode = |s: &str| {
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
        String::from_utf8_lossy(&out).into_owned()
    };
    match ui.split_once(':') {
        Some((u, p)) => (decode(u), Some(decode(p))),
        None => (decode(ui), None),
    }
}

/// Build a [`rsurl::Client`] for the non-HTTP transfer path from the CLI args:
/// proxy (`-x`, incl. socks/https), no-proxy, `-k`, `--no-idn`, connect timeout.
fn transfer_client(url: &Url, args: &Args) -> rsurl::Result<rsurl::Client> {
    let mut c = rsurl::Client::new()
        .verify_tls(!args.insecure)
        .idn(!args.no_idn)
        .ftp_use_epsv(!args.disable_epsv)
        .ftp_create_dirs(args.ftp_create_dirs)
        .ftp_active(args.ftp_port.is_some())
        .require_tls(args.ssl_reqd);
    if let Some(d) = args.connect_timeout {
        c = c.connect_timeout(Some(d));
    }
    // `-m`/--max-time bounds every blocking read of the transfer, so an idle
    // stall can't outlive it. (The non-HTTP backends have no whole-transfer
    // clock; a peer trickling bytes can still exceed `-m` in total.)
    if let Some(d) = args.max_time {
        c = c.read_timeout(Some(d));
    }
    // The same TLS flags the HTTP path applies (`--cacert`, `-E`, pins, ...)
    // reach ftps/imaps/smtps/pop3s/ldaps/mqtts/gophers and STARTTLS upgrades.
    if let Some(v) = args.tls_min {
        c = c.tls_min_version(v);
    }
    if let Some(v) = args.tls_max {
        c = c.tls_max_version(v);
    }
    if let Some(path) = &args.cacert {
        c = c.ca_bundle(path);
    }
    if let Some(dir) = &args.capath {
        c = c.ca_path(dir);
    }
    if let Some(spec) = &args.pinned_pubkey {
        c = c.pinned_pubkey(spec);
    }
    if let Some(path) = &args.crl_file {
        c = c.crl_file(path);
    }
    if let Some(list) = &args.ciphers {
        c = c.ciphers(list);
    }
    if let Some(list) = &args.tls13_ciphers {
        c = c.tls13_ciphers(list);
    }
    if let Some(cert) = &args.cert {
        let (cert_path, inline_pass) = split_cert_pass(cert);
        c = c
            .client_cert(cert_path)
            .cert_type_der(args.cert_type_der)
            .key_type_der(args.key_type_der);
        if let Some(key) = &args.key_file {
            c = c.client_key(key);
        }
        if let Some(pass) = args.key_pass.as_deref().or(inline_pass) {
            c = c.client_key_pass(pass);
        }
    }
    if let Some(spec) = resolve_proxy_spec(url, args) {
        c = c.proxy(&spec)?;
    }
    c = apply_proxy_tls!(c, &args.proxy_tls);
    if let Some(list) = resolve_noproxy(args) {
        c = c.no_proxy(
            list.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect::<Vec<_>>(),
        );
    }
    if let Some(path) = &args.unix_socket {
        #[cfg(unix)]
        {
            c = c.connector(std::sync::Arc::new(rsurl::net::UnixConnector {
                path: path.into(),
            }));
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            return Err(rsurl::Error::UnsupportedScheme(
                "--unix-socket is not supported on this platform".into(),
            ));
        }
    }
    Ok(c)
}

/// Collect the WebSocket messages to send before listening. `-d`/`--data*`
/// becomes a single message (text if valid UTF-8, else binary). Otherwise, if
/// stdin is piped (not a TTY), each line becomes a text message (or the whole
/// input becomes one binary message if it is not UTF-8). A TTY with no `-d`
/// means "subscribe": send nothing and just print what arrives.
fn ws_outgoing(args: &Args) -> std::result::Result<Vec<rsurl::WsMessage>, String> {
    if !args.data_parts.is_empty() {
        let bytes = assemble_form_body(&args.data_parts)?.unwrap_or_default();
        return Ok(vec![bytes_to_ws_message(bytes)]);
    }
    if !io::stdin().is_terminal() {
        let mut buf = Vec::new();
        io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| format!("reading stdin: {e}"))?;
        if buf.is_empty() {
            return Ok(Vec::new());
        }
        return Ok(match std::str::from_utf8(&buf) {
            Ok(s) => s
                .lines()
                .map(|l| rsurl::WsMessage::Text(l.to_string()))
                .collect(),
            Err(_) => vec![rsurl::WsMessage::Binary(buf)],
        });
    }
    Ok(Vec::new())
}

fn bytes_to_ws_message(bytes: Vec<u8>) -> rsurl::WsMessage {
    match String::from_utf8(bytes) {
        Ok(s) => rsurl::WsMessage::Text(s),
        Err(e) => rsurl::WsMessage::Binary(e.into_bytes()),
    }
}

/// Drive a persistent WebSocket from the command line: open the connection,
/// send any `-d`/stdin messages, then print every message the server sends
/// until it closes (or, in send mode, until the connection goes idle past the
/// read timeout / `-m`). Incoming pings are auto-ponged by the library.
fn run_websocket(url: &Url, args: &Args) -> u8 {
    let client = match transfer_client(url, args) {
        Ok(c) => c,
        Err(e) => {
            if show_errors(args) {
                eprintln!("rsurl: --proxy: {e}");
            }
            return 5;
        }
    };

    let outgoing = match ws_outgoing(args) {
        Ok(m) => m,
        Err(e) => {
            if show_errors(args) {
                eprintln!("rsurl: {e}");
            }
            return 2;
        }
    };
    let subscribe = outgoing.is_empty();

    let mut ws = match client.websocket_url(url) {
        Ok(w) => w,
        Err(e) => {
            if show_errors(args) {
                eprintln!("rsurl: {e}");
            }
            return transfer_exit_code(&e);
        }
    };

    if args.verbose {
        let path = if url.path.is_empty() { "/" } else { &url.path };
        eprintln!(
            "* WebSocket connected to {}://{}:{}{path}",
            url.scheme, url.host, url.port
        );
        if ws.compression_enabled() {
            eprintln!("* permessage-deflate negotiated");
        }
    }

    // Send phase.
    for m in &outgoing {
        if let Err(e) = ws.send(m) {
            if show_errors(args) {
                eprintln!("rsurl: send: {e}");
            }
            return transfer_exit_code(&e);
        }
        if args.verbose {
            let kind = match m {
                rsurl::WsMessage::Text(_) => "TEXT",
                rsurl::WsMessage::Binary(_) => "BINARY",
            };
            eprintln!("* > {kind} {} bytes", m.as_bytes().len());
        }
    }

    // In send mode (we have a finite set of messages from `-d`/piped stdin),
    // signal that we are done so the server can complete the closing handshake.
    // We can still drain its replies + close echo below (send vs recv close are
    // tracked separately). Subscribe mode never sends a close — it listens.
    if !subscribe {
        let _ = ws.close();
        if args.verbose {
            eprintln!("* > CLOSE");
        }
    }

    // Receive bound: `-m`/--max-time caps the wait in either mode; otherwise
    // subscribe blocks indefinitely and send mode keeps the client's default
    // idle read timeout so the tool returns once the exchange goes quiet.
    match args.max_time {
        Some(d) => {
            let _ = ws.set_read_timeout(Some(d));
        }
        None if subscribe => {
            let _ = ws.set_read_timeout(None);
        }
        None => {}
    }

    let mut out: Box<dyn Write> = match &args.output {
        Some(path) if path != "-" => match create_output_file(path, args) {
            Ok(f) => Box::new(f),
            Err(e) => {
                if show_errors(args) {
                    eprintln!("rsurl: open {path}: {e}");
                }
                return 23;
            }
        },
        _ => Box::new(io::stdout().lock()),
    };

    let mut code = 0u8;
    loop {
        match ws.recv_event() {
            Ok(rsurl::WsEvent::Text(t)) => {
                let _ = out.write_all(t.as_bytes());
                let _ = out.write_all(b"\n");
                let _ = out.flush();
            }
            Ok(rsurl::WsEvent::Binary(b)) => {
                let _ = out.write_all(&b);
                let _ = out.flush();
            }
            Ok(rsurl::WsEvent::Ping(_)) => {
                if args.verbose {
                    eprintln!("* < PING (auto-pong sent)");
                }
            }
            Ok(rsurl::WsEvent::Pong(_)) => {
                if args.verbose {
                    eprintln!("* < PONG");
                }
            }
            Ok(rsurl::WsEvent::Close(c)) => {
                if args.verbose {
                    match c {
                        Some(cl) => eprintln!("* < CLOSE {} {}", cl.code, cl.reason),
                        None => eprintln!("* < CLOSE"),
                    }
                }
                break;
            }
            // An idle read timeout (or, in send mode, the default) ends the
            // session cleanly rather than as an error.
            Err(rsurl::Error::Io(e))
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                if args.verbose {
                    eprintln!("* idle, closing");
                }
                break;
            }
            // Server dropped the TCP connection without a close frame.
            Err(rsurl::Error::UnexpectedEof) => break,
            Err(e) => {
                if show_errors(args) {
                    eprintln!("rsurl: {e}");
                }
                code = transfer_exit_code(&e);
                break;
            }
        }
    }

    let _ = ws.close();
    code
}

/// Send a message over SMTP/SMTPS: `--mail-from`, `--mail-rcpt` (repeatable),
/// and the body from `-T file` or `-d`.
fn run_smtp(url: &Url, args: &Args) -> u8 {
    let Some(from) = args.mail_from.as_deref() else {
        if show_errors(args) {
            eprintln!("rsurl: smtp requires --mail-from");
        }
        return 2;
    };
    if args.mail_rcpt.is_empty() {
        if show_errors(args) {
            eprintln!("rsurl: smtp requires at least one --mail-rcpt");
        }
        return 2;
    }
    let body: Vec<u8> = if let Some(path) = &args.upload_file {
        match read_local(path) {
            Ok(b) => b,
            Err(e) => {
                if show_errors(args) {
                    eprintln!("rsurl: read {path}: {e}");
                }
                return 2;
            }
        }
    } else if !args.data_parts.is_empty() {
        match assemble_request_body(args) {
            Ok(Some((b, _, _))) => b,
            _ => Vec::new(),
        }
    } else {
        if show_errors(args) {
            eprintln!("rsurl: smtp needs a message body (-T <file> or -d)");
        }
        return 2;
    };
    // URL userinfo is percent-encoded (`-u` was folded into it, encoded, by
    // `apply_cli_credentials`); `smtp_send` takes the raw credentials.
    let (user, pass) = match url.userinfo.as_deref() {
        Some(ui) => {
            let (u, p) = decoded_userinfo(ui);
            (Some(u), p)
        }
        None => (None, None),
    };
    let client = match transfer_client(url, args) {
        Ok(c) => c,
        Err(e) => {
            if show_errors(args) {
                eprintln!("rsurl: {e}");
            }
            return 5;
        }
    };
    match client.smtp_send(
        url,
        &body,
        from,
        &args.mail_rcpt,
        user.as_deref(),
        pass.as_deref(),
    ) {
        Ok(()) => 0,
        Err(e) => {
            if show_errors(args) {
                eprintln!("rsurl: {e}");
            }
            7
        }
    }
}

/// TELNET: connect, send any `-d`/`-T` input, write received data to output.
fn run_telnet(url: &Url, args: &Args) -> u8 {
    let input: Vec<u8> = if let Some(path) = &args.upload_file {
        read_local(path).unwrap_or_default()
    } else if !args.data_parts.is_empty() {
        assemble_request_body(args)
            .ok()
            .flatten()
            .map(|(b, _, _)| b)
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let client = match transfer_client(url, args) {
        Ok(c) => c,
        Err(e) => {
            if show_errors(args) {
                eprintln!("rsurl: {e}");
            }
            return 5;
        }
    };
    match client.telnet(url, &input) {
        Ok(bytes) => {
            let mut out: Box<dyn Write> = match &args.output {
                Some(path) if path != "-" => match create_output_file(path, args) {
                    Ok(f) => Box::new(f),
                    Err(e) => {
                        if show_errors(args) {
                            eprintln!("rsurl: open {path}: {e}");
                        }
                        return 23;
                    }
                },
                _ => Box::new(io::stdout().lock()),
            };
            if out.write_all(&bytes).is_err() {
                return 23;
            }
            0
        }
        Err(e) => {
            if show_errors(args) {
                eprintln!("rsurl: {e}");
            }
            7
        }
    }
}

fn run_transfer(url: &Url, args: &Args) -> u8 {
    // `url` is already IDN-normalised by `process_url`; dispatch the parsed URL
    // directly so the host the caller chose (and `--no-idn`) is honoured. The
    // client carries any `-x` proxy / `--noproxy` so non-HTTP schemes honour
    // them too.
    let client = match transfer_client(url, args) {
        Ok(c) => c,
        Err(e) => {
            if show_errors(args) {
                eprintln!("rsurl: --proxy: {e}");
            }
            return 5;
        }
    };
    match client.transfer_url(url) {
        Ok(bytes) => {
            let mut out: Box<dyn Write> = match &args.output {
                Some(path) if path != "-" => match create_output_file(path, args) {
                    Ok(f) => Box::new(f),
                    Err(e) => {
                        if show_errors(args) {
                            eprintln!("rsurl: open {path}: {e}");
                        }
                        return 23;
                    }
                },
                _ => Box::new(io::stdout().lock()),
            };
            if let Err(e) = out.write_all(&bytes) {
                if show_errors(args) {
                    eprintln!("rsurl: write error: {e}");
                }
                return 23;
            }
            0
        }
        Err(e) => {
            if show_errors(args) {
                eprintln!("rsurl: {e}");
            }
            transfer_exit_code(&e)
        }
    }
}

/// Streaming non-HTTP download to a file: writes the payload through a
/// [`DownloadSink`], so `--limit-rate`, `-#`, `--max-filesize`, `-y`/`-Y`,
/// `--no-clobber`, and `--remove-on-error` all apply. FTP/FTPS and file://
/// stream the source directly (no full-body buffer); other schemes fetch then
/// write through the same sink, so the flags still take effect.
fn run_stream_download(url: &Url, args: &Args) -> u8 {
    let client = match transfer_client(url, args) {
        Ok(c) => c,
        Err(e) => {
            if show_errors(args) {
                eprintln!("rsurl: --proxy: {e}");
            }
            return 5;
        }
    };
    let name = if args.remote_name {
        match remote_name_from_url(url) {
            Ok(n) => n,
            Err(e) => {
                if show_errors(args) {
                    eprintln!("rsurl: {e}");
                }
                return 23;
            }
        }
    } else {
        args.output.clone().unwrap_or_default()
    };
    let (file, out_path) = match create_output_file_tracked(&name, args) {
        Ok(pair) => pair,
        Err(e) => {
            if show_errors(args) {
                eprintln!("rsurl: open {name}: {e}");
            }
            return 23;
        }
    };
    let (speed_limit, speed_time) = low_speed_params(args);
    let now = std::time::Instant::now();
    let mut sink = DownloadSink {
        inner: Box::new(file),
        written: 0,
        max: args.max_filesize,
        rate: args.limit_rate.as_deref().and_then(parse_rate),
        speed_limit,
        speed_time,
        started: now,
        progress: args.progress_bar,
        silent: args.silent,
        last_tick: now,
    };
    let result = client.transfer_url_to(url, &mut sink);
    let time_total = now.elapsed();
    let written = sink.written;
    if args.progress_bar && !args.silent {
        eprintln!();
    }
    match result {
        Ok(_) => {
            // Non-HTTP schemes have no HTTP response, but curl still honors -w:
            // report %{size_download}, %{time_total}, %{url_effective}, etc.
            // against a synthetic empty response (http_code renders 0, as curl
            // does for non-HTTP transfers).
            if args.write_out.is_some() {
                let resp = rsurl::Response {
                    status: 0,
                    reason: String::new(),
                    version: String::new(),
                    headers: Vec::new(),
                    body: Vec::new(),
                    timing: rsurl::Timing::default(),
                    final_url: String::new(),
                    tls: None,
                };
                run_write_out(&resp, url, args, time_total, written);
            }
            0
        }
        Err(e) => {
            if args.remove_on_error {
                drop(sink);
                let _ = std::fs::remove_file(&out_path);
            }
            if e.to_string().contains(MAX_FILESIZE_SENTINEL) {
                if show_errors(args) {
                    eprintln!("rsurl: Maximum file size exceeded");
                }
                return 63;
            }
            if e.to_string().contains(LOW_SPEED_SENTINEL) {
                if show_errors(args) {
                    eprintln!(
                        "rsurl: Operation too slow. Less than {} bytes/sec transferred \
                         the last {speed_time} seconds",
                        speed_limit.unwrap_or(1)
                    );
                }
                return 28;
            }
            if show_errors(args) {
                eprintln!("rsurl: {e}");
            }
            transfer_exit_code(&e)
        }
    }
}

/// Replace bytes/characters that could drive a terminal emulator with a visible
/// `\xHH` escape, so attacker-controlled server data printed to a TTY cannot
/// inject ANSI/OSC control sequences (cursor moves, screen clear, OSC 52
/// clipboard write, window-title set, etc.) — the classic "curl into a
/// terminal" attack.
///
/// The input is interpreted as UTF-8 so that multi-byte characters survive
/// intact (their continuation bytes live in 0x80–0xBF and must NOT be escaped
/// individually). Neutralized: C0 control codepoints `< 0x20` (except `\t`,
/// which is preserved; `\r`/`\n` are added by the caller, not present in the
/// data passed here), `DEL` (0x7f), and the C1 control range `0x80`–`0x9f`.
/// Any byte that is not valid UTF-8 is escaped as `\xHH` as well. Printable
/// ASCII and ordinary (multi-byte) UTF-8 text pass through unchanged.
fn sanitize_for_tty(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut rest = bytes;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                push_sanitized_str(s, &mut out);
                break;
            }
            Err(e) => {
                // Valid prefix up to the error: sanitize as UTF-8 text.
                let valid_up_to = e.valid_up_to();
                if valid_up_to > 0 {
                    // SAFETY: bytes[..valid_up_to] is valid UTF-8 per the error.
                    let s = unsafe { std::str::from_utf8_unchecked(&rest[..valid_up_to]) };
                    push_sanitized_str(s, &mut out);
                }
                // Escape every byte of the invalid sequence as raw \xHH.
                let bad = e.error_len().unwrap_or(1);
                for &b in &rest[valid_up_to..valid_up_to + bad] {
                    out.extend_from_slice(format!("\\x{b:02x}").as_bytes());
                }
                rest = &rest[valid_up_to + bad..];
            }
        }
    }
    out
}

/// Append `s` to `out`, replacing terminal-control codepoints with `\xHH`.
fn push_sanitized_str(s: &str, out: &mut Vec<u8>) {
    for ch in s.chars() {
        let cp = ch as u32;
        let dangerous = (cp < 0x20 && ch != '\t') || (0x7f..=0x9f).contains(&cp);
        if dangerous {
            out.extend_from_slice(format!("\\x{cp:02x}").as_bytes());
        } else {
            let mut buf = [0u8; 4];
            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
        }
    }
}

/// Heuristic mirroring curl's: treat a body as "binary" (unsafe to dump raw to
/// a terminal) if it contains a NUL byte. NUL is the canonical signal curl uses
/// for "this is not text"; refusing on it covers images, archives, executables,
/// etc. while leaving ordinary UTF-8/text bodies alone.
fn body_looks_binary(body: &[u8]) -> bool {
    body.contains(&0)
}

/// `-w`/`--write-out`: render `args.write_out` to stdout after a transfer,
/// expanding `%{var}` variables and `\n`/`\t`/`\r`/`\\` escapes. `time_total`
/// is measured around the request. Variables we don't (yet) compute expand to
/// an empty string, matching curl's treatment of unknown names.
/// Format a phase duration as curl's fixed `%.6f` seconds; an unmeasured phase
/// (`None`) renders as `0.000000`, matching curl.
fn fmt_secs(d: Option<std::time::Duration>) -> String {
    format!("{:.6}", d.map_or(0.0, |d| d.as_secs_f64()))
}

fn run_write_out(
    resp: &Response,
    url: &Url,
    args: &Args,
    time_total: std::time::Duration,
    size_download: u64,
) {
    run_write_out_code(resp, url, args, time_total, size_download, 0, "");
}

/// `-w` after a transfer that failed before producing a response: curl still
/// renders the format, with `%{http_code}` as `000` and `%{exitcode}` /
/// `%{errormsg}` describing the failure (health checks rely on this).
fn write_out_failure(url: &Url, args: &Args, elapsed: std::time::Duration, code: u8, msg: &str) {
    if args.write_out.is_none() {
        return;
    }
    let resp = Response {
        status: 0,
        reason: String::new(),
        version: String::new(),
        headers: Vec::new(),
        body: Vec::new(),
        timing: rsurl::Timing::default(),
        final_url: String::new(),
        tls: None,
    };
    run_write_out_code(&resp, url, args, elapsed, 0, code, msg);
}

/// [`run_write_out`] with the transfer's curl exit code and error message,
/// for `%{exitcode}` / `%{errormsg}`.
fn run_write_out_code(
    resp: &Response,
    url: &Url,
    args: &Args,
    time_total: std::time::Duration,
    size_download: u64,
    exitcode: u8,
    errormsg: &str,
) {
    let Some(fmt) = &args.write_out else { return };
    let size_header: usize = resp
        .headers
        .iter()
        .map(|(k, v)| k.len() + v.len() + 4)
        .sum::<usize>()
        + resp.version.len()
        + resp.reason.len()
        + 6;
    let var = |name: &str| -> String {
        match name {
            // curl prints the code zero-padded: `000` when there was none.
            "http_code" | "response_code" => format!("{:03}", resp.status),
            "exitcode" => exitcode.to_string(),
            "errormsg" => errormsg.to_string(),
            "http_version" => resp.version.clone(),
            "size_download" => size_download.to_string(),
            "size_header" => size_header.to_string(),
            "num_headers" => resp.headers.len().to_string(),
            "content_type" => resp.header("content-type").unwrap_or("").to_string(),
            // We only reach write-out after a successful transfer; a TLS
            // verification failure aborts earlier, so this is always 0 (curl
            // also reports 0 for non-TLS schemes).
            "ssl_verify_result" => "0".to_string(),
            // After -L this is the final URL, not the one requested.
            "url_effective" if !resp.final_url.is_empty() => resp.final_url.clone(),
            "url" | "url_effective" => url_to_display(url),
            "scheme" => url.scheme.to_uppercase(),
            "time_total" => format!("{:.6}", time_total.as_secs_f64()),
            // Phase timers (HTTP/1.1 + HTTPS direct paths). An unmeasured phase
            // — pooled reuse, HTTP/2, HTTP/3 — renders as 0.000000, as curl does.
            "time_namelookup" => fmt_secs(None), // DNS isn't timed separately
            "time_connect" => fmt_secs(resp.timing.connect),
            "time_appconnect" => fmt_secs(resp.timing.appconnect),
            "time_pretransfer" => fmt_secs(resp.timing.pretransfer),
            "time_starttransfer" => fmt_secs(resp.timing.starttransfer),
            _ => String::new(),
        }
    };

    let mut out = String::with_capacity(fmt.len());
    let mut chars = fmt.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '%' => match chars.peek().copied() {
                Some('{') => {
                    chars.next();
                    let mut name = String::new();
                    for nc in chars.by_ref() {
                        if nc == '}' {
                            break;
                        }
                        name.push(nc);
                    }
                    out.push_str(&var(&name));
                }
                Some('%') => {
                    chars.next();
                    out.push('%');
                }
                // %header{Name}: emit a named response header (curl 7.84+).
                _ if chars.clone().take(7).collect::<String>() == "header{" => {
                    for _ in 0..7 {
                        chars.next();
                    }
                    let mut name = String::new();
                    for nc in chars.by_ref() {
                        if nc == '}' {
                            break;
                        }
                        name.push(nc);
                    }
                    out.push_str(resp.header(name.trim()).unwrap_or(""));
                }
                _ => out.push('%'),
            },
            '\\' => match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            },
            other => out.push(other),
        }
    }
    print!("{out}");
    let _ = io::stdout().flush();
}

/// `scheme://host[:port]/path` for `-w`, omitting the scheme's default port.
fn url_to_display(url: &Url) -> String {
    let default = matches!(
        (url.scheme.as_str(), url.port),
        ("http", 80) | ("https", 443)
    );
    if default {
        format!("{}://{}{}", url.scheme, url.host, url.path)
    } else {
        format!("{}://{}:{}{}", url.scheme, url.host, url.port, url.path)
    }
}

/// Parse an HTTP-date (RFC 1123, `Sun, 06 Nov 1994 08:49:37 GMT`) to a Unix
/// epoch. Returns `None` for anything it can't parse. GMT is assumed.
fn httpdate_to_epoch(s: &str) -> Option<u64> {
    let rest = s
        .trim()
        .split_once(", ")
        .map(|(_, r)| r)
        .unwrap_or(s.trim());
    let mut it = rest.split_whitespace();
    let day: i64 = it.next()?.parse().ok()?;
    let mon: i64 = match it.next()? {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year: i64 = it.next()?.parse().ok()?;
    let mut hms = it.next()?.split(':');
    let hh: i64 = hms.next()?.parse().ok()?;
    let mm: i64 = hms.next()?.parse().ok()?;
    let ss: i64 = hms.next()?.parse().ok()?;
    // Days from civil date (Howard Hinnant's algorithm).
    let y = if mon <= 2 { year - 1 } else { year };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if mon > 2 { mon - 3 } else { mon + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let secs = days * 86400 + hh * 3600 + mm * 60 + ss;
    u64::try_from(secs).ok()
}

/// Format a Unix epoch as an IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`).
fn epoch_to_httpdate(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let rem = (secs % 86400) as i64;
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let wd = (days % 7 + 4).rem_euclid(7); // 1970-01-01 was Thursday (4)
                                           // Civil date from days since epoch (Howard Hinnant).
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
    const WD: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MON: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        WD[wd as usize],
        d,
        MON[(m - 1) as usize],
        year,
        hh,
        mm,
        ss
    )
}

/// Build the conditional-request header for `-z`/`--time-cond`. A leading `-`
/// selects `If-Unmodified-Since`; a value naming an existing file uses its
/// mtime, otherwise it is treated as a literal HTTP-date.
fn time_cond_header(spec: &str) -> Option<(&'static str, String)> {
    let (unmod, body) = match spec.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, spec.strip_prefix('+').unwrap_or(spec)),
    };
    let date = match std::fs::metadata(body).and_then(|m| m.modified()) {
        Ok(mtime) => {
            let secs = mtime.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
            epoch_to_httpdate(secs)
        }
        Err(_) => body.trim().to_string(),
    };
    if date.is_empty() {
        return None;
    }
    Some((
        if unmod {
            "If-Unmodified-Since"
        } else {
            "If-Modified-Since"
        },
        date,
    ))
}

/// Evaluate curl's `--proto` spec against a scheme. Tokens are comma-separated
/// with optional `+`/`-`/`=` prefixes (`=` resets the set); `all` is a keyword.
fn proto_allowed(scheme: &str, spec: &str) -> bool {
    const ALL: &[&str] = &[
        "http", "https", "ftp", "ftps", "sftp", "scp", "imap", "imaps", "pop3", "pop3s", "smtp",
        "smtps", "mqtt", "mqtts", "rtsp", "tftp", "ldap", "ldaps", "gopher", "gophers", "dict",
        "file", "ws", "wss", "telnet",
    ];
    let mut set: std::collections::HashSet<String> = ALL.iter().map(|s| s.to_string()).collect();
    for tok in spec.split(',') {
        let tok = tok.trim();
        if tok.is_empty() {
            continue;
        }
        let (op, name) = match tok.as_bytes()[0] {
            b'=' => ('=', &tok[1..]),
            b'+' => ('+', &tok[1..]),
            b'-' => ('-', &tok[1..]),
            _ => ('+', tok),
        };
        let names: Vec<String> = if name == "all" {
            ALL.iter().map(|s| s.to_string()).collect()
        } else {
            vec![name.to_ascii_lowercase()]
        };
        match op {
            '=' => {
                set.clear();
                set.extend(names);
            }
            '+' => set.extend(names),
            '-' => {
                for n in names {
                    set.remove(&n);
                }
            }
            _ => {}
        }
    }
    set.contains(&scheme.to_ascii_lowercase())
}

/// Parse a curl `--limit-rate` value (`1000`, `2k`, `3M`, `1G`) to bytes/sec.
fn parse_rate(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, mult): (&str, u64) = match s.chars().last() {
        Some('k') | Some('K') => (&s[..s.len() - 1], 1024),
        Some('m') | Some('M') => (&s[..s.len() - 1], 1024 * 1024),
        Some('g') | Some('G') => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        _ => (s, 1),
    };
    num.trim()
        .parse::<u64>()
        .ok()
        .map(|n| n.saturating_mul(mult))
}

/// Sentinel in the io::Error message used to signal an exceeded `--max-filesize`
/// across the `send_download` boundary.
const MAX_FILESIZE_SENTINEL: &str = "rsurl-max-filesize-exceeded";

/// Sentinel in the io::Error message used to signal a `-y/-Y` low-speed abort
/// across the `send_download` boundary (maps to curl exit 28).
const LOW_SPEED_SENTINEL: &str = "rsurl-low-speed-abort";

/// A write sink for streamed downloads: enforces `--max-filesize` (early
/// abort), `--limit-rate` (paced writes), `-y/-Y` (low-speed abort), and `-#`
/// progress, and counts bytes for `-w %{size_download}`.
struct DownloadSink<'a> {
    inner: Box<dyn Write + 'a>,
    written: u64,
    max: Option<u64>,
    rate: Option<u64>,
    /// `-Y` minimum average bytes/sec, enforced once `speed_time` has elapsed.
    speed_limit: Option<u64>,
    /// `-y` window in seconds before the low-speed check arms.
    speed_time: u64,
    started: std::time::Instant,
    progress: bool,
    silent: bool,
    last_tick: std::time::Instant,
}

impl Write for DownloadSink<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(max) = self.max {
            if self.written + buf.len() as u64 > max {
                return Err(io::Error::other(MAX_FILESIZE_SENTINEL));
            }
        }
        if let Some(rate) = self.rate.filter(|r| *r > 0) {
            let target = std::time::Duration::from_secs_f64(
                (self.written + buf.len() as u64) as f64 / rate as f64,
            );
            let elapsed = self.started.elapsed();
            if target > elapsed {
                std::thread::sleep(target - elapsed);
            }
        }
        self.inner.write_all(buf)?;
        self.written += buf.len() as u64;
        if let Some(limit) = self.speed_limit {
            let secs = self.started.elapsed().as_secs();
            if secs >= self.speed_time && self.written / secs.max(1) < limit {
                return Err(io::Error::other(LOW_SPEED_SENTINEL));
            }
        }
        if self.progress
            && !self.silent
            && self.last_tick.elapsed() >= std::time::Duration::from_millis(100)
        {
            eprint!("\rrsurl: {} bytes received", self.written);
            let _ = io::stderr().flush();
            self.last_tick = std::time::Instant::now();
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Streaming HTTP download to a file: enforces `--limit-rate`/`-#`/
/// `--max-filesize` and avoids buffering the whole body in memory.
/// CLI-level gate for segmented parallel download (before any network probe).
/// `--parallel-segments n>1` and none of the features that constrain the byte
/// range or the write path (resume, user range, rate limits, upload).
fn parallel_segments_eligible(args: &Args) -> bool {
    args.parallel_segments.is_some_and(|n| n > 1)
        && args.continue_at.is_none()
        && args.range.is_none()
        && args.limit_rate.is_none()
        && args.speed_limit.is_none()
        && args.speed_time.is_none()
        && args.upload_file.is_none()
}

/// Hard cap on concurrent segments regardless of `--parallel-segments`.
const MAX_SEGMENTS: usize = 16;
/// Chunks per connection in `--parallel-segments` mode. Splitting into more
/// chunks than there are connections lets a fast connection pick up extra work
/// while a slow one is still busy; with exactly one chunk each, the transfer
/// can only finish as fast as its slowest segment, which shows up as a crawling
/// last few percent while every other connection sits idle. The download engine
/// clamps the count so chunks never fall below its 1 MiB floor, so a small file
/// is still split into just a few parts.
const SEGMENT_OVERSUBSCRIBE: usize = 4;

/// Format a byte count like `12.3 MiB`.
#[cfg(feature = "bittorrent")]
fn human_bytes(b: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{b} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

/// Size of a resumable parallel download's fixed chunk (the bitmap unit).
const RESUME_CHUNK: u64 = 4 * 1024 * 1024;

/// Lower-hex encoding of bytes.
#[cfg(feature = "bittorrent")]
fn bytes_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// Escape a string for embedding in a JSON double-quoted value.
#[cfg(feature = "bittorrent")]
fn json_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

/// Render torrent metadata as JSON, including each file's computed byte offset.
#[cfg(feature = "bittorrent")]
fn metadata_json(meta: &rsurl::bittorrent::Metainfo) -> String {
    let mut o = String::new();
    o.push_str("{\n");
    o.push_str(&format!("  \"name\": \"{}\",\n", json_escape(&meta.name)));
    o.push_str(&format!(
        "  \"info_hash\": \"{}\",\n",
        bytes_hex(&meta.info_hash)
    ));
    o.push_str(&format!("  \"piece_length\": {},\n", meta.piece_length));
    o.push_str(&format!("  \"num_pieces\": {},\n", meta.num_pieces()));
    o.push_str(&format!("  \"total_length\": {},\n", meta.total_length));
    o.push_str(&format!("  \"private\": {},\n", meta.private));
    o.push_str("  \"trackers\": [");
    for (i, t) in meta.trackers.iter().enumerate() {
        if i > 0 {
            o.push_str(", ");
        }
        o.push_str(&format!("\"{}\"", json_escape(t)));
    }
    o.push_str("],\n");
    o.push_str("  \"files\": [\n");
    let mut off = 0u64;
    let mut first = true;
    for f in &meta.files {
        // BEP 47 padding files are alignment filler, never real content: omit
        // them from the listing but keep counting their bytes in `offset`.
        if f.padding {
            off += f.length;
            continue;
        }
        if !first {
            o.push_str(",\n");
        }
        first = false;
        o.push_str(&format!(
            "    {{\"path\": \"{}\", \"length\": {}, \"offset\": {}}}",
            // Canonical forward-slash path regardless of OS separator.
            json_escape(&f.path.to_string_lossy().replace('\\', "/")),
            f.length,
            off
        ));
        off += f.length;
    }
    o.push_str("\n  ]\n}\n");
    o
}

/// Build a minimal `.torrent` from raw `info` bytes and the magnet's trackers,
/// splicing the verified `info` bytes verbatim so the infohash is preserved.
/// Keys are emitted in canonical bencode order (announce < announce-list < info).
#[cfg(feature = "bittorrent")]
fn build_torrent(info: &[u8], trackers: &[String]) -> Vec<u8> {
    let mut out = Vec::with_capacity(info.len() + 64);
    out.push(b'd');
    if let Some(first) = trackers.first() {
        out.extend_from_slice(b"8:announce");
        out.extend_from_slice(format!("{}:", first.len()).as_bytes());
        out.extend_from_slice(first.as_bytes());
    }
    if !trackers.is_empty() {
        out.extend_from_slice(b"13:announce-list");
        out.push(b'l'); // tiers
        for t in trackers {
            out.push(b'l'); // one tracker per tier
            out.extend_from_slice(format!("{}:", t.len()).as_bytes());
            out.extend_from_slice(t.as_bytes());
            out.push(b'e');
        }
        out.push(b'e');
    }
    out.extend_from_slice(b"4:info");
    out.extend_from_slice(info);
    out.push(b'e');
    out
}

/// Write the `.torrent` bytes to `-o` (else stdout) for `--bt-save-torrent`.
#[cfg(feature = "bittorrent")]
fn bt_write_torrent(bytes: &[u8], args: &Args) -> u8 {
    if let Some(o) = args.output.as_deref().filter(|p| *p != "-") {
        let path = resolve_output_path(o, args);
        match std::fs::write(&path, bytes) {
            Ok(_) => 0,
            Err(e) => {
                if show_errors(args) {
                    eprintln!("rsurl: write {}: {e}", path.display());
                }
                23
            }
        }
    } else {
        match io::stdout().write_all(bytes) {
            Ok(_) => 0,
            Err(e) => {
                if show_errors(args) {
                    eprintln!("rsurl: {e}");
                }
                23
            }
        }
    }
}

/// Resolve a `--bt-file <N|path>` selector to `(index, global_offset, length)`.
/// Accepts a 1-based index, an exact path, a file name, or a path suffix.
#[cfg(feature = "bittorrent")]
fn bt_resolve_file(
    meta: &rsurl::bittorrent::Metainfo,
    sel: &str,
) -> std::result::Result<(usize, u64, u64), String> {
    // Number and match only real files: BEP 47 padding entries are hidden
    // (as in `--bt-info`), so `--bt-file N` means the Nth listed file. The
    // offset below still sums every entry, padding included.
    let real: Vec<usize> = (0..meta.files.len())
        .filter(|&i| !meta.files[i].padding)
        .collect();
    let idx = match sel.parse::<usize>() {
        Ok(n) if n >= 1 && n <= real.len() => Some(real[n - 1]),
        _ => {
            let sel = sel.replace('\\', "/"); // canonical, cross-platform
            real.iter().copied().find(|&i| {
                let f = &meta.files[i];
                let p = f.path.to_string_lossy().replace('\\', "/");
                p == sel
                    || f.path.file_name().and_then(|n| n.to_str()) == Some(sel.as_str())
                    || p.ends_with(&sel)
            })
        }
    };
    match idx {
        Some(i) => {
            let offset: u64 = meta.files[..i].iter().map(|f| f.length).sum();
            Ok((i, offset, meta.files[i].length))
        }
        None => Err(format!(
            "--bt-file: no file matching {sel:?} (torrent has {} file(s); use --bt-info to list them)",
            real.len()
        )),
    }
}

/// Resolve the on-disk file layout for a torrent given the CLI output flags.
/// Per rsurl policy, a download requires an explicit target.
#[cfg(feature = "bittorrent")]
fn bt_layout(
    meta: &rsurl::bittorrent::Metainfo,
    args: &Args,
) -> std::result::Result<Vec<(std::path::PathBuf, u64)>, String> {
    use std::path::Path;
    // `--bt-concat`: the whole linear space as one file (a metadata-aware
    // consumer seeks within it). This is just a single-file layout.
    if args.bt_concat {
        return match args.output.as_deref().filter(|p| *p != "-") {
            Some(o) => Ok(vec![(resolve_output_path(o, args), meta.total_length)]),
            None => Err("--bt-concat needs -o <file>".into()),
        };
    }
    if meta.files.len() == 1 {
        if let Some(o) = args.output.as_deref().filter(|p| *p != "-") {
            let p = resolve_output_path(o, args);
            // `-o <dir>` (e.g. `-o .`): place the file inside the directory
            // rather than treating the directory itself as the target file.
            if p.is_dir() {
                Ok(rsurl::bittorrent::file_layout(meta, &p))
            } else {
                Ok(vec![(p, meta.files[0].length)])
            }
        } else if let Some(dir) = &args.output_dir {
            Ok(rsurl::bittorrent::file_layout(meta, Path::new(dir)))
        } else {
            Err("torrent download needs -o <file> or --output-dir <dir>".into())
        }
    } else if let Some(dir) = &args.output_dir {
        Ok(rsurl::bittorrent::file_layout(meta, Path::new(dir)))
    } else {
        Err("multi-file torrent needs --output-dir <dir>".into())
    }
}

/// Announce to the given trackers (stopping at the first that yields peers)
/// and return the peer addresses found.
#[cfg(feature = "bittorrent")]
#[allow(clippy::too_many_arguments)]
fn bt_announce_peers(
    trackers: &[String],
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    key: u32,
    port: u16,
    left: u64,
    verbose: bool,
) -> Vec<std::net::SocketAddr> {
    use rsurl::bittorrent::tracker::{self, AnnounceParams, Event};
    use std::time::Duration;

    let params = AnnounceParams {
        info_hash,
        peer_id,
        port,
        uploaded: 0,
        downloaded: 0,
        left,
        event: Event::Started,
        num_want: 100,
        key,
    };
    let mut peers = Vec::new();
    for t in trackers {
        match tracker::announce(t, &params, Duration::from_secs(10)) {
            Ok(resp) => {
                if verbose {
                    eprintln!("* tracker {t}: {} peers", resp.peers.len());
                }
                peers.extend(resp.peers);
            }
            Err(e) => {
                if verbose {
                    eprintln!("* tracker {t}: {e}");
                }
            }
        }
        if !peers.is_empty() {
            break; // one responsive tracker is enough to start
        }
    }
    peers
}

/// Fall back to the DHT: resolve the built-in bootstrap nodes and run an
/// iterative `get_peers` lookup for `info_hash`. Returns any peers found.
#[cfg(feature = "bittorrent")]
fn bt_dht_peers(info_hash: [u8; 20], verbose: bool) -> Vec<std::net::SocketAddr> {
    use rsurl::bittorrent::dht;
    use std::time::Duration;

    let bootstrap = dht::default_bootstrap();
    if bootstrap.is_empty() {
        if verbose {
            eprintln!("* dht: no bootstrap nodes resolved");
        }
        return Vec::new();
    }
    let node_id = dht::random_node_id();
    match dht::find_peers(info_hash, &bootstrap, node_id, Duration::from_secs(20)) {
        Ok(peers) => {
            if verbose {
                eprintln!("* dht: found {} peers", peers.len());
            }
            peers
        }
        Err(e) => {
            if verbose {
                eprintln!("* dht: {e}");
            }
            Vec::new()
        }
    }
}

/// Download a torrent: load its metainfo (`.torrent` from a path/`file://`/
/// `http(s)://`, or a `magnet:` link), discover peers (manual `--bt-peer` +
/// trackers + DHT), and fetch + verify the data. Exits when complete (curl-like).
#[cfg(feature = "bittorrent")]
fn run_bittorrent(source: &str, args: &Args) -> u8 {
    use rsurl::bittorrent::{self, metadata, Magnet, Metainfo, SeedMode, TorrentOptions};
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};

    let peer_id = match bittorrent::generate_peer_id() {
        Ok(p) => p,
        Err(e) => {
            if show_errors(args) {
                eprintln!("rsurl: {e}");
            }
            return 1;
        }
    };
    // The tracker `key`: a random per-session value (like other clients) that
    // lets a tracker recognise us across IP changes. Drawn independently of
    // the peer id, which other peers see.
    let announce_key = match bittorrent::generate_peer_id() {
        Ok(id) => u32::from_be_bytes([id[16], id[17], id[18], id[19]]),
        Err(e) => {
            if show_errors(args) {
                eprintln!("rsurl: {e}");
            }
            return 1;
        }
    };
    let listen_port = args.listen_port.unwrap_or(6881);
    // --share-ratio implies seeding to that ratio; --seed alone seeds forever.
    let seed = match (args.share_ratio, args.seed) {
        (Some(r), _) => SeedMode::UntilRatio(r),
        (None, true) => SeedMode::Forever,
        (None, false) => SeedMode::Off,
    };
    // Bind the seed socket now, before any tracker announce — not when the
    // download finishes. Seeding is the only thing that listens, so binding
    // late leaves the port unowned for the whole download: another process can
    // take it, and with `--listen-port 0` there is no way to learn the
    // OS-assigned port in time to announce or report it. Holding it from the
    // start makes both correct.
    let seed_listener = if seed == SeedMode::Off {
        None
    } else {
        match std::net::TcpListener::bind(("0.0.0.0", listen_port)) {
            Ok(l) => Some(std::sync::Arc::new(l)),
            Err(e) => {
                if show_errors(args) {
                    eprintln!("rsurl: cannot listen on port {listen_port}: {e}");
                }
                return 1;
            }
        }
    };
    // `--listen-port 0` means "any free port"; the real one is only knowable
    // now that something is bound. Everything downstream — the announce, the
    // status line — must use this, not the requested value.
    let listen_port = match &seed_listener {
        Some(l) => l.local_addr().map_or(listen_port, |a| a.port()),
        None => listen_port,
    };
    let opts = TorrentOptions {
        peer_id,
        listen_port,
        listener: seed_listener,
        seed,
        verbosity: args.verbosity,
        recheck: args.recheck,
        ..Default::default()
    };

    // Explicit peers from --bt-peer.
    let mut peers: Vec<SocketAddr> = Vec::new();
    for p in &args.bt_peers {
        match p.parse() {
            Ok(a) => peers.push(a),
            Err(_) => {
                if show_errors(args) {
                    eprintln!("rsurl: bad --bt-peer {p}");
                }
            }
        }
    }

    // 1) Obtain the metainfo, the tracker list, and the canonical `.torrent`
    //    bytes (for --bt-save-torrent).
    let (meta, trackers, torrent_bytes) = if source.starts_with("magnet:") {
        let magnet = match Magnet::parse(source) {
            Ok(m) => m,
            Err(e) => {
                if show_errors(args) {
                    eprintln!("rsurl: {e}");
                }
                return 2;
            }
        };
        peers.extend(magnet.peers.iter().copied());
        // Need at least one peer to fetch the info dictionary.
        if peers.is_empty() {
            peers = bt_announce_peers(
                &magnet.trackers,
                magnet.info_hash,
                peer_id,
                announce_key,
                listen_port,
                0,
                args.verbose,
            );
        }
        if peers.is_empty() && !args.no_dht {
            if !args.silent {
                eprintln!("* no tracker peers; trying DHT");
            }
            peers = bt_dht_peers(magnet.info_hash, args.verbose);
        }
        peers.sort();
        peers.dedup();
        if peers.is_empty() {
            if show_errors(args) {
                eprintln!("rsurl: no peers to fetch magnet metadata from");
            }
            return 1;
        }
        if !args.silent {
            let label = magnet.display_name.as_deref().unwrap_or("magnet");
            eprintln!("* fetching metadata for {label} from {} peers", peers.len());
        }
        match metadata::fetch_metainfo(
            magnet.info_hash,
            &peers,
            peer_id,
            // Short per-peer caps: many swarm peers are unreachable, and we
            // probe them concurrently, so fail fast and move on.
            Duration::from_secs(5),
            Duration::from_secs(10),
            args.verbosity >= 2,
        ) {
            Ok((m, info)) => {
                let tb = build_torrent(&info, &magnet.trackers);
                (m, magnet.trackers, tb)
            }
            Err(e) => {
                if show_errors(args) {
                    eprintln!("rsurl: magnet metadata: {e}");
                }
                return 1;
            }
        }
    } else {
        let bytes = if source.starts_with("http://") || source.starts_with("https://") {
            match rsurl::Request::get(source).and_then(|r| r.send()) {
                Ok(resp) if resp.status == 200 => resp.body,
                Ok(resp) => {
                    if show_errors(args) {
                        eprintln!("rsurl: fetching torrent: HTTP {}", resp.status);
                    }
                    return 1;
                }
                Err(e) => {
                    if show_errors(args) {
                        eprintln!("rsurl: fetching torrent: {e}");
                    }
                    return transfer_exit_code(&e);
                }
            }
        } else {
            let path = source.strip_prefix("file://").unwrap_or(source);
            match std::fs::read(path) {
                Ok(b) => b,
                Err(e) => {
                    if show_errors(args) {
                        eprintln!("rsurl: reading torrent {path}: {e}");
                    }
                    return 1;
                }
            }
        };
        match Metainfo::from_bytes(&bytes) {
            Ok(m) => {
                let trackers = m.trackers.clone();
                (m, trackers, bytes) // the loaded file is already a .torrent
            }
            Err(e) => {
                if show_errors(args) {
                    eprintln!("rsurl: {e}");
                }
                return 1;
            }
        }
    };

    // 1b) Metadata-only commands: emit and exit before any download setup.
    if args.bt_info {
        print!("{}", metadata_json(&meta));
        let _ = io::stdout().flush();
        return 0;
    }
    if args.bt_save_torrent {
        return bt_write_torrent(&torrent_bytes, args);
    }

    // 2) Output target: a single-file byte window (`--bt-file`) or a normal
    //    multi/single-file layout.
    let window: Option<(std::path::PathBuf, u64, u64)> = if let Some(sel) = &args.bt_file {
        match bt_resolve_file(&meta, sel) {
            Ok((idx, off, len)) => {
                let out = match args.output.as_deref().filter(|p| *p != "-") {
                    Some(o) => resolve_output_path(o, args),
                    None => std::path::PathBuf::from(
                        meta.files[idx].path.file_name().unwrap_or_default(),
                    ),
                };
                Some((out, off, off + len))
            }
            Err(msg) => {
                if show_errors(args) {
                    eprintln!("rsurl: {msg}");
                }
                return 2;
            }
        }
    } else {
        None
    };
    let layout = if window.is_some() {
        Vec::new()
    } else {
        match bt_layout(&meta, args) {
            Ok(l) => l,
            Err(msg) => {
                if show_errors(args) {
                    eprintln!("rsurl: {msg}");
                }
                return 2;
            }
        }
    };

    // 3) If we still have no peers, announce the trackers for the download,
    //    then fall back to the DHT.
    if peers.is_empty() {
        peers = bt_announce_peers(
            &trackers,
            meta.info_hash,
            peer_id,
            announce_key,
            listen_port,
            meta.total_length,
            args.verbose,
        );
    }
    if peers.is_empty() && !args.no_dht {
        if !args.silent {
            eprintln!("* no tracker peers; trying DHT");
        }
        peers = bt_dht_peers(meta.info_hash, args.verbose);
    }
    peers.sort();
    peers.dedup();
    if peers.is_empty() {
        if show_errors(args) {
            eprintln!("rsurl: no peers found (trackers and DHT returned none)");
        }
        return 1;
    }

    if !args.silent {
        eprintln!(
            "* torrent: {} ({}, {} pieces, {} peers)",
            meta.name,
            human_bytes(meta.total_length),
            meta.num_pieces(),
            peers.len()
        );
        match seed {
            SeedMode::Forever => eprintln!("* will seed after completion on port {listen_port}"),
            SeedMode::UntilRatio(r) => {
                eprintln!("* will seed to ratio {r:.2} on port {listen_port}")
            }
            SeedMode::Off => {}
        }
    }

    // 4) Download with throttled progress to stderr; once complete, the same
    //    callback renders the seeding (upload) status.
    let total = match &window {
        Some((_, s, e)) => e - s, // windowed: progress over the selected range
        None => meta.total_length,
    };
    let show = !args.silent;
    let start = Instant::now();
    let mut last_tick = start;
    let mut cb = |p: &bittorrent::Progress| {
        if !show {
            return;
        }
        let complete = p.num_pieces > 0 && p.pieces_complete == p.num_pieces;
        if complete && p.uploaded > 0 {
            // Seeding phase.
            eprint!(
                "\r* seeding: uploaded {} (ratio {:.2})   ",
                human_bytes(p.uploaded),
                p.uploaded as f64 / total.max(1) as f64,
            );
            let _ = io::stderr().flush();
            return;
        }
        if last_tick.elapsed() >= Duration::from_millis(120) || p.downloaded == total {
            let secs = start.elapsed().as_secs_f64();
            let rate = if secs > 0.0 {
                (p.downloaded as f64 / secs) as u64
            } else {
                0
            };
            eprint!(
                "\r* {}/{} pieces  {}/{}  {}/s   ",
                p.pieces_complete,
                p.num_pieces,
                human_bytes(p.downloaded),
                human_bytes(total),
                human_bytes(rate),
            );
            let _ = io::stderr().flush();
            last_tick = Instant::now();
        }
    };
    let result = match window {
        Some((out, s, e)) => bittorrent::download_window(&meta, out, &peers, &opts, s, e, &mut cb),
        None => bittorrent::download(&meta, layout, &peers, &opts, &mut cb),
    };
    if show {
        eprintln!();
    }
    match result {
        Ok(_) => 0,
        Err(e) => {
            if show_errors(args) {
                eprintln!("rsurl: {e}");
            }
            transfer_exit_code(&e)
        }
    }
}

/// Resolve `-Y` (minimum bytes/sec) and `-y` (window seconds). Per curl, `-y`
/// alone implies `-Y 1` and `-Y` alone implies `-y 30`; neither disables the
/// low-speed check.
fn low_speed_params(args: &Args) -> (Option<u64>, u64) {
    let lim = args
        .speed_limit
        .as_deref()
        .and_then(|s| s.parse::<u64>().ok());
    let tim = args
        .speed_time
        .as_deref()
        .and_then(|s| s.parse::<u64>().ok());
    match (lim, tim) {
        (None, None) => (None, 30),
        (l, t) => (Some(l.unwrap_or(1)), t.unwrap_or(30)),
    }
}

/// How the library download engine should chunk a `-o <file>` transfer.
enum SegmentPlan {
    /// One continuous resumable stream (plain `-C -`).
    Single,
    /// Fixed-size chunks fetched by `workers` parallel connections — the
    /// resumable parallel model (`-C - --parallel-segments`).
    FixedChunks { size: u64, workers: usize },
    /// Split into `count` equal segments fetched by `workers` connections
    /// (`--parallel-segments` without `-C -`). `count` is deliberately a
    /// multiple of `workers` — see [`SEGMENT_OVERSUBSCRIBE`].
    EqualSegments { count: usize, workers: usize },
}

/// Download `<name>` into `<name>.rsurlpart` and finalise on success, delegating
/// to the library's [`rsurl::download`] engine (range + validator handling,
/// transient-fault retry with backoff, streaming chunks to disk, atomic
/// finalize). Backs `-C -` and `--parallel-segments`. Returns a curl exit code;
/// only reached for a concrete output file (not stdout).
fn run_library_download(
    req: &rsurl::Request,
    url: &Url,
    args: &Args,
    name: &str,
    jar: Option<&mut CookieJar>,
    plan: SegmentPlan,
) -> u8 {
    let final_path = resolve_output_path(name, args);
    if args.create_dirs {
        if let Some(p) = final_path.parent() {
            let _ = std::fs::create_dir_all(p);
        }
    } else if let Some(dir) = &args.output_dir {
        let _ = std::fs::create_dir_all(dir);
    }

    // Carry cookie-jar cookies on the request; the library download path streams
    // the raw body and does not consult the jar itself.
    let mut greq = req.clone();
    if let Some(j) = jar.as_deref() {
        if let Some(h) = j.cookie_header(url) {
            greq = greq.header("Cookie", &h);
        }
    }

    // --write-out / --remote-time need response metadata the download engine
    // doesn't return; fetch it best-effort with a HEAD.
    let probe = if args.write_out.is_some() || args.remote_time {
        greq.clone().method("HEAD").send().ok()
    } else {
        None
    };

    let (speed_limit, speed_time) = low_speed_params(args);
    let fixed_delay = args.retry_delay.map(Duration::from_secs);
    let mut opts = rsurl::DownloadOptions {
        max_retries: args.retry,
        segment_size: None,
        segments: None,
        parallelism: 1,
        // Force HTTP/1.1 (dodges H2 RST_STREAM and keeps the body streaming to
        // disk) unless the user explicitly asked for another version.
        prefer_http11: matches!(
            args.http_version,
            None | Some(rsurl::HttpVersionPref::Http11Only)
        ),
        expected_sha256: None,
        max_size: args.max_filesize,
        max_time: None, // already applied to `req`
        limit_rate: args.limit_rate.as_deref().and_then(parse_rate),
        low_speed: speed_limit.map(|l| (l, speed_time)),
        initial_backoff: fixed_delay.unwrap_or(Duration::from_millis(500)),
        max_backoff: fixed_delay.unwrap_or(Duration::from_secs(30)),
        progress: None,
        // Temp-blob knobs; the CLI always downloads to a real path.
        tmp_spill_threshold: None,
        tmp_dir: None,
    };
    match plan {
        SegmentPlan::Single => {}
        SegmentPlan::FixedChunks { size, workers } => {
            opts.segment_size = Some(size);
            opts.parallelism = workers;
        }
        SegmentPlan::EqualSegments { count, workers } => {
            opts.segments = Some(count);
            opts.parallelism = workers;
        }
    }
    if args.progress_bar && !args.silent {
        let mut last = std::time::Instant::now();
        opts.progress = Some(Box::new(move |n, _total| {
            if last.elapsed() >= Duration::from_millis(100) {
                eprint!("\rrsurl: {n} bytes received");
                let _ = io::stderr().flush();
                last = std::time::Instant::now();
            }
        }));
    }

    let now = std::time::Instant::now();
    let outcome = greq.download_resumable(&final_path, opts);
    match outcome {
        Ok(o) => {
            // Final progress line (the throttled in-transfer callback may not
            // have fired for a fast transfer); then end the progress line.
            if args.progress_bar && !args.silent {
                eprintln!("\rrsurl: {} bytes received", o.bytes_written);
            }
            if let Some(resp) = &probe {
                if args.remote_time {
                    set_remote_time(resp, &final_path);
                }
                run_write_out(resp, url, args, now.elapsed(), o.bytes_written);
            }
            0
        }
        Err(e) => {
            if args.progress_bar && !args.silent {
                eprintln!();
            }
            let msg = e.to_string();
            if msg.contains("maximum file size") {
                if show_errors(args) {
                    eprintln!("rsurl: Maximum file size exceeded");
                }
                return 63;
            }
            if msg.contains("low-speed") {
                if show_errors(args) {
                    eprintln!(
                        "rsurl: Operation too slow. Less than {} bytes/sec transferred \
                         the last {speed_time} seconds",
                        speed_limit.unwrap_or(1)
                    );
                }
                return 28;
            }
            if show_errors(args) {
                eprintln!("rsurl: {e}");
            }
            let code = transfer_exit_code(&e);
            write_out_failure(url, args, now.elapsed(), code, &msg);
            code
        }
    }
}

/// Stream an HTTP download to its destination — the `-o`/`-O` file, or stdout
/// when neither names a file — through a [`DownloadSink`] (size cap, rate
/// limit, low-speed abort, progress).
fn run_http_download(
    req: rsurl::Request,
    url: &Url,
    args: &Args,
    jar: Option<&mut CookieJar>,
) -> u8 {
    let (inner, out_path): (Box<dyn Write>, Option<std::path::PathBuf>) =
        match open_download_output(url, args, false) {
            Ok(pair) => pair,
            Err(code) => return code,
        };
    let (speed_limit, speed_time) = low_speed_params(args);
    let now = std::time::Instant::now();
    let mut sink = DownloadSink {
        inner,
        written: 0,
        max: args.max_filesize,
        rate: args.limit_rate.as_deref().and_then(parse_rate),
        speed_limit,
        speed_time,
        started: now,
        progress: args.progress_bar,
        silent: args.silent,
        last_tick: now,
    };
    let result = if args.verbose {
        let mut err = io::stderr().lock();
        req.send_download(&mut sink, jar, &mut err)
    } else {
        req.send_download(&mut sink, jar, &mut io::sink())
    };
    let time_total = now.elapsed();
    let written = sink.written;
    if args.progress_bar && !args.silent {
        eprintln!();
    }
    let _ = sink.flush();
    match result {
        Ok(resp) => {
            if let (true, Some(p)) = (args.remote_time, &out_path) {
                set_remote_time(&resp, p);
            }
            run_write_out(&resp, url, args, time_total, written);
            0
        }
        Err(e) => {
            // --remove-on-error: drop the (partial) file. Close the handle
            // first — Windows refuses to unlink a file that's still open.
            if let (true, Some(p)) = (args.remove_on_error, &out_path) {
                drop(sink);
                let _ = std::fs::remove_file(p);
            }
            let code = download_error_code(&e, args, speed_limit, speed_time);
            write_out_failure(url, args, time_total, code, &e.to_string());
            code
        }
    }
}

/// Open where a streamed download goes: the `-o`/`-O` file (appending when
/// `append` is set, for a resume), or stdout. Returns the writer and the file
/// path, or the curl exit code after reporting the failure.
fn open_download_output(
    url: &Url,
    args: &Args,
    append: bool,
) -> Result<(Box<dyn Write>, Option<std::path::PathBuf>), u8> {
    let name = if args.remote_name {
        match remote_name_from_url(url) {
            Ok(n) => n,
            Err(e) => {
                if show_errors(args) {
                    eprintln!("rsurl: {e}");
                }
                return Err(23);
            }
        }
    } else {
        match args.output.as_deref() {
            Some(p) if p != "-" => p.to_string(),
            _ => return Ok((Box::new(io::stdout().lock()), None)),
        }
    };
    let opened = if append {
        open_append_output(&name, args)
    } else {
        create_output_file_tracked(&name, args)
    };
    match opened {
        Ok((file, path)) => Ok((Box::new(file), Some(path))),
        Err(e) => {
            if show_errors(args) {
                eprintln!("rsurl: open {name}: {e}");
            }
            Err(23)
        }
    }
}

/// Map a streamed-download error to curl's exit code, printing it: the sink's
/// `--max-filesize` (63) and `-y/-Y` (28) aborts, else [`transfer_exit_code`].
fn download_error_code(
    e: &rsurl::Error,
    args: &Args,
    speed_limit: Option<u64>,
    speed_time: u64,
) -> u8 {
    if e.to_string().contains(MAX_FILESIZE_SENTINEL) {
        if show_errors(args) {
            eprintln!("rsurl: Maximum file size exceeded");
        }
        return 63;
    }
    if e.to_string().contains(LOW_SPEED_SENTINEL) {
        if show_errors(args) {
            eprintln!(
                "rsurl: Operation too slow. Less than {} bytes/sec transferred \
                 the last {speed_time} seconds",
                speed_limit.unwrap_or(1)
            );
        }
        return 28;
    }
    if show_errors(args) {
        eprintln!("rsurl: {e}");
    }
    transfer_exit_code(e)
}

/// True when an HTTP body bound for stdout can be streamed rather than
/// buffered whole: the [`streams_to_file`] exclusions apply, `--retry` is off
/// (a retry cannot take back bytes already written), and stdout is not a
/// terminal — the binary-output guard needs the whole body — unless `-o -`
/// explicitly asked for raw output.
fn streams_to_stdout(args: &Args) -> bool {
    let to_stdout = !args.remote_name && args.output.as_deref().is_none_or(|p| p == "-");
    to_stdout
        && !args.include_headers
        && !args.fail
        && !args.fail_with_body
        && !args.digest
        && args.dump_header.is_none()
        && args.retry == 0
        && (args.output.is_some() || !io::stdout().is_terminal())
}

/// The byte offset to resume an HTTP download from, curl-style: `-C <N>`, or
/// for `-C -` the size of the existing output file. `None` means a normal
/// transfer — including `-C -` when a `.rsurlpart` from rsurl's own resumable
/// engine exists (that engine continues it) or there is nothing to resume.
fn resume_offset(url: &Url, args: &Args) -> Option<u64> {
    if let Some(n) = args.continue_at {
        return (n > 0).then_some(n);
    }
    if !args.continue_resume {
        return None;
    }
    let name = if args.remote_name {
        remote_name_from_url(url).ok()?
    } else {
        args.output.clone().filter(|p| p != "-")?
    };
    let path = match &args.output_dir {
        Some(dir) => Path::new(dir).join(&name),
        None => std::path::PathBuf::from(&name),
    };
    if rsurl::resume::part_path(&path).exists() {
        return None;
    }
    let len = std::fs::metadata(&path).ok()?.len();
    (len > 0).then_some(len)
}

/// Resume an HTTP download at byte `offset` (`-C`): ask for
/// `Range: bytes=<offset>-` and append the 206 body to the output. A 416 means
/// there is nothing left to fetch (curl treats it as success); any other 2xx
/// means the server ignored the range, which curl reports as exit 33 rather
/// than corrupting the file.
fn run_http_resume(
    req: rsurl::Request,
    url: &Url,
    args: &Args,
    jar: Option<&mut CookieJar>,
    offset: u64,
) -> u8 {
    let mut req = req.header("Range", &format!("bytes={offset}-"));
    if !args.compressed && !args.has_header("accept-encoding") {
        // Resuming splices raw bytes: ask for (and keep) the identity coding.
        req = req.header("Accept-Encoding", "identity").decompress(false);
    }
    let (inner, out_path) = match open_download_output(url, args, true) {
        Ok(pair) => pair,
        Err(code) => return code,
    };
    let (speed_limit, speed_time) = low_speed_params(args);
    let now = std::time::Instant::now();
    let mut sink = DownloadSink {
        inner,
        written: 0,
        max: args.max_filesize,
        rate: args.limit_rate.as_deref().and_then(parse_rate),
        speed_limit,
        speed_time,
        started: now,
        progress: args.progress_bar,
        silent: args.silent,
        last_tick: now,
    };
    let status = std::cell::Cell::new(0u16);
    let result = req.send_streaming_with(
        jar,
        |h| status.set(h.status),
        |chunk| match status.get() {
            206 => sink.write_all(chunk).map_err(rsurl::Error::Io),
            // Range not satisfiable: the file is already complete.
            416 => Ok(()),
            200..=299 => Err(rsurl::Error::BadResponse(RANGE_IGNORED.into())),
            s if s >= 400 && args.fail => Ok(()),
            _ => sink.write_all(chunk).map_err(rsurl::Error::Io),
        },
    );
    let time_total = now.elapsed();
    let written = sink.written;
    let _ = sink.flush();
    drop(sink);
    if args.progress_bar && !args.silent {
        eprintln!();
    }
    let resp = match result {
        Ok(r) => r,
        Err(e) if e.to_string().contains(RANGE_IGNORED) => {
            return range_ignored(url, args, time_total);
        }
        Err(e) => {
            let code = download_error_code(&e, args, speed_limit, speed_time);
            write_out_failure(url, args, time_total, code, &e.to_string());
            return code;
        }
    };
    if (200..300).contains(&resp.status) && resp.status != 206 {
        return range_ignored(url, args, time_total);
    }
    if args.fail && resp.status >= 400 {
        let msg = format!(
            "The requested URL returned error: {} {}",
            resp.status, resp.reason
        );
        if show_errors(args) {
            eprintln!("rsurl: {msg}");
        }
        run_write_out_code(&resp, url, args, time_total, written, 22, &msg);
        return 22;
    }
    if let (true, Some(p)) = (args.remote_time, &out_path) {
        set_remote_time(&resp, p);
    }
    run_write_out(&resp, url, args, time_total, written);
    0
}

/// Marker error for a resume the server answered with the whole resource.
const RANGE_IGNORED: &str = "HTTP server doesn't seem to support byte ranges. Cannot resume.";

fn range_ignored(url: &Url, args: &Args, elapsed: std::time::Duration) -> u8 {
    if show_errors(args) {
        eprintln!("rsurl: {RANGE_IGNORED}");
    }
    write_out_failure(url, args, elapsed, 33, RANGE_IGNORED);
    33 // CURLE_RANGE_ERROR
}

/// Resolve the on-disk path for an `-o`/`-O` name: prepend `--output-dir`
/// (absolute paths are left alone), then, under `--no-clobber`, append the
/// first free `.1`, `.2`, ... suffix so an existing file is never overwritten.
fn resolve_output_path(path: &str, args: &Args) -> std::path::PathBuf {
    let full = match &args.output_dir {
        Some(dir) => std::path::Path::new(dir).join(path),
        None => std::path::PathBuf::from(path),
    };
    if !args.no_clobber || !full.exists() {
        return full;
    }
    let base = full.as_os_str().to_owned();
    for n in 1u32.. {
        let mut candidate = base.clone();
        candidate.push(format!(".{n}"));
        let candidate = std::path::PathBuf::from(candidate);
        if !candidate.exists() {
            return candidate;
        }
    }
    unreachable!("u32 range exhausted picking a --no-clobber name")
}

/// Create the output file for `path`, first creating parent directories when
/// `--create-dirs` is set (curl semantics). Returns the file and the resolved
/// path actually opened (which `--no-clobber` may have renamed), so callers can
/// e.g. delete it under `--remove-on-error`.
fn create_output_file_tracked(path: &str, args: &Args) -> io::Result<(File, std::path::PathBuf)> {
    let full = resolve_output_path(path, args);
    if args.create_dirs {
        if let Some(parent) = full.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
    } else if let Some(dir) = &args.output_dir {
        // curl creates the --output-dir itself even without --create-dirs.
        std::fs::create_dir_all(dir)?;
    }
    let file = File::create(&full)?;
    Ok((file, full))
}

/// Open the output for a resumed download (`-C`): like
/// [`create_output_file_tracked`] but appending to an existing file instead of
/// truncating it, and never renaming under `--no-clobber` (resuming *is*
/// continuing that file).
fn open_append_output(path: &str, args: &Args) -> io::Result<(File, std::path::PathBuf)> {
    let full = match &args.output_dir {
        Some(dir) => Path::new(dir).join(path),
        None => std::path::PathBuf::from(path),
    };
    if args.create_dirs {
        if let Some(parent) = full.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
    } else if let Some(dir) = &args.output_dir {
        std::fs::create_dir_all(dir)?;
    }
    let file = File::options().append(true).create(true).open(&full)?;
    Ok((file, full))
}

/// As [`create_output_file_tracked`], discarding the resolved path. Used by the
/// callers that don't need to delete the file afterward.
fn create_output_file(path: &str, args: &Args) -> io::Result<File> {
    create_output_file_tracked(path, args).map(|(f, _)| f)
}

/// `-D`/`--dump-header`: write the status line and response headers to `path`
/// (`-` is stdout), CRLF-terminated, exactly as curl does.
fn dump_headers(resp: &Response, path: &str) -> io::Result<()> {
    let mut f: Box<dyn Write> = if path == "-" {
        Box::new(io::stdout().lock())
    } else {
        Box::new(File::create(path)?)
    };
    write!(f, "{} {} {}\r\n", resp.version, resp.status, resp.reason)?;
    for (k, v) in &resp.headers {
        write!(f, "{k}: {v}\r\n")?;
    }
    f.write_all(b"\r\n")
}

/// `-R`/`--remote-time`: stamp `path`'s mtime from the response `Last-Modified`
/// header. Best-effort — failures (bad date, unsupported FS) are ignored.
fn set_remote_time(resp: &Response, path: &Path) {
    let Some(lm) = resp.header("last-modified") else {
        return;
    };
    let Some(epoch) = httpdate_to_epoch(lm) else {
        return;
    };
    let mtime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(epoch);
    if let Ok(f) = File::options().write(true).open(path) {
        let _ = f.set_modified(mtime);
    }
}

/// Error text [`write_output`] returns after refusing to print a binary body to
/// a terminal (curl's warning is already printed; exit 23 follows).
const BINARY_TO_TTY: &str = "binary output refused on a terminal";

/// Write the (buffered) response to its destination: `-O`/`-J` name, `-o`
/// file, or stdout. Returns the path of the file written, if any.
fn write_output(resp: &Response, url: &Url, args: &Args) -> io::Result<Option<std::path::PathBuf>> {
    // Track whether we are writing to stdout (vs. a real file via -o/-O) and
    // whether the user explicitly asked for stdout with `-o -` / `--output -`.
    // Only stdout-to-a-terminal is ever sanitized/guarded; bytes redirected to
    // a file or pipe must be delivered exactly as received (don't corrupt
    // downloads).
    let mut to_stdout = true;
    let mut explicit_stdout = false;
    let mut written_path = None;
    let mut out: Box<dyn Write> = if args.remote_name {
        // -J: prefer a sanitized Content-Disposition filename; else the URL's
        // last path segment.
        let name = args
            .remote_header_name
            .then(|| content_disposition_filename(resp))
            .flatten()
            .map(Ok)
            .unwrap_or_else(|| remote_name_from_url(url))
            .map_err(|e| io::Error::other(e.to_string()))?;
        to_stdout = false;
        let (file, path) = create_output_file_tracked(&name, args)?;
        written_path = Some(path);
        Box::new(file)
    } else {
        match &args.output {
            Some(path) if path != "-" => {
                to_stdout = false;
                let (file, path) = create_output_file_tracked(path, args)?;
                written_path = Some(path);
                Box::new(file)
            }
            Some(_) => {
                explicit_stdout = true; // `-o -` / `--output -`
                Box::new(io::stdout().lock())
            }
            None => Box::new(io::stdout().lock()),
        }
    };

    // A terminal sink is the only case we guard. When output is redirected to a
    // file or pipe, `is_terminal()` is false and every byte is written raw.
    let is_tty = to_stdout && io::stdout().is_terminal();

    if args.include_headers {
        if is_tty {
            let line = format!("{} {} ", resp.version, resp.status);
            out.write_all(line.as_bytes())?;
            out.write_all(&sanitize_for_tty(resp.reason.as_bytes()))?;
            out.write_all(b"\r\n")?;
            for (k, v) in &resp.headers {
                out.write_all(&sanitize_for_tty(k.as_bytes()))?;
                out.write_all(b": ")?;
                out.write_all(&sanitize_for_tty(v.as_bytes()))?;
                out.write_all(b"\r\n")?;
            }
        } else {
            write!(out, "{} {} {}\r\n", resp.version, resp.status, resp.reason)?;
            for (k, v) in &resp.headers {
                write!(out, "{k}: {v}\r\n")?;
            }
        }
        out.write_all(b"\r\n")?;
    }

    if is_tty {
        // `-o -` is the explicit opt-in to dump raw bytes to the terminal.
        if explicit_stdout {
            out.write_all(&resp.body)?;
        } else if body_looks_binary(&resp.body) {
            // Refuse to dump binary to the terminal (curl's behavior).
            if show_errors(args) {
                eprintln!(
                    "Warning: Binary output can mess up your terminal. Use \"--output -\" to tell"
                );
                eprintln!("Warning: rsurl to output it to your terminal anyway, or consider \"-o");
                eprintln!("Warning: <FILE>\" to save to a file.");
            }
            // curl treats the refusal as a write failure (exit 23).
            return Err(io::Error::other(BINARY_TO_TTY));
        } else {
            // Text body to a TTY: neutralize embedded control sequences.
            out.write_all(&sanitize_for_tty(&resp.body))?;
        }
    } else {
        out.write_all(&resp.body)?;
    }
    out.flush()?;
    Ok(written_path)
}

/// Derive the `-O` output filename from the URL's last path segment.
/// Refuses empty or `/` paths (those would land on stdin's place per curl).
fn remote_name_from_url(url: &Url) -> Result<String, String> {
    // Strip query string first, then take everything after the last '/'.
    let path = url.path.as_str();
    let path_no_query = match path.find('?') {
        Some(i) => &path[..i],
        None => path,
    };
    let trimmed = path_no_query.trim_end_matches('/');
    let last = trimmed.rsplit('/').next().unwrap_or("");
    if last.is_empty() {
        return Err("Refusing to overwrite stdin".to_string());
    }
    // Guard against path traversal: only take the basename portion.
    let basename = Path::new(last)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| "Refusing to overwrite stdin".to_string())?;
    if basename.is_empty() {
        return Err("Refusing to overwrite stdin".to_string());
    }
    Ok(basename.to_string())
}

fn print_usage() {
    println!(
        "rsurl {VERSION} — a pure-Rust curl

Usage: rsurl [options] <url>...

Options:
  -o, --output <file>      write body to file instead of stdout
  -O, --remote-name        save body as the URL's last path segment
  -i, --include            include response headers in the output
  -I, --head               issue HEAD instead of GET
  -v, --verbose            print request/response headers to stderr; for a
                           torrent, -v shows a periodic swarm summary and -vv
                           adds per-peer connect/unchoke/disconnect detail
  -s, --silent             suppress error messages
  -X, --request <method>   override HTTP method; for rtsp:// selects the
                           RTSP method (OPTIONS/DESCRIBE/SETUP/PLAY/TEARDOWN)
  -H, --header <line>      add a request header (repeatable)
  -d, --data <body>        POST body (urlencoded); @file reads from disk
                           and strips CR/LF. Repeatable; joined with '&'.
      --data-raw <body>    like -d but '@' is taken literally
      --data-binary <body> like -d but @file is read verbatim (no strip)
      --data-urlencode <s> percent-encode <s> before sending. Forms:
                             text  =text  name=text  @file  name@file
      --json <data>        POST <data> as application/json and set Accept to
                           application/json; @file reads verbatim. Repeatable.
  -F, --form <name=value>  add a multipart/form-data part. Value forms:
                             text  @file (upload)  <file (field from file)
                           Modifiers: ;type=  ;filename=  ;headers=@hdrfile
      --form-string <n=v>  like -F but value is taken literally (no @, <, ;)
      --form-escape        percent-encode names/filenames per RFC 7578 §4.2
                           (default: backslash-escape, curl-historical)
  -T, --upload-file <f>    upload the file: HTTP PUT (default Content-Type:
                           application/octet-stream), FTP/FTPS STOR, TFTP WRQ,
                           MQTT PUBLISH, or SFTP/SCP write
      --key <file>         SSH private-key identity file for sftp:// / scp://
                           public-key auth (repeatable). Without it, the
                           default ~/.ssh/id_ed25519|id_ecdsa|id_rsa are tried
  -C, --continue-at <off>  resume at byte <off> (FTP: REST before STOR);
                           '-C -' auto-resumes an HTTP download via its
                           <name>.rsurlpart (needs server Range support; with
                           --parallel-segments, resumes per chunk)
  -a, --append             FTP/FTPS upload: append (APPE) instead of replacing
                           (STOR). No-op for other protocols; overrides -C
  -A, --user-agent <ua>    set User-Agent
  -e, --referer <ref>      set Referer
  -L, --location           follow 3xx redirects
      --max-redirs <n>     cap on redirect hops (default 50)
  -u, --user <user:pass>   HTTP Basic auth credentials
      --digest             use HTTP Digest auth with -u credentials
      --oauth2-bearer <t>  send Authorization: Bearer <token>
      --aws-sigv4 <spec>   sign with AWS SigV4 (e.g. aws:amz:us-east-1:s3, -u key:secret)
  -k, --insecure           don't verify the TLS certificate chain
      --cacert <file>      PEM bundle to use instead of system trust
      --tlsv1.2/1.3        require at least this TLS version (floor)
      --tls-max <ver>      cap the TLS version (1.2 or 1.3)
      --mail-from <addr>   SMTP envelope sender (smtp://host, body via -T/-d)
      --mail-rcpt <addr>   SMTP envelope recipient (repeatable)
      --no-idn             don't convert international (IDN) hostnames to punycode
      --max-time <secs>    cap on the whole operation's wall time
      --connect-timeout <secs>
                           cap on the TCP connect step
      --http2              require HTTP/2 (ALPN h2); error if unavailable
      --http1.1            force HTTP/1.1 (alias: --http1)
      --http3              try HTTP/3 (QUIC), fall back to HTTP/2/1.1
      --http3-only         require HTTP/3 (QUIC); no fallback
  -b, --cookie <data>      cookies to send: \"k=v[; k2=v2]\" or path to a
                           Netscape cookies.txt file
  -c, --cookie-jar <file>  write all known cookies to <file> on exit
  -x, --proxy <url>        route via a proxy. Scheme picks the kind:
                           http/https/socks4/socks4a/socks5/socks5h (bare
                           host:port = http). SOCKS5 also tunnels HTTP/3 &
                           TFTP (UDP). Reads HTTPS_PROXY/http_proxy/ALL_PROXY.
      --socks4 <host:port> / --socks4a / --socks5 / --socks5-hostname
                           shorthands for -x socks4://… etc.
  -U, --proxy-user <u:p>   credentials for the proxy (Basic / SOCKS5 auth)
      --noproxy <hosts>    comma-separated host suffixes that bypass the
                           proxy; \"*\" bypasses everything (re-checked on
                           every redirect hop, for every proxy kind)
      --proxy-insecure     don't verify an https:// proxy's certificate
                           (-k applies to the origin only, and vice versa)
      --proxy-cacert <f>   / --proxy-capath <dir> / --proxy-crlfile <f>
                           trust settings for an https:// proxy
      --proxy-cert <c[:p]> / --proxy-key <f> / --proxy-pass <p>
                           client certificate for an https:// proxy
      --proxy-cert-type <t> / --proxy-key-type <t>   PEM (default) or DER
      --proxy-pinnedpubkey <h>  pin an https:// proxy's public key
      --proxy-ciphers <l> / --proxy-tls13-ciphers <l>
                           restrict cipher suites offered to the proxy
      --proxy-tlsv1.2/1.3 / --proxy-tls-max <ver>
                           TLS version floor / ceiling for the proxy
  -f, --fail               on HTTP >= 400, emit no body and exit 22
  -S, --show-error         show errors even with -s
  -G, --get                put -d data in the URL query and use GET
  -r, --range <range>      request a byte range (Range: bytes=<range>)
      --compressed         ask for a compressed response (decoded anyway)
  -D, --dump-header <file> write response headers to <file>
  -R, --remote-time        set the saved file's mtime from Last-Modified
      --create-dirs        create missing directories for -o
      --remove-on-error    delete a partial -o/-O file if the transfer fails
      --no-clobber         never overwrite an existing -o/-O file (use .1, .2…)
      --max-filesize <n>   refuse a download larger than <n> bytes
  -w, --write-out <fmt>    after the transfer, print <fmt> with %{{vars}}
                           expanded (http_code, size_download, content_type,
                           url_effective, time_total, time_connect,
                           time_appconnect, time_pretransfer, time_starttransfer,
                           ssl_verify_result, %header{{Name}}; phase timers are
                           HTTP/1.1-only, else 0.000000)
      --url <url>          add a URL (repeatable; same as a positional arg)
  -n, --netrc              read credentials from ~/.netrc (when no -u)
      --netrc-file <file>  read credentials from <file> (implies -n)
  -J, --remote-header-name with -O, name the file from Content-Disposition
      --retry <n>          retry transient failures up to <n> times
      --retry-delay <s>    fixed delay between retries (else exponential)
      --retry-max-time <s> give up retrying after <s> seconds total
      --retry-connrefused  also retry on connection refused
      --retry-all-errors   retry on any error
  -z, --time-cond <t>      If-Modified-Since (or If-Unmodified-Since for
                           a leading '-'); a filename uses its mtime
      --output-dir <dir>   directory to prepend to -o/-O output names
      --fail-with-body     exit 22 on HTTP >= 400 but still write the body
      --proto <spec>       restrict allowed schemes (e.g. =https,http)
      --proto-default <s>  scheme for URLs given without one
  -g, --globoff            disable URL globbing ({{}} and [] taken literally)
  -Z, --parallel           run this invocation's transfers concurrently
      --parallel-max <n>   cap on concurrent transfers (default 50)
      --parallel-segments [n]  fetch one -o/-O file via n concurrent ranges
                               (default 4; add -# for a live progress display)
      --torrent            treat the source (.torrent path/URL or magnet:) as a
                           torrent; downloads its data to -o/--output-dir
      --listen-port <p>    port advertised to BitTorrent peers/trackers (6881;
                           0 = any free port, reported once bound)
      --bt-peer <ip:port>  add a torrent peer directly (repeatable)
      --no-dht             disable the DHT peer-discovery fallback
      --seed               keep seeding after the torrent completes
      --share-ratio <r>    seed until uploaded/downloaded reaches r, then exit
      --recheck            on torrent resume, re-hash on-disk data instead of
                           trusting the saved .rsurlpart bitfield
      --bt-info            print torrent metadata as JSON to stdout, then exit
      --bt-save-torrent    write the .torrent (to -o, else stdout), then exit
      --bt-file <N|path>   download just one file of a multi-file torrent to -o
      --bt-concat          download a multi-file torrent as one concatenated -o
      --location-trusted   keep credentials across cross-host redirects
      --post301/302/303    keep POST (don't downgrade to GET) on that redirect
      --connect-to <spec>  dial HOST2:PORT2 for requests to HOST1:PORT1
                           (keeps the original Host:/SNI)
      --unix-socket <path> connect through a Unix-domain socket (Unix only)
  -4, --ipv4               connect over IPv4 only
  -6, --ipv6               connect over IPv6 only
      --resolve <h:p:addr> use <addr> for <host>:<port> (static DNS)
      --disable-epsv       FTP: skip EPSV, use PASV directly
      --ssl-reqd           mail (smtp/imap/pop3): require STARTTLS/STLS upgrade
                           before sending credentials or data
  -P, --ftp-port <addr>    FTP: active mode (server connects back); <addr> is
                           accepted but the control-connection local IP is used
      --ftp-create-dirs    FTP: create missing remote dirs before upload (-T)
  -K, --config <file>      read options from a curl-style config file
      --next  (-:)         start a new request with its own options
  -#, --progress-bar       show progress on streamed file downloads (-o/-O)
  -E, --cert <c[:pass]>    client certificate for mutual TLS (PEM, or DER with
                           --cert-type). Optional inline ':password' for the key
      --key <file>         client TLS private key (also the SSH identity file);
                           omit when the key is embedded in --cert
      --pass <phrase>      passphrase for an encrypted --key/--cert key
      --cert-type <type>   --cert encoding: PEM (default) or DER
      --key-type <type>    --key encoding: PEM (default) or DER
      --pinnedpubkey <h>   pin the server pubkey: sha256//BASE64[;sha256//...]
                           (SHA-256 of the leaf cert's SPKI); fail on mismatch
      --capath <dir>       trust extra CA certs from every file in <dir>
                           (in addition to system roots / --cacert)
      --crlfile <file>     check the server chain against this CRL (PEM/DER;
                           default backend only)
      --ciphers <list>     restrict TLS<=1.2 cipher suites (OpenSSL/IANA names,
                           ':'-separated; default backend only)
      --tls13-ciphers <l>  restrict TLS 1.3 cipher suites (IANA TLS_* names)
      --limit-rate <speed> cap download rate (e.g. 200k, 1M) on -o/-O downloads
  -y, --speed-time <s> / -Y, --speed-limit <bps>
                           abort an -o/-O download averaging below <bps>
                           bytes/sec over <s> seconds (exit 28)
  -q, --disable            no-op (rsurl reads no config unless -K is given)
  -N, --no-buffer          no-op (output is already streamed)
      --no-progress-meter  no-op (no meter is shown by default)
      --styled-output, --no-styled-output
                           no-op (headers are never styled)
  -h, --help               print this help
  -V, --version            print version
"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_exit_code_maps_curl_codes() {
        use std::io::{Error as IoError, ErrorKind};
        assert_eq!(transfer_exit_code(&rsurl::Error::InvalidUrl("x".into())), 3);
        assert_eq!(
            transfer_exit_code(&rsurl::Error::UnsupportedScheme("gopher+ssh".into())),
            1
        );
        assert_eq!(transfer_exit_code(&rsurl::Error::UnexpectedEof), 52);
        assert_eq!(transfer_exit_code(&rsurl::Error::Ssh("auth".into())), 79);
        assert_eq!(
            transfer_exit_code(&rsurl::Error::BadResponse("operation timed out".into())),
            28
        );
        assert_eq!(
            transfer_exit_code(&rsurl::Error::BadResponse(
                "maximum (50) redirects followed".into()
            )),
            47
        );
        assert_eq!(
            transfer_exit_code(&rsurl::Error::BadResponse("garbage status line".into())),
            8
        );
        assert_eq!(
            transfer_exit_code(&rsurl::Error::Io(IoError::from(
                ErrorKind::ConnectionRefused
            ))),
            7
        );
        assert_eq!(
            transfer_exit_code(&rsurl::Error::Io(IoError::from(ErrorKind::TimedOut))),
            28
        );
        assert_eq!(
            transfer_exit_code(&rsurl::Error::Io(IoError::other(
                "failed to lookup address information: Name or service not known"
            ))),
            6
        );
    }

    #[test]
    fn proto_allowed_evaluates_specs() {
        assert!(proto_allowed("https", "=https,http"));
        assert!(!proto_allowed("ftp", "=https,http"));
        assert!(proto_allowed("http", "all"));
        assert!(!proto_allowed("ftp", "-ftp"));
        assert!(proto_allowed("https", "-ftp"));
        assert!(proto_allowed("https", "+https"));
    }

    #[test]
    fn epoch_httpdate_roundtrips() {
        // Sun, 06 Nov 1994 08:49:37 GMT == 784111777
        assert_eq!(
            epoch_to_httpdate(784111777),
            "Sun, 06 Nov 1994 08:49:37 GMT"
        );
        assert_eq!(
            httpdate_to_epoch("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(784111777)
        );
        assert_eq!(epoch_to_httpdate(0), "Thu, 01 Jan 1970 00:00:00 GMT");
    }

    #[test]
    fn glob_brace_and_range_expand() {
        let urls: Vec<String> = glob_expand("http://h/{a,b}/[1-3]")
            .unwrap()
            .map(|(u, _)| u)
            .collect();
        assert_eq!(
            urls,
            vec![
                "http://h/a/1",
                "http://h/a/2",
                "http://h/a/3",
                "http://h/b/1",
                "http://h/b/2",
                "http://h/b/3",
            ]
        );
    }

    #[test]
    fn glob_disabled_skips_torrent_paths_and_magnets() {
        // A local `.torrent` path must never be glob-expanded: on Windows its
        // backslashes would be eaten as glob escapes (`C:\a\b` -> `C:ab`), and
        // `[`/`]` in a path would be misread as a range. (Regression: CLI
        // torrent downloads failing on windows-latest.)
        let torrent = Args {
            torrent: true,
            ..Default::default()
        };
        assert!(glob_disabled(
            &torrent,
            r"C:\Users\me\AppData\Local\Temp\x.torrent"
        ));
        assert!(glob_disabled(&torrent, "/tmp/x.torrent"));
        // Magnet links are skipped regardless of `--torrent`.
        assert!(glob_disabled(&Args::default(), "magnet:?xt=urn:btih:abc"));
        // But an http(s) torrent URL still globs normally.
        assert!(!glob_disabled(&torrent, "http://h/file[1-3].torrent"));
        // And a plain URL without `--torrent` is unaffected.
        assert!(!glob_disabled(&Args::default(), "http://h/{a,b}"));
        // `-g/--globoff` disables it for everything.
        let off = Args {
            globoff: true,
            ..Default::default()
        };
        assert!(glob_disabled(&off, "http://h/{a,b}"));
    }

    fn range_items(body: &str) -> Vec<String> {
        let seg = expand_range(body).unwrap();
        (0..seg.len()).map(|i| seg.item(i)).collect()
    }

    fn glob_urls(url: &str) -> Vec<String> {
        glob_expand(url).unwrap().map(|(u, _)| u).collect()
    }

    fn toks(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn glob_zero_padded_and_step_and_alpha() {
        assert_eq!(range_items("08-11"), vec!["08", "09", "10", "11"]);
        assert_eq!(range_items("1-10:3"), vec!["1", "4", "7", "10"]);
        assert_eq!(range_items("a-e:2"), vec!["a", "c", "e"]);
    }

    #[test]
    fn glob_output_substitution() {
        let (_, caps) = glob_expand("img[1-2].jpg").unwrap().next().unwrap();
        assert_eq!(apply_glob_output("out-#1.bin", &caps), "out-1.bin");
    }

    #[test]
    fn glob_reversed_range_is_an_error() {
        // curl: "bad range" (exit 3), not a silent no-op.
        assert!(glob_expand("http://h/[5-1]").is_err());
        assert!(glob_expand("http://h/[z-a]").is_err());
    }

    #[test]
    fn glob_ipv6_literal_is_not_a_range() {
        assert_eq!(
            glob_urls("http://[::1]:8080/x"),
            vec!["http://[::1]:8080/x"]
        );
        assert_eq!(
            glob_urls("http://[fe80::1%25en0]/[1-2]"),
            vec!["http://[fe80::1%25en0]/1", "http://[fe80::1%25en0]/2"]
        );
    }

    #[test]
    fn glob_huge_range_is_lazy_and_capped() {
        // 10^11 URLs must neither be materialised nor accepted.
        assert!(glob_expand("http://h/[1-100000000000]").is_err());
        // A large-but-allowed glob starts yielding immediately.
        let mut it = glob_expand("http://h/[1-9000000]").unwrap();
        assert_eq!(it.next().unwrap().0, "http://h/1");
        assert_eq!(it.next().unwrap().0, "http://h/2");
    }

    #[test]
    fn short_bundles_expand() {
        let got = expand_short_bundles(&toks(&["-sS", "-ofile", "u"]));
        assert_eq!(got, vec!["-s", "-S", "-o", "file", "u"]);
        // long options and bare dash pass through
        let got2 = expand_short_bundles(&toks(&["--silent", "-"]));
        assert_eq!(got2, vec!["--silent", "-"]);
    }

    #[test]
    fn short_bundles_leave_option_values_alone() {
        // Values that start with '-' belong to the option before them.
        let got = expand_short_bundles(&toks(&["-d", "-name=x", "-H", "-X-Y: z", "u"]));
        assert_eq!(got, vec!["-d", "-name=x", "-H", "-X-Y: z", "u"]);
        let got = expand_short_bundles(&toks(&["--data", "-abc", "-w", "-%{http_code}"]));
        assert_eq!(got, vec!["--data", "-abc", "-w", "-%{http_code}"]);
        // A bundle ending in a value-taking flag consumes the next token raw.
        let got = expand_short_bundles(&toks(&["-sd", "-v", "u"]));
        assert_eq!(got, vec!["-s", "-d", "-v", "u"]);
        // Everything after `--` is left untouched.
        let got = expand_short_bundles(&toks(&["-s", "--", "-sS"]));
        assert_eq!(got, vec!["-s", "--", "-sS"]);
    }

    #[test]
    fn option_takes_value_matches_parser() {
        for opt in [
            "-o",
            "-d",
            "-H",
            "--data",
            "--max-time",
            "-m",
            "--url-query",
            "-K",
        ] {
            assert!(option_takes_value(opt), "{opt}");
        }
        for opt in ["-s", "-L", "--silent", "--compressed", "-O", "-j", "--"] {
            assert!(!option_takes_value(opt), "{opt}");
        }
    }

    #[test]
    fn double_dash_ends_options() {
        let a = parse_args(&toks(&["-s", "--", "-not-an-option", "http://h/"])).unwrap();
        assert!(a.silent);
        assert_eq!(a.urls, vec!["-not-an-option", "http://h/"]);
        let segs = split_operations(&toks(&["-s", "--", "a", "--next", "b"]));
        assert_eq!(segs.len(), 1, "--next after -- is a URL");
    }

    #[test]
    fn outputs_pair_with_urls_in_order() {
        let a = parse_args(&toks(&["-o", "a", "U1", "-O", "U2", "U3"])).unwrap();
        let (o1, o2, o3) = (a.for_url(0), a.for_url(1), a.for_url(2));
        assert_eq!((o1.output.as_deref(), o1.remote_name), (Some("a"), false));
        assert_eq!((o2.output.as_deref(), o2.remote_name), (None, true));
        // More URLs than output options: the rest go to stdout.
        assert_eq!((o3.output.as_deref(), o3.remote_name), (None, false));
        let all = parse_args(&toks(&["--remote-name-all", "U1", "U2"])).unwrap();
        assert!(all.for_url(1).remote_name);
    }

    #[test]
    fn header_arg_forms() {
        assert_eq!(
            parse_header_arg("X-A: 1").unwrap(),
            HeaderArg::Set("X-A".into(), "1".into())
        );
        assert_eq!(
            parse_header_arg("User-Agent:").unwrap(),
            HeaderArg::Remove("User-Agent".into())
        );
        assert_eq!(
            parse_header_arg("X-Empty;").unwrap(),
            HeaderArg::Set("X-Empty".into(), String::new())
        );
        assert!(parse_header_arg("nocolon").is_err());
        assert!(parse_header_arg(": v").is_err());
    }

    #[test]
    fn fractional_timeouts_parse() {
        assert_eq!(
            parse_seconds("2.5", "-m").unwrap(),
            Some(Duration::from_millis(2500))
        );
        assert_eq!(parse_seconds("0", "-m").unwrap(), None);
        assert!(parse_seconds("-1", "-m").is_err());
        assert!(parse_seconds("soon", "-m").is_err());
        let a = parse_args(&toks(&["--connect-timeout", "0.25", "-m", "1.5", "u"])).unwrap();
        assert_eq!(a.connect_timeout, Some(Duration::from_millis(250)));
        assert_eq!(a.max_time, Some(Duration::from_millis(1500)));
    }

    #[test]
    fn url_query_appends_before_fragment() {
        let q = |url: &str, parts: &[&str]| append_url_queries(url, &toks(parts)).unwrap();
        assert_eq!(q("http://h/p", &["a=b c"]), "http://h/p?a=b+c");
        assert_eq!(
            q("http://h/p?x=1", &["+raw=%41", "k=v"]),
            "http://h/p?x=1&raw=%41&k=v"
        );
        assert_eq!(q("http://h/p#frag", &["a=1"]), "http://h/p?a=1#frag");
    }

    #[test]
    fn tls_errors_map_to_curl_exit_codes() {
        use std::io::Error as IoError;
        let io = |m: &str| rsurl::Error::Io(IoError::other(m.to_string()));
        let bad = |m: &str| rsurl::Error::BadResponse(m.to_string());
        assert_eq!(transfer_exit_code(&io("tls: BadCertificate")), 60);
        assert_eq!(transfer_exit_code(&io("tls: RecordOverflow")), 35);
        assert_eq!(
            transfer_exit_code(&bad("tls: invalid peer certificate: UnknownIssuer")),
            60
        );
        assert_eq!(
            transfer_exit_code(&bad("pinned public key does not match server certificate")),
            90
        );
        assert_eq!(
            transfer_exit_code(&bad("no usable CA certificates parsed from x.pem")),
            77
        );
        assert_eq!(
            transfer_exit_code(&bad("client cert: cannot parse PEM: x")),
            58
        );
        assert_eq!(
            transfer_exit_code(&bad(
                "server certificate has no Subject Alternative Name (CN fallback is not accepted)"
            )),
            60
        );
        // Non-TLS errors are unaffected.
        assert_eq!(transfer_exit_code(&bad("garbage status line")), 8);
    }

    #[test]
    fn content_disposition_prefers_extended_filename() {
        let resp = |cd: &str| Response {
            status: 200,
            reason: String::new(),
            version: "HTTP/1.1".into(),
            headers: vec![("Content-Disposition".into(), cd.into())],
            body: Vec::new(),
            timing: rsurl::Timing::default(),
            final_url: String::new(),
            tls: None,
        };
        let name = |cd: &str| content_disposition_filename(&resp(cd));
        // filename* wins regardless of order, and is percent-decoded.
        assert_eq!(
            name("attachment; filename=\"plain.txt\"; filename*=UTF-8''na%C3%AFve%20file.txt")
                .as_deref(),
            Some("naïve file.txt")
        );
        assert_eq!(
            name("attachment; filename*=UTF-8''ext.bin; filename=plain.bin").as_deref(),
            Some("ext.bin")
        );
        assert_eq!(
            name("attachment; filename*=iso-8859-1'en'caf%E9.txt").as_deref(),
            Some("café.txt")
        );
        // Quoted value with an escaped quote and a ';' inside.
        assert_eq!(
            name(r#"attachment; filename="a\"b;c.txt""#).as_deref(),
            Some("a\"b;c.txt")
        );
        // Path components (either separator) are stripped.
        assert_eq!(
            name("attachment; filename=\"../../etc/passwd\"").as_deref(),
            Some("passwd")
        );
        assert_eq!(
            name(r"attachment; filename=C:\win\evil.exe").as_deref(),
            Some("evil.exe")
        );
        // Quoted, `\w` is an escaped `w` (RFC 9110 quoted-pair): still no drive.
        assert_eq!(
            name(r#"attachment; filename="C:\win.exe""#).as_deref(),
            Some("win.exe")
        );
        assert_eq!(
            name("attachment; filename=\"a.txt:stream\"").as_deref(),
            Some("stream")
        );
        // Windows device names are refused, with or without an extension.
        for dev in ["CON", "nul.txt", "Com1", "LPT9.log", "aux"] {
            assert_eq!(name(&format!("attachment; filename={dev}")), None, "{dev}");
        }
        assert_eq!(
            name("attachment; filename=COM10.txt").as_deref(),
            Some("COM10.txt")
        );
        assert_eq!(name("attachment; filename=\"..\""), None);
        assert_eq!(name("inline"), None);
    }

    #[test]
    fn junk_session_cookies_drops_only_session_cookies() {
        let dir = std::env::temp_dir().join(format!("rsurl-cli-j-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("cookies.txt");
        std::fs::write(
            &file,
            "example.com\tFALSE\t/\tFALSE\t0\tsession\tv1\n\
             example.com\tFALSE\t/\tFALSE\t4102444800\tpersistent\tv2\n",
        )
        .unwrap();
        let path = file.to_str().unwrap().to_string();
        let names = |junk: bool| {
            let args = Args {
                cookie_in: Some(path.clone()),
                junk_session_cookies: junk,
                ..Default::default()
            };
            let jar = build_initial_jar(&args).unwrap().unwrap();
            let mut v: Vec<String> = jar.iter().map(|c| c.name.clone()).collect();
            v.sort();
            v
        };
        let with_all = names(false);
        let junked = names(true);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(with_all.contains(&"persistent".to_string()));
        assert_eq!(junked, vec!["persistent"]);
    }

    #[test]
    fn base64_matches_rfc4648() {
        for (i, o) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
        ] {
            assert_eq!(base64_encode(i.as_bytes()), o);
        }
    }

    // ---- sanitize_for_tty -----------------------------------------------

    #[test]
    fn sanitize_for_tty_passes_plain_ascii_and_utf8() {
        assert_eq!(sanitize_for_tty(b"hello world"), b"hello world");
        // Multi-byte UTF-8 (café, 日本語) must survive byte-for-byte.
        let utf8 = "café 日本語".as_bytes();
        assert_eq!(sanitize_for_tty(utf8), utf8);
    }

    #[test]
    fn sanitize_for_tty_preserves_tab() {
        assert_eq!(sanitize_for_tty(b"a\tb"), b"a\tb");
    }

    #[test]
    fn sanitize_for_tty_neutralizes_escape_sequences() {
        // ANSI CSI clear-screen: ESC [ 2 J
        assert_eq!(sanitize_for_tty(b"\x1b[2J"), b"\\x1b[2J");
        // OSC 52 clipboard write begins with ESC ] -> ESC neutralized, BEL too.
        assert_eq!(
            sanitize_for_tty(b"\x1b]52;c;Zm9v\x07"),
            b"\\x1b]52;c;Zm9v\\x07"
        );
        // Bare control bytes and DEL.
        assert_eq!(sanitize_for_tty(b"\x00\x07\x7f"), b"\\x00\\x07\\x7f");
        // C1 control range: the codepoint U+009B (single-byte CSI) encodes as
        // the two UTF-8 bytes 0xC2 0x9B; it must be neutralized as one char.
        assert_eq!(sanitize_for_tty("\u{9b}".as_bytes()), b"\\x9b");
        // Invalid UTF-8 bytes are escaped individually (e.g. a lone 0xa0).
        assert_eq!(sanitize_for_tty(b"\xa0"), b"\\xa0");
        // But the valid UTF-8 codepoint U+00A0 (NBSP, bytes 0xC2 0xA0) is text
        // and passes through unchanged.
        assert_eq!(sanitize_for_tty("\u{a0}".as_bytes()), "\u{a0}".as_bytes());
    }

    #[test]
    fn body_looks_binary_detects_nul() {
        assert!(body_looks_binary(b"\x89PNG\x00\x00"));
        assert!(!body_looks_binary(b"plain text\n"));
    }

    // ---- percent_encode_form --------------------------------------------

    #[test]
    fn percent_encode_form_passes_unreserved() {
        assert_eq!(percent_encode_form(b"abcXYZ012-._~"), "abcXYZ012-._~");
    }

    #[test]
    fn percent_encode_form_space_becomes_plus() {
        assert_eq!(percent_encode_form(b"hello world"), "hello+world");
    }

    #[test]
    fn percent_encode_form_special_chars_become_hex() {
        // = & + / ? % # are all encoded; '+' is %2B specifically (so the
        // wire encoding survives a re-decode that maps '+' back to space).
        assert_eq!(percent_encode_form(b"=&+/?%#"), "%3D%26%2B%2F%3F%25%23",);
    }

    #[test]
    fn percent_encode_form_high_bytes_use_uppercase_hex() {
        assert_eq!(percent_encode_form(&[0xC3, 0xA9]), "%C3%A9"); // "é"
    }

    // ---- strip_newlines -------------------------------------------------

    #[test]
    fn strip_newlines_removes_crlf_and_nul() {
        let got = strip_newlines(b"a\r\nb\nc\0d".to_vec());
        assert_eq!(got, b"abcd");
    }

    #[test]
    fn strip_newlines_keeps_other_whitespace() {
        // Tabs and spaces are preserved — curl only strips the three bytes.
        let got = strip_newlines(b"a\tb c\r\n".to_vec());
        assert_eq!(got, b"a\tb c");
    }

    // ---- encode_urlencoded ----------------------------------------------

    #[test]
    fn encode_urlencoded_plain_content() {
        // "content" → percent("content")
        let got = encode_urlencoded("hello world").unwrap();
        assert_eq!(got, b"hello+world");
    }

    #[test]
    fn encode_urlencoded_leading_eq_strips_name() {
        // "=content" → percent("content") with no name prefix.
        let got = encode_urlencoded("=hi there").unwrap();
        assert_eq!(got, b"hi+there");
    }

    #[test]
    fn encode_urlencoded_name_value() {
        // "name=content" → "name=percent(content)" (name verbatim)
        let got = encode_urlencoded("name=hello world").unwrap();
        assert_eq!(got, b"name=hello+world");
    }

    #[test]
    fn encode_urlencoded_at_file_reads_and_encodes() {
        let mut tmp = std::env::temp_dir();
        tmp.push("rsurl-urlencode-at-file.txt");
        std::fs::write(&tmp, b"hello world").unwrap();
        let spec = format!("@{}", tmp.display());
        let got = encode_urlencoded(&spec).unwrap();
        let _ = std::fs::remove_file(&tmp);
        assert_eq!(got, b"hello+world");
    }

    #[test]
    fn encode_urlencoded_name_at_file_reads_and_encodes() {
        let mut tmp = std::env::temp_dir();
        tmp.push("rsurl-urlencode-name-at.txt");
        std::fs::write(&tmp, b"value with spaces").unwrap();
        let spec = format!("k@{}", tmp.display());
        let got = encode_urlencoded(&spec).unwrap();
        let _ = std::fs::remove_file(&tmp);
        assert_eq!(got, b"k=value+with+spaces");
    }

    #[test]
    fn encode_urlencoded_eq_wins_over_at() {
        // "x=y@notafile" — the '=' takes precedence, so this is a name=value
        // form with literal value "y@notafile". File is never opened.
        let got = encode_urlencoded("x=y@notafile").unwrap();
        assert_eq!(got, b"x=y%40notafile");
    }

    // ---- assemble_form_body --------------------------------------------

    #[test]
    fn assemble_empty_is_none() {
        assert!(assemble_form_body(&[]).unwrap().is_none());
    }

    #[test]
    fn assemble_joins_with_ampersand() {
        let parts = vec![
            DataPart::Plain {
                value: "a=1".into(),
                at_file_ok: true,
            },
            DataPart::Plain {
                value: "b=2".into(),
                at_file_ok: true,
            },
        ];
        assert_eq!(assemble_form_body(&parts).unwrap().unwrap(), b"a=1&b=2");
    }

    #[test]
    fn assemble_plain_at_file_strips_newlines() {
        let mut tmp = std::env::temp_dir();
        tmp.push("rsurl-assemble-plain-at.txt");
        std::fs::write(&tmp, b"a\r\nb\n").unwrap();
        let parts = vec![DataPart::Plain {
            value: format!("@{}", tmp.display()),
            at_file_ok: true,
        }];
        let got = assemble_form_body(&parts).unwrap().unwrap();
        let _ = std::fs::remove_file(&tmp);
        assert_eq!(got, b"ab");
    }

    #[test]
    fn assemble_binary_at_file_keeps_newlines() {
        let mut tmp = std::env::temp_dir();
        tmp.push("rsurl-assemble-binary-at.txt");
        std::fs::write(&tmp, b"a\r\nb\n").unwrap();
        let parts = vec![DataPart::Binary {
            value: format!("@{}", tmp.display()),
        }];
        let got = assemble_form_body(&parts).unwrap().unwrap();
        let _ = std::fs::remove_file(&tmp);
        assert_eq!(got, b"a\r\nb\n");
    }

    #[test]
    fn assemble_data_raw_treats_at_literally() {
        // --data-raw with @file: the leading '@' is part of the value.
        let parts = vec![DataPart::Plain {
            value: "@literal".into(),
            at_file_ok: false,
        }];
        assert_eq!(assemble_form_body(&parts).unwrap().unwrap(), b"@literal");
    }

    #[test]
    fn assemble_mixes_data_modes() {
        let parts = vec![
            DataPart::Plain {
                value: "n=1".into(),
                at_file_ok: true,
            },
            DataPart::Binary {
                value: "rawbytes".into(),
            },
            DataPart::UrlEncoded {
                value: "k=hello world".into(),
            },
        ];
        let got = assemble_form_body(&parts).unwrap().unwrap();
        assert_eq!(got, b"n=1&rawbytes&k=hello+world");
    }

    #[test]
    fn userinfo_encoding_round_trips_special_characters() {
        let enc = pct_encode_userinfo("p@ss:w%rd /é");
        assert!(!enc.contains(['@', ':', ' ']), "{enc}");
        let (u, p) = decoded_userinfo(&format!("{}:{enc}", pct_encode_userinfo("a:b")));
        assert_eq!(u, "a:b");
        assert_eq!(p.as_deref(), Some("p@ss:w%rd /é"));
        assert_eq!(decoded_userinfo("solo"), ("solo".to_string(), None));
    }

    /// BEP 47 padding entries are hidden from `--bt-info` and `--bt-file`
    /// numbering, but their bytes still count toward later files' offsets.
    #[cfg(feature = "bittorrent")]
    #[test]
    fn bt_listing_and_selection_skip_padding_files() {
        use rsurl::bittorrent::{FileEntry, Metainfo};
        let fe = |p: &str, length: u64, padding: bool| FileEntry {
            path: p.into(),
            length,
            padding,
        };
        let meta = Metainfo {
            info_hash: [0; 20],
            name: "t".into(),
            piece_length: 16,
            pieces: vec![[0; 20]; 3],
            files: vec![
                fe("a.bin", 10, false),
                fe(".pad/6", 6, true),
                fe("b.bin", 20, false),
            ],
            total_length: 36,
            trackers: Vec::new(),
            private: false,
        };
        let json = metadata_json(&meta);
        assert!(!json.contains(".pad"), "{json}");
        assert!(
            json.contains(r#""path": "b.bin", "length": 20, "offset": 16"#),
            "{json}"
        );
        assert_eq!(bt_resolve_file(&meta, "2"), Ok((2, 16, 20)));
        assert_eq!(bt_resolve_file(&meta, "b.bin"), Ok((2, 16, 20)));
        assert!(bt_resolve_file(&meta, "3").is_err());
        assert!(
            bt_resolve_file(&meta, "6").is_err(),
            "padding is not selectable"
        );
    }
}

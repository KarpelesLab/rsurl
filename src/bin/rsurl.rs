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
use std::io::{self, IsTerminal, Read, Seek, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rsurl::{CookieJar, HttpVersionPref, Request, Response, Url};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Default, Clone)]
struct Args {
    urls: Vec<String>,
    output: Option<String>,
    include_headers: bool,
    head: bool,
    verbose: bool,
    /// Count of `-v` flags: 1 = verbose, 2+ = extra (e.g. per-peer torrent
    /// diagnostics). `verbose` stays `true` whenever this is ≥ 1.
    verbosity: u8,
    silent: bool,
    method: Option<String>,
    headers: Vec<(String, String)>,
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
    max_time: Option<u64>,
    connect_timeout: Option<u64>,
    remote_name: bool,
    /// Argument to `-b`/`--cookie`. Either explicit `k=v[; k=v]...` cookie
    /// data (detected by the presence of `=`) or a Netscape `cookies.txt`
    /// file path. Mirrors curl's behaviour.
    cookie_in: Option<String>,
    /// Argument to `-c`/`--cookie-jar`. After all transfers complete, the
    /// jar is written to this path in Netscape `cookies.txt` format.
    cookie_jar: Option<String>,
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

fn main() -> ExitCode {
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
    for op in &ops {
        for url in &op.urls {
            let expansions = if glob_disabled(op, url) {
                vec![(url.clone(), Vec::new())]
            } else {
                match glob_expand(url) {
                    Ok(v) => v,
                    Err(e) => {
                        if show_errors(op) {
                            eprintln!("rsurl: {e}");
                        }
                        last_failure = 3;
                        continue;
                    }
                }
            };
            for (eurl, caps) in expansions {
                let code =
                    if !caps.is_empty() && op.output.as_ref().is_some_and(|o| o.contains('#')) {
                        let mut op2 = op.clone();
                        op2.output = op.output.as_ref().map(|o| apply_glob_output(o, &caps));
                        process_url(&eurl, &op2, jar.as_mut())
                    } else {
                        process_url(&eurl, op, jar.as_mut())
                    };
                if code != 0 {
                    last_failure = code;
                }
            }
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

/// True if the short flag `c` consumes a value (so in a bundle the rest of the
/// token, or the next argv token, is that value).
fn short_flag_takes_value(c: char) -> bool {
    matches!(
        c,
        'o' | 'X'
            | 'H'
            | 'd'
            | 'F'
            | 'T'
            | 'A'
            | 'e'
            | 'u'
            | 'b'
            | 'c'
            | 'x'
            | 'E'
            | 'r'
            | 'D'
            | 'w'
            | 'C'
            | 'y'
            | 'Y'
            | 'U'
            | 'K'
            | 'P'
    )
}

/// Expand bundled short options the way getopt/curl do: `-sSv` → `-s -S -v`,
/// `-ofile` → `-o file`, `-sSofile` → `-s -S -o file`. Long options (`--x`),
/// bare `-`, and two-char tokens pass through unchanged.
fn expand_short_bundles(tokens: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for t in tokens {
        let is_bundle = t.len() > 2 && t.starts_with('-') && !t.starts_with("--");
        if !is_bundle {
            out.push(t.clone());
            continue;
        }
        let chars: Vec<char> = t[1..].chars().collect();
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            out.push(format!("-{c}"));
            if short_flag_takes_value(c) {
                let rest: String = chars[i + 1..].iter().collect();
                if !rest.is_empty() {
                    out.push(rest); // attached value; next argv token otherwise
                }
                break;
            }
            i += 1;
        }
    }
    out
}

/// A URL glob is a sequence of literal runs and brace/bracket sets.
enum GlobSeg {
    Lit(String),
    Set(Vec<String>),
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
                segs.push(GlobSeg::Set(items));
                i = close + 1;
            }
            '[' => {
                let close = find_close(&chars, i, '[', ']')
                    .ok_or_else(|| format!("unmatched '[' in URL glob: {url:?}"))?;
                let inner: String = chars[i + 1..close].iter().collect();
                let items = expand_range(&inner)
                    .ok_or_else(|| format!("bad range '[{inner}]' in URL glob"))?;
                if !lit.is_empty() {
                    segs.push(GlobSeg::Lit(std::mem::take(&mut lit)));
                }
                segs.push(GlobSeg::Set(items));
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

/// Expand a `[...]` range body: `1-100`, `001-100`, `a-z`, each with optional
/// `:step`.
fn expand_range(body: &str) -> Option<Vec<String>> {
    let (range, step) = match body.split_once(':') {
        Some((r, s)) => (r, s.parse::<usize>().ok().filter(|&s| s > 0)?),
        None => (body, 1),
    };
    let (start, end) = range.split_once('-')?;
    // Numeric range (with optional zero-padding to the start's width).
    if let (Ok(a), Ok(b)) = (start.parse::<u64>(), end.parse::<u64>()) {
        let width = if start.starts_with('0') && start.len() > 1 {
            start.len()
        } else {
            0
        };
        let mut out = Vec::new();
        let mut v = a;
        while v <= b {
            out.push(format!("{v:0width$}"));
            v += step as u64;
        }
        return Some(out);
    }
    // Single-char alpha range.
    let (sc, ec) = (start.chars().next()?, end.chars().next()?);
    if start.chars().count() == 1 && end.chars().count() == 1 && sc <= ec {
        let mut out = Vec::new();
        let mut c = sc as u32;
        while c <= ec as u32 {
            if let Some(ch) = char::from_u32(c) {
                out.push(ch.to_string());
            }
            c += step as u32;
        }
        return Some(out);
    }
    None
}

/// Expand a URL's globs into concrete `(url, captures)` pairs. `captures[k]` is
/// the chosen value of the k-th set, for `#N` output-name substitution.
fn glob_expand(url: &str) -> Result<Vec<(String, Vec<String>)>, String> {
    let segs = parse_glob(url)?;
    let mut results = vec![(String::new(), Vec::new())];
    for seg in &segs {
        match seg {
            GlobSeg::Lit(s) => {
                for (u, _) in results.iter_mut() {
                    u.push_str(s);
                }
            }
            GlobSeg::Set(items) => {
                let mut next = Vec::with_capacity(results.len() * items.len());
                for (u, caps) in &results {
                    for item in items {
                        let mut nu = u.clone();
                        nu.push_str(item);
                        let mut nc = caps.clone();
                        nc.push(item.clone());
                        next.push((nu, nc));
                    }
                }
                results = next;
            }
        }
    }
    Ok(results)
}

/// Whether URL globbing must be skipped for this operation's source. Globbing
/// (`{a,b}`/`[1-9]`, with `\` as the escape char) is a URL feature; a BitTorrent
/// source may instead be a local `.torrent` path — on Windows its backslashes
/// would be eaten as glob escapes — or a magnet link, neither of which is a URL
/// to expand. An `http(s)://` torrent URL still globs normally.
fn glob_disabled(op: &Args, url: &str) -> bool {
    op.globoff
        || url.starts_with("magnet:")
        || (op.torrent && !url.starts_with("http://") && !url.starts_with("https://"))
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
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

    struct Item<'a> {
        op: &'a Args,
        url: String,
        caps: Vec<String>,
    }
    let mut items: Vec<Item> = Vec::new();
    for op in ops {
        for url in &op.urls {
            let expansions = if glob_disabled(op, url) {
                vec![(url.clone(), Vec::new())]
            } else {
                match glob_expand(url) {
                    Ok(v) => v,
                    Err(e) => {
                        if show_errors(op) {
                            eprintln!("rsurl: {e}");
                        }
                        continue;
                    }
                }
            };
            for (eurl, caps) in expansions {
                items.push(Item {
                    op,
                    url: eurl,
                    caps,
                });
            }
        }
    }
    if items.is_empty() {
        return 0;
    }
    let max = ops
        .iter()
        .filter_map(|a| a.parallel_max)
        .max()
        .unwrap_or(50)
        .max(1);
    let n_threads = max.min(items.len());
    let idx = AtomicUsize::new(0);
    let worst = AtomicU8::new(0);
    std::thread::scope(|s| {
        for _ in 0..n_threads {
            s.spawn(|| loop {
                let i = idx.fetch_add(1, Ordering::Relaxed);
                if i >= items.len() {
                    break;
                }
                let item = &items[i];
                let code = if !item.caps.is_empty()
                    && item.op.output.as_ref().is_some_and(|o| o.contains('#'))
                {
                    let mut op2 = item.op.clone();
                    op2.output = item
                        .op
                        .output
                        .as_ref()
                        .map(|o| apply_glob_output(o, &item.caps));
                    process_url(&item.url, &op2, None)
                } else {
                    process_url(&item.url, item.op, None)
                };
                if code != 0 {
                    worst.store(code, Ordering::Relaxed);
                }
            });
        }
    });
    worst.load(Ordering::Relaxed)
}

/// Split a token stream into independent operations at `--next` / `-:`.
fn split_operations(toks: &[String]) -> Vec<Vec<String>> {
    let mut segs: Vec<Vec<String>> = vec![Vec::new()];
    for t in toks {
        if t == "--next" || t == "-:" {
            segs.push(Vec::new());
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
        if t == "-K" || t == "--config" {
            let path = it
                .next()
                .ok_or_else(|| "--config requires a file".to_string())?;
            let text =
                std::fs::read_to_string(path).map_err(|e| format!("config file {path}: {e}"))?;
            let inner = expand_config(&parse_config_text(&text), depth + 1)?;
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
    Ok(Some(jar))
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

/// Read the file at `path`, returning its bytes. Used by `-d @file`,
/// `--data-binary @file`, and `--data-urlencode @file`.
fn read_at_file(path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("can't read {path:?}: {e}"))
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
                    std::fs::read(path).map_err(|e| format!("-F: can't read {path:?}: {e}"))?;
                let name = std::path::Path::new(path)
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.clone());
                (bytes, Some(name), true)
            }
            FormBody::FileAsField(path) => {
                let bytes =
                    std::fs::read(path).map_err(|e| format!("-F: can't read {path:?}: {e}"))?;
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
    let bytes = std::fs::read(path).map_err(|e| format!("-T: can't read {path:?}: {e}"))?;
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
    // BitTorrent: a magnet link, or any source under `--torrent`. Routed before
    // URL parsing because the source may be a local `.torrent` path (not a URL)
    // and magnet links have no `://` authority.
    if args.torrent || url.starts_with("magnet:") {
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
                return run_ssh_upload(&parsed_url, path, args);
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
            return run_ssh(&parsed_url, args);
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
    if let Some(ua) = &args.user_agent {
        req = req.header("User-Agent", ua);
    }
    if let Some(rf) = &args.referer {
        req = req.header("Referer", rf);
    }
    if args.auto_referer {
        req = req.auto_referer(true);
    }
    // -z/--time-cond: If-Modified-Since (or If-Unmodified-Since for a leading
    // '-'); a value naming an existing file uses its mtime.
    if let Some(tc) = &args.time_cond {
        if let Some((hdr, date)) = time_cond_header(tc) {
            req = req.header(hdr, &date);
        } else if show_errors(args) {
            eprintln!("rsurl: warning: could not parse --time-cond {tc:?}");
        }
    }
    let has_header = |name: &str| {
        args.headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case(name))
    };
    // `--compressed`: advertise codecs we transparently decode. (We always
    // decode a compressed response; this just asks the server to send one.)
    if args.compressed && !has_header("accept-encoding") {
        req = req.header("Accept-Encoding", "gzip, deflate, br, zstd");
    }
    // `--json`: also request a JSON response (curl sets Accept too). The
    // Content-Type is applied via the assembled body's content type below.
    if !args.json_parts.is_empty() && !has_header("accept") {
        req = req.header("Accept", "application/json");
    }
    // `-r`/`--range`: a bare range becomes `bytes=<range>`.
    if let Some(r) = &args.range {
        if !has_header("range") {
            let v = if r.contains('=') {
                r.clone()
            } else {
                format!("bytes={r}")
            };
            req = req.header("Range", &v);
        }
    }
    if let Some((body_bytes, ctype, _method)) = assembled {
        if !args
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        {
            req = req.header("Content-Type", &ctype);
        }
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
        if !args
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        {
            req = req.header("Authorization", &format!("Bearer {token}"));
        }
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
    if let Some(secs) = args.max_time {
        req = req.max_time(Duration::from_secs(secs));
    }
    if let Some(secs) = args.connect_timeout {
        req = req.connect_timeout(Duration::from_secs(secs));
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

    // If `-b "k=v"` was given, apply those cookies to the jar against the
    // current URL before issuing the request. This must happen before the
    // send_*_with_jar call below, which moves the jar reference.
    if let (Some(j), Some(data)) = (jar.as_deref_mut(), args.cookie_in.as_deref()) {
        if data.contains('=') {
            apply_explicit_cookies(j, data, &parsed_url);
        }
    }

    // Stream the body straight to a file when that's safe and useful: a file
    // output (not a TTY, so no escape-guard needed), no header-inclusion, and
    // no status-gated body suppression. This is the path that enforces
    // --limit-rate, -# progress, and an early --max-filesize abort.
    if streams_to_file(args) {
        // `-C -`: resumable paths. A resumable parallel download is used when
        // segments are requested and there's no cookie jar; otherwise (or if the
        // server isn't range-capable) fall through to single-stream resume.
        if args.continue_resume {
            if parallel_segments_eligible(args) && jar.is_none() {
                if let Some(code) = run_parallel_resume(&req, &parsed_url, args) {
                    return code;
                }
            }
            return run_http_download(req, &parsed_url, args, jar);
        }
        if parallel_segments_eligible(args) {
            return run_parallel_download(req, &parsed_url, args, jar);
        }
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
                return transfer_exit_code(&e);
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

    // --fail-with-body: exit 22 on an HTTP error but still write the body.
    if args.fail_with_body && resp.status >= 400 {
        if show_errors(args) {
            eprintln!(
                "rsurl: The requested URL returned error: {} {}",
                resp.status, resp.reason
            );
        }
        let _ = write_output(&resp, &parsed_url, args);
        run_write_out(&resp, &parsed_url, args, time_total, resp.body.len() as u64);
        return 22;
    }

    // -f/--fail: on an HTTP error, emit no body and exit 22. (Without -f,
    // curl — and now rsurl — exits 0 even on 4xx/5xx.)
    if args.fail && resp.status >= 400 {
        if show_errors(args) {
            eprintln!(
                "rsurl: The requested URL returned error: {} {}",
                resp.status, resp.reason
            );
        }
        run_write_out(&resp, &parsed_url, args, time_total, resp.body.len() as u64);
        return 22;
    }

    if let Err(e) = write_output(&resp, &parsed_url, args) {
        if show_errors(args) {
            eprintln!("rsurl: write error: {e}");
        }
        return 23;
    }

    // -R/--remote-time: stamp the saved file's mtime from Last-Modified.
    if args.remote_time {
        if let Some(path) = args.output.as_deref().filter(|p| *p != "-") {
            set_remote_time(&resp, path);
        } else if args.remote_name {
            if let Ok(name) = remote_name_from_url(&parsed_url) {
                set_remote_time(&resp, &name);
            }
        }
    }

    run_write_out(&resp, &parsed_url, args, time_total, resp.body.len() as u64);
    0
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
                a.output = Some(next_val(&mut it, arg)?);
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
                let (k, v) = h
                    .split_once(':')
                    .ok_or_else(|| format!("malformed header: {h:?}"))?;
                a.headers.push((k.trim().to_string(), v.trim().to_string()));
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
            "--share-ratio" => {
                a.share_ratio = Some(
                    next_val(&mut it, arg)?
                        .parse()
                        .map_err(|_| "--share-ratio requires a number".to_string())?,
                )
            }
            "--tls-max" => {
                let v = next_val(&mut it, arg)?;
                a.tls_max = Some(match v.as_str() {
                    "1.3" => rsurl::tls::ProtocolVersion::TLSv1_3,
                    "1.0" | "1.1" | "1.2" => rsurl::tls::ProtocolVersion::TLSv1_2,
                    other => return Err(format!("--tls-max: unsupported version {other:?}")),
                });
            }
            "--no-idn" => a.no_idn = true,
            "--cacert" => a.cacert = Some(next_val(&mut it, arg)?),
            "--max-time" => {
                let v = next_val(&mut it, arg)?;
                a.max_time = Some(
                    v.parse::<u64>()
                        .map_err(|_| format!("--max-time: not a number: {v:?}"))?,
                );
            }
            "--connect-timeout" => {
                let v = next_val(&mut it, arg)?;
                a.connect_timeout = Some(
                    v.parse::<u64>()
                        .map_err(|_| format!("--connect-timeout: not a number: {v:?}"))?,
                );
            }
            "-O" | "--remote-name" => a.remote_name = true,
            "-b" | "--cookie" => a.cookie_in = Some(next_val(&mut it, arg)?),
            "-c" | "--cookie-jar" => a.cookie_jar = Some(next_val(&mut it, arg)?),
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
            ErrorKind::TimedOut => 28,
            ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted => 7,
            // std has no stable "name resolution failed" kind; the OS resolver
            // surfaces it in the message ("failed to lookup address ...").
            _ if io.to_string().contains("failed to lookup") => 6, // CURLE_COULDNT_RESOLVE_HOST
            _ => 7,                                                // CURLE_COULDNT_CONNECT
        },
    }
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
/// `Content-Disposition: ...; filename=...` (or `filename*=`). Path components,
/// `.`/`..`, and empty names are rejected so a server can't pick the directory.
fn content_disposition_filename(resp: &Response) -> Option<String> {
    let cd = resp.header("content-disposition")?;
    for part in cd.split(';') {
        let p = part.trim();
        let Some(val) = p
            .strip_prefix("filename*=")
            .or_else(|| p.strip_prefix("filename="))
        else {
            continue;
        };
        let val = val.trim().trim_matches('"');
        // RFC 5987 `filename*=UTF-8''name` — drop the charset'lang' prefix.
        let val = val.rsplit("''").next().unwrap_or(val);
        let name = std::path::Path::new(val).file_name()?.to_str()?.to_string();
        if name.is_empty() || name == "." || name == ".." {
            return None;
        }
        return Some(name);
    }
    None
}

fn next_val(it: &mut std::slice::Iter<'_, String>, flag: &str) -> Result<String, String> {
    it.next()
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}

/// Upload a local file to an `ftp://`/`ftps://` URL. By default this is `STOR`
/// (replace/create); with `-C <offset>` the local source is seeked past
/// `offset` bytes and a `REST <offset>` is sent so the server resumes from
/// there. With `-a`/`--append` it's `APPE` instead, which appends the whole
/// file to the remote — `APPE` negotiates no offset, so `-a` takes precedence
/// over `-C` (any `-C` is ignored and the full file is streamed). Returns a
/// curl-style exit code (0 ok, 7 on transfer error, 26 on local-read error).
fn run_ftp_upload(url: &Url, path: &str, args: &Args) -> u8 {
    let bytes = match std::fs::read(path) {
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
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            if show_errors(args) {
                eprintln!("rsurl: -T: can't read {path:?}: {e}");
            }
            return 26;
        }
    };

    match rsurl::tftp::store(url, &bytes) {
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
        timeout: args.max_time.map(Duration::from_secs),
    };
    Ok((opts, user))
}

/// Download an `sftp://`/`scp://` URL and write the bytes to `-o`/stdout (or
/// `-O`). Mirrors [`run_transfer`] but threads SSH auth options and, under
/// `-v`, prints the SSH trace to stderr. Exit codes: 0 ok, 2 usage, 7 transfer.
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
fn run_ssh_upload(url: &Url, path: &str, args: &Args) -> u8 {
    let bytes = match std::fs::read(path) {
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

    // curl publishes at QoS 0 by default. The protocol layer supports QoS 1
    // (PUBLISH then wait for PUBACK); there is no CLI flag to select it yet.
    match rsurl::mqtt::publish(url, &payload, 0) {
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
    if let Some(secs) = args.connect_timeout {
        c = c.connect_timeout(Some(Duration::from_secs(secs)));
    }
    if let Some(spec) = resolve_proxy_spec(url, args) {
        c = c.proxy(&spec)?;
    }
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
        Some(secs) => {
            let _ = ws.set_read_timeout(Some(Duration::from_secs(secs)));
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
        match std::fs::read(path) {
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
    let (user, pass) = match url.userinfo.as_deref() {
        Some(ui) => match ui.split_once(':') {
            Some((u, p)) => (Some(u.to_string()), Some(p.to_string())),
            None => (Some(ui.to_string()), None),
        },
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
        std::fs::read(path).unwrap_or_default()
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
    let (speed_limit, speed_time) = {
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
    };
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
        resume: None,
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
            "http_code" | "response_code" => resp.status.to_string(),
            "http_version" => resp.version.clone(),
            "size_download" => size_download.to_string(),
            "size_header" => size_header.to_string(),
            "num_headers" => resp.headers.len().to_string(),
            "content_type" => resp.header("content-type").unwrap_or("").to_string(),
            // We only reach write-out after a successful transfer; a TLS
            // verification failure aborts earlier, so this is always 0 (curl
            // also reports 0 for non-TLS schemes).
            "ssl_verify_result" => "0".to_string(),
            "url_effective" => {
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
    /// `-C -` resume: periodically persist the partial state to `.rsurlpart`.
    resume: Option<ResumeCtx>,
}

/// State for periodically rewriting a `.rsurlpart` trailer during a resumable
/// HTTP download.
struct ResumeCtx {
    part: std::path::PathBuf,
    total: u64,
    /// Pre-encoded validator tail (url/etag/last-modified); the trailer meta is
    /// `total + done` followed by this.
    validators: Vec<u8>,
    last_save: std::time::Instant,
}

/// Build the `http-stream` resume meta block: `[total][done] + validators`.
fn http_resume_meta(total: u64, done: u64, validators: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(16 + validators.len());
    m.extend_from_slice(&total.to_le_bytes());
    m.extend_from_slice(&done.to_le_bytes());
    m.extend_from_slice(validators);
    m
}

/// Encode the resume validators (final URL, ETag, Last-Modified) as
/// length-prefixed strings.
fn http_resume_validators(url: &str, etag: &str, last_modified: &str) -> Vec<u8> {
    let mut v = Vec::new();
    for s in [url, etag, last_modified] {
        let b = s.as_bytes();
        v.extend_from_slice(&(b.len() as u16).to_le_bytes());
        v.extend_from_slice(b);
    }
    v
}

/// Parse an `http-stream` meta block, returning `done` only if the stored
/// total/url/etag match the current resource (otherwise the partial is stale).
fn http_resume_parse(meta: &[u8], total: u64, url: &str, etag: &str) -> Option<u64> {
    if meta.len() < 16 {
        return None;
    }
    let stored_total = u64::from_le_bytes(meta[0..8].try_into().unwrap());
    let done = u64::from_le_bytes(meta[8..16].try_into().unwrap());
    if stored_total != total {
        return None;
    }
    let mut p = &meta[16..];
    let mut take = || -> Option<String> {
        if p.len() < 2 {
            return None;
        }
        let n = u16::from_le_bytes([p[0], p[1]]) as usize;
        if p.len() < 2 + n {
            return None;
        }
        let s = String::from_utf8_lossy(&p[2..2 + n]).into_owned();
        p = &p[2 + n..];
        Some(s)
    };
    let stored_url = take()?;
    let stored_etag = take()?;
    let _stored_lm = take()?;
    if stored_url != url {
        return None;
    }
    // If both sides have an ETag, they must agree (resource unchanged).
    if !etag.is_empty() && !stored_etag.is_empty() && etag != stored_etag {
        return None;
    }
    Some(done)
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
        // Persist resume state about once a second (bounded I/O).
        let written = self.written;
        if let Some(rc) = &mut self.resume {
            if rc.last_save.elapsed() >= std::time::Duration::from_secs(1) {
                let meta = http_resume_meta(rc.total, written, &rc.validators);
                let _ = rsurl::resume::write_state(
                    &rc.part,
                    rc.total,
                    rsurl::resume::Kind::HttpStream,
                    &meta,
                );
                rc.last_save = std::time::Instant::now();
            }
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

/// Smallest segment worth a separate connection (don't split tiny files).
const MIN_SEGMENT_BYTES: u64 = 1 << 20; // 1 MiB
/// Hard cap on concurrent segments regardless of `--parallel-segments`.
const MAX_SEGMENTS: usize = 16;

/// A `Write` that tallies bytes into a shared counter — lets the progress
/// render thread observe each segment's progress as it streams to the file.
struct CountingWriter<W> {
    inner: W,
    counter: Arc<AtomicU64>,
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.counter.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Format a byte count like `12.3 MiB`.
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

/// A fixed-width `[████░░░░]` bar for `got`/`total`.
fn progress_bar(got: u64, total: u64, width: usize) -> String {
    let filled = if total == 0 {
        width
    } else {
        ((got as u128 * width as u128 / total as u128) as usize).min(width)
    };
    let mut s = String::with_capacity(width + 2);
    s.push('[');
    for _ in 0..filled {
        s.push('\u{2588}'); // █
    }
    for _ in filled..width {
        s.push('\u{2591}'); // ░
    }
    s.push(']');
    s
}

/// Draw the parallel-download progress. On a TTY: one line per segment plus an
/// aggregate line, redrawn in place. Off a TTY: a single `\r` aggregate line.
fn render_parallel(
    lens: &[u64],
    counters: &[Arc<AtomicU64>],
    total: u64,
    start: std::time::Instant,
    tty: bool,
    first: &mut bool,
) {
    const BAR_W: usize = 24;
    let mut err = io::stderr().lock();
    let done: u64 = counters.iter().map(|c| c.load(Ordering::Relaxed)).sum();
    let secs = start.elapsed().as_secs_f64();
    let rate = if secs > 0.0 {
        (done as f64 / secs) as u64
    } else {
        0
    };

    if tty {
        let lines = lens.len() + 1; // per-segment lines + aggregate
        if *first {
            *first = false;
        } else {
            let _ = write!(err, "\x1b[{lines}A");
        }
        for (i, (len, ctr)) in lens.iter().zip(counters).enumerate() {
            let got = ctr.load(Ordering::Relaxed);
            let _ = writeln!(
                err,
                "\r\x1b[2K  seg {:>2}/{:<2} {} {}/{}",
                i + 1,
                lens.len(),
                progress_bar(got, *len, BAR_W),
                human_bytes(got),
                human_bytes(*len),
            );
        }
        let _ = writeln!(
            err,
            "\r\x1b[2K  total     {} {}/{}  {}/s",
            progress_bar(done, total, BAR_W),
            human_bytes(done),
            human_bytes(total),
            human_bytes(rate),
        );
    } else {
        let _ = write!(
            err,
            "\rrsurl: {}/{} ({}/s)   ",
            human_bytes(done),
            human_bytes(total),
            human_bytes(rate),
        );
    }
    let _ = err.flush();
}

/// Size of a resumable parallel download's fixed chunk (the bitmap unit).
const RESUME_CHUNK: u64 = 4 * 1024 * 1024;

fn bit_get(map: &[u8], i: usize) -> bool {
    map[i / 8] & (1 << (i % 8)) != 0
}
fn bit_set(map: &mut [u8], i: usize) {
    map[i / 8] |= 1 << (i % 8);
}

/// Encode an `http-ranged` resume meta block: `[chunk_size:u32][total:u64]`,
/// the validator tail, then the chunk bitmap.
fn http_ranged_meta(chunk: u32, total: u64, validators: &[u8], bitmap: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(12 + validators.len() + bitmap.len());
    m.extend_from_slice(&chunk.to_le_bytes());
    m.extend_from_slice(&total.to_le_bytes());
    m.extend_from_slice(&(validators.len() as u32).to_le_bytes());
    m.extend_from_slice(validators);
    m.extend_from_slice(bitmap);
    m
}

/// Parse an `http-ranged` meta block, returning the chunk bitmap only if the
/// chunk size / total / url / etag still match the current resource.
fn http_ranged_parse(
    meta: &[u8],
    chunk: u32,
    total: u64,
    url: &str,
    etag: &str,
) -> Option<Vec<u8>> {
    if meta.len() < 16 {
        return None;
    }
    if u32::from_le_bytes(meta[0..4].try_into().unwrap()) != chunk {
        return None;
    }
    if u64::from_le_bytes(meta[4..12].try_into().unwrap()) != total {
        return None;
    }
    let vlen = u32::from_le_bytes(meta[12..16].try_into().unwrap()) as usize;
    let rest = meta.get(16..)?;
    let validators = rest.get(..vlen)?;
    let bitmap = rest.get(vlen..)?.to_vec();
    if !validators_match(validators, url, etag) {
        return None;
    }
    Some(bitmap)
}

/// Compare stored validators against the current url/etag, ignoring the
/// (possibly differing) Last-Modified field.
fn validators_match(stored: &[u8], url: &str, etag: &str) -> bool {
    // Decode the three length-prefixed strings.
    let mut p = stored;
    let mut take = || -> Option<String> {
        if p.len() < 2 {
            return None;
        }
        let n = u16::from_le_bytes([p[0], p[1]]) as usize;
        let s = String::from_utf8_lossy(p.get(2..2 + n)?).into_owned();
        p = &p[2 + n..];
        Some(s)
    };
    let (Some(su), Some(se), Some(_lm)) = (take(), take(), take()) else {
        return false;
    };
    su == url && (etag.is_empty() || se.is_empty() || se == etag)
}

/// `-C -` resumable parallel download: split the file into fixed chunks, fetch
/// the not-yet-done ones concurrently via Range requests into `<name>.rsurlpart`
/// (persisting a chunk bitmap), and finalise on completion. Returns `None` to
/// fall back to single-stream resume (server not range-capable / not seekable /
/// no concrete output file).
fn run_parallel_resume(req: &rsurl::Request, url: &Url, args: &Args) -> Option<u8> {
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::sync::Mutex;

    let name = if args.remote_name {
        remote_name_from_url(url).ok()?
    } else {
        args.output.clone().unwrap_or_default()
    };
    if name.is_empty() || name == "-" {
        return None;
    }

    let probe = req.clone().method("HEAD").send().ok()?;
    if probe.status >= 400 {
        return None;
    }
    let total = probe
        .header("content-length")
        .and_then(|v| v.trim().parse::<u64>().ok())?;
    if total == 0
        || !probe
            .header("accept-ranges")
            .is_some_and(|v| v.to_ascii_lowercase().contains("bytes"))
    {
        return None;
    }
    if let Some(max) = args.max_filesize {
        if total > max {
            if show_errors(args) {
                eprintln!("rsurl: Maximum file size exceeded");
            }
            return Some(63);
        }
    }
    let etag = probe.header("etag").unwrap_or("").to_string();
    let last_mod = probe.header("last-modified").unwrap_or("").to_string();
    let url_s = format!("{}://{}:{}{}", url.scheme, url.host, url.port, url.path);

    let final_path = resolve_output_path(&name, args);
    if args.create_dirs {
        if let Some(p) = final_path.parent() {
            let _ = std::fs::create_dir_all(p);
        }
    } else if let Some(dir) = &args.output_dir {
        let _ = std::fs::create_dir_all(dir);
    }
    let part = rsurl::resume::part_path(&final_path);

    let num_chunks = total.div_ceil(RESUME_CHUNK) as usize;
    let map_len = num_chunks.div_ceil(8);
    let validators = http_resume_validators(&url_s, &etag, &last_mod);
    let mut bitmap = vec![0u8; map_len];
    if let Ok(Some(st)) = rsurl::resume::read_state(&part) {
        if st.kind == rsurl::resume::Kind::HttpRanged {
            if let Some(bm) = http_ranged_parse(&st.meta, RESUME_CHUNK as u32, total, &url_s, &etag)
            {
                if bm.len() == map_len {
                    bitmap = bm;
                }
            }
        }
    }

    // Size the data region and stamp the initial state.
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&part)
    {
        Ok(f) => {
            if f.set_len(total).is_err() {
                return None; // not a seekable regular file
            }
        }
        Err(_) => return None,
    }
    let _ = rsurl::resume::write_state(
        &part,
        total,
        rsurl::resume::Kind::HttpRanged,
        &http_ranged_meta(RESUME_CHUNK as u32, total, &validators, &bitmap),
    );

    let n_workers = args
        .parallel_segments
        .unwrap_or(1)
        .min(MAX_SEGMENTS)
        .min(num_chunks.max(1));
    if args.verbose {
        let done = (0..num_chunks).filter(|&i| bit_get(&bitmap, i)).count();
        eprintln!(
            "* resumable parallel: {num_chunks} chunks ({done} already done), {n_workers} workers"
        );
    }

    let bitmap = Arc::new(Mutex::new(bitmap));
    let next = Arc::new(AtomicUsize::new(0));
    let failed = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::with_capacity(n_workers);
    for _ in 0..n_workers {
        let req = req.clone();
        let part = part.clone();
        let bitmap = Arc::clone(&bitmap);
        let next = Arc::clone(&next);
        let failed = Arc::clone(&failed);
        let validators = validators.clone();
        handles.push(std::thread::spawn(move || {
            while !failed.load(Ordering::Relaxed) {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= num_chunks {
                    break;
                }
                if bit_get(&bitmap.lock().unwrap(), i) {
                    continue; // already have this chunk
                }
                let start = i as u64 * RESUME_CHUNK;
                let end = (start + RESUME_CHUNK).min(total) - 1;
                let r = req.clone().header("Range", &format!("bytes={start}-{end}"));
                let mut f = match std::fs::OpenOptions::new().write(true).open(&part) {
                    Ok(f) => f,
                    Err(_) => {
                        failed.store(true, Ordering::Relaxed);
                        break;
                    }
                };
                if f.seek(io::SeekFrom::Start(start)).is_err() {
                    failed.store(true, Ordering::Relaxed);
                    break;
                }
                match r.send_download(&mut f, None, &mut io::sink()) {
                    Ok(resp) if resp.status == 206 => {}
                    _ => {
                        failed.store(true, Ordering::Relaxed);
                        break;
                    }
                }
                // Mark done and persist the bitmap (serialised on the lock).
                let mut bm = bitmap.lock().unwrap();
                bit_set(&mut bm, i);
                let _ = rsurl::resume::write_state(
                    &part,
                    total,
                    rsurl::resume::Kind::HttpRanged,
                    &http_ranged_meta(RESUME_CHUNK as u32, total, &validators, &bm),
                );
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }

    if failed.load(Ordering::Relaxed) {
        if show_errors(args) {
            eprintln!("rsurl: parallel resume incomplete; re-run to continue");
        }
        return Some(18); // CURLE_PARTIAL_FILE
    }

    drop(bitmap);
    if let Err(e) = rsurl::resume::finalize(&part, &final_path, total) {
        if show_errors(args) {
            eprintln!("rsurl: finalize {}: {e}", final_path.display());
        }
        return Some(23);
    }
    if args.remote_time {
        set_remote_time(&probe, &name);
    }
    Some(0)
}

/// Download a single file over `n` concurrent HTTP range requests. Probes with
/// HEAD; if the server doesn't support ranges, the size is unknown/small, or
/// anything goes wrong, falls back to the normal single-stream download
/// ([`run_http_download`]) so behavior is never worse than without the flag.
fn run_parallel_download(
    req: rsurl::Request,
    url: &Url,
    args: &Args,
    jar: Option<&mut CookieJar>,
) -> u8 {
    // Cookies aren't shared across segment threads; keep cookie semantics by
    // falling back to the single-stream path when a jar is in use.
    if jar.is_some() {
        return run_http_download(req, url, args, jar);
    }

    // HEAD probe carries the request's auth/headers/proxy and (if --location)
    // follows redirects to the final resource.
    let probe = match req.clone().method("HEAD").send() {
        Ok(r) => r,
        Err(_) => return run_http_download(req, url, args, None),
    };
    let size = probe
        .header("content-length")
        .and_then(|v| v.trim().parse::<u64>().ok());
    let ranges_ok = probe
        .header("accept-ranges")
        .is_some_and(|v| v.to_ascii_lowercase().contains("bytes"));
    let (Some(size), true) = (size, ranges_ok && probe.status < 400) else {
        return run_http_download(req, url, args, None);
    };

    if let Some(max) = args.max_filesize {
        if size > max {
            if show_errors(args) {
                eprintln!("rsurl: Maximum file size exceeded");
            }
            return 63;
        }
    }

    let requested = args.parallel_segments.unwrap_or(1).min(MAX_SEGMENTS);
    let by_size = size.div_ceil(MIN_SEGMENT_BYTES).max(1) as usize;
    let n = requested.min(by_size);
    if n < 2 {
        // Too small to benefit — one stream is just as good.
        return run_http_download(req, url, args, None);
    }

    let name = if args.remote_name {
        match remote_name_from_url(url) {
            Ok(nm) => nm,
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
    // Preallocate so each segment can seek to its offset and write in place.
    if file.set_len(size).is_err() {
        // Not a regular seekable file — fall back (recreates/truncates it).
        drop(file);
        return run_http_download(req, url, args, None);
    }
    drop(file);

    if args.verbose {
        eprintln!("* Parallel download: {n} segments, {size} bytes");
    }

    let seg = size / n as u64;
    let now = std::time::Instant::now();

    // Per-segment byte counters drive the live display without depending on any
    // one segment's write cadence.
    let counters: Vec<Arc<AtomicU64>> = (0..n).map(|_| Arc::new(AtomicU64::new(0))).collect();
    let mut lens = Vec::with_capacity(n);

    let mut handles = Vec::with_capacity(n);
    for (i, counter_slot) in counters.iter().enumerate() {
        let start = i as u64 * seg;
        let end = if i == n - 1 {
            size - 1
        } else {
            (i as u64 + 1) * seg - 1
        };
        lens.push(end - start + 1);
        let seg_req = req.clone().header("Range", &format!("bytes={start}-{end}"));
        let path = out_path.clone();
        let counter = Arc::clone(counter_slot);
        handles.push(std::thread::spawn(move || -> Result<u64, String> {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .map_err(|e| e.to_string())?;
            f.seek(io::SeekFrom::Start(start))
                .map_err(|e| e.to_string())?;
            // Count bytes as they land so the render thread can show progress.
            let mut w = CountingWriter { inner: f, counter };
            let mut trace = io::sink();
            let resp = seg_req
                .send_download(&mut w, None, &mut trace)
                .map_err(|e| e.to_string())?;
            if resp.status != 206 {
                return Err(format!(
                    "server did not honor Range (status {})",
                    resp.status
                ));
            }
            Ok(end - start + 1)
        }));
    }

    // Live progress display (with `-#`): a render thread redraws every ~120 ms.
    let show_progress = args.progress_bar && !args.silent;
    let render = if show_progress {
        let lens = lens.clone();
        let counters: Vec<Arc<AtomicU64>> = counters.iter().map(Arc::clone).collect();
        let done = Arc::new(AtomicBool::new(false));
        let done_w = Arc::clone(&done);
        let tty = io::stderr().is_terminal();
        let handle = std::thread::spawn(move || {
            let mut first = true;
            while !done_w.load(Ordering::Relaxed) {
                render_parallel(&lens, &counters, size, now, tty, &mut first);
                std::thread::sleep(std::time::Duration::from_millis(120));
            }
            render_parallel(&lens, &counters, size, now, tty, &mut first);
            eprintln!();
        });
        Some((done, handle))
    } else {
        None
    };

    let mut total = 0u64;
    let mut failure: Option<String> = None;
    for h in handles {
        match h.join() {
            Ok(Ok(written)) => total += written,
            Ok(Err(e)) => {
                failure.get_or_insert(e);
            }
            Err(_) => {
                failure.get_or_insert_with(|| "segment thread panicked".to_string());
            }
        }
    }
    if let Some((done, handle)) = render {
        done.store(true, Ordering::Relaxed);
        let _ = handle.join();
    }

    if failure.is_none() && total == size {
        let elapsed = now.elapsed();
        if args.remote_time {
            set_remote_time(&probe, &name);
        }
        run_write_out(&probe, url, args, elapsed, size);
        return 0;
    }

    // Something went wrong mid-stream — retry as a single stream, which
    // recreates (truncates) the file via the normal path.
    if args.verbose {
        eprintln!(
            "* Parallel download incomplete ({}); retrying as a single stream",
            failure.as_deref().unwrap_or("size mismatch")
        );
    }
    run_http_download(req, url, args, None)
}

/// Resolve the on-disk file layout for a torrent given the CLI output flags.
/// Per rsurl policy, a download requires an explicit target.
#[cfg(feature = "bittorrent")]
fn bt_layout(
    meta: &rsurl::bittorrent::Metainfo,
    args: &Args,
) -> std::result::Result<Vec<(std::path::PathBuf, u64)>, String> {
    use std::path::Path;
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
fn bt_announce_peers(
    trackers: &[String],
    info_hash: [u8; 20],
    peer_id: [u8; 20],
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
        key: 0,
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
    let listen_port = args.listen_port.unwrap_or(6881);
    // --share-ratio implies seeding to that ratio; --seed alone seeds forever.
    let seed = match (args.share_ratio, args.seed) {
        (Some(r), _) => SeedMode::UntilRatio(r),
        (None, true) => SeedMode::Forever,
        (None, false) => SeedMode::Off,
    };
    let opts = TorrentOptions {
        peer_id,
        listen_port,
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

    // 1) Obtain the metainfo and the tracker list.
    let (meta, trackers) = if source.starts_with("magnet:") {
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
            Ok(m) => (m, magnet.trackers),
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
                (m, trackers)
            }
            Err(e) => {
                if show_errors(args) {
                    eprintln!("rsurl: {e}");
                }
                return 1;
            }
        }
    };

    // 2) Output layout.
    let layout = match bt_layout(&meta, args) {
        Ok(l) => l,
        Err(msg) => {
            if show_errors(args) {
                eprintln!("rsurl: {msg}");
            }
            return 2;
        }
    };

    // 3) If we still have no peers, announce the trackers for the download,
    //    then fall back to the DHT.
    if peers.is_empty() {
        peers = bt_announce_peers(
            &trackers,
            meta.info_hash,
            peer_id,
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
    let total = meta.total_length;
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
    let result = bittorrent::download(&meta, layout, &peers, &opts, &mut cb);
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

/// `-C -` resume for a single HTTP stream. Probes with HEAD; if the server
/// reports a size and `Accept-Ranges: bytes`, downloads into `<name>.rsurlpart`
/// (continuing any valid prior partial via `Range: bytes=done-`), periodically
/// persisting the resume trailer, and finalises (truncate + rename) on success.
/// Returns `Some(exit_code)` when it handled the transfer, or `None` to fall
/// back to a normal in-place download.
fn http_resume(
    req: &rsurl::Request,
    url: &Url,
    args: &Args,
    name: &str,
    mut jar: Option<&mut CookieJar>,
) -> Option<u8> {
    // HEAD probe for size + range support + validators.
    let probe = req.clone().method("HEAD").send().ok()?;
    if probe.status >= 400 {
        return None;
    }
    let total = probe
        .header("content-length")
        .and_then(|v| v.trim().parse::<u64>().ok())?;
    if !probe
        .header("accept-ranges")
        .is_some_and(|v| v.to_ascii_lowercase().contains("bytes"))
    {
        return None;
    }
    if let Some(max) = args.max_filesize {
        if total > max {
            if show_errors(args) {
                eprintln!("rsurl: Maximum file size exceeded");
            }
            return Some(63);
        }
    }
    let etag = probe.header("etag").unwrap_or("").to_string();
    let last_mod = probe.header("last-modified").unwrap_or("").to_string();
    // A stable per-resource validator string (deterministic across runs).
    let url_s = format!("{}://{}:{}{}", url.scheme, url.host, url.port, url.path);

    let final_path = resolve_output_path(name, args);
    if args.create_dirs {
        if let Some(p) = final_path.parent() {
            let _ = std::fs::create_dir_all(p);
        }
    } else if let Some(dir) = &args.output_dir {
        let _ = std::fs::create_dir_all(dir);
    }
    let part = rsurl::resume::part_path(&final_path);

    // Resume offset from any matching prior partial.
    let mut done = match rsurl::resume::read_state(&part) {
        Ok(Some(st)) if st.kind == rsurl::resume::Kind::HttpStream => {
            http_resume_parse(&st.meta, total, &url_s, &etag).unwrap_or(0)
        }
        _ => 0,
    };
    if done > total {
        done = 0;
    }
    if done == total {
        if let Err(e) = rsurl::resume::finalize(&part, &final_path, total) {
            if show_errors(args) {
                eprintln!("rsurl: finalize {}: {e}", final_path.display());
            }
            return Some(23);
        }
        return Some(0);
    }

    let (speed_limit, speed_time) = low_speed_params(args);
    let validators = http_resume_validators(&url_s, &etag, &last_mod);

    // At most two attempts: if a ranged GET comes back 200 (range ignored), we
    // restart once from offset 0.
    for _ in 0..2 {
        let from = done;
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&part)
        {
            Ok(f) => f,
            Err(e) => {
                if show_errors(args) {
                    eprintln!("rsurl: open {}: {e}", part.display());
                }
                return Some(23);
            }
        };
        // Size the data region to `total` (drops any stale trailer), then append
        // from `from`.
        if file.set_len(total).is_err() {
            return None; // not a seekable regular file — fall back
        }
        let mut f = file;
        if f.seek(io::SeekFrom::Start(from)).is_err() {
            return None;
        }

        let now = std::time::Instant::now();
        let mut sink = DownloadSink {
            inner: Box::new(f),
            written: from,
            max: args.max_filesize,
            rate: args.limit_rate.as_deref().and_then(parse_rate),
            speed_limit,
            speed_time,
            started: now,
            progress: args.progress_bar,
            silent: args.silent,
            last_tick: now,
            resume: Some(ResumeCtx {
                part: part.clone(),
                total,
                validators: validators.clone(),
                last_save: now,
            }),
        };
        let mut greq = req.clone();
        if from > 0 {
            greq = greq.header("Range", &format!("bytes={from}-"));
        }
        let result = if args.verbose {
            let mut err = io::stderr().lock();
            greq.send_download(&mut sink, jar.as_deref_mut(), &mut err)
        } else {
            greq.send_download(&mut sink, jar.as_deref_mut(), &mut io::sink())
        };
        if args.progress_bar && !args.silent {
            eprintln!();
        }
        match result {
            Ok(resp) => {
                if from > 0 && resp.status == 200 {
                    // Server ignored the Range — restart cleanly from scratch.
                    if args.verbose {
                        eprintln!("* server ignored Range; restarting from 0");
                    }
                    done = 0;
                    continue;
                }
                drop(sink); // close the handle before renaming (Windows)
                if let Err(e) = rsurl::resume::finalize(&part, &final_path, total) {
                    if show_errors(args) {
                        eprintln!("rsurl: finalize {}: {e}", final_path.display());
                    }
                    return Some(23);
                }
                if args.remote_time {
                    set_remote_time(&resp, name);
                }
                run_write_out(&resp, url, args, now.elapsed(), total);
                return Some(0);
            }
            Err(e) => {
                // Persist the latest offset so a re-run can resume.
                let written = sink.written;
                drop(sink);
                let meta = http_resume_meta(total, written, &validators);
                let _ = rsurl::resume::write_state(
                    &part,
                    total,
                    rsurl::resume::Kind::HttpStream,
                    &meta,
                );
                if show_errors(args) {
                    eprintln!("rsurl: {e}");
                }
                return Some(transfer_exit_code(&e));
            }
        }
    }
    Some(0)
}

fn run_http_download(
    req: rsurl::Request,
    url: &Url,
    args: &Args,
    mut jar: Option<&mut CookieJar>,
) -> u8 {
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
    // `-C -`: resume into <name>.rsurlpart via a Range request when the server
    // supports it. Returns None (fall through to a normal download) if the
    // target isn't a concrete file or the server isn't range-capable.
    if args.continue_resume && !name.is_empty() && name != "-" {
        if let Some(code) = http_resume(&req, url, args, &name, jar.as_deref_mut()) {
            return code;
        }
    }
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
        resume: None,
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
    match result {
        Ok(resp) => {
            if args.remote_time {
                set_remote_time(&resp, &name);
            }
            run_write_out(&resp, url, args, time_total, written);
            0
        }
        Err(e) => {
            // --remove-on-error: drop the (partial) file. Close the handle
            // first — Windows refuses to unlink a file that's still open.
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

/// As [`create_output_file_tracked`], discarding the resolved path. Used by the
/// callers that don't need to delete the file afterward.
fn create_output_file(path: &str, args: &Args) -> io::Result<File> {
    create_output_file_tracked(path, args).map(|(f, _)| f)
}

/// `-D`/`--dump-header`: write the status line and response headers to `path`,
/// CRLF-terminated, exactly as curl does.
fn dump_headers(resp: &Response, path: &str) -> io::Result<()> {
    let mut f = File::create(path)?;
    write!(f, "{} {} {}\r\n", resp.version, resp.status, resp.reason)?;
    for (k, v) in &resp.headers {
        write!(f, "{k}: {v}\r\n")?;
    }
    f.write_all(b"\r\n")
}

/// `-R`/`--remote-time`: stamp `path`'s mtime from the response `Last-Modified`
/// header. Best-effort — failures (bad date, unsupported FS) are ignored.
fn set_remote_time(resp: &Response, path: &str) {
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

fn write_output(resp: &Response, url: &Url, args: &Args) -> io::Result<()> {
    // Track whether we are writing to stdout (vs. a real file via -o/-O) and
    // whether the user explicitly asked for stdout with `-o -` / `--output -`.
    // Only stdout-to-a-terminal is ever sanitized/guarded; bytes redirected to
    // a file or pipe must be delivered exactly as received (don't corrupt
    // downloads).
    let mut to_stdout = true;
    let mut explicit_stdout = false;
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
        Box::new(create_output_file(&name, args)?)
    } else {
        match &args.output {
            Some(path) if path != "-" => {
                to_stdout = false;
                Box::new(create_output_file(path, args)?)
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
        } else {
            // Text body to a TTY: neutralize embedded control sequences.
            out.write_all(&sanitize_for_tty(&resp.body))?;
        }
    } else {
        out.write_all(&resp.body)?;
    }
    Ok(())
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
                           proxy; \"*\" bypasses everything
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
      --listen-port <p>    port advertised to BitTorrent peers/trackers (6881)
      --bt-peer <ip:port>  add a torrent peer directly (repeatable)
      --no-dht             disable the DHT peer-discovery fallback
      --seed               keep seeding after the torrent completes
      --share-ratio <r>    seed until uploaded/downloaded reaches r, then exit
      --recheck            on torrent resume, re-hash on-disk data instead of
                           trusting the saved .rsurlpart bitfield
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
            .into_iter()
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

    #[test]
    fn glob_zero_padded_and_step_and_alpha() {
        assert_eq!(expand_range("08-11").unwrap(), vec!["08", "09", "10", "11"]);
        assert_eq!(expand_range("1-10:3").unwrap(), vec!["1", "4", "7", "10"]);
        assert_eq!(expand_range("a-e:2").unwrap(), vec!["a", "c", "e"]);
    }

    #[test]
    fn glob_output_substitution() {
        let (_, caps) = &glob_expand("img[1-2].jpg").unwrap()[0];
        assert_eq!(apply_glob_output("out-#1.bin", caps), "out-1.bin");
    }

    #[test]
    fn short_bundles_expand() {
        let got = expand_short_bundles(&["-sS".into(), "-ofile".into(), "u".into()]);
        assert_eq!(got, vec!["-s", "-S", "-o", "file", "u"]);
        // long options and bare dash pass through
        let got2 = expand_short_bundles(&["--silent".into(), "-".into()]);
        assert_eq!(got2, vec!["--silent", "-"]);
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
}

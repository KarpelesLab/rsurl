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
//!     -X, --request <method>   override HTTP method
//!     -H, --header <line>      add a request header (repeatable)
//!     -d, --data <body>        POST body (urlencoded); @file reads from disk
//!         --data-raw <body>    like -d but no @file interpretation
//!         --data-binary <body> like -d but no newline stripping when @file
//!         --data-urlencode <s> URL-encode <s> before sending; @file allowed
//!     -A, --user-agent <ua>    set User-Agent
//!     -e, --referer <ref>      set Referer
//!     -L, --location           follow 3xx redirects
//!         --max-redirs <n>     cap on redirect hops (default 50)
//!     -u, --user <user:pass>   HTTP Basic auth credentials
//!     -k, --insecure           don't verify the TLS certificate chain
//!         --cacert <file>      PEM bundle to use instead of system trust
//!         --max-time <secs>    cap on the whole operation's wall time
//!         --connect-timeout    cap on the TCP connect step
//!         --http2              require HTTP/2 (ALPN h2); error if unavailable
//!         --http1.1            force HTTP/1.1 (alias: --http1)
//!     -b, --cookie <data>      cookies: "k=v[; k=v]" or a Netscape file path
//!     -c, --cookie-jar <file>  write all known cookies to <file> on exit
//!     -x, --proxy <url>        outbound HTTP proxy (e.g. http://host:port)
//!         --proxy-user <u:p>   credentials for the proxy
//!         --noproxy <hosts>    comma-list of host suffixes that bypass it
//!     -h, --help               print help
//!     -V, --version            print version

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use rsurl::{CookieJar, HttpVersionPref, Request, Response, Url};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Default)]
struct Args {
    urls: Vec<String>,
    output: Option<String>,
    include_headers: bool,
    head: bool,
    verbose: bool,
    silent: bool,
    method: Option<String>,
    headers: Vec<(String, String)>,
    /// One entry per `-d` / `--data-raw` / `--data-binary` / `--data-urlencode`
    /// on the command line, in order. Final body is the concatenation of
    /// each part's encoded bytes joined with `b"&"`. See [`DataPart`] and
    /// [`assemble_form_body`].
    data_parts: Vec<DataPart>,
    user_agent: Option<String>,
    referer: Option<String>,
    /// Most recent HTTP version flag (--http2, --http1.1) seen on the CLI.
    /// `None` means "Auto" — the library decides via ALPN. Last one wins,
    /// matching curl.
    http_version: Option<HttpVersionPref>,
    follow_redirects: bool,
    max_redirs: Option<u32>,
    basic_auth: Option<(String, String)>,
    insecure: bool,
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

fn main() -> ExitCode {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse_args(&raw) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("rsurl: {e}");
            eprintln!("try 'rsurl --help'");
            return ExitCode::from(2);
        }
    };

    if args.urls.is_empty() {
        print_usage();
        return ExitCode::from(2);
    }

    // Cookie jar: built once and shared across every URL on the command
    // line, so Set-Cookie from URL N is visible to URL N+1, just like curl.
    // We only allocate one if the user asked for cookie behaviour.
    let mut jar: Option<CookieJar> = match build_initial_jar(&args) {
        Ok(j) => j,
        Err(e) => {
            if !args.silent {
                eprintln!("rsurl: {e}");
            }
            return ExitCode::from(2);
        }
    };

    // Run each URL; remember the last non-zero code (matches curl's
    // behaviour of returning the most recent error).
    let mut last_failure: u8 = 0;
    for url in &args.urls {
        let code = process_url(url, &args, jar.as_mut());
        if code != 0 {
            last_failure = code;
        }
    }

    // Final save (after every transfer) so cookies set on the last hop
    // make it to disk. Failure here is reported but does not override an
    // earlier non-zero exit code — curl behaves the same way.
    if let (Some(j), Some(path)) = (jar.as_ref(), args.cookie_jar.as_deref()) {
        if let Err(e) = j.save_netscape(path) {
            if !args.silent {
                eprintln!("rsurl: writing cookie jar {path}: {e}");
            }
            if last_failure == 0 {
                last_failure = 23;
            }
        }
    }
    ExitCode::from(last_failure)
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
    let parsed_url = match Url::parse(url) {
        Ok(u) => u,
        Err(e) => {
            if !args.silent {
                eprintln!("rsurl: {e}");
            }
            return 3;
        }
    };

    // Non-HTTP schemes go through the generic transfer dispatcher; HTTP-only
    // options (-X, -H, -d, ...) are ignored for them in this milestone.
    if !matches!(parsed_url.scheme.as_str(), "http" | "https") {
        return run_transfer(url, args);
    }

    // Assemble the body up front so we know whether to default the method
    // to POST. Errors from file I/O surface as exit code 2 ("usage").
    let body = match assemble_form_body(&args.data_parts) {
        Ok(b) => b,
        Err(e) => {
            if !args.silent {
                eprintln!("rsurl: {e}");
            }
            return 2;
        }
    };

    let method = args.method.clone().unwrap_or_else(|| {
        if args.head {
            "HEAD".to_string()
        } else if body.is_some() {
            "POST".to_string()
        } else {
            "GET".to_string()
        }
    });

    let mut req = match Request::new(&method, url) {
        Ok(r) => r,
        Err(e) => {
            if !args.silent {
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
    if let Some(body_bytes) = body {
        if !args
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        {
            req = req.header("Content-Type", "application/x-www-form-urlencoded");
        }
        req = req.body(body_bytes);
    }
    match args.http_version {
        Some(HttpVersionPref::Http2Only) => req = req.http2_only(),
        Some(HttpVersionPref::Http11Only) => req = req.http11_only(),
        Some(HttpVersionPref::Auto) | None => {}
    }

    if args.follow_redirects {
        req = req.follow_redirects(true);
    }
    if let Some(n) = args.max_redirs {
        req = req.max_redirs(n);
    }
    if let Some((u, p)) = &args.basic_auth {
        req = req.basic_auth(u, p);
    }
    if args.insecure {
        req = req.verify_tls(false);
    }
    if let Some(path) = &args.cacert {
        req = req.ca_bundle(path);
    }
    if let Some(secs) = args.max_time {
        req = req.max_time(Duration::from_secs(secs));
    }
    if let Some(secs) = args.connect_timeout {
        req = req.connect_timeout(Duration::from_secs(secs));
    }

    // Proxy: explicit `-x` wins over env vars; `-x ""` disables both.
    let proxy_spec = resolve_proxy_spec(&parsed_url, args);
    if let Some(spec) = proxy_spec {
        req = match req.proxy(&spec) {
            Ok(r) => r,
            Err(e) => {
                if !args.silent {
                    eprintln!("rsurl: --proxy: {e}");
                }
                return 5;
            }
        };
        if let Some((u, p)) = &args.proxy_user {
            req = match req.proxy_user(u, p) {
                Ok(r) => r,
                Err(e) => {
                    if !args.silent {
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

    let send_result = match (jar, args.verbose) {
        (Some(j), true) => {
            let mut err = io::stderr().lock();
            req.send_traced_with_jar(j, &mut err)
        }
        (Some(j), false) => req.send_with_jar(j),
        (None, true) => {
            let mut err = io::stderr().lock();
            req.send_traced(&mut err)
        }
        (None, false) => req.send(),
    };
    let resp = match send_result {
        Ok(r) => r,
        Err(e) => {
            if !args.silent {
                eprintln!("rsurl: {e}");
            }
            return 7;
        }
    };

    let exit_for_status: u8 = if (200..400).contains(&resp.status) {
        0
    } else {
        22
    };

    if let Err(e) = write_output(&resp, &parsed_url, args) {
        if !args.silent {
            eprintln!("rsurl: write error: {e}");
        }
        return 23;
    }

    exit_for_status
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
            "-v" | "--verbose" => a.verbose = true,
            "-s" | "--silent" => a.silent = true,
            "-X" | "--request" => a.method = Some(next_val(&mut it, arg)?),
            "-H" | "--header" => {
                let h = next_val(&mut it, arg)?;
                let (k, v) = h
                    .split_once(':')
                    .ok_or_else(|| format!("malformed header: {h:?}"))?;
                a.headers.push((k.trim().to_string(), v.trim().to_string()));
            }
            "-d" | "--data" => a.data_parts.push(DataPart::Plain {
                value: next_val(&mut it, arg)?,
                at_file_ok: true,
            }),
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
            "-A" | "--user-agent" => a.user_agent = Some(next_val(&mut it, arg)?),
            "-e" | "--referer" => a.referer = Some(next_val(&mut it, arg)?),
            "--http2" => a.http_version = Some(HttpVersionPref::Http2Only),
            // curl also accepts `--http1` as a shorthand for `--http1.1`.
            "--http1.1" | "--http1" => a.http_version = Some(HttpVersionPref::Http11Only),
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
            "--proxy-user" => {
                let v = next_val(&mut it, arg)?;
                let (u, p) = match v.split_once(':') {
                    Some((u, p)) => (u.to_string(), p.to_string()),
                    None => (v.clone(), String::new()),
                };
                a.proxy_user = Some((u, p));
            }
            "--noproxy" => a.noproxy = Some(next_val(&mut it, arg)?),
            s if s.starts_with("--") => return Err(format!("unknown option: {s}")),
            s if s.starts_with('-') && s.len() > 1 => return Err(format!("unknown option: {s}")),
            _ => {
                a.urls.push(arg.clone());
            }
        }
    }
    Ok(a)
}

fn next_val(it: &mut std::slice::Iter<'_, String>, flag: &str) -> Result<String, String> {
    it.next()
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn run_transfer(url: &str, args: &Args) -> u8 {
    match rsurl::transfer(url) {
        Ok(bytes) => {
            let mut out: Box<dyn Write> = match &args.output {
                Some(path) if path != "-" => match File::create(path) {
                    Ok(f) => Box::new(f),
                    Err(e) => {
                        if !args.silent {
                            eprintln!("rsurl: open {path}: {e}");
                        }
                        return 23;
                    }
                },
                _ => Box::new(io::stdout().lock()),
            };
            if let Err(e) = out.write_all(&bytes) {
                if !args.silent {
                    eprintln!("rsurl: write error: {e}");
                }
                return 23;
            }
            0
        }
        Err(e) => {
            if !args.silent {
                eprintln!("rsurl: {e}");
            }
            7
        }
    }
}

fn write_output(resp: &Response, url: &Url, args: &Args) -> io::Result<()> {
    let mut out: Box<dyn Write> = if args.remote_name {
        let name = remote_name_from_url(url).map_err(|e| io::Error::other(e.to_string()))?;
        Box::new(File::create(&name)?)
    } else {
        match &args.output {
            Some(path) if path != "-" => Box::new(File::create(path)?),
            _ => Box::new(io::stdout().lock()),
        }
    };
    if args.include_headers {
        write!(out, "{} {} {}\r\n", resp.version, resp.status, resp.reason)?;
        for (k, v) in &resp.headers {
            write!(out, "{k}: {v}\r\n")?;
        }
        out.write_all(b"\r\n")?;
    }
    out.write_all(&resp.body)?;
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
  -v, --verbose            print request/response headers to stderr
  -s, --silent             suppress error messages
  -X, --request <method>   override HTTP method
  -H, --header <line>      add a request header (repeatable)
  -d, --data <body>        POST body (urlencoded); @file reads from disk
                           and strips CR/LF. Repeatable; joined with '&'.
      --data-raw <body>    like -d but '@' is taken literally
      --data-binary <body> like -d but @file is read verbatim (no strip)
      --data-urlencode <s> percent-encode <s> before sending. Forms:
                             text  =text  name=text  @file  name@file
  -A, --user-agent <ua>    set User-Agent
  -e, --referer <ref>      set Referer
  -L, --location           follow 3xx redirects
      --max-redirs <n>     cap on redirect hops (default 50)
  -u, --user <user:pass>   HTTP Basic auth credentials
  -k, --insecure           don't verify the TLS certificate chain
      --cacert <file>      PEM bundle to use instead of system trust
      --max-time <secs>    cap on the whole operation's wall time
      --connect-timeout <secs>
                           cap on the TCP connect step
      --http2              require HTTP/2 (ALPN h2); error if unavailable
      --http1.1            force HTTP/1.1 (alias: --http1)
  -b, --cookie <data>      cookies to send: \"k=v[; k2=v2]\" or path to a
                           Netscape cookies.txt file
  -c, --cookie-jar <file>  write all known cookies to <file> on exit
  -x, --proxy <url>        route via HTTP proxy (e.g. http://host:8080).
                           Also reads HTTPS_PROXY / http_proxy / ALL_PROXY.
      --proxy-user <u:p>   credentials for the proxy (Basic)
      --noproxy <hosts>    comma-separated host suffixes that bypass the
                           proxy; \"*\" bypasses everything
  -h, --help               print this help
  -V, --version            print version
"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

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

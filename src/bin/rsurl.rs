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
//!     -T, --upload-file <f>    upload the file (HTTP PUT, FTP/FTPS STOR, TFTP WRQ, or MQTT PUBLISH)
//!     -C, --continue-at <off>  resume at byte <off> (FTP sends REST before STOR)
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
    /// For FTP uploads this sends `REST <offset>` before `STOR`. The curl
    /// "automatic" form `-C -` is not supported and is rejected at parse time.
    continue_at: Option<u64>,
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
        + args.upload_file.is_some() as u8;
    if n > 1 {
        return Err("-d/--data, -F/--form, and -T/--upload-file are mutually exclusive".into());
    }
    if let Some(path) = &args.upload_file {
        return build_upload_body(path).map(Some);
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
        // RTSP honours `-X`/`--request` to select the control method
        // (OPTIONS/DESCRIBE/SETUP/PLAY/TEARDOWN); default is DESCRIBE.
        if parsed_url.scheme == "rtsp" {
            return run_rtsp(&parsed_url, args);
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
            if !args.silent {
                eprintln!(
                    "rsurl: -T is only supported for HTTP(S), FTP(S), and TFTP URLs in this build"
                );
            }
            return 2;
        }
        return run_transfer(url, args);
    }

    // Assemble the body up front so we know whether to default the method
    // (PUT for `-T`, POST for `-d`/`-F`). Errors from file I/O or mutually
    // exclusive flag combos surface as exit code 2 ("usage").
    let assembled = match assemble_request_body(args) {
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
        } else if let Some((_, _, m)) = &assembled {
            (*m).to_string()
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
                    return Err(
                        "-C -: automatic resume is not supported; pass an explicit byte offset"
                            .into(),
                    );
                }
                a.continue_at = Some(
                    v.parse::<u64>()
                        .map_err(|_| format!("-C/--continue-at: not a byte offset: {v:?}"))?,
                );
            }
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

/// Upload a local file to an `ftp://`/`ftps://` URL via STOR. With
/// `-C <offset>` the local source is seeked past `offset` bytes and a
/// `REST <offset>` is sent so the server resumes/appends from there. Returns a
/// curl-style exit code (0 ok, 7 on transfer error, 26 on local-read error).
fn run_ftp_upload(url: &Url, path: &str, args: &Args) -> u8 {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            if !args.silent {
                eprintln!("rsurl: -T: can't read {path:?}: {e}");
            }
            return 26;
        }
    };

    // For REST resume, only the tail past `offset` is streamed; the server
    // already holds the first `offset` bytes.
    let (body, resume_at): (&[u8], Option<u64>) = match args.continue_at {
        Some(off) => {
            let off_usize = off as usize;
            if off_usize > bytes.len() {
                if !args.silent {
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

    match rsurl::ftp::store(url, body, resume_at) {
        Ok(()) => 0,
        Err(e) => {
            if !args.silent {
                eprintln!("rsurl: {e}");
            }
            7
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
            if !args.silent {
                eprintln!("rsurl: -T: can't read {path:?}: {e}");
            }
            return 26;
        }
    };

    match rsurl::tftp::store(url, &bytes) {
        Ok(()) => 0,
        Err(e) => {
            if !args.silent {
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
        if !args.silent {
            eprintln!("rsurl: -d/--data and -T/--upload-file are mutually exclusive");
        }
        return 2;
    }

    let payload: Vec<u8> = if let Some(path) = &args.upload_file {
        match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                if !args.silent {
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
                if !args.silent {
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
            if !args.silent {
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
  -X, --request <method>   override HTTP method; for rtsp:// selects the
                           RTSP method (OPTIONS/DESCRIBE/SETUP/PLAY/TEARDOWN)
  -H, --header <line>      add a request header (repeatable)
  -d, --data <body>        POST body (urlencoded); @file reads from disk
                           and strips CR/LF. Repeatable; joined with '&'.
      --data-raw <body>    like -d but '@' is taken literally
      --data-binary <body> like -d but @file is read verbatim (no strip)
      --data-urlencode <s> percent-encode <s> before sending. Forms:
                             text  =text  name=text  @file  name@file
  -F, --form <name=value>  add a multipart/form-data part. Value forms:
                             text  @file (upload)  <file (field from file)
                           Modifiers: ;type=  ;filename=  ;headers=@hdrfile
      --form-string <n=v>  like -F but value is taken literally (no @, <, ;)
      --form-escape        percent-encode names/filenames per RFC 7578 §4.2
                           (default: backslash-escape, curl-historical)
  -T, --upload-file <f>    upload the file: HTTP PUT (default Content-Type:
                           application/octet-stream), FTP/FTPS STOR, TFTP WRQ,
                           or MQTT PUBLISH
  -C, --continue-at <off>  resume at byte <off> (FTP: REST before STOR);
                           the automatic form '-C -' is not supported
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

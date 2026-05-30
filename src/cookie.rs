//! HTTP cookies: parsing `Set-Cookie`, building `Cookie:`, and Netscape
//! `cookies.txt` I/O for curl's `-b`/`-c` flags.
//!
//! Scope is what's useful to a CLI HTTP client, not a browser:
//!
//! * **Receive side.** [`CookieJar::add_set_cookie`] parses one `Set-Cookie`
//!   header line per RFC 6265 §5.2 and stores it against the request's
//!   origin. Attributes recognised: `Domain`, `Path`, `Expires`, `Max-Age`,
//!   `Secure`, `HttpOnly`. `SameSite` is parsed but otherwise ignored — it
//!   is a same-origin protection enforced by browsers, not by CLI clients.
//!
//! * **Send side.** [`CookieJar::cookie_header`] returns the value of the
//!   `Cookie:` request header for a given origin, sorted longest-path-first
//!   per RFC 6265 §5.4, filtering out expired and Secure-on-plain entries.
//!
//! * **Persistence.** [`CookieJar::load_netscape`] / [`save_netscape`] use
//!   the tab-separated `cookies.txt` format documented at
//!   <https://curl.se/docs/http-cookies.html> — same one curl itself reads
//!   and writes, including the `#HttpOnly_` line prefix for HttpOnly entries.
//!
//! Intentionally out of scope: IDN normalisation, the full Public Suffix
//! List, and SameSite enforcement. None of these matter for a CLI tool that
//! follows a single user-driven redirect chain. A *minimal* eTLD heuristic
//! is applied (see `is_scopable_cookie_domain`): a subdomain-scoped cookie
//! domain must carry at least one internal dot, so a bare TLD like
//! `Domain=com` can't broadcast to every host under it. This is a heuristic,
//! not a real PSL — `co.uk` and friends still pass.

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};

/// One parsed cookie. `expires` is a Unix epoch second; `None` means a
/// session cookie (lives only for this rsurl invocation, never persisted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    /// Effective host the cookie applies to. **Without** the leading `.`
    /// even when the `Domain=` attribute supplied one — the dot only
    /// signals subdomain-match scope, which we track separately in
    /// `host_only` rather than smuggling through the string.
    pub domain: String,
    pub path: String,
    pub expires: Option<u64>,
    pub secure: bool,
    pub http_only: bool,
    /// `true` when the cookie was set without an explicit `Domain=` —
    /// matches only the exact host. `false` means subdomain-match.
    pub host_only: bool,
}

/// Bag of cookies. Cheap to clone in tests; threaded by `&mut` through the
/// redirect chain in [`crate::Request::send_with_jar`].
#[derive(Debug, Clone, Default)]
pub struct CookieJar {
    cookies: Vec<Cookie>,
}

impl CookieJar {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of stored (non-expired) cookies; cheap, mostly for tests
    /// and the CLI's "wrote N cookies" trace.
    pub fn len(&self) -> usize {
        self.cookies.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty()
    }

    /// Append every Set-Cookie line from the response to the jar, using
    /// the request URL as the cookie's origin. Lines that don't parse, or
    /// that try to set a cookie for a domain the request URL doesn't
    /// belong to, are silently dropped — matching what curl does.
    pub fn ingest_response(&mut self, request_url: &crate::Url, headers: &[(String, String)]) {
        let now = unix_now();
        for (k, v) in headers {
            if k.eq_ignore_ascii_case("set-cookie") {
                self.add_set_cookie(request_url, v, now);
            }
        }
    }

    /// Parse a single `Set-Cookie` header value against `request_url` and
    /// merge it into the jar. `now` is injected so tests can pin a clock.
    pub fn add_set_cookie(&mut self, request_url: &crate::Url, line: &str, now: u64) {
        let Some(parsed) = parse_set_cookie(line, request_url, now) else {
            return;
        };

        // A zero or past expiry means delete (RFC 6265 §5.3 step 11).
        if let Some(exp) = parsed.expires {
            if exp <= now {
                self.remove_matching(&parsed);
                return;
            }
        }

        // Replace any existing cookie with same (name, domain, path) trio
        // (RFC 6265 §5.3 step 11.2).
        self.remove_matching(&parsed);
        self.cookies.push(parsed);
    }

    fn remove_matching(&mut self, c: &Cookie) {
        self.cookies.retain(|x| {
            !(x.name == c.name && x.domain.eq_ignore_ascii_case(&c.domain) && x.path == c.path)
        });
    }

    /// Drop every cookie whose stored Expires is at or before `now`.
    /// Called before send-side matching and before serialising.
    pub fn purge_expired(&mut self) {
        let now = unix_now();
        self.cookies.retain(|c| match c.expires {
            Some(exp) => exp > now,
            None => true,
        });
    }

    /// Build the value of the `Cookie:` request header for an outgoing
    /// request, or `None` if no stored cookie matches. Returned as a
    /// `name1=value1; name2=value2` string ready to splice into the
    /// request writer.
    pub fn cookie_header(&self, url: &crate::Url) -> Option<String> {
        let now = unix_now();
        let mut matches: Vec<&Cookie> = self
            .cookies
            .iter()
            .filter(|c| matches_request(c, url, now))
            // Defence in depth: never emit a name/value carrying CR/LF/NUL or
            // other control bytes into the outgoing `Cookie:` header, even if
            // a stored cookie slipped past ingest validation somehow.
            .filter(|c| !has_forbidden_cookie_char(&c.name) && !has_forbidden_cookie_char(&c.value))
            .collect();
        if matches.is_empty() {
            return None;
        }
        // RFC 6265 §5.4 step 2: longer-path cookies first, ties broken by
        // earlier creation order. We don't track creation order, so the
        // tiebreaker is jar insertion order — stable enough for this use.
        matches.sort_by_key(|c| std::cmp::Reverse(c.path.len()));
        let parts: Vec<String> = matches
            .iter()
            .map(|c| format!("{}={}", c.name, c.value))
            .collect();
        Some(parts.join("; "))
    }

    /// Read a Netscape `cookies.txt` file into a fresh jar. Missing file
    /// is an error, **not** an empty jar — curl prints "no cookies found"
    /// but still succeeds; we surface the I/O error so the caller can
    /// decide. Use `load_netscape_or_empty` to silently start fresh.
    pub fn load_netscape(path: &str) -> Result<Self> {
        let f = File::open(path).map_err(Error::Io)?;
        let mut jar = CookieJar::new();
        for (lineno, line) in BufReader::new(f).lines().enumerate() {
            let line = line.map_err(Error::Io)?;
            match parse_netscape_line(&line) {
                LineOutcome::Cookie(cookie) => jar.cookies.push(*cookie),
                // Comment, blank, or a security-rejected entry: skip quietly.
                LineOutcome::Skip => {}
                LineOutcome::Malformed => {
                    // Surface as a soft warning through Err so the caller can
                    // decide. We pick BadResponse because there's no dedicated
                    // cookie error variant.
                    return Err(Error::BadResponse(format!(
                        "cookies.txt: malformed line {} in {path}",
                        lineno + 1
                    )));
                }
            }
        }
        Ok(jar)
    }

    /// Same as [`Self::load_netscape`] but treats `NotFound` as "start with
    /// an empty jar" — what curl does when `-b` points at a not-yet-created
    /// path that is also the `-c` destination.
    pub fn load_netscape_or_empty(path: &str) -> Result<Self> {
        match Self::load_netscape(path) {
            Ok(j) => Ok(j),
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(CookieJar::new()),
            Err(e) => Err(e),
        }
    }

    /// Write the jar to `path` in Netscape `cookies.txt` format. Session
    /// cookies (no Expires / Max-Age) are skipped, matching what curl does
    /// — they live only for the invocation that received them.
    pub fn save_netscape(&self, path: &str) -> Result<()> {
        let mut f = File::create(path).map_err(Error::Io)?;
        writeln!(
            f,
            "# Netscape HTTP Cookie File\n\
             # https://curl.se/docs/http-cookies.html\n\
             # This file was generated by rsurl. Edit at your own risk.\n"
        )
        .map_err(Error::Io)?;
        for c in &self.cookies {
            let Some(exp) = c.expires else { continue }; // skip session cookies
                                                         // Defensive: never write a record whose fields still carry a
                                                         // field/line separator. A TAB/CR/LF here would forge or split a
                                                         // tab-separated record (field-boundary / newline injection).
            if has_jar_separator(&c.name)
                || has_jar_separator(&c.value)
                || has_jar_separator(&c.domain)
                || has_jar_separator(&c.path)
            {
                continue;
            }
            // The first field can carry an #HttpOnly_ prefix that signals
            // browsers (and curl) to not expose the cookie to JS. We don't
            // care about JS, but we round-trip the bit so a load-then-save
            // doesn't silently drop it.
            let prefix = if c.http_only { "#HttpOnly_" } else { "" };
            // domain_flag: TRUE if cookie matches subdomains (i.e., was
            // set with an explicit Domain= attribute), FALSE if host-only.
            let dflag = if c.host_only { "FALSE" } else { "TRUE" };
            let sflag = if c.secure { "TRUE" } else { "FALSE" };
            writeln!(
                f,
                "{prefix}{}\t{dflag}\t{}\t{sflag}\t{exp}\t{}\t{}",
                c.domain, c.path, c.name, c.value
            )
            .map_err(Error::Io)?;
        }
        Ok(())
    }

    /// Append a single explicit cookie (for `curl -b "name=value"` form).
    /// Always treated as a session cookie scoped to the request origin
    /// when the request is made — i.e., applies to whichever URL we're
    /// about to hit, with default path "/" and host-only domain.
    pub fn add_explicit(&mut self, name: &str, value: &str, request_url: &crate::Url) {
        // Strip any existing matching entry so the explicit form wins.
        let cookie = Cookie {
            name: name.to_string(),
            value: value.to_string(),
            domain: request_url.host.to_ascii_lowercase(),
            path: "/".into(),
            expires: None,
            secure: false,
            http_only: false,
            host_only: true,
        };
        self.remove_matching(&cookie);
        self.cookies.push(cookie);
    }
}

/// Whether a stored cookie should be attached to a request for `url`.
fn matches_request(c: &Cookie, url: &crate::Url, now: u64) -> bool {
    if let Some(exp) = c.expires {
        if exp <= now {
            return false;
        }
    }
    if c.secure && url.scheme != "https" {
        return false;
    }
    if !domain_match(&url.host, &c.domain, c.host_only) {
        return false;
    }
    if !path_match(&url.path, &c.path) {
        return false;
    }
    true
}

/// RFC 6265 §5.1.3. `request_host` matches `cookie_domain` if:
/// * `host_only` and they're identical (case-insensitive), or
/// * `!host_only` and `request_host == cookie_domain` or
///   `request_host` ends with `.cookie_domain`.
fn domain_match(request_host: &str, cookie_domain: &str, host_only: bool) -> bool {
    let rh = request_host.to_ascii_lowercase();
    let cd = cookie_domain.to_ascii_lowercase();
    if host_only {
        return rh == cd;
    }
    if rh == cd {
        return true;
    }
    rh.ends_with(&format!(".{cd}"))
}

/// RFC 6265 §5.1.4. Request path matches cookie path if the cookie path is
/// a prefix and either covers the whole path or stops at a `/`.
fn path_match(request_path: &str, cookie_path: &str) -> bool {
    if request_path == cookie_path {
        return true;
    }
    if let Some(rest) = request_path.strip_prefix(cookie_path) {
        if cookie_path.ends_with('/') {
            return true;
        }
        return rest.starts_with('/');
    }
    false
}

/// Parse one `Set-Cookie` header value against the request URL. Returns
/// `None` if the cookie is unusable (missing `=`, empty name, or scoped to
/// a domain the request URL doesn't belong to).
fn parse_set_cookie(line: &str, request_url: &crate::Url, now: u64) -> Option<Cookie> {
    // First segment is name=value; everything after `;` is an attribute.
    let mut parts = line.split(';');
    let nv = parts.next()?.trim();
    let (name, value) = nv.split_once('=')?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let value = value.trim();

    // RFC 6265 `cookie-octet` forbids control chars, TAB, CR, LF (and the
    // `cookie-name` token grammar likewise excludes them). Reject any such
    // cookie outright: an embedded TAB/CR/LF would let an attacker forge a
    // tab-separated cookies.txt record or inject extra `Cookie:` header
    // fields downstream (field-boundary / newline injection).
    if has_forbidden_cookie_char(name) || has_forbidden_cookie_char(value) {
        return None;
    }

    // Inferred defaults; attributes below may override.
    let request_host = request_url.host.to_ascii_lowercase();
    let mut domain = request_host.clone();
    let mut host_only = true;
    let mut path = default_path(&request_url.path);
    let mut expires: Option<u64> = None;
    let mut max_age: Option<i64> = None;
    let mut secure = false;
    let mut http_only = false;

    for attr in parts {
        let attr = attr.trim();
        if attr.is_empty() {
            continue;
        }
        let (k, v) = match attr.split_once('=') {
            Some((k, v)) => (k.trim(), Some(v.trim())),
            None => (attr, None),
        };
        if k.eq_ignore_ascii_case("domain") {
            if let Some(v) = v {
                // Strip optional leading dot; non-empty after that is required.
                let v = v.strip_prefix('.').unwrap_or(v).to_ascii_lowercase();
                if v.is_empty() {
                    continue;
                }
                // Minimal public-suffix guard (NOT a real PSL): reject a
                // Domain= that is a single bare label with no internal dot
                // (e.g. `com`, `localhost`). Such a value would scope the
                // cookie to every host under a TLD. The dot-count heuristic
                // is the agreed scope; a full eTLD list is out of scope.
                if !is_scopable_cookie_domain(&v) {
                    return None;
                }
                // RFC 6265 §5.3 step 5: reject cookie if request host
                // doesn't domain-match the supplied Domain.
                if !domain_match(&request_host, &v, false) {
                    return None;
                }
                domain = v;
                host_only = false;
            }
        } else if k.eq_ignore_ascii_case("path") {
            if let Some(v) = v {
                if v.starts_with('/') {
                    path = v.to_string();
                }
            }
        } else if k.eq_ignore_ascii_case("expires") {
            if let Some(v) = v {
                expires = parse_http_date(v);
            }
        } else if k.eq_ignore_ascii_case("max-age") {
            if let Some(v) = v {
                if let Ok(n) = v.parse::<i64>() {
                    max_age = Some(n);
                }
            }
        } else if k.eq_ignore_ascii_case("secure") {
            secure = true;
        } else if k.eq_ignore_ascii_case("httponly") {
            http_only = true;
        }
        // Anything else (SameSite, Priority, ...) is silently ignored.
    }

    // Max-Age takes precedence over Expires (RFC 6265 §5.3 step 3).
    if let Some(ma) = max_age {
        expires = if ma <= 0 {
            Some(0) // delete-on-ingest sentinel
        } else {
            Some(now.saturating_add(ma as u64))
        };
    }

    Some(Cookie {
        name: name.to_string(),
        value: value.to_string(),
        domain,
        path,
        expires,
        secure,
        http_only,
        host_only,
    })
}

/// RFC 6265 §5.1.4: "default-path" of a Set-Cookie that didn't supply Path=.
/// Effectively: strip query/fragment (callers already do this), take the
/// directory part of the URI's path. Yields `/` for `/` or `/foo`.
fn default_path(uri_path: &str) -> String {
    if uri_path.is_empty() || !uri_path.starts_with('/') {
        return "/".into();
    }
    // Last slash position (other than the first one).
    if let Some(idx) = uri_path.rfind('/') {
        if idx == 0 {
            return "/".into();
        }
        return uri_path[..idx].to_string();
    }
    "/".into()
}

/// Best-effort HTTP-date parser. Handles the three flavours RFC 9110 §5.6.7
/// blesses (IMF-fixdate, obs RFC 850, asctime). Returns a Unix epoch second,
/// or `None` if we can't make sense of it — in which case the cookie is
/// treated as session (since `expires` stays `None`).
fn parse_http_date(s: &str) -> Option<u64> {
    let s = s.trim();
    // IMF-fixdate, e.g. "Sun, 06 Nov 1994 08:49:37 GMT"
    if let Some(t) = try_imf_fixdate(s) {
        return Some(t);
    }
    // RFC 850, e.g. "Sunday, 06-Nov-94 08:49:37 GMT"
    if let Some(t) = try_rfc850(s) {
        return Some(t);
    }
    // asctime: "Sun Nov  6 08:49:37 1994"
    if let Some(t) = try_asctime(s) {
        return Some(t);
    }
    None
}

fn try_imf_fixdate(s: &str) -> Option<u64> {
    // "Sun, 06 Nov 1994 08:49:37 GMT" — 29 chars in the canonical form,
    // but we'll be lenient on the trailing zone (some servers send +0000).
    let rest = s.split_once(',')?.1.trim();
    let mut it = rest.split_whitespace();
    let day = it.next()?.parse::<u32>().ok()?;
    let mon = parse_month(it.next()?)?;
    let year = it.next()?.parse::<i32>().ok()?;
    let time = it.next()?;
    let (h, m, sec) = parse_hms(time)?;
    epoch_from_ymd_hms(year, mon, day, h, m, sec)
}

fn try_rfc850(s: &str) -> Option<u64> {
    let rest = s.split_once(',')?.1.trim();
    let mut it = rest.split_whitespace();
    let dmy = it.next()?; // "06-Nov-94"
    let time = it.next()?;
    let mut dmy_it = dmy.split('-');
    let day = dmy_it.next()?.parse::<u32>().ok()?;
    let mon = parse_month(dmy_it.next()?)?;
    let y2 = dmy_it.next()?.parse::<i32>().ok()?;
    // 2-digit year: per RFC 9110 §5.6.7, two-digit years are interpreted
    // in the 50-year window straddling the current year. Approximate that
    // with a 1970 pivot: 00..49 → 2000s, 50..99 → 1900s.
    let year = if y2 < 50 { 2000 + y2 } else { 1900 + y2 };
    let (h, m, sec) = parse_hms(time)?;
    epoch_from_ymd_hms(year, mon, day, h, m, sec)
}

fn try_asctime(s: &str) -> Option<u64> {
    // "Sun Nov  6 08:49:37 1994" — note the double space when day < 10.
    let mut it = s.split_whitespace();
    let _wd = it.next()?;
    let mon = parse_month(it.next()?)?;
    let day = it.next()?.parse::<u32>().ok()?;
    let time = it.next()?;
    let year = it.next()?.parse::<i32>().ok()?;
    let (h, m, sec) = parse_hms(time)?;
    epoch_from_ymd_hms(year, mon, day, h, m, sec)
}

fn parse_month(s: &str) -> Option<u32> {
    Some(match &s.to_ascii_lowercase()[..3] {
        "jan" => 1,
        "feb" => 2,
        "mar" => 3,
        "apr" => 4,
        "may" => 5,
        "jun" => 6,
        "jul" => 7,
        "aug" => 8,
        "sep" => 9,
        "oct" => 10,
        "nov" => 11,
        "dec" => 12,
        _ => return None,
    })
}

fn parse_hms(s: &str) -> Option<(u32, u32, u32)> {
    let mut it = s.split(':');
    let h = it.next()?.parse::<u32>().ok()?;
    let m = it.next()?.parse::<u32>().ok()?;
    let sec = it.next()?.parse::<u32>().ok()?;
    Some((h, m, sec))
}

/// Compute the Unix epoch second for a UTC Y/M/D h:m:s. Pure arithmetic
/// (Howard Hinnant's `days_from_civil`) so we don't pull a `chrono`-class
/// dep in just for cookie expiry. Returns `None` for out-of-range values.
fn epoch_from_ymd_hms(y: i32, m: u32, d: u32, hh: u32, mm: u32, ss: u32) -> Option<u64> {
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    let year = if m <= 2 { y - 1 } else { y };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = (year - era * 400) as u32; // [0, 399]
    let mp = if m > 2 { m - 3 } else { m + 9 }; // [0, 11]
    let doy = (153 * mp + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days_since_civil_epoch = (era as i64) * 146097 + (doe as i64) - 719468; // 719468 = days from 0000-03-01 to 1970-01-01
    if days_since_civil_epoch < 0 {
        return None;
    }
    let secs = (days_since_civil_epoch as u64) * 86400
        + (hh as u64) * 3600
        + (mm as u64) * 60
        + (ss as u64);
    Some(secs)
}

/// `true` if `s` contains any byte RFC 6265 forbids in a cookie name or
/// value: ASCII control characters (incl. TAB, CR, LF) and DEL. Used at
/// ingest (Set-Cookie / jar load) and again on emit (`Cookie:` header) so a
/// malformed entry can never split a header line or forge a jar record.
fn has_forbidden_cookie_char(s: &str) -> bool {
    s.bytes().any(|b| b.is_ascii_control() || b == 0x7f)
}

/// `true` if `s` contains a `cookies.txt` field or line separator — used by
/// `save_netscape` as a last-ditch guard against writing a record that
/// could forge field boundaries or split into extra lines.
fn has_jar_separator(s: &str) -> bool {
    s.bytes().any(|b| b == b'\t' || b == b'\r' || b == b'\n')
}

/// Minimal public-suffix heuristic — **not** a real PSL. A subdomain-scoped
/// cookie domain must contain at least one internal dot so it names a
/// registrable domain rather than a bare TLD (`com`) or unqualified label
/// (`localhost`). This rejects the obvious `Domain=co.uk`-style over-broad
/// scoping a single-label check can catch; it deliberately does not attempt
/// the full eTLD list (e.g. `co.uk` itself still passes).
fn is_scopable_cookie_domain(domain: &str) -> bool {
    let d = domain.trim_matches('.');
    !d.is_empty() && d.contains('.')
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Outcome of parsing one `cookies.txt` line, so the loader can tell a
/// genuinely malformed line (worth surfacing as an error) apart from one we
/// deliberately drop — a comment/blank line, or an entry rejected by the
/// security guards below (which must be skipped *silently*, not error out).
enum LineOutcome {
    /// A usable cookie.
    Cookie(Box<Cookie>),
    /// Comment, blank, or security-rejected — skip without complaint.
    Skip,
    /// Structurally malformed (wrong field count / unparseable expiry).
    Malformed,
}

/// Parse one line of a Netscape `cookies.txt` file into a [`LineOutcome`].
fn parse_netscape_line(line: &str) -> LineOutcome {
    let mut http_only = false;
    let body = if let Some(rest) = line.strip_prefix("#HttpOnly_") {
        http_only = true;
        rest
    } else if line.starts_with('#') || line.trim().is_empty() {
        return LineOutcome::Skip;
    } else {
        line
    };
    let fields: Vec<&str> = body.split('\t').collect();
    if fields.len() != 7 {
        return LineOutcome::Malformed;
    }
    let domain = fields[0].to_string();
    if domain.is_empty() {
        return LineOutcome::Malformed;
    }
    let host_only = !fields[1].eq_ignore_ascii_case("TRUE");
    let path = fields[2].to_string();
    let secure = fields[3].eq_ignore_ascii_case("TRUE");
    let Ok(expires_raw) = fields[4].parse::<i64>() else {
        return LineOutcome::Malformed;
    };
    let expires = if expires_raw <= 0 {
        // 0 means session in curl's writer; we treat that as None.
        None
    } else {
        Some(expires_raw as u64)
    };
    let name = fields[5].to_string();
    let value = fields[6].to_string();
    if name.is_empty() {
        return LineOutcome::Malformed;
    }
    // A hostile jar file is an untrusted input too: drop any entry whose
    // name/value carries a control/TAB/CR/LF byte (would re-inject into the
    // outgoing `Cookie:` header — see `cookie_header`). Drop silently rather
    // than erroring: the line is structurally fine, just unsafe to keep.
    if has_forbidden_cookie_char(&name) || has_forbidden_cookie_char(&value) {
        return LineOutcome::Skip;
    }
    let domain = domain.trim_start_matches('.').to_string();
    // Minimal public-suffix guard (NOT a real PSL): a subdomain-scoped
    // (`!host_only`) entry whose domain is a single bare label with no
    // internal dot (e.g. `.com`) would broadcast to every host under a TLD.
    // Drop it silently. Host-only entries keep working — they match one host.
    if !host_only && !is_scopable_cookie_domain(&domain) {
        return LineOutcome::Skip;
    }
    LineOutcome::Cookie(Box::new(Cookie {
        name,
        value,
        domain,
        path,
        expires,
        secure,
        http_only,
        host_only,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Url;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn parses_simple_set_cookie() {
        let mut j = CookieJar::new();
        j.add_set_cookie(&url("https://example.com/"), "sid=abc; Path=/; Secure", 0);
        assert_eq!(j.cookies.len(), 1);
        let c = &j.cookies[0];
        assert_eq!(c.name, "sid");
        assert_eq!(c.value, "abc");
        assert_eq!(c.domain, "example.com");
        assert!(c.host_only);
        assert!(c.secure);
        assert_eq!(c.path, "/");
    }

    #[test]
    fn domain_attribute_enables_subdomain_match() {
        let mut j = CookieJar::new();
        j.add_set_cookie(
            &url("https://www.example.com/"),
            "id=1; Domain=example.com; Path=/",
            0,
        );
        // Same host
        assert_eq!(
            j.cookie_header(&url("https://www.example.com/")).as_deref(),
            Some("id=1")
        );
        // Sibling subdomain
        assert_eq!(
            j.cookie_header(&url("https://api.example.com/")).as_deref(),
            Some("id=1")
        );
        // Unrelated host
        assert!(j.cookie_header(&url("https://other.com/")).is_none());
    }

    #[test]
    fn rejects_cookie_for_unrelated_domain() {
        let mut j = CookieJar::new();
        j.add_set_cookie(&url("https://example.com/"), "evil=1; Domain=other.com", 0);
        assert!(j.is_empty());
    }

    #[test]
    fn secure_only_on_https() {
        let mut j = CookieJar::new();
        j.add_set_cookie(&url("https://example.com/"), "s=1; Secure", 0);
        assert!(j.cookie_header(&url("https://example.com/")).is_some());
        assert!(j.cookie_header(&url("http://example.com/")).is_none());
    }

    #[test]
    fn max_age_overrides_expires() {
        let mut j = CookieJar::new();
        j.add_set_cookie(
            &url("https://example.com/"),
            "a=1; Expires=Thu, 01 Jan 1970 00:00:01 GMT; Max-Age=3600",
            1_000_000,
        );
        let c = &j.cookies[0];
        assert_eq!(c.expires, Some(1_003_600));
    }

    #[test]
    fn negative_max_age_deletes() {
        let mut j = CookieJar::new();
        j.add_set_cookie(&url("https://example.com/"), "a=1", 100);
        j.add_set_cookie(&url("https://example.com/"), "a=1; Max-Age=-1", 100);
        assert!(j.is_empty());
    }

    #[test]
    fn cookie_header_sorts_longer_path_first() {
        let mut j = CookieJar::new();
        j.add_set_cookie(&url("https://example.com/foo/bar"), "deep=1", 0);
        j.add_set_cookie(&url("https://example.com/"), "root=1", 0);
        let h = j
            .cookie_header(&url("https://example.com/foo/bar"))
            .unwrap();
        // deep (path=/foo) should precede root (path=/).
        assert!(h.starts_with("deep=1"), "got {h:?}");
        assert!(h.ends_with("root=1"), "got {h:?}");
    }

    #[test]
    fn path_match_respects_segment_boundary() {
        let mut j = CookieJar::new();
        // Explicit Path=/foo — implicit default for the request URL /foo is /,
        // which would defeat the segment-boundary check we want to exercise.
        j.add_set_cookie(&url("https://example.com/foo"), "f=1; Path=/foo", 0);
        // /foobar does not start with /foo + /, so cookie must not be sent.
        assert!(j
            .cookie_header(&url("https://example.com/foobar"))
            .is_none());
        assert!(j.cookie_header(&url("https://example.com/foo/x")).is_some());
    }

    #[test]
    fn netscape_round_trip() {
        let mut j = CookieJar::new();
        j.cookies.push(Cookie {
            name: "sid".into(),
            value: "abc".into(),
            domain: "example.com".into(),
            path: "/".into(),
            expires: Some(2_000_000_000),
            secure: true,
            http_only: true,
            host_only: false,
        });
        let tmp = std::env::temp_dir().join("rsurl_cookie_test.txt");
        let path = tmp.to_str().unwrap();
        j.save_netscape(path).unwrap();
        let back = CookieJar::load_netscape(path).unwrap();
        let _ = std::fs::remove_file(path);
        assert_eq!(back.cookies.len(), 1);
        let c = &back.cookies[0];
        assert_eq!(c.name, "sid");
        assert_eq!(c.value, "abc");
        assert!(c.secure);
        assert!(c.http_only);
        assert!(!c.host_only);
        assert_eq!(c.expires, Some(2_000_000_000));
    }

    #[test]
    fn netscape_load_missing_treated_as_empty_with_helper() {
        let j = CookieJar::load_netscape_or_empty("/nonexistent/path/cookies.txt").unwrap();
        assert!(j.is_empty());
    }

    #[test]
    fn ingest_response_picks_up_multiple_set_cookies() {
        let mut j = CookieJar::new();
        let u = url("https://example.com/");
        let h = vec![
            ("Set-Cookie".into(), "a=1".into()),
            ("X-Other".into(), "skip".into()),
            ("Set-Cookie".into(), "b=2".into()),
        ];
        j.ingest_response(&u, &h);
        assert_eq!(j.len(), 2);
    }

    #[test]
    fn default_path_strips_filename() {
        assert_eq!(default_path("/"), "/");
        assert_eq!(default_path("/foo"), "/");
        assert_eq!(default_path("/foo/bar"), "/foo");
        assert_eq!(default_path("/foo/bar/"), "/foo/bar");
    }

    #[test]
    fn parses_imf_fixdate() {
        let t = parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
        assert_eq!(t, 784_111_777);
    }

    #[test]
    fn parses_rfc850() {
        let t = parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT").unwrap();
        assert_eq!(t, 784_111_777);
    }

    #[test]
    fn parses_asctime() {
        let t = parse_http_date("Sun Nov  6 08:49:37 1994").unwrap();
        assert_eq!(t, 784_111_777);
    }

    #[test]
    fn rejects_set_cookie_with_tab_in_value() {
        // A TAB embedded in the value would forge a tab-separated jar field.
        let mut j = CookieJar::new();
        j.add_set_cookie(&url("https://example.com/"), "sid=ab\tcd", 0);
        assert!(j.is_empty(), "cookie with TAB in value must be dropped");
    }

    #[test]
    fn rejects_set_cookie_with_newline_in_name() {
        let mut j = CookieJar::new();
        j.add_set_cookie(&url("https://example.com/"), "a\r\nb=1", 0);
        assert!(j.is_empty(), "cookie with CRLF in name must be dropped");
    }

    #[test]
    fn rejects_set_cookie_with_control_char_in_value() {
        let mut j = CookieJar::new();
        j.add_set_cookie(&url("https://example.com/"), "k=va\x00lue", 0);
        assert!(j.is_empty(), "cookie with NUL in value must be dropped");
    }

    #[test]
    fn rejects_bare_tld_domain_attribute() {
        // Domain=com would scope to every host under the TLD.
        let mut j = CookieJar::new();
        j.add_set_cookie(&url("https://example.com/"), "evil=1; Domain=com", 0);
        assert!(j.is_empty(), "bare-TLD Domain= must be rejected");
    }

    #[test]
    fn accepts_registrable_domain_attribute() {
        // Domain=example.com (one internal dot) is fine.
        let mut j = CookieJar::new();
        j.add_set_cookie(
            &url("https://www.example.com/"),
            "id=1; Domain=example.com",
            0,
        );
        assert_eq!(j.len(), 1);
    }

    #[test]
    fn save_netscape_skips_record_with_embedded_separator() {
        // Construct a cookie that bypassed ingest (e.g. via add_explicit /
        // direct push) and ensure the writer refuses to emit a forged record.
        let mut j = CookieJar::new();
        j.cookies.push(Cookie {
            name: "sid".into(),
            value: "abc\tevil.com\tFALSE\t/\tTRUE\t9999999999\tforged".into(),
            domain: "example.com".into(),
            path: "/".into(),
            expires: Some(2_000_000_000),
            secure: false,
            http_only: false,
            host_only: true,
        });
        let tmp = std::env::temp_dir().join("rsurl_cookie_sep_test.txt");
        let path = tmp.to_str().unwrap();
        j.save_netscape(path).unwrap();
        let body = std::fs::read_to_string(path).unwrap();
        let _ = std::fs::remove_file(path);
        assert!(
            !body.contains("forged"),
            "record with embedded TAB must be skipped, got: {body}"
        );
    }

    #[test]
    fn load_netscape_drops_entry_with_control_char() {
        // A hostile jar file line whose value carries a CR must be dropped on
        // load so it can't be re-injected into an outgoing Cookie: header.
        let tmp = std::env::temp_dir().join("rsurl_cookie_hostile_load.txt");
        let path = tmp.to_str().unwrap();
        // value field carries a bare CR.
        std::fs::write(
            &tmp,
            "example.com\tTRUE\t/\tFALSE\t2000000000\tsid\tab\rcd\n",
        )
        .unwrap();
        let j = CookieJar::load_netscape(path).unwrap();
        let _ = std::fs::remove_file(path);
        assert!(j.is_empty(), "entry with CR in value must be dropped");
    }

    #[test]
    fn load_netscape_drops_bare_tld_domain() {
        // A subdomain-scoped (domain_flag=TRUE) line for `.com` would
        // broadcast to every host under the TLD — drop it.
        let tmp = std::env::temp_dir().join("rsurl_cookie_bare_tld_load.txt");
        let path = tmp.to_str().unwrap();
        std::fs::write(&tmp, ".com\tTRUE\t/\tFALSE\t2000000000\tsid\tabc\n").unwrap();
        let j = CookieJar::load_netscape(path).unwrap();
        let _ = std::fs::remove_file(path);
        assert!(j.is_empty(), "bare-TLD jar entry must be dropped");
    }

    #[test]
    fn load_netscape_keeps_host_only_single_label() {
        // Host-only (domain_flag=FALSE) single-label hosts like `localhost`
        // must still load — the eTLD guard only applies to subdomain scope.
        let tmp = std::env::temp_dir().join("rsurl_cookie_localhost_load.txt");
        let path = tmp.to_str().unwrap();
        std::fs::write(&tmp, "localhost\tFALSE\t/\tFALSE\t2000000000\tsid\tabc\n").unwrap();
        let j = CookieJar::load_netscape(path).unwrap();
        let _ = std::fs::remove_file(path);
        assert_eq!(j.len(), 1, "host-only localhost cookie must load");
    }

    #[test]
    fn add_explicit_creates_session_cookie() {
        let mut j = CookieJar::new();
        j.add_explicit("session", "xyz", &url("https://example.com/"));
        let h = j.cookie_header(&url("https://example.com/")).unwrap();
        assert_eq!(h, "session=xyz");
        // session cookies are not persisted
        let tmp = std::env::temp_dir().join("rsurl_explicit_cookie_test.txt");
        let path = tmp.to_str().unwrap();
        j.save_netscape(path).unwrap();
        let body = std::fs::read_to_string(path).unwrap();
        let _ = std::fs::remove_file(path);
        assert!(
            !body.contains("session"),
            "session cookies must not be saved, got: {body}"
        );
    }
}

//! The libcurl "easy" interface on top of `rsurl::Request`.
//!
//! `curl_easy_setopt` accumulates options into an [`EasyHandle`]; `perform`
//! builds an `rsurl::Request` ([`build_request`]) and delivers the response to
//! the caller's write/header callbacks ([`deliver`]). The build/deliver split
//! is shared with the multi interface, which runs the request on a worker
//! thread but fires callbacks on the caller's thread.

use std::ffi::{c_void, CStr, CString};
use std::os::raw::{c_char, c_int, c_long};
use std::ptr;
use std::time::Duration;

use rsurl::{Error, HttpVersionPref, Request, Response};

use crate::consts::*;
use crate::{curl_slist, ffi_guard, CURL};

/// libcurl write/header callback: `(ptr, size, nmemb, userdata) -> consumed`.
pub type WriteCb = unsafe extern "C" fn(*mut c_char, usize, usize, *mut c_void) -> usize;

/// Largest chunk handed to the write callback in one call (libcurl's
/// `CURL_MAX_WRITE_SIZE`).
const MAX_WRITE_SIZE: usize = 16 * 1024;

/// TLS options for the session to an `https://` proxy (`CURLOPT_PROXY_*`),
/// independent of the origin's.
#[derive(Clone)]
struct ProxyTls {
    verify_peer: bool,
    cainfo: Option<String>,
    capath: Option<String>,
    sslcert: Option<String>,
    sslkey: Option<String>,
    keypasswd: Option<String>,
    pinnedpubkey: Option<String>,
    crlfile: Option<String>,
    cipher_list: Option<String>,
    tls13_ciphers: Option<String>,
}

impl Default for ProxyTls {
    fn default() -> Self {
        ProxyTls {
            verify_peer: true,
            cainfo: None,
            capath: None,
            sslcert: None,
            sslkey: None,
            keypasswd: None,
            pinnedpubkey: None,
            crlfile: None,
            cipher_list: None,
            tls13_ciphers: None,
        }
    }
}

pub struct EasyHandle {
    // request shape
    pub url: Option<String>,
    custom_request: Option<String>,
    nobody: bool,
    upload: bool,
    post: bool,
    follow: bool,
    failonerror: bool,
    verbose: bool,
    verify_peer: bool,
    max_redirs: Option<u32>,
    http_version: c_long,
    timeout_ms: Option<u64>,
    connect_timeout_ms: Option<u64>,
    header_in_body: bool,
    httpauth: c_long,
    // strings
    proxy: Option<String>,
    useragent: Option<String>,
    referer: Option<String>,
    cookie: Option<String>,
    userpwd: Option<String>,
    username: Option<String>,
    password: Option<String>,
    bearer: Option<String>,
    accept_encoding: Option<String>,
    range: Option<String>,
    cainfo: Option<String>,
    capath: Option<String>,
    sslcert: Option<String>,
    sslkey: Option<String>,
    keypasswd: Option<String>,
    pinnedpubkey: Option<String>,
    crlfile: Option<String>,
    cipher_list: Option<String>,
    tls13_ciphers: Option<String>,
    /// `CURLOPT_NOPROXY`: comma-separated hosts that bypass the proxy.
    noproxy: Option<String>,
    /// `CURLOPT_PROXY_*` TLS options for an `https://` proxy.
    proxy_tls: ProxyTls,
    #[allow(dead_code)]
    unix_socket: Option<String>,
    // post body: either a borrowed pointer+len (POSTFIELDS) or an owned copy.
    post_ptr: *const u8,
    post_len: Option<usize>,
    post_copy: Option<Vec<u8>>,
    // slists owned by the caller, read at perform.
    http_header: *const curl_slist,
    resolve: *const curl_slist,
    connect_to: *const curl_slist,
    // callbacks
    write_fn: Option<WriteCb>,
    write_data: *mut c_void,
    header_fn: Option<WriteCb>,
    header_data: *mut c_void,
    error_buffer: *mut c_char,
    /// `CURLOPT_PRIVATE`: opaque caller pointer, returned by `CURLINFO_PRIVATE`.
    private: *mut c_void,
    // results + getinfo-string storage (kept alive until next perform/cleanup)
    last: Option<Response>,
    info_effective_url: Option<CString>,
    info_content_type: Option<CString>,
}

impl EasyHandle {
    fn new() -> Self {
        EasyHandle {
            url: None,
            custom_request: None,
            nobody: false,
            upload: false,
            post: false,
            follow: false,
            failonerror: false,
            verbose: false,
            verify_peer: true,
            max_redirs: None,
            http_version: CURL_HTTP_VERSION_NONE,
            timeout_ms: None,
            connect_timeout_ms: None,
            header_in_body: false,
            httpauth: 0,
            proxy: None,
            useragent: None,
            referer: None,
            cookie: None,
            userpwd: None,
            username: None,
            password: None,
            bearer: None,
            accept_encoding: None,
            range: None,
            cainfo: None,
            capath: None,
            sslcert: None,
            sslkey: None,
            keypasswd: None,
            pinnedpubkey: None,
            crlfile: None,
            cipher_list: None,
            tls13_ciphers: None,
            noproxy: None,
            proxy_tls: ProxyTls::default(),
            unix_socket: None,
            post_ptr: ptr::null(),
            post_len: None,
            post_copy: None,
            http_header: ptr::null(),
            resolve: ptr::null(),
            connect_to: ptr::null(),
            write_fn: None,
            write_data: ptr::null_mut(),
            header_fn: None,
            header_data: ptr::null_mut(),
            error_buffer: ptr::null_mut(),
            private: ptr::null_mut(),
            last: None,
            info_effective_url: None,
            info_content_type: None,
        }
    }
}

fn as_handle<'a>(h: *mut CURL) -> Option<&'a mut EasyHandle> {
    if h.is_null() {
        None
    } else {
        // SAFETY: produced by Box::into_raw in curl_easy_init; one-thread-per-handle.
        Some(unsafe { &mut *(h as *mut EasyHandle) })
    }
}

#[no_mangle]
pub extern "C" fn curl_easy_init() -> *mut CURL {
    ffi_guard(ptr::null_mut(), || {
        Box::into_raw(Box::new(EasyHandle::new())) as *mut CURL
    })
}

#[no_mangle]
pub unsafe extern "C" fn curl_easy_cleanup(handle: *mut CURL) {
    ffi_guard((), || {
        if !handle.is_null() {
            drop(Box::from_raw(handle as *mut EasyHandle));
        }
    });
}

#[no_mangle]
pub extern "C" fn curl_easy_reset(handle: *mut CURL) {
    ffi_guard((), || {
        if let Some(h) = as_handle(handle) {
            *h = EasyHandle::new();
        }
    });
}

#[no_mangle]
pub extern "C" fn curl_easy_duphandle(handle: *mut CURL) -> *mut CURL {
    ffi_guard(ptr::null_mut(), || {
        let Some(src) = as_handle(handle) else {
            return ptr::null_mut();
        };
        // Clone the option set; results/storage start fresh. Raw pointers
        // (callbacks, userdata, slists) are copied as-is, matching libcurl
        // (the dup shares the caller's slists/buffers).
        let dup = EasyHandle {
            url: src.url.clone(),
            custom_request: src.custom_request.clone(),
            proxy: src.proxy.clone(),
            useragent: src.useragent.clone(),
            referer: src.referer.clone(),
            cookie: src.cookie.clone(),
            userpwd: src.userpwd.clone(),
            username: src.username.clone(),
            password: src.password.clone(),
            bearer: src.bearer.clone(),
            accept_encoding: src.accept_encoding.clone(),
            range: src.range.clone(),
            cainfo: src.cainfo.clone(),
            capath: src.capath.clone(),
            sslcert: src.sslcert.clone(),
            sslkey: src.sslkey.clone(),
            keypasswd: src.keypasswd.clone(),
            pinnedpubkey: src.pinnedpubkey.clone(),
            crlfile: src.crlfile.clone(),
            cipher_list: src.cipher_list.clone(),
            tls13_ciphers: src.tls13_ciphers.clone(),
            noproxy: src.noproxy.clone(),
            proxy_tls: src.proxy_tls.clone(),
            unix_socket: src.unix_socket.clone(),
            post_copy: src.post_copy.clone(),
            last: None,
            info_effective_url: None,
            info_content_type: None,
            ..EasyHandle {
                // copy the Copy/pointer/flag fields verbatim
                nobody: src.nobody,
                upload: src.upload,
                post: src.post,
                follow: src.follow,
                failonerror: src.failonerror,
                verbose: src.verbose,
                verify_peer: src.verify_peer,
                max_redirs: src.max_redirs,
                http_version: src.http_version,
                timeout_ms: src.timeout_ms,
                connect_timeout_ms: src.connect_timeout_ms,
                header_in_body: src.header_in_body,
                httpauth: src.httpauth,
                post_ptr: src.post_ptr,
                post_len: src.post_len,
                http_header: src.http_header,
                resolve: src.resolve,
                connect_to: src.connect_to,
                write_fn: src.write_fn,
                write_data: src.write_data,
                header_fn: src.header_fn,
                header_data: src.header_data,
                error_buffer: src.error_buffer,
                private: src.private,
                ..EasyHandle::new()
            }
        };
        Box::into_raw(Box::new(dup)) as *mut CURL
    })
}

// ---------------------------------------------------------------------------
// setopt
// ---------------------------------------------------------------------------

unsafe fn opt_string(value: usize) -> Option<String> {
    let p = value as *const c_char;
    if p.is_null() {
        None
    } else {
        Some(CStr::from_ptr(p).to_string_lossy().into_owned())
    }
}

/// `CURLcode curl_easy_setopt(CURL*, CURLoption, ...)`.
///
/// Implemented non-variadic: the single third argument is taken as `usize` and
/// reinterpreted by the option's type class (`option / 10000`). On most targets
/// this is ABI-compatible with a variadic call for the pointer-width option
/// classes — `long`, pointer, and function-pointer options — because those
/// occupy the argument slot a fixed prototype reads; on Apple AArch64, where
/// variadic arguments live on the stack, the exported symbol is an assembly
/// trampoline instead (see `varargs.rs`). All `curl_easy_getinfo` arms are
/// likewise width-independent (the caller supplies the typed out-pointer).
///
/// The one exception is 64-bit `curl_off_t` (`*_LARGE`) options: on a 64-bit
/// target the value fits the single `value` slot, but on a 32-bit (ILP32)
/// target a variadic 64-bit argument spans two arg slots that this faked
/// signature cannot read, so those options are rejected there rather than
/// stored truncated (see `CURLOPT_POSTFIELDSIZE_LARGE` below). See the crate
/// README.
#[cfg_attr(not(all(target_arch = "aarch64", target_vendor = "apple")), no_mangle)]
pub unsafe extern "C" fn curl_easy_setopt(
    handle: *mut CURL,
    option: c_int,
    value: usize,
) -> CURLcode {
    ffi_guard(CURLE_BAD_FUNCTION_ARGUMENT, || {
        let Some(h) = as_handle(handle) else {
            return CURLE_BAD_FUNCTION_ARGUMENT;
        };
        let lv = value as c_long; // for LONG / enum options
        match option {
            // --- strings / pointers ---
            CURLOPT_URL => h.url = opt_string(value),
            CURLOPT_CUSTOMREQUEST => h.custom_request = opt_string(value),
            CURLOPT_PROXY => h.proxy = opt_string(value),
            CURLOPT_USERAGENT => h.useragent = opt_string(value),
            CURLOPT_REFERER => h.referer = opt_string(value),
            CURLOPT_COOKIE => h.cookie = opt_string(value),
            CURLOPT_USERPWD => h.userpwd = opt_string(value),
            CURLOPT_USERNAME => h.username = opt_string(value),
            CURLOPT_PASSWORD => h.password = opt_string(value),
            CURLOPT_XOAUTH2_BEARER => h.bearer = opt_string(value),
            // NULL disables decoding (libcurl's default); "" means "every
            // encoding this build supports".
            CURLOPT_ACCEPT_ENCODING => h.accept_encoding = opt_string(value),
            CURLOPT_RANGE => h.range = opt_string(value).filter(|r| !r.is_empty()),
            CURLOPT_CAINFO => h.cainfo = opt_string(value),
            CURLOPT_CAPATH => h.capath = opt_string(value),
            CURLOPT_SSLCERT => h.sslcert = opt_string(value),
            CURLOPT_SSLKEY => h.sslkey = opt_string(value),
            CURLOPT_KEYPASSWD => h.keypasswd = opt_string(value),
            CURLOPT_PINNEDPUBLICKEY => h.pinnedpubkey = opt_string(value),
            CURLOPT_CRLFILE => h.crlfile = opt_string(value),
            CURLOPT_SSL_CIPHER_LIST => h.cipher_list = opt_string(value),
            CURLOPT_TLS13_CIPHERS => h.tls13_ciphers = opt_string(value),
            CURLOPT_NOPROXY => h.noproxy = opt_string(value),
            CURLOPT_PROXY_CAINFO => h.proxy_tls.cainfo = opt_string(value),
            CURLOPT_PROXY_CAPATH => h.proxy_tls.capath = opt_string(value),
            CURLOPT_PROXY_SSLCERT => h.proxy_tls.sslcert = opt_string(value),
            CURLOPT_PROXY_SSLKEY => h.proxy_tls.sslkey = opt_string(value),
            CURLOPT_PROXY_KEYPASSWD => h.proxy_tls.keypasswd = opt_string(value),
            CURLOPT_PROXY_PINNEDPUBLICKEY => h.proxy_tls.pinnedpubkey = opt_string(value),
            CURLOPT_PROXY_CRLFILE => h.proxy_tls.crlfile = opt_string(value),
            CURLOPT_PROXY_SSL_CIPHER_LIST => h.proxy_tls.cipher_list = opt_string(value),
            CURLOPT_PROXY_TLS13_CIPHERS => h.proxy_tls.tls13_ciphers = opt_string(value),
            CURLOPT_UNIX_SOCKET_PATH => h.unix_socket = opt_string(value),
            CURLOPT_POSTFIELDS => {
                // Borrowed by default (caller keeps it alive until perform).
                h.post_ptr = value as *const u8;
                h.post_copy = None;
                h.post = true;
            }
            CURLOPT_COPYPOSTFIELDS => {
                let p = value as *const u8;
                let len = h.post_len.unwrap_or_else(|| {
                    if p.is_null() {
                        0
                    } else {
                        CStr::from_ptr(p as *const c_char).to_bytes().len()
                    }
                });
                h.post_copy = if p.is_null() {
                    Some(Vec::new())
                } else {
                    Some(std::slice::from_raw_parts(p, len).to_vec())
                };
                h.post_ptr = ptr::null();
                h.post = true;
            }
            CURLOPT_HTTPHEADER => h.http_header = value as *const curl_slist,
            CURLOPT_RESOLVE => h.resolve = value as *const curl_slist,
            CURLOPT_CONNECT_TO => h.connect_to = value as *const curl_slist,
            CURLOPT_WRITEDATA => h.write_data = value as *mut c_void,
            CURLOPT_HEADERDATA => h.header_data = value as *mut c_void,
            CURLOPT_ERRORBUFFER => h.error_buffer = value as *mut c_char,
            CURLOPT_PRIVATE => h.private = value as *mut c_void,
            // --- functions ---
            CURLOPT_WRITEFUNCTION => {
                h.write_fn = if value == 0 {
                    None
                } else {
                    Some(std::mem::transmute::<usize, WriteCb>(value))
                }
            }
            CURLOPT_HEADERFUNCTION => {
                h.header_fn = if value == 0 {
                    None
                } else {
                    Some(std::mem::transmute::<usize, WriteCb>(value))
                }
            }
            // --- longs / enums ---
            CURLOPT_FOLLOWLOCATION => h.follow = lv != 0,
            CURLOPT_MAXREDIRS => h.max_redirs = if lv < 0 { None } else { Some(lv as u32) },
            CURLOPT_VERBOSE => h.verbose = lv != 0,
            CURLOPT_HEADER => h.header_in_body = lv != 0,
            CURLOPT_NOBODY => h.nobody = lv != 0,
            CURLOPT_FAILONERROR => h.failonerror = lv != 0,
            CURLOPT_POST => h.post = lv != 0,
            CURLOPT_UPLOAD | CURLOPT_PUT => h.upload = lv != 0,
            CURLOPT_HTTPGET => {
                if lv != 0 {
                    // Back to a plain GET: drop any POST body set earlier, not
                    // just the flag (build_request infers POST from a body).
                    h.post = false;
                    h.upload = false;
                    h.nobody = false;
                    h.post_ptr = ptr::null();
                    h.post_copy = None;
                }
            }
            CURLOPT_SSL_VERIFYPEER => h.verify_peer = lv != 0,
            CURLOPT_PROXY_SSL_VERIFYPEER => h.proxy_tls.verify_peer = lv != 0,
            CURLOPT_HTTP_VERSION => h.http_version = lv,
            CURLOPT_HTTPAUTH => h.httpauth = lv,
            // libcurl: 0 means "no timeout" (the default); negative is an error.
            CURLOPT_TIMEOUT
            | CURLOPT_TIMEOUT_MS
            | CURLOPT_CONNECTTIMEOUT
            | CURLOPT_CONNECTTIMEOUT_MS => {
                if lv < 0 {
                    return CURLE_BAD_FUNCTION_ARGUMENT;
                }
                let ms = match option {
                    CURLOPT_TIMEOUT | CURLOPT_CONNECTTIMEOUT => (lv as u64).saturating_mul(1000),
                    _ => lv as u64,
                };
                let v = (ms > 0).then_some(ms);
                if matches!(option, CURLOPT_TIMEOUT | CURLOPT_TIMEOUT_MS) {
                    h.timeout_ms = v;
                } else {
                    h.connect_timeout_ms = v;
                }
            }
            CURLOPT_POSTFIELDSIZE => h.post_len = if lv < 0 { None } else { Some(lv as usize) },
            CURLOPT_POSTFIELDSIZE_LARGE => {
                // `curl_off_t` is 64-bit. On a 64-bit target it arrives in the
                // single pointer-width `value` slot and is reinterpreted
                // directly. On a 32-bit (ILP32) target the variadic 64-bit
                // argument spans two arg slots that this non-variadic signature
                // cannot read, so reject it rather than store a truncated size;
                // callers should use the `long`-typed CURLOPT_POSTFIELDSIZE
                // instead (sufficient for bodies below 2 GiB).
                #[cfg(target_pointer_width = "64")]
                {
                    let off = value as i64;
                    h.post_len = if off < 0 { None } else { Some(off as usize) };
                }
                #[cfg(not(target_pointer_width = "64"))]
                {
                    return CURLE_NOT_BUILT_IN;
                }
            }
            // --- recognized but behaviorally irrelevant here: accept silently ---
            CURLOPT_SSL_VERIFYHOST
            | CURLOPT_PROXY_SSL_VERIFYHOST
            | CURLOPT_NOSIGNAL
            | CURLOPT_NOPROGRESS
            | CURLOPT_TCP_NODELAY
            | CURLOPT_TCP_KEEPALIVE
            | CURLOPT_BUFFERSIZE
            | CURLOPT_MAXCONNECTS
            | CURLOPT_FRESH_CONNECT
            | CURLOPT_FORBID_REUSE
            | CURLOPT_COOKIEFILE
            | CURLOPT_COOKIEJAR
            | CURLOPT_FILETIME
            | CURLOPT_SSL_OPTIONS
            | CURLOPT_SSL_VERIFYSTATUS
            | CURLOPT_PROGRESSFUNCTION
            | CURLOPT_XFERINFOFUNCTION
            | CURLOPT_DEBUGFUNCTION => {}
            _ => return CURLE_UNKNOWN_OPTION,
        }
        CURLE_OK
    })
}

// ---------------------------------------------------------------------------
// Build an rsurl::Request from the accumulated options.
// ---------------------------------------------------------------------------

fn slist_lines(mut node: *const curl_slist) -> Vec<String> {
    let mut out = Vec::new();
    // SAFETY: the caller's slist is a valid (or null) chain for the request's
    // lifetime, per the libcurl contract.
    unsafe {
        while !node.is_null() {
            if !(*node).data.is_null() {
                out.push(CStr::from_ptr((*node).data).to_string_lossy().into_owned());
            }
            node = (*node).next;
        }
    }
    out
}

/// Build the `rsurl::Request` for this handle (used by perform and the multi
/// interface). Returns a `CURLcode` on a build error.
pub fn build_request(h: &EasyHandle) -> Result<Request, CURLcode> {
    let url = h.url.as_deref().ok_or(CURLE_URL_MALFORMAT)?;

    let method = if let Some(m) = &h.custom_request {
        m.clone()
    } else if h.nobody {
        "HEAD".to_string()
    } else if h.upload {
        "PUT".to_string()
    } else if h.post || !h.post_ptr.is_null() || h.post_copy.is_some() {
        "POST".to_string()
    } else {
        "GET".to_string()
    };

    let mut req = Request::new(&method, url).map_err(|e| map_error(&e))?;
    req = req.verify_tls(h.verify_peer);
    if h.follow {
        req = req.follow_redirects(true);
        if let Some(n) = h.max_redirs {
            req = req.max_redirs(n);
        }
    }
    if let Some(ms) = h.connect_timeout_ms {
        req = req.connect_timeout(Duration::from_millis(ms));
    }
    if let Some(ms) = h.timeout_ms {
        req = req.max_time(Duration::from_millis(ms));
    }

    // HTTP version preference.
    req = match h.http_version {
        CURL_HTTP_VERSION_1_0 | CURL_HTTP_VERSION_1_1 => {
            req.http_version(HttpVersionPref::Http11Only)
        }
        CURL_HTTP_VERSION_2_0 | CURL_HTTP_VERSION_2TLS | CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE => {
            req.http_version(HttpVersionPref::Http2Only)
        }
        CURL_HTTP_VERSION_3 => req.http3(),
        CURL_HTTP_VERSION_3ONLY => req.http3_only(),
        _ => req,
    };

    // Auth.
    let use_digest = h.httpauth & CURLAUTH_DIGEST != 0 && h.httpauth & CURLAUTH_BASIC == 0;
    if let Some(up) = &h.userpwd {
        let (u, p) = split_userpwd(up);
        req = if use_digest {
            req.digest_auth(true).basic_auth(&u, &p)
        } else {
            req.basic_auth(&u, &p)
        };
    } else if let Some(u) = &h.username {
        let p = h.password.clone().unwrap_or_default();
        req = if use_digest {
            req.digest_auth(true).basic_auth(u, &p)
        } else {
            req.basic_auth(u, &p)
        };
    }
    // libcurl: a CURLOPT_HTTPHEADER entry naming a header libcurl would
    // generate itself (in any of its "Name: v" / "Name:" / "Name;" forms)
    // replaces the generated one — it is never sent twice.
    let custom = slist_lines(h.http_header);
    let custom_has = |name: &str| {
        custom.iter().any(|l| {
            l.split_once([':', ';'])
                .is_some_and(|(n, _)| n.trim().eq_ignore_ascii_case(name))
        })
    };
    if let Some(tok) = &h.bearer {
        if !custom_has("Authorization") {
            req = req.header("Authorization", &format!("Bearer {tok}"));
        }
    }

    // Simple header-valued options.
    if let Some(v) = &h.useragent {
        if !custom_has("User-Agent") {
            req = req.header("User-Agent", v);
        }
    }
    if let Some(v) = &h.referer {
        if !custom_has("Referer") {
            req = req.header("Referer", v);
        }
    }
    if let Some(v) = &h.cookie {
        if !custom_has("Cookie") {
            req = req.header("Cookie", v);
        }
    }
    if let Some(v) = &h.range {
        // CURLOPT_RANGE takes the bare "X-Y" range set; HTTP needs the unit.
        req = req.header("Range", &format!("bytes={v}"));
    }
    let custom_ae = custom_has("Accept-Encoding");
    match &h.accept_encoding {
        Some(v) => {
            let val = if v.is_empty() {
                "gzip, deflate, br, zstd"
            } else {
                v.as_str()
            };
            req = req.header("Accept-Encoding", val);
        }
        // Without CURLOPT_ACCEPT_ENCODING libcurl never decodes: a caller that
        // asked for an encoding through its own header gets the raw bytes.
        None if custom_ae => req = req.decompress(false),
        None => {}
    }

    // Caller-supplied headers: "Name: value" sends it, "Name;" sends an empty
    // header, and "Name:" (no value) is libcurl's "remove this header" form,
    // which only affects headers libcurl adds itself — so it is not sent.
    for line in custom {
        if let Some((name, val)) = line.split_once(':') {
            let val = val.trim();
            if !val.is_empty() {
                req = req.header(name.trim(), val);
            }
        } else if let Some(name) = line.trim_end().strip_suffix(';') {
            req = req.header(name.trim(), "");
        }
    }

    // TLS material.
    if let Some(v) = &h.cainfo {
        req = req.ca_bundle(v);
    }
    if let Some(v) = &h.capath {
        req = req.ca_path(v);
    }
    if let Some(v) = &h.sslcert {
        req = req.client_cert(v);
    }
    if let Some(v) = &h.sslkey {
        req = req.client_key(v);
    }
    if let Some(v) = &h.keypasswd {
        req = req.client_key_pass(v);
    }
    if let Some(v) = &h.pinnedpubkey {
        req = req.pinned_pubkey(v);
    }
    if let Some(v) = &h.crlfile {
        req = req.crl_file(v);
    }
    if let Some(v) = &h.cipher_list {
        req = req.ciphers(v);
    }
    if let Some(v) = &h.tls13_ciphers {
        req = req.tls13_ciphers(v);
    }

    // Proxy. The no-proxy list is re-checked on every redirect hop.
    if let Some(spec) = &h.proxy {
        req = req.proxy(spec).map_err(|e| map_error(&e))?;
    }
    if let Some(list) = &h.noproxy {
        req = req.no_proxy(list.split(',').map(str::trim).filter(|s| !s.is_empty()));
    }
    // TLS to an `https://` proxy — independent of the origin's settings.
    let pt = &h.proxy_tls;
    req = req.proxy_verify_tls(pt.verify_peer);
    if let Some(v) = &pt.cainfo {
        req = req.proxy_ca_bundle(v);
    }
    if let Some(v) = &pt.capath {
        req = req.proxy_ca_path(v);
    }
    if let Some(v) = &pt.sslcert {
        req = req.proxy_client_cert(v);
    }
    if let Some(v) = &pt.sslkey {
        req = req.proxy_client_key(v);
    }
    if let Some(v) = &pt.keypasswd {
        req = req.proxy_client_key_pass(v);
    }
    if let Some(v) = &pt.pinnedpubkey {
        req = req.proxy_pinned_pubkey(v);
    }
    if let Some(v) = &pt.crlfile {
        req = req.proxy_crl_file(v);
    }
    if let Some(v) = &pt.cipher_list {
        req = req.proxy_ciphers(v);
    }
    if let Some(v) = &pt.tls13_ciphers {
        req = req.proxy_tls13_ciphers(v);
    }

    // --resolve / --connect-to.
    for line in slist_lines(h.resolve) {
        if let Some((host, port, ip)) = parse_resolve(&line) {
            req = req.resolve_addr(&host, port, ip);
        }
    }
    for line in slist_lines(h.connect_to) {
        if let Some((fh, fp, th, tp)) = parse_connect_to(&line) {
            req = req.connect_to(&fh, fp, &th, tp);
        }
    }

    // Body.
    let body: Option<Vec<u8>> = if let Some(b) = &h.post_copy {
        Some(b.clone())
    } else if !h.post_ptr.is_null() {
        // SAFETY: POSTFIELDS contract — caller keeps the buffer alive to perform.
        let len = h.post_len.unwrap_or_else(|| unsafe {
            CStr::from_ptr(h.post_ptr as *const c_char).to_bytes().len()
        });
        Some(unsafe { std::slice::from_raw_parts(h.post_ptr, len) }.to_vec())
    } else {
        None
    };
    if let Some(b) = body {
        req = req.body(b);
    }

    Ok(req)
}

/// Deliver a completed response to this handle's callbacks (write/header,
/// honoring CURLOPT_HEADER), store it for `getinfo`, and return the CURLcode.
/// Runs on the caller's thread (perform, or curl_multi_perform).
pub fn deliver(h: &mut EasyHandle, resp: Response) -> CURLcode {
    // FAILONERROR: a >= 400 status is an error and the body is not delivered.
    if h.failonerror && resp.status >= 400 {
        let code = CURLE_HTTP_RETURNED_ERROR;
        set_error_buffer(h, "The requested URL returned error");
        h.last = Some(resp);
        return code;
    }

    // Header block: status line, each header, terminating CRLF.
    if h.header_fn.is_some() || !h.header_data.is_null() || h.header_in_body {
        let mut block: Vec<u8> = Vec::new();
        let status_line = format!("{} {} {}\r\n", resp.version, resp.status, resp.reason);
        block.extend_from_slice(status_line.as_bytes());
        for (k, v) in &resp.headers {
            block.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
        }
        block.extend_from_slice(b"\r\n");

        // libcurl delivers headers one line at a time: to HEADERFUNCTION, else
        // (when only HEADERDATA is set) through the write function with
        // HEADERDATA as its userdata — by default, fwrite to that FILE*.
        let header_sink = match h.header_fn {
            Some(cb) => Some((cb, h.header_data)),
            None if !h.header_data.is_null() => Some((
                h.write_fn.unwrap_or(default_write as WriteCb),
                h.header_data,
            )),
            None => None,
        };
        if let Some((cb, data)) = header_sink {
            for line in split_keep_crlf(&block) {
                if !invoke(cb, line, data) {
                    return CURLE_WRITE_ERROR;
                }
            }
        }
        if h.header_in_body && !write_body(h, &block) {
            return CURLE_WRITE_ERROR;
        }
    }

    // Body (none for HEAD/NOBODY).
    if !h.nobody && !resp.body.is_empty() && !write_body(h, &resp.body) {
        return CURLE_WRITE_ERROR;
    }

    h.last = Some(resp);
    CURLE_OK
}

fn write_body(h: &EasyHandle, data: &[u8]) -> bool {
    match (h.write_fn, h.write_data.is_null()) {
        (Some(cb), _) => {
            for chunk in data.chunks(MAX_WRITE_SIZE) {
                if !invoke(cb, chunk, h.write_data) {
                    return false;
                }
            }
            true
        }
        // libcurl's default write callback is fwrite() to the WRITEDATA FILE*.
        (None, false) => data
            .chunks(MAX_WRITE_SIZE)
            .all(|chunk| invoke(default_write, chunk, h.write_data)),
        (None, true) => {
            // No WRITEDATA: libcurl writes to stdout.
            use std::io::Write;
            let mut out = std::io::stdout();
            out.write_all(data).is_ok() && out.flush().is_ok()
        }
    }
}

extern "C" {
    fn fwrite(ptr: *const c_void, size: usize, nmemb: usize, stream: *mut c_void) -> usize;
}

/// libcurl's default write callback: `fwrite(ptr, size, nmemb, (FILE *)userdata)`.
unsafe extern "C" fn default_write(
    ptr: *mut c_char,
    size: usize,
    nmemb: usize,
    userdata: *mut c_void,
) -> usize {
    fwrite(ptr as *const c_void, size, nmemb, userdata)
}

fn invoke(cb: WriteCb, data: &[u8], userdata: *mut c_void) -> bool {
    if data.is_empty() {
        return true;
    }
    // SAFETY: cb is a caller-provided C function pointer; we pass a valid
    // (ptr, size=1, nmemb=len) per the libcurl callback contract.
    let n = unsafe { cb(data.as_ptr() as *mut c_char, 1, data.len(), userdata) };
    n == data.len()
}

fn split_keep_crlf(block: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start = 0;
    for i in 0..block.len() {
        if block[i] == b'\n' {
            out.push(&block[start..=i]);
            start = i + 1;
        }
    }
    if start < block.len() {
        out.push(&block[start..]);
    }
    out
}

fn set_error_buffer(h: &EasyHandle, msg: &str) {
    if h.error_buffer.is_null() {
        return;
    }
    // CURL_ERROR_SIZE is 256; leave room for the NUL.
    let bytes = msg.as_bytes();
    let n = bytes.len().min(255);
    // SAFETY: caller guarantees error_buffer points to >= 256 bytes.
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), h.error_buffer as *mut u8, n);
        *h.error_buffer.add(n) = 0;
    }
}

/// Build the request for an easy handle given by raw pointer. Used by the
/// multi interface to assemble the request on the caller's thread before
/// handing it (which is `Send`) to a worker.
pub(crate) fn build_request_ptr(handle: *mut CURL) -> Result<Request, CURLcode> {
    match as_handle(handle) {
        Some(h) => build_request(h),
        None => Err(CURLE_FAILED_INIT),
    }
}

/// Deliver a completed response to an easy handle given by raw pointer (runs
/// on the caller's thread, e.g. inside `curl_multi_perform`).
pub(crate) fn deliver_ptr(handle: *mut CURL, resp: Response) -> CURLcode {
    match as_handle(handle) {
        Some(h) => deliver(h, resp),
        None => CURLE_FAILED_INIT,
    }
}

#[no_mangle]
pub extern "C" fn curl_easy_perform(handle: *mut CURL) -> CURLcode {
    ffi_guard(CURLE_FAILED_INIT, || {
        let Some(h) = as_handle(handle) else {
            return CURLE_FAILED_INIT;
        };
        let req = match build_request(h) {
            Ok(r) => r,
            Err(code) => {
                set_error_buffer(h, "failed to build request");
                return code;
            }
        };
        match req.send() {
            Ok(resp) => deliver(h, resp),
            Err(e) => {
                let code = map_error(&e);
                set_error_buffer(h, &e.to_string());
                code
            }
        }
    })
}

// ---------------------------------------------------------------------------
// getinfo
// ---------------------------------------------------------------------------

/// `CURLcode curl_easy_getinfo(CURL*, CURLINFO, ...)` — the variadic out-pointer
/// is read as a fixed third argument (see [`curl_easy_setopt`] for the ABI).
#[cfg_attr(not(all(target_arch = "aarch64", target_vendor = "apple")), no_mangle)]
pub unsafe extern "C" fn curl_easy_getinfo(
    handle: *mut CURL,
    info: c_int,
    out: *mut c_void,
) -> CURLcode {
    ffi_guard(CURLE_BAD_FUNCTION_ARGUMENT, || {
        let Some(h) = as_handle(handle) else {
            return CURLE_BAD_FUNCTION_ARGUMENT;
        };
        if out.is_null() {
            return CURLE_BAD_FUNCTION_ARGUMENT;
        }
        let resp = h.last.as_ref();
        match info {
            CURLINFO_RESPONSE_CODE => {
                *(out as *mut c_long) = resp.map(|r| r.status as c_long).unwrap_or(0);
            }
            CURLINFO_HTTP_VERSION => {
                *(out as *mut c_long) = resp.map(|r| http_version_code(&r.version)).unwrap_or(0);
            }
            CURLINFO_REDIRECT_COUNT => {
                // rsurl does not count hops; report whether a redirect was
                // followed at all (the final URL differs from the request URL).
                let redirected = resp.is_some_and(|r| {
                    !r.final_url.is_empty()
                        && !h.url.as_deref().is_some_and(|u| same_url(u, &r.final_url))
                });
                *(out as *mut c_long) = redirected as c_long;
            }
            CURLINFO_HEADER_SIZE => {
                *(out as *mut c_long) = resp.map(|r| header_block_len(r) as c_long).unwrap_or(0);
            }
            CURLINFO_PRIVATE => *(out as *mut *mut c_void) = h.private,
            CURLINFO_EFFECTIVE_URL => {
                let s = resp
                    .map(|r| {
                        if r.final_url.is_empty() {
                            h.url.clone().unwrap_or_default()
                        } else {
                            r.final_url.clone()
                        }
                    })
                    .unwrap_or_else(|| h.url.clone().unwrap_or_default());
                h.info_effective_url = CString::new(s).ok();
                *(out as *mut *const c_char) = h
                    .info_effective_url
                    .as_ref()
                    .map(|c| c.as_ptr())
                    .unwrap_or(ptr::null());
            }
            CURLINFO_CONTENT_TYPE => {
                let ct = resp
                    .and_then(|r| r.header("content-type"))
                    .map(|s| s.to_string());
                match ct.and_then(|s| CString::new(s).ok()) {
                    Some(c) => {
                        h.info_content_type = Some(c);
                        *(out as *mut *const c_char) =
                            h.info_content_type.as_ref().unwrap().as_ptr();
                    }
                    None => *(out as *mut *const c_char) = ptr::null(),
                }
            }
            CURLINFO_SIZE_DOWNLOAD => {
                *(out as *mut f64) = resp.map(|r| r.body.len() as f64).unwrap_or(0.0);
            }
            CURLINFO_SIZE_DOWNLOAD_T => {
                *(out as *mut i64) = resp.map(|r| r.body.len() as i64).unwrap_or(0);
            }
            CURLINFO_CONNECT_TIME => *(out as *mut f64) = time_secs(resp, |t| t.connect),
            CURLINFO_APPCONNECT_TIME => *(out as *mut f64) = time_secs(resp, |t| t.appconnect),
            CURLINFO_PRETRANSFER_TIME => *(out as *mut f64) = time_secs(resp, |t| t.pretransfer),
            CURLINFO_STARTTRANSFER_TIME => {
                *(out as *mut f64) = time_secs(resp, |t| t.starttransfer)
            }
            CURLINFO_TOTAL_TIME => *(out as *mut f64) = time_secs(resp, total_time),
            CURLINFO_NAMELOOKUP_TIME => *(out as *mut f64) = time_secs(resp, |t| t.namelookup),
            CURLINFO_NAMELOOKUP_TIME_T => *(out as *mut i64) = time_us(resp, |t| t.namelookup),
            CURLINFO_CONNECT_TIME_T => *(out as *mut i64) = time_us(resp, |t| t.connect),
            CURLINFO_APPCONNECT_TIME_T => *(out as *mut i64) = time_us(resp, |t| t.appconnect),
            CURLINFO_PRETRANSFER_TIME_T => *(out as *mut i64) = time_us(resp, |t| t.pretransfer),
            CURLINFO_STARTTRANSFER_TIME_T => {
                *(out as *mut i64) = time_us(resp, |t| t.starttransfer)
            }
            CURLINFO_TOTAL_TIME_T => *(out as *mut i64) = time_us(resp, total_time),
            _ => return CURLE_UNKNOWN_OPTION,
        }
        CURLE_OK
    })
}

/// Whether two URL strings name the same resource once normalised (the final
/// URL rsurl reports is re-serialised, so compare parsed components).
fn same_url(a: &str, b: &str) -> bool {
    match (rsurl::Url::parse(a), rsurl::Url::parse(b)) {
        (Ok(a), Ok(b)) => {
            a.scheme.eq_ignore_ascii_case(&b.scheme)
                && a.host.eq_ignore_ascii_case(&b.host)
                && a.port == b.port
                && a.path == b.path
        }
        _ => a == b,
    }
}

/// Whole-transfer time: the measured total, else the latest phase we have.
fn total_time(t: &rsurl::Timing) -> Option<Duration> {
    t.total.or(t.starttransfer)
}

/// Bytes of the response header block as delivered to the header callback:
/// status line, each `Name: value` line, and the terminating blank line.
fn header_block_len(r: &Response) -> usize {
    let status = r.version.len() + 1 + 3 + 1 + r.reason.len() + 2;
    let fields: usize = r
        .headers
        .iter()
        .map(|(k, v)| k.len() + 2 + v.len() + 2)
        .sum();
    status + fields + 2
}

fn time_secs(resp: Option<&Response>, f: impl Fn(&rsurl::Timing) -> Option<Duration>) -> f64 {
    resp.and_then(|r| f(&r.timing))
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn time_us(resp: Option<&Response>, f: impl Fn(&rsurl::Timing) -> Option<Duration>) -> i64 {
    resp.and_then(|r| f(&r.timing))
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

fn http_version_code(version: &str) -> c_long {
    match version {
        "HTTP/1.0" => CURL_HTTP_VERSION_1_0,
        "HTTP/1.1" => CURL_HTTP_VERSION_1_1,
        "HTTP/2" => CURL_HTTP_VERSION_2_0,
        "HTTP/3" => CURL_HTTP_VERSION_3,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn split_userpwd(s: &str) -> (String, String) {
    match s.split_once(':') {
        Some((u, p)) => (u.to_string(), p.to_string()),
        None => (s.to_string(), String::new()),
    }
}

fn parse_resolve(line: &str) -> Option<(String, u16, std::net::IpAddr)> {
    // "[+]HOST:PORT:ADDR[,ADDR...]" — take the first address.
    let line = line.trim_start_matches(['+', '-']);
    let mut it = line.splitn(3, ':');
    let host = it.next()?.to_string();
    let port: u16 = it.next()?.parse().ok()?;
    let addr = it.next()?.split(',').next()?.trim_matches(['[', ']']);
    let ip: std::net::IpAddr = addr.parse().ok()?;
    Some((host, port, ip))
}

fn parse_connect_to(line: &str) -> Option<(String, u16, String, u16)> {
    // "HOST:PORT:CONNECT-TO-HOST:CONNECT-TO-PORT" (empty fields = wildcard).
    let parts: Vec<&str> = line.splitn(4, ':').collect();
    if parts.len() != 4 {
        return None;
    }
    let fp = parts[1].parse().unwrap_or(0);
    let tp = parts[3].parse().unwrap_or(0);
    Some((parts[0].to_string(), fp, parts[2].to_string(), tp))
}

/// Map an `rsurl::Error` to the closest `CURLcode`.
pub fn map_error(e: &Error) -> CURLcode {
    match e {
        Error::UnsupportedScheme(_) => CURLE_UNSUPPORTED_PROTOCOL,
        Error::InvalidUrl(_) => CURLE_URL_MALFORMAT,
        Error::Io(io) => match io.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
                CURLE_OPERATION_TIMEDOUT
            }
            std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::NotFound
            | std::io::ErrorKind::AddrNotAvailable => CURLE_COULDNT_CONNECT,
            _ => CURLE_RECV_ERROR,
        },
        Error::UnexpectedEof => CURLE_GOT_NOTHING,
        Error::BadResponse(_) => CURLE_WEIRD_SERVER_REPLY,
        Error::H2NotNegotiated => CURLE_HTTP2,
        Error::Ssh(_) => CURLE_UNSUPPORTED_PROTOCOL,
        Error::Decode(_) => CURLE_BAD_CONTENT_ENCODING,
        Error::Status { .. } => CURLE_HTTP_RETURNED_ERROR,
        Error::Cancelled => CURLE_ABORTED_BY_CALLBACK,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pointer-width options (here a plain `long`) work on every target.
    #[test]
    fn long_option_is_accepted_on_any_target() {
        unsafe {
            let h = curl_easy_init();
            assert!(!h.is_null());
            assert_eq!(curl_easy_setopt(h, CURLOPT_POSTFIELDSIZE, 16), CURLE_OK);
            curl_easy_cleanup(h);
        }
    }

    /// `CURLOPT_POSTFIELDSIZE_LARGE` carries a 64-bit `curl_off_t`. It is honored
    /// on 64-bit targets and rejected with `CURLE_NOT_BUILT_IN` on 32-bit (ILP32),
    /// where the variadic 64-bit argument cannot be read through the faked
    /// non-variadic signature. The 32-bit arm is exercised by the i686 CI leg.
    #[test]
    fn postfieldsize_large_depends_on_pointer_width() {
        unsafe {
            let h = curl_easy_init();
            assert!(!h.is_null());
            let rc = curl_easy_setopt(h, CURLOPT_POSTFIELDSIZE_LARGE, 123);
            #[cfg(target_pointer_width = "64")]
            assert_eq!(rc, CURLE_OK);
            #[cfg(not(target_pointer_width = "64"))]
            assert_eq!(rc, CURLE_NOT_BUILT_IN);
            curl_easy_cleanup(h);
        }
    }
}

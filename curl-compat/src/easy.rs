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
/// Declared non-variadic: on 64-bit SysV/AArch64 the single third argument
/// (long / pointer / curl_off_t / function pointer) is passed in the same
/// register, so taking it as `usize` and reinterpreting by the option's type
/// class (`option / 10000`) is ABI-compatible. See the crate README.
#[no_mangle]
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
            CURLOPT_ACCEPT_ENCODING => {
                h.accept_encoding = Some(opt_string(value).unwrap_or_default())
            }
            CURLOPT_RANGE => h.range = opt_string(value),
            CURLOPT_CAINFO => h.cainfo = opt_string(value),
            CURLOPT_CAPATH => h.capath = opt_string(value),
            CURLOPT_SSLCERT => h.sslcert = opt_string(value),
            CURLOPT_SSLKEY => h.sslkey = opt_string(value),
            CURLOPT_KEYPASSWD => h.keypasswd = opt_string(value),
            CURLOPT_PINNEDPUBLICKEY => h.pinnedpubkey = opt_string(value),
            CURLOPT_CRLFILE => h.crlfile = opt_string(value),
            CURLOPT_SSL_CIPHER_LIST => h.cipher_list = opt_string(value),
            CURLOPT_TLS13_CIPHERS => h.tls13_ciphers = opt_string(value),
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
                    h.post = false;
                    h.upload = false;
                    h.nobody = false;
                }
            }
            CURLOPT_SSL_VERIFYPEER => h.verify_peer = lv != 0,
            CURLOPT_HTTP_VERSION => h.http_version = lv,
            CURLOPT_HTTPAUTH => h.httpauth = lv,
            CURLOPT_TIMEOUT => h.timeout_ms = Some((lv.max(0) as u64) * 1000),
            CURLOPT_TIMEOUT_MS => h.timeout_ms = Some(lv.max(0) as u64),
            CURLOPT_CONNECTTIMEOUT => h.connect_timeout_ms = Some((lv.max(0) as u64) * 1000),
            CURLOPT_CONNECTTIMEOUT_MS => h.connect_timeout_ms = Some(lv.max(0) as u64),
            CURLOPT_POSTFIELDSIZE => h.post_len = if lv < 0 { None } else { Some(lv as usize) },
            CURLOPT_POSTFIELDSIZE_LARGE => {
                let off = value as i64;
                h.post_len = if off < 0 { None } else { Some(off as usize) };
            }
            // --- recognized but behaviorally irrelevant here: accept silently ---
            CURLOPT_SSL_VERIFYHOST
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
            | CURLOPT_DEBUGFUNCTION
            | CURLOPT_PRIVATE => {}
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
    if let Some(tok) = &h.bearer {
        req = req.header("Authorization", &format!("Bearer {tok}"));
    }

    // Simple header-valued options.
    if let Some(v) = &h.useragent {
        req = req.header("User-Agent", v);
    }
    if let Some(v) = &h.referer {
        req = req.header("Referer", v);
    }
    if let Some(v) = &h.cookie {
        req = req.header("Cookie", v);
    }
    if let Some(v) = &h.range {
        req = req.header("Range", v);
    }
    if let Some(v) = &h.accept_encoding {
        let val = if v.is_empty() {
            "gzip, deflate, br, zstd"
        } else {
            v.as_str()
        };
        req = req.header("Accept-Encoding", val);
    }

    // Caller-supplied headers (full "Name: value" lines).
    for line in slist_lines(h.http_header) {
        if let Some((name, val)) = line.split_once(':') {
            req = req.header(name.trim(), val.trim());
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

    // Proxy.
    if let Some(spec) = &h.proxy {
        req = req.proxy(spec).map_err(|e| map_error(&e))?;
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
    if h.header_fn.is_some() || h.header_in_body {
        let mut block: Vec<u8> = Vec::new();
        let status_line = format!("{} {} {}\r\n", resp.version, resp.status, resp.reason);
        block.extend_from_slice(status_line.as_bytes());
        for (k, v) in &resp.headers {
            block.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
        }
        block.extend_from_slice(b"\r\n");

        if let Some(cb) = h.header_fn {
            // libcurl delivers headers one line at a time.
            for line in split_keep_crlf(&block) {
                if !invoke(cb, line, h.header_data) {
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
    match h.write_fn {
        Some(cb) => {
            for chunk in data.chunks(MAX_WRITE_SIZE) {
                if !invoke(cb, chunk, h.write_data) {
                    return false;
                }
            }
            true
        }
        None => {
            // libcurl's default: write the body to stdout.
            use std::io::Write;
            std::io::stdout().write_all(data).is_ok()
        }
    }
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

#[no_mangle]
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
            CURLINFO_REDIRECT_COUNT | CURLINFO_HEADER_SIZE => {
                *(out as *mut c_long) = 0;
            }
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
            CURLINFO_STARTTRANSFER_TIME | CURLINFO_TOTAL_TIME => {
                *(out as *mut f64) = time_secs(resp, |t| t.starttransfer)
            }
            CURLINFO_NAMELOOKUP_TIME => *(out as *mut f64) = 0.0,
            CURLINFO_CONNECT_TIME_T => *(out as *mut i64) = time_us(resp, |t| t.connect),
            CURLINFO_STARTTRANSFER_TIME_T | CURLINFO_TOTAL_TIME_T => {
                *(out as *mut i64) = time_us(resp, |t| t.starttransfer)
            }
            _ => return CURLE_UNKNOWN_OPTION,
        }
        CURLE_OK
    })
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

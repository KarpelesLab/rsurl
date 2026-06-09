//! C ABI for rsurl.
//!
//! A deliberately minimal, libcurl-shaped "easy" API. Function names use a
//! `rsurl_` prefix (not `curl_`) so this can be linked alongside libcurl
//! without symbol clashes, while still being familiar to anyone who has
//! used libcurl before.
//!
//! Lifecycle:
//!
//! ```c
//! RSURL *h = rsurl_easy_init();
//! rsurl_easy_setopt_str(h, RSURLOPT_URL, "http://example.com");
//! rsurl_easy_perform(h);
//! const uint8_t *body; size_t len;
//! rsurl_easy_response_body(h, &body, &len);
//! rsurl_easy_cleanup(h);
//! ```
//!
//! All pointer parameters except `handle` may be NULL where stated. Returned
//! pointers from `rsurl_easy_response_*` borrow from the handle and become
//! invalid on the next `rsurl_easy_perform` or `rsurl_easy_cleanup`.
//!
//! Thread safety: a handle (`RSURL*`) must not be used concurrently from
//! multiple threads; use one handle per thread (libcurl easy-handle model).
//! The library performs no internal synchronization on a handle — concurrent
//! access to the same handle from more than one thread is undefined behavior.

#![allow(non_camel_case_types)]

use std::ffi::{c_char, c_int, c_long, CStr};
use std::panic::{self, AssertUnwindSafe};
use std::ptr;

use crate::http::{Request, Response};

/// Unwind barrier for the C ABI: a Rust panic crossing an `extern "C"`
/// boundary is undefined behavior, so every exported function runs its body
/// through `catch_unwind` and converts a caught panic into `default`.
///
/// `AssertUnwindSafe` is sound here because the closures only touch a single
/// handle behind a raw pointer (no shared `&mut` state observed after a
/// panic) and any panic aborts the operation before returning a value to C;
/// the handle is left in a valid—if possibly partially-updated—state, which
/// is the same guarantee callers already get from an error return.
fn ffi_guard<T>(default: T, f: impl FnOnce() -> T) -> T {
    panic::catch_unwind(AssertUnwindSafe(f)).unwrap_or(default)
}

/// Opaque handle. Never dereferenced from C.
pub enum RSURL {}

/// Option codes accepted by `rsurl_easy_setopt`.
#[repr(C)]
pub enum RsurlOpt {
    /// const char* — the target URL.
    Url = 1,
    /// const char* — override HTTP method (default GET, or POST if body set).
    CustomRequest = 2,
    /// const char* — single header line ("Name: value"). Repeat to add multiple.
    Header = 3,
    /// const char* — request body (UTF-8 string, NUL-terminated).
    PostFieldsString = 4,
    /// long — connect timeout in seconds. 0 disables.
    ConnectTimeout = 5,
    /// long — read timeout in seconds. 0 disables.
    Timeout = 6,
    /// const char* — User-Agent value.
    UserAgent = 7,
    /// long — convert international (IDN) hostnames to punycode. Non-zero
    /// (default) on, 0 off (curl `--no-idn`). No-op without the `idn` feature.
    Idn = 8,
    /// long — follow 3xx redirects (curl `CURLOPT_FOLLOWLOCATION`). Off default.
    FollowLocation = 9,
    /// long — maximum redirects to follow when FollowLocation is on. <0 = none.
    MaxRedirs = 10,
    /// const char* — `"user:password"` for HTTP Basic auth (`CURLOPT_USERPWD`).
    UserPwd = 11,
    /// long — verify the TLS peer certificate (default on). 0 = curl `-k`
    /// (`CURLOPT_SSL_VERIFYPEER`).
    SslVerifyPeer = 12,
    /// const char* — proxy URL (`CURLOPT_PROXY`): http/https/socks4/4a/5/5h.
    Proxy = 13,
    /// const char* — `Referer` header value (`CURLOPT_REFERER`).
    Referer = 14,
    /// const char* — byte range, e.g. `"0-1023"` (`CURLOPT_RANGE`).
    Range = 15,
    /// const char* — `Cookie` request header (`CURLOPT_COOKIE`).
    Cookie = 16,
    /// const char* — OAuth2 bearer token (`CURLOPT_XOAUTH2_BEARER`).
    Bearer = 17,
    /// const char* — `Accept-Encoding` value; empty string requests every codec
    /// rsurl can decode, like curl `--compressed` (`CURLOPT_ACCEPT_ENCODING`).
    AcceptEncoding = 18,
}

/// Status codes returned by the API.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RsurlCode {
    Ok = 0,
    InvalidHandle = 1,
    UnknownOption = 2,
    InvalidArg = 3,
    /// Reserved. Never returned by the API: the response getters signal "no
    /// response available" via a NULL/0 out-value together with `Ok`, not this
    /// code. Kept for ABI stability and `rsurl_strerror` coverage.
    NoResponse = 4,
    Network = 5,
    BadResponse = 6,
    Unsupported = 7,
}

struct Handle {
    url: Option<String>,
    method: Option<String>,
    user_agent: Option<String>,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
    connect_timeout_secs: Option<u64>,
    timeout_secs: Option<u64>,
    /// Convert international (IDN) hostnames to punycode. On by default.
    idn: bool,
    follow_location: bool,
    max_redirs: Option<u32>,
    basic_auth: Option<(String, String)>,
    verify_peer: bool,
    proxy: Option<String>,
    referer: Option<String>,
    range: Option<String>,
    cookie: Option<String>,
    bearer: Option<String>,
    accept_encoding: Option<String>,
    last_response: Option<Response>,
    /// Stable storage so C callers can read header values as NUL-terminated
    /// strings without us having to allocate per-call.
    header_buf: Vec<Vec<u8>>,
}

impl Handle {
    fn new() -> Self {
        Handle {
            url: None,
            method: None,
            user_agent: None,
            headers: Vec::new(),
            body: None,
            connect_timeout_secs: None,
            timeout_secs: None,
            idn: true,
            follow_location: false,
            max_redirs: None,
            basic_auth: None,
            verify_peer: true,
            proxy: None,
            referer: None,
            range: None,
            cookie: None,
            bearer: None,
            accept_encoding: None,
            last_response: None,
            header_buf: Vec::new(),
        }
    }
}

// These mint a `&mut`/`&` from a raw pointer with no synchronization. The C
// contract (see module docs) is that a single handle is never used concurrently
// from multiple threads — one handle per thread, libcurl easy-handle model —
// so no two live borrows of the same `Handle` can exist at once. Violating that
// contract (sharing a handle across threads without external locking) is
// undefined behavior.

fn handle_mut<'a>(h: *mut RSURL) -> Option<&'a mut Handle> {
    if h.is_null() {
        return None;
    }
    // SAFETY: handles are always created from Box::into_raw of a Handle, and
    // the caller upholds the one-handle-per-thread contract (no aliasing).
    Some(unsafe { &mut *(h as *mut Handle) })
}

fn handle_ref<'a>(h: *const RSURL) -> Option<&'a Handle> {
    if h.is_null() {
        return None;
    }
    // SAFETY: handles are always created from Box::into_raw of a Handle, and
    // the caller upholds the one-handle-per-thread contract (no aliasing).
    Some(unsafe { &*(h as *const Handle) })
}

/// Allocate a new easy handle. Returns NULL on allocation failure (practically
/// never on this platform). Free with `rsurl_easy_cleanup`.
#[no_mangle]
pub extern "C" fn rsurl_easy_init() -> *mut RSURL {
    ffi_guard(ptr::null_mut(), || {
        let boxed = Box::new(Handle::new());
        Box::into_raw(boxed) as *mut RSURL
    })
}

/// Free an easy handle. NULL is a no-op.
#[no_mangle]
pub extern "C" fn rsurl_easy_cleanup(handle: *mut RSURL) {
    ffi_guard((), || {
        if handle.is_null() {
            return;
        }
        // SAFETY: handle came from rsurl_easy_init's Box::into_raw.
        unsafe {
            drop(Box::from_raw(handle as *mut Handle));
        }
    })
}

/// Reset all options on a handle but keep it allocated. Clears any previous
/// response data.
#[no_mangle]
pub extern "C" fn rsurl_easy_reset(handle: *mut RSURL) -> RsurlCode {
    ffi_guard(RsurlCode::Network, || {
        let Some(h) = handle_mut(handle) else {
            return RsurlCode::InvalidHandle;
        };
        *h = Handle::new();
        RsurlCode::Ok
    })
}

/// Set an option taking a NUL-terminated `const char*`.
///
/// Pass NULL to clear/unset that option. The string is copied into the handle.
///
/// # Safety
///
/// `handle` must be a pointer returned by [`rsurl_easy_init`] and not yet
/// freed by [`rsurl_easy_cleanup`]. `value`, if non-null, must point to a
/// valid NUL-terminated C string for the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn rsurl_easy_setopt_str(
    handle: *mut RSURL,
    option: c_int,
    value: *const c_char,
) -> RsurlCode {
    ffi_guard(RsurlCode::Network, || {
        let Some(h) = handle_mut(handle) else {
            return RsurlCode::InvalidHandle;
        };
        let s = if value.is_null() {
            None
        } else {
            // SAFETY: caller asserts value is a valid NUL-terminated C string.
            match unsafe { CStr::from_ptr(value) }.to_str() {
                Ok(s) => Some(s.to_string()),
                Err(_) => return RsurlCode::InvalidArg,
            }
        };
        let Some(opt) = opt_from_int(option) else {
            return RsurlCode::UnknownOption;
        };
        match opt {
            RsurlOpt::Url => h.url = s,
            RsurlOpt::CustomRequest => h.method = s,
            RsurlOpt::UserAgent => h.user_agent = s,
            RsurlOpt::Header => match s {
                Some(line) => {
                    let Some((k, v)) = line.split_once(':') else {
                        return RsurlCode::InvalidArg;
                    };
                    h.headers.push((k.trim().to_string(), v.trim().to_string()));
                }
                None => h.headers.clear(),
            },
            RsurlOpt::PostFieldsString => h.body = s.map(|s| s.into_bytes()),
            RsurlOpt::UserPwd => {
                h.basic_auth = s.map(|v| match v.split_once(':') {
                    Some((u, p)) => (u.to_string(), p.to_string()),
                    None => (v, String::new()),
                });
            }
            RsurlOpt::Proxy => h.proxy = s,
            RsurlOpt::Referer => h.referer = s,
            RsurlOpt::Range => h.range = s,
            RsurlOpt::Cookie => h.cookie = s,
            RsurlOpt::Bearer => h.bearer = s,
            RsurlOpt::AcceptEncoding => h.accept_encoding = s,
            RsurlOpt::ConnectTimeout
            | RsurlOpt::Timeout
            | RsurlOpt::Idn
            | RsurlOpt::FollowLocation
            | RsurlOpt::MaxRedirs
            | RsurlOpt::SslVerifyPeer => return RsurlCode::InvalidArg,
        }
        RsurlCode::Ok
    })
}

/// Set an option taking a `long` (e.g. timeouts).
#[no_mangle]
pub extern "C" fn rsurl_easy_setopt_long(
    handle: *mut RSURL,
    option: c_int,
    value: c_long,
) -> RsurlCode {
    ffi_guard(RsurlCode::Network, || {
        let Some(h) = handle_mut(handle) else {
            return RsurlCode::InvalidHandle;
        };
        let Some(opt) = opt_from_int(option) else {
            return RsurlCode::UnknownOption;
        };
        let secs = if value <= 0 { None } else { Some(value as u64) };
        match opt {
            RsurlOpt::ConnectTimeout => h.connect_timeout_secs = secs,
            RsurlOpt::Timeout => h.timeout_secs = secs,
            RsurlOpt::Idn => h.idn = value != 0,
            RsurlOpt::FollowLocation => h.follow_location = value != 0,
            RsurlOpt::MaxRedirs => {
                h.max_redirs = if value < 0 {
                    Some(0)
                } else {
                    Some(value as u32)
                }
            }
            RsurlOpt::SslVerifyPeer => h.verify_peer = value != 0,
            _ => return RsurlCode::InvalidArg,
        }
        RsurlCode::Ok
    })
}

fn opt_from_int(v: c_int) -> Option<RsurlOpt> {
    Some(match v {
        1 => RsurlOpt::Url,
        2 => RsurlOpt::CustomRequest,
        3 => RsurlOpt::Header,
        4 => RsurlOpt::PostFieldsString,
        5 => RsurlOpt::ConnectTimeout,
        6 => RsurlOpt::Timeout,
        7 => RsurlOpt::UserAgent,
        8 => RsurlOpt::Idn,
        9 => RsurlOpt::FollowLocation,
        10 => RsurlOpt::MaxRedirs,
        11 => RsurlOpt::UserPwd,
        12 => RsurlOpt::SslVerifyPeer,
        13 => RsurlOpt::Proxy,
        14 => RsurlOpt::Referer,
        15 => RsurlOpt::Range,
        16 => RsurlOpt::Cookie,
        17 => RsurlOpt::Bearer,
        18 => RsurlOpt::AcceptEncoding,
        _ => return None,
    })
}

/// Execute the request configured on the handle. Replaces any previous
/// response stored on the handle.
#[no_mangle]
pub extern "C" fn rsurl_easy_perform(handle: *mut RSURL) -> RsurlCode {
    ffi_guard(RsurlCode::Network, || {
        let Some(h) = handle_mut(handle) else {
            return RsurlCode::InvalidHandle;
        };
        let Some(url) = h.url.as_deref() else {
            return RsurlCode::InvalidArg;
        };
        let method = h.method.clone().unwrap_or_else(|| {
            if h.body.is_some() {
                "POST".to_string()
            } else {
                "GET".to_string()
            }
        });

        let mut req = match Request::new(&method, url) {
            Ok(r) => r,
            Err(crate::Error::UnsupportedScheme(_)) => return RsurlCode::Unsupported,
            Err(_) => return RsurlCode::InvalidArg,
        };
        req = req.idn(h.idn).verify_tls(h.verify_peer);
        if h.follow_location {
            req = req.follow_redirects(true);
            if let Some(n) = h.max_redirs {
                req = req.max_redirs(n);
            }
        }
        if let Some(spec) = &h.proxy {
            req = match req.proxy(spec) {
                Ok(r) => r,
                Err(_) => return RsurlCode::InvalidArg,
            };
        }
        if let Some((u, p)) = &h.basic_auth {
            req = req.basic_auth(u, p);
        }
        for (k, v) in &h.headers {
            req = req.header(k, v);
        }
        if let Some(ua) = &h.user_agent {
            req = req.header("User-Agent", ua);
        }
        if let Some(referer) = &h.referer {
            req = req.header("Referer", referer);
        }
        if let Some(cookie) = &h.cookie {
            req = req.header("Cookie", cookie);
        }
        if let Some(token) = &h.bearer {
            req = req.header("Authorization", &format!("Bearer {token}"));
        }
        if let Some(range) = &h.range {
            let v = if range.contains('=') {
                range.clone()
            } else {
                format!("bytes={range}")
            };
            req = req.header("Range", &v);
        }
        if let Some(enc) = &h.accept_encoding {
            // curl: an empty string means "every codec I can decode".
            let v = if enc.is_empty() {
                "gzip, deflate, br, zstd"
            } else {
                enc.as_str()
            };
            req = req.header("Accept-Encoding", v);
        }
        if let Some(body) = h.body.clone() {
            req = req.body(body);
        }

        match req.send() {
            Ok(resp) => {
                h.header_buf = resp
                    .headers
                    .iter()
                    .map(|(k, v)| {
                        let mut s = format!("{k}: {v}").into_bytes();
                        s.push(0);
                        s
                    })
                    .collect();
                h.last_response = Some(resp);
                RsurlCode::Ok
            }
            Err(crate::Error::UnsupportedScheme(_)) => RsurlCode::Unsupported,
            Err(crate::Error::Io(_)) | Err(crate::Error::UnexpectedEof) => RsurlCode::Network,
            Err(crate::Error::BadResponse(_))
            | Err(crate::Error::H2NotNegotiated)
            // `Ssh`, `Decode`, and `Status` cannot arise from this HTTP
            // `req.send()` path (the latter two are Response-method
            // conveniences), but the match must be exhaustive; treat them all
            // as a protocol/bad-response.
            | Err(crate::Error::Ssh(_))
            | Err(crate::Error::Decode(_))
            | Err(crate::Error::Status { .. }) => RsurlCode::BadResponse,
            Err(crate::Error::InvalidUrl(_)) => RsurlCode::InvalidArg,
        }
    })
}

/// Borrow a pointer to the response body and its length. The returned pointer
/// is **owned by the handle** and remains valid only until the next
/// `rsurl_easy_perform`, `rsurl_easy_reset`, or `rsurl_easy_cleanup` on this
/// handle; holding it across any of those calls is a use-after-free.
/// `out_ptr` is set to NULL and `out_len` to 0 if no response is available
/// (the call still returns `Ok` in that case, not `NoResponse`).
///
/// The returned buffer is **raw response bytes plus a length**; it is **not**
/// NUL-terminated and may contain embedded NUL bytes. C callers must use the
/// `*out_len` value and must **not** pass `*out_ptr` to `strlen`, `printf`,
/// or any function that treats it as a NUL-terminated C string.
///
/// # Safety
///
/// `handle` must be a pointer returned by [`rsurl_easy_init`] and not yet
/// freed by [`rsurl_easy_cleanup`]. `out_ptr` and `out_len` must be non-null
/// and point to writable storage of the appropriate type. The borrowed
/// `*out_ptr` must not be used after the next perform/reset/cleanup on
/// `handle`.
#[no_mangle]
pub unsafe extern "C" fn rsurl_easy_response_body(
    handle: *const RSURL,
    out_ptr: *mut *const u8,
    out_len: *mut usize,
) -> RsurlCode {
    ffi_guard(RsurlCode::Network, || {
        let Some(h) = handle_ref(handle) else {
            return RsurlCode::InvalidHandle;
        };
        if out_ptr.is_null() || out_len.is_null() {
            return RsurlCode::InvalidArg;
        }
        match &h.last_response {
            Some(resp) => unsafe {
                *out_ptr = resp.body.as_ptr();
                *out_len = resp.body.len();
            },
            None => unsafe {
                *out_ptr = ptr::null();
                *out_len = 0;
            },
        }
        RsurlCode::Ok
    })
}

/// Return the response HTTP status code, or 0 if no response is available.
#[no_mangle]
pub extern "C" fn rsurl_easy_response_status(handle: *const RSURL) -> c_long {
    ffi_guard(0, || {
        handle_ref(handle)
            .and_then(|h| h.last_response.as_ref())
            .map(|r| r.status as c_long)
            .unwrap_or(0)
    })
}

/// Borrow a pointer to a NUL-terminated `"Name: value"` header line by index.
/// Returns NULL if `index` is out of range or no response is available.
///
/// The returned pointer is **owned by the handle** (it borrows into the
/// handle's internal header storage) and is invalidated by the next
/// `rsurl_easy_perform`, `rsurl_easy_reset`, or `rsurl_easy_cleanup` on this
/// handle. Holding it across any of those calls — or dereferencing it after
/// the handle is freed — is a use-after-free. Copy the bytes out if you need
/// them to outlive the next operation.
///
/// # Safety
///
/// `handle` must be a pointer returned by [`rsurl_easy_init`] and not yet
/// freed by [`rsurl_easy_cleanup`]. The returned pointer must not be freed by
/// the caller and must not be used after the next perform/reset/cleanup on
/// `handle`.
#[no_mangle]
pub extern "C" fn rsurl_easy_response_header(handle: *const RSURL, index: usize) -> *const c_char {
    ffi_guard(ptr::null(), || {
        let Some(h) = handle_ref(handle) else {
            return ptr::null();
        };
        h.header_buf
            .get(index)
            .map(|b| b.as_ptr() as *const c_char)
            .unwrap_or(ptr::null())
    })
}

/// Return the number of response headers available.
#[no_mangle]
pub extern "C" fn rsurl_easy_response_header_count(handle: *const RSURL) -> usize {
    ffi_guard(0, || {
        handle_ref(handle).map(|h| h.header_buf.len()).unwrap_or(0)
    })
}

/// Return a static, NUL-terminated human-readable string for a status code.
#[no_mangle]
pub extern "C" fn rsurl_strerror(code: c_int) -> *const c_char {
    ffi_guard(ptr::null(), || {
        let s: &'static [u8] = match code {
            0 => b"ok\0",
            1 => b"invalid handle\0",
            2 => b"unknown option\0",
            3 => b"invalid argument\0",
            4 => b"no response available\0",
            5 => b"network error\0",
            6 => b"bad response\0",
            7 => b"unsupported scheme or feature\0",
            _ => b"unknown error\0",
        };
        s.as_ptr() as *const c_char
    })
}

/// Return the rsurl version as a NUL-terminated string.
#[no_mangle]
pub extern "C" fn rsurl_version() -> *const c_char {
    ffi_guard(ptr::null(), || {
        concat!("rsurl/", env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
    })
}

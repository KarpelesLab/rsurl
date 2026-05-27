//! C ABI for curlrs.
//!
//! A deliberately minimal, libcurl-shaped "easy" API. Function names use a
//! `curlrs_` prefix (not `curl_`) so this can be linked alongside libcurl
//! without symbol clashes, while still being familiar to anyone who has
//! used libcurl before.
//!
//! Lifecycle:
//!
//! ```c
//! CURLRS *h = curlrs_easy_init();
//! curlrs_easy_setopt(h, CURLRSOPT_URL, "http://example.com");
//! curlrs_easy_perform(h);
//! const uint8_t *body; size_t len;
//! curlrs_easy_response_body(h, &body, &len);
//! curlrs_easy_cleanup(h);
//! ```
//!
//! All pointer parameters except `handle` may be NULL where stated. Returned
//! pointers from `curlrs_easy_response_*` borrow from the handle and become
//! invalid on the next `curlrs_easy_perform` or `curlrs_easy_cleanup`.

#![allow(non_camel_case_types)]

use std::ffi::{c_char, c_int, c_long, CStr};
use std::ptr;

use crate::http::{Request, Response};

/// Opaque handle. Never dereferenced from C.
pub enum CURLRS {}

/// Option codes accepted by `curlrs_easy_setopt`.
#[repr(C)]
pub enum CurlrsOpt {
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
}

/// Status codes returned by the API.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CurlrsCode {
    Ok = 0,
    InvalidHandle = 1,
    UnknownOption = 2,
    InvalidArg = 3,
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
            last_response: None,
            header_buf: Vec::new(),
        }
    }
}

fn handle_mut<'a>(h: *mut CURLRS) -> Option<&'a mut Handle> {
    if h.is_null() {
        return None;
    }
    // SAFETY: handles are always created from Box::into_raw of a Handle.
    Some(unsafe { &mut *(h as *mut Handle) })
}

fn handle_ref<'a>(h: *const CURLRS) -> Option<&'a Handle> {
    if h.is_null() {
        return None;
    }
    // SAFETY: handles are always created from Box::into_raw of a Handle.
    Some(unsafe { &*(h as *const Handle) })
}

/// Allocate a new easy handle. Returns NULL on allocation failure (practically
/// never on this platform). Free with `curlrs_easy_cleanup`.
#[no_mangle]
pub extern "C" fn curlrs_easy_init() -> *mut CURLRS {
    let boxed = Box::new(Handle::new());
    Box::into_raw(boxed) as *mut CURLRS
}

/// Free an easy handle. NULL is a no-op.
#[no_mangle]
pub extern "C" fn curlrs_easy_cleanup(handle: *mut CURLRS) {
    if handle.is_null() {
        return;
    }
    // SAFETY: handle came from curlrs_easy_init's Box::into_raw.
    unsafe {
        drop(Box::from_raw(handle as *mut Handle));
    }
}

/// Reset all options on a handle but keep it allocated. Clears any previous
/// response data.
#[no_mangle]
pub extern "C" fn curlrs_easy_reset(handle: *mut CURLRS) -> CurlrsCode {
    let Some(h) = handle_mut(handle) else {
        return CurlrsCode::InvalidHandle;
    };
    *h = Handle::new();
    CurlrsCode::Ok
}

/// Set an option taking a NUL-terminated `const char*`.
///
/// Pass NULL to clear/unset that option. The string is copied into the handle.
///
/// # Safety
///
/// `handle` must be a pointer returned by [`curlrs_easy_init`] and not yet
/// freed by [`curlrs_easy_cleanup`]. `value`, if non-null, must point to a
/// valid NUL-terminated C string for the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn curlrs_easy_setopt_str(
    handle: *mut CURLRS,
    option: c_int,
    value: *const c_char,
) -> CurlrsCode {
    let Some(h) = handle_mut(handle) else {
        return CurlrsCode::InvalidHandle;
    };
    let s = if value.is_null() {
        None
    } else {
        // SAFETY: caller asserts value is a valid NUL-terminated C string.
        match unsafe { CStr::from_ptr(value) }.to_str() {
            Ok(s) => Some(s.to_string()),
            Err(_) => return CurlrsCode::InvalidArg,
        }
    };
    let Some(opt) = opt_from_int(option) else {
        return CurlrsCode::UnknownOption;
    };
    match opt {
        CurlrsOpt::Url => h.url = s,
        CurlrsOpt::CustomRequest => h.method = s,
        CurlrsOpt::UserAgent => h.user_agent = s,
        CurlrsOpt::Header => match s {
            Some(line) => {
                let Some((k, v)) = line.split_once(':') else {
                    return CurlrsCode::InvalidArg;
                };
                h.headers.push((k.trim().to_string(), v.trim().to_string()));
            }
            None => h.headers.clear(),
        },
        CurlrsOpt::PostFieldsString => h.body = s.map(|s| s.into_bytes()),
        CurlrsOpt::ConnectTimeout | CurlrsOpt::Timeout => return CurlrsCode::InvalidArg,
    }
    CurlrsCode::Ok
}

/// Set an option taking a `long` (e.g. timeouts).
#[no_mangle]
pub extern "C" fn curlrs_easy_setopt_long(
    handle: *mut CURLRS,
    option: c_int,
    value: c_long,
) -> CurlrsCode {
    let Some(h) = handle_mut(handle) else {
        return CurlrsCode::InvalidHandle;
    };
    let Some(opt) = opt_from_int(option) else {
        return CurlrsCode::UnknownOption;
    };
    let secs = if value <= 0 { None } else { Some(value as u64) };
    match opt {
        CurlrsOpt::ConnectTimeout => h.connect_timeout_secs = secs,
        CurlrsOpt::Timeout => h.timeout_secs = secs,
        _ => return CurlrsCode::InvalidArg,
    }
    CurlrsCode::Ok
}

fn opt_from_int(v: c_int) -> Option<CurlrsOpt> {
    Some(match v {
        1 => CurlrsOpt::Url,
        2 => CurlrsOpt::CustomRequest,
        3 => CurlrsOpt::Header,
        4 => CurlrsOpt::PostFieldsString,
        5 => CurlrsOpt::ConnectTimeout,
        6 => CurlrsOpt::Timeout,
        7 => CurlrsOpt::UserAgent,
        _ => return None,
    })
}

/// Execute the request configured on the handle. Replaces any previous
/// response stored on the handle.
#[no_mangle]
pub extern "C" fn curlrs_easy_perform(handle: *mut CURLRS) -> CurlrsCode {
    let Some(h) = handle_mut(handle) else {
        return CurlrsCode::InvalidHandle;
    };
    let Some(url) = h.url.as_deref() else {
        return CurlrsCode::InvalidArg;
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
        Err(crate::Error::UnsupportedScheme(_)) => return CurlrsCode::Unsupported,
        Err(_) => return CurlrsCode::InvalidArg,
    };
    for (k, v) in &h.headers {
        req = req.header(k, v);
    }
    if let Some(ua) = &h.user_agent {
        req = req.header("User-Agent", ua);
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
            CurlrsCode::Ok
        }
        Err(crate::Error::UnsupportedScheme(_)) => CurlrsCode::Unsupported,
        Err(crate::Error::Io(_)) | Err(crate::Error::UnexpectedEof) => CurlrsCode::Network,
        Err(crate::Error::BadResponse(_)) | Err(crate::Error::H2NotNegotiated) => {
            CurlrsCode::BadResponse
        }
        Err(crate::Error::InvalidUrl(_)) => CurlrsCode::InvalidArg,
    }
}

/// Borrow a pointer to the response body and its length. Pointer remains
/// valid until the next perform/reset/cleanup. `out_ptr` is set to NULL and
/// `out_len` to 0 if no response is available.
///
/// # Safety
///
/// `handle` must be a pointer returned by [`curlrs_easy_init`] and not yet
/// freed by [`curlrs_easy_cleanup`]. `out_ptr` and `out_len` must be non-null
/// and point to writable storage of the appropriate type.
#[no_mangle]
pub unsafe extern "C" fn curlrs_easy_response_body(
    handle: *const CURLRS,
    out_ptr: *mut *const u8,
    out_len: *mut usize,
) -> CurlrsCode {
    let Some(h) = handle_ref(handle) else {
        return CurlrsCode::InvalidHandle;
    };
    if out_ptr.is_null() || out_len.is_null() {
        return CurlrsCode::InvalidArg;
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
    CurlrsCode::Ok
}

/// Return the response HTTP status code, or 0 if no response is available.
#[no_mangle]
pub extern "C" fn curlrs_easy_response_status(handle: *const CURLRS) -> c_long {
    handle_ref(handle)
        .and_then(|h| h.last_response.as_ref())
        .map(|r| r.status as c_long)
        .unwrap_or(0)
}

/// Borrow a pointer to a NUL-terminated `"Name: value"` header line by index.
/// Returns NULL if `index` is out of range or no response is available.
#[no_mangle]
pub extern "C" fn curlrs_easy_response_header(
    handle: *const CURLRS,
    index: usize,
) -> *const c_char {
    let Some(h) = handle_ref(handle) else {
        return ptr::null();
    };
    h.header_buf
        .get(index)
        .map(|b| b.as_ptr() as *const c_char)
        .unwrap_or(ptr::null())
}

/// Return the number of response headers available.
#[no_mangle]
pub extern "C" fn curlrs_easy_response_header_count(handle: *const CURLRS) -> usize {
    handle_ref(handle).map(|h| h.header_buf.len()).unwrap_or(0)
}

/// Return a static, NUL-terminated human-readable string for a status code.
#[no_mangle]
pub extern "C" fn curlrs_strerror(code: c_int) -> *const c_char {
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
}

/// Return the curlrs version as a NUL-terminated string.
#[no_mangle]
pub extern "C" fn curlrs_version() -> *const c_char {
    concat!("curlrs/", env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

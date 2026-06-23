//! libcurl-ABI compatibility layer for rsurl.
//!
//! This crate exposes libcurl's public C symbols (`curl_*`), constants, and
//! `curl/curl.h`, implemented on top of the pure-Rust `rsurl` crate, so a
//! program written for libcurl can link (and, with the SONAME + version script
//! the build sets on ELF, dynamically load) against rsurl instead.
//!
//! It is an **independent reimplementation** built solely from libcurl's
//! publicly documented API and the well-known public ABI constant values — no
//! libcurl source or headers were consulted.
//!
//! Scope is the easy + multi interfaces over HTTP(S); see the README for the
//! covered options and the known limitations (symbol-version node, 64-bit-Unix
//! varargs ABI, and the option/info subset).
//!
//! Thread-safety follows libcurl's contract: an easy handle is single-threaded;
//! distinct handles may be used from distinct threads.

#![allow(non_camel_case_types)]
#![allow(clippy::missing_safety_doc)]

mod consts;
mod easy;
mod multi;
mod version;

pub use consts::*;
pub use version::{curl_version, curl_version_info, curl_version_info_data};

use std::alloc::{alloc, dealloc, Layout};
use std::ffi::{c_void, CStr, CString};
use std::os::raw::{c_char, c_int, c_long};
use std::panic::{self, AssertUnwindSafe};
use std::ptr;

/// Opaque easy handle (`CURL *`). Never dereferenced from C.
pub enum CURL {}
/// Opaque multi handle (`CURLM *`).
pub enum CURLM {}
/// Opaque share handle (`CURLSH *`); minimally supported.
pub enum CURLSH {}

/// Unwind barrier: a Rust panic must not cross the `extern "C"` boundary.
/// Mirrors `rsurl`'s own `ffi_guard`.
pub(crate) fn ffi_guard<T>(default: T, f: impl FnOnce() -> T) -> T {
    panic::catch_unwind(AssertUnwindSafe(f)).unwrap_or(default)
}

// ---------------------------------------------------------------------------
// Allocator for buffers handed to C that the caller frees with `curl_free`
// (curl_easy_escape / curl_easy_unescape). We size-prefix each allocation so
// `curl_free` can reclaim it from just the pointer, mirroring malloc/free.
// ---------------------------------------------------------------------------

const ALLOC_HDR: usize = 16; // keeps 16-byte payload alignment; stores the size

unsafe fn c_alloc(len: usize) -> *mut u8 {
    let Some(total) = len.checked_add(ALLOC_HDR) else {
        return ptr::null_mut();
    };
    let Ok(layout) = Layout::from_size_align(total, 16) else {
        return ptr::null_mut();
    };
    let base = alloc(layout);
    if base.is_null() {
        return ptr::null_mut();
    }
    (base as *mut usize).write(total);
    base.add(ALLOC_HDR)
}

unsafe fn c_free_raw(p: *mut u8) {
    if p.is_null() {
        return;
    }
    let base = p.sub(ALLOC_HDR);
    let total = (base as *mut usize).read();
    if let Ok(layout) = Layout::from_size_align(total, 16) {
        dealloc(base, layout);
    }
}

/// Copy `bytes` into a `curl_free`-able, NUL-terminated buffer. Returns NULL on
/// allocation failure.
unsafe fn c_dup(bytes: &[u8]) -> *mut c_char {
    let p = c_alloc(bytes.len() + 1);
    if p.is_null() {
        return ptr::null_mut();
    }
    ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len());
    *p.add(bytes.len()) = 0;
    p as *mut c_char
}

/// `void curl_free(void *p)` — free a buffer libcurl returned (escape/unescape).
#[no_mangle]
pub unsafe extern "C" fn curl_free(p: *mut c_void) {
    ffi_guard((), || c_free_raw(p as *mut u8));
}

// ---------------------------------------------------------------------------
// Global init / cleanup (no global state to manage; succeed).
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn curl_global_init(_flags: c_long) -> CURLcode {
    CURLE_OK
}

#[no_mangle]
pub extern "C" fn curl_global_init_mem(
    _flags: c_long,
    _m: *mut c_void,
    _f: *mut c_void,
    _r: *mut c_void,
    _c: *mut c_void,
    _rd: *mut c_void,
) -> CURLcode {
    // Custom allocators are ignored; we use Rust's allocator throughout.
    CURLE_OK
}

#[no_mangle]
pub extern "C" fn curl_global_cleanup() {}

// ---------------------------------------------------------------------------
// curl_slist
// ---------------------------------------------------------------------------

/// `struct curl_slist { char *data; struct curl_slist *next; }`.
#[repr(C)]
pub struct curl_slist {
    pub data: *mut c_char,
    pub next: *mut curl_slist,
}

/// `curl_slist *curl_slist_append(curl_slist *list, const char *string)`.
#[no_mangle]
pub unsafe extern "C" fn curl_slist_append(
    list: *mut curl_slist,
    string: *const c_char,
) -> *mut curl_slist {
    ffi_guard(ptr::null_mut(), || {
        if string.is_null() {
            return list;
        }
        // Duplicate the string with Rust's allocator (freed in free_all).
        let bytes = CStr::from_ptr(string).to_bytes();
        let Ok(data) = CString::new(bytes) else {
            return list; // interior NUL — reject, matching libcurl's strdup
        };
        let node = Box::into_raw(Box::new(curl_slist {
            data: data.into_raw(),
            next: ptr::null_mut(),
        }));
        if list.is_null() {
            return node;
        }
        // Append at the tail.
        let mut tail = list;
        while !(*tail).next.is_null() {
            tail = (*tail).next;
        }
        (*tail).next = node;
        list
    })
}

/// `void curl_slist_free_all(curl_slist *list)`.
#[no_mangle]
pub unsafe extern "C" fn curl_slist_free_all(list: *mut curl_slist) {
    ffi_guard((), || {
        let mut cur = list;
        while !cur.is_null() {
            let node = Box::from_raw(cur);
            if !node.data.is_null() {
                drop(CString::from_raw(node.data));
            }
            cur = node.next;
        }
    });
}

// ---------------------------------------------------------------------------
// strerror family
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn curl_easy_strerror(code: CURLcode) -> *const c_char {
    let s: &CStr = match code {
        CURLE_OK => c"No error",
        CURLE_UNSUPPORTED_PROTOCOL => c"Unsupported protocol",
        CURLE_FAILED_INIT => c"Failed initialization",
        CURLE_URL_MALFORMAT => c"URL using bad/illegal format or missing URL",
        CURLE_NOT_BUILT_IN => c"A requested feature, option or value was not built in",
        CURLE_COULDNT_RESOLVE_PROXY => c"Couldn't resolve proxy name",
        CURLE_COULDNT_RESOLVE_HOST => c"Couldn't resolve host name",
        CURLE_COULDNT_CONNECT => c"Couldn't connect to server",
        CURLE_WEIRD_SERVER_REPLY => c"Weird server reply",
        CURLE_REMOTE_ACCESS_DENIED => c"Access denied to remote resource",
        CURLE_HTTP2 => c"HTTP/2 error",
        CURLE_HTTP_RETURNED_ERROR => c"HTTP response code said error",
        CURLE_WRITE_ERROR => c"Failed writing received data to disk/application",
        CURLE_UPLOAD_FAILED => c"Upload failed",
        CURLE_READ_ERROR => c"Failed to open/read local data from file/application",
        CURLE_OUT_OF_MEMORY => c"Out of memory",
        CURLE_OPERATION_TIMEDOUT => c"Timeout was reached",
        CURLE_RANGE_ERROR => c"Requested range was not delivered by the server",
        CURLE_SSL_CONNECT_ERROR => c"SSL connect error",
        CURLE_ABORTED_BY_CALLBACK => c"Operation was aborted by an application callback",
        CURLE_BAD_FUNCTION_ARGUMENT => c"A libcurl function was given a bad argument",
        CURLE_TOO_MANY_REDIRECTS => c"Number of redirects hit maximum amount",
        CURLE_UNKNOWN_OPTION => c"An unknown option was passed in to libcurl",
        CURLE_GOT_NOTHING => c"Server returned nothing (no headers, no data)",
        CURLE_SEND_ERROR => c"Failed sending data to the peer",
        CURLE_RECV_ERROR => c"Failure when receiving data from the peer",
        CURLE_SSL_CERTPROBLEM => c"Problem with the local SSL certificate",
        CURLE_PEER_FAILED_VERIFICATION => c"SSL peer certificate or SSH remote key was not OK",
        CURLE_BAD_CONTENT_ENCODING => c"Unrecognized or bad HTTP Content or Transfer-Encoding",
        CURLE_FILESIZE_EXCEEDED => c"Maximum file size exceeded",
        CURLE_SSL_CACERT_BADFILE => c"Could not load CACERT file, missing or wrong format",
        CURLE_AGAIN => c"Socket not ready for send/recv",
        _ => c"Unknown error",
    };
    s.as_ptr()
}

#[no_mangle]
pub extern "C" fn curl_multi_strerror(code: CURLMcode) -> *const c_char {
    let s: &CStr = match code {
        CURLM_CALL_MULTI_PERFORM => c"Please call curl_multi_perform() soon",
        CURLM_OK => c"No error",
        CURLM_BAD_HANDLE => c"Invalid multi handle",
        CURLM_BAD_EASY_HANDLE => c"Invalid easy handle",
        CURLM_OUT_OF_MEMORY => c"Out of memory",
        CURLM_INTERNAL_ERROR => c"Internal error",
        CURLM_BAD_SOCKET => c"Invalid socket argument",
        CURLM_UNKNOWN_OPTION => c"Unknown option",
        CURLM_ADDED_ALREADY => c"The easy handle is already added to a multi handle",
        _ => c"Unknown error",
    };
    s.as_ptr()
}

#[no_mangle]
pub extern "C" fn curl_share_strerror(_code: c_int) -> *const c_char {
    c"No error".as_ptr()
}

// ---------------------------------------------------------------------------
// curl_easy_escape / curl_easy_unescape (RFC 3986 percent-coding)
// ---------------------------------------------------------------------------

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// `char *curl_easy_escape(CURL *handle, const char *string, int length)`.
/// `length == 0` means strlen. Result is `curl_free`-able.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_escape(
    _handle: *mut CURL,
    string: *const c_char,
    length: c_int,
) -> *mut c_char {
    ffi_guard(ptr::null_mut(), || {
        if string.is_null() {
            return ptr::null_mut();
        }
        let input: &[u8] = if length > 0 {
            std::slice::from_raw_parts(string as *const u8, length as usize)
        } else {
            CStr::from_ptr(string).to_bytes()
        };
        // Worst case is 3 bytes out per input byte; an absurd caller-supplied
        // length must not overflow the capacity into a too-small allocation.
        let Some(cap) = input.len().checked_mul(3) else {
            return ptr::null_mut();
        };
        let mut out = Vec::with_capacity(cap);
        for &b in input {
            if is_unreserved(b) {
                out.push(b);
            } else {
                out.push(b'%');
                out.push(hex_upper(b >> 4));
                out.push(hex_upper(b & 0x0f));
            }
        }
        c_dup(&out)
    })
}

/// `char *curl_easy_unescape(CURL *handle, const char *string, int length, int *outlength)`.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_unescape(
    _handle: *mut CURL,
    string: *const c_char,
    length: c_int,
    outlength: *mut c_int,
) -> *mut c_char {
    ffi_guard(ptr::null_mut(), || {
        if string.is_null() {
            return ptr::null_mut();
        }
        let input: &[u8] = if length > 0 {
            std::slice::from_raw_parts(string as *const u8, length as usize)
        } else {
            CStr::from_ptr(string).to_bytes()
        };
        let mut out = Vec::with_capacity(input.len());
        let mut i = 0;
        while i < input.len() {
            if input[i] == b'%' && i + 2 < input.len() {
                if let (Some(h), Some(l)) = (unhex(input[i + 1]), unhex(input[i + 2])) {
                    out.push((h << 4) | l);
                    i += 3;
                    continue;
                }
            }
            out.push(input[i]);
            i += 1;
        }
        if !outlength.is_null() {
            *outlength = out.len() as c_int;
        }
        c_dup(&out)
    })
}

fn hex_upper(n: u8) -> u8 {
    match n {
        0..=9 => b'0' + n,
        _ => b'A' + (n - 10),
    }
}

fn unhex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

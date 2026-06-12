//! `curl_version` / `curl_version_info` — version reporting.

use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_long, c_uint};
use std::ptr;
use std::sync::OnceLock;

use crate::consts::*;

/// Public `curl_version_info_data` layout (the age-0 prefix, which is the only
/// part we advertise via `age = 0`). Field order/types match the documented
/// public struct so a caller reading the age-0 fields sees correct values.
/// Later-`age` fields are intentionally omitted; we report `age = CURLVERSION_FIRST`.
#[repr(C)]
pub struct curl_version_info_data {
    pub age: c_int,
    pub version: *const c_char,
    pub version_num: c_uint,
    pub host: *const c_char,
    pub features: c_int,
    pub ssl_version: *const c_char,
    pub ssl_version_num: c_long,
    pub libz_version: *const c_char,
    /// NULL-terminated array of supported protocol scheme names.
    pub protocols: *const *const c_char,
}

/// Pointer wrapper so the cached address can live in a `OnceLock` (the raw
/// pointers it holds reference `'static` / leaked data and are never mutated).
struct VersionPtr(usize);
unsafe impl Send for VersionPtr {}
unsafe impl Sync for VersionPtr {}

/// `char *curl_version(void)` — a human-readable version string.
#[no_mangle]
pub extern "C" fn curl_version() -> *const c_char {
    REPORTED_VERSION.as_ptr()
}

/// `curl_version_info_data *curl_version_info(CURLversion age)`.
///
/// Returns a pointer to a process-lifetime structure (built once). We report
/// `age = 0`, so callers should only read the age-0 fields.
#[no_mangle]
pub extern "C" fn curl_version_info(_age: c_int) -> *const curl_version_info_data {
    static DATA: OnceLock<VersionPtr> = OnceLock::new();
    let p = DATA.get_or_init(|| {
        // Scheme names rsurl can actually drive. `CStr::as_ptr()` points into
        // the binary's read-only data and lives for the whole process.
        let protos: &'static [&'static CStr] =
            &[c"http", c"https", c"ftp", c"ftps", c"ws", c"wss", c"file"];
        let mut vec: Vec<*const c_char> = protos.iter().map(|s| s.as_ptr()).collect();
        vec.push(ptr::null());
        let protocols = Box::leak(vec.into_boxed_slice());

        let data = curl_version_info_data {
            age: 0, // CURLVERSION_FIRST
            version: REPORTED_VERSION.as_ptr(),
            version_num: REPORTED_VERSION_NUM,
            host: c"rust".as_ptr(),
            features: CURL_VERSION_SSL | CURL_VERSION_LIBZ | CURL_VERSION_HTTP2,
            ssl_version: c"purecrypto".as_ptr(),
            ssl_version_num: 0,
            libz_version: c"compcol".as_ptr(),
            protocols: protocols.as_ptr(),
        };
        VersionPtr(Box::into_raw(Box::new(data)) as usize)
    });
    p.0 as *const curl_version_info_data
}

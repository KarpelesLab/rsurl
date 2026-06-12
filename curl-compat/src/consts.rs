//! libcurl public ABI constants, reconstructed from the documented public API
//! (curl.se man pages) — NOT copied from libcurl source. These integer values
//! are the interoperability interface a drop-in must match.

#![allow(non_upper_case_globals)]

use std::os::raw::c_int;

/// `CURLcode` — easy-interface result codes (subset; the common ones).
pub type CURLcode = c_int;

pub const CURLE_OK: CURLcode = 0;
pub const CURLE_UNSUPPORTED_PROTOCOL: CURLcode = 1;
pub const CURLE_FAILED_INIT: CURLcode = 2;
pub const CURLE_URL_MALFORMAT: CURLcode = 3;
pub const CURLE_NOT_BUILT_IN: CURLcode = 4;
pub const CURLE_COULDNT_RESOLVE_PROXY: CURLcode = 5;
pub const CURLE_COULDNT_RESOLVE_HOST: CURLcode = 6;
pub const CURLE_COULDNT_CONNECT: CURLcode = 7;
pub const CURLE_WEIRD_SERVER_REPLY: CURLcode = 8;
pub const CURLE_REMOTE_ACCESS_DENIED: CURLcode = 9;
pub const CURLE_HTTP2: CURLcode = 16;
pub const CURLE_HTTP_RETURNED_ERROR: CURLcode = 22;
pub const CURLE_WRITE_ERROR: CURLcode = 23;
pub const CURLE_UPLOAD_FAILED: CURLcode = 25;
pub const CURLE_READ_ERROR: CURLcode = 26;
pub const CURLE_OUT_OF_MEMORY: CURLcode = 27;
pub const CURLE_OPERATION_TIMEDOUT: CURLcode = 28;
pub const CURLE_RANGE_ERROR: CURLcode = 33;
pub const CURLE_SSL_CONNECT_ERROR: CURLcode = 35;
pub const CURLE_BAD_DOWNLOAD_RESUME: CURLcode = 36;
pub const CURLE_ABORTED_BY_CALLBACK: CURLcode = 42;
pub const CURLE_BAD_FUNCTION_ARGUMENT: CURLcode = 43;
pub const CURLE_TOO_MANY_REDIRECTS: CURLcode = 47;
pub const CURLE_UNKNOWN_OPTION: CURLcode = 48;
pub const CURLE_GOT_NOTHING: CURLcode = 52;
pub const CURLE_SEND_ERROR: CURLcode = 55;
pub const CURLE_RECV_ERROR: CURLcode = 56;
pub const CURLE_SSL_CERTPROBLEM: CURLcode = 58;
pub const CURLE_PEER_FAILED_VERIFICATION: CURLcode = 60;
pub const CURLE_BAD_CONTENT_ENCODING: CURLcode = 61;
pub const CURLE_FILESIZE_EXCEEDED: CURLcode = 63;
pub const CURLE_SSL_CACERT_BADFILE: CURLcode = 77;
pub const CURLE_AGAIN: CURLcode = 81;

/// `CURLMcode` — multi-interface result codes.
pub type CURLMcode = c_int;

pub const CURLM_CALL_MULTI_PERFORM: CURLMcode = -1;
pub const CURLM_OK: CURLMcode = 0;
pub const CURLM_BAD_HANDLE: CURLMcode = 1;
pub const CURLM_BAD_EASY_HANDLE: CURLMcode = 2;
pub const CURLM_OUT_OF_MEMORY: CURLMcode = 3;
pub const CURLM_INTERNAL_ERROR: CURLMcode = 4;
pub const CURLM_BAD_SOCKET: CURLMcode = 5;
pub const CURLM_UNKNOWN_OPTION: CURLMcode = 6;
pub const CURLM_ADDED_ALREADY: CURLMcode = 7;

/// `curl_global_init` flags.
pub const CURL_GLOBAL_NOTHING: std::os::raw::c_long = 0;
pub const CURL_GLOBAL_SSL: std::os::raw::c_long = 1 << 0;
pub const CURL_GLOBAL_WIN32: std::os::raw::c_long = 1 << 1;
pub const CURL_GLOBAL_ALL: std::os::raw::c_long = CURL_GLOBAL_SSL | CURL_GLOBAL_WIN32;
pub const CURL_GLOBAL_DEFAULT: std::os::raw::c_long = CURL_GLOBAL_ALL;

/// `curl_version_info` feature bits (the ones we report).
pub const CURL_VERSION_SSL: c_int = 1 << 2;
pub const CURL_VERSION_LIBZ: c_int = 1 << 3;
pub const CURL_VERSION_HTTP2: c_int = 1 << 16;

/// The libcurl version we report (so programs that string-match `libcurl/` or
/// check a minimum version are satisfied). `version_num` is `0xMMNNPP`.
pub const REPORTED_VERSION: &std::ffi::CStr = c"libcurl/8.4.0 rsurl/0.0.6";
pub const REPORTED_VERSION_NUM: std::os::raw::c_uint = 0x08_04_00;

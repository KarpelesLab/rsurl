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

// ---------------------------------------------------------------------------
// CURLoption — `value = type_base + ordinal`. The base encodes the argument
// type, which is how `curl_easy_setopt` reinterprets its variadic third arg.
// ---------------------------------------------------------------------------

pub const CURLOPTTYPE_LONG: c_int = 0;
pub const CURLOPTTYPE_OBJECTPOINT: c_int = 10000; // also STRINGPOINT / SLISTPOINT / CBPOINT
pub const CURLOPTTYPE_FUNCTIONPOINT: c_int = 20000;
pub const CURLOPTTYPE_OFF_T: c_int = 30000;
pub const CURLOPTTYPE_BLOB: c_int = 40000;

// LONG options
pub const CURLOPT_PORT: c_int = 3;
pub const CURLOPT_TIMEOUT: c_int = 13;
pub const CURLOPT_INFILESIZE: c_int = 14;
pub const CURLOPT_LOW_SPEED_LIMIT: c_int = 19;
pub const CURLOPT_LOW_SPEED_TIME: c_int = 20;
pub const CURLOPT_RESUME_FROM: c_int = 21;
pub const CURLOPT_CRLF: c_int = 27;
pub const CURLOPT_SSLVERSION: c_int = 32;
pub const CURLOPT_VERBOSE: c_int = 41;
pub const CURLOPT_HEADER: c_int = 42;
pub const CURLOPT_NOPROGRESS: c_int = 43;
pub const CURLOPT_NOBODY: c_int = 44;
pub const CURLOPT_FAILONERROR: c_int = 45;
pub const CURLOPT_UPLOAD: c_int = 46;
pub const CURLOPT_POST: c_int = 47;
pub const CURLOPT_NETRC: c_int = 51;
pub const CURLOPT_FOLLOWLOCATION: c_int = 52;
pub const CURLOPT_PUT: c_int = 54;
pub const CURLOPT_AUTOREFERER: c_int = 58;
pub const CURLOPT_PROXYPORT: c_int = 59;
pub const CURLOPT_POSTFIELDSIZE: c_int = 60;
pub const CURLOPT_HTTPPROXYTUNNEL: c_int = 61;
pub const CURLOPT_SSL_VERIFYPEER: c_int = 64;
pub const CURLOPT_MAXREDIRS: c_int = 68;
pub const CURLOPT_FILETIME: c_int = 69;
pub const CURLOPT_MAXCONNECTS: c_int = 71;
pub const CURLOPT_FRESH_CONNECT: c_int = 74;
pub const CURLOPT_FORBID_REUSE: c_int = 75;
pub const CURLOPT_CONNECTTIMEOUT: c_int = 78;
pub const CURLOPT_HTTPGET: c_int = 80;
pub const CURLOPT_SSL_VERIFYHOST: c_int = 81;
pub const CURLOPT_HTTP_VERSION: c_int = 84;
pub const CURLOPT_COOKIESESSION: c_int = 96;
pub const CURLOPT_BUFFERSIZE: c_int = 98;
pub const CURLOPT_NOSIGNAL: c_int = 99;
pub const CURLOPT_PROXYTYPE: c_int = 101;
pub const CURLOPT_HTTPAUTH: c_int = 107;
pub const CURLOPT_PROXYAUTH: c_int = 111;
pub const CURLOPT_IPRESOLVE: c_int = 113;
pub const CURLOPT_MAXFILESIZE: c_int = 114;
pub const CURLOPT_TCP_NODELAY: c_int = 121;
pub const CURLOPT_TIMEOUT_MS: c_int = 155;
pub const CURLOPT_CONNECTTIMEOUT_MS: c_int = 156;
pub const CURLOPT_POSTREDIR: c_int = 161;
pub const CURLOPT_TCP_KEEPALIVE: c_int = 213;
pub const CURLOPT_SSL_OPTIONS: c_int = 216;
pub const CURLOPT_SSL_VERIFYSTATUS: c_int = 232;

// OBJECTPOINT / STRINGPOINT / SLISTPOINT options (base 10000)
pub const CURLOPT_WRITEDATA: c_int = 10001;
pub const CURLOPT_URL: c_int = 10002;
pub const CURLOPT_PROXY: c_int = 10004;
pub const CURLOPT_USERPWD: c_int = 10005;
pub const CURLOPT_PROXYUSERPWD: c_int = 10006;
pub const CURLOPT_RANGE: c_int = 10007;
pub const CURLOPT_READDATA: c_int = 10009;
pub const CURLOPT_ERRORBUFFER: c_int = 10010;
pub const CURLOPT_POSTFIELDS: c_int = 10015;
pub const CURLOPT_REFERER: c_int = 10016;
pub const CURLOPT_USERAGENT: c_int = 10018;
pub const CURLOPT_COOKIE: c_int = 10022;
pub const CURLOPT_HTTPHEADER: c_int = 10023;
pub const CURLOPT_SSLCERT: c_int = 10025;
pub const CURLOPT_KEYPASSWD: c_int = 10026;
pub const CURLOPT_HEADERDATA: c_int = 10029; // a.k.a. WRITEHEADER
pub const CURLOPT_COOKIEFILE: c_int = 10031;
pub const CURLOPT_CUSTOMREQUEST: c_int = 10036;
pub const CURLOPT_INTERFACE: c_int = 10062;
pub const CURLOPT_CAINFO: c_int = 10065;
pub const CURLOPT_COOKIEJAR: c_int = 10082;
pub const CURLOPT_SSL_CIPHER_LIST: c_int = 10083;
pub const CURLOPT_SSLCERTTYPE: c_int = 10086;
pub const CURLOPT_SSLKEY: c_int = 10087;
pub const CURLOPT_SSLKEYTYPE: c_int = 10088;
pub const CURLOPT_CAPATH: c_int = 10097;
pub const CURLOPT_ACCEPT_ENCODING: c_int = 10102;
pub const CURLOPT_PRIVATE: c_int = 10103;
pub const CURLOPT_COPYPOSTFIELDS: c_int = 10165;
pub const CURLOPT_CRLFILE: c_int = 10169;
pub const CURLOPT_USERNAME: c_int = 10173;
pub const CURLOPT_PASSWORD: c_int = 10174;
pub const CURLOPT_NOPROXY: c_int = 10177;
pub const CURLOPT_RESOLVE: c_int = 10203;
pub const CURLOPT_XOAUTH2_BEARER: c_int = 10220;
pub const CURLOPT_PINNEDPUBLICKEY: c_int = 10230;
pub const CURLOPT_UNIX_SOCKET_PATH: c_int = 10231;
pub const CURLOPT_DEFAULT_PROTOCOL: c_int = 10238;
pub const CURLOPT_CONNECT_TO: c_int = 10243;
pub const CURLOPT_TLS13_CIPHERS: c_int = 10277;

// FUNCTIONPOINT options (base 20000)
pub const CURLOPT_WRITEFUNCTION: c_int = 20011;
pub const CURLOPT_READFUNCTION: c_int = 20012;
pub const CURLOPT_PROGRESSFUNCTION: c_int = 20056;
pub const CURLOPT_HEADERFUNCTION: c_int = 20079;
pub const CURLOPT_DEBUGFUNCTION: c_int = 20094;
pub const CURLOPT_XFERINFOFUNCTION: c_int = 20219;

// OFF_T options (base 30000)
pub const CURLOPT_INFILESIZE_LARGE: c_int = 30115;
pub const CURLOPT_RESUME_FROM_LARGE: c_int = 30116;
pub const CURLOPT_MAXFILESIZE_LARGE: c_int = 30117;
pub const CURLOPT_POSTFIELDSIZE_LARGE: c_int = 30120;

// CURLOPT_HTTP_VERSION values
pub const CURL_HTTP_VERSION_NONE: c_long = 0;
pub const CURL_HTTP_VERSION_1_0: c_long = 1;
pub const CURL_HTTP_VERSION_1_1: c_long = 2;
pub const CURL_HTTP_VERSION_2_0: c_long = 3;
pub const CURL_HTTP_VERSION_2TLS: c_long = 4;
pub const CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE: c_long = 5;
pub const CURL_HTTP_VERSION_3: c_long = 30;
pub const CURL_HTTP_VERSION_3ONLY: c_long = 31;

// ---------------------------------------------------------------------------
// CURLINFO — `value = type_base + ordinal`. High bits encode the out-type.
// ---------------------------------------------------------------------------

pub const CURLINFO_STRING: c_int = 0x10_0000;
pub const CURLINFO_LONG: c_int = 0x20_0000;
pub const CURLINFO_DOUBLE: c_int = 0x30_0000;
pub const CURLINFO_SLIST: c_int = 0x40_0000;
pub const CURLINFO_OFF_T: c_int = 0x60_0000;

pub const CURLINFO_EFFECTIVE_URL: c_int = CURLINFO_STRING + 1;
pub const CURLINFO_CONTENT_TYPE: c_int = CURLINFO_STRING + 18;
pub const CURLINFO_PRIVATE: c_int = CURLINFO_STRING + 21;
pub const CURLINFO_REDIRECT_URL: c_int = CURLINFO_STRING + 31;
pub const CURLINFO_SCHEME: c_int = CURLINFO_STRING + 49;

pub const CURLINFO_RESPONSE_CODE: c_int = CURLINFO_LONG + 2;
pub const CURLINFO_HEADER_SIZE: c_int = CURLINFO_LONG + 11;
pub const CURLINFO_REDIRECT_COUNT: c_int = CURLINFO_LONG + 20;
pub const CURLINFO_HTTP_VERSION: c_int = CURLINFO_LONG + 46;

pub const CURLINFO_TOTAL_TIME: c_int = CURLINFO_DOUBLE + 3;
pub const CURLINFO_NAMELOOKUP_TIME: c_int = CURLINFO_DOUBLE + 4;
pub const CURLINFO_CONNECT_TIME: c_int = CURLINFO_DOUBLE + 5;
pub const CURLINFO_PRETRANSFER_TIME: c_int = CURLINFO_DOUBLE + 6;
pub const CURLINFO_SIZE_DOWNLOAD: c_int = CURLINFO_DOUBLE + 8;
pub const CURLINFO_STARTTRANSFER_TIME: c_int = CURLINFO_DOUBLE + 17;
pub const CURLINFO_APPCONNECT_TIME: c_int = CURLINFO_DOUBLE + 33;

pub const CURLINFO_SIZE_DOWNLOAD_T: c_int = CURLINFO_OFF_T + 8;
pub const CURLINFO_CONNECT_TIME_T: c_int = CURLINFO_OFF_T + 48;
pub const CURLINFO_STARTTRANSFER_TIME_T: c_int = CURLINFO_OFF_T + 49;
pub const CURLINFO_TOTAL_TIME_T: c_int = CURLINFO_OFF_T + 50;

// CURLAUTH bitmask (for HTTPAUTH); we recognize BASIC and DIGEST.
pub const CURLAUTH_BASIC: c_long = 1 << 0;
pub const CURLAUTH_DIGEST: c_long = 1 << 1;

use std::os::raw::c_long;

/*
 * rsurl.h — C ABI for the rsurl pure-Rust HTTP client.
 *
 * Copyright (c) 2026 Karpelès Lab Inc. — MIT License.
 *
 * Link against -lrsurl (librsurl.so / .dylib / .dll). Function names use
 * the rsurl_ prefix so the library can coexist with libcurl in the same
 * process without symbol collisions.
 */

#ifndef RSURL_H
#define RSURL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque easy-handle. Created with rsurl_easy_init, freed with
 * rsurl_easy_cleanup.
 *
 * Thread safety: a handle (RSURL*) must not be used concurrently from multiple
 * threads; use one handle per thread (libcurl easy-handle model). The library
 * performs no internal synchronization on a handle, so concurrent access to
 * the same handle from more than one thread is undefined behavior. */
typedef struct RSURL RSURL;

/* Option identifiers passed to rsurl_easy_setopt_str / _long. */
typedef enum {
    RSURLOPT_URL              = 1,  /* const char* */
    RSURLOPT_CUSTOMREQUEST    = 2,  /* const char* */
    RSURLOPT_HEADER           = 3,  /* const char* "Name: value" (repeat) */
    RSURLOPT_POSTFIELDSSTRING = 4,  /* const char* (UTF-8 body) */
    RSURLOPT_CONNECTTIMEOUT   = 5,  /* long seconds */
    RSURLOPT_TIMEOUT          = 6,  /* long seconds */
    RSURLOPT_USERAGENT        = 7,  /* const char* */
    RSURLOPT_IDN              = 8,  /* long: 1 (default) convert IDN hosts to
                                       punycode, 0 = off (curl --no-idn) */
    RSURLOPT_FOLLOWLOCATION   = 9,  /* long: follow 3xx redirects (off default) */
    RSURLOPT_MAXREDIRS        = 10, /* long: max redirects (<0 = none) */
    RSURLOPT_USERPWD          = 11, /* const char* "user:password" (Basic auth) */
    RSURLOPT_SSL_VERIFYPEER   = 12, /* long: verify TLS peer (default 1; 0 = -k) */
    RSURLOPT_PROXY            = 13, /* const char* proxy URL (http/socks5h/...) */
    RSURLOPT_REFERER          = 14, /* const char* Referer header */
    RSURLOPT_RANGE            = 15, /* const char* byte range, e.g. "0-1023" */
    RSURLOPT_COOKIE           = 16, /* const char* Cookie request header */
    RSURLOPT_XOAUTH2_BEARER   = 17, /* const char* OAuth2 bearer token */
    RSURLOPT_ACCEPT_ENCODING  = 18  /* const char*; "" = all codecs (--compressed) */
} rsurl_option_t;

/* Status codes returned by API functions. */
typedef enum {
    RSURLE_OK              = 0,
    RSURLE_INVALID_HANDLE  = 1,
    RSURLE_UNKNOWN_OPTION  = 2,
    RSURLE_INVALID_ARG     = 3,
    /* Reserved: never returned. The response getters report "no response
     * available" via a NULL/0 out-value together with RSURLE_OK, not this
     * code. Kept for ABI stability and rsurl_strerror coverage. */
    RSURLE_NO_RESPONSE     = 4,
    RSURLE_NETWORK         = 5,
    RSURLE_BAD_RESPONSE    = 6,
    RSURLE_UNSUPPORTED     = 7
} rsurl_code_t;

/* --- Lifecycle ---------------------------------------------------------- */

/* Allocate a new easy handle. Returns NULL on allocation failure. */
RSURL *rsurl_easy_init(void);

/* Free an easy handle. NULL is a no-op. */
void rsurl_easy_cleanup(RSURL *handle);

/* Reset options and clear stored response. Handle remains valid. */
rsurl_code_t rsurl_easy_reset(RSURL *handle);

/* --- Options ------------------------------------------------------------ */

/* Set a string-valued option. Pass NULL to clear it. The string is copied. */
rsurl_code_t rsurl_easy_setopt_str(RSURL *handle, int option,
                                     const char *value);

/* Set a long-valued option. Values <= 0 disable the option where applicable. */
rsurl_code_t rsurl_easy_setopt_long(RSURL *handle, int option, long value);

/* --- Execution ---------------------------------------------------------- */

/* Execute the request. Replaces any previous response on the handle. */
rsurl_code_t rsurl_easy_perform(RSURL *handle);

/* --- Response inspection ------------------------------------------------ */

/* Borrow the response body. *out_ptr / *out_len are owned by the handle and
 * valid only until the next rsurl_easy_perform / _reset / _cleanup on this
 * handle; holding the pointer across any of those is a use-after-free. The
 * buffer is raw bytes (not NUL-terminated, may contain embedded NULs): use
 * *out_len, not strlen. If no response is available, *out_ptr is set to NULL
 * and *out_len to 0 and the call still returns RSURLE_OK. */
rsurl_code_t rsurl_easy_response_body(const RSURL *handle,
                                        const uint8_t **out_ptr,
                                        size_t *out_len);

/* Return the HTTP status code (e.g. 200), or 0 if no response is available. */
long rsurl_easy_response_status(const RSURL *handle);

/* Return the number of response headers available. */
size_t rsurl_easy_response_header_count(const RSURL *handle);

/* Borrow a NUL-terminated "Name: value" string for header at `index`, or
 * NULL if out of range / no response available. The returned pointer is owned
 * by the handle and valid only until the next rsurl_easy_perform / _reset /
 * _cleanup on this handle; holding it across any of those is a use-after-free.
 * Do not free it. Copy the bytes out if you need them to outlive the next
 * operation. */
const char *rsurl_easy_response_header(const RSURL *handle, size_t index);

/* --- Utility ------------------------------------------------------------ */

/* Static human-readable string for a rsurl_code_t value. */
const char *rsurl_strerror(int code);

/* NUL-terminated version string, e.g. "rsurl/0.0.1". */
const char *rsurl_version(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* RSURL_H */

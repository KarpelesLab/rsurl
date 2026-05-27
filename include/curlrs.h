/*
 * curlrs.h — C ABI for the curlrs pure-Rust HTTP client.
 *
 * Copyright (c) 2026 Karpelès Lab Inc. — MIT License.
 *
 * Link against -lcurlrs (libcurlrs.so / .dylib / .dll). Function names use
 * the curlrs_ prefix so the library can coexist with libcurl in the same
 * process without symbol collisions.
 */

#ifndef CURLRS_H
#define CURLRS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque easy-handle. Created with curlrs_easy_init, freed with
 * curlrs_easy_cleanup. */
typedef struct CURLRS CURLRS;

/* Option identifiers passed to curlrs_easy_setopt_str / _long. */
typedef enum {
    CURLRSOPT_URL              = 1,  /* const char* */
    CURLRSOPT_CUSTOMREQUEST    = 2,  /* const char* */
    CURLRSOPT_HEADER           = 3,  /* const char* "Name: value" (repeat) */
    CURLRSOPT_POSTFIELDSSTRING = 4,  /* const char* (UTF-8 body) */
    CURLRSOPT_CONNECTTIMEOUT   = 5,  /* long seconds */
    CURLRSOPT_TIMEOUT          = 6,  /* long seconds */
    CURLRSOPT_USERAGENT        = 7   /* const char* */
} curlrs_option_t;

/* Status codes returned by API functions. */
typedef enum {
    CURLRSE_OK              = 0,
    CURLRSE_INVALID_HANDLE  = 1,
    CURLRSE_UNKNOWN_OPTION  = 2,
    CURLRSE_INVALID_ARG     = 3,
    CURLRSE_NO_RESPONSE     = 4,
    CURLRSE_NETWORK         = 5,
    CURLRSE_BAD_RESPONSE    = 6,
    CURLRSE_UNSUPPORTED     = 7
} curlrs_code_t;

/* --- Lifecycle ---------------------------------------------------------- */

/* Allocate a new easy handle. Returns NULL on allocation failure. */
CURLRS *curlrs_easy_init(void);

/* Free an easy handle. NULL is a no-op. */
void curlrs_easy_cleanup(CURLRS *handle);

/* Reset options and clear stored response. Handle remains valid. */
curlrs_code_t curlrs_easy_reset(CURLRS *handle);

/* --- Options ------------------------------------------------------------ */

/* Set a string-valued option. Pass NULL to clear it. The string is copied. */
curlrs_code_t curlrs_easy_setopt_str(CURLRS *handle, int option,
                                     const char *value);

/* Set a long-valued option. Values <= 0 disable the option where applicable. */
curlrs_code_t curlrs_easy_setopt_long(CURLRS *handle, int option, long value);

/* --- Execution ---------------------------------------------------------- */

/* Execute the request. Replaces any previous response on the handle. */
curlrs_code_t curlrs_easy_perform(CURLRS *handle);

/* --- Response inspection ------------------------------------------------ */

/* Borrow the response body. *out_ptr / *out_len are valid until the next
 * curlrs_easy_perform / _reset / _cleanup on this handle. */
curlrs_code_t curlrs_easy_response_body(const CURLRS *handle,
                                        const uint8_t **out_ptr,
                                        size_t *out_len);

/* Return the HTTP status code (e.g. 200), or 0 if no response is available. */
long curlrs_easy_response_status(const CURLRS *handle);

/* Return the number of response headers available. */
size_t curlrs_easy_response_header_count(const CURLRS *handle);

/* Borrow a NUL-terminated "Name: value" string for header at `index`, or
 * NULL if out of range. Pointer is valid until the next perform/reset/cleanup. */
const char *curlrs_easy_response_header(const CURLRS *handle, size_t index);

/* --- Utility ------------------------------------------------------------ */

/* Static human-readable string for a curlrs_code_t value. */
const char *curlrs_strerror(int code);

/* NUL-terminated version string, e.g. "curlrs/0.0.1". */
const char *curlrs_version(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CURLRS_H */

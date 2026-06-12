/*
 * curl/curl.h — libcurl-compatible header for the rsurl drop-in.
 *
 * Independently authored from libcurl's *publicly documented* API and the
 * well-known public ABI constant values. No libcurl source or headers were
 * consulted. This is a compatibility shim, not libcurl.
 *
 * Scope grows by phase; this revision declares the always-available pieces
 * (global, version, slist, strerror, escape/unescape). The easy and multi
 * interfaces are declared in the same header as they are implemented.
 */
#ifndef RSURL_CURL_COMPAT_CURL_H
#define RSURL_CURL_COMPAT_CURL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void CURL;
typedef void CURLM;
typedef void CURLSH;

/* In libcurl these are enums; their underlying type is `int`, so an `int`
 * typedef is ABI-compatible and lets callers compare against the macros below. */
typedef int CURLcode;
typedef int CURLMcode;
typedef int CURLversion;

/* 64-bit file-size type (this shim targets 64-bit platforms). */
typedef long long curl_off_t;

/* ---- CURLcode (subset) ---- */
#define CURLE_OK 0
#define CURLE_UNSUPPORTED_PROTOCOL 1
#define CURLE_FAILED_INIT 2
#define CURLE_URL_MALFORMAT 3
#define CURLE_NOT_BUILT_IN 4
#define CURLE_COULDNT_RESOLVE_PROXY 5
#define CURLE_COULDNT_RESOLVE_HOST 6
#define CURLE_COULDNT_CONNECT 7
#define CURLE_WEIRD_SERVER_REPLY 8
#define CURLE_REMOTE_ACCESS_DENIED 9
#define CURLE_HTTP2 16
#define CURLE_HTTP_RETURNED_ERROR 22
#define CURLE_WRITE_ERROR 23
#define CURLE_UPLOAD_FAILED 25
#define CURLE_READ_ERROR 26
#define CURLE_OUT_OF_MEMORY 27
#define CURLE_OPERATION_TIMEDOUT 28
#define CURLE_RANGE_ERROR 33
#define CURLE_SSL_CONNECT_ERROR 35
#define CURLE_ABORTED_BY_CALLBACK 42
#define CURLE_BAD_FUNCTION_ARGUMENT 43
#define CURLE_TOO_MANY_REDIRECTS 47
#define CURLE_UNKNOWN_OPTION 48
#define CURLE_GOT_NOTHING 52
#define CURLE_SEND_ERROR 55
#define CURLE_RECV_ERROR 56
#define CURLE_SSL_CERTPROBLEM 58
#define CURLE_PEER_FAILED_VERIFICATION 60
#define CURLE_BAD_CONTENT_ENCODING 61
#define CURLE_FILESIZE_EXCEEDED 63
#define CURLE_SSL_CACERT_BADFILE 77
#define CURLE_AGAIN 81

/* ---- CURLMcode ---- */
#define CURLM_CALL_MULTI_PERFORM (-1)
#define CURLM_OK 0
#define CURLM_BAD_HANDLE 1
#define CURLM_BAD_EASY_HANDLE 2
#define CURLM_OUT_OF_MEMORY 3
#define CURLM_INTERNAL_ERROR 4
#define CURLM_BAD_SOCKET 5
#define CURLM_UNKNOWN_OPTION 6
#define CURLM_ADDED_ALREADY 7

/* ---- curl_global_init flags ---- */
#define CURL_GLOBAL_NOTHING 0L
#define CURL_GLOBAL_SSL (1L << 0)
#define CURL_GLOBAL_WIN32 (1L << 1)
#define CURL_GLOBAL_ALL (CURL_GLOBAL_SSL | CURL_GLOBAL_WIN32)
#define CURL_GLOBAL_DEFAULT CURL_GLOBAL_ALL

/* ---- curl_version_info feature bits (subset) ---- */
#define CURL_VERSION_SSL (1 << 2)
#define CURL_VERSION_LIBZ (1 << 3)
#define CURL_VERSION_HTTP2 (1 << 16)

struct curl_slist {
  char *data;
  struct curl_slist *next;
};

typedef struct {
  int age;
  const char *version;
  unsigned int version_num;
  const char *host;
  int features;
  const char *ssl_version;
  long ssl_version_num;
  const char *libz_version;
  const char *const *protocols;
} curl_version_info_data;

/* ---- always-available functions ---- */
CURLcode curl_global_init(long flags);
CURLcode curl_global_init_mem(long flags, void *m, void *f, void *r, void *c,
                              void *rd);
void curl_global_cleanup(void);

char *curl_version(void);
curl_version_info_data *curl_version_info(CURLversion age);

struct curl_slist *curl_slist_append(struct curl_slist *list,
                                     const char *string);
void curl_slist_free_all(struct curl_slist *list);

const char *curl_easy_strerror(CURLcode code);
const char *curl_multi_strerror(CURLMcode code);
const char *curl_share_strerror(int code);

void curl_free(void *p);
char *curl_easy_escape(CURL *handle, const char *string, int length);
char *curl_easy_unescape(CURL *handle, const char *string, int length,
                         int *outlength);

#ifdef __cplusplus
}
#endif

#endif /* RSURL_CURL_COMPAT_CURL_H */

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

/* ===================== easy interface ===================== */

/* Option-type bases (the type of curl_easy_setopt's third argument). */
#define CURLOPTTYPE_LONG 0
#define CURLOPTTYPE_OBJECTPOINT 10000
#define CURLOPTTYPE_FUNCTIONPOINT 20000
#define CURLOPTTYPE_OFF_T 30000
#define CURLOPTTYPE_BLOB 40000
#define CURLOPTTYPE_STRINGPOINT CURLOPTTYPE_OBJECTPOINT
#define CURLOPTTYPE_SLISTPOINT CURLOPTTYPE_OBJECTPOINT
#define CURLOPTTYPE_CBPOINT CURLOPTTYPE_OBJECTPOINT

typedef enum {
  CURLOPT_PORT = 3,
  CURLOPT_TIMEOUT = 13,
  CURLOPT_INFILESIZE = 14,
  CURLOPT_LOW_SPEED_LIMIT = 19,
  CURLOPT_LOW_SPEED_TIME = 20,
  CURLOPT_RESUME_FROM = 21,
  CURLOPT_CRLF = 27,
  CURLOPT_SSLVERSION = 32,
  CURLOPT_VERBOSE = 41,
  CURLOPT_HEADER = 42,
  CURLOPT_NOPROGRESS = 43,
  CURLOPT_NOBODY = 44,
  CURLOPT_FAILONERROR = 45,
  CURLOPT_UPLOAD = 46,
  CURLOPT_POST = 47,
  CURLOPT_NETRC = 51,
  CURLOPT_FOLLOWLOCATION = 52,
  CURLOPT_PUT = 54,
  CURLOPT_AUTOREFERER = 58,
  CURLOPT_PROXYPORT = 59,
  CURLOPT_POSTFIELDSIZE = 60,
  CURLOPT_HTTPPROXYTUNNEL = 61,
  CURLOPT_SSL_VERIFYPEER = 64,
  CURLOPT_MAXREDIRS = 68,
  CURLOPT_FILETIME = 69,
  CURLOPT_MAXCONNECTS = 71,
  CURLOPT_FRESH_CONNECT = 74,
  CURLOPT_FORBID_REUSE = 75,
  CURLOPT_CONNECTTIMEOUT = 78,
  CURLOPT_HTTPGET = 80,
  CURLOPT_SSL_VERIFYHOST = 81,
  CURLOPT_HTTP_VERSION = 84,
  CURLOPT_COOKIESESSION = 96,
  CURLOPT_BUFFERSIZE = 98,
  CURLOPT_NOSIGNAL = 99,
  CURLOPT_PROXYTYPE = 101,
  CURLOPT_HTTPAUTH = 107,
  CURLOPT_PROXYAUTH = 111,
  CURLOPT_IPRESOLVE = 113,
  CURLOPT_MAXFILESIZE = 114,
  CURLOPT_TCP_NODELAY = 121,
  CURLOPT_TIMEOUT_MS = 155,
  CURLOPT_CONNECTTIMEOUT_MS = 156,
  CURLOPT_POSTREDIR = 161,
  CURLOPT_TCP_KEEPALIVE = 213,
  CURLOPT_SSL_OPTIONS = 216,
  CURLOPT_SSL_VERIFYSTATUS = 232,

  CURLOPT_WRITEDATA = 10001,
  CURLOPT_URL = 10002,
  CURLOPT_PROXY = 10004,
  CURLOPT_USERPWD = 10005,
  CURLOPT_PROXYUSERPWD = 10006,
  CURLOPT_RANGE = 10007,
  CURLOPT_READDATA = 10009,
  CURLOPT_ERRORBUFFER = 10010,
  CURLOPT_POSTFIELDS = 10015,
  CURLOPT_REFERER = 10016,
  CURLOPT_USERAGENT = 10018,
  CURLOPT_COOKIE = 10022,
  CURLOPT_HTTPHEADER = 10023,
  CURLOPT_SSLCERT = 10025,
  CURLOPT_KEYPASSWD = 10026,
  CURLOPT_HEADERDATA = 10029,
  CURLOPT_WRITEHEADER = 10029,
  CURLOPT_COOKIEFILE = 10031,
  CURLOPT_CUSTOMREQUEST = 10036,
  CURLOPT_INTERFACE = 10062,
  CURLOPT_CAINFO = 10065,
  CURLOPT_COOKIEJAR = 10082,
  CURLOPT_SSL_CIPHER_LIST = 10083,
  CURLOPT_SSLCERTTYPE = 10086,
  CURLOPT_SSLKEY = 10087,
  CURLOPT_SSLKEYTYPE = 10088,
  CURLOPT_CAPATH = 10097,
  CURLOPT_ACCEPT_ENCODING = 10102,
  CURLOPT_PRIVATE = 10103,
  CURLOPT_COPYPOSTFIELDS = 10165,
  CURLOPT_CRLFILE = 10169,
  CURLOPT_USERNAME = 10173,
  CURLOPT_PASSWORD = 10174,
  CURLOPT_NOPROXY = 10177,
  CURLOPT_RESOLVE = 10203,
  CURLOPT_XOAUTH2_BEARER = 10220,
  CURLOPT_PINNEDPUBLICKEY = 10230,
  CURLOPT_UNIX_SOCKET_PATH = 10231,
  CURLOPT_DEFAULT_PROTOCOL = 10238,
  CURLOPT_CONNECT_TO = 10243,
  CURLOPT_TLS13_CIPHERS = 10277,

  CURLOPT_WRITEFUNCTION = 20011,
  CURLOPT_READFUNCTION = 20012,
  CURLOPT_PROGRESSFUNCTION = 20056,
  CURLOPT_HEADERFUNCTION = 20079,
  CURLOPT_DEBUGFUNCTION = 20094,
  CURLOPT_XFERINFOFUNCTION = 20219,

  CURLOPT_INFILESIZE_LARGE = 30115,
  CURLOPT_RESUME_FROM_LARGE = 30116,
  CURLOPT_MAXFILESIZE_LARGE = 30117,
  CURLOPT_POSTFIELDSIZE_LARGE = 30120
} CURLoption;

/* CURLOPT_HTTP_VERSION values */
#define CURL_HTTP_VERSION_NONE 0
#define CURL_HTTP_VERSION_1_0 1
#define CURL_HTTP_VERSION_1_1 2
#define CURL_HTTP_VERSION_2_0 3
#define CURL_HTTP_VERSION_2TLS 4
#define CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE 5
#define CURL_HTTP_VERSION_3 30
#define CURL_HTTP_VERSION_3ONLY 31

/* CURLOPT_HTTPAUTH bits (subset) */
#define CURLAUTH_BASIC (1 << 0)
#define CURLAUTH_DIGEST (1 << 1)
#define CURLAUTH_ANY (~0)

/* CURLINFO out-type bases */
#define CURLINFO_STRING 0x100000
#define CURLINFO_LONG 0x200000
#define CURLINFO_DOUBLE 0x300000
#define CURLINFO_SLIST 0x400000
#define CURLINFO_OFF_T 0x600000

typedef enum {
  CURLINFO_EFFECTIVE_URL = CURLINFO_STRING + 1,
  CURLINFO_RESPONSE_CODE = CURLINFO_LONG + 2,
  CURLINFO_TOTAL_TIME = CURLINFO_DOUBLE + 3,
  CURLINFO_NAMELOOKUP_TIME = CURLINFO_DOUBLE + 4,
  CURLINFO_CONNECT_TIME = CURLINFO_DOUBLE + 5,
  CURLINFO_PRETRANSFER_TIME = CURLINFO_DOUBLE + 6,
  CURLINFO_SIZE_DOWNLOAD = CURLINFO_DOUBLE + 8,
  CURLINFO_HEADER_SIZE = CURLINFO_LONG + 11,
  CURLINFO_CONTENT_TYPE = CURLINFO_STRING + 18,
  CURLINFO_REDIRECT_COUNT = CURLINFO_LONG + 20,
  CURLINFO_PRIVATE = CURLINFO_STRING + 21,
  CURLINFO_STARTTRANSFER_TIME = CURLINFO_DOUBLE + 17,
  CURLINFO_REDIRECT_URL = CURLINFO_STRING + 31,
  CURLINFO_APPCONNECT_TIME = CURLINFO_DOUBLE + 33,
  CURLINFO_HTTP_VERSION = CURLINFO_LONG + 46,
  CURLINFO_SCHEME = CURLINFO_STRING + 49,
  CURLINFO_SIZE_DOWNLOAD_T = CURLINFO_OFF_T + 8,
  CURLINFO_CONNECT_TIME_T = CURLINFO_OFF_T + 48,
  CURLINFO_STARTTRANSFER_TIME_T = CURLINFO_OFF_T + 49,
  CURLINFO_TOTAL_TIME_T = CURLINFO_OFF_T + 50
} CURLINFO;

/* write/header callback: (ptr, size, nmemb, userdata) -> bytes consumed */
typedef size_t (*curl_write_callback)(char *ptr, size_t size, size_t nmemb,
                                      void *userdata);

CURL *curl_easy_init(void);
void curl_easy_cleanup(CURL *handle);
void curl_easy_reset(CURL *handle);
CURL *curl_easy_duphandle(CURL *handle);
CURLcode curl_easy_setopt(CURL *handle, CURLoption option, ...);
CURLcode curl_easy_getinfo(CURL *handle, CURLINFO info, ...);
CURLcode curl_easy_perform(CURL *handle);

/* ===================== multi interface ===================== */

typedef int CURLMSG;
#define CURLMSG_NONE 0
#define CURLMSG_DONE 1

typedef struct CURLMsg {
  CURLMSG msg;            /* what this message means */
  CURL *easy_handle;      /* the handle it concerns */
  union {
    void *whatever;       /* (not used) */
    CURLcode result;      /* return code for the transfer */
  } data;
} CURLMsg;

/* Poll descriptor (programs may pass an array; this shim ignores extra fds). */
struct curl_waitfd {
  int fd;
  short events;
  short revents;
};

CURLM *curl_multi_init(void);
CURLMcode curl_multi_cleanup(CURLM *multi);
CURLMcode curl_multi_add_handle(CURLM *multi, CURL *easy);
CURLMcode curl_multi_remove_handle(CURLM *multi, CURL *easy);
CURLMcode curl_multi_perform(CURLM *multi, int *running_handles);
CURLMcode curl_multi_poll(CURLM *multi, struct curl_waitfd *extra_fds,
                          int extra_nfds, int timeout_ms, int *numfds);
CURLMcode curl_multi_wait(CURLM *multi, struct curl_waitfd *extra_fds,
                          int extra_nfds, int timeout_ms, int *numfds);
CURLMsg *curl_multi_info_read(CURLM *multi, int *msgs_in_queue);
CURLMcode curl_multi_setopt(CURLM *multi, int option, ...);

#ifdef __cplusplus
}
#endif

#endif /* RSURL_CURL_COMPAT_CURL_H */

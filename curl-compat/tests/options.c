/* Option-semantics test: argv[1] is an echo server URL whose body describes
 * the request ("M=<method> R=<range> L=<body length>"); argv[2]/argv[3] are
 * files for WRITEDATA / HEADERDATA. Prints key=value tokens the Rust harness
 * checks. Every setopt/getinfo call goes through the variadic prototypes. */
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct buf {
  char p[512];
  size_t len;
};

static size_t wr(char *ptr, size_t size, size_t nmemb, void *ud) {
  struct buf *b = (struct buf *)ud;
  size_t n = size * nmemb;
  if (b->len + n >= sizeof(b->p))
    return 0;
  memcpy(b->p + b->len, ptr, n);
  b->len += n;
  b->p[b->len] = 0;
  return n;
}

/* Perform on `h` collecting the body into a fresh buffer; prints `tag=body`. */
static int fetch(CURL *h, const char *tag) {
  struct buf b;
  b.len = 0;
  b.p[0] = 0;
  curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, wr);
  curl_easy_setopt(h, CURLOPT_WRITEDATA, &b);
  CURLcode rc = curl_easy_perform(h);
  if (rc != CURLE_OK) {
    fprintf(stderr, "%s: perform failed: %s\n", tag, curl_easy_strerror(rc));
    return 1;
  }
  printf("%s=%s\n", tag, b.p);
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 4) {
    fprintf(stderr, "usage: options <url> <bodyfile> <headfile>\n");
    return 2;
  }
  const char *url = argv[1];
  curl_global_init(CURL_GLOBAL_DEFAULT);

  /* 1. Default write callback: fwrite into the WRITEDATA / HEADERDATA FILE*s,
   *    plus CURLOPT_PRIVATE, TIMEOUT 0 (= none) and HEADER_SIZE. */
  CURL *h = curl_easy_init();
  FILE *bf = fopen(argv[2], "wb");
  FILE *hf = fopen(argv[3], "wb");
  if (!bf || !hf) {
    fprintf(stderr, "fopen failed\n");
    return 1;
  }
  static int marker;
  curl_easy_setopt(h, CURLOPT_URL, url);
  curl_easy_setopt(h, CURLOPT_WRITEDATA, bf);
  curl_easy_setopt(h, CURLOPT_HEADERDATA, hf);
  curl_easy_setopt(h, CURLOPT_PRIVATE, (void *)&marker);
  curl_easy_setopt(h, CURLOPT_TIMEOUT, 0L);
  curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT, 0L);
  CURLcode rc = curl_easy_perform(h);
  fclose(bf);
  fclose(hf);
  printf("timeout0=%d\n", (int)rc);
  if (rc != CURLE_OK) {
    fprintf(stderr, "default-write perform failed: %s\n", curl_easy_strerror(rc));
    return 1;
  }
  char *priv = NULL;
  curl_easy_getinfo(h, CURLINFO_PRIVATE, &priv);
  printf("private=%s\n", priv == (char *)&marker ? "ok" : "bad");
  long hsize = 0;
  curl_easy_getinfo(h, CURLINFO_HEADER_SIZE, &hsize);
  printf("header_size_ok=%d\n", hsize > 20 ? 1 : 0);
  printf("unknown_opt=%d\n", (int)curl_easy_setopt(h, (CURLoption)9999, 1L));
  curl_easy_cleanup(h);

  /* 2. A POST body, then HTTPGET: must go back to a body-less GET. */
  h = curl_easy_init();
  curl_easy_setopt(h, CURLOPT_URL, url);
  curl_easy_setopt(h, CURLOPT_POSTFIELDS, "a=1&b");
  if (fetch(h, "post"))
    return 1;
  curl_easy_setopt(h, CURLOPT_HTTPGET, 1L);
  if (fetch(h, "httpget"))
    return 1;

  /* 3. CURLOPT_RANGE takes a bare range set; the request carries `bytes=`. */
  curl_easy_setopt(h, CURLOPT_RANGE, "0-3");
  if (fetch(h, "range"))
    return 1;
  curl_easy_cleanup(h);

  /* 4. HTTPHEADER naming User-Agent/Referer replaces USERAGENT/REFERER
   *    (never both on the wire). The echo server lists every value. */
  char uaurl[512];
  snprintf(uaurl, sizeof(uaurl), "%sua", url);
  h = curl_easy_init();
  curl_easy_setopt(h, CURLOPT_URL, uaurl);
  curl_easy_setopt(h, CURLOPT_USERAGENT, "opt-ua");
  curl_easy_setopt(h, CURLOPT_REFERER, "opt-ref");
  struct curl_slist *hdrs = NULL;
  hdrs = curl_slist_append(hdrs, "user-agent: hdr-ua");
  hdrs = curl_slist_append(hdrs, "Referer: hdr-ref");
  curl_easy_setopt(h, CURLOPT_HTTPHEADER, hdrs);
  if (fetch(h, "ua"))
    return 1;
  curl_slist_free_all(hdrs);
  curl_easy_cleanup(h);

  curl_global_cleanup();
  return 0;
}

/* Easy-interface smoke test: GET argv[1] with a write callback + a custom
 * header, then read response info. Prints a token the Rust harness checks. */
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct buf {
  char *p;
  size_t len;
};

static size_t wr(char *ptr, size_t size, size_t nmemb, void *ud) {
  struct buf *b = (struct buf *)ud;
  size_t n = size * nmemb;
  b->p = (char *)realloc(b->p, b->len + n + 1);
  memcpy(b->p + b->len, ptr, n);
  b->len += n;
  b->p[b->len] = 0;
  return n;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: easy <url>\n");
    return 2;
  }
  curl_global_init(CURL_GLOBAL_DEFAULT);
  CURL *h = curl_easy_init();
  struct buf b = {NULL, 0};
  struct curl_slist *hdr = NULL;
  hdr = curl_slist_append(hdr, "X-Test: yes");

  curl_easy_setopt(h, CURLOPT_URL, argv[1]);
  curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, wr);
  curl_easy_setopt(h, CURLOPT_WRITEDATA, &b);
  curl_easy_setopt(h, CURLOPT_HTTPHEADER, hdr);
  curl_easy_setopt(h, CURLOPT_USERAGENT, "easy-smoke/1");
  curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(h, CURLOPT_TIMEOUT, 10L);

  CURLcode rc = curl_easy_perform(h);
  if (rc != CURLE_OK) {
    fprintf(stderr, "perform failed: %s\n", curl_easy_strerror(rc));
    return 1;
  }

  long code = 0;
  curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &code);
  char *ct = NULL;
  curl_easy_getinfo(h, CURLINFO_CONTENT_TYPE, &ct);
  char *eu = NULL;
  curl_easy_getinfo(h, CURLINFO_EFFECTIVE_URL, &eu);
  double dl = 0;
  curl_easy_getinfo(h, CURLINFO_SIZE_DOWNLOAD, &dl);

  printf("EASY_OK code=%ld ct=%s eu=%s dl=%.0f body=%s\n", code,
         ct ? ct : "(null)", eu ? eu : "(null)", dl, b.p ? b.p : "");

  curl_slist_free_all(hdr);
  curl_easy_cleanup(h);
  curl_global_cleanup();
  free(b.p);
  return 0;
}

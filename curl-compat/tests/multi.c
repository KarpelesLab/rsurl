/* Multi-interface smoke test: run two concurrent GETs (argv[1], argv[2])
 * through curl_multi_*, then read each handle's response code. */
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

static CURL *mk(const char *url, struct buf *b) {
  CURL *e = curl_easy_init();
  curl_easy_setopt(e, CURLOPT_URL, url);
  curl_easy_setopt(e, CURLOPT_WRITEFUNCTION, wr);
  curl_easy_setopt(e, CURLOPT_WRITEDATA, b);
  curl_easy_setopt(e, CURLOPT_TIMEOUT, 10L);
  return e;
}

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "usage: multi <url1> <url2>\n");
    return 2;
  }
  curl_global_init(CURL_GLOBAL_DEFAULT);
  CURLM *m = curl_multi_init();
  struct buf b1 = {NULL, 0}, b2 = {NULL, 0};
  CURL *e1 = mk(argv[1], &b1);
  CURL *e2 = mk(argv[2], &b2);
  curl_multi_add_handle(m, e1);
  curl_multi_add_handle(m, e2);

  int done = 0;
  int running = 0;
  do {
    curl_multi_perform(m, &running);
    int q = 0;
    CURLMsg *msg;
    while ((msg = curl_multi_info_read(m, &q)) != NULL) {
      if (msg->msg == CURLMSG_DONE) {
        done++;
      }
    }
    if (running) {
      curl_multi_poll(m, NULL, 0, 1000, NULL);
    }
  } while (running);

  /* drain any final messages */
  int q = 0;
  CURLMsg *msg;
  while ((msg = curl_multi_info_read(m, &q)) != NULL) {
    if (msg->msg == CURLMSG_DONE) {
      done++;
    }
  }

  long c1 = 0, c2 = 0;
  curl_easy_getinfo(e1, CURLINFO_RESPONSE_CODE, &c1);
  curl_easy_getinfo(e2, CURLINFO_RESPONSE_CODE, &c2);
  printf("MULTI_OK done=%d c1=%ld c2=%ld b1=%s b2=%s\n", done, c1, c2,
         b1.p ? b1.p : "", b2.p ? b2.p : "");

  curl_multi_remove_handle(m, e1);
  curl_multi_remove_handle(m, e2);
  curl_easy_cleanup(e1);
  curl_easy_cleanup(e2);
  curl_multi_cleanup(m);
  curl_global_cleanup();
  free(b1.p);
  free(b2.p);
  return 0;
}

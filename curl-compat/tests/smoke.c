/* C smoke test for the libcurl-compat drop-in: exercises the always-available
 * surface (version, slist, escape/unescape, strerror) and prints a token the
 * Rust harness checks. Linked against libcurl.{so,a} built by this crate. */
#include <curl/curl.h>
#include <stdio.h>
#include <string.h>

int main(void) {
  if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
    fprintf(stderr, "global_init failed\n");
    return 1;
  }

  const char *ver = curl_version();
  if (!ver || strstr(ver, "libcurl/") == NULL) {
    fprintf(stderr, "bad version string: %s\n", ver ? ver : "(null)");
    return 1;
  }

  curl_version_info_data *vi = curl_version_info(0);
  if (!vi || (vi->features & CURL_VERSION_SSL) == 0) {
    fprintf(stderr, "version_info missing SSL feature\n");
    return 1;
  }

  /* slist append + free */
  struct curl_slist *l = NULL;
  l = curl_slist_append(l, "A: 1");
  l = curl_slist_append(l, "B: 2");
  if (!l || !l->next || strcmp(l->data, "A: 1") != 0 ||
      strcmp(l->next->data, "B: 2") != 0) {
    fprintf(stderr, "slist mismatch\n");
    return 1;
  }
  curl_slist_free_all(l);

  /* escape / unescape round-trip */
  char *esc = curl_easy_escape(NULL, "a b/c", 0);
  if (!esc || strcmp(esc, "a%20b%2Fc") != 0) {
    fprintf(stderr, "escape mismatch: %s\n", esc ? esc : "(null)");
    return 1;
  }
  int outlen = 0;
  char *un = curl_easy_unescape(NULL, esc, 0, &outlen);
  if (!un || outlen != 5 || strcmp(un, "a b/c") != 0) {
    fprintf(stderr, "unescape mismatch\n");
    return 1;
  }
  curl_free(esc);
  curl_free(un);

  if (strcmp(curl_easy_strerror(CURLE_OK), "No error") != 0) {
    fprintf(stderr, "strerror mismatch\n");
    return 1;
  }

  curl_global_cleanup();
  printf("SMOKE_OK %s\n", ver);
  return 0;
}

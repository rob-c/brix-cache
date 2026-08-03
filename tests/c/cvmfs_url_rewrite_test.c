/*
 * cvmfs_url_rewrite_test.c — the CVMFS mirror URL builders must never truncate.
 *
 * WHAT: unit-tests the static URL helpers inside client/apps/fs/brixcvmfs_transport.c
 *       (to_https / transport_url) by including the translation unit directly and
 *       stubbing its ten project externals — nothing here touches the network.
 * WHY:  the TU built with two -Wformat-truncation warnings: to_https() rewrote
 *       http:// → https:// into a same-sized buffer and ignored snprintf's return.
 *       A truncated URL is a *different* URL: the TLS probe would GET an object
 *       nobody asked for, and the resulting 4xx would be misread as "this mirror
 *       has no TLS". Silencing the warning without fixing the semantics would have
 *       kept that bug.
 * HOW:  three axes — the rewrite succeeds; a rewrite that would not fit reports
 *       "not rewritten" rather than emitting a shortened URL; and the sizing
 *       invariant (BRIXCVMFS_URL_HTTPS_MAX == BRIXCVMFS_URL_MAX + 1) makes the
 *       refusal unreachable for the transport's own longest legal URL. Compiled
 *       -O2 -D_FORTIFY_SOURCE=2 -Werror so the warning itself cannot return.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* --- the ten project externals brixcvmfs_transport.o leaves undefined ------ */

#include "brix.h"
#include "net/cpool.h"
#include "net/proxy_env.h"
#include "cvmfs/dict/dict.h"

brix_cpool *brix_cpool_create(const brix_cpool_vtbl *vt, void *ctx, int n, brix_status *st)
{ (void) vt; (void) ctx; (void) n; (void) st; return NULL; }
void *brix_cpool_checkout(brix_cpool *p, brix_status *st)
{ (void) p; (void) st; return NULL; }
void brix_cpool_checkin(brix_cpool *p, void *conn, int healthy)
{ (void) p; (void) conn; (void) healthy; }
void brix_cpool_destroy(brix_cpool *p) { (void) p; }

int brix_proxy_resolve(const char *scheme, const char *host, int port, brix_proxy_t *out)
{ (void) scheme; (void) host; (void) port; (void) out; return 0; }
void brix_proxy_report(const brix_proxy_t *p, const char *host, int port)
{ (void) p; (void) host; (void) port; }

void brix_status_clear(brix_status *st) { (void) st; }
void brix_status_set(brix_status *st, int kxr, int sys_errno, const char *fmt, ...)
{ (void) st; (void) kxr; (void) sys_errno; (void) fmt; }

int cvmfs_dict_id(const unsigned char *dict, size_t dictlen, char hex[CVMFS_DICT_ID_HEXLEN + 1])
{ (void) dict; (void) dictlen; hex[0] = '\0'; return -1; }
int cvmfs_dict_decompress(const unsigned char *dict, size_t dictlen,
                          const unsigned char *src, size_t srclen,
                          unsigned char *out, size_t outcap, size_t *outlen)
{ (void) dict; (void) dictlen; (void) src; (void) srclen;
  (void) out; (void) outcap; (void) outlen; return -1; }

#include "apps/fs/brixcvmfs_transport.c"

/* -------------------------------------------------------------------------- */

static int failures;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        if (!(cond)) { fprintf(stderr, "FAIL: %s\n", (msg)); failures++; }      \
    } while (0)

/* The sizing invariant the whole fix rests on: s/http:/https:/ adds exactly one
 * byte, so an https buffer one larger than the http buffer can always hold the
 * rewrite of anything that fitted in the latter. */
_Static_assert(BRIXCVMFS_URL_HTTPS_MAX == BRIXCVMFS_URL_MAX + 1,
               "https buffer must be exactly one byte larger than the http one");

static void test_rewrite_succeeds(void)
{
    char buf[BRIXCVMFS_URL_HTTPS_MAX];

    CHECK(to_https("http://s1.example.org/data/0a/bcdef", buf, sizeof(buf)) == 1,
          "an http:// url was not rewritten");
    CHECK(strcmp(buf, "https://s1.example.org/data/0a/bcdef") == 0,
          "the rewritten url is not the input with an https scheme");
}

static void test_non_http_is_left_alone(void)
{
    char buf[BRIXCVMFS_URL_HTTPS_MAX];

    memset(buf, 'x', sizeof(buf));
    CHECK(to_https("https://s1.example.org/x", buf, sizeof(buf)) == 0,
          "an already-https url reported a rewrite");
    CHECK(to_https("root://s1.example.org/x", buf, sizeof(buf)) == 0,
          "a non-http scheme reported a rewrite");
    CHECK(to_https("http:/", buf, sizeof(buf)) == 0,
          "a truncated scheme prefix reported a rewrite");
    CHECK(buf[0] == 'x', "a refused rewrite still wrote to the destination");
}

/* Security-negative: a rewrite that does not fit must report failure, because a
 * shortened URL names a different object. */
static void test_a_rewrite_that_would_not_fit_is_refused(void)
{
    char url[64], small[16];

    memset(url, 'a', sizeof(url));
    memcpy(url, "http://", 7);
    url[sizeof(url) - 1] = '\0';

    CHECK(to_https(url, small, sizeof(small)) == 0,
          "a url that could not fit was reported as rewritten");
    CHECK(to_https(url, small, 9) == 0, "a one-char-short buffer reported success");
    CHECK(to_https(url, small, 1) == 0, "a one-byte buffer reported success");
}

/* The transport's own longest legal http url — one byte short of BRIXCVMFS_URL_MAX
 * — must still rewrite, or prefer_tls would silently stop applying to long paths. */
static void test_the_longest_legal_url_still_rewrites(void)
{
    char url[BRIXCVMFS_URL_MAX], buf[BRIXCVMFS_URL_HTTPS_MAX];

    memset(url, 'a', sizeof(url));
    memcpy(url, "http://", 7);
    url[sizeof(url) - 1] = '\0';

    CHECK(to_https(url, buf, sizeof(buf)) == 1,
          "the longest url the transport can build failed to rewrite");
    CHECK(strlen(buf) == strlen(url) + 1, "the rewrite lost bytes");
    CHECK(strncmp(buf, "https://a", 9) == 0, "the rewrite corrupted the url");
}

/* The caller-visible contract: transport_url() hands back the plain http url
 * whenever a rewrite did not happen, so a refusal degrades to cleartext against
 * the *right* object rather than TLS against the wrong one. */
static void test_transport_url_selection(void)
{
    char buf[BRIXCVMFS_URL_HTTPS_MAX];
    const char *http = "http://s1.example.org/data/00/aa";
    const char *pick;
    int use_https;

    g_tcfg.prefer_tls = 1;
    pick = transport_url(1, http, buf, sizeof(buf), &use_https);
    CHECK(use_https == 1 && pick == buf, "the first attempt did not prefer TLS");

    pick = transport_url(0, http, buf, sizeof(buf), &use_https);
    CHECK(use_https == 0 && pick == http, "a retry attempt was not downgraded");

    g_tcfg.prefer_tls = 0;
    pick = transport_url(1, http, buf, sizeof(buf), &use_https);
    CHECK(use_https == 0 && pick == http, "TLS was preferred with prefer_tls off");

    g_tcfg.prefer_tls = 1;
    pick = transport_url(1, http, buf, 8, &use_https);
    CHECK(use_https == 0 && pick == http,
          "a refused rewrite still selected the https buffer");
}

int main(void)
{
    test_rewrite_succeeds();
    test_non_http_is_left_alone();
    test_a_rewrite_that_would_not_fit_is_refused();
    test_the_longest_legal_url_still_rewrites();
    test_transport_url_selection();

    if (failures) { fprintf(stderr, "%d check(s) failed\n", failures); return 1; }
    printf("cvmfs_url_rewrite: all checks passed\n");
    return 0;
}

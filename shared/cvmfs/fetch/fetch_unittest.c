/*
 * fetch_unittest.c — standalone tests for CVMFS object decode/verify + the
 * content-addressed fetch orchestrator (hash-verified mirror-agnostic retry).
 *
 * Compiles without nginx:
 *   gcc -Wall -Wextra -Werror -I shared -o /tmp/cvmfs_fetch_ut \
 *       shared/cvmfs/fetch/fetch_unittest.c shared/cvmfs/fetch/fetch.c \
 *       shared/cvmfs/fetch/fetch_bundle.c shared/cvmfs/bundle/bundle.c \
 *       shared/cvmfs/object/object.c shared/cvmfs/failover/failover.c \
 *       shared/cvmfs/grammar/hash.c shared/cache/cas_store.c \
 *       -lcrypto -lz && /tmp/cvmfs_fetch_ut
 * Exit 0 = all checks pass.
 */
#include "cvmfs/fetch/fetch.h"
#include "cvmfs/bundle/bundle.h"
#include "cvmfs/object/object.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

static int g_checks, g_failed;
#define CHECK(cond, name) do {                                    \
    g_checks++;                                                   \
    if (cond) { printf("  ok   %s\n", name); }                    \
    else      { printf("  FAIL %s (line %d)\n", name, __LINE__); g_failed++; } \
} while (0)

static void rm_rf(const char *p) {
    char cmd[600]; snprintf(cmd, sizeof(cmd), "rm -rf '%s'", p);
    if (system(cmd) != 0) { /* best effort */ }
}

/* zlib-compress src into a malloc'd buffer; caller frees. */
static unsigned char *zlib_of(const unsigned char *src, size_t n, size_t *outn) {
    uLongf cap = compressBound(n);
    unsigned char *buf = malloc(cap);
    compress(buf, &cap, src, n);
    *outn = cap;
    return buf;
}

/* ---- mock transport ----------------------------------------------------- */
typedef struct {
    unsigned char *good;  size_t good_n;    /* zlib(plaintext) */
    unsigned char *evil;  size_t evil_n;    /* zlib(other) — poisoned mirror */
    int            fail_if_called;          /* cache-hit assertion */
    int            was_called;
} mock_ud_t;

static int mock_transport(const char *proxy, const char *host, const char *rel,
                          unsigned char *out, size_t outcap, size_t *outlen, void *ud) {
    (void) proxy; (void) rel;
    mock_ud_t *m = ud;
    m->was_called = 1;
    if (m->fail_if_called) return -1;
    if (strstr(host, "dead")) return -1;                       /* transport failure */
    if (strstr(host, "evil")) {                                /* poisoned bytes */
        if (m->evil_n > outcap) return -1;
        memcpy(out, m->evil, m->evil_n); *outlen = m->evil_n; return 0;
    }
    if (m->good_n > outcap) return -1;
    memcpy(out, m->good, m->good_n); *outlen = m->good_n; return 0;
}

/* ---- object decode/verify ---------------------------------------------- */
static void test_object(void) {
    const unsigned char plain[] = "the quick brown fox jumps over the lazy dog, twice.";
    size_t pn = sizeof(plain) - 1;

    cvmfs_hash_t h;
    CHECK(cvmfs_object_hash(CVMFS_HASH_SHA1, plain, pn, &h) == 0 && h.len == 20,
          "sha1 content hash");

    size_t cn; unsigned char *cz = zlib_of(plain, pn, &cn);
    unsigned char dec[256]; size_t dn = 0;
    CHECK(cvmfs_object_inflate(cz, cn, dec, sizeof(dec), &dn) == 0 && dn == pn
          && memcmp(dec, plain, pn) == 0, "inflate roundtrip");
    CHECK(cvmfs_object_verify(dec, dn, &h) == 1, "verify genuine");

    dec[0] ^= 0xff;
    CHECK(cvmfs_object_verify(dec, dn, &h) == 0, "verify tampered rejected"); /* neg */
    free(cz);
}

/* ---- fetch orchestrator ------------------------------------------------- */
static void test_fetch(void) {
    char root[] = "/tmp/brix_fetch_ut.XXXXXX";
    if (mkdtemp(root) == NULL) { perror("mkdtemp"); g_failed++; return; }

    const unsigned char plain[] = "content-addressed object payload for the fetch test";
    const unsigned char evil[]  = "malicious substituted payload of same-ish length!!";
    size_t pn = sizeof(plain) - 1;

    mock_ud_t m; memset(&m, 0, sizeof(m));
    m.good = zlib_of(plain, pn, &m.good_n);
    m.evil = zlib_of(evil, sizeof(evil) - 1, &m.evil_n);

    /* object identity = hash of the STORED (compressed) bytes (real CVMFS). */
    cvmfs_hash_t h;
    cvmfs_object_hash(CVMFS_HASH_SHA1, m.good, m.good_n, &h);

    brix_cas_store_t cache; brix_cas_init(&cache, root, 0);
    unsigned char scratch[4096];

    /* --- scenario 1: poisoned first mirror, good second mirror --- */
    cvmfs_failover_t fo; cvmfs_failover_init(&fo, 60);
    cvmfs_failover_add_host(&fo, "http://evil.mirror");   /* index 0 */
    cvmfs_failover_add_host(&fo, "http://good.mirror");   /* index 1 */

    cvmfs_fetch_ctx_t ctx; memset(&ctx, 0, sizeof(ctx));
    ctx.fo = &fo; ctx.cache = &cache; ctx.transport = mock_transport;
    ctx.transport_ud = &m; ctx.store_form = CVMFS_STORE_COMPRESSED;
    ctx.scratch = scratch; ctx.scratch_cap = sizeof(scratch);

    unsigned char out[4096]; size_t on = 0;
    int rc = cvmfs_fetch_object(&ctx, &h, 0, out, sizeof(out), &on, 1000);
    CHECK(rc == 0 && on == pn && memcmp(out, plain, pn) == 0,
          "fetch survives poisoned mirror, verifies via next");
    CHECK(fo.hosts[0].blacklisted_until > 1000, "poisoned mirror blacklisted");

    /* --- scenario 2: second fetch is a cache hit (transport must not run) --- */
    m.fail_if_called = 1; m.was_called = 0;
    size_t on2 = 0;
    int rc2 = cvmfs_fetch_object(&ctx, &h, 0, out, sizeof(out), &on2, 1001);
    CHECK(rc2 == 0 && on2 == pn && m.was_called == 0, "cache hit skips transport");
    m.fail_if_called = 0;

    /* --- scenario 3: all mirrors dead → offline --- */
    cvmfs_hash_t h2;
    const unsigned char other[] = "a different uncached object";
    cvmfs_object_hash(CVMFS_HASH_SHA1, other, sizeof(other) - 1, &h2);
    cvmfs_failover_t fo2; cvmfs_failover_init(&fo2, 60);
    cvmfs_failover_add_host(&fo2, "http://dead.one");
    cvmfs_failover_add_host(&fo2, "http://dead.two");
    ctx.fo = &fo2;
    size_t on3 = 0;
    int rc3 = cvmfs_fetch_object(&ctx, &h2, 0, out, sizeof(out), &on3, 2000);
    CHECK(rc3 == -2, "all-mirrors-down → offline (-2)");   /* resilience-neg */

    free(m.good); free(m.evil);
    rm_rf(root);
}

/* ---- bundle ingest (phase-87 G2) ---------------------------------------- */

/* Append one CAS-pathed item (or a miss marker when data == NULL) to the
 * stream being built in `buf`. Returns the new write offset. */
static size_t bundle_add(unsigned char *buf, size_t off, const cvmfs_hash_t *h,
                         const unsigned char *data, size_t dn) {
    char obj[160], path[176];
    cvmfs_hash_to_object_path(h, 0, obj, sizeof(obj));
    int plen = snprintf(path, sizeof(path), "data/%s", obj);
    int w = cvmfs_bundle_item_encode(buf + off, 4096, path, (size_t) plen,
                                     data ? (uint64_t) dn : CVMFS_BUNDLE_MISS);
    off += (size_t) w;
    if (data) { memcpy(buf + off, data, dn); off += dn; }
    return off;
}

static void test_bundle_ingest(void) {
    char root[] = "/tmp/brix_bundle_ut.XXXXXX";
    if (mkdtemp(root) == NULL) { perror("mkdtemp"); g_failed++; return; }

    const unsigned char plain[] = "bundled object payload, stored compressed";
    size_t pn = sizeof(plain) - 1;
    size_t cn; unsigned char *cz = zlib_of(plain, pn, &cn);

    /* member identities: hash of STORED bytes (good), an absent object (miss),
     * and the good hash again but with tampered bytes (security-neg). */
    cvmfs_hash_t hg, hm;
    cvmfs_object_hash(CVMFS_HASH_SHA1, cz, cn, &hg);
    const unsigned char absent[] = "an object the server did not have";
    cvmfs_object_hash(CVMFS_HASH_SHA1, absent, sizeof(absent) - 1, &hm);

    unsigned char *tampered = malloc(cn);
    memcpy(tampered, cz, cn); tampered[0] ^= 0xff;

    unsigned char stream[16384];
    cvmfs_bundle_hdr_encode(stream, 3);
    size_t off = CVMFS_BUNDLE_HDR_LEN;
    off = bundle_add(stream, off, &hg, cz, cn);            /* verifiable   */
    off = bundle_add(stream, off, &hm, NULL, 0);           /* miss marker  */
    off = bundle_add(stream, off, &hg, tampered, cn);      /* tampered     */

    brix_cas_store_t cache; brix_cas_init(&cache, root, 0);
    cvmfs_failover_t fo; cvmfs_failover_init(&fo, 60);
    cvmfs_failover_add_host(&fo, "http://good.mirror");

    mock_ud_t m; memset(&m, 0, sizeof(m));
    unsigned char scratch[4096];
    cvmfs_fetch_ctx_t ctx; memset(&ctx, 0, sizeof(ctx));
    ctx.fo = &fo; ctx.cache = &cache; ctx.transport = mock_transport;
    ctx.transport_ud = &m; ctx.store_form = CVMFS_STORE_COMPRESSED;
    ctx.scratch = scratch; ctx.scratch_cap = sizeof(scratch);

    /* success: good stored; miss + tampered both counted for fallback (the
     * tampered copy arrives after the good one is cached, so the cas_has
     * fast path must NOT let it masquerade as stored=2). */
    unsigned stored = 0, fb = 0;
    int rc = cvmfs_bundle_ingest(&ctx, stream, off, &stored, &fb);
    CHECK(rc == 0 && stored == 2 && fb == 1,
          "ingest: good stored, tampered-after-cached is a cache hit, miss falls back");

    /* ...so run tampered-FIRST against a fresh cache: must be rejected. */
    char root2[] = "/tmp/brix_bundle_ut.XXXXXX";
    if (mkdtemp(root2) != NULL) {
        unsigned char s2[16384];
        cvmfs_bundle_hdr_encode(s2, 1);
        size_t o2 = bundle_add(s2, CVMFS_BUNDLE_HDR_LEN, &hg, tampered, cn);
        brix_cas_store_t cache2; brix_cas_init(&cache2, root2, 0);
        ctx.cache = &cache2;
        unsigned st2 = 9, fb2 = 9;
        int rc2 = cvmfs_bundle_ingest(&ctx, s2, o2, &st2, &fb2);
        char key[160]; cvmfs_hash_to_hex(&hg, 0, key, sizeof(key));
        CHECK(rc2 == 0 && st2 == 0 && fb2 == 1 && !brix_cas_has(&cache2, key),
              "ingest: tampered member rejected, never cached");   /* security-neg */
        ctx.cache = &cache;
        rm_rf(root2);
    }

    /* the bundled-in object now serves as a normal cache hit — no transport. */
    m.fail_if_called = 1; m.was_called = 0;
    unsigned char out[4096]; size_t on = 0;
    int frc = cvmfs_fetch_object(&ctx, &hg, 0, out, sizeof(out), &on, 3000);
    CHECK(frc == 0 && on == pn && memcmp(out, plain, pn) == 0 && m.was_called == 0,
          "bundled object is a verified single-fetch cache hit");
    m.fail_if_called = 0;

    /* malformed frame: truncated mid-member → -1, counts zeroed. */
    unsigned st3 = 9, fb3 = 9;
    CHECK(cvmfs_bundle_ingest(&ctx, stream, off - 3, &st3, &fb3) == -1
          && st3 == 0 && fb3 == 0, "truncated frame rejected whole");   /* neg */

    /* non-CAS member path (traversal shape) → not stored, counted fallback. */
    unsigned char s3[4096];
    cvmfs_bundle_hdr_encode(s3, 1);
    const char *evil_path = "../../etc/passwd";
    int w3 = cvmfs_bundle_item_encode(s3 + CVMFS_BUNDLE_HDR_LEN, 4096,
                                      evil_path, strlen(evil_path), cn);
    size_t o3 = CVMFS_BUNDLE_HDR_LEN + (size_t) w3;
    memcpy(s3 + o3, cz, cn); o3 += cn;
    unsigned st4 = 9, fb4 = 9;
    CHECK(cvmfs_bundle_ingest(&ctx, s3, o3, &st4, &fb4) == 0
          && st4 == 0 && fb4 == 1, "non-CAS path skipped");   /* security-neg */

    free(cz); free(tampered);
    rm_rf(root);
}

int main(void) {
    test_object();
    test_fetch();
    test_bundle_ingest();
    printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}

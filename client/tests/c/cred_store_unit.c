/* client/tests/c/cred_store_unit.c
 *
 * WHAT: Unit tests for the credential store core (cred.c): registry, cache,
 *       expiry gate, and refresh machinery — exercised against a deterministic
 *       stub S3-keys handler that overrides the weak accessor in cred.c.
 * WHY:  The store-core cases (success+cache, missing-handler, expiry+refresh)
 *       need a controllable stub handler.  cred_unit.c now links the REAL
 *       cred_s3.c (B6), so a stub `brix_cred_s3keys()` cannot coexist with the
 *       real one in the same binary.  This file is the isolated home for the
 *       stub-driven store-core tests; it links ONLY cred.c + status.c and the
 *       in-file stub so there is exactly ONE strong `brix_cred_s3keys`.
 * HOW:  Strong `brix_cred_s3keys()` here overrides the weak one in cred.c.
 *       No real per-kind handlers are linked (x509/bearer/sss/krb5 are absent);
 *       test_missing_handler uses XRDC_CRED_KIND_COUNT (out-of-range) to exercise
 *       the bounds-guard path rather than relying on a weak-NULL accessor.
 *
 * Build+run:
 *   cd /home/rcurrie/HEP-x/nginx-xrootd/client
 *   gcc -std=c11 -D_GNU_SOURCE -DXRDPROTO_NO_NGX \
 *       -I lib -I ../src \
 *       tests/c/cred_store_unit.c lib/cred.c lib/status.c \
 *       ../shared/xrdproto/libxrdproto.a -lssl -lcrypto \
 *       -o /tmp/cred_store_unit && /tmp/cred_store_unit
 */

#include "cred.h"
#include "brix.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* stub state */
static int     s_available_val   = 1;     /* what stub available() returns       */
static int     s_acquire_count   = 0;     /* total acquire() calls               */
static int     s_refresh_count   = 0;     /* total refresh() calls               */
static int64_t s_not_after_delta = 0;     /* not_after = now + delta (0=no exp)  */

static int
stub_available(const brix_cred_config *cfg)
{
    (void)cfg;
    return s_available_val;
}

static int
stub_acquire(const brix_cred_config *cfg, brix_cred_view *out,
             int64_t *not_after, brix_status *st)
{
    (void)cfg; (void)st;
    s_acquire_count++;
    out->kind      = XRDC_CRED_S3KEYS;
    out->path      = NULL;
    out->token     = NULL;
    out->s3_access = "AKIA_STUB";
    out->s3_secret = "stub_secret";
    out->not_after = 0;
    if (s_not_after_delta != 0) {
        *not_after = (int64_t)time(NULL) + s_not_after_delta;
    } else {
        *not_after = 0;
    }
    return 0;
}

static int
stub_refresh(const brix_cred_config *cfg, brix_status *st)
{
    (void)cfg; (void)st;
    s_refresh_count++;
    return 0;
}

static const brix_cred_handler s_stub_handler = {
    .kind      = XRDC_CRED_S3KEYS,
    .available = stub_available,
    .acquire   = stub_acquire,
    .refresh   = stub_refresh,
};

/*
 * brix_cred_s3keys — strong override of the weak accessor in cred.c.
 *
 * WHAT: returns the deterministic stub handler for XRDC_CRED_S3KEYS.
 * WHY:  this binary links without the real cred_s3.c; the stub provides
 *       controllable behaviour for store-core (cache/expiry/refresh) tests.
 * HOW:  strong definition; linker prefers it over the weak symbol in cred.c.
 */
const brix_cred_handler *
brix_cred_s3keys(void)
{
    return &s_stub_handler;
}

/* helpers */
static void
reset_stub(int available_val, int64_t not_after_delta)
{
    s_available_val   = available_val;
    s_acquire_count   = 0;
    s_refresh_count   = 0;
    s_not_after_delta = not_after_delta;
}

/* test 1: success path + cache */
/*
 * test_success_and_cache — handler present + available → acquire returns keys;
 * second acquire returns cached result (acquire-count stays 1).
 */
static void
test_success_and_cache(void)
{
    reset_stub(1, 0);

    brix_cred_config cfg = {0};
    brix_cred_store *s   = brix_cred_store_new(&cfg);
    assert(s != NULL);

    assert(brix_cred_available(s, XRDC_CRED_S3KEYS) == 1);

    brix_status    st = {0};
    brix_cred_view v  = {0};

    int rc = brix_cred_acquire(s, XRDC_CRED_S3KEYS, 0, &v, &st);
    assert(rc == 0);
    assert(v.s3_access != NULL && strcmp(v.s3_access, "AKIA_STUB") == 0);
    assert(v.s3_secret != NULL && strcmp(v.s3_secret, "stub_secret") == 0);
    assert(s_acquire_count == 1);

    /* second acquire — must hit cache; acquire-count must NOT increment */
    brix_cred_view v2 = {0};
    rc = brix_cred_acquire(s, XRDC_CRED_S3KEYS, 0, &v2, &st);
    assert(rc == 0);
    assert(s_acquire_count == 1);   /* still 1 — served from cache */
    assert(strcmp(v2.s3_access, "AKIA_STUB") == 0);

    brix_cred_store_free(s);
    printf("test_success_and_cache: PASS\n");
}

/* test 2: invalid-kind error */
/*
 * test_missing_handler — an out-of-range kind (XRDC_CRED_KIND_COUNT) has no
 * handler by construction → available()==0 and acquire()==-1 with st set.
 *
 * NOTE: all real handlers are absent in this binary (only the stub s3keys is
 * present), but XRDC_CRED_KIND_COUNT is always out-of-range regardless.
 */
static void
test_missing_handler(void)
{
    brix_cred_config cfg = {0};
    brix_cred_store *s   = brix_cred_store_new(&cfg);
    assert(s != NULL);

    /* XRDC_CRED_KIND_COUNT is one past the last valid kind — always out-of-range */
    assert(brix_cred_available(s, (brix_cred_kind)XRDC_CRED_KIND_COUNT) == 0);

    brix_status    st = {0};
    brix_cred_view v  = {0};
    int rc = brix_cred_acquire(s, (brix_cred_kind)XRDC_CRED_KIND_COUNT, 0, &v, &st);
    assert(rc == -1);
    assert(st.kxr != 0);         /* XRDC_EAUTH or XRDC_EUSAGE — both non-zero */
    assert(st.msg[0] != '\0');   /* must have a message                        */

    brix_cred_store_free(s);
    printf("test_missing_handler: PASS\n");
}

/* test 3: expiry + refresh gate */
/*
 * test_expiry_and_refresh — with auto_refresh=1 and a credential expiring in
 * 30s, a min_remaining_s=60 request triggers refresh+re-acquire; with
 * auto_refresh=0 it does NOT.
 */
static void
test_expiry_and_refresh(void)
{
    /* sub-test 3a: auto_refresh=1 triggers refresh when near expiry */
    reset_stub(1, 30 /* expires in 30s */);

    brix_cred_config cfg = { .auto_refresh = 1 };
    brix_cred_store *s   = brix_cred_store_new(&cfg);
    assert(s != NULL);

    brix_status    st = {0};
    brix_cred_view v  = {0};

    /* prime the cache */
    int rc = brix_cred_acquire(s, XRDC_CRED_S3KEYS, 0, &v, &st);
    assert(rc == 0);
    assert(s_acquire_count == 1);
    assert(s_refresh_count == 0);

    /* request with min_remaining_s=60 — credential expires in 30s → refresh */
    rc = brix_cred_acquire(s, XRDC_CRED_S3KEYS, 60, &v, &st);
    assert(rc == 0);
    assert(s_refresh_count == 1);   /* refresh was called   */
    assert(s_acquire_count == 2);   /* re-acquire after refresh */

    brix_cred_store_free(s);

    /* sub-test 3b: auto_refresh=0 does NOT trigger refresh even near expiry */
    reset_stub(1, 30 /* expires in 30s */);

    brix_cred_config cfg2 = { .auto_refresh = 0 };
    brix_cred_store *s2   = brix_cred_store_new(&cfg2);
    assert(s2 != NULL);

    brix_status    st2 = {0};
    brix_cred_view v2  = {0};

    rc = brix_cred_acquire(s2, XRDC_CRED_S3KEYS, 0, &v2, &st2);
    assert(rc == 0);
    assert(s_acquire_count == 1);

    rc = brix_cred_acquire(s2, XRDC_CRED_S3KEYS, 60, &v2, &st2);
    assert(rc == 0);
    assert(s_refresh_count == 0);   /* NO refresh with auto_refresh=0 */
    assert(s_acquire_count == 1);   /* NO re-acquire either             */

    brix_cred_store_free(s2);
    printf("test_expiry_and_refresh: PASS\n");
}

/* main */
int
main(void)
{
    test_success_and_cache();
    test_missing_handler();
    test_expiry_and_refresh();
    printf("cred_store_unit: all tests PASS\n");
    return 0;
}

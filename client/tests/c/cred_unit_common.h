/* client/tests/c/cred_unit_common.h — shared assertion helpers for the
 * credential-store unit binaries (cred_unit + its shard, cli_cred_unit).
 * Header-only so no build registration is needed. */
#ifndef CRED_UNIT_COMMON_H
#define CRED_UNIT_COMMON_H

#include "cred.h"   /* via TEST_INC -Ilib/auth/cred (client/Makefile) */

#include <assert.h>
#include <string.h>

/* Assert availability of `kind` is `expect_avail`, then run one acquire into
 * *v / *st (both zeroed here) and return its rc. */
static inline int
cred_acquire_kind(brix_cred_store *s, brix_cred_kind kind, int expect_avail,
                  brix_cred_view *v, brix_status *st)
{
    assert(s != NULL);
    assert(brix_cred_available(s, kind) == expect_avail);
    memset(v, 0, sizeof(*v));
    memset(st, 0, sizeof(*st));
    return brix_cred_acquire(s, kind, 0, v, st);
}

/* acquire(kind) on an unavailable credential must fail with `kxr` and a
 * non-empty message; when needle != NULL the message must mention it. */
static inline void
cred_expect_refusal(brix_cred_store *s, brix_cred_kind kind, int kxr,
                    const char *needle)
{
    brix_cred_view v;
    brix_status    st;

    assert(cred_acquire_kind(s, kind, 0, &v, &st) == -1);
    assert(st.kxr == kxr);
    assert(st.msg[0] != '\0');
    assert(needle == NULL || strstr(st.msg, needle) != NULL);
}

/* acquire(kind) on an available path-backed credential (x509 proxy, SSS
 * keytab) must succeed with view.path == want.  Frees the store; returns
 * view.not_after for the caller to assert on. */
static inline int64_t
cred_expect_path(brix_cred_store *s, brix_cred_kind kind, const char *want)
{
    brix_cred_view v;
    brix_status    st;

    assert(cred_acquire_kind(s, kind, 1, &v, &st) == 0);
    assert(v.path != NULL && strcmp(v.path, want) == 0);
    brix_cred_store_free(s);
    return v.not_after;
}

/* acquire(BEARER) on an available token must succeed with view.token == want.
 * Frees the store; returns view.not_after for the caller to assert on. */
static inline int64_t
cred_expect_bearer(brix_cred_store *s, const char *want)
{
    brix_cred_view v;
    brix_status    st;

    assert(cred_acquire_kind(s, XRDC_CRED_BEARER, 1, &v, &st) == 0);
    assert(v.token != NULL && strcmp(v.token, want) == 0);
    brix_cred_store_free(s);
    return v.not_after;
}

/* acquire(S3KEYS) on an available key pair must succeed with the exact
 * access/secret values.  Frees the store; returns view.not_after. */
static inline int64_t
cred_expect_s3keys(brix_cred_store *s, const char *acc, const char *sec)
{
    brix_cred_view v;
    brix_status    st;

    assert(cred_acquire_kind(s, XRDC_CRED_S3KEYS, 1, &v, &st) == 0);
    assert(v.s3_access != NULL && strcmp(v.s3_access, acc) == 0);
    assert(v.s3_secret != NULL && strcmp(v.s3_secret, sec) == 0);
    brix_cred_store_free(s);
    return v.not_after;
}

#endif /* CRED_UNIT_COMMON_H */

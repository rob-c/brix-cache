/* client/tests/c/vfs_s3_creds_unit.c
 *
 * WHAT: Unit coverage for s3_creds_load() (lib/fs/backend/s3/vfs_s3_http.c) —
 *       phase-92 task C2, wiring the client credential store into the VFS S3
 *       backend so a private bucket signs SigV4 with CLI/.aws/.s3cfg keys, not
 *       just $AWS_* (or anonymous).
 * WHY:  Before phase-92 s3_creds_load() ignored opts and read only $AWS_*; the
 *       fully-featured brix_cred_s3keys() handler was never consumed by the VFS
 *       backend, so `xrdcp --s3-access ... s3://...` still signed anonymously.
 * HOW:  Overrides the weak brix_cred_s3keys() accessor with a controllable stub
 *       (same technique as cred_store_unit.c) so the store returns deterministic
 *       keys, then drives s3_creds_load() and inspects the loaded vfs_s3_file.
 *
 * Cases:
 *   success:      a store carrying a complete access/secret pair lands both into
 *                 the file, overriding any $AWS_* in the environment.
 *   edge:         opts->cred == NULL falls back to $AWS_*; region defaults when
 *                 $AWS_DEFAULT_REGION is unset.
 *   security-neg: a partial store result (access present, secret NULL) does NOT
 *                 mix the store access key with the env secret — it falls back to
 *                 the $AWS_* pair wholesale, so the request is never mis-signed.
 *
 * Build+run (see client/Makefile CLIENT_UNIT_TESTS):
 *   cc $(ALL_CFLAGS) $(TEST_INC) tests/c/vfs_s3_creds_unit.c \
 *      $(CLIENT_LIB) $(PROTO_LIB) $(LDLIBS) -o bin/vfs_s3_creds_unit && bin/vfs_s3_creds_unit
 */

#include "cred.h"
#include "brix.h"
#include "fs/backend/s3/vfs_s3_internal.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* stub state — 0=unavailable, 1=complete pair, 2=access-only (secret NULL) */
static int s_mode = 1;

static int
stub_available(const brix_cred_config *cfg)
{
    (void)cfg;
    return s_mode != 0;
}

static int
stub_acquire(const brix_cred_config *cfg, brix_cred_view *out,
             int64_t *not_after, brix_status *st)
{
    (void)cfg; (void)st;
    if (s_mode == 0) {
        return -1;
    }
    out->kind      = XRDC_CRED_S3KEYS;
    out->path      = NULL;
    out->token     = NULL;
    out->s3_access = "AKIA_STORE";
    out->s3_secret = (s_mode == 2) ? NULL : "store_secret";
    out->not_after = 0;
    *not_after     = 0;
    return 0;
}

static int
stub_refresh(const brix_cred_config *cfg, brix_status *st)
{
    (void)cfg; (void)st;
    return 0;
}

static const brix_cred_handler s_stub_handler = {
    .kind      = XRDC_CRED_S3KEYS,
    .available = stub_available,
    .acquire   = stub_acquire,
    .refresh   = stub_refresh,
};

/* strong override of the weak accessor in cred.c (this binary omits cred_s3.c) */
const brix_cred_handler *
brix_cred_s3keys(void)
{
    return &s_stub_handler;
}

/* success: a complete store pair wins over the environment. */
static void
test_store_pair_wins(void)
{
    s_mode = 1;
    setenv("AWS_ACCESS_KEY_ID", "AKIA_ENV", 1);
    setenv("AWS_SECRET_ACCESS_KEY", "env_secret", 1);
    setenv("AWS_DEFAULT_REGION", "eu-west-2", 1);

    brix_cred_config cfg = {0};
    brix_cred_store *s   = brix_cred_store_new(&cfg);
    assert(s != NULL);

    vfs_s3_file sf = {0};
    brix_vfs_open_opts opts = {0};
    opts.cred = s;

    s3_creds_load(&sf, &opts);
    assert(strcmp(sf.ak, "AKIA_STORE") == 0);
    assert(strcmp(sf.sk, "store_secret") == 0);
    assert(strcmp(sf.region, "eu-west-2") == 0);   /* region still from env */

    brix_cred_store_free(s);
    printf("  ok: store pair overrides env\n");
}

/* edge: no store → env fallback; unset region defaults. */
static void
test_null_cred_env_fallback(void)
{
    setenv("AWS_ACCESS_KEY_ID", "AKIA_ENV", 1);
    setenv("AWS_SECRET_ACCESS_KEY", "env_secret", 1);
    unsetenv("AWS_DEFAULT_REGION");

    vfs_s3_file sf = {0};
    brix_vfs_open_opts opts = {0};
    opts.cred = NULL;

    s3_creds_load(&sf, &opts);
    assert(strcmp(sf.ak, "AKIA_ENV") == 0);
    assert(strcmp(sf.sk, "env_secret") == 0);
    assert(strcmp(sf.region, S3_REGION_DEFAULT) == 0);

    printf("  ok: NULL cred falls back to env + default region\n");
}

/* security-neg: a partial store result must NOT mix store access with env secret;
 * it falls back to the env pair wholesale (never a mis-signed request). */
static void
test_partial_store_no_key_mixing(void)
{
    s_mode = 2;   /* store yields access only, secret NULL */
    setenv("AWS_ACCESS_KEY_ID", "AKIA_ENV", 1);
    setenv("AWS_SECRET_ACCESS_KEY", "env_secret", 1);

    brix_cred_config cfg = {0};
    brix_cred_store *s   = brix_cred_store_new(&cfg);
    assert(s != NULL);

    vfs_s3_file sf = {0};
    brix_vfs_open_opts opts = {0};
    opts.cred = s;

    s3_creds_load(&sf, &opts);
    /* MUST fall back to env as a pair: store's AKIA_STORE must NOT appear. */
    assert(strcmp(sf.ak, "AKIA_ENV") == 0);
    assert(strcmp(sf.sk, "env_secret") == 0);

    brix_cred_store_free(s);
    printf("  ok: partial store result does not mix keys (env pair used)\n");
}

int
main(void)
{
    printf("vfs_s3_creds_unit:\n");
    test_store_pair_wins();
    test_null_cred_env_fallback();
    test_partial_store_no_key_mixing();
    printf("vfs_s3_creds_unit: ALL PASS\n");
    return 0;
}

/* client/tests/c/cli_cred_unit.c
 *
 * WHAT: Unit tests for xrdc_cli_cred_store_build (cli_cred.c): the builder
 *       that maps per-tool CLI values into an xrdc_cred_store without requiring
 *       callers to know xrdc_cred_config field names.
 * WHY:  Three tests — success/mapping, env-fallback, and precedence — prove
 *       that (a) explicit args reach the store, (b) NULL/empty args fall back
 *       to env/default discovery, and (c) a CLI-supplied literal overrides the
 *       environment, matching the invariants documented in cli_cred.c.
 * HOW:  Calls xrdc_cli_cred_store_build directly (no server), isolates the
 *       environment before each test, and inspects via xrdc_cred_available +
 *       xrdc_cred_acquire.  Pattern matches client/tests/c/cred_unit.c.
 *
 * Build+run (from the client/ directory):
 *   HAVE_KRB5=$(pkg-config --exists krb5 2>/dev/null && echo yes)
 *   KRB5_FLAGS=$([ "$HAVE_KRB5" = yes ] && pkg-config --cflags --libs krb5)
 *   gcc -std=c11 -D_GNU_SOURCE -DXRDPROTO_NO_NGX \
 *       $([ "$HAVE_KRB5" = yes ] && echo -DXROOTD_HAVE_KRB5) \
 *       -I lib -I ../src \
 *       tests/c/cli_cred_unit.c lib/cli_cred.c \
 *       lib/cred.c lib/cred_x509.c lib/cred_bearer.c \
 *       lib/cred_sss.c lib/cred_krb5.c lib/cred_s3.c \
 *       lib/status.c lib/sss_keytab.c lib/path.c \
 *       lib/sec/sec_token.c lib/credinfo.c lib/proxy.c \
 *       $KRB5_FLAGS \
 *       ../shared/xrdproto/libxrdproto.a -lssl -lcrypto \
 *       -o /tmp/cli_cred_unit && /tmp/cli_cred_unit
 */

#include "cred.h"     /* xrdc_cred_store, xrdc_cred_available, xrdc_cred_acquire,
                         xrdc_cred_store_free — and pulls in xrdc.h which has
                         xrdc_cli_cred_store_build + xrdc_cred_store_free decls */
#include "xrdc.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>   /* rmdir */

/* Test 1: success/mapping */
/*
 * test_builder_s3keys_success — explicit s3_access/s3_secret args reach store.
 *
 * WHAT: call the builder with s3_access/s3_secret strings (other args NULL);
 *       confirm XRDC_CRED_S3KEYS is available and acquire returns exactly those
 *       values.
 * WHY:  proves the builder correctly populates cfg.s3_access/s3_secret and that
 *       xrdc_cred_store_new picks them up at the highest-precedence level.
 * HOW:  unset both AWS env vars so only the cfg values can satisfy the probe;
 *       also point $HOME at an empty temp dir so ~/.aws/credentials is absent.
 *       Assert available()==1 and acquire returns the expected strings.
 *       Restore HOME and env after the test.
 */
static void
test_builder_s3keys_success(void)
{
    const char *orig_home = getenv("HOME");
    char tmphome[] = "/tmp/cli_cred_unit_home_XXXXXX";
    assert(mkdtemp(tmphome) != NULL);

    unsetenv("AWS_ACCESS_KEY_ID");
    unsetenv("AWS_SECRET_ACCESS_KEY");
    setenv("HOME", tmphome, 1);

    const char *ak = "AKIA_CLI_CRED_TEST_01";
    const char *sk = "cli_cred_test_secret_xyz";

    struct xrdc_cred_store *s =
        xrdc_cli_cred_store_build(NULL, NULL, NULL, ak, sk, NULL, 0);
    assert(s != NULL);

    assert(xrdc_cred_available(s, XRDC_CRED_S3KEYS) == 1);

    xrdc_status    st = {0};
    xrdc_cred_view v  = {0};
    int rc = xrdc_cred_acquire(s, XRDC_CRED_S3KEYS, 0, &v, &st);
    assert(rc == 0);
    assert(v.s3_access != NULL && strcmp(v.s3_access, ak) == 0);
    assert(v.s3_secret != NULL && strcmp(v.s3_secret, sk) == 0);

    xrdc_cred_store_free(s);

    if (orig_home != NULL) {
        setenv("HOME", orig_home, 1);
    } else {
        unsetenv("HOME");
    }
    rmdir(tmphome);
    printf("test_builder_s3keys_success: PASS\n");
}

/* Test 2: env-fallback */
/*
 * test_builder_env_fallback — NULL/empty args fall back to env discovery.
 *
 * WHAT: call the builder with ALL NULL args, but set AWS env vars; confirm
 *       XRDC_CRED_S3KEYS is available (discovered from the environment) even
 *       though no cfg fields were populated.
 * WHY:  proves that the NULL/empty guard in the builder leaves the cfg fields
 *       at NULL, which triggers per-handler env discovery — preserving today's
 *       unmodified discovery path when no CLI flags are supplied.
 * HOW:  set both AWS env vars; call builder with all-NULL; assert available==1
 *       and acquire returns the env values.  Unset after the test.
 */
static void
test_builder_env_fallback(void)
{
    const char *acc = "AKIA_ENV_FALLBACK_02";
    const char *sec = "env_fallback_secret_02";

    setenv("AWS_ACCESS_KEY_ID",     acc, 1);
    setenv("AWS_SECRET_ACCESS_KEY", sec, 1);

    /* All args NULL/empty — builder populates no cfg fields. */
    struct xrdc_cred_store *s =
        xrdc_cli_cred_store_build(NULL, NULL, NULL, NULL, NULL, NULL, 0);
    assert(s != NULL);

    /* The env fallback must still be discovered. */
    assert(xrdc_cred_available(s, XRDC_CRED_S3KEYS) == 1);

    xrdc_status    st = {0};
    xrdc_cred_view v  = {0};
    int rc = xrdc_cred_acquire(s, XRDC_CRED_S3KEYS, 0, &v, &st);
    assert(rc == 0);
    assert(v.s3_access != NULL && strcmp(v.s3_access, acc) == 0);
    assert(v.s3_secret != NULL && strcmp(v.s3_secret, sec) == 0);

    xrdc_cred_store_free(s);

    unsetenv("AWS_ACCESS_KEY_ID");
    unsetenv("AWS_SECRET_ACCESS_KEY");
    printf("test_builder_env_fallback: PASS\n");
}

/* Test 3: precedence (bearer literal overrides env) */
/*
 * test_builder_bearer_precedence — a bearer literal arg beats $BEARER_TOKEN.
 *
 * WHAT: set $BEARER_TOKEN to one value; call the builder with a different
 *       bearer literal; confirm acquire returns the literal (CLI beats env).
 * WHY:  proves that a CLI-supplied override reaches cfg.bearer_literal, which
 *       the bearer handler places at higher precedence than $BEARER_TOKEN —
 *       the same invariant exercised by test_bearer_literal_precedence in
 *       cred_unit.c, but now verified through the builder abstraction.
 * HOW:  setenv BEARER_TOKEN to an env string; call builder with a distinct
 *       literal; assert acquire returns the literal, not the env string.
 *       Unsetenv after.
 */
static void
test_builder_bearer_precedence(void)
{
    const char *env_tok = "env-bearer-token-should-lose";
    const char *cli_tok = "cli-bearer-override-should-win";

    setenv("BEARER_TOKEN", env_tok, 1);
    unsetenv("BEARER_TOKEN_FILE");

    struct xrdc_cred_store *s =
        xrdc_cli_cred_store_build(NULL, cli_tok, NULL, NULL, NULL, NULL, 0);
    assert(s != NULL);

    assert(xrdc_cred_available(s, XRDC_CRED_BEARER) == 1);

    xrdc_status    st = {0};
    xrdc_cred_view v  = {0};
    int rc = xrdc_cred_acquire(s, XRDC_CRED_BEARER, 0, &v, &st);
    assert(rc == 0);
    assert(v.token != NULL);
    /* The CLI literal must win over $BEARER_TOKEN. */
    assert(strcmp(v.token, cli_tok) == 0);
    assert(strcmp(v.token, env_tok) != 0);

    xrdc_cred_store_free(s);

    unsetenv("BEARER_TOKEN");
    printf("test_builder_bearer_precedence: PASS\n");
}

/* main */
int
main(void)
{
    test_builder_s3keys_success();
    test_builder_env_fallback();
    test_builder_bearer_precedence();
    printf("cli_cred_unit: all tests PASS\n");
    return 0;
}

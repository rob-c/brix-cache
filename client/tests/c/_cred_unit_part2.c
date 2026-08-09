/* _cred_unit_part2.c — fragment 2 of cred_unit.c (auto-split).
 * Do not compile directly; it is #included by cred_unit.c. */
#ifndef _CRED_UNIT_PART2_C_INC
#define _CRED_UNIT_PART2_C_INC
#ifndef __CRED_UNIT_C_COMPILED__
/* client/tests/c/cred_unit.c
 *
 * WHAT: Unit tests for all REAL per-kind credential handlers (B3-B6):
 *       X.509 proxy, bearer token, SSS keytab, Kerberos ccache, and S3 keys.
 * WHY:  Each handler is validated against real env vars, temp files, and missing
 *       paths.  The store-core cases (cache/expiry/refresh) that need a
 *       controllable stub live in cred_store_unit.c to avoid a duplicate-symbol
 *       link error with the real brix_cred_s3keys() defined in cred_s3.c.
 *       The X509 cases (B3) test path discovery.  The bearer cases (B4) test
 *       token discovery.  The SSS cases (B5) test keytab resolution and error
 *       paths.  The krb5 cases (B5) test ccache error paths; a live TGT positive
 *       test is deferred to tests/test_krb5_auth.py (requires a KDC harness).
 *       The S3 cases (B6) test env + cfg precedence and the missing-creds path.
 * HOW:  All five handlers are linked REAL (cred_x509.c, cred_bearer.c,
 *       cred_sss.c, cred_krb5.c, cred_s3.c).  test_missing_handler tests an
 *       out-of-range kind (XRDC_CRED_KIND_COUNT) since all five are present.
 *
 * Build+run:
 *   cd /home/rcurrie/HEP-x/nginx-xrootd/client
 *   HAVE_KRB5=$(pkg-config --exists krb5 2>/dev/null && echo yes)
 *   KRB5_FLAGS=$([ "$HAVE_KRB5" = yes ] && pkg-config --cflags --libs krb5)
 *   gcc -std=c11 -D_GNU_SOURCE -DXRDPROTO_NO_NGX \
 *       $([ "$HAVE_KRB5" = yes ] && echo -DBRIX_HAVE_KRB5) \
 *       -I lib -I ../src \
 *       tests/c/cred_unit.c lib/cred.c lib/cred_x509.c lib/cred_bearer.c \
 *       lib/cred_sss.c lib/cred_krb5.c lib/cred_s3.c lib/status.c \
 *       lib/sss_keytab.c lib/path.c lib/sec/sec_token.c \
 *       lib/credinfo.c lib/proxy.c \
 *       $KRB5_FLAGS \
 *       ../shared/xrdproto/libxrdproto.a -lssl -lcrypto \
 *       -o /tmp/cred_unit && /tmp/cred_unit
 */

#include "cred.h"
#include "sss_keytab.h"
#include "brix.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>

/* X509 tests (use real cred_x509.c) */
#endif /* __CRED_UNIT_C_COMPILED__ */

/*
 * test_krb5_null_accessor — when BRIX_HAVE_KRB5 is NOT defined, the accessor
 * must return NULL so the store treats KRB5 as absent.
 *
 * WHAT: assert brix_cred_krb5() == NULL in the stub build.
 * WHY:  mirrors the contract in cred.h: "NULL when compiled out".
 * HOW:  compile-time branch: in the stub case assert NULL; in the real case skip
 *       (the accessor returns a real handler pointer, so != NULL is expected).
 */
static void
test_krb5_null_accessor(void)
{
#ifndef BRIX_HAVE_KRB5
    assert(brix_cred_krb5() == NULL);
    printf("test_krb5_null_accessor: PASS (krb5 compiled out)\n");
#else
    /* BRIX_HAVE_KRB5 is defined: accessor returns a real handler, not NULL. */
    assert(brix_cred_krb5() != NULL);
    printf("test_krb5_null_accessor: PASS (real krb5 handler present)\n");
#endif
}

/* S3 keys tests (use real cred_s3.c) */
/*
 * test_s3keys_env_success — both AWS env vars set → available()==1 and
 * acquire() returns those exact key values.
 *
 * WHAT: set $AWS_ACCESS_KEY_ID and $AWS_SECRET_ACCESS_KEY; confirm the handler
 *       discovers them and the store returns correct s3_access / s3_secret.
 * WHY:  proves the environment discovery path and that the store deep-copies
 *       both key strings independently of the handler's static buffer.
 * HOW:  setenv both vars (overriding any ~/.aws interference); acquire; assert
 *       values match; unsetenv both after the test.
 */
static void
test_s3keys_env_success(void)
{
    const char *acc = "AKIAIOSFODNN7TEST01";
    const char *sec = "wJalrXUtnFEMI/K7MDENG/test01SecretKey";

    setenv("AWS_ACCESS_KEY_ID",     acc, 1);
    setenv("AWS_SECRET_ACCESS_KEY", sec, 1);

    brix_cred_config cfg  = {0};
    brix_cred_store *s    = brix_cred_store_new(&cfg);
    assert(s != NULL);

    assert(brix_cred_available(s, XRDC_CRED_S3KEYS) == 1);

    brix_status    st = {0};
    brix_cred_view v  = {0};
    int rc = brix_cred_acquire(s, XRDC_CRED_S3KEYS, 0, &v, &st);
    assert(rc == 0);
    assert(v.s3_access != NULL && strcmp(v.s3_access, acc) == 0);
    assert(v.s3_secret != NULL && strcmp(v.s3_secret, sec) == 0);
    assert(v.not_after == 0);   /* static keys have no per-use expiry */

    brix_cred_store_free(s);
    unsetenv("AWS_ACCESS_KEY_ID");
    unsetenv("AWS_SECRET_ACCESS_KEY");
    printf("test_s3keys_env_success: PASS\n");
}

/*
 * test_s3keys_missing — no credentials available → available()==0, acquire==-1.
 *
 * WHAT: unset both env vars AND redirect $HOME to an empty temp dir (so
 *       ~/.aws/credentials is absent); confirm the handler returns -1 +
 *       XRDC_EAUTH in st.
 * WHY:  exercises the no-credentials error branch of available() and acquire().
 * HOW:  mkdtemp for an isolated $HOME with no ~/.aws subtree; setenv HOME to
 *       that dir; unset both AWS env vars; assert failure; restore env; rmdir.
 */
static void
test_s3keys_missing(void)
{
    const char *orig_home = getenv("HOME");
    char tmphome[] = "/tmp/brix_s3test_home_XXXXXX";

    assert(mkdtemp(tmphome) != NULL);

    unsetenv("AWS_ACCESS_KEY_ID");
    unsetenv("AWS_SECRET_ACCESS_KEY");
    setenv("HOME", tmphome, 1);

    brix_cred_config cfg = {0};
    brix_cred_store *s   = brix_cred_store_new(&cfg);
    assert(s != NULL);

    assert(brix_cred_available(s, XRDC_CRED_S3KEYS) == 0);

    brix_status    st = {0};
    brix_cred_view v  = {0};
    int rc = brix_cred_acquire(s, XRDC_CRED_S3KEYS, 0, &v, &st);
    assert(rc == -1);
    assert(st.kxr == XRDC_EAUTH);
    assert(st.msg[0] != '\0');

    brix_cred_store_free(s);

    /* Restore env */
    if (orig_home != NULL) {
        setenv("HOME", orig_home, 1);
    } else {
        unsetenv("HOME");
    }
    rmdir(tmphome);
    printf("test_s3keys_missing: PASS\n");
}

/*
 * test_s3keys_cfg_precedence — cfg->s3_access/s3_secret beat the env vars.
 *
 * WHAT: set $AWS_ACCESS_KEY_ID and $AWS_SECRET_ACCESS_KEY to one pair; set
 *       cfg->s3_access/s3_secret to a different pair; confirm acquire() returns
 *       the cfg values (highest discovery precedence).
 * WHY:  CLI flag (--s3-access/--s3-secret) must override environment variables.
 * HOW:  setenv both env vars; cfg.s3_access/s3_secret to distinct values;
 *       assert view.s3_access == cfg value; unsetenv after.
 */
static void
test_s3keys_cfg_precedence(void)
{
    const char *env_acc = "AKIA_ENV_KEY_001";
    const char *env_sec = "env_secret_000";
    const char *cfg_acc = "AKIA_CFG_KEY_999";
    const char *cfg_sec = "cfg_secret_999";

    setenv("AWS_ACCESS_KEY_ID",     env_acc, 1);
    setenv("AWS_SECRET_ACCESS_KEY", env_sec, 1);

    brix_cred_config cfg = {0};
    cfg.s3_access = cfg_acc;   /* explicit override beats env */
    cfg.s3_secret = cfg_sec;

    brix_cred_store *s = brix_cred_store_new(&cfg);
    assert(s != NULL);

    assert(brix_cred_available(s, XRDC_CRED_S3KEYS) == 1);

    brix_status    st = {0};
    brix_cred_view v  = {0};
    int rc = brix_cred_acquire(s, XRDC_CRED_S3KEYS, 0, &v, &st);
    assert(rc == 0);
    assert(v.s3_access != NULL && strcmp(v.s3_access, cfg_acc) == 0);
    assert(v.s3_secret != NULL && strcmp(v.s3_secret, cfg_sec) == 0);

    brix_cred_store_free(s);
    unsetenv("AWS_ACCESS_KEY_ID");
    unsetenv("AWS_SECRET_ACCESS_KEY");
    printf("test_s3keys_cfg_precedence: PASS\n");
}

/*
 * test_s3keys_file_success — ~/.aws/credentials [default] section discovered.
 *
 * WHAT: create a minimal credentials file under a temp $HOME with a [defaultx]
 *       section both before and after the real [default] section; confirm
 *       available()==1 and acquire() returns the [default] keys only.
 * WHY:  the ~/.aws/credentials path had zero positive coverage; also directly
 *       exercises Fix 1 (exact header match via strcmp): "[defaultx]" must NOT
 *       match "[default]" even though it starts with the same nine characters.
 * HOW:  mkdtemp → mkdir $HOME/.aws → write credentials file (3 sections) →
 *       setenv HOME → unset both AWS env vars → cfg with NULL s3_access/s3_secret
 *       (falls through to Level 3) → acquire → assert values; confirm [defaultx]
 *       keys are NOT returned.  Restore HOME and clean up temp tree after.
 */
static void
test_s3keys_file_success(void)
{
    const char *orig_home = getenv("HOME");
    char  tmphome[] = "/tmp/brix_s3file_home_XXXXXX";
    char  awsdir[512];
    char  credpath[512];
    FILE *f;

    assert(mkdtemp(tmphome) != NULL);
    snprintf(awsdir,   sizeof(awsdir),   "%s/.aws",             tmphome);
    snprintf(credpath, sizeof(credpath), "%s/.aws/credentials", tmphome);

    assert(mkdir(awsdir, 0700) == 0);

    f = fopen(credpath, "w");
    assert(f != NULL);
    /* [defaultx] BEFORE [default] — must NOT be picked up as [default] (Fix 1). */
    fprintf(f, "[defaultx]\n");
    fprintf(f, "aws_access_key_id = AKIA_WRONG_BEFORE\n");
    fprintf(f, "aws_secret_access_key = wrongsecret_before\n");
    fprintf(f, "\n");
    /* The real [default] section — these are the expected values. */
    fprintf(f, "[default]\n");
    fprintf(f, "aws_access_key_id = AKIA_FROM_FILE\n");
    fprintf(f, "aws_secret_access_key = filesecret123\n");
    fprintf(f, "\n");
    /* [defaultx] AFTER [default] — must not bleed back once [default] exits. */
    fprintf(f, "[defaultx]\n");
    fprintf(f, "aws_access_key_id = AKIA_WRONG_AFTER\n");
    fprintf(f, "aws_secret_access_key = wrongsecret_after\n");
    fclose(f);

    unsetenv("AWS_ACCESS_KEY_ID");
    unsetenv("AWS_SECRET_ACCESS_KEY");
    setenv("HOME", tmphome, 1);

    brix_cred_config cfg = {0};   /* s3_access/s3_secret NULL: falls to Level 3 */
    brix_cred_store *s   = brix_cred_store_new(&cfg);
    assert(s != NULL);

    assert(brix_cred_available(s, XRDC_CRED_S3KEYS) == 1);

    brix_status    st = {0};
    brix_cred_view v  = {0};
    int rc = brix_cred_acquire(s, XRDC_CRED_S3KEYS, 0, &v, &st);
    assert(rc == 0);
    /* [default] keys must be returned. */
    assert(v.s3_access != NULL && strcmp(v.s3_access, "AKIA_FROM_FILE") == 0);
    assert(v.s3_secret != NULL && strcmp(v.s3_secret, "filesecret123")  == 0);
    assert(v.not_after == 0);
    /* [defaultx] keys must NOT have been picked up (Fix 1: exact header match). */
    assert(strcmp(v.s3_access, "AKIA_WRONG_BEFORE") != 0);
    assert(strcmp(v.s3_access, "AKIA_WRONG_AFTER")  != 0);

    brix_cred_store_free(s);

    /* Restore env */
    if (orig_home != NULL) {
        setenv("HOME", orig_home, 1);
    } else {
        unsetenv("HOME");
    }
    unlink(credpath);
    rmdir(awsdir);
    rmdir(tmphome);
    printf("test_s3keys_file_success: PASS\n");
}

/* main */
int
main(void)
{
    test_x509_env_success();
    test_x509_missing();
    test_x509_cfg_precedence();
    test_bearer_env_success();
    test_bearer_missing();
    test_bearer_literal_precedence();
    test_bearer_jwt_not_after();
    test_sss_missing_keytab();
    test_sss_path_resolution();
    test_sss_positive();
    test_krb5_null_accessor();
    test_krb5_missing_ccache();
    test_s3keys_env_success();
    test_s3keys_missing();
    test_s3keys_cfg_precedence();
    test_s3keys_file_success();
    printf("cred_unit: all tests PASS\n");
    return 0;
}
#endif /* _CRED_UNIT_PART2_C_INC */

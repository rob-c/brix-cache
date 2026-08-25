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
#include "cred_unit_common.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>

/* X509 tests (use real cred_x509.c) */
/*
 * test_x509_env_success — $X509_USER_PROXY overrides the /tmp default.
 *
 * WHAT: set $X509_USER_PROXY to a temp file, confirm available()==1 and
 *       acquire() returns 0 with view.path matching the temp file.
 * WHY:  proves the env-var override path and that the store deep-copies path.
 * HOW:  mkstemp creates a real readable file; after the test, unlink + unsetenv.
 *       An empty file is intentional — the handler must still succeed (not_after==0
 *       is the best-effort fallback for a non-PEM file).
 */
static void
test_x509_env_success(void)
{
    char tmpl[] = "/tmp/proxy_XXXXXX";
    int  fd     = mkstemp(tmpl);
    assert(fd >= 0);
    close(fd);

    setenv("X509_USER_PROXY", tmpl, 1);

    brix_cred_config cfg = {0};

    /* empty file → not_after is best-effort zero, not an error */
    assert(cred_expect_path(brix_cred_store_new(&cfg),
                            XRDC_CRED_X509_PROXY, tmpl) == 0);

    unsetenv("X509_USER_PROXY");
    unlink(tmpl);
    printf("test_x509_env_success: PASS\n");
}

/*
 * test_x509_missing — a guaranteed-missing proxy path → available()==0, acquire==-1.
 *
 * WHAT: cfg->proxy_path points at a path that does not exist; confirms the
 *       handler returns -1 with XRDC_ENOENT in st.
 * WHY:  exercises the not-present error branch of acquire().
 * HOW:  unsetenv $X509_USER_PROXY first so the fallback is also absent; then
 *       set cfg.proxy_path to a path we know is missing.
 */
static void
test_x509_missing(void)
{
    unsetenv("X509_USER_PROXY");

    brix_cred_config cfg  = {0};
    cfg.proxy_path        = "/tmp/brix_cred_unit_no_such_proxy_XXXXXX";

    brix_cred_store *s = brix_cred_store_new(&cfg);

    cred_expect_refusal(s, XRDC_CRED_X509_PROXY, XRDC_ENOENT, NULL);

    brix_cred_store_free(s);
    printf("test_x509_missing: PASS\n");
}

/*
 * test_x509_cfg_precedence — cfg->proxy_path beats $X509_USER_PROXY.
 *
 * WHAT: two temp files; $X509_USER_PROXY points at one, cfg->proxy_path at
 *       the other; confirm acquire() returns the cfg path (highest precedence).
 * WHY:  CLI flag (--proxy) must override the environment variable.
 * HOW:  create both files; set both paths; assert view.path == cfg_path.
 *       After the test, restore env and remove both files.
 */
static void
test_x509_cfg_precedence(void)
{
    char env_tmpl[] = "/tmp/proxy_env_XXXXXX";
    char cfg_tmpl[] = "/tmp/proxy_cfg_XXXXXX";
    int  fd_env     = mkstemp(env_tmpl);
    int  fd_cfg     = mkstemp(cfg_tmpl);
    assert(fd_env >= 0 && fd_cfg >= 0);
    close(fd_env);
    close(fd_cfg);

    setenv("X509_USER_PROXY", env_tmpl, 1);

    brix_cred_config cfg = {0};
    cfg.proxy_path       = cfg_tmpl;   /* explicit override beats env */

    /* cfg->proxy_path wins over $X509_USER_PROXY */
    (void) cred_expect_path(brix_cred_store_new(&cfg),
                            XRDC_CRED_X509_PROXY, cfg_tmpl);

    unsetenv("X509_USER_PROXY");
    unlink(env_tmpl);
    unlink(cfg_tmpl);
    printf("test_x509_cfg_precedence: PASS\n");
}

/* bearer tests (use real cred_bearer.c) */
/*
 * test_bearer_env_success — $BEARER_TOKEN is visible as the token.
 *
 * WHAT: set $BEARER_TOKEN to a known opaque string; confirm available()==1 and
 *       acquire() fills view.token with that exact value.  not_after==0 is
 *       expected and acceptable for a non-JWT value.
 * WHY:  proves the env-var discovery path and that the store deep-copies the token.
 * HOW:  setenv; store acquire; assert; unsetenv.  A non-JWT value exercises the
 *       "not_after==0 still succeeds" branch in bearer_acquire().
 */
static void
test_bearer_env_success(void)
{
    const char *tok = "opaque-test-token-12345";
    setenv("BEARER_TOKEN", tok, 1);
    unsetenv("BEARER_TOKEN_FILE");

    brix_cred_config cfg = {0};

    /* non-JWT value → not_after is best-effort zero, not an error */
    assert(cred_expect_bearer(brix_cred_store_new(&cfg), tok) == 0);

    unsetenv("BEARER_TOKEN");
    printf("test_bearer_env_success: PASS\n");
}

/*
 * test_bearer_missing — no token source available → available()==0, acquire==-1.
 *
 * WHAT: clear every discovery source; confirm the handler returns -1 + XRDC_EAUTH.
 * WHY:  exercises the no-token error branch of acquire().
 * HOW:  unsetenv BEARER_TOKEN, BEARER_TOKEN_FILE, XDG_RUNTIME_DIR; cfg is zero.
 *       We do NOT manipulate /tmp/bt_u<uid> (might exist on the system) so instead
 *       we probe via cfg->bearer_literal="" and leave /tmp alone.  Because the stub
 *       overrides s3keys, the missing-bearer case uses the real handler.
 */
static void
test_bearer_missing(void)
{
    unsetenv("BEARER_TOKEN");
    unsetenv("BEARER_TOKEN_FILE");
    unsetenv("XDG_RUNTIME_DIR");

    /* Point cfg at a path we know doesn't exist and no literal/env set, so
     * brix_token_discover also returns NULL (BEARER_TOKEN cleared above). */
    brix_cred_config cfg = {0};
    cfg.bearer_path = "/tmp/brix_cred_unit_no_such_bearer_XXXXXX";

    brix_cred_store *s = brix_cred_store_new(&cfg);

    cred_expect_refusal(s, XRDC_CRED_BEARER, XRDC_EAUTH, NULL);

    brix_cred_store_free(s);
    printf("test_bearer_missing: PASS\n");
}

/*
 * test_bearer_literal_precedence — cfg->bearer_literal beats $BEARER_TOKEN.
 *
 * WHAT: set $BEARER_TOKEN to one value; cfg->bearer_literal to another; confirm
 *       acquire() returns the literal (highest precedence).
 * WHY:  CLI flag / programmatic override must beat the environment variable.
 * HOW:  both strings set; assert view.token == literal.
 */
static void
test_bearer_literal_precedence(void)
{
    const char *env_tok  = "env-token-value";
    const char *lit_tok  = "literal-override-value";

    setenv("BEARER_TOKEN", env_tok, 1);

    brix_cred_config cfg = {0};
    cfg.bearer_literal   = lit_tok;   /* explicit override beats $BEARER_TOKEN */

    /* literal wins */
    (void) cred_expect_bearer(brix_cred_store_new(&cfg), lit_tok);

    unsetenv("BEARER_TOKEN");
    printf("test_bearer_literal_precedence: PASS\n");
}

/*
 * test_bearer_jwt_not_after — a fake JWT with an exp claim sets not_after.
 *
 * WHAT: supply a minimal (unsigned) JWT whose payload is {"exp":9999999999};
 *       confirm not_after == 9999999999 after acquire.
 * WHY:  proves brix_token_meta_get is called and its result wired into not_after.
 * HOW:  the JWT is crafted as base64url(header).base64url(payload).base64url(sig)
 *       where the payload is {"exp":9999999999}.  brix_token_meta_get does NOT
 *       verify signatures, so this exercises the real exp-parse path.
 *       Token: eyJhbGciOiJub25lIn0.eyJleHAiOjk5OTk5OTk5OTl9.ZmFrZXNpZw
 */
static void
test_bearer_jwt_not_after(void)
{
    /* header={"alg":"none"} payload={"exp":9999999999} sig=fakesig */
    const char *jwt = "eyJhbGciOiJub25lIn0.eyJleHAiOjk5OTk5OTk5OTl9.ZmFrZXNpZw";

    setenv("BEARER_TOKEN", jwt, 1);
    unsetenv("BEARER_TOKEN_FILE");

    brix_cred_config cfg = {0};

    /* exp claim 9999999999 must propagate to not_after */
    assert(cred_expect_bearer(brix_cred_store_new(&cfg), jwt)
           == (int64_t) 9999999999LL);

    unsetenv("BEARER_TOKEN");
    printf("test_bearer_jwt_not_after: PASS\n");
}

/* SSS tests (use real cred_sss.c + sss_keytab.c) */
/*
 * test_sss_missing_keytab — cfg->keytab_path at a guaranteed-absent file →
 * available()==0 and acquire()==-1 with XRDC_EAUTH in st.
 *
 * WHAT: exercises the error branch of both available() and acquire() when the
 *       keytab does not exist.
 * WHY:  proves the handler propagates the error correctly to the store.
 * HOW:  unset $XrdSecSSSKT so it cannot accidentally resolve to a real keytab;
 *       point cfg->keytab_path at a path that will never exist.
 */
static void
test_sss_missing_keytab(void)
{
    unsetenv("XrdSecSSSKT");
    unsetenv("XrdSecsssKT");

    brix_cred_config cfg = {0};
    cfg.keytab_path = "/tmp/brix_cred_unit_no_such_keytab_XXXXXX";

    brix_cred_store *s = brix_cred_store_new(&cfg);

    cred_expect_refusal(s, XRDC_CRED_SSS, XRDC_EAUTH, NULL);

    brix_cred_store_free(s);
    printf("test_sss_missing_keytab: PASS\n");
}

/*
 * test_sss_path_resolution — $XrdSecSSSKT override propagates into the error
 * message when the keytab is absent.
 *
 * WHAT: set $XrdSecSSSKT to a missing path; confirm acquire()==-1 and that the
 *       error message contains the expected path, proving the env var was resolved.
 * WHY:  validates the brix_sss_keytab_default() > env-var branch so the caller
 *       can trust that the right location was probed.
 * HOW:  setenv $XrdSecSSSKT to a path we know does not exist; acquire; check
 *       st.msg contains that path string.  unsetenv after.
 */
static void
test_sss_path_resolution(void)
{
    const char *missing = "/tmp/brix_cred_unit_sss_env_path_XXXXXX";
    setenv("XrdSecSSSKT", missing, 1);
    unsetenv("XrdSecsssKT");

    brix_cred_config cfg = {0};   /* cfg->keytab_path is NULL: env wins */

    brix_cred_store *s = brix_cred_store_new(&cfg);

    /* The error message must mention the path that was actually probed. */
    cred_expect_refusal(s, XRDC_CRED_SSS, XRDC_EAUTH, missing);

    brix_cred_store_free(s);
    unsetenv("XrdSecSSSKT");
    printf("test_sss_path_resolution: PASS\n");
}

/*
 * test_sss_positive — a synthesised minimal keytab → available()==1 and
 * acquire() fills view.path with the keytab path.
 *
 * WHAT: creates a valid SSS keytab via brix_sss_keytab_write, then confirms the
 *       handler finds and returns it.
 * WHY:  the other two SSS tests are error-path only; a positive case is needed to
 *       confirm the success branch end-to-end.
 * HOW:  1) mkstemp → brix_sss_keytab_write with one synthetic key;
 *       2) point cfg->keytab_path at that file;
 *       3) assert available()==1 and acquire returns view.path == keytab path;
 *       4) unlink + cleanup.
 */
static void
test_sss_positive(void)
{
    /* Create a temp file that brix_sss_keytab_write will target (it opens with
     * O_TRUNC so the initial empty content is fine; we just need the path). */
    char tmpl[] = "/tmp/sss_keytab_XXXXXX";
    int  fd     = mkstemp(tmpl);
    assert(fd >= 0);
    close(fd);

    /* Synthesise a valid key entry. */
    brix_sss_key key;
    memset(&key, 0, sizeof(key));
    key.id      = 1;
    key.key[0]  = 0xde; key.key[1] = 0xad;
    key.key[2]  = 0xbe; key.key[3] = 0xef;
    key.key_len = 4;
    snprintf(key.user,  sizeof(key.user),  "%s", "testuser");
    snprintf(key.group, sizeof(key.group), "%s", "testgroup");
    snprintf(key.name,  sizeof(key.name),  "%s", "testkey");
    key.exp = 0;   /* never expires */

    brix_status wst = {0};
    int wrc = brix_sss_keytab_write(tmpl, &key, 1, &wst);
    assert(wrc == 0);

    /* Point the cfg at the newly written keytab. */
    brix_cred_config cfg = {0};
    cfg.keytab_path = tmpl;

    /* keytab has no per-use expiry → not_after stays 0 */
    assert(cred_expect_path(brix_cred_store_new(&cfg),
                            XRDC_CRED_SSS, tmpl) == 0);

    unlink(tmpl);
    printf("test_sss_positive: PASS\n");
}

/* krb5 tests (use real cred_krb5.c) */
/*
 * test_krb5_missing_ccache — $KRB5CCNAME pointing at a guaranteed-absent ccache
 * → available()==0 and acquire()==-1 with XRDC_EAUTH in st.
 *
 * WHAT: exercises the error branch when the ccache has no principal.
 * WHY:  confirms the handler correctly propagates a missing-principal failure.
 * HOW:  set $KRB5CCNAME to "FILE:/tmp/no_such_ccache_XXXXXX"; call available and
 *       acquire; assert failure.  krb5_cc_resolve("FILE:/path") parses the name
 *       but krb5_cc_get_principal fails because the backing file does not exist.
 *       unsetenv after the test so subsequent tests see the original env.
 *
 * NOTE: a positive test (live TGT present) is deferred to tests/test_krb5_auth.py
 * which sets up a real KDC harness (kdc_helpers.py).
 */
static void
test_krb5_missing_ccache(void)
{
#ifndef BRIX_HAVE_KRB5
    /* When krb5 is compiled out, the accessor returns NULL and the store
     * reports XRDC_EAUTH for every acquire; that path is covered by the
     * invalid-kind test above.  Skip the ccache-specific test. */
    printf("test_krb5_missing_ccache: SKIP (BRIX_HAVE_KRB5 not defined)\n");
    return;
#else
    const char *missing_cc = "FILE:/tmp/brix_cred_unit_no_such_krb5cc_XXXXXX";
    setenv("KRB5CCNAME", missing_cc, 1);

    brix_cred_config cfg = {0};   /* cfg->ccache is NULL: $KRB5CCNAME is used */

    brix_cred_store *s = brix_cred_store_new(&cfg);

    cred_expect_refusal(s, XRDC_CRED_KRB5, XRDC_EAUTH, NULL);

    brix_cred_store_free(s);
    unsetenv("KRB5CCNAME");
    printf("test_krb5_missing_ccache: PASS\n");
#endif
}

#define __CRED_UNIT_C_COMPILED__
#include "_cred_unit_part2.c"

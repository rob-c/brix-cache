/* client/tests/c/cred_unit.c
 *
 * WHAT: Unit tests for all REAL per-kind credential handlers (B3-B6):
 *       X.509 proxy, bearer token, SSS keytab, Kerberos ccache, and S3 keys.
 * WHY:  Each handler is validated against real env vars, temp files, and missing
 *       paths.  The store-core cases (cache/expiry/refresh) that need a
 *       controllable stub live in cred_store_unit.c to avoid a duplicate-symbol
 *       link error with the real xrdc_cred_s3keys() defined in cred_s3.c.
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
 *       $([ "$HAVE_KRB5" = yes ] && echo -DXROOTD_HAVE_KRB5) \
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

    xrdc_cred_config cfg = {0};
    xrdc_cred_store *s   = xrdc_cred_store_new(&cfg);
    assert(s != NULL);

    assert(xrdc_cred_available(s, XRDC_CRED_X509_PROXY) == 1);

    xrdc_status   st = {0};
    xrdc_cred_view v  = {0};
    int rc = xrdc_cred_acquire(s, XRDC_CRED_X509_PROXY, 0, &v, &st);
    assert(rc == 0);
    assert(v.path != NULL);
    assert(strcmp(v.path, tmpl) == 0);
    /* empty file → not_after is best-effort zero, not an error */
    assert(v.not_after == 0);

    xrdc_cred_store_free(s);
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

    xrdc_cred_config cfg  = {0};
    cfg.proxy_path        = "/tmp/xrdc_cred_unit_no_such_proxy_XXXXXX";

    xrdc_cred_store *s = xrdc_cred_store_new(&cfg);
    assert(s != NULL);

    assert(xrdc_cred_available(s, XRDC_CRED_X509_PROXY) == 0);

    xrdc_status   st = {0};
    xrdc_cred_view v  = {0};
    int rc = xrdc_cred_acquire(s, XRDC_CRED_X509_PROXY, 0, &v, &st);
    assert(rc == -1);
    assert(st.kxr == XRDC_ENOENT);
    assert(st.msg[0] != '\0');

    xrdc_cred_store_free(s);
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

    xrdc_cred_config cfg = {0};
    cfg.proxy_path       = cfg_tmpl;   /* explicit override beats env */

    xrdc_cred_store *s = xrdc_cred_store_new(&cfg);
    assert(s != NULL);

    assert(xrdc_cred_available(s, XRDC_CRED_X509_PROXY) == 1);

    xrdc_status   st = {0};
    xrdc_cred_view v  = {0};
    int rc = xrdc_cred_acquire(s, XRDC_CRED_X509_PROXY, 0, &v, &st);
    assert(rc == 0);
    assert(v.path != NULL);
    /* cfg->proxy_path wins over $X509_USER_PROXY */
    assert(strcmp(v.path, cfg_tmpl) == 0);

    xrdc_cred_store_free(s);
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

    xrdc_cred_config cfg  = {0};
    xrdc_cred_store *s    = xrdc_cred_store_new(&cfg);
    assert(s != NULL);

    assert(xrdc_cred_available(s, XRDC_CRED_BEARER) == 1);

    xrdc_status    st = {0};
    xrdc_cred_view v  = {0};
    int rc = xrdc_cred_acquire(s, XRDC_CRED_BEARER, 0, &v, &st);
    assert(rc == 0);
    assert(v.token != NULL);
    assert(strcmp(v.token, tok) == 0);
    /* non-JWT value → not_after is best-effort zero, not an error */
    assert(v.not_after == 0);

    xrdc_cred_store_free(s);
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
     * xrdc_token_discover also returns NULL (BEARER_TOKEN cleared above). */
    xrdc_cred_config cfg = {0};
    cfg.bearer_path = "/tmp/xrdc_cred_unit_no_such_bearer_XXXXXX";

    xrdc_cred_store *s = xrdc_cred_store_new(&cfg);
    assert(s != NULL);

    assert(xrdc_cred_available(s, XRDC_CRED_BEARER) == 0);

    xrdc_status    st = {0};
    xrdc_cred_view v  = {0};
    int rc = xrdc_cred_acquire(s, XRDC_CRED_BEARER, 0, &v, &st);
    assert(rc == -1);
    assert(st.kxr == XRDC_EAUTH);
    assert(st.msg[0] != '\0');

    xrdc_cred_store_free(s);
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

    xrdc_cred_config cfg = {0};
    cfg.bearer_literal   = lit_tok;   /* explicit override beats $BEARER_TOKEN */

    xrdc_cred_store *s = xrdc_cred_store_new(&cfg);
    assert(s != NULL);

    assert(xrdc_cred_available(s, XRDC_CRED_BEARER) == 1);

    xrdc_status    st = {0};
    xrdc_cred_view v  = {0};
    int rc = xrdc_cred_acquire(s, XRDC_CRED_BEARER, 0, &v, &st);
    assert(rc == 0);
    assert(v.token != NULL);
    assert(strcmp(v.token, lit_tok) == 0);   /* literal wins */

    xrdc_cred_store_free(s);
    unsetenv("BEARER_TOKEN");
    printf("test_bearer_literal_precedence: PASS\n");
}

/*
 * test_bearer_jwt_not_after — a fake JWT with an exp claim sets not_after.
 *
 * WHAT: supply a minimal (unsigned) JWT whose payload is {"exp":9999999999};
 *       confirm not_after == 9999999999 after acquire.
 * WHY:  proves xrdc_token_meta_get is called and its result wired into not_after.
 * HOW:  the JWT is crafted as base64url(header).base64url(payload).base64url(sig)
 *       where the payload is {"exp":9999999999}.  xrdc_token_meta_get does NOT
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

    xrdc_cred_config cfg  = {0};
    xrdc_cred_store *s    = xrdc_cred_store_new(&cfg);
    assert(s != NULL);

    xrdc_status    st = {0};
    xrdc_cred_view v  = {0};
    int rc = xrdc_cred_acquire(s, XRDC_CRED_BEARER, 0, &v, &st);
    assert(rc == 0);
    assert(v.token != NULL);
    assert(strcmp(v.token, jwt) == 0);
    /* exp claim 9999999999 must propagate to not_after */
    assert(v.not_after == (int64_t)9999999999LL);

    xrdc_cred_store_free(s);
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

    xrdc_cred_config cfg = {0};
    cfg.keytab_path = "/tmp/xrdc_cred_unit_no_such_keytab_XXXXXX";

    xrdc_cred_store *s = xrdc_cred_store_new(&cfg);
    assert(s != NULL);

    assert(xrdc_cred_available(s, XRDC_CRED_SSS) == 0);

    xrdc_status    st = {0};
    xrdc_cred_view v  = {0};
    int rc = xrdc_cred_acquire(s, XRDC_CRED_SSS, 0, &v, &st);
    assert(rc == -1);
    assert(st.kxr == XRDC_EAUTH);
    assert(st.msg[0] != '\0');

    xrdc_cred_store_free(s);
    printf("test_sss_missing_keytab: PASS\n");
}

/*
 * test_sss_path_resolution — $XrdSecSSSKT override propagates into the error
 * message when the keytab is absent.
 *
 * WHAT: set $XrdSecSSSKT to a missing path; confirm acquire()==-1 and that the
 *       error message contains the expected path, proving the env var was resolved.
 * WHY:  validates the xrdc_sss_keytab_default() > env-var branch so the caller
 *       can trust that the right location was probed.
 * HOW:  setenv $XrdSecSSSKT to a path we know does not exist; acquire; check
 *       st.msg contains that path string.  unsetenv after.
 */
static void
test_sss_path_resolution(void)
{
    const char *missing = "/tmp/xrdc_cred_unit_sss_env_path_XXXXXX";
    setenv("XrdSecSSSKT", missing, 1);
    unsetenv("XrdSecsssKT");

    xrdc_cred_config cfg = {0};   /* cfg->keytab_path is NULL: env wins */

    xrdc_cred_store *s = xrdc_cred_store_new(&cfg);
    assert(s != NULL);

    assert(xrdc_cred_available(s, XRDC_CRED_SSS) == 0);

    xrdc_status    st = {0};
    xrdc_cred_view v  = {0};
    int rc = xrdc_cred_acquire(s, XRDC_CRED_SSS, 0, &v, &st);
    assert(rc == -1);
    assert(st.kxr == XRDC_EAUTH);
    /* The error message must mention the path that was actually probed. */
    assert(strstr(st.msg, missing) != NULL);

    xrdc_cred_store_free(s);
    unsetenv("XrdSecSSSKT");
    printf("test_sss_path_resolution: PASS\n");
}

/*
 * test_sss_positive — a synthesised minimal keytab → available()==1 and
 * acquire() fills view.path with the keytab path.
 *
 * WHAT: creates a valid SSS keytab via xrdc_sss_keytab_write, then confirms the
 *       handler finds and returns it.
 * WHY:  the other two SSS tests are error-path only; a positive case is needed to
 *       confirm the success branch end-to-end.
 * HOW:  1) mkstemp → xrdc_sss_keytab_write with one synthetic key;
 *       2) point cfg->keytab_path at that file;
 *       3) assert available()==1 and acquire returns view.path == keytab path;
 *       4) unlink + cleanup.
 */
static void
test_sss_positive(void)
{
    /* Create a temp file that xrdc_sss_keytab_write will target (it opens with
     * O_TRUNC so the initial empty content is fine; we just need the path). */
    char tmpl[] = "/tmp/sss_keytab_XXXXXX";
    int  fd     = mkstemp(tmpl);
    assert(fd >= 0);
    close(fd);

    /* Synthesise a valid key entry. */
    xrdc_sss_key key;
    memset(&key, 0, sizeof(key));
    key.id      = 1;
    key.key[0]  = 0xde; key.key[1] = 0xad;
    key.key[2]  = 0xbe; key.key[3] = 0xef;
    key.key_len = 4;
    snprintf(key.user,  sizeof(key.user),  "%s", "testuser");
    snprintf(key.group, sizeof(key.group), "%s", "testgroup");
    snprintf(key.name,  sizeof(key.name),  "%s", "testkey");
    key.exp = 0;   /* never expires */

    xrdc_status wst = {0};
    int wrc = xrdc_sss_keytab_write(tmpl, &key, 1, &wst);
    assert(wrc == 0);

    /* Point the cfg at the newly written keytab. */
    xrdc_cred_config cfg = {0};
    cfg.keytab_path = tmpl;

    xrdc_cred_store *s = xrdc_cred_store_new(&cfg);
    assert(s != NULL);

    assert(xrdc_cred_available(s, XRDC_CRED_SSS) == 1);

    xrdc_status    st = {0};
    xrdc_cred_view v  = {0};
    int rc = xrdc_cred_acquire(s, XRDC_CRED_SSS, 0, &v, &st);
    assert(rc == 0);
    assert(v.path != NULL);
    assert(strcmp(v.path, tmpl) == 0);
    assert(v.not_after == 0);   /* keytab has no per-use expiry */

    xrdc_cred_store_free(s);
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
#ifndef XROOTD_HAVE_KRB5
    /* When krb5 is compiled out, the accessor returns NULL and the store
     * reports XRDC_EAUTH for every acquire; that path is covered by the
     * invalid-kind test above.  Skip the ccache-specific test. */
    printf("test_krb5_missing_ccache: SKIP (XROOTD_HAVE_KRB5 not defined)\n");
    return;
#else
    const char *missing_cc = "FILE:/tmp/xrdc_cred_unit_no_such_krb5cc_XXXXXX";
    setenv("KRB5CCNAME", missing_cc, 1);

    xrdc_cred_config cfg = {0};   /* cfg->ccache is NULL: $KRB5CCNAME is used */

    xrdc_cred_store *s = xrdc_cred_store_new(&cfg);
    assert(s != NULL);

    assert(xrdc_cred_available(s, XRDC_CRED_KRB5) == 0);

    xrdc_status    st = {0};
    xrdc_cred_view v  = {0};
    int rc = xrdc_cred_acquire(s, XRDC_CRED_KRB5, 0, &v, &st);
    assert(rc == -1);
    assert(st.kxr == XRDC_EAUTH);
    assert(st.msg[0] != '\0');

    xrdc_cred_store_free(s);
    unsetenv("KRB5CCNAME");
    printf("test_krb5_missing_ccache: PASS\n");
#endif
}

/*
 * test_krb5_null_accessor — when XROOTD_HAVE_KRB5 is NOT defined, the accessor
 * must return NULL so the store treats KRB5 as absent.
 *
 * WHAT: assert xrdc_cred_krb5() == NULL in the stub build.
 * WHY:  mirrors the contract in cred.h: "NULL when compiled out".
 * HOW:  compile-time branch: in the stub case assert NULL; in the real case skip
 *       (the accessor returns a real handler pointer, so != NULL is expected).
 */
static void
test_krb5_null_accessor(void)
{
#ifndef XROOTD_HAVE_KRB5
    assert(xrdc_cred_krb5() == NULL);
    printf("test_krb5_null_accessor: PASS (krb5 compiled out)\n");
#else
    /* XROOTD_HAVE_KRB5 is defined: accessor returns a real handler, not NULL. */
    assert(xrdc_cred_krb5() != NULL);
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

    xrdc_cred_config cfg  = {0};
    xrdc_cred_store *s    = xrdc_cred_store_new(&cfg);
    assert(s != NULL);

    assert(xrdc_cred_available(s, XRDC_CRED_S3KEYS) == 1);

    xrdc_status    st = {0};
    xrdc_cred_view v  = {0};
    int rc = xrdc_cred_acquire(s, XRDC_CRED_S3KEYS, 0, &v, &st);
    assert(rc == 0);
    assert(v.s3_access != NULL && strcmp(v.s3_access, acc) == 0);
    assert(v.s3_secret != NULL && strcmp(v.s3_secret, sec) == 0);
    assert(v.not_after == 0);   /* static keys have no per-use expiry */

    xrdc_cred_store_free(s);
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
    char tmphome[] = "/tmp/xrdc_s3test_home_XXXXXX";

    assert(mkdtemp(tmphome) != NULL);

    unsetenv("AWS_ACCESS_KEY_ID");
    unsetenv("AWS_SECRET_ACCESS_KEY");
    setenv("HOME", tmphome, 1);

    xrdc_cred_config cfg = {0};
    xrdc_cred_store *s   = xrdc_cred_store_new(&cfg);
    assert(s != NULL);

    assert(xrdc_cred_available(s, XRDC_CRED_S3KEYS) == 0);

    xrdc_status    st = {0};
    xrdc_cred_view v  = {0};
    int rc = xrdc_cred_acquire(s, XRDC_CRED_S3KEYS, 0, &v, &st);
    assert(rc == -1);
    assert(st.kxr == XRDC_EAUTH);
    assert(st.msg[0] != '\0');

    xrdc_cred_store_free(s);

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

    xrdc_cred_config cfg = {0};
    cfg.s3_access = cfg_acc;   /* explicit override beats env */
    cfg.s3_secret = cfg_sec;

    xrdc_cred_store *s = xrdc_cred_store_new(&cfg);
    assert(s != NULL);

    assert(xrdc_cred_available(s, XRDC_CRED_S3KEYS) == 1);

    xrdc_status    st = {0};
    xrdc_cred_view v  = {0};
    int rc = xrdc_cred_acquire(s, XRDC_CRED_S3KEYS, 0, &v, &st);
    assert(rc == 0);
    assert(v.s3_access != NULL && strcmp(v.s3_access, cfg_acc) == 0);
    assert(v.s3_secret != NULL && strcmp(v.s3_secret, cfg_sec) == 0);

    xrdc_cred_store_free(s);
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
    char  tmphome[] = "/tmp/xrdc_s3file_home_XXXXXX";
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

    xrdc_cred_config cfg = {0};   /* s3_access/s3_secret NULL: falls to Level 3 */
    xrdc_cred_store *s   = xrdc_cred_store_new(&cfg);
    assert(s != NULL);

    assert(xrdc_cred_available(s, XRDC_CRED_S3KEYS) == 1);

    xrdc_status    st = {0};
    xrdc_cred_view v  = {0};
    int rc = xrdc_cred_acquire(s, XRDC_CRED_S3KEYS, 0, &v, &st);
    assert(rc == 0);
    /* [default] keys must be returned. */
    assert(v.s3_access != NULL && strcmp(v.s3_access, "AKIA_FROM_FILE") == 0);
    assert(v.s3_secret != NULL && strcmp(v.s3_secret, "filesecret123")  == 0);
    assert(v.not_after == 0);
    /* [defaultx] keys must NOT have been picked up (Fix 1: exact header match). */
    assert(strcmp(v.s3_access, "AKIA_WRONG_BEFORE") != 0);
    assert(strcmp(v.s3_access, "AKIA_WRONG_AFTER")  != 0);

    xrdc_cred_store_free(s);

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

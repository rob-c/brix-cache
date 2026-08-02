/* client/tests/c/cred_refresh_unit.c
 *
 * WHAT: phase-92 task C2(a) — proves `--auto-refresh` is no longer a silent
 *       no-op.  The cred-store bearer/X.509 refresh handlers now delegate to the
 *       public engine wrappers brix_cred_refresh_bearer / brix_cred_refresh_gsi
 *       (credrefresh.c); this exercises those wrappers, which is where the whole
 *       of the new behaviour lives (the two handlers are one-line delegates).
 * WHY:  before phase-92 bearer_refresh()/x509_refresh() returned 0 without ever
 *       calling the fully-written engine, so a near-expiry credential was never
 *       re-minted even with --auto-refresh set.
 * HOW:  a fake `oidc-token` on $PATH (execvp resolves it) lets the bearer path
 *       run end-to-end hermetically; discovery is forced to "needs refresh" by
 *       seeding $BEARER_TOKEN with a structurally-valid but expired JWT so the
 *       result is independent of any real token on the host.
 *
 * Cases:
 *   success:      a resolvable account + fake oidc-agent re-mints the token and
 *                 installs it into $BEARER_TOKEN (return 1).
 *   edge:         a NULL account with $OIDC_ACCOUNT set is resolved from the env
 *                 (return 1) — the wrapper's account fallback.
 *   security-neg: no account at all → return 0 (fail-soft, never spawns oidc);
 *                 and the GSI wrapper with no discoverable cert → return 0 (never
 *                 mints a proxy without a user cert).
 *
 * Build+run: see client/Makefile CLIENT_UNIT_TESTS.
 */

#include "brix.h"   /* brix_cred_refresh_bearer / _gsi via brix_auth.h */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* structurally valid JWT, exp=1000000000 (year 2001) → parses + expired, so
 * token_needs_refresh() returns 1 regardless of any real token on the host. */
static const char *EXPIRED_JWT =
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEwMDAwMDAwMDB9.AAAA";

static const char *FAKE_TOKEN = "REFRESHED.FAKE.TOKEN";

/* Install a fake `oidc-token` on $PATH that echoes FAKE_TOKEN; returns its dir. */
static char *
install_fake_oidc(char *dirbuf, size_t dirsz)
{
    char tmpl[] = "/tmp/credrefresh_XXXXXX";
    char *dir = mkdtemp(tmpl);
    char path[512];
    FILE *f;

    assert(dir != NULL);
    snprintf(dirbuf, dirsz, "%s", dir);

    snprintf(path, sizeof(path), "%s/oidc-token", dir);
    f = fopen(path, "w");
    assert(f != NULL);
    fprintf(f, "#!/bin/sh\necho %s\n", FAKE_TOKEN);
    fclose(f);
    assert(chmod(path, 0755) == 0);

    /* prepend to PATH so execvp("oidc-token") finds our stub first */
    {
        const char *old = getenv("PATH");
        char newpath[4096];
        snprintf(newpath, sizeof(newpath), "%s:%s", dir, old ? old : "");
        setenv("PATH", newpath, 1);
    }
    return dirbuf;
}

/* success: explicit account + fake oidc-agent → token re-minted into env. */
static void
test_bearer_refresh_success(void)
{
    char dir[512];
    install_fake_oidc(dir, sizeof(dir));

    unsetenv("BEARER_TOKEN_FILE");
    setenv("BEARER_TOKEN", EXPIRED_JWT, 1);   /* → needs_refresh == 1 */

    int rc = brix_cred_refresh_bearer("myaccount", 0, NULL);
    assert(rc == 1);
    const char *tok = getenv("BEARER_TOKEN");
    assert(tok != NULL && strcmp(tok, FAKE_TOKEN) == 0);
    printf("  ok: bearer refresh re-mints token via oidc-agent\n");
}

/* edge: NULL account resolves from $OIDC_ACCOUNT (wrapper fallback). */
static void
test_bearer_refresh_account_from_env(void)
{
    char dir[512];
    install_fake_oidc(dir, sizeof(dir));

    unsetenv("BEARER_TOKEN_FILE");
    setenv("BEARER_TOKEN", EXPIRED_JWT, 1);
    setenv("OIDC_ACCOUNT", "envaccount", 1);

    int rc = brix_cred_refresh_bearer(NULL, 0, NULL);
    assert(rc == 1);
    assert(strcmp(getenv("BEARER_TOKEN"), FAKE_TOKEN) == 0);
    printf("  ok: bearer refresh resolves account from $OIDC_ACCOUNT\n");
}

/* security-neg: no account → fail-soft 0 (never spawns oidc). */
static void
test_bearer_refresh_no_account_soft(void)
{
    unsetenv("OIDC_ACCOUNT");
    setenv("BEARER_TOKEN", EXPIRED_JWT, 1);

    int rc = brix_cred_refresh_bearer(NULL, 0, NULL);
    assert(rc == 0);
    /* the token must be left exactly as-is — no half-refresh */
    assert(strcmp(getenv("BEARER_TOKEN"), EXPIRED_JWT) == 0);
    printf("  ok: bearer refresh with no account is a fail-soft no-op\n");
}

/* security-neg: no discoverable user cert → GSI never mints a proxy. */
static void
test_gsi_refresh_no_cert_soft(void)
{
    setenv("X509_USER_CERT", "/nonexistent/credrefresh/usercert.pem", 1);

    int rc = brix_cred_refresh_gsi(0, NULL);
    assert(rc == 0);
    printf("  ok: gsi refresh with no cert is a fail-soft no-op\n");
}

int
main(void)
{
    printf("cred_refresh_unit:\n");
    test_bearer_refresh_success();
    test_bearer_refresh_account_from_env();
    test_bearer_refresh_no_account_soft();
    test_gsi_refresh_no_cert_soft();
    printf("cred_refresh_unit: ALL PASS\n");
    return 0;
}

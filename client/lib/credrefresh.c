/*
 * credrefresh.c — Phase 40 (b): proactive client-side credential (re)acquisition.
 *
 * WHAT: Before (and between) transfers, if the bearer token or GSI proxy is
 *       missing / expired / near-expiry, VOLUNTEER to obtain a fresh one — a
 *       token via the local oidc-agent (the `oidc-token` CLI), a GSI proxy via
 *       brix_proxy_create() from the long-lived user cert. Opt-in (xrdcp
 *       --auto-refresh); a silent no-op when the credential is healthy or no
 *       refresh source is available.
 * WHY:  long-running / batch transfers routinely outlive a ~1h access token or a
 *       ~12h proxy. Phase 40 (c) already WARNS ("expired — run X"); doing it FOR
 *       the user is the user-friendly next step the toolkit is positioned to give.
 * HOW:  reuses the SAME expiry introspection as (c) (brix_token_meta_get,
 *       brix_proxy_remaining) and the EXISTING brix_proxy_create primitive — no
 *       new auth plumbing. A refreshed token is installed into the process
 *       environment ($BEARER_TOKEN) so the existing brix_token_discover path picks
 *       it up on the next connection; a refreshed proxy is written to the default
 *       path the GSI code already reads. Every step fails SOFT: a missing
 *       oidc-token, no configured account, or no user cert simply skips.
 *
 * Clean-room: standard POSIX fork/exec/pipe + the in-tree proxy/token helpers.
 */
#include "brix.h"
#include "core/compat/subprocess.h"   /* shared fork/exec stdout capture (libxrdproto) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/types.h>

/* Refresh anything with this many seconds (or fewer) of remaining validity, so a
 * credential cannot expire in the middle of a transfer that has just started. */
#define XRDC_CRED_MARGIN_SECS 300

/*
 * Fetch a fresh access token from the local oidc-agent via the `oidc-token` CLI
 * (`oidc-token <account>`). Returns 0 and a NUL-terminated bare token in out[],
 * or -1 (st set) if oidc-token is absent, the account is unknown to the agent, or
 * it produced no token. Pure fork/exec/pipe; the bare token is read from stdout.
 */
static int
run_oidc_token(const char *account, char *out, size_t outsz, brix_status *st)
{
    char *const argv[] = { (char *) "oidc-token", (char *) account, NULL };
    size_t      got = 0;
    int         ec = -1;

    if (account == NULL || account[0] == '\0') {
        brix_status_set(st, XRDC_EAUTH, 0,
                        "no oidc account (set --oidc-account or $OIDC_ACCOUNT)");
        return -1;
    }
    /* Shared fork/exec stdout capture (libxrdproto). */
    if (brix_subprocess_capture(argv, out, outsz, &got, &ec) != 0) {
        brix_status_set(st, XRDC_ESOCK, 0, "oidc-token: failed to spawn");
        return -1;
    }
    if (ec != 0) {
        brix_status_set(st, XRDC_EAUTH, 0,
                        "oidc-token failed for account \"%s\" (status %d)",
                        account, ec);
        return -1;
    }
    if (got + 1 >= outsz) {
        /* Filled the buffer — the token was (probably) truncated; refuse to
         * install a half token rather than fail opaquely server-side. */
        brix_status_set(st, XRDC_EAUTH, 0,
                        "oidc-token output too large (> %zu bytes)", outsz - 1);
        return -1;
    }
    if (brix_rstrip(out) == 0) {    /* trim trailing whitespace the CLI appends */
        brix_status_set(st, XRDC_EAUTH, 0,
                        "oidc-token returned an empty token for \"%s\"", account);
        return -1;
    }
    return 0;
}

/* 1 if a long-lived GSI user cert is discoverable (so minting a proxy can work);
 * avoids attempting brix_proxy_create for token-only users with no cert. */
static int
gsi_cert_available(void)
{
    const char *cert = getenv("X509_USER_CERT");
    char        def[1024];
    const char *home;

    if (cert != NULL && cert[0] != '\0') {
        return access(cert, R_OK) == 0;
    }
    home = getenv("HOME");
    if (home == NULL || home[0] == '\0') {
        return 0;
    }
    snprintf(def, sizeof(def), "%s/.globus/usercert.pem", home);
    return access(def, R_OK) == 0;
}

/* Does the bearer token need refreshing? 1 if absent/expired/near-expiry. */
static int
token_needs_refresh(void)
{
    char           *tok = brix_token_discover();
    brix_token_meta m;

    if (tok == NULL) {
        return 1;   /* none discoverable — get one if we can */
    }
    memset(&m, 0, sizeof(m));
    brix_token_meta_get(tok, &m);
    free(tok);
    if (!m.valid) {
        return 0;   /* opaque/non-JWT token we cannot reason about — leave it */
    }
    if (m.expired) {
        return 1;
    }
    if (m.exp > 0 && (m.exp - (long) time(NULL)) < XRDC_CRED_MARGIN_SECS) {
        return 1;
    }
    return 0;
}

/*
 * Refresh whatever local credential is stale, best-effort.
 *
 * want_write       — reserved for future scope-aware refresh (unused today).
 * oidc_account     — oidc-agent account; NULL ⇒ $OIDC_ACCOUNT.
 * verbose / out    — narrate what was (re)acquired when verbose and out != NULL.
 * Returns the number of credentials freshly acquired (0 = nothing to do / no
 * source available). Never fails the caller — a refresh source that is absent or
 * errors simply leaves the existing credential (the server stays authoritative,
 * and Phase 40 (c) pre-flight will still warn if it is genuinely unusable).
 */
int
brix_cred_autorefresh(int want_write, const char *oidc_account, int verbose,
                      FILE *out)
{
    int         refreshed = 0;
    const char *account = oidc_account;

    (void) want_write;
    if (account == NULL || account[0] == '\0') {
        account = getenv("OIDC_ACCOUNT");
    }

    /* Bearer token via oidc-agent — only when an account is configured. */
    if (account != NULL && account[0] != '\0' && token_needs_refresh()) {
        char        tok[16384];
        brix_status st;
        brix_status_clear(&st);
        if (run_oidc_token(account, tok, sizeof(tok), &st) == 0) {
            if (setenv("BEARER_TOKEN", tok, 1) == 0) {
                refreshed++;
                if (verbose && out != NULL) {
                    fprintf(out, "xrdcp: refreshed bearer token via oidc-agent "
                                 "(account %s)\n", account);
                }
            }
        } else if (verbose && out != NULL) {
            fprintf(out, "xrdcp: token auto-refresh skipped: %s\n", st.msg);
        }
    }

    /* GSI proxy via brix_proxy_create — only when a user cert exists. */
    if (gsi_cert_available()) {
        char pxp[1024];
        long left = 0;
        int  have, stale;
        brix_proxy_default_path(pxp, sizeof(pxp));
        have = (access(pxp, R_OK) == 0);
        if (!have) {
            stale = 1;                                  /* none → mint one */
        } else if (brix_proxy_remaining(pxp, &left) != 0) {
            stale = 1;                                  /* present but unparseable → renew */
        } else {
            stale = (left < XRDC_CRED_MARGIN_SECS);     /* expiring soon → renew */
        }
        if (stale) {
            brix_proxy_opts po;
            brix_status     st;
            memset(&po, 0, sizeof(po));   /* defaults: ~/.globus cert/key, 12h, 2048 */
            brix_status_clear(&st);
            if (brix_proxy_create(&po, &st) == 0) {
                refreshed++;
                if (verbose && out != NULL) {
                    fprintf(out, "xrdcp: refreshed GSI proxy (%s)\n", pxp);
                }
            } else if (verbose && out != NULL) {
                fprintf(out, "xrdcp: proxy auto-refresh skipped: %s\n", st.msg);
            }
        }
    }

    return refreshed;
}

/* client/lib/cred_sss.c
 *
 * WHAT: SSS (Simple Shared Secret) credential handler for the unified
 *       credential store (cred.c). Implements xrdc_cred_sss() returning the
 *       XRDC_CRED_SSS handler with available / acquire operations.
 * WHY:  SSS keytab discovery was only available through sec_sss.c; the unified
 *       store needs a standalone handler so auth pre-flight diagnostics and the
 *       auth handshake both share a single keytab resolution path.
 * HOW:  Discovery precedence:
 *         cfg->keytab_path  (CLI override, highest precedence)
 *         > xrdc_sss_keytab_default()  ($XrdSecSSSKT > $XrdSecsssKT >
 *                                        ~/.xrd/sss.keytab)
 *       available() resolves the path and probes with xrdc_sss_keytab_read
 *       (must read successfully and n>0).
 *       acquire() fills out->path with a static buffer copy of the resolved path
 *       and sets *not_after=0 (a keytab has no per-use expiry).
 *       refresh=NULL: keytab is long-lived; no automatic refresh mechanism.
 *
 *       Lifetime contract (cred.h): acquire() writes out->path as a pointer to
 *       a function-local static char[] that remains valid after acquire() returns.
 *       The store's slot_store_view strdup's out->path immediately afterwards —
 *       before any other acquire can overwrite the buffer.  The store is
 *       single-threaded per acquire, so one static buffer is safe for this window.
 *
 * ngx-free.  No goto.  Functional/modular: one responsibility per function.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "cred.h"
#include "xrdc.h"
#include "sss_keytab.h"

#include <string.h>

/* ---- keytab path resolution --------------------------------------------- */

/*
 * resolve_keytab_path — fill out[outsz] with the resolved SSS keytab path.
 *
 * WHAT: implements the two-level precedence: cfg->keytab_path (CLI override) >
 *       xrdc_sss_keytab_default() (env/default discovery).
 * WHY:  mirrors the precedence documented in cred.h's keytab_path comment and
 *       matches the behaviour callers expect from sec_sss.c's discovery.
 * HOW:  two early-return branches; snprintf is always NUL-terminated within outsz.
 */
static void
resolve_keytab_path(const xrdc_cred_config *cfg, char *out, size_t outsz)
{
    if (cfg != NULL && cfg->keytab_path != NULL && cfg->keytab_path[0] != '\0') {
        snprintf(out, outsz, "%s", cfg->keytab_path);
        return;
    }
    xrdc_sss_keytab_default(out, outsz);
}

/* ---- keytab probe -------------------------------------------------------- */

/*
 * keytab_probe — resolve the keytab path and check that it has at least one key.
 *
 * WHAT: resolves the path into path_out[outsz] and calls xrdc_sss_keytab_read;
 *       returns 1 iff the read succeeds and n>0.
 * WHY:  shared by sss_available() and sss_acquire() so the probe logic lives in
 *       one place (available and acquire must agree on what "usable" means).
 * HOW:  stack-allocated key array (no heap); xrdc_sss_keytab_read fills *n.
 *       path_out is filled by resolve_keytab_path so the caller learns the path
 *       (acquire uses it to populate out->path and the error message).
 */
static int
keytab_probe(const xrdc_cred_config *cfg, char *path_out, size_t outsz)
{
    xrdc_sss_key keys[XRDC_SSS_KEYS_MAX];
    xrdc_status  st;
    int          n = 0;

    resolve_keytab_path(cfg, path_out, outsz);
    xrdc_status_clear(&st);
    return (xrdc_sss_keytab_read(path_out, keys, XRDC_SSS_KEYS_MAX, &n, &st) == 0
            && n > 0) ? 1 : 0;
}

/* ---- handler callbacks -------------------------------------------------- */

/*
 * sss_available — 1 if the resolved keytab exists and contains at least one key.
 *
 * WHAT: fast probe for auth pre-flight diagnostics and xrdc_cred_available().
 * WHY:  mirrors sec_sss.c:sss_have() semantics (keytab readable + n>0).
 * HOW:  keytab_probe with a scratch path buffer (not exposed to the caller).
 */
static int
sss_available(const xrdc_cred_config *cfg)
{
    char path[XRDC_PATH_MAX];
    return keytab_probe(cfg, path, sizeof(path));
}

/*
 * sss_acquire — resolve the keytab path, verify it is usable, fill *out.
 *
 * WHAT: the store's acquire call for XRDC_CRED_SSS.
 * WHY:  single canonical acquire path for the SSS keytab credential.
 * HOW:  1) keytab_probe — resolves path into s_path and reads keys;
 *       2) on failure → -1 + XRDC_EAUTH with the resolved path in the message;
 *       3) fill out: kind=SSS, path=s_path, not_after=0 (no per-use expiry).
 *
 * Lifetime of s_path: declared static so the buffer remains valid after this
 * function returns. slot_store_view strdup's out->path before any other acquire
 * can overwrite the buffer.
 */
static int
sss_acquire(const xrdc_cred_config *cfg, xrdc_cred_view *out,
            int64_t *not_after, xrdc_status *st)
{
    /* static: must outlive this return so slot_store_view can strdup it */
    static char s_path[XRDC_PATH_MAX];

    if (!keytab_probe(cfg, s_path, sizeof(s_path))) {
        xrdc_status_set(st, XRDC_EAUTH, 0,
                        "sss: no usable keytab at %s "
                        "(set XrdSecSSSKT or cfg->keytab_path)", s_path);
        return -1;
    }

    out->kind      = XRDC_CRED_SSS;
    out->path      = s_path;   /* static buffer; store deep-copies via slot_store_view */
    out->token     = NULL;
    out->s3_access = NULL;
    out->s3_secret = NULL;

    *not_after = 0;   /* keytab has no per-use expiry */
    return 0;
}

/* ---- handler accessor --------------------------------------------------- */

static const xrdc_cred_handler s_sss_handler = {
    .kind      = XRDC_CRED_SSS,
    .available = sss_available,
    .acquire   = sss_acquire,
    .refresh   = NULL,   /* keytab is long-lived; no automatic refresh mechanism */
};

/*
 * xrdc_cred_sss — return the static SSS keytab handler.
 *
 * WHAT: strong definition that overrides the weak accessor in cred.c.
 * WHY:  weak/strong pattern lets lib and test binaries link without every handler
 *       compiled in; this file provides the real SSS implementation.
 * HOW:  returns a pointer to the file-scoped static handler struct.
 */
const xrdc_cred_handler *
xrdc_cred_sss(void)
{
    return &s_sss_handler;
}

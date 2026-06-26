/* client/lib/cred_krb5.c
 *
 * WHAT: Kerberos 5 credential handler for the unified credential store (cred.c).
 *       Implements xrdc_cred_krb5() returning the XRDC_CRED_KRB5 handler with
 *       available / acquire operations. Compile-gated on XROOTD_HAVE_KRB5.
 * WHY:  ccache discovery was only available through sec_krb5.c; the credential
 *       store needs a standalone handler so auth pre-flight diagnostics and the
 *       auth handshake both share one ccache resolution path.
 * HOW:  Discovery precedence:
 *         cfg->ccache     (CLI override, highest precedence)
 *         > $KRB5CCNAME   (environment)
 *         > krb5_cc_default (library default)
 *       available() opens the ccache and verifies it has a client principal.
 *       acquire() fills out->path with "<type>:<name>" in a static buffer and
 *       best-effort reads the TGT endtime via krb5_cc_next_cred (krbtgt/... entry).
 *       refresh=NULL: TGT renewal (kinit) is the user's responsibility; this
 *       handler does NOT invoke kinit or perform any ticket refresh.
 *       When XROOTD_HAVE_KRB5 is not defined at compile time, xrdc_cred_krb5()
 *       returns NULL so the store simply skips the KRB5 slot.
 *
 *       Lifetime contract (cred.h): acquire() writes out->path as a pointer to
 *       a function-local static char[] that remains valid after acquire() returns.
 *       The store's slot_store_view strdup's out->path immediately afterwards —
 *       before any other acquire can overwrite the buffer.
 *
 * Mirrors xrdc_sec_krb5() in lib/sec/sec_krb5.c for all krb5 API calls.
 * ngx-free.  No goto.  Functional/modular: one responsibility per function.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "cred.h"
#include "xrdc.h"

#ifdef XROOTD_HAVE_KRB5

#include <krb5.h>
#include <string.h>
#include <stdlib.h>

/* ---- ccache resolution -------------------------------------------------- */

/*
 * open_ccache — open the ccache selected by cfg->ccache > $KRB5CCNAME >
 * krb5_cc_default and write it into *cc.
 *
 * WHAT: resolves the caller's preference into an open krb5_ccache handle.
 * WHY:  single resolution path reused by both available() and acquire() so the
 *       two cannot drift apart.
 * HOW:  three early-return branches; caller owns *cc on success (must close).
 */
static int
open_ccache(krb5_context ctx, const xrdc_cred_config *cfg, krb5_ccache *cc)
{
    const char *env;

    if (cfg != NULL && cfg->ccache != NULL && cfg->ccache[0] != '\0') {
        return krb5_cc_resolve(ctx, cfg->ccache, cc) == 0 ? 0 : -1;
    }
    env = getenv("KRB5CCNAME");
    if (env != NULL && env[0] != '\0') {
        return krb5_cc_resolve(ctx, env, cc) == 0 ? 0 : -1;
    }
    return krb5_cc_default(ctx, cc) == 0 ? 0 : -1;
}

/* ---- ccache name formatting --------------------------------------------- */

/*
 * format_ccache_name — write the canonical "TYPE:name" ccache name into out[outsz].
 *
 * WHAT: combines krb5_cc_get_type and krb5_cc_get_name into one NUL-terminated
 *       string (e.g. "FILE:/tmp/krb5cc_1000").
 * WHY:  out->path should be the form users recognise from $KRB5CCNAME, not just
 *       the bare residual path.
 * HOW:  two-part snprintf; always NUL-terminated within outsz.
 */
static void
format_ccache_name(krb5_context ctx, krb5_ccache cc, char *out, size_t outsz)
{
    const char *type = krb5_cc_get_type(ctx, cc);
    const char *name = krb5_cc_get_name(ctx, cc);

    if (type != NULL && type[0] != '\0' && name != NULL) {
        snprintf(out, outsz, "%s:%s", type, name);
    } else if (name != NULL) {
        snprintf(out, outsz, "%s", name);
    } else {
        snprintf(out, outsz, "(unknown-ccache)");
    }
}

/* ---- TGT endtime extraction --------------------------------------------- */

/*
 * extract_tgt_endtime — scan the ccache for the krbtgt/... credential and return
 * its endtime, or 0 if not found / unreadable.
 *
 * WHAT: best-effort TGT expiry to populate the store's not_after field.
 * WHY:  lets the store's expiry gate warn before the TGT expires mid-session and
 *       trigger auto-refresh (kinit delegation) before a transfer stalls.
 * HOW:  krb5_cc_start_seq_get; iterate with krb5_cc_next_cred; check the first
 *       component of creds.server for "krbtgt"; capture endtime on match.
 *       All cred contents and the cursor are freed on every exit path.
 */
static int64_t
extract_tgt_endtime(krb5_context ctx, krb5_ccache cc)
{
    krb5_cc_cursor  cursor;
    krb5_creds      creds;
    int64_t         endtime = 0;
    krb5_error_code krc;

    if (krb5_cc_start_seq_get(ctx, cc, &cursor) != 0) {
        return 0;
    }

    while ((krc = krb5_cc_next_cred(ctx, cc, &cursor, &creds)) == 0) {
        krb5_data *comp = krb5_princ_component(ctx, creds.server, 0);
        if (comp != NULL
            && comp->length == 6   /* strlen("krbtgt") */
            && memcmp(comp->data, "krbtgt", 6) == 0) {
            endtime = (int64_t)creds.times.endtime;
            krb5_free_cred_contents(ctx, &creds);
            break;
        }
        krb5_free_cred_contents(ctx, &creds);
    }

    krb5_cc_end_seq_get(ctx, cc, &cursor);
    return endtime;
}

/* ---- handler callbacks -------------------------------------------------- */

/*
 * krb5_available — 1 if the resolved ccache has a usable client principal.
 *
 * WHAT: fast probe for auth pre-flight diagnostics and xrdc_cred_available().
 * WHY:  mirrors sec_krb5.c:krb5_have() semantics (open ccache + get_principal).
 * HOW:  init context; open_ccache; krb5_cc_get_principal; free all on every path.
 */
static int
krb5_available(const xrdc_cred_config *cfg)
{
    krb5_context   ctx;
    krb5_ccache    cc;
    krb5_principal me = NULL;
    int            ok = 0;

    if (krb5_init_context(&ctx) != 0) {
        return 0;
    }
    if (open_ccache(ctx, cfg, &cc) == 0) {
        if (krb5_cc_get_principal(ctx, cc, &me) == 0) {
            ok = 1;
            krb5_free_principal(ctx, me);
        }
        krb5_cc_close(ctx, cc);
    }
    krb5_free_context(ctx);
    return ok;
}

/*
 * krb5_acquire — open the ccache, verify it has a principal, fill *out.
 *
 * WHAT: the store's acquire call for XRDC_CRED_KRB5.
 * WHY:  single canonical acquire path for the Kerberos credential.
 * HOW:  1) krb5_init_context (error → XRDC_EAUTH);
 *       2) open_ccache (error → XRDC_EAUTH);
 *       3) krb5_cc_get_principal to confirm a live principal (error → XRDC_EAUTH);
 *       4) format ccache name into s_path;
 *       5) extract_tgt_endtime (best-effort; 0 on failure);
 *       6) free all krb5 objects;
 *       7) fill *out; return 0.
 *
 * Lifetime of s_path: declared static so the buffer remains valid after this
 * function returns. slot_store_view strdup's out->path before any other acquire
 * can overwrite the buffer.
 *
 * Note: TGT renewal (kinit) is the user's responsibility. refresh=NULL is
 * intentional — this handler never invokes kinit or requests a new TGT.
 */
static int
krb5_acquire(const xrdc_cred_config *cfg, xrdc_cred_view *out,
             int64_t *not_after, xrdc_status *st)
{
    /* static: must outlive this return so slot_store_view can strdup it */
    static char s_path[XRDC_PATH_MAX];

    krb5_context   ctx;
    krb5_ccache    cc;
    krb5_principal me = NULL;
    int64_t        endtime;

    if (krb5_init_context(&ctx) != 0) {
        xrdc_status_set(st, XRDC_EAUTH, 0, "krb5: cannot initialise context");
        return -1;
    }

    if (open_ccache(ctx, cfg, &cc) != 0) {
        krb5_free_context(ctx);
        xrdc_status_set(st, XRDC_EAUTH, 0,
                        "krb5: no credential cache (run kinit)");
        return -1;
    }

    if (krb5_cc_get_principal(ctx, cc, &me) != 0) {
        krb5_cc_close(ctx, cc);
        krb5_free_context(ctx);
        xrdc_status_set(st, XRDC_EAUTH, 0,
                        "krb5: ccache has no principal (run kinit)");
        return -1;
    }
    krb5_free_principal(ctx, me);

    format_ccache_name(ctx, cc, s_path, sizeof(s_path));
    endtime = extract_tgt_endtime(ctx, cc);

    krb5_cc_close(ctx, cc);
    krb5_free_context(ctx);

    out->kind      = XRDC_CRED_KRB5;
    out->path      = s_path;   /* static buffer; store deep-copies via slot_store_view */
    out->token     = NULL;
    out->s3_access = NULL;
    out->s3_secret = NULL;

    *not_after = endtime;   /* 0 when TGT endtime could not be read (non-fatal) */
    return 0;
}

/* ---- handler accessor --------------------------------------------------- */

static const xrdc_cred_handler s_krb5_handler = {
    .kind      = XRDC_CRED_KRB5,
    .available = krb5_available,
    .acquire   = krb5_acquire,
    .refresh   = NULL,  /* TGT renewal is user's job (kinit) — not automated here */
};

/*
 * xrdc_cred_krb5 — return the static Kerberos credential handler.
 *
 * WHAT: strong definition that overrides the weak accessor in cred.c.
 * WHY:  weak/strong pattern; this file provides the real krb5 implementation.
 * HOW:  returns a pointer to the file-scoped static handler struct.
 */
const xrdc_cred_handler *
xrdc_cred_krb5(void)
{
    return &s_krb5_handler;
}

#else  /* !XROOTD_HAVE_KRB5 */

/*
 * xrdc_cred_krb5 — compiled-out NULL accessor.
 *
 * WHAT: returns NULL when krb5 dev libs were absent at build time.
 * WHY:  the store NULL-guards all handler slots; returning NULL makes the store
 *       silently skip XRDC_CRED_KRB5 exactly as if no handler were linked.
 * HOW:  mirrors xrdc_sec_krb5() in lib/sec/sec_krb5.c.
 */
const xrdc_cred_handler *
xrdc_cred_krb5(void)
{
    return NULL;
}

#endif  /* XROOTD_HAVE_KRB5 */

/* client/lib/cred_bearer.c
 *
 * WHAT: Bearer-token credential handler for the unified credential store (cred.c).
 *       Implements xrdc_cred_bearer() returning the XRDC_CRED_BEARER handler with
 *       available / acquire / refresh operations.
 * WHY:  Bearer token discovery was only available through the sec_token.c auth
 *       module path; the unified store needs a standalone handler so the same token
 *       is shared between the root:// auth handshake, HTTP Authorization headers,
 *       and auto-refresh — all from a single source of truth.
 * HOW:  Discovery precedence:
 *         cfg->bearer_literal  (verbatim — highest precedence)
 *         > cfg->bearer_path   (read that file, symlink-safe via xrdc_open_credfile)
 *         > xrdc_token_discover() (env/default: $BEARER_TOKEN → $BEARER_TOKEN_FILE
 *                                  → $XDG_RUNTIME_DIR/bt_u<uid> → /tmp/bt_u<uid>)
 *       Lifetime contract (see cred.h acquire pointer doc): tokens can be arbitrarily
 *       large, so a process-lifetime `static char *g_tok` is kept; on each acquire:
 *         free(g_tok); g_tok = <new malloc'd token>; out->token = g_tok;
 *       The store calls strdup on out->token immediately after acquire() returns, so
 *       g_tok stays valid for that window.  No stack pointers; no fixed static buffer.
 *       refresh() is a documented no-op for B4 — oidc-token refresh is deferred to
 *       task C2 where xrdc_cred_autorefresh is adapted to the (cfg, st) contract.
 *
 * ngx-free.  No goto.  Functional/modular: one responsibility per function.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "cred.h"
#include "xrdc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* process-lifetime token buffer */
/*
 * g_tok — owns the most recently acquired token string.
 *
 * WHAT: single malloc'd buffer holding the current token; replaced on every
 *       acquire() call by free+assign.
 * WHY:  tokens are variable-length (JWTs can be several KB); a fixed static char[]
 *       would truncate or waste memory. The free/replace invariant keeps exactly one
 *       live allocation and satisfies the lifetime contract: g_tok is valid until the
 *       next acquire() call overwrites it, which is after the store has already
 *       strdup'd the value.
 * HOW:  module-scoped static pointer; set to NULL at process start (C default).
 *       Only bearer_acquire() touches it.
 */
static char *g_tok = NULL;

/* file reading helper */
/*
 * slurp_credfile — read a credential file safely into a malloc'd string.
 *
 * WHAT: open `path` via xrdc_open_credfile (O_NOFOLLOW, owned-by-euid, non-secret)
 *       and read up to 1 MiB into a malloc'd NUL-terminated string, stripping
 *       trailing whitespace.  Returns the string or NULL on any error.
 * WHY:  cfg->bearer_path points at a user-managed file; symlink safety and owner
 *       check match the behaviour of sec_token.c:slurp() for the file-path case.
 * HOW:  xrdc_open_credfile returns an fd (caller closes); fdopen + fread;
 *       bail if the file exceeds 1 MiB (not a JWT).
 */
static char *
slurp_credfile(const char *path)
{
    int    fd;
    FILE  *fp;
    long   sz;
    size_t got;
    char  *buf;
    size_t i;

    fd = xrdc_open_credfile(path, 0, NULL);
    if (fd < 0) {
        return NULL;
    }
    fp = fdopen(fd, "rb");
    if (fp == NULL) {
        close(fd);
        return NULL;
    }
    if (fseek(fp, 0, SEEK_END) != 0 || (sz = ftell(fp)) < 0) {
        fclose(fp);
        return NULL;
    }
    rewind(fp);
    if (sz > (1 << 20)) {   /* a JWT is never a megabyte */
        fclose(fp);
        return NULL;
    }
    buf = (char *)malloc((size_t)sz + 1);
    if (buf == NULL) {
        fclose(fp);
        return NULL;
    }
    got = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    buf[got] = '\0';

    /* strip trailing whitespace in-place */
    i = got;
    while (i > 0 &&
           (buf[i - 1] == '\n' || buf[i - 1] == '\r' ||
            buf[i - 1] == ' '  || buf[i - 1] == '\t')) {
        buf[--i] = '\0';
    }
    if (buf[0] == '\0') {
        free(buf);
        return NULL;
    }
    return buf;
}

/* token acquisition */
/*
 * obtain_token — apply discovery precedence and return a malloc'd token string.
 *
 * WHAT: cfg->bearer_literal > cfg->bearer_path > xrdc_token_discover().
 * WHY:  explicit CLI/programmatic overrides must win over environment variables so
 *       callers can specify a token for a particular operation.
 * HOW:  three early-return branches; each branch produces a malloc'd string (or NULL)
 *       so the caller owns the result uniformly.
 */
static char *
obtain_token(const xrdc_cred_config *cfg)
{
    if (cfg != NULL && cfg->bearer_literal != NULL && cfg->bearer_literal[0] != '\0') {
        return strdup(cfg->bearer_literal);
    }
    if (cfg != NULL && cfg->bearer_path != NULL && cfg->bearer_path[0] != '\0') {
        return slurp_credfile(cfg->bearer_path);
    }
    return xrdc_token_discover();
}

/* handler callbacks */
/*
 * bearer_available — 1 if a token is obtainable via the discovery precedence.
 *
 * WHAT: fast probe mirroring sec_token.c:token_have(); does NOT cache the result.
 * WHY:  used by auth pre-flight diagnostics and xrdc_cred_available(); must agree
 *       with what acquire() would do.
 * HOW:  obtain_token then free; 1 if non-NULL.
 */
static int
bearer_available(const xrdc_cred_config *cfg)
{
    char *t = obtain_token(cfg);
    if (t == NULL) {
        return 0;
    }
    free(t);
    return 1;
}

/*
 * bearer_acquire — obtain the token, fill *out and *not_after.
 *
 * WHAT: the store's acquire call for XRDC_CRED_BEARER.  Replaces g_tok with the
 *       new token so the pointer survives until the store strdup's it.
 * WHY:  g_tok is the owner of the most-recently-acquired token (free/replace
 *       invariant); out->token = g_tok satisfies the lifetime contract.
 * HOW:  1) obtain_token() for discovery+precedence;
 *       2) free(g_tok); g_tok = new token;
 *       3) fill *out;
 *       4) xrdc_token_meta_get for not_after (0 if not a JWT or exp absent);
 *       5) return 0 on success, -1 + XRDC_EAUTH on no token.
 */
static int
bearer_acquire(const xrdc_cred_config *cfg, xrdc_cred_view *out,
               int64_t *not_after, xrdc_status *st)
{
    char            *tok;
    xrdc_token_meta  meta;

    tok = obtain_token(cfg);
    if (tok == NULL) {
        xrdc_status_set(st, XRDC_EAUTH, 0,
                        "no bearer token (set BEARER_TOKEN, BEARER_TOKEN_FILE, "
                        "or cfg->bearer_literal)");
        return -1;
    }

    /* Replace the process-lifetime buffer; old pointer is freed first. */
    free(g_tok);
    g_tok = tok;

    out->kind      = XRDC_CRED_BEARER;
    out->path      = NULL;
    out->token     = g_tok;   /* valid until next acquire(); store strdup's immediately */
    out->s3_access = NULL;
    out->s3_secret = NULL;
    out->not_after = 0;

    /* Best-effort expiry: parse the JWT exp claim; 0 is acceptable for non-JWTs. */
    xrdc_token_meta_get(g_tok, &meta);
    *not_after = (int64_t)meta.exp;   /* 0 if absent or unparseable; still succeed */

    return 0;
}

/*
 * bearer_refresh — no-op for task B4.
 *
 * WHAT: called by the store when auto_refresh is set and the token is near expiry.
 * WHY:  the oidc-token refresh path (credrefresh.c:run_oidc_token) does not yet
 *       conform to the (cfg, st) handler contract.  Adapting it — mapping
 *       cfg->oidc_account into run_oidc_token and installing the new token into the
 *       store cache — is deferred to task C2.  Returning 0 is correct: the store
 *       treats a non-zero refresh return as best-effort advisory only.
 * HOW:  no-op; suppress unused-parameter warnings.
 */
static int
bearer_refresh(const xrdc_cred_config *cfg, xrdc_status *st)
{
    (void)cfg;
    (void)st;
    return 0;   /* no-op; C2 will wire xrdc_cred_autorefresh here */
}

/* handler accessor */
static const xrdc_cred_handler s_bearer_handler = {
    .kind      = XRDC_CRED_BEARER,
    .available = bearer_available,
    .acquire   = bearer_acquire,
    .refresh   = bearer_refresh,
};

/*
 * xrdc_cred_bearer — return the static bearer-token handler.
 *
 * WHAT: strong definition that overrides the weak accessor in cred.c.
 * WHY:  weak/strong pattern lets lib and unit-test binaries link without every
 *       handler compiled in; this file provides the real bearer implementation.
 * HOW:  returns a pointer to the file-scoped static handler struct.
 */
const xrdc_cred_handler *
xrdc_cred_bearer(void)
{
    return &s_bearer_handler;
}

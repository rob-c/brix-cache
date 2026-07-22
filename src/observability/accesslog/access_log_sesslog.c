/*
 * WHAT: Mirror selected legacy access-log records into the sesslog lifecycle
 * (AUTH events and namespace-verb ATTEMPT/RESULT pairs). Split out of
 * access_log.c for file-size governance; behavior is byte-identical.
 * WHY: Root handlers already have well-audited success/error exits; reusing the
 * access-logger chokepoint gives root:// AUTH and ATTEMPT/RESULT session
 * coverage without touching every handler in the root plane.
 * HOW: brix_log_access populates a brix_access_event_t (access_log_internal.h)
 * and calls brix_access_maybe_sesslog(); this file owns that entry point plus
 * all of its file-local classification helpers and lookup tables.
 */

#include "core/ngx_brix_module.h"
#include "core/compat/cstr.h"
#include "observability/accesslog/access_log.h"
#include "observability/accesslog/access_log_internal.h"
#include "observability/sesslog/sesslog_ngx.h"

#include <string.h>

static ngx_flag_t
brix_access_streq(const char *a, const char *b)
{
    return a != NULL && b != NULL && ngx_strcmp(a, b) == 0;
}

static ngx_flag_t
brix_access_contains(const char *s, const char *needle)
{
    return s != NULL && needle != NULL && strstr(s, needle) != NULL;
}

/*
 * WHAT: Convert the legacy access-log auth detail into a sesslog auth method.
 * WHY: Existing root auth handlers already log AUTH records; piggybacking those
 * calls keeps method-specific auth code untouched.
 * HOW: Prefer the detail token when it names a method, otherwise derive from
 * the authenticated ctx/config state.
 */
static brix_sess_am_t
brix_access_sess_auth_method(brix_ctx_t *ctx,
    ngx_stream_brix_srv_conf_t *conf, const char *detail)
{
    if (brix_access_streq(detail, "gsi")) {
        return BRIX_SESS_AM_GSI;
    }
    if (brix_access_streq(detail, "ztn") || brix_access_streq(detail, "token")) {
        return BRIX_SESS_AM_TOKEN;
    }
    if (brix_access_streq(detail, "sss")) {
        return BRIX_SESS_AM_SSS;
    }
    if (brix_access_streq(detail, "krb5")) {
        return BRIX_SESS_AM_KRB5;
    }
    if (brix_access_streq(detail, "pwd")) {
        return BRIX_SESS_AM_PWD;
    }
    if (brix_access_streq(detail, "unix")) {
        return BRIX_SESS_AM_UNIX;
    }
    if (brix_access_streq(detail, "host")) {
        return BRIX_SESS_AM_HOST;
    }
    if (ctx != NULL && ctx->token.auth) {
        return BRIX_SESS_AM_TOKEN;
    }
    return brix_sess_am_from_stream_auth(conf != NULL ? conf->auth
                                                      : BRIX_AUTH_NONE);
}

/*
 * WHAT: Collapse method-specific auth messages into stable sesslog err tokens.
 * WHY: AUTH failure text is deliberately human-readable and inconsistent; the
 * session grammar requires a small closed token set.
 * HOW: Preserve high-signal substrings where available and fall back to kXR
 * status mapping.
 */
static const char *
brix_access_sess_auth_err(uint16_t errcode, const char *errmsg, char *scratch,
    size_t scratch_size)
{
    if (brix_access_contains(errmsg, "scope")) {
        return "scope";
    }
    if (brix_access_contains(errmsg, "expired")) {
        return "expired-cert";
    }
    if (brix_access_contains(errmsg, "signature")
        || brix_access_contains(errmsg, "validation")
        || brix_access_contains(errmsg, "verification")
        || brix_access_contains(errmsg, "decrypt"))
    {
        return "bad-signature";
    }
    if (brix_access_contains(errmsg, "rate limit")) {
        return "busy";
    }
    if (brix_access_contains(errmsg, "not authorized")
        || brix_access_contains(errmsg, "denied"))
    {
        return "permission";
    }

    return brix_sesslog_err_from_kxr((int) errcode, scratch, scratch_size);
}

/*
 * WHAT: Static verb→sesslog-mode mapping for the fixed-mode namespace verbs.
 * WHY: The mode assignment for these verbs is a pure lookup; expressing it as a
 * data table (rather than an if/else ladder) keeps the classifier flat and makes
 * adding a verb a one-row edit (coding-standards §8.6, table-driven dispatch).
 * HOW: One row per verb naming its sesslog mode. OPEN is deliberately absent —
 * its mode depends on the detail token and is resolved separately.
 */
typedef struct {
    const char       *verb;
    brix_sess_mode_t  mode;
} brix_access_verb_mode_t;

static const brix_access_verb_mode_t  brix_access_verb_modes[] = {
    { "STAT",     BRIX_SESS_MODE_META },
    { "STATX",    BRIX_SESS_MODE_META },
    { "LOCATE",   BRIX_SESS_MODE_META },
    { "QUERY",    BRIX_SESS_MODE_META },
    { "SET",      BRIX_SESS_MODE_META },
    { "READLINK", BRIX_SESS_MODE_META },
    { "DIRLIST",  BRIX_SESS_MODE_LIST },
    { "RM",       BRIX_SESS_MODE_DELETE },
    { "RMDIR",    BRIX_SESS_MODE_DELETE },
    { "DELETE",   BRIX_SESS_MODE_DELETE },
    { "MKDIR",    BRIX_SESS_MODE_WRITE },
    { "MV",       BRIX_SESS_MODE_WRITE },
    { "TRUNCATE", BRIX_SESS_MODE_WRITE },
    { "CHMOD",    BRIX_SESS_MODE_WRITE },
    { "SETATTR",  BRIX_SESS_MODE_WRITE },
    { "LINK",     BRIX_SESS_MODE_WRITE },
    { "SYMLINK",  BRIX_SESS_MODE_WRITE },
};

/*
 * WHAT: Resolve an OPEN verb to its sesslog mode from the detail token.
 * WHY: OPEN is the one namespace verb whose direction (read vs write) is not
 * fixed by the verb name — write/staging/tpc-pull opens count as WRITE, every
 * other open as READ.
 * HOW: Inspect the detail substring; return WRITE for any write-shaped open,
 * READ otherwise. Behavior identical to the former inline OPEN branch.
 */
static brix_sess_mode_t
brix_access_open_mode(const char *detail)
{
    if (brix_access_contains(detail, "wr")
        || brix_access_contains(detail, "staging")
        || brix_access_contains(detail, "tpc-pull"))
    {
        return BRIX_SESS_MODE_WRITE;
    }
    return BRIX_SESS_MODE_READ;
}

/*
 * WHAT: Map root access-log verbs to sesslog access modes.
 * WHY: The legacy access logger is already present on namespace-operation exits;
 * this table lets it produce uniform ATTEMPT/RESULT pairs without touching every
 * handler in the root plane.
 * HOW: OPEN resolves via detail (brix_access_open_mode); every other namespace
 * verb is a row lookup in brix_access_verb_modes. Lifecycle and pure I/O verbs
 * match nothing and return 0 (they aggregate into AUTH, XFER, or END).
 */
static ngx_flag_t
brix_access_sess_mode(const char *verb, const char *detail,
    brix_sess_mode_t *mode)
{
    size_t  i;

    if (verb == NULL || mode == NULL) {
        return 0;
    }

    if (brix_access_streq(verb, "OPEN")) {
        *mode = brix_access_open_mode(detail);
        return 1;
    }

    for (i = 0; i < sizeof(brix_access_verb_modes)
                    / sizeof(brix_access_verb_modes[0]); i++)
    {
        if (brix_access_streq(verb, brix_access_verb_modes[i].verb)) {
            *mode = brix_access_verb_modes[i].mode;
            return 1;
        }
    }

    return 0;
}

/*
 * WHAT: Emit the sesslog AUTH event for an AUTH access-log record.
 * WHY: Keeps the AUTH-specific method/identity/err derivation out of the mirror
 * dispatcher so each stays single-purpose.
 * HOW: On success pass DN/VO (or "-"); on failure derive a stable err token.
 */
static void
brix_access_sesslog_auth(brix_ctx_t *ctx, ngx_stream_brix_srv_conf_t *conf,
    const brix_access_event_t *ev)
{
    char         errscratch[64];
    const char  *err;

    err = ev->xrd_ok ? NULL
                     : brix_access_sess_auth_err(ev->errcode, ev->errmsg,
                                                 errscratch, sizeof(errscratch));
    brix_sess_auth(ctx->sess, ev->xrd_ok,
                   brix_access_sess_auth_method(ctx, conf, ev->detail),
                   ev->xrd_ok && ctx->login.dn[0] != '\0'
                       ? ctx->login.dn : "-",
                   ev->xrd_ok && ctx->login.primary_vo[0] != '\0'
                       ? ctx->login.primary_vo : "-",
                   err);
}

/*
 * WHAT: Emit the sesslog ATTEMPT/RESULT pair for a namespace access-log record.
 * WHY: Isolates the namespace-verb path (mode classification + attempt/result)
 * from the AUTH path in the dispatcher.
 * HOW: Classify the verb into a mode; ignore verbs with no mode; otherwise emit
 * ATTEMPT then RESULT with a derived err token on failure.
 */
static void
brix_access_sesslog_namespace(brix_ctx_t *ctx, const brix_access_event_t *ev)
{
    char              errscratch[64];
    brix_sess_mode_t  mode = 0;
    const char       *err;
    const char       *path;

    if (!brix_access_sess_mode(ev->verb, ev->detail, &mode)) {
        return;
    }

    err = ev->xrd_ok ? NULL
                     : brix_sesslog_err_from_kxr((int) ev->errcode, errscratch,
                                                 sizeof(errscratch));
    path = ev->path != NULL ? ev->path : "-";
    brix_sess_attempt(ctx->sess, path, mode);
    brix_sess_result(ctx->sess, ev->xrd_ok, path, mode, err);
}

/*
 * WHAT: Mirror selected legacy access-log calls into the sesslog lifecycle.
 * WHY: Root handlers already have well-audited success/error exits; using this
 * chokepoint gives root:// ATTEMPT/RESULT and AUTH coverage with minimal risk.
 * HOW: AUTH emits auth events; namespace verbs emit immediate ATTEMPT followed
 * by RESULT; pure data I/O is intentionally ignored and summarized by XFER.
 */
void
brix_access_maybe_sesslog(brix_ctx_t *ctx, ngx_stream_brix_srv_conf_t *conf,
    const brix_access_event_t *ev)
{
    if (ctx == NULL || ctx->sess == NULL || ev->verb == NULL) {
        return;
    }

    if (brix_access_streq(ev->verb, "AUTH")) {
        brix_access_sesslog_auth(ctx, conf, ev);
        return;
    }

    brix_access_sesslog_namespace(ctx, ev);
}

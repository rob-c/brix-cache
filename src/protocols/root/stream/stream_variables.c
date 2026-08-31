/*
 * stream_variables.c — the $brix_session_* nginx-variable surface for the
 * root:// stream plane (phase 106 W2).
 *
 * WHAT: Registers the session-scoped variables an operator needs to write a
 *       `stream {}` access_log for root:// traffic, and implements their
 *       get_handlers.
 *
 * WHY:  Before this file the stream plane registered NO variables at all
 *       (ngx_stream_add_variable appeared nowhere in the tree), so the
 *       flagship protocol was invisible to nginx's own access_log. Operators
 *       could see aggregate Prometheus counters or unstructured error-log
 *       lines, and nothing else: there was no way to answer "who moved what,
 *       over which session" with the logging tool they already use.
 *
 * HOW:  SESSION scope, deliberately. A stream session is long-lived and
 *       carries many XRootD ops, so a variable evaluated at log time describes
 *       the SESSION, not an op — "the path" or "the status" would be
 *       ill-defined, and inventing a per-op stream log is a separate problem
 *       nginx's access_log cannot express. Every variable here is therefore a
 *       session total or a session-stable identity, which is exactly what a
 *       single access_log line at session close should carry.
 *
 *       Handler rules, per phase 106's variable-handler trap:
 *         1. ctx may be NULL — a connection can be closed before the module
 *            attaches its context (a port scan, a TLS failure, a client that
 *            hangs up mid-handshake). Every handler answers "-" instead of
 *            dereferencing.
 *         2. Values are either static strings or copied into the CONNECTION
 *            pool, which outlives the log phase. Never the request pool: there
 *            isn't one on the stream plane.
 *         3. Identity is session-stable once login completes, so these are
 *            cacheable; the byte totals change as the session runs and are
 *            marked NOCACHEABLE.
 *
 *       SECURITY: these expose the SUBJECT of an identity (DN, VO, login
 *       user), never the credential that proved it. ctx->bearer_token and the
 *       GSI/sigver key material are deliberately absent and must stay absent —
 *       a variable is loggable, and a logged bearer token is a credential
 *       leak.
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include "core/ngx_brix_module.h"
#include "core/types/context.h"

#include "protocols/root/stream/stream_variables.h"


/* The sentinel for "brix has nothing to say about this session". Distinct from
 * an empty value so a log line never silently reads as a zero-byte session. */
static const char  brix_stream_var_none[] = "-";


static brix_ctx_t *
brix_stream_var_ctx(ngx_stream_session_t *s)
{
    return ngx_stream_get_module_ctx(s, ngx_stream_brix_module);
}


static ngx_int_t
brix_stream_var_none_value(ngx_stream_variable_value_t *v,
    ngx_uint_t no_cacheable)
{
    v->len = sizeof(brix_stream_var_none) - 1;
    v->valid = 1;
    v->no_cacheable = no_cacheable ? 1 : 0;
    v->not_found = 0;
    v->data = (u_char *) brix_stream_var_none;
    return NGX_OK;
}


/*
 * brix_stream_var_cstr — publish a NUL-terminated session string.
 *
 * Copies into the CONNECTION pool: the session's own buffers are reused across
 * ops, so handing nginx a pointer into ctx would risk the value changing (or
 * the buffer being recycled) between the handler running and the log line
 * being written. An empty source string reports the sentinel, not "".
 */
static ngx_int_t
brix_stream_var_cstr(ngx_stream_session_t *s, ngx_stream_variable_value_t *v,
    const char *src, ngx_uint_t no_cacheable)
{
    size_t   len;
    u_char  *copy;

    if (src == NULL || *src == '\0') {
        return brix_stream_var_none_value(v, no_cacheable);
    }

    len = ngx_strlen(src);
    copy = ngx_pnalloc(s->connection->pool, len);
    if (copy == NULL) {
        return brix_stream_var_none_value(v, no_cacheable);
    }
    ngx_memcpy(copy, src, len);

    v->len = (unsigned) len;
    v->valid = 1;
    v->no_cacheable = no_cacheable ? 1 : 0;
    v->not_found = 0;
    v->data = copy;
    return NGX_OK;
}


static ngx_int_t
brix_stream_var_size(ngx_stream_session_t *s, ngx_stream_variable_value_t *v,
    size_t value)
{
    u_char  *buf;

    buf = ngx_pnalloc(s->connection->pool, NGX_SIZE_T_LEN);
    if (buf == NULL) {
        return brix_stream_var_none_value(v, 1);
    }

    v->len = (unsigned) (ngx_sprintf(buf, "%uz", value) - buf);
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->data = buf;
    return NGX_OK;
}


/*
 * One handler per SHAPE, not per variable.
 *
 * Six near-identical get_handlers (fetch ctx, NULL-check, read one field) is
 * the cloned-logic shape the duplication guard rejects, and nginx already
 * provides the mechanism to avoid it: the `data` member of ngx_stream_variable_t
 * is passed to the handler, so one handler can serve every variable of a given
 * shape with `data` selecting the field.
 */
typedef enum {
    BRIX_SV_PROTOCOL = 0,
    BRIX_SV_DN,
    BRIX_SV_VO,
    BRIX_SV_USER,
    BRIX_SV_AUTH,
    BRIX_SV_TLS,
    BRIX_SV_BYTES_OUT,
    BRIX_SV_BYTES_IN
} brix_stream_var_e;


/*
 * brix_stream_session_auth — how this session authenticated.
 *
 * Deliberately NOT login.logged_in / login.auth_done. Those are LIVE
 * authorization state, and kXR_endsess clears both on purpose
 * (session/lifecycle.c:96-97) so a client cannot keep using the connection
 * after ending its session. A well-behaved client therefore ends its session
 * before closing, and by the time nginx writes the access-log line both flags
 * read 0 — every real transfer would be logged as "brix never ran". A log
 * variable needs the HISTORICAL fact, not the current permission, so this
 * reads evidence that is never revoked: the presented login name, and is_bound
 * for the kXR_bind parallel DATA channel, which inherits the primary session's
 * auth and carries no login of its own (and is where the bytes actually move).
 */
static const char *
brix_stream_session_auth(const brix_ctx_t *ctx)
{
    if (ctx->token.auth) {
        return "token";
    }
    if (ctx->login.dn[0] != '\0') {
        return "gsi";
    }
    if (ctx->login.user[0] != '\0' || ctx->is_bound) {
        return "none";
    }
    return NULL;                 /* caller reports the sentinel */
}


/* The string value for `which`, or NULL when brix has nothing to report. */
static const char *
brix_stream_str_field(ngx_stream_session_t *s, const brix_ctx_t *ctx,
    brix_stream_var_e which)
{
    switch (which) {
    case BRIX_SV_PROTOCOL:
        return (ctx->protocol_label[0] != '\0') ? ctx->protocol_label : "root";
    case BRIX_SV_DN:
        return ctx->login.dn;
    case BRIX_SV_VO:
        return ctx->login.primary_vo;
    case BRIX_SV_USER:
        return ctx->login.user;
    case BRIX_SV_AUTH:
        return brix_stream_session_auth(ctx);
    case BRIX_SV_TLS:
        return (s->connection != NULL && s->connection->ssl != NULL)
               ? "on" : "off";
    default:
        return NULL;
    }
}


/* $brix_protocol, $brix_session_{dn,vo,user,auth,tls}. */
static ngx_int_t
brix_stream_var_str(ngx_stream_session_t *s, ngx_stream_variable_value_t *v,
    uintptr_t data)
{
    brix_ctx_t *ctx = brix_stream_var_ctx(s);

    if (ctx == NULL) {
        /* $brix_session_tls needs no ctx: the transport is a property of the
         * connection, and reporting "-" for a TLS connection brix never got to
         * serve would be wrong. */
        if ((brix_stream_var_e) data == BRIX_SV_TLS) {
            return brix_stream_var_cstr(s, v,
                (s->connection != NULL && s->connection->ssl != NULL)
                ? "on" : "off", 0);
        }
        return brix_stream_var_none_value(v, 0);
    }

    return brix_stream_var_cstr(s, v,
        brix_stream_str_field(s, ctx, (brix_stream_var_e) data), 0);
}


/* $brix_session_bytes_out / _in. */
static ngx_int_t
brix_stream_var_bytes(ngx_stream_session_t *s, ngx_stream_variable_value_t *v,
    uintptr_t data)
{
    brix_ctx_t *ctx = brix_stream_var_ctx(s);

    if (ctx == NULL) {
        return brix_stream_var_none_value(v, 1);
    }
    return brix_stream_var_size(s, v,
        ((brix_stream_var_e) data == BRIX_SV_BYTES_OUT)
        ? ctx->totals.bytes : ctx->totals.bytes_written);
}


static ngx_stream_variable_t  brix_stream_variables[] = {
    { ngx_string("brix_protocol"), NULL, brix_stream_var_str,
      BRIX_SV_PROTOCOL, 0, 0 },
    { ngx_string("brix_session_dn"), NULL, brix_stream_var_str,
      BRIX_SV_DN, 0, 0 },
    { ngx_string("brix_session_vo"), NULL, brix_stream_var_str,
      BRIX_SV_VO, 0, 0 },
    { ngx_string("brix_session_user"), NULL, brix_stream_var_str,
      BRIX_SV_USER, 0, 0 },
    { ngx_string("brix_session_auth"), NULL, brix_stream_var_str,
      BRIX_SV_AUTH, 0, 0 },
    { ngx_string("brix_session_tls"), NULL, brix_stream_var_str,
      BRIX_SV_TLS, 0, 0 },
    { ngx_string("brix_session_bytes_out"), NULL, brix_stream_var_bytes,
      BRIX_SV_BYTES_OUT, NGX_STREAM_VAR_NOCACHEABLE, 0 },
    { ngx_string("brix_session_bytes_in"), NULL, brix_stream_var_bytes,
      BRIX_SV_BYTES_IN, NGX_STREAM_VAR_NOCACHEABLE, 0 },
      ngx_stream_null_variable
};


ngx_int_t
brix_stream_add_variables(ngx_conf_t *cf)
{
    ngx_stream_variable_t *v, *nv;

    for (v = brix_stream_variables; v->name.len; v++) {
        nv = ngx_stream_add_variable(cf, &v->name, v->flags);
        if (nv == NULL) {
            return NGX_ERROR;
        }
        nv->get_handler = v->get_handler;
        nv->data = v->data;
    }

    return NGX_OK;
}

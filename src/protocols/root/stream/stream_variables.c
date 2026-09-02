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
#include <string.h>   /* strchr — first-FQAN split */

#include "core/ngx_brix_module.h"
#include "core/types/context.h"
#include "core/types/identity.h"            /* brix_identity_*_cstr (phase-110 W2) */
#include "observability/metrics/unified.h"  /* the shared name functions (rule 2) */
#include "fs/backend/sd.h"                  /* brix_sd_backend_name ($brix_tier)  */

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
    BRIX_SV_FQAN,
    BRIX_SV_SUB,        /* the identity SUBJECT ($brix_sub; alias $brix_session_user) */
    BRIX_SV_ISSUER,
    BRIX_SV_USER,       /* the MAPPED local account ($brix_user) */
    BRIX_SV_AUTH,
    BRIX_SV_TLS,
    BRIX_SV_TIER,
    BRIX_SV_ORIGIN,
    BRIX_SV_OP,
    BRIX_SV_STATUS,
    BRIX_SV_CACHE,
    BRIX_SV_PATH,
    BRIX_SV_CHECKSUM,
    BRIX_SV_BYTES_OUT,
    BRIX_SV_BYTES_IN,
    BRIX_SV_OPS,
    BRIX_SV_BACKEND_TIME,
    BRIX_SV_DURATION
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
    ngx_uint_t  bit;

    /* Derive WHICH method from historical session evidence (the comment above),
     * then render it through the SHARED name function so the stream
     * $brix_auth_method speaks the exact vocabulary the HTTP variable, the JSON
     * "auth_method" key and the brix_auth_total{method} label speak (phase-110
     * rule 2 / R12). */
    if (ctx->token.auth) {
        bit = BRIX_AUTHN_TOKEN;
    } else if (ctx->login.dn[0] != '\0') {
        bit = BRIX_AUTHN_GSI;
    } else if (ctx->login.user[0] != '\0' || ctx->is_bound) {
        bit = BRIX_AUTHN_NONE;               /* → "none" */
    } else {
        return NULL;                         /* caller reports the sentinel */
    }
    return brix_metric_auth_method_name(bit);
}


/* The export's shared conf for $brix_tier / $brix_origin. */
static ngx_http_brix_shared_conf_t *
brix_stream_common_conf(ngx_stream_session_t *s)
{
    ngx_stream_brix_srv_conf_t *sc =
        ngx_stream_get_module_srv_conf(s, ngx_stream_brix_module);

    return sc != NULL ? &sc->common : NULL;
}


/* Forward decl: the operative-FQAN splitter, defined below with the other
 * non-identity string helpers but used by the identity field switch. */
static const char *brix_stream_first_vo(ngx_stream_session_t *s,
    const brix_identity_t *id, const brix_ctx_t *ctx);


/* An identity cstr, or a login.* fallback when the identity field is empty —
 * the dn/vo shape (no phase-106 value lost by the rename). */
static const char *
brix_stream_id_or(const char *idval, const char *fallback)
{
    return (idval != NULL && idval[0] != '\0') ? idval : fallback;
}


/* $brix_sub: token sub / S3 key, else the DN, else the kXR_login username the
 * client presented (the phase-106 $brix_session_user value — this alias). */
static const char *
brix_stream_subject(const brix_identity_t *id, const brix_ctx_t *ctx)
{
    const char *s = id != NULL ? brix_identity_subject_cstr(id) : NULL;

    if (s != NULL && s[0] != '\0') {
        return s;
    }
    s = id != NULL ? brix_identity_dn_cstr(id) : NULL;
    if (s != NULL && s[0] != '\0') {
        return s;
    }
    return ctx->login.dn[0] != '\0' ? ctx->login.dn : ctx->login.user;
}


static const char *
brix_stream_issuer(const brix_identity_t *id)
{
    return (id != NULL && id->issuer.len > 0)
           ? (const char *) id->issuer.data : NULL;
}


/* The MAPPED local account ($brix_user, impersonation target) — distinct from
 * the subject. "-" when the identity did not map. */
static const char *
brix_stream_mapped_user(const brix_identity_t *id)
{
    return (id != NULL && id->mapped_resolved && id->mapped_user[0] != '\0')
           ? id->mapped_user : NULL;
}


/*
 * Identity on the stream plane (phase-110 W2): the SAME meaning as the HTTP
 * variables. The canonical source is ctx->identity (the phase-2 identity object
 * every plane populates at authn); the legacy login.* fields are the fallback
 * for a session that authenticated through a path that filled only them, so
 * the phase-106 $brix_session_dn/vo values are never lost by the rename.
 */
static const char *
brix_stream_identity_field(ngx_stream_session_t *sess, const brix_ctx_t *ctx,
    brix_stream_var_e which)
{
    const brix_identity_t *id = ctx->identity;

    switch (which) {
    case BRIX_SV_DN:
        return brix_stream_id_or(id != NULL ? brix_identity_dn_cstr(id) : NULL,
                                 ctx->login.dn);
    case BRIX_SV_VO:
        /* The FULL VO list; login.primary_vo fallback keeps the phase-106
         * $brix_session_vo value. */
        return brix_stream_id_or(id != NULL ? brix_identity_vo_csv_cstr(id)
                                            : NULL, ctx->login.primary_vo);
    case BRIX_SV_FQAN:
        /* The OPERATIVE FQAN — the FIRST field of the VO list, matching the
         * HTTP handler's "first verified entry", NOT the whole list. */
        return brix_stream_first_vo(sess, id, ctx);
    case BRIX_SV_SUB:
        return brix_stream_subject(id, ctx);
    case BRIX_SV_ISSUER:
        return brix_stream_issuer(id);   /* root:// rarely carries one → "-" */
    case BRIX_SV_USER:
        return brix_stream_mapped_user(id);
    default:
        return NULL;
    }
}


/* The operative FQAN for $brix_fqan: the first comma-separated field of the
 * identity's VO list (matching the HTTP handler's first-vo_list-entry rule),
 * else the phase-106 login.primary_vo, else NULL (sentinel). A multi-VO CSV is
 * truncated at the first comma into a connection-pool copy so the value is a
 * single NUL-terminated FQAN, never the whole list. */
static const char *
brix_stream_first_vo(ngx_stream_session_t *s, const brix_identity_t *id,
    const brix_ctx_t *ctx)
{
    const char *csv = id != NULL ? brix_identity_vo_csv_cstr(id) : NULL;
    const char *comma;
    char       *first;
    size_t      n;

    if (csv == NULL || csv[0] == '\0') {
        return ctx->login.primary_vo[0] != '\0' ? ctx->login.primary_vo : NULL;
    }
    comma = strchr(csv, ',');
    if (comma == NULL) {
        return csv;                       /* single field, already terminated */
    }
    n = (size_t) (comma - csv);
    first = ngx_pnalloc(s->connection->pool, n + 1);
    if (first == NULL) {
        return csv;                       /* degrade to the full list */
    }
    ngx_memcpy(first, csv, n);
    first[n] = '\0';
    return first;
}


/* Session-stable transport/config string fields. */
static const char *
brix_stream_conf_field(ngx_stream_session_t *s, const brix_ctx_t *ctx,
    brix_stream_var_e which)
{
    ngx_http_brix_shared_conf_t *c;

    switch (which) {
    case BRIX_SV_PROTOCOL:
        return (ctx->protocol_label[0] != '\0') ? ctx->protocol_label : "root";
    case BRIX_SV_AUTH:
        return brix_stream_session_auth(ctx);
    case BRIX_SV_TLS:
        return (s->connection != NULL && s->connection->ssl != NULL)
               ? "on" : "off";
    case BRIX_SV_TIER:
        c = brix_stream_common_conf(s);
        /* NULL instance = default POSIX backend (vfs.h), as on the HTTP plane. */
        return c == NULL ? NULL
               : (c->storage_instance != NULL
                  ? brix_sd_backend_name(c->storage_instance) : "posix");
    case BRIX_SV_ORIGIN:
        c = brix_stream_common_conf(s);
        /* A root:// origin is a local export path with no user:pass@ userinfo,
         * so no stripping is needed; it is NUL-terminated storage. */
        return (c != NULL && c->storage_backend.len > 0)
               ? (const char *) c->storage_backend.data : NULL;
    default:
        return NULL;
    }
}


/* Primary-op string facts the session's I/O monitor recorded. */
static const char *
brix_stream_monitor_field(const brix_ctx_t *ctx, brix_stream_var_e which)
{
    const brix_io_monitor_t *m = &ctx->io_monitor;

    switch (which) {
    case BRIX_SV_OP:
        return m->have_op ? brix_metric_op_name(m->op) : NULL;
    case BRIX_SV_STATUS:
        return (m->have_op || m->err != BRIX_ERR_NONE)
               ? brix_metric_err_name(m->err) : NULL;
    case BRIX_SV_CACHE:
        return m->cache != BRIX_CACHE_STATUS_NONE
               ? brix_metric_cache_status_name(m->cache) : NULL;
    case BRIX_SV_PATH:
        return m->path_len > 0 ? m->path : NULL;
    case BRIX_SV_CHECKSUM:
        return m->have_checksum ? m->checksum : NULL;
    default:
        return NULL;
    }
}


/* Non-identity string fields: config facts + monitor facts. The monitor group
 * (OP..CHECKSUM) is a contiguous enum run, so the split is a range test. */
static const char *
brix_stream_str_field(ngx_stream_session_t *s, const brix_ctx_t *ctx,
    brix_stream_var_e which)
{
    if (which >= BRIX_SV_OP && which <= BRIX_SV_CHECKSUM) {
        return brix_stream_monitor_field(ctx, which);
    }
    return brix_stream_conf_field(s, ctx, which);
}


/* Is `which` one of the identity-shaped fields (routed to identity_field)? */
static int
brix_stream_is_identity(brix_stream_var_e which)
{
    switch (which) {
    case BRIX_SV_DN:
    case BRIX_SV_VO:
    case BRIX_SV_FQAN:
    case BRIX_SV_SUB:
    case BRIX_SV_ISSUER:
    case BRIX_SV_USER:
        return 1;
    default:
        return 0;
    }
}


/* $brix_protocol, the identity set, $brix_{auth,tls,tier,origin,op,status,
 * cache,path,checksum} — every string-valued stream variable. */
static ngx_int_t
brix_stream_var_str(ngx_stream_session_t *s, ngx_stream_variable_value_t *v,
    uintptr_t data)
{
    brix_stream_var_e  which = (brix_stream_var_e) data;
    brix_ctx_t        *ctx = brix_stream_var_ctx(s);
    const char        *val;

    if (ctx == NULL) {
        /* $brix_tls needs no ctx: the transport is a property of the
         * connection, and reporting "-" for a TLS connection brix never got to
         * serve would be wrong. */
        if (which == BRIX_SV_TLS) {
            return brix_stream_var_cstr(s, v,
                (s->connection != NULL && s->connection->ssl != NULL)
                ? "on" : "off", 0);
        }
        return brix_stream_var_none_value(v, 0);
    }

    val = brix_stream_is_identity(which)
          ? brix_stream_identity_field(s, ctx, which)
          : brix_stream_str_field(s, ctx, which);
    /* The monitor-derived fields (op/status/cache/path/checksum) change as the
     * session proceeds, so they are NOCACHEABLE; the session-stable ones are
     * cacheable. The flag on the variable-table row governs nginx's caching;
     * here we just publish the value. */
    return brix_stream_var_cstr(s, v, val, 0);
}


/* $brix_session_bytes_out / _in and their $brix_bytes_served / _received
 * successors — the session transfer totals. */
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


/* $brix_ops — the count of brix ops the session performed. */
static ngx_int_t
brix_stream_var_ops(ngx_stream_session_t *s, ngx_stream_variable_value_t *v,
    uintptr_t data)
{
    brix_ctx_t *ctx = brix_stream_var_ctx(s);

    (void) data;
    if (ctx == NULL) {
        return brix_stream_var_none_value(v, 1);
    }
    return brix_stream_var_size(s, v, (size_t) ctx->io_monitor.ops);
}


/* Render `usec` microseconds as seconds.mmm (the $request_time / $session_time
 * shape) for $brix_backend_time and $brix_duration. */
static ngx_int_t
brix_stream_var_seconds(ngx_stream_session_t *s, ngx_stream_variable_value_t *v,
    ngx_msec_int_t ms)
{
    u_char *p;

    p = ngx_pnalloc(s->connection->pool, NGX_TIME_T_LEN + 4);
    if (p == NULL) {
        return brix_stream_var_none_value(v, 1);
    }
    ms = ngx_max(ms, 0);
    v->len = (unsigned) (ngx_sprintf(p, "%T.%03M", (time_t) ms / 1000,
                                     ms % 1000) - p);
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->data = p;
    return NGX_OK;
}


/* $brix_backend_time — summed VFS op latency of the session, seconds.mmm. */
static ngx_int_t
brix_stream_var_backend_time(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    brix_ctx_t *ctx = brix_stream_var_ctx(s);

    (void) data;
    if (ctx == NULL) {
        return brix_stream_var_none_value(v, 1);
    }
    return brix_stream_var_seconds(s, v,
        (ngx_msec_int_t) ctx->io_monitor.backend_usec / 1000);
}


/* $brix_duration — wall time of the session, byte-identical to nginx's
 * $session_time (rule 6: the one transport fact brix twins, because nginx
 * spells it $request_time on HTTP and $session_time on stream). */
static ngx_int_t
brix_stream_var_duration(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    ngx_time_t *tp = ngx_timeofday();

    (void) data;
    return brix_stream_var_seconds(s, v,
        (ngx_msec_int_t) ((tp->sec - s->start_sec) * 1000
                          + (tp->msec - s->start_msec)));
}


static ngx_stream_variable_t  brix_stream_variables[] = {
    { ngx_string("brix_protocol"), NULL, brix_stream_var_str,
      BRIX_SV_PROTOCOL, 0, 0 },

    /* Identity — the SAME names as the HTTP plane (phase-110 W2). */
    { ngx_string("brix_dn"), NULL, brix_stream_var_str, BRIX_SV_DN, 0, 0 },
    { ngx_string("brix_vo"), NULL, brix_stream_var_str, BRIX_SV_VO, 0, 0 },
    { ngx_string("brix_fqan"), NULL, brix_stream_var_str, BRIX_SV_FQAN, 0, 0 },
    { ngx_string("brix_sub"), NULL, brix_stream_var_str, BRIX_SV_SUB, 0, 0 },
    { ngx_string("brix_issuer"), NULL, brix_stream_var_str,
      BRIX_SV_ISSUER, 0, 0 },
    { ngx_string("brix_user"), NULL, brix_stream_var_str, BRIX_SV_USER, 0, 0 },
    { ngx_string("brix_auth_method"), NULL, brix_stream_var_str,
      BRIX_SV_AUTH, 0, 0 },
    { ngx_string("brix_tls"), NULL, brix_stream_var_str, BRIX_SV_TLS, 0, 0 },
    { ngx_string("brix_tier"), NULL, brix_stream_var_str, BRIX_SV_TIER, 0, 0 },
    { ngx_string("brix_origin"), NULL, brix_stream_var_str,
      BRIX_SV_ORIGIN, 0, 0 },

    /* Per-session data-plane facts from the I/O monitor. */
    { ngx_string("brix_op"), NULL, brix_stream_var_str,
      BRIX_SV_OP, NGX_STREAM_VAR_NOCACHEABLE, 0 },
    { ngx_string("brix_status"), NULL, brix_stream_var_str,
      BRIX_SV_STATUS, NGX_STREAM_VAR_NOCACHEABLE, 0 },
    { ngx_string("brix_cache_status"), NULL, brix_stream_var_str,
      BRIX_SV_CACHE, NGX_STREAM_VAR_NOCACHEABLE, 0 },
    { ngx_string("brix_path"), NULL, brix_stream_var_str,
      BRIX_SV_PATH, NGX_STREAM_VAR_NOCACHEABLE, 0 },
    { ngx_string("brix_checksum"), NULL, brix_stream_var_str,
      BRIX_SV_CHECKSUM, NGX_STREAM_VAR_NOCACHEABLE, 0 },
    { ngx_string("brix_bytes_served"), NULL, brix_stream_var_bytes,
      BRIX_SV_BYTES_OUT, NGX_STREAM_VAR_NOCACHEABLE, 0 },
    { ngx_string("brix_bytes_received"), NULL, brix_stream_var_bytes,
      BRIX_SV_BYTES_IN, NGX_STREAM_VAR_NOCACHEABLE, 0 },
    { ngx_string("brix_ops"), NULL, brix_stream_var_ops,
      BRIX_SV_OPS, NGX_STREAM_VAR_NOCACHEABLE, 0 },
    { ngx_string("brix_backend_time"), NULL, brix_stream_var_backend_time,
      BRIX_SV_BACKEND_TIME, NGX_STREAM_VAR_NOCACHEABLE, 0 },
    { ngx_string("brix_duration"), NULL, brix_stream_var_duration,
      BRIX_SV_DURATION, NGX_STREAM_VAR_NOCACHEABLE, 0 },

    /* Deprecated phase-106 aliases (removal phase-112): same handlers, old
     * spelling, so a phase-106 log_format keeps working. Allowlisted in
     * directive_registry_allowlist.txt. */
    { ngx_string("brix_session_dn"), NULL, brix_stream_var_str,
      BRIX_SV_DN, 0, 0 },
    { ngx_string("brix_session_vo"), NULL, brix_stream_var_str,
      BRIX_SV_VO, 0, 0 },
    { ngx_string("brix_session_user"), NULL, brix_stream_var_str,
      BRIX_SV_SUB, 0, 0 },
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

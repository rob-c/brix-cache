/*
 * cms/server_recv_lifecycle.c — CMS data-server connection teardown + audit.
 *
 * WHAT: Owns the lifecycle side of an accepted CMS data-server connection: the
 * session-end-hint bookkeeping, the registration/auth audit-log helpers, the
 * canonical connection teardown (brix_cms_srv_close), and the shared fatal
 * epilogue (cms_srv_fail_close) every error path funnels through.
 *
 * WHY: Split out of the former monolithic server_recv.c (Phase-79 file-size
 * split).  Grouping "how a connection ends and what we record about it" in one
 * file keeps the parse, dispatch, and event-loop concerns each single-purpose.
 * The functions called from the frame handlers and the read loop are declared
 * in server_recv_internal.h and are therefore non-static here.
 *
 * HOW: brix_cms_srv_close drops timers, releases admission-cap slots, blacklists
 * a departing logged-in node, ends the audit session, and closes the socket;
 * cms_srv_fail_close records an end reason first.  The audit helpers translate
 * connection state into brix_sess_* calls.
 */

#include "server.h"
#include "server_recv_internal.h"
#include "observability/sesslog/sesslog_ngx.h"
#include "core/compat/log_diag.h"

void
cms_srv_set_end_hint(brix_cms_srv_ctx_t *ctx, brix_sess_end_t why)
{
    if (ctx == NULL || ctx->sess_end_hint_set) {
        return;
    }

    ctx->sess_end_hint = why;
    ctx->sess_end_hint_set = 1;
}

static brix_sess_end_t
cms_srv_end_reason(brix_cms_srv_ctx_t *ctx, ngx_connection_t *c)
{
    if (ngx_exiting || ngx_terminate) {
        return BRIX_SESS_END_SHUTDOWN;
    }

    if (ctx != NULL && ctx->sess_end_hint_set) {
        return ctx->sess_end_hint;
    }

    if (c != NULL) {
        if ((c->read != NULL && c->read->timedout)
            || (c->write != NULL && c->write->timedout))
        {
            return BRIX_SESS_END_TIMEOUT;
        }
        if (c->error) {
            return BRIX_SESS_END_ERROR;
        }
    }

    return BRIX_SESS_END_CLIENT;
}

static const char *
cms_srv_target_path(brix_cms_srv_ctx_t *ctx, char *dst, size_t dst_size)
{
    u_char *p;
    u_char *end;

    if (ctx == NULL || dst == NULL || dst_size == 0) {
        return "-";
    }

    end = (u_char *) dst + dst_size;
    p = ngx_snprintf((u_char *) dst, dst_size, "%s:%d",
                     ctx->host, (int) ctx->port);
    if (p < end) {
        *p = '\0';
    } else {
        dst[dst_size - 1] = '\0';
    }

    return dst;
}

void
cms_srv_log_auth_fail(brix_cms_srv_ctx_t *ctx, const char *err)
{
    if (ctx == NULL) {
        return;
    }

    brix_sess_auth(ctx->sess, 0, BRIX_SESS_AM_HOST, "-", "-", err);
}

void
cms_srv_log_registration(brix_cms_srv_ctx_t *ctx)
{
    char        target[BRIX_SESSLOG_PATH_MAX];
    const char *path;

    if (ctx == NULL || ctx->sess_attempt_logged) {
        return;
    }

    path = cms_srv_target_path(ctx, target, sizeof(target));
    brix_sess_auth_once(ctx->sess, BRIX_SESS_AM_HOST, ctx->host, "-");
    brix_sess_attempt(ctx->sess, path, BRIX_SESS_MODE_META);
    ctx->sess_attempt_logged = 1;
    brix_sess_result(ctx->sess, 1, path, BRIX_SESS_MODE_META, NULL);
}

/* brix_cms_srv_close — tear down a CMS data-server connection: drop the ping
 * timer, unregister host/port from the server registry if logged_in (so locate
 * queries stop routing clients to a dead server), NULL ctx->c, and close. */

void
brix_cms_srv_close(brix_cms_srv_ctx_t *ctx)
{
    ngx_connection_t  *c;

    c = ctx->c;
    if (c == NULL) {
        return;
    }

    if (ctx->ping_timer.timer_set) {
        ngx_del_timer(&ctx->ping_timer);
    }

    /* WS3: cancel the login/idle read deadline before tearing the socket down. */
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    /* WS4 + A3: release the admission-cap slots (global + per-IP) exactly once. */
    if (ctx->counted) {
        brix_cms_srv_conn_dec();
        brix_cms_srv_ip_dec(ctx->host);
        ctx->counted = 0;
    }

    if (ctx->logged_in) {
        /* Blacklist for 30 s so in-flight locate responses don't route to a
         * server that just went away.  brix_srv_register() clears the flag
         * the moment the server successfully reconnects and re-heartbeats. */
        brix_srv_blacklist(ctx->host, ctx->port,
                           NGX_BRIX_CMS_SRV_DROP_BLACKLIST_MS);
        BRIX_DIAG(NGX_LOG_NOTICE, c->log, 0,
            "xrootd[cms]: data server %s:%d disconnected (blacklisted 30s)",
            "the data server dropped its CMS connection — it crashed, was "
            "restarted, or lost network to the manager",
            "if it does not re-register within seconds, check that server's "
            "health and connectivity; clients are routed away from it "
            "meanwhile",
            ctx->host, (int) ctx->port);
    }

    brix_sess_end(ctx->sess, cms_srv_end_reason(ctx, c));
    ctx->sess = NULL;

    ctx->c = NULL;
    ngx_close_connection(c);
}

/*
 * cms_srv_fail_close — record why the session ended, then tear it down.
 * Shared epilogue for every fatal per-frame/per-read error so each handler
 * stays single-purpose; after this returns ctx->c is NULL and the caller must
 * not touch the connection again.
 */
void
cms_srv_fail_close(brix_cms_srv_ctx_t *ctx, brix_sess_end_t why)
{
    cms_srv_set_end_hint(ctx, why);
    brix_cms_srv_close(ctx);
}

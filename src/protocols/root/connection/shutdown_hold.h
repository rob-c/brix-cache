#ifndef BRIX_CONNECTION_SHUTDOWN_HOLD_H
#define BRIX_CONNECTION_SHUTDOWN_HOLD_H

/*
 * shutdown_hold.h — keep a retiring worker alive for parked XRootD handles.
 *
 * nginx's graceful worker loop exits once only cancelable timers remain.  An
 * authenticated XRootD keepalive deliberately has no idle read timer, but an
 * open handle must survive a reload so a client can continue using that
 * session on the retiring worker.  The embedded timer is non-cancelable and
 * is re-armed at a long cadence; the normal worker_shutdown_timeout remains
 * the hard upper bound during shutdown.
 */

#include <ngx_event.h>
#include "core/types/context.h"

#define BRIX_SHUTDOWN_HOLD_INTERVAL ((ngx_msec_t) 3600000)

static void
brix_shutdown_hold_timer(ngx_event_t *ev)
{
    brix_ctx_t *ctx = ev->data;

    if (ctx == NULL || ctx->destroyed) {
        return;
    }

    ngx_add_timer(ev, BRIX_SHUTDOWN_HOLD_INTERVAL);
}

static ngx_inline void
brix_shutdown_hold_sync(ngx_connection_t *c, brix_ctx_t *ctx, ngx_flag_t hold)
{
    if (!hold) {
        if (ctx->shutdown_hold_ev.timer_set) {
            ngx_del_timer(&ctx->shutdown_hold_ev);
        }
        return;
    }

    /* The request-boundary housekeeping marks a socket idle before attempting
     * the next header read.  An obligation that starts from that boundary must
     * clear the marker again or ngx_close_idle_connections() will drop it during
     * a reload even though the hold timer is live. */
    c->idle = 0;

    if (ctx->shutdown_hold_ev.timer_set) {
        return;
    }

    ctx->shutdown_hold_ev.handler = brix_shutdown_hold_timer;
    ctx->shutdown_hold_ev.data = ctx;
    ctx->shutdown_hold_ev.log = c->log;
    ctx->shutdown_hold_ev.cancelable = 0;
    ngx_add_timer(&ctx->shutdown_hold_ev, BRIX_SHUTDOWN_HOLD_INTERVAL);
}

#endif /* BRIX_CONNECTION_SHUTDOWN_HOLD_H */

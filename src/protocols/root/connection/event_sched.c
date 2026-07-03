#include "event_sched.h"
#include <ngx_event.h>
#include "core/ngx_brix_module.h"
#include "deadline.h"

ngx_int_t brix_schedule_read_resume(ngx_connection_t *c) {
    ngx_event_t *rev = c->read;
    if (!rev->active && !rev->ready) {
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    if (!rev->posted) {
        ngx_post_event(rev, &ngx_posted_events);
    }
    return NGX_OK;
}

/* Re-arm the connection's write event so a deferred/partial response resumes
 * flushing on the next event-loop iteration. */
ngx_int_t
brix_schedule_write_resume(ngx_connection_t *c)
{
    ngx_event_t          *wev = c->write;
    ngx_stream_session_t *s   = c->data;
    brix_ctx_t         *ctx = ngx_stream_get_module_ctx(s,
                                    ngx_stream_brix_module);

    /*
     * Phase 39: a response was just parked / re-parked for the write event.  This
     * is the single chokepoint for every client write park, so arm/refresh the
     * response-drain deadline here — it resets on each park (one per write-event
     * drain cycle), firing only after brix_send_timeout with no progress (a
     * stuck/half-open consumer).  No-op when the directive is unset.  ctx is the
     * client stream ctx (write resume is never called on a non-client connection).
     */
    if (ctx != NULL) {
        brix_arm_send_deadline(c, ctx);
    }

    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        return NGX_ERROR;
    }
    if (wev->ready && !wev->posted) {
        ngx_post_event(wev, &ngx_posted_events);
    }
    return NGX_OK;
}

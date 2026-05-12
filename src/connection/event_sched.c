#include "event_sched.h"
#include <ngx_event.h>

/*
 * xrootd_schedule_read_resume — re-arm the read event and post it to the
 * nginx event queue so the recv loop runs again without blocking.
 *
 * Called after an upstream response arrives or AIO completes and we need to
 * resume reading the next request from the client.  If the event is already
 * active or already posted, the duplicate post is skipped (ngx_post_event
 * checks the posted flag atomically).
 */
ngx_int_t xrootd_schedule_read_resume(ngx_connection_t *c) {
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

/*
 * xrootd_schedule_write_resume — arm the write event so xrootd_send() will
 * be called when the kernel socket send buffer has space again.
 *
 * If the write event is already "ready" (kernel notified without blocking),
 * we post it immediately rather than waiting for the next epoll cycle.
 */
ngx_int_t xrootd_schedule_write_resume(ngx_connection_t *c) {
    ngx_event_t *wev = c->write;
    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        return NGX_ERROR;
    }
    if (wev->ready && !wev->posted) {
        ngx_post_event(wev, &ngx_posted_events);
    }
    return NGX_OK;
}

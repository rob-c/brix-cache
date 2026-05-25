/* ------------------------------------------------------------------ */
/* Section: Async Event Scheduling                                      */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements helper functions for resuming the async recv/send loop after AIO completion or upstream response arrival. Both helpers
 *      re-arm and post their respective events (read/write) to ngx_posted_events, ensuring the next client request gets processed without waiting for
 *      the next epoll cycle. Guards against duplicate posts via rev->posted/wev->posted checks — nginx prevents double-posting internally but these
 *      helpers provide additional safety before posting.
 * WHY: After AIO completion or upstream response arrival, the async I/O loop must be immediately resumed rather than waiting for nginx's next natural epoll cycle. Without event reposting, latency increases proportional to idle poll timeout, degrading throughput during high-concurrency transfers. The posted-flag guard prevents duplicate scheduling which would cause redundant epoll notifications and unnecessary CPU cycles.
 * HOW: Two-phase re-arm pattern — first ngx_handle_read/write_event() determines if kernel needs notification (active+ready check), then ngx_post_event() pushes to ngx_posted_events queue with atomic posted-flag verification before posting. */

/* ------------------------------------------------------------------ */
/* Section: Read Event Resume                                           */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_schedule_read_resume() resumes the async recv loop by re-arming c->read event (if not active/ready) and posting it to ngx_posted_events.
 *      Guards against duplicate posts via rev->posted check. Called after upstream response arrival or AIO completion when the next client request needs processing.
 *      The posted flag is checked atomically — nginx prevents double-posting internally but this helper provides additional safety before posting.
 * WHY: After each recv cycle completes, the read event must be re-armed and reposted so nginx's epoll machinery immediately detects the next incoming message rather than waiting for idle poll timeout. AIO completion or upstream response arrival is the signal that we've finished processing one request and are ready for the next — this helper ensures zero-latency scheduling instead of proportional-to-poll-interval delay.
 * HOW: Two-phase resume — first ngx_handle_read_event() re-arms if event not active/ready (prevents stale arm state), then ngx_post_event() pushes to ngx_posted_events with atomic rev->posted guard preventing duplicate epoll notifications. Returns NGX_OK on success; NGX_ERROR on re-arm failure. */

/* ---- Function: xrootd_schedule_read_resume() ----
 *
 * WHAT: Resumes the async recv loop by re-arming c->read event (if not active/ready) and posting it to ngx_posted_events — guards against duplicate posts
 *      via rev->posted check. Called after upstream response arrival or AIO completion when the next client request needs processing. The posted flag is checked
 *      atomically — nginx prevents double-posting internally but this helper provides additional safety before posting. Returns NGX_OK on success; NGX_ERROR on
 *      re-arm failure (ngx_handle_read_event). */

/* ---- WHY: Async recv loop requires event re-arming after each response processing cycle — without reposting the read event, the next client request would not be
 *      detected by nginx's epoll machinery until the next natural polling cycle. AIO completion or upstream response arrival signals that we're ready to process
 *      the next incoming message; this helper ensures immediate scheduling rather than waiting for idle poll timeout. ---- */

#include "event_sched.h"
#include <ngx_event.h>

/* ---- xrootd_schedule_read_resume — re-arm and post read event to nginx queue ----
 *
 * WHAT: Resumes the async recv loop by re-arming c->read event (if not active/ready) and posting it to ngx_posted_events. Guards against duplicate posts via rev->posted check. Called after upstream response arrival or AIO completion when the next client request needs processing. The posted flag is checked atomically - nginx prevents double-posting internally.
 *
 * HOW: Two-phase resume — first ngx_handle_read_event() re-arms if event not active/ready (prevents stale arm state), then ngx_post_event() pushes to ngx_posted_events with atomic rev->posted guard preventing duplicate epoll notifications. Returns NGX_OK on success; NGX_ERROR on re-arm failure. */
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

/* ------------------------------------------------------------------ */
/* Section: Write Event Resume                                          */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_schedule_write_resume() resumes async send by re-arming c->write event via ngx_handle_write_event() (returns NGX_ERROR on failure). If the kernel already signaled "ready" (send buffer has space), posts immediately rather than waiting for next epoll cycle. This avoids unnecessary latency when we have data queued and can send right away without blocking.
 * WHY: After each write completion, the write event must be reposted so nginx's epoll machinery immediately detects available send buffer space rather than waiting for idle poll timeout. When kernel already signals "ready" (TCP send buffer has space), immediate posting enables high-throughput continuous transfers with zero-latency between consecutive writes instead of proportional-to-poll-interval delays that degrade throughput during bulk operations.
 * HOW: Two-phase write resume — first ngx_handle_write_event() arms the event and returns NGX_ERROR on failure, then conditional post only if wev->ready AND !wev->posted (prevents duplicate scheduling when kernel hasn't yet signaled space availability). Returns NGX_OK on success; NGX_ERROR on re-arm failure. */

/* ---- Function: xrootd_schedule_write_resume() ----
 *
 * WHAT: Resumes async send by re-arming c->write event via ngx_handle_write_event() (returns NGX_ERROR on failure) — if the kernel already signaled "ready" (send buffer has space),
 *      posts immediately to ngx_posted_events rather than waiting for next epoll cycle. This avoids unnecessary latency when we have data queued and can send right away without blocking.
 *      Only posts if both ready AND not posted to prevent duplicate scheduling. Returns NGX_OK on success; NGX_ERROR on re-arm failure. */

/* ---- WHY: Async send loop requires event posting after each write completion — without reposting the write event, queued data would stall until nginx's next natural polling cycle detects
 *      available send buffer space. When kernel already signals "ready" (we have space in TCP send buffer), immediate posting avoids waiting for idle poll timeout and enables high-throughput
 *      continuous transfers without unnecessary latency between consecutive writes. ---- */

/* ---- xrootd_schedule_write_resume: arm write event and post to queue if ready ----
 *
 * WHAT: Resumes async send by re-arming c->write event via ngx_handle_write_event() (returns NGX_ERROR on failure) - if the kernel already signaled "ready" (send buffer has space), posts immediately to ngx_posted_events rather than waiting for next epoll cycle. Only posts if both ready AND not posted to prevent duplicate scheduling.
 *
 * WHY: After each write completion, the write event must be reposted so nginx's epoll machinery immediately detects available send buffer space rather than waiting for idle poll timeout. When kernel already signals "ready" (TCP send buffer has space), immediate posting enables high-throughput continuous transfers with zero-latency between consecutive writes.
 *
 * HOW: Two-phase write resume — first ngx_handle_write_event() arms the event and returns NGX_ERROR on failure, then conditional post only if wev->ready AND !wev->posted. Returns NGX_OK on success; NGX_ERROR on re-arm failure. */
ngx_int_t
xrootd_schedule_write_resume(ngx_connection_t *c)
{
    ngx_event_t *wev = c->write;
    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        return NGX_ERROR;
    }
    if (wev->ready && !wev->posted) {
        ngx_post_event(wev, &ngx_posted_events);
    }
    return NGX_OK;
}

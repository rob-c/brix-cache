#ifndef BRIX_CONN_EVENT_SCHED_H
#define BRIX_CONN_EVENT_SCHED_H
#include "core/ngx_brix_module.h"

/*
 * brix_schedule_read_resume — ensure the read event is active and posted so
 * the recv loop runs in the next event iteration without blocking on epoll.
 *
 * Safe to call when the event is already active (duplicate posts are guarded
 * by the posted flag).  Returns NGX_OK or NGX_ERROR.
 */
ngx_int_t brix_schedule_read_resume(ngx_connection_t *c);

/*
 * brix_schedule_write_resume — arm the write event so brix_send() fires
 * when the kernel socket send buffer has room.
 *
 * Posts the write event only when it is already ready (wev->ready); otherwise
 * just arms epoll and waits for the writable edge.  Use this ONLY right after a
 * real c->send()/send_chain() returned NGX_AGAIN: there wev->ready is freshly 0
 * and the socket is genuinely full, so posting would busy-loop — we must wait
 * for the kernel's writable notification.  Returns NGX_OK or NGX_ERROR.
 */
ngx_int_t brix_schedule_write_resume(ngx_connection_t *c);

/*
 * brix_ensure_write_event — guarantee the write event WILL run on the next
 * event-loop iteration by posting it unconditionally (guarded only against a
 * double-post).  Use this when PARKING output without having just touched the
 * socket (a pipelined-write ack queued from a completion callback, or a
 * response deferred behind the out_ring): wev->ready may be stale-0 while the
 * socket is actually writable, and under edge-triggered epoll no fresh writable
 * edge arrives for an already-writable socket — so relying on wev->ready (as
 * brix_schedule_write_resume does) strands the parked output and permanently
 * suspends recv (the pipeline-saturation stall at pipeline_depth x chunk).
 * Posting unconditionally cannot busy-loop: brix_send() attempts the real send
 * and, on a genuine NGX_AGAIN, falls through to brix_schedule_write_resume
 * (arm-only) to wait for the writable edge.  Returns NGX_OK or NGX_ERROR.
 */
ngx_int_t brix_ensure_write_event(ngx_connection_t *c);

#endif /* BRIX_CONN_EVENT_SCHED_H */

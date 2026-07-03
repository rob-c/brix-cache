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
 * If the write event is already ready, it is posted immediately to avoid an
 * extra epoll round-trip.  Returns NGX_OK or NGX_ERROR.
 */
ngx_int_t brix_schedule_write_resume(ngx_connection_t *c);

#endif /* BRIX_CONN_EVENT_SCHED_H */

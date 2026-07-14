#ifndef BRIX_HTTP_CACHE_FILL_INTERNAL_H
#define BRIX_HTTP_CACHE_FILL_INTERNAL_H

/*
 * http_cache_fill_internal.h - private glue shared by the three
 * http_cache_fill translation units (split mechanically from a single file
 * for auditability; zero behaviour change):
 *
 *   http_cache_fill.c           public entry + pool resolver (+ !NGX_THREADS stub)
 *   http_cache_fill_registry.c  coalescing waiter registry (attach/detach/hold/abort)
 *   http_cache_fill_worker.c    worker thread + resolve + done finalize
 *
 * It declares the fill ctx / waiter structs, the per-worker in-flight list, and
 * the handful of symbols DEFINED in one unit but REFERENCED from another. All of
 * this machinery is thread-pool-only; the unit bodies stay guarded by NGX_THREADS.
 */

#include "http_cache_fill.h"
#include "observability/sesslog/sesslog_ngx.h"   /* brix_sess_t, brix_sess_xfer_t */

#include <limits.h>                          /* PATH_MAX */
#include <stdatomic.h>

struct brix_http_cache_fill_ctx_s;

/* One request parked on an in-flight fill (event-loop-only). */
typedef struct brix_http_fill_waiter_s {
    ngx_http_request_t                   *r;
    brix_http_cache_reenter_pt          reenter;
    void                                 *reenter_data;
    struct brix_http_fill_waiter_s     *next;
    struct brix_http_cache_fill_ctx_s  *owner;   /* valid while !resolved */
    ngx_event_t                           hold;    /* T20 client-hold timer */
    ngx_msec_t                            parked_ms;  /* attach timestamp   */
    unsigned                              resolved:1;
} brix_http_fill_waiter_t;

/* Per-fill task context — ONE per (inst,key) in flight, shared by every
 * concurrent request for that object. */
typedef struct brix_http_cache_fill_ctx_s {
    brix_sd_instance_t                *inst;
    brix_http_fill_waiter_t           *waiters;
    _Atomic int                          waiters_n;  /* read by the worker */
    struct brix_http_cache_fill_ctx_s *next;       /* in-flight list     */
    ngx_thread_task_t                   *task;       /* the calloc block   */
    time_t                               client_hold; /* T20 deadlines     */
    time_t                               max_life;
    ngx_int_t                            result;    /* NGX_OK/DECLINED/ERROR */
    int                                  err;       /* errno from the fill  */
    ngx_msec_t                           started_ms; /* fill post timestamp */
    unsigned                             attempts;   /* origin attempts run */
    char                                 key[PATH_MAX];
    brix_sess_t                         *sess;
    brix_sess_xfer_t                     sess_xfer;
} brix_http_cache_fill_ctx_t;

/* Per-worker in-flight fills (event-loop-only; a handful at a time). Owned by
 * the registry unit; the worker unit unlinks a completed fill and the entry
 * unit both scans (coalesce) and publishes new fills. */
extern brix_http_cache_fill_ctx_t  *brix_http_fills;

/* Registry unit (http_cache_fill_registry.c). */
const char *brix_http_fill_log_key(const char *key, char *buf, size_t cap);
brix_http_cache_fill_ctx_t *brix_http_fill_find(brix_sd_instance_t *inst,
    const char *key);
void brix_http_fill_detach(brix_http_fill_waiter_t *w);
void brix_http_fill_send_retry_later(ngx_http_request_t *r);
ngx_int_t brix_http_fill_attach(brix_http_cache_fill_ctx_t *t,
    ngx_http_request_t *r, brix_http_cache_reenter_pt reenter,
    void *reenter_data);

/* Worker unit (http_cache_fill_worker.c). */
void brix_http_cache_fill_thread(void *data, ngx_log_t *log);
void brix_http_cache_fill_done(ngx_event_t *ev);

#endif /* BRIX_HTTP_CACHE_FILL_INTERNAL_H */

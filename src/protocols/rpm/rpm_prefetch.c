/*
 * rpm_prefetch.c — warming the two files a dnf client always asks for next
 * (phase-104 D15.10).
 *
 * WHAT: after a fresh repomd.xml has been pulled through this mirror, read
 *       the warm set out of it (primary + filelists) and fill those objects
 *       into the cache store on the thread pool, before any client asks.
 * WHY:  Appendix X finding X-3 measured what a stock EL9 dnf does with a
 *       repository index: it fetches primary AND filelists, unconditionally,
 *       every time its metadata window expires. On a cold mirror those two
 *       fills are the client's entire wait, and they are the one speculation
 *       a repository mirror can make that is never wrong — the index the
 *       mirror is holding names them. The alternative is what every mirror
 *       does today: three serial WAN round trips per client, of which the
 *       last two were knowable the moment the first returned.
 * HOW:  the trigger is narrow on purpose — a REPOMD-class request that was a
 *       FILL, i.e. this worker has just pulled a *new* index. The index is
 *       read from the handle the serve is about to use (a positional pread,
 *       so it disturbs nothing), the hrefs are re-checked by the request
 *       grammar (brix_rpm_classify) exactly as if a client had asked for
 *       them, and only the fills themselves are posted to the thread pool.
 *       Nothing here ever runs an origin fetch on the event loop, nothing
 *       parks the client's request on the speculation, and every failure is
 *       silent to the client by construction: a warm fill that does not
 *       happen is the cache miss the client would have had anyway.
 */

#include "rpm.h"
#include "rpm_repomd.h"

#include "core/aio/aio.h"                    /* brix_task_bind             */
#include "fs/backend/cache/sd_cache.h"
#include "fs/vfs/vfs.h"
#include "observability/metrics/metrics_macros.h"

#if (NGX_THREADS)

/* Warm fills in flight on THIS worker. The set is at most two objects per
 * index, so the cap is about a reload storm (every location re-pulling its
 * index at once), not about steady state. */
#define RPM_PREFETCH_MAX_INFLIGHT  4

static ngx_uint_t  rpm_prefetch_inflight;

typedef struct {
    ngx_pool_t          *pool;
    ngx_log_t           *log;
    brix_sd_instance_t  *inst;
    ngx_uint_t           count;
    ngx_uint_t           warmed;      /* thread out */
    ngx_uint_t           failed;      /* thread out */
    char                 key[BRIX_RPM_REPOMD_WARM_MAX][BRIX_RPM_KEY_MAX];
} rpm_prefetch_job_t;


/* The thread half: the same whole-file fill the miss path runs, one object at
 * a time. `needs_offload` answering 0 means the object is already COMPLETE in
 * the store (nothing to warm) or the source is local (nothing worth warming),
 * so it is the presence check as well as the worth-it check. */
static void
rpm_prefetch_thread(void *data, ngx_log_t *log)
{
    rpm_prefetch_job_t *t = data;
    ngx_uint_t          i;

    (void) log;

    for (i = 0; i < t->count; i++) {
        if (!brix_sd_cache_fill_needs_offload(t->inst, t->key[i])) {
            continue;
        }
        if (brix_sd_cache_fill_key(t->inst, t->key[i], NULL) == NGX_OK) {
            t->warmed++;
            BRIX_RPM_METRIC_INC(prefetch_total);
            continue;
        }
        t->failed++;
        BRIX_RPM_METRIC_INC(prefetch_fail_total);
    }
}


/* The completion half (event loop): drop the in-flight count and say what
 * happened once, at debug level. A warm pass that fetched nothing is the
 * normal case on a mirror whose index did not change, and an operator who
 * wants to know how much it absorbed reads the two counters. */
static void
rpm_prefetch_done(ngx_event_t *ev)
{
    ngx_thread_task_t  *task = ev->data;
    rpm_prefetch_job_t *t = task->ctx;
    ngx_pool_t         *pool = t->pool;

    if (rpm_prefetch_inflight > 0) {
        rpm_prefetch_inflight--;
    }
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, t->log, 0,
                   "rpm: repodata prefetch done: %ui warmed, %ui failed, "
                   "%ui in flight", t->warmed, t->failed,
                   rpm_prefetch_inflight);
    ngx_destroy_pool(pool);
}


/* Post the composed key set. Every failure is a silent return: this is
 * speculation, and a mirror that fails a request because it could not
 * speculate would be worse than one that never speculated. */
static void
rpm_prefetch_post(ngx_http_request_t *r, brix_sd_instance_t *sd,
    char keys[][BRIX_RPM_KEY_MAX], ngx_uint_t count)
{
    static ngx_str_t    pname = ngx_string("default");
    ngx_thread_pool_t  *tp;
    ngx_thread_task_t  *task;
    rpm_prefetch_job_t *t;
    ngx_pool_t         *pool;
    ngx_uint_t          i;

    if (rpm_prefetch_inflight >= RPM_PREFETCH_MAX_INFLIGHT) {
        return;
    }
    tp = (ngx_cycle != NULL)
         ? ngx_thread_pool_get((ngx_cycle_t *) ngx_cycle, &pname) : NULL;
    if (tp == NULL) {
        return;
    }
    /* The job owns a pool of its own: it outlives the request that noticed
     * the new index, and r->pool is gone the moment the response finalizes. */
    pool = ngx_create_pool(8192, ngx_cycle->log);
    if (pool == NULL) {
        return;
    }
    task = ngx_thread_task_alloc(pool, sizeof(rpm_prefetch_job_t));
    if (task == NULL) {
        ngx_destroy_pool(pool);
        return;
    }
    t = task->ctx;
    t->pool  = pool;
    t->log   = ngx_cycle->log;
    t->inst  = sd;
    t->count = count;
    for (i = 0; i < count; i++) {
        ngx_cpystrn((u_char *) t->key[i], (u_char *) keys[i],
                    BRIX_RPM_KEY_MAX);
    }

    brix_task_bind(task, rpm_prefetch_thread, rpm_prefetch_done);
    task->event.log = t->log;
    if (ngx_thread_task_post(tp, task) != NGX_OK) {
        ngx_destroy_pool(pool);
        return;
    }
    rpm_prefetch_inflight++;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "rpm: repodata prefetch posted: %ui object(s) named by "
                   "\"%V\"", count, &r->uri);
}


/* The composed, re-classified key set. An href that does not classify as a
 * digest-named metadata file is dropped rather than fetched: the index is
 * upstream data, and the only paths this mirror fetches unasked are the ones
 * its own request grammar would have accepted from a client. */
static ngx_uint_t
rpm_prefetch_keys(ngx_http_request_t *r, ngx_http_brix_rpm_ctx_t *ctx,
    const char *xml, size_t len, char keys[][BRIX_RPM_KEY_MAX])
{
    brix_rpm_repomd_ref_t  refs[BRIX_RPM_REPOMD_WARM_MAX];
    brix_rpm_req_t         req;
    size_t                 n, i;
    ngx_uint_t             count = 0;

    n = brix_rpm_repomd_warm_set(xml, len, refs, BRIX_RPM_REPOMD_WARM_MAX);

    for (i = 0; i < n; i++) {
        if (brix_rpm_repomd_sibling_key(ctx->key, ctx->key_len, refs[i].href,
                                        refs[i].href_len, keys[count],
                                        BRIX_RPM_KEY_MAX) != 0)
        {
            continue;
        }
        if (brix_rpm_classify(keys[count], ngx_strlen(keys[count]), &req) != 0
            || req.cls != BRIX_RPM_REQ_METADATA)
        {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                "rpm: ignoring repodata location \"%*s\" named by \"%V\" - "
                "not a digest-named metadata file",
                (int) refs[i].href_len, refs[i].href, &r->uri);
            continue;
        }
        count++;
    }
    return count;
}

#endif /* NGX_THREADS */


void
brix_rpm_prefetch_repomd(ngx_http_request_t *r,
    ngx_http_brix_rpm_loc_conf_t *lcf, ngx_http_brix_rpm_ctx_t *ctx,
    brix_vfs_file_t *fh, off_t size, brix_sd_instance_t *sd)
{
#if (NGX_THREADS)
    char        keys[BRIX_RPM_REPOMD_WARM_MAX][BRIX_RPM_KEY_MAX];
    u_char     *buf;
    ssize_t     n;
    ngx_uint_t  count;

    /* Only a FRESHLY PULLED index says anything new: a hit means this worker
     * already fetched whatever the index named, and a request that never
     * reached the origin has no warm set to act on. */
    if (!lcf->prefetch || sd == NULL || ctx->req.cls != BRIX_RPM_REQ_REPOMD
        || ctx->disp != BRIX_RPM_OUT_FILL)
    {
        return;
    }
    if (size <= 0 || size > BRIX_RPM_REPOMD_MAX) {
        return;
    }

    buf = ngx_palloc(r->pool, (size_t) size);
    if (buf == NULL) {
        return;
    }
    n = brix_vfs_file_pread(fh, buf, (size_t) size, 0);
    if (n <= 0) {
        return;
    }

    count = rpm_prefetch_keys(r, ctx, (const char *) buf, (size_t) n, keys);
    if (count == 0) {
        return;
    }
    rpm_prefetch_post(r, sd, keys, count);
#else
    (void) r; (void) lcf; (void) ctx; (void) fh; (void) size; (void) sd;
#endif
}

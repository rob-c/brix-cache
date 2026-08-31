/*
 * backend_async_http.c — http-plane park/resume adapter for the durable async
 * backend-op queue. See backend_async_http.h for the contract.
 */
#include "backend_async_http.h"

#include <string.h>

/* Per-request park record: enough to render the reply once the batch flushes.
 * Lives on r->pool, kept alive by the r->main->count reference. */
typedef struct {
    ngx_http_request_t       *r;
    brix_baq_http_render_pt   render;
    void                     *ctx;
} brix_baq_http_park_t;

/*
 * Queue-level completion (brix_baq_done_pt): trampoline from the queue's opaque
 * client pointer back into the http renderer. Runs on the event loop.
 */
static void
baq_http_wake(void *client, int op_errno)
{
    brix_baq_http_park_t *p = client;

    p->render(p->r, p->ctx, op_errno);
}

ngx_int_t
brix_baq_http_try(ngx_http_request_t *r, ngx_http_brix_shared_conf_t *common,
    const brix_baq_req_t *req, brix_baq_http_render_pt render, void *ctx)
{
    brix_baq_http_park_t *park;
    brix_baq_req_t        q;

    if (common == NULL || req == NULL || !common->backend_async) {
        return NGX_DECLINED;
    }

    park = ngx_pcalloc(r->pool, sizeof(*park));
    if (park == NULL) {
        return NGX_DECLINED;
    }
    park->r      = r;
    park->render = render;
    park->ctx    = ctx;

    q          = *req;
    q.policy   = brix_vfs_policy_from_write_enable(common->allow_write);
    q.batch    = common->backend_async_batch;
    q.wait_ms  = common->backend_async_wait;

    if (brix_baq_enqueue(&q, baq_http_wake, park) != NGX_OK) {
        return NGX_DECLINED;                 /* caller falls back to inline */
    }

    /* Hold the request open until the flush wakes it; the render finalises. */
    r->main->count++;
    return NGX_DONE;
}

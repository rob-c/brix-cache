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
    brix_baq_op_t op, const char *root_canon, const char *src_key,
    const char *dst_key, uint32_t mode, brix_baq_http_render_pt render,
    void *ctx)
{
    brix_baq_http_park_t *park;

    if (common == NULL || !common->backend_async) {
        return NGX_DECLINED;
    }

    park = ngx_pcalloc(r->pool, sizeof(*park));
    if (park == NULL) {
        return NGX_DECLINED;
    }
    park->r      = r;
    park->render = render;
    park->ctx    = ctx;

    if (brix_baq_enqueue(op, root_canon, src_key, dst_key, mode,
                         common->backend_async_batch, common->backend_async_wait,
                         baq_http_wake, park) != NGX_OK)
    {
        return NGX_DECLINED;                 /* caller falls back to inline */
    }

    /* Hold the request open until the flush wakes it; the render finalises. */
    r->main->count++;
    return NGX_DONE;
}

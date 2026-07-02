/* geo.c — uncached origin passthrough (geo API + T12 manifest stopgap).
 *
 * WHAT: forwards a classified request (with query string) to the location's
 *       configured http origin over the shared blocking libcurl transport
 *       and relays status + body. Never cached: the geo answer depends on
 *       the caller, and (until T12) manifests are mutable signed metadata.
 * WHY:  CVMFS clients call the geo API through their site proxy at mount
 *       time to order CVMFS_SERVER_URL; failure is non-fatal for the client
 *       but a correct answer improves Stratum-1 ordering.
 * HOW:  responses are tiny (a comma-separated index list; manifests are a
 *       few hundred bytes), so one bounded in-memory transport request on a
 *       thread-pool task is appropriate — the same aio posting idiom the
 *       tier fills use (xrootd_task_bind, r->main->count++, finalize in the
 *       done handler). The response buffer is pool-allocated BEFORE the
 *       post: the request pool is never touched off the event loop.
 */
#include "cvmfs.h"
#include "core/aio/aio.h"
#include "fs/cache/origin/s3_transport.h"
#include "fs/vfs/vfs_backend_registry.h"

#define CVMFS_PT_RESP_MAX    (64 * 1024)   /* geo lists + manifests are tiny */
#define CVMFS_PT_TIMEOUT_MS  5000

typedef struct {
    ngx_http_request_t *r;
    char                path[2048];      /* origin path incl. query          */
    char                host[256];
    int                 port;
    int                 tls;
    int                 status;          /* HTTP status, or -1 transport fail */
    u_char             *body;            /* pool-allocated on the event loop */
    size_t              body_len;
} cvmfs_pt_task_t;

/* thread-pool side: one blocking GET over the shared transport */
static void
cvmfs_pt_thread(void *data, ngx_log_t *log)
{
    cvmfs_pt_task_t              *t = data;
    const xrootd_s3_transport_t  *tr = &xrootd_s3_origin_curl_transport;
    xrootd_s3_resp_t              resp;
    const void                   *body;
    size_t                        blen = 0;
    char                          errbuf[256];

    (void) log;
    t->status = -1;
    if (tr->request(NULL, t->host, t->port, t->tls, "GET", t->path, NULL,
                    NULL, 0, CVMFS_PT_TIMEOUT_MS, &resp,
                    errbuf, sizeof(errbuf)) != 0)
    {
        return;
    }
    t->status = resp.status;
    body = tr->resp_body(&resp, &blen);
    if (body != NULL && blen > 0 && blen <= CVMFS_PT_RESP_MAX) {
        ngx_memcpy(t->body, body, blen);
        t->body_len = blen;
    }
    tr->resp_free(&resp);
}

/* event-loop side: emit the relayed response */
static void
cvmfs_pt_done(ngx_event_t *ev)
{
    ngx_thread_task_t   *task = ev->data;
    cvmfs_pt_task_t     *t = task->ctx;
    ngx_http_request_t  *r = t->r;
    ngx_connection_t    *c = r->connection;
    ngx_buf_t           *b;
    ngx_chain_t          out;
    ngx_int_t            rc;

    if (t->status < 100) {
        ngx_http_finalize_request(r, NGX_HTTP_BAD_GATEWAY);
        ngx_http_run_posted_requests(c);
        return;
    }

    r->headers_out.status = (ngx_uint_t) t->status;
    r->headers_out.content_length_n = (off_t) t->body_len;
    rc = ngx_http_send_header(r);
    if (rc != NGX_OK || r->header_only || t->body_len == 0) {
        ngx_http_finalize_request(r,
            (rc == NGX_OK) ? ngx_http_send_special(r, NGX_HTTP_LAST) : rc);
        ngx_http_run_posted_requests(c);
        return;
    }

    b = ngx_pcalloc(r->pool, sizeof(*b));
    if (b == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        ngx_http_run_posted_requests(c);
        return;
    }
    b->pos = b->start = t->body;
    b->last = b->end = t->body + t->body_len;
    b->memory = 1;
    b->last_buf = 1;
    out.buf = b;
    out.next = NULL;
    ngx_http_finalize_request(r, ngx_http_output_filter(r, &out));
    ngx_http_run_posted_requests(c);
}

/* Route a classified request to the origin, uncached. Returns NGX_DONE
 * (async completion via cvmfs_pt_done) or an HTTP error status. */
ngx_int_t
xrootd_cvmfs_geo_passthrough(ngx_http_request_t *r,
    ngx_http_xrootd_cvmfs_loc_conf_t *lcf)
{
    ngx_http_xrootd_cvmfs_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_xrootd_cvmfs_module);
    cvmfs_pt_task_t    *t;
    const char         *host, *base, *root;
    int                 port, tls, n;
    ngx_thread_task_t  *task;
    ngx_thread_pool_t  *pool;

    /* proxy mode (T14) resolves against the per-upstream registry root */
    root = (ctx != NULL && ctx->up_root != NULL) ? ctx->up_root
                                                 : lcf->common.root_canon;
    if (xrootd_vfs_backend_http_endpoint(root, &host, &port, &tls, &base)
        != 0)
    {
        /* passthrough requires an http(s) backend */
        return NGX_HTTP_NOT_IMPLEMENTED;
    }

    pool = lcf->common.thread_pool;
    if (pool == NULL) {
        static ngx_str_t  default_name = ngx_string("default");
        ngx_str_t        *pname = lcf->common.thread_pool_name.len > 0
                                  ? &lcf->common.thread_pool_name
                                  : &default_name;

        pool = ngx_thread_pool_get((ngx_cycle_t *) ngx_cycle, pname);
        if (pool != NULL) {
            lcf->common.thread_pool = pool;
        }
    }
    if (pool == NULL) {
        return NGX_HTTP_SERVICE_UNAVAILABLE;   /* no pool: cannot relay */
    }

    task = ngx_thread_task_alloc(r->pool, sizeof(cvmfs_pt_task_t));
    if (task == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    t = task->ctx;
    t->r = r;
    t->port = port;
    t->tls = tls;
    (void) ngx_cpystrn((u_char *) t->host, (u_char *) host, sizeof(t->host));
    t->body = ngx_palloc(r->pool, CVMFS_PT_RESP_MAX);
    if (t->body == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* origin path = <base> + <uri> [+ "?" + args]; reject over-long paths
     * instead of truncating (a truncated geo path returns a wrong answer). */
    if (r->args.len > 0) {
        n = snprintf(t->path, sizeof(t->path), "%s%.*s?%.*s", base,
                     (int) r->uri.len, r->uri.data,
                     (int) r->args.len, r->args.data);
    } else {
        n = snprintf(t->path, sizeof(t->path), "%s%.*s", base,
                     (int) r->uri.len, r->uri.data);
    }
    if (n < 0 || (size_t) n >= sizeof(t->path)) {
        return NGX_HTTP_REQUEST_URI_TOO_LARGE;
    }

    xrootd_task_bind(task, cvmfs_pt_thread, cvmfs_pt_done);
    task->event.log = r->connection->log;

    if (ngx_thread_task_post(pool, task) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    r->main->count++;                 /* request survives until cvmfs_pt_done */
    return NGX_DONE;
}

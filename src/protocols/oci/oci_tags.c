/*
 * oci_tags.c — uncached passthrough of the two LISTING routes: GET
 * /v2/<name>/tags/list (§0.7.1) and GET /v2/<name>/referrers/<digest> (§D15.1).
 *
 * WHAT: forward the listing to the upstream registry, running the D1 token
 *       dance on our own behalf, and relay the answer verbatim.
 * WHY:  a listing is the one shape of registry route whose answer is a
 *       *statement about the upstream right now*, not an object. Caching it
 *       would make `podman search`-style tooling and CI tag-discovery read a
 *       stale world, and the pagination cursor (`?n=&last=`) is the upstream's
 *       own opaque token — a cached page would pair a fresh cursor with a stale
 *       page and silently skip tags. A referrers answer is mutable in exactly
 *       the same way: pushing a signature adds a row to it without changing any
 *       object the mirror holds, so a cached copy would hide the signature the
 *       client came to verify. So these routes are deliberately the one place
 *       the mirror is a proxy rather than a cache.
 * HOW:  the same bounded thread-pool relay the CVMFS geo passthrough uses (one
 *       blocking transport request, pool-allocated response buffer sized before
 *       the post, finalize on the event loop). The 401 retry runs INSIDE the
 *       thread: the fill path gets its retry from the sd_http driver, but this
 *       route never touches the storage driver, so it drives the dance itself.
 *
 * The upstream's own status and body are relayed unchanged — including its
 * error envelope, which is already in the spec's shape and carries detail we
 * would only lose by re-synthesizing it. Only a transport failure (no HTTP
 * answer at all) becomes an envelope of ours.
 */

#include "oci.h"
#include "oci_module_internal.h"

#include "core/aio/aio.h"
#include "core/http/http_headers.h"
#include "core/http/http_file_response.h"   /* brix_http_finalize_memory_body */
#include "fs/cache/origin/s3_transport.h"
#include "observability/metrics/metrics.h"
#include "observability/metrics/metrics_macros.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

/* Registries page tag lists; an unpaginated one for a busy repository is still
 * only tens of KiB. A larger answer is refused rather than truncated — half a
 * JSON array is worse than a 502. */
#define OCI_TAGS_RESP_MAX     (256 * 1024)
#define OCI_TAGS_TIMEOUT_MS   10000

typedef struct {
    ngx_http_request_t   *r;
    brix_oci_upstream_t  *up;
    char                  path[2048];       /* upstream path incl. query    */
    char                  ctype[128];
    char                  filters[64];      /* upstream OCI-Filters-Applied */
    int                   status;           /* HTTP status, or -1 transport */
    u_char               *body;             /* pool-allocated pre-post      */
    size_t                body_len;
} oci_tags_task_t;

/* Is `v` a non-empty comma-separated list of bare tokens? The OCI filter names
 * are ASCII words; anything else — a space, a control byte, a stray colon — is
 * either an upstream that does not speak this header or an attempt to write a
 * second header through it, and both are dropped rather than relayed. */
static int
oci_filters_token_list(const char *v)
{
    size_t  i;

    if (v[0] == '\0' || v[0] == ',') {
        return 0;
    }
    for (i = 0; v[i] != '\0'; i++) {
        if (!isalnum((unsigned char) v[i]) && v[i] != ',' && v[i] != '-'
            && v[i] != '_')
        {
            return 0;
        }
    }
    return 1;
}

/* One request leg. Fills t->status / t->ctype / t->body, and on a 401 copies
 * the challenge into `challenge` so the caller can run the dance. */
static void
oci_tags_leg(oci_tags_task_t *t, const char *hdrs,
    char *challenge, size_t challenge_len)
{
    const brix_s3_transport_t  *tr = &brix_s3_origin_curl_transport;
    brix_s3_resp_t              resp;
    const void                 *body;
    size_t                      blen = 0;
    char                        errbuf[256];

    t->status     = -1;
    t->body_len   = 0;
    t->filters[0] = '\0';
    challenge[0]  = '\0';

    if (tr->request(NULL, t->up->host, t->up->port, t->up->tls, "GET", t->path,
                    hdrs, NULL, 0, OCI_TAGS_TIMEOUT_MS, &resp,
                    errbuf, sizeof(errbuf)) != 0)
    {
        ngx_log_error(NGX_LOG_ERR, t->up->log, 0,
            "oci: tags upstream unreachable host=%s: %s", t->up->host, errbuf);
        return;
    }
    t->status = resp.status;

    if (resp.status == NGX_HTTP_UNAUTHORIZED) {
        (void) tr->resp_header(&resp, "www-authenticate",
                               challenge, challenge_len);
    }
    (void) tr->resp_header(&resp, "content-type", t->ctype, sizeof(t->ctype));

    /* A referrers answer that was filtered MUST say so, or the client cannot
     * tell "no artifacts of that type" from "this registry ignored the
     * filter". The value is relayed, not synthesized — a registry may honour
     * filters we have never heard of — but only after it proves it is a bare
     * token list, because these bytes become a header on our own response. */
    (void) tr->resp_header(&resp, "oci-filters-applied",
                           t->filters, sizeof(t->filters));
    if (!oci_filters_token_list(t->filters)) {
        t->filters[0] = '\0';
    }

    body = tr->resp_body(&resp, &blen);
    if (body != NULL && blen > 0 && blen <= OCI_TAGS_RESP_MAX) {
        ngx_memcpy(t->body, body, blen);
        t->body_len = blen;
    }
    tr->resp_free(&resp);
}

/* thread-pool side: anonymous GET, then one authenticated retry if challenged */
static void
oci_tags_thread(void *data, ngx_log_t *log)
{
    oci_tags_task_t  *t = data;
    char              challenge[1024];
    char              tok[BRIX_OCI_TOKEN_MAX];
    char              hdrs[BRIX_OCI_TOKEN_MAX + 64];

    (void) log;

    oci_tags_leg(t, NULL, challenge, sizeof(challenge));

    if (t->status != NGX_HTTP_UNAUTHORIZED || challenge[0] == '\0') {
        return;
    }
    if (brix_oci_token_get(t->up, t->path, challenge, tok, sizeof(tok)) != 0) {
        return;                            /* relay the upstream's own 401 */
    }
    if (snprintf(hdrs, sizeof(hdrs), "Authorization: Bearer %s\r\n", tok)
        >= (int) sizeof(hdrs))
    {
        return;
    }
    oci_tags_leg(t, hdrs, challenge, sizeof(challenge));
}

/* event-loop side: emit the relayed response */
static void
oci_tags_done(ngx_event_t *ev)
{
    ngx_thread_task_t        *task = ev->data;
    oci_tags_task_t          *t = task->ctx;
    ngx_http_request_t       *r = t->r;
    ngx_connection_t         *c = r->connection;
    ngx_http_brix_oci_ctx_t  *ctx;
    ngx_int_t                 rc;

    ctx = ngx_http_get_module_ctx(r, ngx_http_brix_oci_module);

    if (t->status < 100) {
        if (ctx != NULL) {
            ctx->disp = BRIX_OCI_OUT_ERROR;
        }
        BRIX_OCI_METRIC_INC(upstream_errors_total[BRIX_OCI_UPERR_OTHER]);
        ngx_http_finalize_request(r,
            brix_oci_error(r, NGX_HTTP_BAD_GATEWAY, BRIX_OCI_ERR_UNAVAILABLE,
                           "tag listing upstream unreachable"));
        ngx_http_run_posted_requests(c);
        return;
    }

    if (ctx != NULL) {
        ctx->disp = (t->status < 400) ? BRIX_OCI_OUT_FILL : BRIX_OCI_OUT_ERROR;
    }
    if (t->status >= 400) {
        BRIX_OCI_METRIC_INC(
            upstream_errors_total[brix_oci_uperr_bucket((ngx_uint_t) t->status)]);
    }

    r->headers_out.status = (ngx_uint_t) t->status;
    r->headers_out.content_length_n = (off_t) t->body_len;

    if (t->ctype[0] != '\0') {
        r->headers_out.content_type.len  = ngx_strlen(t->ctype);
        r->headers_out.content_type.data = (u_char *) t->ctype;
        r->headers_out.content_type_len  = r->headers_out.content_type.len;
    }
    if (t->filters[0] != '\0'
        && brix_http_set_header(r, "OCI-Filters-Applied", t->filters, NULL)
           != NGX_OK)
    {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        ngx_http_run_posted_requests(c);
        return;
    }
    if (brix_oci_api_version_header(r) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        ngx_http_run_posted_requests(c);
        return;
    }

    rc = ngx_http_send_header(r);
    if (rc != NGX_OK || r->header_only || t->body_len == 0) {
        ngx_http_finalize_request(r,
            (rc == NGX_OK) ? ngx_http_send_special(r, NGX_HTTP_LAST) : rc);
        ngx_http_run_posted_requests(c);
        return;
    }

    brix_http_finalize_memory_body(r, t->body, t->body_len);
}

/* Build "<base>/v2/[<ns>/]<name>/tags/list[?<args>]". The namespace expansion
 * matches oci_key.c exactly: a tag list that skipped it would answer for a
 * different repository than the manifests served beside it. The query string
 * rides verbatim — `n` and `last` are the upstream's own pagination cursor and
 * rewriting either would corrupt the walk — but control bytes are refused
 * first, because this string becomes a request line on a second connection. */
static ngx_int_t
oci_tags_path(ngx_http_request_t *r, ngx_http_brix_oci_loc_conf_t *lcf,
    const brix_oci_req_t *req, char *out, size_t outsz)
{
    char       terminal[BRIX_OCI_DIGEST_STRLEN + 16];
    ngx_str_t  ns = ngx_null_string;
    size_t     i;
    int        n;

    for (i = 0; i < r->args.len; i++) {
        if (r->args.data[i] < 0x20 || r->args.data[i] == 0x7f) {
            return NGX_HTTP_BAD_REQUEST;
        }
    }

    if (lcf->upstream_ns.len > 0 && req->name_components == 1) {
        ns = lcf->upstream_ns;
    }

    /* The subject digest has classified, so it is lowercase hex of its
     * algorithm's exact width and cannot spell a path component of its own.
     * It is re-emitted from the PARSED value, so the algorithm we forward
     * upstream is the one the grammar accepted, not the one the wire spelled. */
    if (req->cls == BRIX_OCI_REQ_REFERRERS) {
        n = snprintf(terminal, sizeof(terminal), "referrers/%s:%s",
                     brix_oci_alg_name(req->digest.alg), req->digest.hex);
    } else {
        n = snprintf(terminal, sizeof(terminal), "tags/list");
    }
    if (n < 0 || (size_t) n >= sizeof(terminal)) {
        return NGX_HTTP_REQUEST_URI_TOO_LARGE;
    }

    n = snprintf(out, outsz, "%s/v2/%.*s%s%.*s/%s%s%.*s",
                 lcf->up->base_path,
                 (int) ns.len, ns.data, (ns.len > 0) ? "/" : "",
                 (int) req->name_len, req->name, terminal,
                 (r->args.len > 0) ? "?" : "",
                 (int) r->args.len, r->args.data);

    return (n < 0 || (size_t) n >= outsz) ? NGX_HTTP_REQUEST_URI_TOO_LARGE
                                          : NGX_OK;
}

/* The location's thread pool, resolved lazily on first use. Mirrors the CVMFS
 * passthrough: postconfiguration resolves it per server, but a location that
 * inherited its config from a server without an explicit pool name still needs
 * the "default" fallback, and that lookup is only valid post-fork. Exported
 * (internal header): the D16 proof gate posts its mint task to the same pool
 * this listing relay uses — one pool, one back-pressure story. */
ngx_thread_pool_t *
brix_oci_thread_pool(ngx_http_brix_oci_loc_conf_t *lcf)
{
    static ngx_str_t   default_name = ngx_string("default");
    ngx_str_t         *pname;
    ngx_thread_pool_t *pool = lcf->common.thread_pool;

    if (pool != NULL) {
        return pool;
    }
    pname = (lcf->common.thread_pool_name.len > 0)
            ? &lcf->common.thread_pool_name : &default_name;

    pool = ngx_thread_pool_get((ngx_cycle_t *) ngx_cycle, pname);
    if (pool != NULL) {
        lcf->common.thread_pool = pool;
    }
    return pool;
}

ngx_int_t
brix_oci_listing_passthrough(ngx_http_request_t *r,
    ngx_http_brix_oci_loc_conf_t *lcf, ngx_http_brix_oci_ctx_t *ctx)
{
    oci_tags_task_t    *t;
    ngx_thread_task_t  *task;
    ngx_thread_pool_t  *pool;
    ngx_int_t           rc;

    if (lcf->up == NULL) {
        return brix_oci_error(r, NGX_HTTP_NOT_IMPLEMENTED,
                              BRIX_OCI_ERR_UNSUPPORTED,
                              "listing requires brix_oci_mirror");
    }

    brix_oci_up_log_ensure(lcf);

    pool = brix_oci_thread_pool(lcf);
    if (pool == NULL) {
        /* No pool means no blocking relay is possible; failing loudly beats a
         * synchronous curl on the event loop. */
        return brix_oci_error(r, NGX_HTTP_SERVICE_UNAVAILABLE,
                              BRIX_OCI_ERR_UNAVAILABLE,
                              "no thread pool configured for listing");
    }

    task = ngx_thread_task_alloc(r->pool, sizeof(oci_tags_task_t));
    if (task == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    t     = task->ctx;
    t->r  = r;
    t->up = lcf->up;

    rc = oci_tags_path(r, lcf, &ctx->req, t->path, sizeof(t->path));
    if (rc != NGX_OK) {
        return brix_oci_error(r, (ngx_uint_t) rc, BRIX_OCI_ERR_NAME_INVALID,
                              "listing path rejected");
    }

    /* Pool-allocated on the event loop: the request pool is never touched from
     * the worker thread. */
    t->body = ngx_palloc(r->pool, OCI_TAGS_RESP_MAX);
    if (t->body == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    brix_task_bind(task, oci_tags_thread, oci_tags_done);
    task->event.log = r->connection->log;

    if (ngx_thread_task_post(pool, task) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    r->main->count++;                  /* request survives until oci_tags_done */

    return NGX_DONE;
}

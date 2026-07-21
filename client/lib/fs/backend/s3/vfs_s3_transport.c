/* client/lib/vfs_s3_transport.c
 *
 * WHAT: The client-side HTTP transport for the shared S3 driver
 *       (src/fs/backend/sd_s3.c). Implements brix_s3_transport_t over the
 *       client's HTTP/1.1 stack (brix_http_req/_header/_resp_free).
 * WHY:  sd_s3 holds the S3 protocol logic in src/ (shared, ngx-free) but needs
 *       an injected transport — this is the client's. A server consumer would
 *       provide its own (e.g. libcurl) without touching the driver.
 * HOW:  one stateless request op (tctx unused) + thin response accessors that
 *       wrap a heap brix_http_resp behind the transport's opaque handle.
 */
#include "vfs_s3_internal.h"
#include "fs/backend/s3/sd_s3_transport.h"

#include <stdlib.h>

static int
s3t_request(void *tctx, const char *host, int port, int tls,
            const char *method, const char *path_and_query, const char *headers,
            const void *body, size_t body_len, int timeout_ms,
            brix_s3_resp_t *resp, char *errbuf, size_t errcap)
{
    brix_http_resp *r;
    brix_status     st;

    (void) tctx;

    r = calloc(1, sizeof(*r));
    if (r == NULL) {
        if (errbuf != NULL && errcap > 0) {
            snprintf(errbuf, errcap, "s3 transport: out of memory");
        }
        return -1;
    }
    brix_status_clear(&st);
    /* verify=0, ca_dir=NULL — matches the original vfs_s3 request policy. */
    if (brix_http_req(host, port, tls, method, path_and_query, headers,
                      body, body_len, timeout_ms, 0, NULL, r, &st) != 0) {
        if (errbuf != NULL && errcap > 0) {
            snprintf(errbuf, errcap, "%s", st.msg);
        }
        free(r);
        return -1;
    }
    resp->status = r->status;
    resp->opaque = r;
    return 0;
}

static int
s3t_resp_header(const brix_s3_resp_t *resp, const char *name,
                char *out, size_t outcap)
{
    /* brix_http_header: 1 = found, 0 = absent → map to 0 / -1. */
    return brix_http_header((const brix_http_resp *) resp->opaque,
                            name, out, outcap) == 1 ? 0 : -1;
}

/* Raw header block for enumeration (generic x-amz-meta-* listxattr). */
static const char *
s3t_resp_headers_raw(const brix_s3_resp_t *resp)
{
    const brix_http_resp *r = (const brix_http_resp *) resp->opaque;

    return (r != NULL) ? r->headers : NULL;
}

static const void *
s3t_resp_body(const brix_s3_resp_t *resp, size_t *len)
{
    const brix_http_resp *r = (const brix_http_resp *) resp->opaque;
    if (len != NULL) {
        *len = r->body_len;
    }
    return r->body;
}

static void
s3t_resp_free(brix_s3_resp_t *resp)
{
    if (resp->opaque != NULL) {
        brix_http_resp_free((brix_http_resp *) resp->opaque);
        free(resp->opaque);
        resp->opaque = NULL;
    }
}

const brix_s3_transport_t brix_s3_http_transport = {
    .request     = s3t_request,
    .resp_header = s3t_resp_header,
    .resp_headers_raw = s3t_resp_headers_raw,
    .resp_body   = s3t_resp_body,
    .resp_free   = s3t_resp_free,
};

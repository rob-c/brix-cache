/*
 * ssi.c — minimal unary XrdSsi request/response service (§7). See ssi.h.
 *
 * The read/write hooks are clean early-returns keyed on ctx->files[idx].ssi, so
 * the normal file data path is unchanged for every non-SSI handle.
 */

#include "../ngx_xrootd_module.h"   /* master header: ngx + tunables + config + types */
#include "ssi.h"
#include "../connection/fd_table.h"
#include "../response/response.h"
#include "../protocol/opcodes.h"
#include "../protocol/wire_core_requests.h"

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int
xrootd_ssi_match(ngx_stream_xrootd_srv_conf_t *conf, const char *path,
                 const char **service, size_t *service_len)
{
    const char *svc;
    size_t      n;

    if (conf == NULL || !conf->ssi_enable || path == NULL) {
        return 0;
    }
    if (ngx_strncmp(path, XROOTD_SSI_PREFIX, XROOTD_SSI_PREFIX_LEN) != 0) {
        return 0;
    }
    svc = path + XROOTD_SSI_PREFIX_LEN;
    /* service = up to the next '/' or '?' or end; must be non-empty */
    n = 0;
    while (svc[n] != '\0' && svc[n] != '/' && svc[n] != '?') {
        n++;
    }
    if (n == 0 || n >= 64) {
        return 0;
    }
    *service     = svc;
    *service_len = n;
    return 1;
}

ngx_int_t
xrootd_ssi_invoke(const char *service, u_char *req, size_t req_len,
                  u_char **resp, size_t *resp_len)
{
    /* Built-in "echo": the response is the request verbatim. Additional compiled-in
     * services dispatch here by name. */
    if (ngx_strcmp(service, "echo") == 0) {
        *resp     = req;
        *resp_len = req_len;
        return NGX_OK;
    }
    return NGX_ERROR;
}

ngx_int_t
xrootd_ssi_open(xrootd_ctx_t *ctx, ngx_connection_t *c,
                const char *service, size_t service_len)
{
    ngx_connection_t   *conn = c;
    xrootd_ssi_req_t   *rq;
    int                 idx, devnull;
    ServerOpenBody      body;
    size_t              total;
    u_char             *buf;

    /* Reject unknown services up front (echo is the only built-in). */
    {
        char svc[64];
        ngx_memcpy(svc, service, service_len);
        svc[service_len] = '\0';
        if (ngx_strcmp(svc, "echo") != 0) {
            return xrootd_send_error(ctx, c, kXR_NotFound, "unknown SSI service");
        }
    }

    idx = xrootd_alloc_fhandle(ctx);
    if (idx < 0) {
        return xrootd_send_error(ctx, c, kXR_ServerError, "too many open files");
    }

    /* A real (harmless) fd keeps the slot "in use" and makes close()/free work
     * via the normal path; all I/O is intercepted on ctx->files[idx].ssi first. */
    devnull = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (devnull < 0) {
        xrootd_free_fhandle(ctx, idx);
        return xrootd_send_error(ctx, c, kXR_ServerError, "ssi open");
    }

    rq = ngx_pcalloc(conn->pool, sizeof(*rq));
    if (rq == NULL) {
        close(devnull);
        xrootd_free_fhandle(ctx, idx);
        return xrootd_send_error(ctx, c, kXR_NoMemory, "ssi alloc");
    }
    ngx_memcpy(rq->service, service, service_len);
    rq->service[service_len] = '\0';

    ctx->files[idx].fd        = devnull;
    ctx->files[idx].ssi       = rq;
    ctx->files[idx].readable  = 1;
    ctx->files[idx].writable  = 1;
    ctx->files[idx].is_regular = 0;

    /* kXR_ok + ServerOpenBody{fhandle=idx} (no retstat). */
    total = XRD_RESPONSE_HDR_LEN + sizeof(ServerOpenBody);
    buf   = ngx_palloc(conn->pool, total);
    if (buf == NULL) {
        return xrootd_send_error(ctx, c, kXR_NoMemory, "ssi resp");
    }
    xrootd_build_resp_hdr(ctx->cur_streamid, kXR_ok,
                          (uint32_t) sizeof(ServerOpenBody),
                          (ServerResponseHdr *) buf);
    ngx_memzero(&body, sizeof(body));
    body.fhandle[0] = (u_char) idx;
    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, &body, sizeof(body));

    return xrootd_queue_response(ctx, c, buf, total);
}

ngx_int_t
xrootd_ssi_write(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx)
{
    xrootd_ssi_req_t *rq = ctx->files[idx].ssi;
    size_t            n  = ctx->cur_dlen;

    if (rq->dispatched) {
        return xrootd_send_error(ctx, c, kXR_FileLocked,
                                 "SSI request already dispatched");
    }
    if (n > 0) {
        if (rq->req_len + n > XROOTD_SSI_REQ_MAX) {
            return xrootd_send_error(ctx, c, kXR_ArgTooLong,
                                     "SSI request too large");
        }
        if (rq->req == NULL) {
            rq->req = ngx_palloc(c->pool, XROOTD_SSI_REQ_MAX);
            if (rq->req == NULL) {
                return xrootd_send_error(ctx, c, kXR_NoMemory, "ssi req buf");
            }
        }
        if (ctx->payload != NULL) {
            ngx_memcpy(rq->req + rq->req_len, ctx->payload, n);
            rq->req_len += n;
        }
    }
    return xrootd_send_ok(ctx, c, NULL, 0);
}

ngx_int_t
xrootd_ssi_read(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx,
                uint64_t offset, uint32_t rlen)
{
    xrootd_ssi_req_t *rq = ctx->files[idx].ssi;
    size_t            avail, n;

    if (!rq->dispatched) {
        if (xrootd_ssi_invoke(rq->service, rq->req, rq->req_len,
                              &rq->resp, &rq->resp_len) != NGX_OK)
        {
            return xrootd_send_error(ctx, c, kXR_ServerError,
                                     "SSI service failed");
        }
        rq->dispatched = 1;
    }

    if (offset >= rq->resp_len) {
        return xrootd_send_ok(ctx, c, NULL, 0);          /* EOF */
    }
    avail = rq->resp_len - (size_t) offset;
    n     = (rlen < avail) ? rlen : avail;
    return xrootd_send_ok(ctx, c, rq->resp + offset, n);
}

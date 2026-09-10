/* File: launch_dns.c — the kXR_open TPC-destination leg parked on DNS (phase-116)
 *
 * WHAT: When the source host of a native TPC pull has no cached answer, the
 * SSRF gate cannot decide on the event loop without blocking.  This file parks
 * the kXR_open in XRD_ST_AIO on an async brix_dns_resolve() of the source host,
 * applies the loopback/private policy to every answered address, and either
 * refuses ("DNS resolution failed for ..." / "... resolves to a prohibited
 * address") or resumes the prepare pipeline at brix_tpc_prepare_pull_resolved().
 *
 * WHY: I-DNS-1 — no getaddrinfo on the event loop: the previous gate blocked
 * the worker for the resolver's full timeout budget on an unresolvable source.
 * Deferring the verdict to the pull thread instead would let an unresolvable
 * source open its destination successfully and fail only at kXR_sync, changing
 * the wire contract clients and tests pin (the open itself reports the DNS
 * failure).
 *
 * HOW: A self-owned wait (ngx_calloc) holds the request, a copy of the parsed
 * tpc.* params and destination path, and the streamid.  A c->pool cleanup
 * cancels the request if the client goes away first; the completion disarms
 * that cleanup, restores the request context (brix_aio_restore_request — 0
 * means the ctx is gone), answers, and re-arms the loop with brix_aio_resume().
 * An inline completion (the resolver answered from its own cache) is detected
 * through the `parked` flag and finished on the starter's stack without ever
 * entering XRD_ST_AIO.  The request logs to the cycle log: c->log lives in the
 * pool the cleanup guards, and a thread completion must never read it late.
 * */

#include "tpc_internal.h"
#include "core/aio/aio.h"
#include "core/compat/net_target.h"
#include "net/dns/dns.h"

#include <stdio.h>
#include <string.h>

typedef struct {
    brix_ctx_t                  *ctx;
    ngx_connection_t            *c;
    ngx_stream_brix_srv_conf_t  *conf;
    ngx_pool_cleanup_t          *cln;        /* c->pool: cancels a parked wait */
    brix_dns_req_t               dns;
    brix_tpc_params_t            tpc;
    char                         dst_path[PATH_MAX];
    u_char                       streamid[2];
    uint16_t                     options;
    uint16_t                     mode_bits;
    unsigned                     parked:1;   /* ctx->state is XRD_ST_AIO */
    unsigned                     done:1;     /* the handler ran inline */
} tpc_dns_wait_t;


/* c->pool cleanup: the client went away while the open was parked. */
static void
tpc_dns_wait_sever(void *data)
{
    tpc_dns_wait_t  *w = data;

    brix_dns_resolve_cancel(&w->dns);
    ngx_free(w);
}


/* 0 = every answered address passes the source policy; -1 = refuse (err). */
static int
tpc_dns_wait_verdict(const tpc_dns_wait_t *w, char *err, size_t errsz)
{
    brix_net_target_policy_t  policy;

    if (w->dns.rc != NGX_OK || w->dns.naddrs == 0) {
        (void) snprintf(err, errsz, "DNS resolution failed for %s: %s",
                        w->tpc.src_host,
                        w->dns.error ? w->dns.error : "no usable address");
        return -1;
    }

    ngx_memzero(&policy, sizeof(policy));
    policy.allow_local   = w->conf->common.tpc_allow_local;
    policy.allow_private = w->conf->common.tpc_allow_private;
    policy.dns           = w->conf->common.dns.policy;

    return brix_net_target_check_addrs(w->dns.addrs, w->dns.naddrs, &policy,
                                       w->tpc.src_host, err, errsz) == NGX_OK
           ? 0 : -1;
}


/* Answer the open from the verdict; frees w.  TPC_ANSWERED or NGX_ERROR. */
static ngx_int_t
tpc_dns_wait_answer(tpc_dns_wait_t *w)
{
    char       err[512];
    ngx_int_t  rc;

    if (tpc_dns_wait_verdict(w, err, sizeof(err)) != 0) {
        rc = brix_tpc_refuse(w->ctx, w->c, w->dst_path, kXR_NotAuthorized,
                             err);
    } else {
        rc = brix_tpc_prepare_pull_resolved(w->ctx, w->c, w->conf, &w->tpc,
                                            w->dst_path, w->options,
                                            w->mode_bits);
        rc = (rc == NGX_OK) ? TPC_ANSWERED : NGX_ERROR;
    }
    ngx_free(w);
    return rc;
}


static void
tpc_dns_wait_handler(brix_dns_req_t *req)
{
    tpc_dns_wait_t    *w = req->data;
    ngx_connection_t  *c = w->c;

    if (!w->parked) {
        w->done = 1;                      /* inline: the starter answers */
        return;
    }

    w->cln->handler = NULL;               /* the pool no longer owns the wait */
    if (!brix_aio_restore_request(w->ctx, w->streamid)) {
        ngx_free(w);                      /* client gone: nobody to answer */
        return;
    }
    (void) tpc_dns_wait_answer(w);
    brix_aio_resume(c);
}


ngx_int_t
brix_tpc_prepare_park_dns(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const brix_tpc_params_t *tpc,
    const char *dst_path, uint16_t options, uint16_t mode_bits)
{
    tpc_dns_wait_t  *w;

    w = ngx_calloc(sizeof(tpc_dns_wait_t), c->log);
    if (w == NULL) {
        return brix_tpc_refuse(ctx, c, dst_path, kXR_ServerError,
                               "TPC source lookup: out of memory");
    }
    w->cln = ngx_pool_cleanup_add(c->pool, 0);
    if (w->cln == NULL) {
        ngx_free(w);
        return brix_tpc_refuse(ctx, c, dst_path, kXR_ServerError,
                               "TPC source lookup: out of memory");
    }
    w->cln->handler = tpc_dns_wait_sever;
    w->cln->data = w;

    w->ctx = ctx;
    w->c = c;
    w->conf = conf;
    w->tpc = *tpc;
    ngx_cpystrn((u_char *) w->dst_path, (u_char *) dst_path,
                sizeof(w->dst_path));
    w->streamid[0] = ctx->recv.cur_streamid[0];
    w->streamid[1] = ctx->recv.cur_streamid[1];
    w->options = options;
    w->mode_bits = mode_bits;

    w->dns.name.data = (u_char *) w->tpc.src_host;
    w->dns.name.len = ngx_strlen(w->tpc.src_host);
    w->dns.port = tpc->src_port ? tpc->src_port : 1094;
    w->dns.af = BRIX_AF_AUTO;
    w->dns.socktype = SOCK_STREAM;
    w->dns.policy = conf->common.dns.policy;
    w->dns.log = ngx_cycle->log;
    w->dns.handler = tpc_dns_wait_handler;
    w->dns.data = w;

    if (brix_dns_resolve(&w->dns) != NGX_OK) {
        w->cln->handler = NULL;
        ngx_free(w);
        return brix_tpc_refuse(ctx, c, dst_path, kXR_ServerError,
                               "TPC source lookup could not be started");
    }

    if (w->done) {
        /* answered inline: finish on this stack, never XRD_ST_AIO */
        w->cln->handler = NULL;
        return tpc_dns_wait_answer(w);
    }

    w->parked = 1;
    ctx->state = XRD_ST_AIO;
    return TPC_ANSWERED;
}

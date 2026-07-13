#include "proxy_internal.h"
#include "protocols/root/session/registry.h"

/*
 * WHAT: File handle translation helpers for transparent proxy forwarding.
 *       Translates client-side file handles to upstream-side handles for
 *       opcodes that carry one or more fhandle fields (single-fh opcodes,
 *       readv/writev segments, and nested kXR_ckpXeq embedded requests).
 *
 * WHY:  The proxy maintains a per-connection handle map (local → upstream)
 *       because client and upstream use independent fh numbering spaces.
 *       Each forwarded request must rewrite every fhandle from the client's
 *       namespace to the upstream's namespace so the backend can locate the
 *       file using its own handle. Bound-secondary connections also trigger
 *       lazy-open on first read when the upstream handle is still free.
 *
 * HOW:  brix_proxy_fh_translate_single() handles opcodes with a single fhandle
 *       at body[0] (read/write/close/sync) plus nested kXR_ckpXeq frames that
 *       embed a sub-request header (and, if that sub-request is writev, every
 *       segment descriptor fhandle). brix_proxy_fh_translate_vector() iterates
 *       readv/writev descriptor arrays, translating the fhandle at offset 0 in
 *       each 16-byte entry. Both return NGX_OK, NGX_ABORT (request rejected via
 *       proxy_reject_request — req freed, kXR_error queued) or NGX_ERROR, and may
 *       transfer req ownership to brix_proxy_lazy_open for bound-secondary
 *       deferred open (NGX_DONE).
 */

/*
 * WHAT: Check if a bound-secondary read needs lazy-open and initiate it if so.
 *       Returns NGX_DONE if lazy-open was initiated (req ownership transferred),
 *       NGX_DECLINED if no lazy-open needed (caller should proceed), or NGX_ERROR.
 *
 * WHY:  Bound-secondary connections defer opening files until first read, so we
 *       must check if the handle is still free and trigger lazy-open before
 *       proceeding with the request.
 *
 * HOW:  Check if this is a bound read on an unopened handle. If so, transfer
 *       req to lazy_open and return NGX_DONE. Otherwise return NGX_DECLINED.
 */
static ngx_int_t
check_bound_secondary_lazy_open(brix_proxy_ctx_t *proxy,
                                 brix_ctx_t       *ctx,
                                 ngx_connection_t *c,
                                 u_char           *req,
                                 size_t            total,
                                 uint16_t          reqid,
                                 int               local_fh)
{
    if (!ctx->is_bound) {
        return NGX_DECLINED;
    }
    if (reqid != kXR_read && reqid != kXR_pgread) {
        return NGX_DECLINED;
    }
    if (local_fh < 0 || local_fh >= BRIX_MAX_FILES) {
        return NGX_DECLINED;
    }
    if (proxy->fh_map[local_fh].upstream_fh != BRIX_PROXY_FH_FREE) {
        return NGX_DECLINED;
    }

    /* req ownership transfers to brix_proxy_lazy_open */
    ngx_int_t rc = brix_proxy_lazy_open(proxy, ctx, c, local_fh, req, total);
    return (rc == NGX_OK) ? NGX_DONE : rc; /* NGX_DONE signals early exit */
}

/*
 * WHAT: Translate fhandles in a nested kXR_ckpXeq writev descriptor array.
 *       Returns NGX_OK, or NGX_ABORT/NGX_ERROR (request rejected, req freed).
 *
 * WHY:  kXR_ckpXeq can embed a writev sub-request whose write_list descriptors
 *       each contain a fhandle that must be translated to the upstream namespace.
 *
 * HOW:  Parse sub_dlen from the sub-request header, iterate descriptors at 16-byte
 *       intervals, translate fhandle at offset 0 in each entry.
 */
static ngx_int_t
translate_ckpxeq_writev_fhandles(brix_proxy_ctx_t *proxy,
                                  brix_ctx_t       *ctx,
                                  ngx_connection_t *c,
                                  u_char           *req,
                                  u_char           *sub,
                                  size_t            body_len)
{
    uint32_t sub_dlen = ((uint32_t) sub[20] << 24)
                      | ((uint32_t) sub[21] << 16)
                      | ((uint32_t) sub[22] << 8)
                      |  (uint32_t) sub[23];
    size_t   pos      = 24;
    size_t   desc_end = 24 + (size_t) sub_dlen;

    if (desc_end > body_len) {
        desc_end = body_len;   /* defensive clamp */
    }
    while (pos + 16 <= desc_end) {
        if (proxy_translate_fh(proxy, sub + pos, 0) != 0) {
            return proxy_reject_request(ctx, c, req, kXR_InvalidRequest,
                                        "proxy: invalid fhandle in writev");
        }
        pos += 16;
    }
    return NGX_OK;
}

/*
 * WHAT: Translate fhandles in a kXR_ckpXeq embedded sub-request. Returns NGX_OK,
 *       or NGX_ABORT/NGX_ERROR (request rejected, req freed).
 *
 * WHY:  kXR_ckpXeq frames carry an embedded sub-request header (and trailing body).
 *       The sub-request's fhandle must be translated, and if it's a writev, every
 *       descriptor fhandle must also be translated.
 *
 * HOW:  Translate the sub-request fhandle at sub[4]. If sub_reqid is writev, call
 *       the writev descriptor translator.
 */
static ngx_int_t
translate_ckpxeq_sub_request(brix_proxy_ctx_t *proxy,
                              brix_ctx_t       *ctx,
                              ngx_connection_t *c,
                              u_char           *req,
                              size_t            body_len)
{
    u_char   *sub       = req + XRD_REQUEST_HDR_LEN;
    uint16_t  sub_reqid = (uint16_t) ((sub[2] << 8) | sub[3]);

    if (proxy_translate_fh(proxy, sub + 4, 0) != 0) {
        return proxy_reject_request(ctx, c, req, kXR_InvalidRequest,
                                    "proxy: invalid file handle");
    }

    if (sub_reqid == kXR_writev) {
        return translate_ckpxeq_writev_fhandles(proxy, ctx, c, req, sub, body_len);
    }

    return NGX_OK;
}

/*
 * WHAT: Translate file handle for opcodes with a single fhandle at body[0],
 *       plus kXR_chkpoint kXR_ckpXeq nested requests. Returns NGX_OK, NGX_DONE
 *       (lazy-open), NGX_ABORT (rejected, req freed) or NGX_ERROR.
 *       May transfer req ownership to brix_proxy_lazy_open for bound-secondary.
 *
 * WHY:  read/pgread/write/pgwrite/close/sync/chkpoint all carry fhandle[0] at
 *       offset 4 in the 24-byte request header. kXR_ckpXeq embeds a full sub-request
 *       whose fhandle must also be translated, and if that sub-request is writev,
 *       every write_list descriptor fhandle needs translation too.
 *
 * HOW:  Extract local_fh from req[4]. For bound-secondary reads, check if upstream_fh
 *       is still free; if so, transfer req to lazy_open and return NGX_DONE (caller
 *       exits immediately). Otherwise translate body[0]. For kXR_ckpXeq, delegate to
 *       the nested sub-request translator.
 */
ngx_int_t
brix_proxy_fh_translate_single(brix_proxy_ctx_t *proxy,
                                brix_ctx_t       *ctx,
                                ngx_connection_t *c,
                                u_char           *req,
                                size_t            total,
                                uint16_t          reqid,
                                size_t            body_len)
{
    int local_fh = (int)(unsigned char) req[4];

    /* Bound secondary: lazy-open the file on first read for this handle */
    ngx_int_t rc = check_bound_secondary_lazy_open(proxy, ctx, c, req, total,
                                                    reqid, local_fh);
    if (rc == NGX_DONE || rc == NGX_ERROR) {
        return rc; /* lazy-open initiated or error */
    }

    if (proxy_translate_fh(proxy, req + 4, 0) != 0) {
        return proxy_reject_request(ctx, c, req, kXR_InvalidRequest,
                                    "proxy: invalid file handle");
    }

    /* kXR_ckpXeq: translate embedded sub-request */
    if (reqid == kXR_chkpoint && req[19] == kXR_ckpXeq && body_len >= 24) {
        rc = translate_ckpxeq_sub_request(proxy, ctx, c, req, body_len);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    proxy->fwd_local_fh = local_fh;
    return NGX_OK;
}

/*
 * WHAT: Collect unique unopened file handles from a readv descriptor array.
 *       Returns the count of unique pending handles found (writes to pending[] array).
 *
 * WHY:  Bound-secondary readv may reference multiple unopened handles in a single
 *       request (xrdcp parallel streams). We must identify all of them and open
 *       them sequentially before dispatching the request.
 *
 * HOW:  Iterate the descriptor array, extract fh from each entry. If the handle
 *       is in range, unopened (upstream_fh == FREE), and not yet seen, add it
 *       to pending[] and mark seen[].
 */
static int
collect_unopened_readv_handles(brix_proxy_ctx_t *proxy,
                                u_char           *payload,
                                uint32_t          cur_dlen,
                                int               pending[BRIX_MAX_FILES])
{
    int   n_pending = 0;
    int   seen[BRIX_MAX_FILES];
    int   i;
    size_t pos;

    for (i = 0; i < BRIX_MAX_FILES; i++) { seen[i] = 0; }

    pos = 0;
    while (pos + 16 <= cur_dlen) {
        int fh = (int)(unsigned char) payload[pos];
        if (fh >= 0 && fh < BRIX_MAX_FILES
            && proxy->fh_map[fh].upstream_fh == BRIX_PROXY_FH_FREE
            && !seen[fh])
        {
            seen[fh] = 1;
            pending[n_pending++] = fh;
        }
        pos += 16;
    }

    return n_pending;
}

/*
 * WHAT: Initiate lazy-open queue for bound-secondary readv with multiple unopened handles.
 *       Returns NGX_DONE if lazy-open was queued (req ownership transferred) or NGX_DECLINED
 *       if no unopened handles were found.
 *
 * WHY:  When a bound-secondary readv references multiple unopened handles, we must open
 *       them all sequentially before dispatching. The first is opened immediately; the
 *       rest are queued in lazy_open_pending_fhs.
 *
 * HOW:  Collect unopened handles. If any found, store the tail (handles 1..n-1) in the
 *       pending queue, transfer req to lazy_open for the first handle, return NGX_DONE.
 */
static ngx_int_t
initiate_readv_lazy_open_queue(brix_proxy_ctx_t *proxy,
                                brix_ctx_t       *ctx,
                                ngx_connection_t *c,
                                u_char           *req,
                                size_t            total,
                                u_char           *payload,
                                uint32_t          cur_dlen)
{
    int pending[BRIX_MAX_FILES];
    int n_pending = collect_unopened_readv_handles(proxy, payload, cur_dlen, pending);

    if (n_pending == 0) {
        return NGX_DECLINED;
    }

    /* Store the queue; lazy_open will consume entries one by one */
    int first_fh = pending[0];
    for (int i = 1; i < n_pending; i++) {
        proxy->lazy_open_pending_fhs[i - 1] = pending[i];
    }
    proxy->lazy_open_pending_count = n_pending - 1;

    ngx_int_t rc = brix_proxy_lazy_open(proxy, ctx, c, first_fh, req, total);
    return (rc == NGX_OK) ? NGX_DONE : rc; /* NGX_DONE signals early exit */
}

/*
 * WHAT: Translate file handles in readv or writev descriptor arrays. Returns NGX_OK,
 *       NGX_DONE (lazy-open), NGX_ABORT (rejected, req freed) or NGX_ERROR.
 *       For bound-secondary readv, may queue multiple lazy-opens and transfer req to the first.
 *
 * WHY:  readv and writev carry an array of 16-byte descriptors, each with fhandle[4] + rlen/wlen[4]
 *       + offset[8]. Every fhandle must be translated to the upstream namespace. Bound-secondary
 *       connections may reference several unopened handles in a single readv (xrdcp parallel streams);
 *       we collect all unique unresolved handles and open them sequentially before dispatching.
 *
 * HOW:  For bound-secondary readv, delegate to the lazy-open queue initiator. If it returns NGX_DONE,
 *       return immediately (req ownership transferred). Otherwise iterate the descriptor array
 *       translating fhandle at offset 0 in each entry.
 */
ngx_int_t
brix_proxy_fh_translate_vector(brix_proxy_ctx_t *proxy,
                                brix_ctx_t       *ctx,
                                ngx_connection_t *c,
                                u_char           *req,
                                size_t            total,
                                uint16_t          reqid,
                                uint32_t          cur_dlen)
{
    u_char *payload = req + XRD_REQUEST_HDR_LEN;

    if (reqid == kXR_readv && ctx->is_bound && cur_dlen >= 4) {
        ngx_int_t rc = initiate_readv_lazy_open_queue(proxy, ctx, c, req, total,
                                                       payload, cur_dlen);
        if (rc == NGX_DONE || rc == NGX_ERROR) {
            return rc; /* lazy-open queue initiated or error */
        }
    }

    /* Translate all fhandles in the descriptor array */
    size_t pos = 0;
    while (pos + 16 <= cur_dlen) {
        if (proxy_translate_fh(proxy, payload + pos, 0) != 0) {
            return proxy_reject_request(ctx, c, req, kXR_InvalidRequest,
                                        reqid == kXR_readv
                                        ? "proxy: invalid fhandle in readv"
                                        : "proxy: invalid fhandle in writev");
        }
        pos += 16;
    }

    proxy->fwd_local_fh = -1;
    return NGX_OK;
}

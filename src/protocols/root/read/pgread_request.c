/*
 * pgread_request.c — the request-side half of kXR_pgread: decode + early
 * checks (brix_pgread_parse_validate), worst-case scratch sizing, and the
 * warm page-cache inline path (brix_pgread_try_warm).  Split out of
 * pgread.c along the decode/produce seam when the §1.1 offload work pushed
 * that file over the 600-line cap (coding-standards §1); pgread.c keeps the
 * producers (AIO post, offload, sync fallback) and response framing.
 */

#include "read.h"
#include "read_internal.h"
#include "pgread_internal.h"

#include "core/ngx_brix_module.h"
#include "fs/backend/sd.h"   /* phase-55: route preadv through the SD seam */
#include "fs/vfs/vfs_io_core.h"  /* brix_vfs_effective_obj — POSIX-wrap or driver obj */
#include "protocols/root/session/registry.h" /* §1.2 pathid validation (bound-path bitmap) */

/*
 * brix_pgread_parse_validate - decode the request and run all early checks.
 *
 * WHAT: Unpacks the kXR_pgread request into `run`, validates the handle,
 *       rejects negative offset/length, answers a zero-length read with an
 *       empty kXR_status frame, caps rlen, and resolves the fd.  Returns 1 to
 *       continue; 0 when the request was fully handled (*rc holds the
 *       handler's return value — error sent, empty response queued, or
 *       NGX_ERROR).
 *
 * WHY: All reject/short-circuit paths in one early-return helper keeps the
 *      handler a flat orchestrator (coding-standards §8).
 *
 * HOW: Mirrors brix_validate_read_handle's continue-flag + *rc convention
 *      so the caller propagates the exact wire response codes unchanged.
 */
ngx_int_t
brix_pgread_parse_validate(brix_ctx_t *ctx, ngx_connection_t *c,
    brix_pgread_run_t *run, ngx_int_t *rc)
{
    xrdw_pgread_req_t             req;
    ServerStatusResponse_pgRead  *hdr_buf;

    xrdw_pgread_req_unpack(((ClientRequestHdr *) ctx->recv.hdr_buf)->body, &req);
    run->idx = (int) (unsigned char) req.fhandle[0];
    run->offset = req.offset;
    run->rlen = (size_t) (uint32_t) req.rlen;

    /* §1.2 optional request args ride the payload: pathid at byte 0 when
     * dlen >= 1, reqflags at byte 1 when dlen >= 2 (extra bytes tolerated) —
     * stock 5.6.9 parses exactly this shape at any dlen, verified live. A
     * nonzero pathid must name one of THIS session's live kXR_bind paths;
     * stock refuses anything else with kXR_ArgInvalid "invalid path ID".
     * kXR_pgRetry (and unknown flag bits) change nothing server-side: the
     * pages are re-read and re-checksummed fresh, which is stock behavior.
     * The response itself still travels the control stream — response
     * offloading over the bound path is the audit's §1.1 gap, all opcodes
     * alike. */
    if (ctx->recv.cur_dlen >= 1 && ctx->recv.payload != NULL) {
        run->pathid   = (unsigned) ((u_char *) ctx->recv.payload)[0];
        run->reqflags = (ctx->recv.cur_dlen >= 2)
                        ? (unsigned) ((u_char *) ctx->recv.payload)[1] : 0;
        if (run->pathid != 0
            && !brix_session_pathid_bound(ctx->is_bound ? ctx->bound_sessid
                                                          : ctx->login.sessid,
                                            run->pathid))
        {
            BRIX_OP_ERR(ctx, BRIX_OP_PGREAD);
            *rc = brix_send_error(ctx, c, kXR_ArgInvalid,
                                    "invalid path ID");
            return 0;
        }
    }

    if (!brix_validate_read_handle(ctx, c, run->idx, "PGREAD",
                                     BRIX_OP_PGREAD, rc)) {
        return 0;
    }

    if (run->offset < 0) {
        BRIX_OP_ERR(ctx, BRIX_OP_PGREAD);
        *rc = brix_send_error(ctx, c, kXR_IOError,
                                "negative read offset");
        return 0;
    }

    /* The wire rlen is a signed 32-bit field; a negative request length is
     * invalid.  Read unsigned it would turn -1 into ~4 GiB (then capped),
     * silently succeeding where the reference rejects with kXR_ArgInvalid. */
    if (req.rlen < 0) {
        BRIX_OP_ERR(ctx, BRIX_OP_PGREAD);
        *rc = brix_send_error(ctx, c, kXR_ArgInvalid,
                                "negative read length");
        return 0;
    }

    if (run->rlen == 0) {
        hdr_buf = ngx_palloc(c->pool, sizeof(*hdr_buf));
        if (hdr_buf == NULL) {
            *rc = NGX_ERROR;
            return 0;
        }
        brix_build_pgread_status(ctx, run->offset, 0, hdr_buf);
        BRIX_OP_OK(ctx, BRIX_OP_PGREAD);
        *rc = brix_queue_response(ctx, c, (u_char *) hdr_buf,
                                    sizeof(*hdr_buf));
        return 0;
    }

    if (run->rlen > BRIX_READ_REQUEST_MAX) {
        run->rlen = BRIX_READ_REQUEST_MAX;
    }

    run->fd = ctx->files[run->idx].fd;
    return 1;
}

/*
 * brix_pgread_scratch_size - worst-case gapped wire-buffer size.
 *
 * WHAT: The byte count the interleaved [CRC32c(4)][data] wire output can
 *       reach for this request — data bytes plus one 4-byte CRC per page
 *       (data is read straight into the gaps; no separate flat copy region).
 *
 * WHY: The buffer-size math is pure and self-contained; isolating it keeps
 *      the page-count subtlety (alignment split) documented in one place.
 *
 * HOW: File-offset alignment can split an otherwise single-page read across
 *      two pages (short first fragment + remainder), so the page count is
 *      derived from the in-page offset, not just rlen — otherwise the
 *      scratch/out region would be one CRC short.
 */
size_t
brix_pgread_scratch_size(const brix_pgread_run_t *run)
{
    size_t  n_pages_max;

    n_pages_max = ((size_t) (run->offset & (kXR_pgPageSZ - 1)) + run->rlen
                   + kXR_pgPageSZ - 1) / kXR_pgPageSZ;
    if (n_pages_max == 0) {
        n_pages_max = 1;
    }
    return run->rlen + n_pages_max * BRIX_PG_CKSZ;
}

/*
 * brix_pgread_try_warm - inline warm-cache fast path.
 *
 * WHAT: Attempts the whole read + in-place CRC on the event loop via
 *       preadv2(RWF_NOWAIT).  On a full hit fills run->{out_buf, out_size,
 *       flat_buf}, charges the backend byte metric, and returns 1; on any
 *       miss returns 0 with the run output untouched.
 *
 * WHY: When the whole range is already page-cache resident, reading + CRCing
 *      inline skips the thread-pool handoff entirely — the handoff latency,
 *      not the copy, is the single-stream (n=1) cost. A miss (not resident /
 *      EOF / error) falls through to the blocking offload, which re-reads the
 *      full range. Only attempted with a pool configured (else the blocking
 *      path runs inline anyway) and for a regular file (RWF_NOWAIT is
 *      meaningful against the page cache). Mirrors the kXR_read Phase-32 probe.
 *
 * HOW: Delegates to brix_pgread_read_encode_inplace with nowait=1 against
 *      the handle's effective storage object; a hit means errno stayed 0 and
 *      every requested byte was delivered.
 */
ngx_flag_t
brix_pgread_try_warm(brix_ctx_t *ctx, ngx_stream_brix_srv_conf_t *rconf,
    brix_pgread_run_t *run)
{
    brix_pgread_io_t warm_io = { .nowait = 1, .nread = 0, .io_errno = 0 };
    size_t          warm_osz;
    brix_sd_obj_t warm_scratch;
    brix_sd_obj_t *warm_obj;

    if (rconf->common.thread_pool == NULL
        || !ctx->files[run->idx].is_regular)
    {
        return 0;
    }

    warm_obj = brix_vfs_effective_obj(&ctx->files[run->idx].sd_obj, run->fd,
                                        &warm_scratch);

    /* The RWF_NOWAIT probe needs the driver's native preadv2; drivers without
     * one (remote/object backends) have no page cache to probe — treat as a
     * miss so the read offloads to the blocking path. */
    if (warm_obj->driver->preadv2 == NULL) {
        return 0;
    }

    warm_osz = brix_pgread_read_encode_inplace(warm_obj, (off_t) run->offset,
                                                 run->rlen, run->scratch,
                                                 &warm_io);
    if (warm_io.io_errno != 0 || warm_io.nread != (ssize_t) run->rlen) {
        return 0;
    }

    run->out_size = warm_osz;
    run->flat_buf = run->scratch;
    run->out_buf  = run->scratch;      /* rlen already == bytes encoded */

    /* The warm fast path bypasses brix_vfs_io_execute (where the
     * cold pgread paths attribute), so charge the per-backend read
     * total here for the file bytes just read. */
    brix_metric_backend_bytes(
        ctx->files[run->idx].sd_obj.driver != NULL
            ? ctx->files[run->idx].sd_obj.driver->name : "posix",
        BRIX_METRIC_OP_READ, (size_t) warm_io.nread);

    return 1;
}

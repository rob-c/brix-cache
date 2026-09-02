/*
 * read.c — kXR_read opcode.  See each function's docblock below.
 */

#include "read.h"
#include "fs/backend/sd.h"   /* phase-55: route raw fd I/O through the SD seam */
#include "fs/backend/csi_tagstore.h"  /* phase-59 W2: page-checksum verify */
#include "protocols/root/zip/zip_member.h"   /* phase-57 W2: ZIP member read dispatch */
#include "protocols/ssi/ssi.h"          /* §7: SSI handle read dispatch */

#include "core/ngx_brix_module.h"
#include "protocols/root/connection/budget.h"
#include "prefetch.h"

#include <sys/uio.h>   /* Phase 32 WS4: preadv2(RWF_NOWAIT) warm-cache probe */

#include "read_internal.h"
#include "protocols/root/response/response.h"  /* brix_send_redirect / _wait */
#include "protocols/root/session/registry.h"   /* §1.1 brix_session_pathid_bound */
#include "protocols/root/session/offload_registry.h" /* §1.1 brix_offload_lookup */
#include "protocols/root/connection/write_helpers.h"  /* §1.1 brix_queue_response_base */
#include "core/aio/aio.h"        /* §1.1 acquire/release read buffer, io_failure_log */

/*
 * brix_fsoverload_backoff — the shared memory-budget-overload response (§1.10,
 * xrootd.fsoverload). A read/readv the process-wide memory budget cannot admit
 * gets one of two backoffs: a kXR_redirect to brix_fsoverload_redirect's host
 * (offload the read to a sibling server) when that is configured, else a
 * kXR_wait(brix_fsoverload_stall) telling the client to retry here later. The
 * redirect host is NUL-terminated at config time (brix_pstrdupz), so it is passed
 * straight to brix_send_redirect; kXR_wait stays clamped by brix_max_delay at its
 * own emission choke point.
 *
 * §1.3 kXR_readrdok: a redirect issued in response to a kXR_read/readv (NOT at
 * open time) can only be followed by a client that advertised the readrdok login
 * ability. A client that did not — an older client, or one that cleared the bit —
 * would mishandle a mid-read redirect. For such a client we degrade to the
 * kXR_wait backoff (retry-here) even when a redirect host is configured, which is
 * always safe: the read is simply deferred until this node's budget frees.
 */
ngx_int_t
brix_fsoverload_backoff(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *rconf)
{
    if (rconf->fsoverload_redirect_host.len > 0
        && (ctx->login.ability & 0x04 /* kXR_readrdok */))
    {
        return brix_send_redirect(ctx, c,
            (const char *) rconf->fsoverload_redirect_host.data,
            (uint16_t) rconf->fsoverload_redirect_port);
    }
    return brix_send_wait(ctx, c, (uint32_t) rconf->fsoverload_stall);
}

/* Codec-vs-protocol drift guard: the wire codec (shared libxrdproto, deliberately
 * XProtocol-free) hard-codes the request body as XRDW_BODY_LEN bytes. This is the
 * one translation unit that sees both that constant and the real XProtocol
 * ClientRequestHdr, so it ties them together at compile time — if XRootD ever
 * resized the body region, every xrdw_*_unpack() call here would read the wrong
 * offsets, and this assert fails the build instead of corrupting requests. */
_Static_assert(sizeof(((ClientRequestHdr *) 0)->body) == XRDW_BODY_LEN,
    "wire codec body length must match XProtocol ClientRequestHdr.body");

/*
 * read_validate_req — decode the wire request and run the early-return checks.
 *
 * WHAT: unpacks the kXR_read body into *io, validates the file handle, serves
 * the trivial rlen==0 case, clamps oversized requests and rejects negative
 * offsets.
 * WHY: every serve strategy needs the same validated (idx, fd, offset, rlen)
 * tuple; hoisting the checks keeps the dispatcher a pure strategy selector.
 * HOW: returns 1 when the request is valid and *io is filled (databuf NULL);
 * returns 0 when the request was fully handled here (ok/error response already
 * queued) with *rc set to the value the opcode handler must return.
 */
static ngx_flag_t
read_validate_req(brix_ctx_t *ctx, ngx_connection_t *c,
    brix_read_io_t *io, ngx_int_t *rc)
{
    xrdw_read_req_t req;

    /*
     * The shared codec decodes the big-endian wire body into host order; the file
     * handle is a 4-byte blob but only byte 0 indexes our slot table
     * (BRIX_MAX_FILES <= 256); the (unsigned char) cast prevents sign-extension
     * of a high-bit handle byte into a negative idx.
     */
    xrdw_read_req_unpack(((ClientRequestHdr *) ctx->recv.hdr_buf)->body, &req);
    io->idx = (int) (unsigned char) req.fhandle[0];
    io->offset = req.offset;
    io->rlen = (size_t) (uint32_t) req.rlen;
    io->databuf = NULL;
    io->pathid  = 0;

    /*
     * §1.1: a kXR_read's optional read_args ride the payload — pathid at byte 0
     * when dlen >= 1 (the response-offload channel selector). Mirror pgread/§1.2:
     * a NONZERO pathid MUST name one of this session's live kXR_bind paths, else
     * kXR_ArgInvalid "invalid path ID", exactly as stock refuses an unbound path
     * ID (read previously ignored the read_args entirely — an inconsistency vs
     * pgread). Routing the response over that bound path (offloading) is a later
     * slice; the validated pathid is captured in io for it.
     */
    if (ctx->recv.cur_dlen >= 1 && ctx->recv.payload != NULL) {
        io->pathid = (unsigned) ((u_char *) ctx->recv.payload)[0];
        if (io->pathid != 0
            && !brix_session_pathid_bound(ctx->is_bound ? ctx->bound_sessid
                                                          : ctx->login.sessid,
                                            io->pathid))
        {
            BRIX_OP_ERR(ctx, BRIX_OP_READ);
            *rc = brix_send_error(ctx, c, kXR_ArgInvalid, "invalid path ID");
            return 0;
        }
    }

    if (!brix_validate_read_handle(ctx, c, io->idx, "READ",
                                     BRIX_OP_READ, rc)) {
        return 0;
    }

    if (io->rlen == 0) {
        BRIX_OP_OK(ctx, BRIX_OP_READ);
        *rc = brix_send_ok(ctx, c, NULL, 0);
        return 0;
    }

    if (io->rlen > BRIX_READ_REQUEST_MAX) {
        io->rlen = BRIX_READ_REQUEST_MAX;
    }

    io->fd = ctx->files[io->idx].fd;

    if (io->offset < 0) {
        brix_log_access(ctx, c, "READ", ctx->files[io->idx].path, "-",
                          0, kXR_IOError, "negative read offset", 0);
        BRIX_OP_ERR(ctx, BRIX_OP_READ);
        *rc = brix_send_error(ctx, c, kXR_IOError, "negative read offset");
        return 0;
    }

    return 1;
}

/*
 * brix_read_try_offload — §1.1 response offloading (do_Offload/do_OffloadIO
 * parity): when a validated read carries a NONZERO read_args pathid AND that
 * bound secondary data channel lives on THIS worker AND is quiescent, serve the
 * read's response over the SECONDARY's socket instead of the primary control
 * stream.  Returns 1 when the response was routed to the secondary (*rc = the
 * value brix_handle_read must return), 0 when the read must fall through to the
 * normal primary-stream serve strategies (byte-identical to before).
 *
 * WHAT (eligible case): borrow a buffer from the SECONDARY's read pool, fill its
 * data region [8 .. 8+n) with the file bytes via one synchronous VFS read, stamp
 * an 8-byte kXR_ok header carrying the PRIMARY request's streamid at [0 .. 8),
 * and queue the contiguous [hdr|data] frame on the secondary's out-ring.
 * WHY it is safe: buffers are acquired AND released on the secondary's ctx, so
 * the ordinary per-connection drain/release discipline applies with no cross-
 * connection lifetime tangle — the frame simply rides the machinery the secondary
 * already runs for its own bound reads.  The client correlates the response by
 * streamid regardless of which stream carries it.
 * HOW it is gated (this first routing slice deliberately handles only the safe,
 * common case): same-worker secondary that is idle (no queued response, no async
 * ack, no in-flight AIO, live fd), and a single-frame (<= one window) read.
 * Anything else — large/windowed, busy secondary, cross-worker pathid, pool
 * exhaustion — returns 0 and is served the old way.
 */
static ngx_flag_t
brix_read_try_offload(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *rconf, brix_read_io_t *io, ngx_int_t *rc)
{
    ngx_connection_t *sec_c;
    brix_ctx_t       *sec_ctx;
    size_t            total;
    u_char           *buf;
    brix_vfs_job_t    job;
    ssize_t           nread;

    sec_ctx = brix_read_offload_secondary(ctx, c, io->pathid, &sec_c);
    if (sec_ctx == NULL) {
        return 0;
    }

    /* Single-frame only: clamp to what a read-only handle actually holds; a read
     * larger than one streaming window belongs on the windowed primary path. */
    total = read_clamped_total(ctx, io);
    if (total > (size_t) BRIX_READ_WINDOW) {
        return 0;
    }

    /* Borrow the frame buffer from the SECONDARY's pool (acquire+release both on
     * its ctx) — header (8) + up to `total` data bytes, laid out contiguously. */
    buf = brix_acquire_read_buffer(sec_ctx, sec_c, XRD_RESPONSE_HDR_LEN + total);
    if (buf == NULL) {
        return 0;   /* secondary pool exhausted — fall back rather than fail */
    }

    /* One synchronous fill straight into the frame's data region [8 .. 8+total). */
    brix_vfs_job_read_init(&job, io->fd, (off_t) io->offset, total,
                              buf + XRD_RESPONSE_HDR_LEN, total, 0);
    job.csi = ctx->files[io->idx].csi;              /* phase-59 W2: verify on read */
    brix_vfs_job_set_obj(&job, &ctx->files[io->idx].sd_obj);
    brix_vfs_io_execute(&job);
    nread = job.nio;

    if (nread < 0) {
        /* Read/CSI failure: nothing has touched the secondary wire yet, so the
         * error rides the PRIMARY control stream exactly like the normal path. */
        brix_release_read_buffer(sec_ctx, sec_c, buf);
        if (job.io_errno != 0) {
            errno = job.io_errno;
        }
        brix_read_io_failure_log(c->log, "offload", io->fd,
                                   (off_t) io->offset, total, errno);
        BRIX_OP_ERR(ctx, BRIX_OP_READ);
        *rc = brix_send_error(ctx, c, kXR_IOError, strerror(errno));
        return 1;
    }

    /* Stamp the kXR_ok header with the PRIMARY request's streamid. */
    brix_build_resp_hdr(ctx->recv.cur_streamid, kXR_ok, (uint32_t) nread,
                          (ServerResponseHdr *) buf);

    /* Byte accounting + access log stay on the PRIMARY ctx (the request's owner). */
    ctx->files[io->idx].bytes_read += (size_t) nread;
    ctx->totals.bytes += (size_t) nread;
    if (rconf->access_log_fd != NGX_INVALID_FILE) {
        char read_detail[64];
        snprintf(read_detail, sizeof(read_detail), "%lld+%zu",
                 (long long) io->offset, io->rlen);
        brix_log_access(ctx, c, "READ", ctx->files[io->idx].path,
                          read_detail, 1, 0, NULL, (size_t) nread);
    }
    BRIX_OP_OK(ctx, BRIX_OP_READ);

    /* Queue the contiguous [hdr|data] frame on the SECONDARY's out-ring; the
     * secondary owns `buf` and releases it when the slot drains. */
    *rc = brix_queue_response_base(sec_ctx, sec_c, buf,
                                     XRD_RESPONSE_HDR_LEN + (size_t) nread, buf);
    if (*rc == NGX_OK) {
        brix_metric_offload(BRIX_PROTO_ROOT);   /* §1.1 observability */
    }

    /*
     * Release here on error OR on a full inline send (secondary ring stayed
     * empty) — only a parked-and-draining response keeps the buffer, whose slot
     * drain then releases it.  Mirrors read_finish_buffered's post-queue release;
     * brix_release_read_buffer is idempotent so the error/parked overlap is safe.
     */
    if (*rc != NGX_OK || sec_ctx->out.count == 0) {
        brix_release_read_buffer(sec_ctx, sec_c, buf);
    }
    return 1;
}

/*
 * brix_handle_read — kXR_read dispatcher: validate, then pick a serve strategy.
 *
 * WHAT: routes a validated read to one of the serve paths — SSI/ZIP/codec
 * early dispatch, zero-copy sendfile, windowed streaming, or the buffered
 * memory path (warm-probe → AIO → synchronous fallback).
 * WHY: each strategy has its own invariants (TLS => memory-backed buffers,
 * cleartext/kTLS => sendfile; heap bounded by the streaming window); keeping
 * the handler a flat early-return ladder makes the strategy choice auditable.
 * HOW: read_validate_req() supplies the decoded request; every branch
 * tail-calls its serve helper.
 */
ngx_int_t
brix_handle_read(brix_ctx_t *ctx, ngx_connection_t *c)
{
    brix_read_io_t                io;
    ngx_stream_brix_srv_conf_t *rconf;
    ngx_int_t                     rc;

    if (!read_validate_req(ctx, c, &io, &rc)) {
        return rc;
    }

    rconf = ngx_stream_get_module_srv_conf(
                (ngx_stream_session_t *) c->data, ngx_stream_brix_module);

    /* §7 XrdSsi: an SSI handle has no backing file — the first read dispatches the
     * accumulated request to the service and serves the response. Early dispatch
     * off the normal fd read path, like zip/slice below. */
    if (ctx->files[io.idx].ssi != NULL) {
        BRIX_OP_OK(ctx, BRIX_OP_READ);
        return brix_ssi_read(ctx, c, io.idx, (uint64_t) io.offset,
                             (uint32_t) io.rlen);
    }

    /* Phase-57 W2: ZIP member handles translate the read into the archive's
     * byte range (stored = offset add; deflate = stream inflate) — an early
     * dispatch off the normal fd read path. */
    if (ctx->files[io.idx].zip_mode) {
        return brix_zip_read(ctx, c, io.idx, io.offset, io.rlen);
    }

    /*
     * Phase-42 W4: inline read compression (opt-in, off by default).  Routed to
     * its own isolated synchronous handler so EVERYTHING below — the sendfile
     * fast path, windowed streaming and AIO pipeline — stays byte-identical for
     * the default (read_codec == 0 / BRIX_CODEC_IDENTITY) case.  pgread/readv
     * have their own handlers and never reach here, so their plaintext + CRC32c
     * invariant is preserved.
     */
    if (ctx->files[io.idx].read_codec != 0) {
        return brix_read_compressed(ctx, c, rconf, io.idx, (off_t) io.offset,
                                      io.rlen);
    }

    /*
     * §1.1 response offloading: a read tagged with a live, same-worker bound
     * pathid is served over that secondary data channel; every ineligible read
     * (pathid 0, cross-worker, busy secondary, large) returns 0 here and falls
     * through to the normal primary-stream strategies below, unchanged.
     */
    {
        ngx_int_t orc;
        if (brix_read_try_offload(ctx, c, rconf, &io, &orc)) {
            return orc;
        }
    }

    /*
     * Zero-copy sendfile fast path (gate in read_sendfile_serve_fd — the
     * TLS-vs-cleartext INVARIANT lives there, and the BACKEND elects the fd
     * for driver-backed handles).  Anything that fails the gate drops to the
     * memory/window path below.
     */
    {
        ngx_fd_t sfd = read_sendfile_serve_fd(ctx, c, &io);

        if (sfd != NGX_INVALID_FILE) {
            return brix_read_serve_sendfile(ctx, c, rconf, &io, sfd);
        }
    }

    /*
     * Phase 31 W2.1: bound resident heap for large memory-backed reads.  This
     * is the memory path (TLS / non-regular file) — unlike the cleartext
     * sendfile branch above it must buffer data in heap.  Clamp the request to
     * what the file actually holds (read-only handles have a cached size); if
     * that exceeds one streaming window, serve the read as a sequence of
     * window-sized kXR_oksofar chunks ending in kXR_ok, holding only ~one window
     * in read_scratch at a time instead of the whole request.  Writable handles
     * (size unknown) use rlen and let a short read at EOF terminate early.
     */
    {
        size_t total = read_clamped_total(ctx, &io);

        if (total > (size_t) BRIX_READ_WINDOW) {
            return read_serve_windowed(ctx, c, rconf, &io, total);
        }
    }

    /*
     * Small memory read (<= one window): single-shot.  Admit the full rlen and
     * buffer it in read_scratch — bounded by the window, so no streaming needed.
     */
    return read_serve_buffered(ctx, c, rconf, &io);
}

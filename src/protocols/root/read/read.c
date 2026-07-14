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
     * Zero-copy sendfile fast path (gate in read_sendfile_eligible — the
     * TLS-vs-cleartext INVARIANT lives there).  Anything that fails the gate
     * drops to the memory/window path below.
     */
    if (read_sendfile_eligible(ctx, c, io.idx)) {
        return brix_read_serve_sendfile(ctx, c, rconf, &io);
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

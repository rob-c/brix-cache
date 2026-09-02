/*
 * read_sendfile.c — kXR_read zero-copy sendfile serve path (split from read.c).
 * See each function's docblock below.
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

/*
 * brix_ktls_send_active — true when kernel-TLS transmit is active on this
 * connection (Phase 29 kTLS).
 *
 * Without kTLS, a TLS data stream must encrypt in userspace and therefore cannot
 * use sendfile(2) — the historical reason the read path gates the zero-copy
 * sendfile branch on !c->ssl.  When the kernel TLS ULP is negotiated for the send
 * side (OpenSSL SSL_OP_ENABLE_KTLS + a kTLS-offloadable cipher), the kernel does
 * the record encryption inside sendfile, so a file-backed chain is legal over TLS
 * and the read inherits the cleartext sendfile fast path (and its Phase-2
 * pipelining).  Returns 0 whenever kTLS is unavailable or not negotiated, so the
 * caller transparently falls back to the memory/window path — the relaxation is
 * always safe.
 */
static ngx_flag_t
brix_ktls_send_active(ngx_connection_t *c)
{
#ifdef BIO_get_ktls_send
    if (c->ssl != NULL && c->ssl->connection != NULL) {
        return BIO_get_ktls_send(SSL_get_wbio(c->ssl->connection)) > 0 ? 1 : 0;
    }
#endif
    return 0;
}

/* Zero-copy sendfile serve path for a regular-file cleartext (or kTLS) read:
 * clamps the chunk to EOF, charges bytes/bandwidth/dashboard + access log,
 * builds the sendfile chain and queues it.  Always completes the request --
 * the caller tail-calls this with the fd read_sendfile_serve_fd resolved
 * (the handle's own fd, or the one its backend elected for this range). */
ngx_int_t
brix_read_serve_sendfile(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *rconf, const brix_read_io_t *io,
    ngx_fd_t sfd)
{
    size_t       data_total;
    u_char      *send_base = NULL;
    ngx_chain_t *rsp_chain;
    int          idx = io->idx;

    off_t file_size;
    off_t avail;

    /*
     * Read-only handles: file size is stable, use the value cached at open
     * time to skip the fstat(2) syscall on every chunk request.
     * Writable handles (kXR_open_updt): re-stat so a write on the same
     * session is visible to subsequent reads — through the driver's fstat
     * slot when the handle is driver-backed (a bare fstat on the serve fd
     * would report block-0 size, not object size, for a striped backend).
     */
    if (!ctx->files[idx].writable) {
        file_size = ctx->files[idx].cached_size;
    } else if (ctx->files[idx].sd_obj.driver != NULL) {
        brix_sd_stat_t snap;
        if (ctx->files[idx].sd_obj.driver->fstat == NULL
            || ctx->files[idx].sd_obj.driver->fstat(&ctx->files[idx].sd_obj,
                                                    &snap) != NGX_OK)
        {
            BRIX_RETURN_ERR(ctx, c, BRIX_OP_READ, "READ",
                              ctx->files[idx].path, "-",
                              kXR_IOError, strerror(errno));
        }
        file_size = snap.size;
    } else {
        struct stat st;
        if (fstat(io->fd, &st) != 0) {
            BRIX_RETURN_ERR(ctx, c, BRIX_OP_READ, "READ",
                              ctx->files[idx].path, "-",
                              kXR_IOError, strerror(errno));
        }
        file_size = st.st_size;
    }

    /*
     * Clamp the chunk to bytes actually present: sendfile would otherwise be
     * asked for data past EOF.  offset at/after EOF yields a zero-length OK
     * (legal short read); otherwise serve min(rlen, remaining-to-EOF).  This
     * is also why data_total — not the client's requested rlen — drives every
     * accounting counter below.
     */
    if ((off_t) io->offset >= file_size) {
        data_total = 0;
    } else {
        avail = file_size - (off_t) io->offset;
        data_total = (avail < (off_t) io->rlen) ? (size_t) avail : io->rlen;
    }

    brix_prefetch_read_file(c->log, &ctx->files[idx], (off_t) io->offset,
                              data_total, file_size);

    ctx->files[idx].bytes_read += data_total;
    ctx->totals.bytes += data_total;
    brix_rl_charge_ctx(ctx, data_total);  /* Phase 25 bandwidth */

    /* Per-backend storage byte totals: this zero-copy branch never reaches
     * brix_vfs_io_execute (the kernel moves the bytes), so attribute here,
     * to the backend that elected the serve fd (bare-fd handles are the
     * default POSIX driver). Buffered reads attribute at the io_execute seam
     * instead — no double count. */
    brix_metric_backend_bytes(ctx->files[idx].sd_obj.driver != NULL
                                  ? ctx->files[idx].sd_obj.driver->name
                                  : "posix",
                              BRIX_METRIC_OP_READ, data_total);

    if (ctx->files[idx].dashboard_slot >= 0 &&
        ngx_brix_dashboard_shm_zone != NULL)
    {
        brix_transfer_slot_update(ngx_brix_dashboard_shm_zone->data,
                                    ctx->files[idx].dashboard_slot,
                                    (ngx_atomic_int_t) data_total,
                                    (int64_t) ngx_current_msec);
        brix_transfer_slot_count_op(ngx_brix_dashboard_shm_zone->data,
                                      ctx->files[idx].dashboard_slot,
                                      "read");
    }

    if (rconf->access_log_fd != NGX_INVALID_FILE) {
        char read_detail[64];

        snprintf(read_detail, sizeof(read_detail), "%lld+%zu",
                 (long long) io->offset, io->rlen);
        brix_log_access(ctx, c, "READ", ctx->files[idx].path,
                          read_detail, 1, 0, NULL, data_total);
    }
    BRIX_OP_OK(ctx, BRIX_OP_READ);

    rsp_chain = brix_build_sendfile_chain(ctx, c, sfd,
                                            ctx->files[idx].path,
                                            (off_t) io->offset, data_total,
                                            &send_base);
    if (rsp_chain == NULL) {
        brix_release_read_buffer(ctx, c, send_base);
        return NGX_ERROR;
    }

    {
        ngx_int_t rc = brix_queue_response_chain(ctx, c, rsp_chain,
                                                   send_base);

        if (rc != NGX_OK || ctx->state != XRD_ST_SENDING) {
            brix_release_read_buffer(ctx, c, send_base);
        }
        return rc;
    }
}

/*
 * read_sendfile_serve_fd — gate + fd resolver for the zero-copy sendfile path.
 *
 * WHAT: the kernel fd to sendfile this read from, or NGX_INVALID_FILE when the
 * handle/connection pair must take the memory/window path instead.
 * WHY: INVARIANT — TLS serves memory-backed buffers and cleartext serves
 * file-backed + sendfile, never mixed; this resolver is the single place that
 * split is decided for kXR_read.  The storage side of the decision belongs to
 * the BACKEND (its read_sendfile_fd slot — e.g. pblock declines a range that
 * spans striped blocks, cache declines a partial object), so a driver-backed
 * handle asks the driver rather than being refused outright: requiring a bare
 * fd here quietly turned the whole fast path off once every open became
 * driver-backed, buffering each cleartext byte through userspace twice.
 * HOW: the transport conditions must all hold —
 *   - is_regular: sendfile(2) only works against a real file, not a pipe/dir.
 *   - rlen >= BRIX_READ_SENDFILE_MIN: a small read is cheaper on the memory
 *     path (one preadv2 + one writev of [hdr|data]) than through the
 *     4-setsockopt TCP_CORK bracket nginx wraps around a header+file chain.
 *   - !c->ssl OR kTLS active: a userspace-TLS stream cannot sendfile because
 *     nginx must encrypt each record in user memory (INVARIANT: TLS =>
 *     memory-backed buffers).  kTLS lifts that — the kernel encrypts inside
 *     sendfile — so a TLS connection with kTLS negotiated rejoins this branch.
 *   - no CSI: phase-59 W2/ADR-6 — CSI needs the bytes in memory to verify.
 * Then the storage verdict: a bare-fd handle serves from its own fd; a
 * driver-backed handle serves from whatever fd its read_sendfile_fd slot
 * elects for [offset, offset+rlen) (NULL slot / decline => memory path).
 */
ngx_fd_t
read_sendfile_serve_fd(brix_ctx_t *ctx, ngx_connection_t *c,
    const brix_read_io_t *io)
{
    brix_sd_obj_t *obj = &ctx->files[io->idx].sd_obj;

    if (!ctx->files[io->idx].is_regular
        || io->rlen < BRIX_READ_SENDFILE_MIN
        || (c->ssl && !brix_ktls_send_active(c))
        || ctx->files[io->idx].csi != NULL)
    {
        return NGX_INVALID_FILE;
    }
    if (obj->driver == NULL) {
        return io->fd;
    }
    if (obj->driver->read_sendfile_fd == NULL) {
        return NGX_INVALID_FILE;
    }
    return obj->driver->read_sendfile_fd(obj, (off_t) io->offset, io->rlen, 1);
}

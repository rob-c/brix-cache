/*
 * read.c — kXR_read opcode.  See each function's docblock below.
 */

#include "read.h"
#include "../fs/backend/sd.h"   /* phase-55: route raw fd I/O through the SD seam */
#include "../fs/backend/csi_tagstore.h"  /* phase-59 W2: page-checksum verify */
#include "../zip/zip_member.h"   /* phase-57 W2: ZIP member read dispatch */
#include "../ssi/ssi.h"          /* §7: SSI handle read dispatch */

#include "../ngx_xrootd_module.h"
#include "../connection/budget.h"
#include "prefetch.h"

#include <sys/uio.h>   /* Phase 32 WS4: preadv2(RWF_NOWAIT) warm-cache probe */

/* Codec-vs-protocol drift guard: the wire codec (shared libxrdproto, deliberately
 * XProtocol-free) hard-codes the request body as XRDW_BODY_LEN bytes. This is the
 * one translation unit that sees both that constant and the real XProtocol
 * ClientRequestHdr, so it ties them together at compile time — if XRootD ever
 * resized the body region, every xrdw_*_unpack() call here would read the wrong
 * offsets, and this assert fails the build instead of corrupting requests. */
_Static_assert(sizeof(((ClientRequestHdr *) 0)->body) == XRDW_BODY_LEN,
    "wire codec body length must match XProtocol ClientRequestHdr.body");

/*
 * xrootd_ktls_send_active — true when kernel-TLS transmit is active on this
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
xrootd_ktls_send_active(ngx_connection_t *c)
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
 * the caller tail-calls this under the is_regular && (!ssl || kTLS) gate. */
static ngx_int_t
xrootd_read_serve_sendfile(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *rconf, int idx, ngx_fd_t fd,
    int64_t offset, size_t rlen)
{
    size_t       data_total;
    u_char      *send_base = NULL;
    ngx_chain_t *rsp_chain;

    off_t file_size;
    off_t avail;

    /*
     * Read-only handles: file size is stable, use the value cached at open
     * time to skip the fstat(2) syscall on every chunk request.
     * Writable handles (kXR_open_updt): re-stat so a write on the same
     * session is visible to subsequent reads.
     */
    if (!ctx->files[idx].writable) {
        file_size = ctx->files[idx].cached_size;
    } else {
        struct stat st;
        if (fstat(fd, &st) != 0) {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_READ, "READ",
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
    if ((off_t) offset >= file_size) {
        data_total = 0;
    } else {
        avail = file_size - (off_t) offset;
        data_total = (avail < (off_t) rlen) ? (size_t) avail : rlen;
    }

    xrootd_prefetch_read_file(c->log, &ctx->files[idx], (off_t) offset,
                              data_total, file_size);

    ctx->files[idx].bytes_read += data_total;
    ctx->session_bytes += data_total;
    xrootd_rl_charge_ctx(ctx, data_total);  /* Phase 25 bandwidth */

    if (ctx->files[idx].dashboard_slot >= 0 &&
        ngx_xrootd_dashboard_shm_zone != NULL)
    {
        xrootd_transfer_slot_update(ngx_xrootd_dashboard_shm_zone->data,
                                    ctx->files[idx].dashboard_slot,
                                    (ngx_atomic_int_t) data_total,
                                    (int64_t) ngx_current_msec);
        xrootd_transfer_slot_count_op(ngx_xrootd_dashboard_shm_zone->data,
                                      ctx->files[idx].dashboard_slot,
                                      "read");
    }

    if (rconf->access_log_fd != NGX_INVALID_FILE) {
        char read_detail[64];

        snprintf(read_detail, sizeof(read_detail), "%lld+%zu",
                 (long long) offset, rlen);
        xrootd_log_access(ctx, c, "READ", ctx->files[idx].path,
                          read_detail, 1, 0, NULL, data_total);
    }
    XROOTD_OP_OK(ctx, XROOTD_OP_READ);

    rsp_chain = xrootd_build_sendfile_chain(ctx, c, fd,
                                            ctx->files[idx].path,
                                            (off_t) offset, data_total,
                                            &send_base);
    if (rsp_chain == NULL) {
        xrootd_release_read_buffer(ctx, c, send_base);
        return NGX_ERROR;
    }

    {
        ngx_int_t rc = xrootd_queue_response_chain(ctx, c, rsp_chain,
                                                   send_base);

        if (rc != NGX_OK || ctx->state != XRD_ST_SENDING) {
            xrootd_release_read_buffer(ctx, c, send_base);
        }
        return rc;
    }
}

ngx_int_t
xrootd_handle_read(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    xrdw_read_req_t               req;
    int                           idx;
    int64_t                       offset;
    size_t                        rlen;
    u_char                       *databuf;
    ssize_t                       nread;
    size_t                        data_total;
    ngx_chain_t                  *rsp_chain;
    ngx_stream_xrootd_srv_conf_t *rconf;
    int                           fd;
    ngx_int_t                     rc;

    /*
     * The shared codec decodes the big-endian wire body into host order; the file
     * handle is a 4-byte blob but only byte 0 indexes our slot table
     * (XROOTD_MAX_FILES <= 256); the (unsigned char) cast prevents sign-extension
     * of a high-bit handle byte into a negative idx.
     */
    xrdw_read_req_unpack(((ClientRequestHdr *) ctx->hdr_buf)->body, &req);
    idx = (int) (unsigned char) req.fhandle[0];
    offset = req.offset;
    rlen = (size_t) (uint32_t) req.rlen;

    if (!xrootd_validate_read_handle(ctx, c, idx, "READ",
                                     XROOTD_OP_READ, &rc)) {
        return rc;
    }

    if (rlen == 0) {
        XROOTD_OP_OK(ctx, XROOTD_OP_READ);
        return xrootd_send_ok(ctx, c, NULL, 0);
    }

    if (rlen > XROOTD_READ_REQUEST_MAX) {
        rlen = XROOTD_READ_REQUEST_MAX;
    }

    fd = ctx->files[idx].fd;

    if (offset < 0) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_READ, "READ",
                          ctx->files[idx].path, "-",
                          kXR_IOError, "negative read offset");
    }

    rconf = ngx_stream_get_module_srv_conf(
                (ngx_stream_session_t *) c->data, ngx_stream_xrootd_module);

    /* §7 XrdSsi: an SSI handle has no backing file — the first read dispatches the
     * accumulated request to the service and serves the response. Early dispatch
     * off the normal fd read path, like zip/slice below. */
    if (ctx->files[idx].ssi != NULL) {
        XROOTD_OP_OK(ctx, XROOTD_OP_READ);
        return xrootd_ssi_read(ctx, c, idx, (uint64_t) offset, (uint32_t) rlen);
    }

    /* Phase-57 W2: ZIP member handles translate the read into the archive's
     * byte range (stored = offset add; deflate = stream inflate) — an early
     * dispatch off the normal fd read path. */
    if (ctx->files[idx].zip_mode) {
        return xrootd_zip_read(ctx, c, idx, offset, rlen);
    }

    /*
     * Phase-42 W4: inline read compression (opt-in, off by default).  Routed to
     * its own isolated synchronous handler so EVERYTHING below — the sendfile
     * fast path, windowed streaming and AIO pipeline — stays byte-identical for
     * the default (read_codec == 0 / XROOTD_CODEC_IDENTITY) case.  pgread/readv
     * have their own handlers and never reach here, so their plaintext + CRC32c
     * invariant is preserved.
     */
    if (ctx->files[idx].read_codec != 0) {
        return xrootd_read_compressed(ctx, c, rconf, idx, (off_t) offset, rlen);
    }

    /*
     * Zero-copy sendfile fast path.  Two conditions must both hold:
     *   - is_regular: sendfile(2) only works against a real file, not a pipe/dir.
     *   - !c->ssl OR kTLS active: a userspace-TLS stream cannot sendfile because
     *     nginx must encrypt each record in user memory (INVARIANT: TLS =>
     *     memory-backed buffers).  kTLS lifts that — the kernel encrypts inside
     *     sendfile — so a TLS connection with kTLS negotiated rejoins this branch.
     * Anything that fails the gate (TLS without kTLS, irregular file) drops to the
     * memory/window path below.
     */
    if (ctx->files[idx].is_regular
        && (!c->ssl || xrootd_ktls_send_active(c))
        && ctx->files[idx].csi == NULL   /* phase-59 W2/ADR-6: CSI needs the
                                          * bytes in memory to verify, so an
                                          * integrity-checked handle takes the
                                          * buffered path, not zero-copy sendfile */
        && ctx->files[idx].sd_obj.driver == NULL) /* Layer 3: a driver-backed
                                          * handle's bare fd is only block 0 — a
                                          * sendfile over it cannot span striped
                                          * blocks, so serve via the buffered
                                          * io_core path (driver preadv) instead */
    {
        return xrootd_read_serve_sendfile(ctx, c, rconf, idx, fd,
                                          offset, rlen);
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
        size_t total = rlen;

        if (!ctx->files[idx].writable && ctx->files[idx].cached_size > 0) {
            off_t avail = ctx->files[idx].cached_size - (off_t) offset;
            total = (avail <= 0) ? 0
                  : ((off_t) total > avail ? (size_t) avail : total);
        }

        if (total > (size_t) XROOTD_READ_WINDOW) {
            /* Admit one window's worth — a windowed stream holds ~2 MiB, not
             * the full request, so many more fit under the budget. */
            if (!xrootd_budget_admit(ctx, rconf->memory_budget,
                                     (size_t) XROOTD_READ_WINDOW)) {
                return xrootd_send_wait(ctx, c, 1);
            }

            /*
             * Arm the windowed-read state machine: the pump below (and any
             * resumption after a partial flush) reads from rd_win_* rather than
             * this request's locals, so it survives across event-loop returns.
             * cur_streamid is snapshotted into rd_win_streamid because each
             * kXR_oksofar/kXR_ok chunk must echo the originating request's stream
             * id, but cur_streamid will be overwritten by the next inbound header
             * before this stream finishes draining.
             */
            ctx->rd_win_active = 1;
            ctx->rd_win_fd = fd;
            ctx->rd_win_idx = idx;
            ctx->rd_win_offset = (off_t) offset;
            ctx->rd_win_remaining = total;
            ctx->rd_win_streamid[0] = ctx->cur_streamid[0];
            ctx->rd_win_streamid[1] = ctx->cur_streamid[1];

            xrootd_prefetch_read_file(c->log, &ctx->files[idx], (off_t) offset,
                                      total,
                                      ctx->files[idx].writable
                                          ? 0 : ctx->files[idx].cached_size);

            if (rconf->access_log_fd != NGX_INVALID_FILE) {
                char read_detail[64];
                snprintf(read_detail, sizeof(read_detail), "%lld+%zu",
                         (long long) offset, rlen);
                xrootd_log_access(ctx, c, "READ", ctx->files[idx].path,
                                  read_detail, 1, 0, NULL, total);
            }

            xrootd_read_window_pump(ctx, c, rconf);
            return NGX_OK;
        }
    }

    /*
     * Small memory read (<= one window): single-shot.  Admit the full rlen and
     * buffer it in read_scratch — bounded by the window, so no streaming needed.
     */
    if (!xrootd_budget_admit(ctx, rconf->memory_budget, rlen)) {
        return xrootd_send_wait(ctx, c, 1);
    }

    /*
     * Per-in-flight read buffer (read pipelining): each outstanding memory read
     * gets its OWN buffer from rd_pool rather than the single shared read_scratch,
     * so this response can keep draining the (possibly jittered) socket while the
     * recv loop already issues the next read into a different buffer.  Released
     * back to the pool when this response's out_ring slot drains.
     */
    databuf = xrootd_acquire_read_buffer(ctx, c, rlen);
    if (databuf == NULL) {
        return NGX_ERROR;
    }

    /* Charge the (possibly grown) read-pool footprint to the budget now so a
     * concurrent connection's admission check sees this allocation promptly. */
    xrootd_budget_sync(ctx);

    if (ctx->files[idx].is_regular) {
        off_t  file_size;
        size_t hint_len;

        file_size = ctx->files[idx].writable ? 0
                                              : ctx->files[idx].cached_size;
        hint_len = rlen;

        if (file_size > 0) {
            if ((off_t) offset >= file_size) {
                hint_len = 0;
            } else if ((off_t) hint_len > file_size - (off_t) offset) {
                hint_len = (size_t) (file_size - (off_t) offset);
            }
        }

        xrootd_prefetch_read_file(c->log, &ctx->files[idx], (off_t) offset,
                                  hint_len, file_size);
    }

    /*
     * Phase 32 WS4: warm-cache fast path.  Probe the page cache with a
     * non-blocking preadv2(RWF_NOWAIT).  If the whole request is resident it
     * returns rlen bytes immediately and we complete inline below — skipping the
     * thread-pool round-trip (hundreds of µs) that otherwise dominates a
     * cache-hot read.  A short or EAGAIN result is a (partial) cache miss: fall
     * through to the AIO thread (or a synchronous pread if no pool), which reads
     * the full data, blocking off the event loop.  Only attempted for regular
     * files (RWF_NOWAIT is meaningful against the page cache).
     */
    {
        ssize_t warm = -1;
#if defined(RWF_NOWAIT)
        if (rconf->common.thread_pool != NULL && ctx->files[idx].is_regular) {
            struct iovec    iov;
            xrootd_sd_obj_t obj;
            iov.iov_base = databuf;
            iov.iov_len  = rlen;
            xrootd_sd_posix_wrap(&obj, fd);   /* phase-55: SD seam */
            warm = obj.driver->preadv2(&obj, &iov, 1,
                                                  (off_t) offset, RWF_NOWAIT);
        }
#endif

        /*
         * Only an exact rlen match counts as a hit: a short warm result means
         * part of the range was not resident (or EOF), and re-issuing a blocking
         * read for the missing tail from the event loop would stall it — so any
         * non-exact result falls through to the thread pool / sync path, which
         * re-reads the full range from offset (the partial warm bytes are simply
         * overwritten).
         */
        if (warm == (ssize_t) rlen) {
            nread = warm;   /* full page-cache hit — databuf is filled; complete inline */

            /* phase-59 W2: the warm fast path bypasses the VFS job, so verify
             * the page CRCs here too; a mismatch fails the read (EIO). */
            if (ctx->files[idx].csi != NULL && nread > 0
                && xrootd_csi_verify_read(
                       (xrootd_csi_t *) ctx->files[idx].csi, databuf,
                       (off_t) offset, (size_t) nread) == XROOTD_CSI_MISMATCH)
            {
                nread = -1;
                errno = EIO;
            }

        } else if (rconf->common.thread_pool != NULL) {
            ngx_thread_task_t *task;
            xrootd_read_aio_t *t;
            ngx_flag_t         posted;

            /*
             * One reusable task per session (ctx->read_aio_task): allocate it the
             * first time, otherwise reset the two fields ngx reuse requires —
             * unlink from any prior queue (next) and clear the completion flag so
             * the event loop will fire the done-callback again.
             */
            task = ctx->read_aio_task;
            if (task == NULL) {
                task = ngx_thread_task_alloc(c->pool, sizeof(xrootd_read_aio_t));
                if (task == NULL) {
                    xrootd_release_read_buffer(ctx, c, databuf);
                    return NGX_ERROR;
                }
                ctx->read_aio_task = task;
            } else {
                task->next = NULL;
                task->event.complete = 0;
            }

            t = task->ctx;
            t->c = c;
            t->ctx = ctx;
            t->fd = fd;
            t->handle_idx = idx;
            t->offset = (off_t) offset;
            t->rlen = rlen;
            t->databuf = databuf;
            t->streamid[0] = ctx->cur_streamid[0];
            t->streamid[1] = ctx->cur_streamid[1];
            t->nread = 0;
            t->io_errno = 0;
            t->csi = ctx->files[idx].csi;   /* phase-59 W2: verify on read */
            t->obj = ctx->files[idx].sd_obj; /* Layer 3: driver obj (or zeroed) */

            xrootd_task_bind(task, xrootd_read_aio_thread, xrootd_read_aio_done);

            (void) xrootd_aio_post_task(ctx, c, rconf->common.thread_pool, task,
                                        "xrootd: thread_task_post failed, sync read fallback",
                                        &posted);
            /*
             * Posted: the read now completes off-thread; the done-callback owns
             * databuf and finishes the response, so return early — nothing more to
             * do on the event loop.  Not posted (queue full / post error): fall
             * through to a blocking pread here so the read never silently drops.
             */
            if (posted) {
                return NGX_OK;
            }
            {
                xrootd_vfs_job_t job;

                xrootd_vfs_job_read_init(&job, fd, (off_t) offset, rlen,
                                          databuf, rlen, 0);
                job.csi = ctx->files[idx].csi;   /* phase-59 W2: verify on read */
                xrootd_vfs_job_set_obj(&job, &ctx->files[idx].sd_obj);
                xrootd_vfs_io_execute(&job);
                nread = job.nio;
                if (job.io_errno != 0) {
                    /* A CSI page-checksum mismatch surfaces here as EIO
                     * (job.csi_mismatch set); the existing nread<0 path fails
                     * the read so corrupt data is never served. */
                    errno = job.io_errno;
                }
            }

        } else {
            xrootd_vfs_job_t job;

            /* No thread pool configured: read inline on the event loop. */
            xrootd_vfs_job_read_init(&job, fd, (off_t) offset, rlen,
                                      databuf, rlen, 0);
            job.csi = ctx->files[idx].csi;   /* phase-59 W2: verify on read */
            xrootd_vfs_job_set_obj(&job, &ctx->files[idx].sd_obj);
            xrootd_vfs_io_execute(&job);
            nread = job.nio;
            if (job.io_errno != 0) {
                /* CSI mismatch surfaces as EIO here; the nread<0 path below
                 * fails the read so corrupt data is never served. */
                errno = job.io_errno;
            }
        }
    }
    if (nread < 0) {
        xrootd_release_read_buffer(ctx, c, databuf);
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_READ, "READ",
                          ctx->files[idx].path, "-",
                          kXR_IOError, strerror(errno));
    }

    data_total = (size_t) nread;

    ctx->files[idx].bytes_read += data_total;
    ctx->session_bytes += data_total;

    if (ctx->files[idx].dashboard_slot >= 0 &&
        ngx_xrootd_dashboard_shm_zone != NULL)
    {
        xrootd_transfer_slot_update(ngx_xrootd_dashboard_shm_zone->data,
                                    ctx->files[idx].dashboard_slot,
                                    (ngx_atomic_int_t) data_total,
                                    (int64_t) ngx_current_msec);
        xrootd_transfer_slot_count_op(ngx_xrootd_dashboard_shm_zone->data,
                                      ctx->files[idx].dashboard_slot, "read");
    }

    if (rconf->access_log_fd != NGX_INVALID_FILE) {
        char read_detail[64];

        snprintf(read_detail, sizeof(read_detail), "%lld+%zu",
                 (long long) offset, rlen);
        xrootd_log_access(ctx, c, "READ", ctx->files[idx].path,
                          read_detail, 1, 0, NULL, data_total);
    }
    XROOTD_OP_OK(ctx, XROOTD_OP_READ);

    rsp_chain = xrootd_build_chunked_chain(ctx, c, databuf, data_total);
    if (rsp_chain == NULL) {
        xrootd_release_read_buffer(ctx, c, databuf);
        return NGX_ERROR;
    }

    {
        ngx_int_t rc = xrootd_queue_response_chain(ctx, c, rsp_chain, databuf);

        if (rc != NGX_OK || ctx->state != XRD_ST_SENDING) {
            xrootd_release_read_buffer(ctx, c, databuf);
        } else {
            /*
             * Parked and draining: per-in-flight buffer + per-slot header make
             * this memory-backed (TLS) read safe to pipeline, so let the recv loop
             * queue the next read behind it instead of idling while it drains a
             * jittered socket.  (A single-chunk response only: the non-windowed
             * path is bounded by XROOTD_READ_WINDOW < XROOTD_READ_CHUNK_MAX.)
             */
            ctx->resp_pipelinable = 1;
        }
        return rc;
    }
}

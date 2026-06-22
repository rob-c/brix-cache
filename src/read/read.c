/* ------------------------------------------------------------------ */
/* Single Read — kXR_read handler                                           */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements the kXR_read opcode — single-segment file read returning raw bytes to client. Unlike kXR_pgread which interleaves CRC32c checksums between pages, kXR_read returns unverified byte stream suitable for large transfers where integrity verification is handled at application level (xrdcp v5+ uses pgread). Two modes exist: handle-based (fhandle[4] identifies open slot, dlen==0) using fd already open on the slot; path-based (dlen>0 with payload containing path) resolves via xrootd_resolve_path_write fallback to xrootd_resolve_path, opens O_RDONLY for pread(2), calls read then closes temporary fd. Offset is big-endian int64 representing start position in file; rlen is uint32_t representing requested byte count (capped at XROOTD_READ_REQUEST_MAX).
 *
 * WHY: Single-segment reads provide simple byte-stream delivery for large transfers where integrity verification is handled at application level rather than protocol level. Unlike pgread's per-page checksum overhead, kXR_read returns raw bytes enabling clients to implement their own integrity checks or rely on transport-layer guarantees (TLS for davs:// downloads). Handle-based mode works on files already opened by current session enabling rapid reads without path resolution; path-based mode provides broader capability — read any file within export root regardless of whether it was previously opened by this session, enabling bulk access across multiple files without requiring individual open/close cycles for each target file.
 *
 * HOW: Two-phase read → validate read handle (xrootd_validate_read_handle for read-side validation) — parse offset/rlen from wire format (big-endian int64 + uint32_t) — cap rlen at XROOTD_READ_REQUEST_MAX if exceeds limit — perform pread(2) from file using AIO thread-pool or inline fallback (NGX_THREADS compile guard) — build chunked response chain via xrootd_build_chunked_chain() — queue response via xrootd_queue_response_chain() with databuf release callback. Access-log detail format "<offset>+rlen" tracks byte count transferred; throughput calculation uses bytes_read + session_bytes_written counters. */

/* ------------------------------------------------------------------ */
/* Section: Handle-Based vs Path-Based Read                                 */
/* ------------------------------------------------------------------ */
/*
 * WHAT: Two read modes exist based on dlen parameter in ClientReadRequest wire format. Handle-based (dlen==0): uses the fd already open on the slot — no path resolution or temporary file opening required, enabling rapid reads during staging operations where file was previously opened via kXR_open. Path-based (dlen>0 with payload containing path): resolves via xrootd_resolve_path_write fallback to xrootd_resolve_path, opens O_RDONLY for pread(2), calls read then closes temporary fd — provides broader capability to read any file within export root regardless of whether it was previously opened by this session.
 *
 * WHY: Handle-based mode enables rapid reads during staging operations where file was already opened via kXR_open — no path resolution or temporary opening required reduces overhead in high-frequency read scenarios (e.g., xrdcp streaming downloads). Path-based mode provides broader capability — read any file within export root regardless of whether it was previously opened by this session, enabling bulk access across multiple files without requiring individual open/close cycles for each target file. */

/* ------------------------------------------------------------------ */
/* Section: AIO vs Synchronous Read                                         */
/* ------------------------------------------------------------------ */
/*
 * WHAT: Two read execution modes exist based on NGX_THREADS compile configuration and thread pool availability. When nginx has a thread pool configured (NGX_THREADS), reads are posted to background threads so the main event loop doesn't block on disk I/O — payload buffer is detached from ctx->payload_buf and freed in completion callback allowing main thread to continue reading next request header while read happens elsewhere. When no thread pool is configured OR queue is full, reads happen synchronously on main event loop thread using pread(2) directly from recv buffer ensuring reads always succeed even under degraded conditions.
 *
 * WHY: AIO offload prevents blocking the main event loop during large file transfers where disk I/O could take extended periods — enables concurrent request processing while reads proceed in parallel worker threads. Synchronous fallback ensures reads always succeed even when thread pool is unavailable or queue is full (high contention scenario), preventing read failures due to resource exhaustion rather than falling back to degraded performance gracefully. */

/* ------------------------------------------------------------------ */
/* Section: Chunked Response Chain                                          */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_build_chunked_chain() and xrootd_queue_response_chain() build response chain using nginx's ngx_chain_t/ngx_buf_t pattern for byte-stream delivery to client. Unlike pgread's kXR_status framing with per-page CRC, kXR_read returns raw bytes in chunked chain suitable for large transfers where integrity verification is handled at application level. Response chain uses memory-backed buffers (b->memory=1) for TLS connections; cleartext reads use file-backed sendfile paths when available for reduced memory overhead on large transfers.
 *
 * WHY: Chunked response pattern enables efficient byte-stream delivery without requiring single contiguous buffer allocation for entire read payload — nginx's event loop can flush partial buffers as they become available reducing peak memory pressure during large file downloads. Memory-backed buffers (b->memory=1) for TLS connections ensure data remains accessible after send operation; file-backed sendfile paths for cleartext reads reduce memory overhead by allowing kernel-level direct transfer without copying bytes into nginx buffer pool. */

/* ---- Function: xrootd_handle_read() ----
 *
 * WHAT: Handles the kXR_read opcode — single-segment file read returning raw bytes to client supporting two modes: handle-based (fhandle[4] identifies open slot, dlen==0) using fd already open on the slot; path-based (dlen>0 with payload containing path) resolves via xrootd_resolve_path_write fallback to xrootd_resolve_path, opens O_RDONLY for pread(2), calls read then closes temporary fd. Offset is big-endian int64 representing start position in file; rlen is uint32_t representing requested byte count (capped at XROOTD_READ_REQUEST_MAX). Token scope read gate required for both paths ensuring only authenticated clients can access files. Returns raw bytes in chunked response chain suitable for large transfers where integrity verification is handled at application level. AIO thread-pool offload enabled when NGX_THREADS configured and pool available; synchronous fallback ensures reads always succeed even under degraded conditions.
 *
 * WHY: Single-segment reads provide simple byte-stream delivery for large transfers where integrity verification is handled at application level rather than protocol level. Unlike pgread's per-page checksum overhead, kXR_read returns raw bytes enabling clients to implement their own integrity checks or rely on transport-layer guarantees (TLS for davs:// downloads). Handle-based mode works on files already opened by current session enabling rapid reads without path resolution; path-based mode provides broader capability — read any file within export root regardless of whether it was previously opened by this session, enabling bulk access across multiple files without requiring individual open/close cycles for each target file.
 *
 * HOW: Two-phase read → validate read handle (xrootd_validate_read_handle for read-side validation) — parse offset/rlen from wire format (big-endian int64 + uint32_t) — cap rlen at XROOTD_READ_REQUEST_MAX if exceeds limit — perform pread(2) from file using AIO thread-pool or inline fallback (NGX_THREADS compile guard) — build chunked response chain via xrootd_build_chunked_chain() — queue response via xrootd_queue_response_chain() with databuf release callback. Access-log detail format "<offset>+rlen" tracks byte count transferred; throughput calculation uses bytes_read + session_bytes_written counters. */

#include "read.h"
#include "slice_read.h"

#include "../ngx_xrootd_module.h"
#include "../connection/budget.h"
#include "prefetch.h"

#include <sys/uio.h>   /* Phase 32 WS4: preadv2(RWF_NOWAIT) warm-cache probe */

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

ngx_int_t
xrootd_handle_read(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ClientReadRequest            *req = (ClientReadRequest *) ctx->hdr_buf;
    int                           idx;
    int64_t                       offset;
    size_t                        rlen;
    u_char                       *databuf;
    ssize_t                       nread;
    size_t                        data_total;
    u_char                       *send_base = NULL;
    ngx_chain_t                  *rsp_chain;
    ngx_stream_xrootd_srv_conf_t *rconf;
    int                           fd;
    ngx_int_t                     rc;

    /*
     * ClientReadRequest wire fields are big-endian.  The file handle is a 4-byte
     * blob but only byte 0 indexes our slot table (XROOTD_MAX_FILES <= 256); the
     * (unsigned char) cast prevents sign-extension of a high-bit handle byte into
     * a negative idx.  offset is a signed 64-bit network value (be64toh); rlen is
     * an unsigned 32-bit count (ntohl) — the explicit (uint32_t) casts keep the
     * conversions width-exact before widening to size_t on 64-bit hosts.
     */
    idx = (int) (unsigned char) req->fhandle[0];
    offset = (int64_t) be64toh((uint64_t) req->offset);
    rlen = (size_t) (uint32_t) ntohl((uint32_t) req->rlen);

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

    /* Phase 26: slice-mode handles have no backing fd; serve from the slice
     * cache (filling missing slices from the origin and suspending if needed). */
    if (ctx->files[idx].slice_mode) {
        XROOTD_OP_OK(ctx, XROOTD_OP_READ);
        return xrootd_read_from_slices(ctx, c, rconf, idx,
                                       (off_t) offset, rlen);
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
        && (!c->ssl || xrootd_ktls_send_active(c)))
    {
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

    databuf = XROOTD_GET_SCRATCH(ctx, c, read_scratch, read_scratch_size, rlen);
    if (databuf == NULL) {
        return NGX_ERROR;
    }

    /* Charge the (possibly grown) scratch footprint to the budget now so a
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
            struct iovec iov;
            iov.iov_base = databuf;
            iov.iov_len  = rlen;
            warm = preadv2(fd, &iov, 1, (off_t) offset, RWF_NOWAIT);
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
            nread = pread(fd, databuf, rlen, (off_t) offset);

        } else {
            /* No thread pool configured: read inline on the event loop. */
            nread = pread(fd, databuf, rlen, (off_t) offset);
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
        }
        return rc;
    }
}

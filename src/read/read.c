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

#include "../ngx_xrootd_module.h"
#include "prefetch.h"

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

    if (ctx->files[idx].is_regular && !c->ssl) {
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

    databuf = xrootd_get_read_scratch(ctx, c, rlen);
    if (databuf == NULL) {
        return NGX_ERROR;
    }

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

    if (rconf->common.thread_pool != NULL) {
        ngx_thread_task_t *task;
        xrootd_read_aio_t *t;
        ngx_flag_t         posted;

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

        task->handler = xrootd_read_aio_thread;
        task->event.handler = xrootd_read_aio_done;
        task->event.data = task;

        (void) xrootd_aio_post_task(ctx, c, rconf->common.thread_pool, task,
                                    "xrootd: thread_task_post failed, sync read fallback",
                                    &posted);
        if (posted) {
            return NGX_OK;
        }
    }

    nread = pread(fd, databuf, rlen, (off_t) offset);
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

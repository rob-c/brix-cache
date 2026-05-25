#include "cache_internal.h"
#include "writethrough_metrics.h"


#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ---- Origin path derivation from local filesystem path ----

 * WHAT: Translates a local cache filesystem path into the corresponding origin XRootD
 *       server path by stripping either the cache_root or xrootd_root prefix. Returns
 *       NGX_OK with the derived origin_path, or NGX_ERROR if neither prefix matches.

 * WHY: Write-through flush needs to know where on the origin server to write back data.
 *       The local file lives under cache_root (or root in non-cache mode), but the origin
 *       server expects a path relative to its own root. This function computes that mapping.

 * HOW: 1) Try cache_root prefix — strip it, return remainder as origin_path;
 *      2) If no match, try xrootd_root prefix — same logic;
 *      3) If neither matches → NGX_ERROR (file not in managed namespace).
 */
static ngx_int_t
xrootd_wt_origin_path_from_local(ngx_stream_xrootd_srv_conf_t *conf,
    const char *local_path, char *origin_path, size_t origin_path_size)
{
    const ngx_str_t *prefixes[2];
    ngx_uint_t       i;

    if (local_path == NULL || origin_path == NULL || origin_path_size < 2) {
        return NGX_ERROR;
    }

    prefixes[0] = &conf->cache_root;
    prefixes[1] = &conf->common.root;

    for (i = 0; i < 2; i++) {
        const ngx_str_t *prefix = prefixes[i];
        size_t           plen;
        const char      *rel;

        if (prefix == NULL || prefix->data == NULL || prefix->len == 0) {
            continue;
        }

        plen = prefix->len;
        while (plen > 1 && prefix->data[plen - 1] == '/') {
            plen--;
        }

        if (ngx_strncmp((u_char *) local_path, prefix->data, plen) != 0) {
            continue;
        }

        if (plen == 1 && prefix->data[0] == '/') {
            if (ngx_strlen(local_path) + 1 > origin_path_size) {
                return NGX_ERROR;
            }
            ngx_cpystrn((u_char *) origin_path, (u_char *) local_path,
                        origin_path_size);
            return NGX_OK;
        }

        rel = local_path + plen;
        if (*rel == '\0') {
            ngx_cpystrn((u_char *) origin_path, (u_char *) "/",
                        origin_path_size);
            return NGX_OK;
        }

        if (*rel == '/') {
            if (ngx_strlen(rel) + 1 > origin_path_size) {
                return NGX_ERROR;
            }
            ngx_cpystrn((u_char *) origin_path, (u_char *) rel,
                        origin_path_size);
            return NGX_OK;
        }

        continue;
    }

    return NGX_ERROR;
}

/* ---- Error propagation from fill operation to flush task ----

 * WHAT: Copies error fields (result, xrd_error, sys_errno, err_msg) from a
 *       xrootd_cache_fill_t structure into the caller's xrootd_wt_flush_t.

 * WHY: The write-through flush uses cache_fill_t internally to perform origin-side
 *       I/O. When that operation fails, this helper normalizes the error into the
 *       wt structure so the public API (xrootd_wt_flush_sync_handle / flush_on_close)
 *       can report it consistently.

 * HOW: Direct field copy — result set to NGX_ERROR; xrd_error from fill or default
 *      kXR_ServerError; sys_errno and err_msg copied verbatim via ngx_cpystrn.
 */
static void
xrootd_wt_copy_error(xrootd_wt_flush_t *wt, xrootd_cache_fill_t *fill)
{
    wt->result = NGX_ERROR;
    wt->xrd_error = fill->xrd_error ? fill->xrd_error : kXR_ServerError;
    wt->sys_errno = fill->sys_errno;
    ngx_cpystrn((u_char *) wt->err_msg,
                (u_char *) (fill->err_msg[0] ? fill->err_msg
                                              : "write-through flush failed"),
                sizeof(wt->err_msg));
}

/* ---- Flush task initialization and validation ----

 * WHAT: Validates the flush request parameters (file index, dirty offset, path)
 *       initializes an xrootd_wt_flush_t structure with configuration, logging context,
 *       mode bits, local/origin paths. Returns NGX_DECLINED if no dirty data needs flushing.
 *       NGX_OK on success, NGX_ERROR if validation or origin-path derivation fails.

 * WHY: Both sync and async flush entry points (xrootd_wt_flush_sync_handle /
 *       xrootd_wt_flush_on_close) share this initialization logic. Centralizing it avoids
 *       duplication and ensures consistent validation before the actual flush runs.

 * HOW: 1) Zero-fill wt structure;
 *      2) Validate idx range, fd >= 0, wt_enabled flag, dirty offset >= 0 → NGX_DECLINED if any fail;
 *      3) Copy conf, log, mode_bits, local_path;
 *      4) Derive origin path via xrootd_wt_origin_path_from_local — error here → NGX_ERROR.
 */
static ngx_int_t
xrootd_wt_init_task(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, int idx, const char *local_path,
    xrootd_wt_flush_t *wt)
{
    const char *path;

    ngx_memzero(wt, sizeof(*wt));

    if (idx < 0 || idx >= XROOTD_MAX_FILES
        || ctx->files[idx].fd < 0
        || !ctx->files[idx].wt_enabled
        || ctx->files[idx].wt_dirty_offset < 0)
    {
        return NGX_DECLINED;
    }

    path = (local_path != NULL) ? local_path : ctx->files[idx].path;
    if (path == NULL || path[0] == '\0') {
        return NGX_ERROR;
    }

    wt->conf = conf;
    wt->log = c->log;
    wt->metrics = (ctx != NULL) ? ctx->metrics : NULL;
    wt->mode_bits = ctx->files[idx].wt_mode_bits;
    wt->result = NGX_OK;

    ngx_cpystrn((u_char *) wt->local_path, (u_char *) path,
                sizeof(wt->local_path));

    if (xrootd_wt_origin_path_from_local(conf, path, wt->origin_path,
                                         sizeof(wt->origin_path))
        != NGX_OK)
    {
        ngx_cpystrn((u_char *) wt->err_msg,
                    (u_char *) "write-through origin path derivation failed",
                    sizeof(wt->err_msg));
        wt->xrd_error = kXR_ArgInvalid;
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* ---- Complete write-through flush cycle: connect → chunked pread + origin_write → truncate/sync/close ----

 * WHAT: Executes the full write-back of dirty cached data to the origin XRootD server.
 *       Connects to origin → opens a writable handle on origin_path → reads local file in chunks via
 *       pread → writes each chunk via xrootd_cache_origin_write_chunk → truncates + syncs + closes.
 *       Sets wt->result = NGX_OK on success, or propagates error via xrootd_wt_copy_error on failure.

 * WHY: This is the core flush engine. Both sync and async paths call it after task initialization.
 *       It handles all origin-side I/O (connect, bootstrap, open-write, chunked write, truncate/sync),
 *       local file reads (open + pread loop), buffer allocation, and cleanup on both success and failure.

 * HOW: 1) Validate host/port configured; early exit if missing;
 *      2) Open local file O_RDONLY, fstat to get size;
 *      3) Connect origin → bootstrap login → open writable handle (mode_bits);
 *      4) Chunked pread loop: read XROOTD_CACHE_FETCH_CHUNK bytes, write_chunk each chunk;
 *      5) Truncate to st.st_size + sync on origin; close all handles;
 *      6) On any failure → goto failed: close handles, copy error into wt.
 */
static void
xrootd_wt_run_flush(xrootd_wt_flush_t *wt)
{
    xrootd_cache_fill_t        fill;
    xrootd_cache_origin_conn_t oc;
    const ngx_str_t           *host;
    uint16_t                   port;
    u_char                     fhandle[XRD_FHANDLE_LEN];
    u_char                    *buf;
    struct stat                st;
    off_t                      offset;
    int                        fd;
    int                        opened_origin;

    wt->bytes_flushed = 0;

    ngx_memzero(&fill, sizeof(fill));
    fill.conf = wt->conf;
    fill.result = NGX_OK;
    ngx_cpystrn((u_char *) fill.clean_path, (u_char *) wt->origin_path,
                sizeof(fill.clean_path));

    host = wt->conf->wt_origin_host.len > 0 ? &wt->conf->wt_origin_host
                                            : &wt->conf->cache_origin_host;
    port = wt->conf->wt_origin_host.len > 0 ? wt->conf->wt_origin_port
                                            : wt->conf->cache_origin_port;

    if (host->len == 0 || port == 0) {
        fill.xrd_error = kXR_ServerError;
        ngx_cpystrn((u_char *) fill.err_msg,
                    (u_char *) "write-through origin not configured",
                    sizeof(fill.err_msg));
        xrootd_wt_copy_error(wt, &fill);
        return;
    }

    fd = open(wt->local_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fill.sys_errno = errno;
        fill.xrd_error = kXR_IOError;
        ngx_cpystrn((u_char *) fill.err_msg,
                    (u_char *) "write-through local open failed",
                    sizeof(fill.err_msg));
        xrootd_wt_copy_error(wt, &fill);
        return;
    }

    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        fill.sys_errno = errno;
        fill.xrd_error = kXR_IOError;
        ngx_cpystrn((u_char *) fill.err_msg,
                    (u_char *) "write-through local file invalid",
                    sizeof(fill.err_msg));
        close(fd);
        xrootd_wt_copy_error(wt, &fill);
        return;
    }

    oc.fd = -1;
    oc.ssl_ctx = NULL;
    oc.ssl = NULL;
    opened_origin = 0;
    buf = NULL;

    if (xrootd_cache_origin_connect_addr(&fill, &oc, host, port) != 0
        || xrootd_cache_origin_bootstrap(&fill, &oc) != 0
        || xrootd_cache_origin_open_write(&fill, &oc, wt->origin_path,
                                          wt->mode_bits, fhandle) != 0)
    {
        goto failed;
    }
    opened_origin = 1;

    buf = malloc(XROOTD_CACHE_FETCH_CHUNK);
    if (buf == NULL) {
        xrootd_cache_set_error(&fill, kXR_NoMemory, 0,
                               "write-through buffer allocation failed");
        goto failed;
    }

    offset = 0;
    while (offset < st.st_size) {
        size_t  want;
        ssize_t nread;

        want = (size_t) (st.st_size - offset);
        if (want > XROOTD_CACHE_FETCH_CHUNK) {
            want = XROOTD_CACHE_FETCH_CHUNK;
        }

        nread = pread(fd, buf, want, offset);
        if (nread < 0) {
            xrootd_cache_set_error(&fill, kXR_IOError, errno,
                                   "write-through local read failed");
            goto failed;
        }
        if (nread == 0) {
            xrootd_cache_set_error(&fill, kXR_IOError, 0,
                                   "write-through local file changed during flush");
            goto failed;
        }

        if (xrootd_cache_origin_write_chunk(&fill, &oc, fhandle,
                                            (uint64_t) offset, buf,
                                            (size_t) nread)
            != 0)
        {
            goto failed;
        }

        offset += nread;
    }

    if (xrootd_cache_origin_truncate(&fill, &oc, fhandle,
                                     (uint64_t) st.st_size) != 0
        || xrootd_cache_origin_sync(&fill, &oc, fhandle) != 0)
    {
        goto failed;
    }

    xrootd_cache_origin_close_file(&oc, fhandle);
    xrootd_cache_origin_close(&oc);
    free(buf);
    close(fd);
    wt->bytes_flushed = (st.st_size > 0) ? (size_t) st.st_size : 0;
    wt->result = NGX_OK;
    return;

failed:
    if (opened_origin) {
        xrootd_cache_origin_close_file(&oc, fhandle);
    }
    xrootd_cache_origin_close(&oc);
    free(buf);
    close(fd);
    xrootd_wt_copy_error(wt, &fill);
}

/* ---- Synchronous write-through flush at kXR_sync / kXR_close time ----

 * WHAT: Initializes a flush task, runs it synchronously via xrootd_wt_run_flush,
 *       and reports the result. On success clears wt_dirty_offset/wt_bytes_written.
 *       On failure logs error + access log line; optionally sends a kXR_status wire
 *       response with fail_status if non-zero.

 * WHY: Called on kXR_sync (explicit sync opcode) or kXR_close when dirty data exists.
 *       This is the synchronous flush path — blocks until origin write-back completes,
 *       then returns NGX_OK (flush succeeded or no-op due to NGX_DECLINED).

 * HOW: 1) Init task via xrootd_wt_init_task;
 *      2) If NGX_DECLINED → no dirty data, return NGX_OK;
 *      3) If NGX_ERROR → log error; send fail_status wire response if configured;
 *      4) Run flush synchronously (xrootd_wt_run_flush);
 *      5) On success: clear dirty offset/bytes, log access line; on failure: log + access.
 */
ngx_int_t
xrootd_wt_flush_sync_handle(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, int idx, const char *local_path,
    uint16_t fail_status)
{
    xrootd_wt_flush_t wt;
    ngx_int_t         rc;

    rc = xrootd_wt_init_task(ctx, c, conf, idx, local_path, &wt);
    if (rc == NGX_DECLINED) {
        return NGX_OK;
    }
    if (rc != NGX_OK) {
        xrootd_wt_metric_flush_error(ctx ? ctx->metrics : NULL);
        xrootd_dashboard_event_add(XROOTD_DASH_EVENT_IO, XROOTD_XFER_PROTO_ROOT,
                                   fail_status ? fail_status : kXR_ServerError,
                                   wt.err_msg[0] ? wt.err_msg
                                                 : "write-through flush init failed",
                                   local_path ? local_path : "-");
        if (fail_status != 0) {
            XROOTD_OP_ERR(ctx, XROOTD_OP_SYNC);
            return xrootd_send_error(ctx, c, fail_status,
                                     wt.err_msg[0] ? wt.err_msg
                                                   : "write-through flush failed");
        }
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "wt: %s",
                      wt.err_msg[0] ? wt.err_msg
                                    : "write-through flush init failed");
        return NGX_OK;
    }

    xrootd_wt_run_flush(&wt);
    if (wt.result == NGX_OK) {
        xrootd_wt_mark_clean(ctx, idx);
        xrootd_wt_metric_flush_success(wt.metrics, wt.bytes_flushed);
        xrootd_log_access(ctx, c, "WT", wt.origin_path, "flush",
                          1, 0, NULL, 0);
        return NGX_OK;
    }

    xrootd_wt_metric_flush_error(wt.metrics);
    xrootd_dashboard_event_add(XROOTD_DASH_EVENT_IO, XROOTD_XFER_PROTO_ROOT,
                               wt.xrd_error ? wt.xrd_error : kXR_ServerError,
                               wt.err_msg[0] ? wt.err_msg
                                             : "write-through flush failed",
                               wt.origin_path[0] ? wt.origin_path
                                                 : wt.local_path);

    ngx_log_error(NGX_LOG_ERR, c->log, wt.sys_errno,
                  "wt: flush failed local=\"%s\" origin=\"%s\": %s",
                  wt.local_path, wt.origin_path,
                  wt.err_msg[0] ? wt.err_msg : "write-through flush failed");
    xrootd_log_access(ctx, c, "WT", wt.origin_path, "flush",
                      0, wt.xrd_error ? wt.xrd_error : kXR_ServerError,
                      wt.err_msg[0] ? wt.err_msg : "write-through flush failed",
                      0);

    if (fail_status != 0) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_SYNC);
        return xrootd_send_error(ctx, c, fail_status,
                                 wt.err_msg[0] ? wt.err_msg
                                               : "write-through flush failed");
    }

    return NGX_OK;
}

/* ---- Write-through flush entry point at kXR_close — async or sync mode selection ----

 * WHAT: Initializes a flush task, then dispatches it either asynchronously (via nginx
 *       thread pool) or synchronously based on wt_mode configuration. On async success,
 *       sets wt_flush_pending flag and returns immediately; on fallback/post failure runs
 *       sync via xrootd_wt_flush_sync_handle.

 * WHY: Write-through flush can block for large files. When configured as async mode
 *       (XROOTD_WT_MODE_ASYNC) with a thread pool available, the flush runs off the event
 *       loop so the client connection stays responsive. Async failures fall back to sync.

 * HOW: 1) Init task via xrootd_wt_init_task;
 *      2) If NGX_DECLINED → no dirty data, return NGX_OK;
 *      3) If wt_mode == async + thread_pool available → allocate ngx_thread_task,
 *         memcpy wt into task->ctx, post handler=xrootd_wt_flush_thread;
 *      4) On post failure or sync mode → delegate to xrootd_wt_flush_sync_handle.
 */
ngx_int_t
xrootd_wt_flush_on_close(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, int idx, const char *local_path)
{
    xrootd_wt_flush_t     wt;
    ngx_thread_task_t    *task;
    ngx_int_t             rc;

    rc = xrootd_wt_init_task(ctx, c, conf, idx, local_path, &wt);
    if (rc == NGX_DECLINED) {
        return NGX_OK;
    }
    if (rc != NGX_OK) {
        xrootd_wt_metric_flush_error(ctx ? ctx->metrics : NULL);
        xrootd_dashboard_event_add(XROOTD_DASH_EVENT_IO, XROOTD_XFER_PROTO_ROOT,
                                   kXR_ServerError,
                                   wt.err_msg[0] ? wt.err_msg
                                                 : "write-through flush init failed",
                                   local_path ? local_path : "-");
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "wt: %s",
                      wt.err_msg[0] ? wt.err_msg
                                    : "write-through flush init failed");
        return NGX_OK;
    }

    if (conf->wt_mode == XROOTD_WT_MODE_ASYNC && conf->common.thread_pool != NULL) {
        task = ngx_calloc(sizeof(ngx_thread_task_t) + sizeof(xrootd_wt_flush_t),
                          c->log);
        if (task != NULL) {
            xrootd_wt_flush_t *async_wt;

            task->ctx = task + 1;
            async_wt = task->ctx;
            ngx_memcpy(async_wt, &wt, sizeof(wt));

            task->handler = xrootd_wt_flush_thread;
            task->event.handler = xrootd_wt_flush_done;
            task->event.data = task;

            if (ngx_thread_task_post(conf->common.thread_pool, task) == NGX_OK) {
                ctx->files[idx].wt_flush_pending = 1;
                xrootd_wt_metric_pending_inc(async_wt->metrics);
                xrootd_log_access(ctx, c, "WT", wt.origin_path, "async",
                                  1, 0, NULL, 0);
                return NGX_OK;
            }

            ngx_free(task);
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "wt: async flush post failed, falling back to sync");
        }
    }

    return xrootd_wt_flush_sync_handle(ctx, c, conf, idx, local_path, 0);
}

/* ---- nginx thread-pool worker callback for async write-through flush ----

 * WHAT: Entry point executed by the nginx thread pool when an async flush task is
 *       dispatched. Casts data to xrootd_wt_flush_t and delegates to xrootd_run_flush.

 * WHY: The async flush path (xrootd_wt_flush_on_close) allocates an ngx_thread_task
 *       with this handler. It runs in a worker thread, blocking on origin I/O while the
 *       event-loop stays free for other connections.

 * HOW: Single-line delegation — casts void* data → xrootd_wt_flush_t, calls run_flush.
 */
void
xrootd_wt_flush_thread(void *data, ngx_log_t *log)
{
    xrootd_wt_flush_t *wt = data;

    (void) log;
    xrootd_wt_run_flush(wt);
}

/* ---- Async flush completion callback — logs result, frees task ----

 * WHAT: Event-loop callback invoked when the nginx thread pool finishes an async flush
 *       task. Logs success or failure with local/origin paths and error message.
 *       Frees the allocated ngx_thread_task structure.

 * WHY: The async flush path (xrootd_wt_flush_on_close) posts a task with this event
 *       handler. When the worker thread completes xrootd_run_flush, the event-loop receives
 *       this callback to finalize logging and memory cleanup.

 * HOW: 1) Extract task from ev->data, wt from task->ctx;
 *      2) Log INFO on success (result == NGX_OK), ERROR on failure with sys_errno + err_msg;
 *      3) Free the task via ngx_free.
 */
void
xrootd_wt_flush_done(ngx_event_t *ev)
{
    ngx_thread_task_t *task = ev->data;
    xrootd_wt_flush_t *wt = task->ctx;

    xrootd_wt_metric_pending_dec(wt->metrics);

    if (wt->result == NGX_OK) {
        xrootd_wt_metric_flush_success(wt->metrics, wt->bytes_flushed);
        ngx_log_error(NGX_LOG_INFO, wt->log, 0,
                      "wt: async flush completed local=\"%s\" origin=\"%s\"",
                      wt->local_path, wt->origin_path);
    } else {
        xrootd_wt_metric_flush_error(wt->metrics);
        xrootd_dashboard_event_add(XROOTD_DASH_EVENT_IO, XROOTD_XFER_PROTO_ROOT,
                                   wt->xrd_error ? wt->xrd_error
                                                 : kXR_ServerError,
                                   wt->err_msg[0] ? wt->err_msg
                                                  : "write-through flush failed",
                                   wt->origin_path[0] ? wt->origin_path
                                                      : wt->local_path);
        ngx_log_error(NGX_LOG_ERR, wt->log, wt->sys_errno,
                      "wt: async flush failed local=\"%s\" origin=\"%s\": %s",
                      wt->local_path, wt->origin_path,
                      wt->err_msg[0] ? wt->err_msg
                                     : "write-through flush failed");
    }

    ngx_free(task);
}

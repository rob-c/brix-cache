/* ------------------------------------------------------------------ */
/* Write-Side Shared Helpers                                            */
/* ------------------------------------------------------------------ */

/*
 * common.c — shared helpers for write-side opcode handlers.
 *
 * Provides xrootd_try_post_write_aio() — AIO task setup and thread-pool
 * dispatch for kXR_write / kXR_pgwrite syscalls.
 *
 * Note: path-based write opcodes (mkdir, mv, rmdir, truncate) perform auth via
 * xrootd_auth_gate() directly; chmod/rm dispatch through the op-descriptor
 * table in op_table.c.  The former shared resolver
 * (xrootd_write_resolve_existing_path) was retired once those callers migrated
 * and has been removed.
 */
#include "ngx_xrootd_module.h"

ngx_int_t
xrootd_try_post_write_aio(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx,
    off_t offset, const u_char *data, size_t len, int64_t req_offset,
    ngx_uint_t is_pgwrite, u_char *payload_to_free, const char *fallback_log,
    ngx_flag_t *posted)
{
    ngx_stream_xrootd_srv_conf_t *conf;
    ngx_thread_task_t            *task;
    xrootd_write_aio_t           *t;

    *posted = 0;

    conf = ngx_stream_get_module_srv_conf((ngx_stream_session_t *) (c->data),
                                          ngx_stream_xrootd_module);
    if (conf->common.thread_pool == NULL) {
        return NGX_OK;
    }

    task = ngx_thread_task_alloc(c->pool, sizeof(xrootd_write_aio_t));
    if (task == NULL) {
        return NGX_ERROR;
    }

    t = task->ctx;
    t->c               = c;
    t->ctx             = ctx;
    t->conf            = conf;
    t->fd              = ctx->files[idx].fd;
    t->handle_idx      = idx;
    t->offset          = offset;
    t->data            = data;
    t->len             = len;
    t->req_offset      = req_offset;
    t->is_pgwrite      = is_pgwrite;
    t->nwritten        = -1;
    t->io_errno        = 0;
    t->payload_to_free = payload_to_free;
    t->streamid[0]     = ctx->cur_streamid[0];
    t->streamid[1]     = ctx->cur_streamid[1];
    ngx_cpystrn((u_char *) t->path,
                (u_char *) (ctx->files[idx].path != NULL
                             ? ctx->files[idx].path : "-"),
                sizeof(t->path));

    xrootd_task_bind(task, xrootd_write_aio_thread, xrootd_write_aio_done);

    return xrootd_aio_post_task(ctx, c, conf->common.thread_pool, task, fallback_log,
                                posted);
}
/* ---- WHY: Provides uniform thread-pool dispatch for write syscalls, enabling parallel disk I/O without blocking the main event loop during large file transfers. Detaches payload from ctx->payload_buf so the main thread can safely read next request headers while write happens in worker threads. The posted flag enables callers to distinguish between dispatched and fallback cases — dispatched=1 means completion callback handles response; dispatched=0 means caller must perform synchronous pwrite. ---- */

/* ---- HOW: Sets *posted=0 initially; retrieves conf via ngx_stream_get_module_srv_conf(); returns NGX_OK if thread_pool==NULL (no AIO configured). Allocates task struct with ngx_thread_task_alloc() — if OOM returns NGX_ERROR. Populates t=xrootd_write_aio_t context: c, ctx, conf, fd from files[idx], handle_idx, offset, data, len, req_offset, is_pgwrite, nwritten=-1, io_errno=0, payload_to_free, streamid copy, path copy via ngx_cpystrn(). Binds the worker + done callbacks via xrootd_task_bind(task, xrootd_write_aio_thread, xrootd_write_aio_done). Calls xrootd_aio_post_task() which sets posted=1 on success or 0 if queue full. Returns result from post_task call. */

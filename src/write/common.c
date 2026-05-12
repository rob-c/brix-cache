/*
 * common.c — shared helpers for write-side opcode handlers.
 *
 * Provides:
 *   xrootd_write_resolve_existing_path — path extraction + resolve + VO ACL
 *   xrootd_try_post_write_aio          — AIO task setup and dispatch
 */
#include "ngx_xrootd_module.h"

ngx_flag_t
xrootd_write_resolve_existing_path(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, const char *verb, ngx_uint_t op,
    const char *not_found_msg, uint32_t needed_privs, char *reqpath,
    size_t reqpathsz, char *resolved, size_t resolvedsz, ngx_int_t *rc)
{
    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        *rc = xrootd_send_error(ctx, c, kXR_ArgMissing, "no path given");
        return 0;
    }

    if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
                             reqpath, reqpathsz, 0)) {
        xrootd_log_access(ctx, c, verb, "-", "-",
                          0, kXR_ArgInvalid, "invalid path payload", 0);
        XROOTD_OP_ERR(ctx, op);
        *rc = xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                "invalid path payload");
        return 0;
    }

    if (!xrootd_resolve_path(c->log, &conf->root, reqpath,
                             resolved, resolvedsz)) {
        xrootd_log_access(ctx, c, verb, reqpath, "-",
                          0, kXR_NotFound, not_found_msg, 0);
        XROOTD_OP_ERR(ctx, op);
        *rc = xrootd_send_error(ctx, c, kXR_NotFound, not_found_msg);
        return 0;
    }

    if (xrootd_check_authdb(ctx, resolved, needed_privs) != NGX_OK) {
        xrootd_log_access(ctx, c, verb, resolved, "-",
                          0, kXR_NotAuthorized, "authdb denied", 0);
        XROOTD_OP_ERR(ctx, op);
        *rc = xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                "authdb denied");
        return 0;
    }

    if (xrootd_check_vo_acl(c->log, resolved, conf->vo_rules,
                            ctx->vo_list) != NGX_OK) {
        xrootd_log_access(ctx, c, verb, resolved, "-",
                          0, kXR_NotAuthorized, "VO not authorized", 0);
        XROOTD_OP_ERR(ctx, op);
        *rc = xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                "VO not authorized");
        return 0;
    }

    return 1;
}

#if (NGX_THREADS)

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
    if (conf->thread_pool == NULL) {
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

    task->handler       = xrootd_write_aio_thread;
    task->event.handler = xrootd_write_aio_done;
    task->event.data    = task;

    return xrootd_aio_post_task(ctx, c, conf->thread_pool, task, fallback_log,
                                posted);
}

#endif /* NGX_THREADS */

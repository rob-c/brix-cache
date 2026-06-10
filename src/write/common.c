/* ------------------------------------------------------------------ */
/* Write-Side Shared Helpers                                            */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file provides shared helper functions for write-side opcode handlers (mkdir.c, mv.c, chmod.c, rm.c, rmdir.c, truncate.c). Two primary helpers exist: xrootd_write_resolve_existing_path() — path extraction + canonical resolution + VO ACL + authdb gate; and xrootd_try_post_write_aio() — AIO task setup and dispatch to nginx thread pool. These helpers reduce code duplication across write handlers by providing common validation, resolution, and async I/O patterns.
 *
 * WHY: Write-side opcodes share identical validation patterns (path extraction → canonical resolution → authdb check → VO ACL check) but differ in their final syscall behavior (mkdir vs rename vs chmod etc.). Shared helpers eliminate code duplication while ensuring consistent security gate enforcement across all mutating operations. AIO helper provides uniform thread-pool dispatch pattern for write syscalls, enabling parallel disk I/O without blocking the main event loop during large file transfers.
 *
 * HOW: xrootd_write_resolve_existing_path() performs four-phase validation → payload extraction (returns error if missing) — path sanitization (returns error if malformed) — canonical resolution via xrootd_resolve_path() (returns error if not found) — authdb gate check (returns error if denied) — VO ACL evaluation (returns error if unauthorized) — return 1 on success, 0 with rc=error response on failure. xrootd_try_post_write_aio() performs three-phase dispatch → thread pool availability check (NGX_THREADS compile guard) — task struct allocation + payload detachment from ctx->payload_buf — ngx_thread_task_post to worker pool — return posted=1 if dispatched, posted=0 if fallback required. */

/* ------------------------------------------------------------------ */
/* Section: Path Resolution and Security Gates                            */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_write_resolve_existing_path() provides a unified validation pipeline for write-side opcodes requiring path-based operations on existing filesystem paths. Performs four-phase validation: payload extraction, path sanitization, canonical resolution via xrootd_resolve_path(), authdb gate check, and VO ACL evaluation. Returns 1 (ngx_flag_t true) on success, 0 with *rc set to error response on failure.
 *
 * WHY: Eliminates code duplication across write handlers while ensuring consistent security gate enforcement. All mutating operations (mkdir, mv, chmod, rm, rmdir, truncate) share identical validation requirements — path must exist within export root, client must be authenticated, authdb/VOMS ACL must permit the operation type. Providing a single shared function ensures all opcodes use identical security patterns without risk of inconsistency or oversight in individual handlers. */

/* ------------------------------------------------------------------ */
/* Section: Path Resolution Pipeline                                        */
/* ------------------------------------------------------------------ */
/*
 * WHAT: Four-phase validation pipeline for existing path write operations. Phase 1 (payload extraction): returns kXR_ArgMissing error if ctx->payload==NULL || ctx->cur_dlen==0 — ensures client provides valid path specification. Phase 2 (path sanitization): uses xrootd_extract_path() to extract and clean the path from payload, rejecting malformed payloads with kXR_ArgInvalid. Phase 3 (canonical resolution): calls xrootd_resolve_path() to canonicalize and confine the path within conf->common.root export boundary — returns kXR_NotFound error if path cannot be resolved or is outside root. Phase 4 (security gates): performs authdb check with needed_privs parameter, then VO ACL evaluation using conf->vo_rules + ctx->vo_list — both return kXR_NotAuthorized on denial.
 *
 * WHY: Sequential validation ensures each phase fails fast before proceeding to subsequent phases, minimizing unnecessary processing when early checks fail. Authdb and VO ACL gates use the same shared functions as read opcodes (src/path/authdb.c, src/path/acl.c) ensuring consistent authorization enforcement across all operation types. The needed_privs parameter allows callers to specify different privilege levels for different operations (XROOTD_AUTH_UPDATE for chmod/truncate vs XROOTD_AUTH_DELETE for rm/rmdir). */

/* ---- Function: xrootd_write_resolve_existing_path() ----
 *
 * WHAT: Provides a unified validation pipeline for write-side opcodes requiring path-based operations on existing filesystem paths. Performs four-phase validation: payload extraction (kXR_ArgMissing if missing), path sanitization (kXR_ArgInvalid if malformed), canonical resolution via xrootd_resolve_path() (kXR_NotFound if unresolved), authdb gate check with needed_privs parameter (kXR_NotAuthorized if denied), VO ACL evaluation using conf->vo_rules + ctx->vo_list (kXR_NotAuthorized if unauthorized). Returns 1 (ngx_flag_t true) on success, 0 with *rc set to error response on failure. Used by mkdir.c, mv.c, chmod.c, rm.c, rmdir.c, truncate.c handlers.
 *
 * WHY: Eliminates code duplication across write handlers while ensuring consistent security gate enforcement. All mutating operations (mkdir, mv, chmod, rm, rmdir, truncate) share identical validation requirements — path must exist within export root, client must be authenticated, authdb/VOMS ACL must permit the operation type. Providing a single shared function ensures all opcodes use identical security patterns without risk of inconsistency or oversight in individual handlers.
 *
 * HOW: Four-phase validation → payload extraction (returns error if missing) — path sanitization (returns error if malformed) — canonical resolution via xrootd_resolve_path() (returns error if not found) — authdb gate check with needed_privs parameter (returns error if denied) — VO ACL evaluation using conf->vo_rules + ctx->vo_list (returns error if unauthorized) — return 1 on success, 0 with rc=error response on failure. */

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
                             reqpath, reqpathsz, 1)) {
        xrootd_log_access(ctx, c, verb, "-", "-",
                          0, kXR_ArgInvalid, "invalid path payload", 0);
        XROOTD_OP_ERR(ctx, op);
        *rc = xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                "invalid path payload");
        return 0;
    }

    if (xrootd_count_path_depth(reqpath) != NGX_OK) {
        xrootd_log_access(ctx, c, verb, reqpath, "-",
                          0, kXR_ArgInvalid,
                          "path exceeds maximum depth", 0);
        XROOTD_OP_ERR(ctx, op);
        *rc = xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                "path exceeds maximum depth");
        return 0;
    }

    if (!xrootd_resolve_path(c->log, &conf->common.root, reqpath,
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

    if (xrootd_check_vo_acl_identity(c->log, resolved, conf->vo_rules,
                                     ctx->identity) != NGX_OK) {
        xrootd_log_access(ctx, c, verb, resolved, "-",
                          0, kXR_NotAuthorized, "VO not authorized", 0);
        XROOTD_OP_ERR(ctx, op);
        *rc = xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                "VO not authorized");
        return 0;
    }

    return 1;
}


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

    task->handler       = xrootd_write_aio_thread;
    task->event.handler = xrootd_write_aio_done;
    task->event.data    = task;

    return xrootd_aio_post_task(ctx, c, conf->common.thread_pool, task, fallback_log,
                                posted);
}
/* ---- WHY: Provides uniform thread-pool dispatch for write syscalls, enabling parallel disk I/O without blocking the main event loop during large file transfers. Detaches payload from ctx->payload_buf so the main thread can safely read next request headers while write happens in worker threads. The posted flag enables callers to distinguish between dispatched and fallback cases — dispatched=1 means completion callback handles response; dispatched=0 means caller must perform synchronous pwrite. ---- */

/* ---- HOW: Sets *posted=0 initially; retrieves conf via ngx_stream_get_module_srv_conf(); returns NGX_OK if thread_pool==NULL (no AIO configured). Allocates task struct with ngx_thread_task_alloc() — if OOM returns NGX_ERROR. Populates t=xrootd_write_aio_t context: c, ctx, conf, fd from files[idx], handle_idx, offset, data, len, req_offset, is_pgwrite, nwritten=-1, io_errno=0, payload_to_free, streamid copy, path copy via ngx_cpystrn(). Sets task->handler=xrootd_write_aio_thread (worker), task->event.handler=xrootd_write_aio_done (main loop callback). Calls xrootd_aio_post_task() which sets posted=1 on success or 0 if queue full. Returns result from post_task call. */

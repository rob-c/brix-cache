#include "fd_table.h"
#include "../session/registry.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

/*
 * xrootd_alloc_fhandle — find the first free handle slot.
 *
 * The returned index is used as the on-wire fhandle byte sent to the client.
 * It is therefore bounded by XROOTD_MAX_FILES; the wire format reserves only
 * one byte for the handle value.
 *
 * Primary handles are owned by the TCP session that opened them.  kXR_bind
 * secondaries are the one exception: they may read a primary-published handle,
 * materializing a local fd from shared metadata when the first read arrives.
 */
int
xrootd_alloc_fhandle(xrootd_ctx_t *ctx)
{
    int handle_index;

    /*
     * The XRootD wire handle stores this slot number in one byte.  Keep all
     * allocation/validation paths using the same bounded table.
     */
    for (handle_index = 0; handle_index < XROOTD_MAX_FILES; handle_index++) {
        if (ctx->files[handle_index].fd < 0) {
            return handle_index;
        }
    }

    return -1;
}

/*
 * xrootd_set_fhandle_path — store a canonical path for the given slot.
 *
 * The path is heap-allocated via ngx_alloc() — NOT pool-allocated — so that
 * it survives past the request that issued the kXR_open.  The path must be
 * freed with ngx_free() (done by xrootd_free_fhandle).
 *
 * Do NOT free() this buffer directly; the buffer is ngx_alloc-managed.
 */
ngx_int_t
xrootd_set_fhandle_path(xrootd_ctx_t *ctx, ngx_connection_t *c,
    int handle_index, const char *path)
{
    char   *path_copy;
    size_t  path_bytes;

    if (handle_index < 0 || handle_index >= XROOTD_MAX_FILES
        || path == NULL)
    {
        return NGX_ERROR;
    }

    path_bytes = ngx_strlen(path) + 1;
    path_copy = ngx_alloc(path_bytes, c->log);
    if (path_copy == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(path_copy, path, path_bytes);

    if (ctx->files[handle_index].path != NULL) {
        ngx_free(ctx->files[handle_index].path);
    }

    ctx->files[handle_index].path = path_copy;
    return NGX_OK;
}

static ngx_flag_t
xrootd_local_file_matches_shared_handle(const xrootd_file_t *file,
    const xrootd_shared_handle_entry_t *shared)
{
    if (file->fd < 0 || file->path == NULL || !file->readable
        || !shared->readable)
    {
        return 0;
    }

    return file->device == shared->device
           && file->inode == shared->inode
           && ngx_strcmp(file->path, shared->path) == 0;
}

static ngx_int_t
xrootd_reopen_bound_read_handle(xrootd_ctx_t *ctx, ngx_connection_t *c,
    int handle_index, const xrootd_shared_handle_entry_t *shared)
{
    ngx_stream_xrootd_srv_conf_t *conf;
    xrootd_file_t                *file;
    struct stat                   st;
    int                           fd;
    int                           open_flags;

    if (!shared->readable || shared->path[0] == '\0') {
        return NGX_DECLINED;
    }

    conf = ngx_stream_get_module_srv_conf(ctx->session,
                                          ngx_stream_xrootd_module);
    if (conf == NULL) {
        return NGX_ERROR;
    }

    /*
     * The primary published a canonical, ACL-checked path.  The secondary
     * still opens it with the same confinement helper so a stale or corrupted
     * shared-memory entry cannot escape the configured export root.
     */
    open_flags = O_RDONLY | O_NOCTTY | O_CLOEXEC;
    if (shared->from_cache) {
        fd = open(shared->path, open_flags);
    } else {
        fd = xrootd_open_confined(c->log, &conf->root, shared->path,
                                  open_flags, 0);
    }

    if (fd < 0) {
        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, errno,
                       "xrootd: bound handle reopen failed handle=%d path=%s",
                       handle_index, shared->path);
        return NGX_DECLINED;
    }

    if (fstat(fd, &st) != 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, errno,
                       "xrootd: fstat failed on bound handle=%d",
                       handle_index);
        close(fd);
        return NGX_DECLINED;
    }

    if (st.st_dev != shared->device || st.st_ino != shared->inode) {
        close(fd);
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "xrootd: bound handle=%d path changed before reopen",
                       handle_index);
        return NGX_DECLINED;
    }

    file = &ctx->files[handle_index];
    file->fd             = fd;
    file->readable       = 1;
    file->writable       = 0;
    file->from_cache     = shared->from_cache ? 1 : 0;
    file->is_regular     = S_ISREG(st.st_mode) ? 1 : 0;
    file->device         = st.st_dev;
    file->inode          = st.st_ino;
    file->cached_size    = (off_t) st.st_size;
    file->read_last_end  = -1;
    file->read_ahead_end = 0;
    file->bytes_read     = 0;
    file->bytes_written  = 0;
    file->open_time      = ngx_current_msec;

    if (xrootd_set_fhandle_path(ctx, c, handle_index, shared->path)
        != NGX_OK)
    {
        xrootd_free_fhandle(ctx, handle_index);
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: bound handle=%d reopened shared path=%s",
                   handle_index, shared->path);
    return NGX_OK;
}

ngx_int_t
xrootd_ensure_read_handle(xrootd_ctx_t *ctx, ngx_connection_t *c,
    int handle_index)
{
    xrootd_shared_handle_entry_t shared;

    if (handle_index < 0 || handle_index >= XROOTD_MAX_FILES) {
        return NGX_DECLINED;
    }

    if (!ctx->is_bound) {
        return ctx->files[handle_index].fd >= 0 ? NGX_OK : NGX_DECLINED;
    }

    /*
     * A bound stream only follows the primary session's current handle table.
     * Re-check the shared slot on every read request so a primary close, reuse,
     * or session teardown immediately revokes the secondary's local fd.
     */
    if (!xrootd_session_handle_lookup(ctx->bound_sessid, handle_index,
                                      &shared))
    {
        if (ctx->files[handle_index].fd >= 0) {
            xrootd_free_fhandle(ctx, handle_index);
        }
        return NGX_DECLINED;
    }

    if (xrootd_local_file_matches_shared_handle(&ctx->files[handle_index],
                                                &shared))
    {
        return NGX_OK;
    }

    if (ctx->files[handle_index].fd >= 0
        || ctx->files[handle_index].path != NULL)
    {
        xrootd_free_fhandle(ctx, handle_index);
    }

    return xrootd_reopen_bound_read_handle(ctx, c, handle_index, &shared);
}

void
xrootd_free_fhandle(xrootd_ctx_t *ctx, int handle_index)
{
    xrootd_file_t *file;

    if (handle_index < 0 || handle_index >= XROOTD_MAX_FILES) {
        return;
    }

    file = &ctx->files[handle_index];

    if (!ctx->is_bound && file->fd >= 0) {
        xrootd_session_handle_unpublish(ctx->sessid, handle_index);
    }

    if (file->fd >= 0) {
        close(file->fd);
    }

    /*
     * Checkpoint files are temporary rollback state owned by the handle.
     * Normal close/free removes any abandoned checkpoint path.
     */
    if (file->ckp_path != NULL) {
        (void) unlink(file->ckp_path);
        ngx_free(file->ckp_path);
    }

    /*
     * POSC cleanup: if posc_final_path is still set here the session ended
     * without a clean kXR_close (disconnect, error, or abandon).  Unlink the
     * temp staging file so partial writes are not left on disk.
     */
    if (file->posc_final_path != NULL) {
        if (file->path != NULL) {
            (void) unlink(file->path);
        }
        ngx_free(file->posc_final_path);
    }

    if (file->path != NULL) {
        ngx_free(file->path);
    }

    file->fd             = -1;
    file->readable       = 0;
    file->writable       = 0;
    file->from_cache     = 0;
    file->bytes_read     = 0;
    file->bytes_written  = 0;
    file->open_time      = 0;
    file->path           = NULL;
    file->is_regular     = 0;
    file->device         = 0;
    file->inode          = 0;
    file->cached_size    = 0;
    file->read_last_end  = -1;
    file->read_ahead_end = 0;
    file->ckp_path       = NULL;
    file->ckp_size       = 0;
    file->posc_final_path = NULL;
    file->tpc_destination = 0;
    file->tpc_armed       = 0;
    file->tpc_started     = 0;
    file->tpc_done        = 0;
    file->tpc_key[0]      = '\0';
    file->tpc_org[0]      = '\0';
    file->tpc_src_host[0] = '\0';
    file->tpc_src_port    = 0;
    file->tpc_src_path[0] = '\0';
}

void
xrootd_close_all_files(xrootd_ctx_t *ctx)
{
    int handle_index;

    for (handle_index = 0; handle_index < XROOTD_MAX_FILES; handle_index++) {
        xrootd_free_fhandle(ctx, handle_index);
    }
}

ngx_flag_t
xrootd_validate_file_handle(xrootd_ctx_t *ctx, ngx_connection_t *c,
    int handle_index, const char *verb, ngx_uint_t op, ngx_int_t *rc)
{
    if (handle_index < 0 || handle_index >= XROOTD_MAX_FILES
        || ctx->files[handle_index].fd < 0)
    {
        xrootd_log_access(ctx, c, verb, "-", "-",
                          0, kXR_FileNotOpen, "invalid file handle", 0);
        XROOTD_OP_ERR(ctx, op);
        *rc = xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                "invalid file handle");
        return 0;
    }

    return 1;
}

ngx_flag_t
xrootd_validate_read_handle(xrootd_ctx_t *ctx, ngx_connection_t *c,
    int handle_index, const char *verb, ngx_uint_t op, ngx_int_t *rc)
{
    ngx_int_t ensure_rc;

    ensure_rc = xrootd_ensure_read_handle(ctx, c, handle_index);
    if (ensure_rc != NGX_OK) {
        if (ensure_rc == NGX_ERROR) {
            xrootd_log_access(ctx, c, verb, "-", "-",
                              0, kXR_ServerError,
                              "could not prepare file handle", 0);
            XROOTD_OP_ERR(ctx, op);
            *rc = xrootd_send_error(ctx, c, kXR_ServerError,
                                    "could not prepare file handle");
            return 0;
        }

        xrootd_log_access(ctx, c, verb, "-", "-",
                          0, kXR_FileNotOpen, "invalid file handle", 0);
        XROOTD_OP_ERR(ctx, op);
        *rc = xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                "invalid file handle");
        return 0;
    }

    /*
     * Authorization and path checks happened at open time.  Later handle I/O
     * verifies the capability bit recorded on the handle rather than resolving
     * the path again on every read.
     */
    if (!ctx->files[handle_index].readable) {
        xrootd_log_access(ctx, c, verb, ctx->files[handle_index].path, "-",
                          0, kXR_NotAuthorized,
                          "file not open for reading", 0);
        XROOTD_OP_ERR(ctx, op);
        *rc = xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                "file not open for reading");
        return 0;
    }

    return 1;
}

ngx_flag_t
xrootd_validate_write_handle(xrootd_ctx_t *ctx, ngx_connection_t *c,
    int handle_index, const char *verb, ngx_uint_t op, ngx_int_t *rc)
{
    if (!xrootd_validate_file_handle(ctx, c, handle_index, verb, op, rc)) {
        return 0;
    }

    if (!ctx->files[handle_index].writable) {
        xrootd_log_access(ctx, c, verb, ctx->files[handle_index].path, "-",
                          0, kXR_NotAuthorized, "file not open for writing",
                          0);
        XROOTD_OP_ERR(ctx, op);
        *rc = xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                "file not open for writing");
        return 0;
    }

    return 1;
}

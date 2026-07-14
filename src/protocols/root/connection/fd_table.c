#include "fd_table.h"
#include "fs/vfs/vfs.h"   /* brix_vfs_open_fd_at (handle-table confined open) */
#include "protocols/root/session/registry.h"
#include "fs/cache/writethrough_metrics.h"
#include "protocols/root/write/pgw_fob.h"
#include "fs/backend/csi_tagstore.h"
#include "protocols/root/zip/zip_member.h"   /* brix_zip_handle_cleanup (frees inflate stream) */
#include "protocols/ssi/ssi.h"          /* brix_ssi_handle_cleanup (timers + registry) */

#include <errno.h>
#include <string.h>
#include <unistd.h>

/* brix_alloc_fhandle — return the first free slot (fd < 0) in ctx->files; the
 * index becomes the one-byte on-wire fhandle, so it is bounded by BRIX_MAX_FILES.
 * -1 when all slots are occupied. Single-owner per connection (event thread, no
 * locking); a slot is only reused once its fd is closed. */
int
brix_alloc_fhandle(brix_ctx_t *ctx)
{
    int handle_index;

    /*
     * The XRootD wire handle stores this slot number in one byte.  Keep all
     * allocation/validation paths using the same bounded table.
     */
    for (handle_index = 0; handle_index < BRIX_MAX_FILES; handle_index++) {
        if (ctx->files[handle_index].fd < 0) {
            return handle_index;
        }
    }

    return -1;
}

/* brix_ctx_has_open_file — 1 if any handle slot is occupied (fd >= 0), else 0.
 * Used by the recv-loop drain gate: a connection with an open file is mid-transfer
 * (a streaming read parked between kXR_read chunks), so a draining worker must let
 * it finish rather than fast-teardown at the request boundary — a forced mid-stream
 * reconnect loses the in-flight fill. Single-owner per connection (event thread). */
int
brix_ctx_has_open_file(const brix_ctx_t *ctx)
{
    int handle_index;

    for (handle_index = 0; handle_index < BRIX_MAX_FILES; handle_index++) {
        if (ctx->files[handle_index].fd >= 0) {
            return 1;
        }
    }

    return 0;
}

/* brix_set_fhandle_path — store a heap copy (ngx_alloc, NOT pool, so it outlives
 * the kXR_open request) of the canonical path in the slot, freeing any prior path
 * first; brix_free_fhandle owns the free. NGX_OK, or NGX_ERROR on bad bounds or
 * allocation failure. Heap (not pool) avoids fragmentation across open/close cycles. */
ngx_int_t
brix_set_fhandle_path(brix_ctx_t *ctx, ngx_connection_t *c,
    int handle_index, const char *path)
{
    char   *path_copy;
    size_t  path_bytes;

    if (handle_index < 0 || handle_index >= BRIX_MAX_FILES
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

/* brix_local_file_matches_shared_handle — 1 iff the local fd still corresponds to
 * the primary's published handle (fd valid + readable, same device/inode/path), used
 * by brix_ensure_read_handle to decide whether a bound secondary must reopen. */

static ngx_flag_t
brix_local_file_matches_shared_handle(const brix_file_t *file,
    const brix_shared_handle_entry_t *shared)
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

/* brix_reopen_bound_read_handle — reopen a bound secondary's stale fd to match the
 * primary's shared entry via a cache-aware confined open (O_RDONLY|O_NOCTTY|O_CLOEXEC),
 * refreshing all file metadata from the fresh fstat; NGX_DECLINED (revoke) if the
 * filesystem object's device/inode changed. */

static ngx_int_t
brix_reopen_bound_read_handle(brix_ctx_t *ctx, ngx_connection_t *c,
    int handle_index, const brix_shared_handle_entry_t *shared)
{
    ngx_stream_brix_srv_conf_t *conf;
    brix_file_t                *file;
    struct stat                   st;
    int                           fd;
    int                           open_flags;

    if (!shared->readable || shared->path[0] == '\0') {
        return NGX_DECLINED;
    }

    conf = ngx_stream_get_module_srv_conf(ctx->session,
                                          ngx_stream_brix_module);
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
        fd = open(shared->path, open_flags);  /* vfs-seam-allow: separate server-managed cache-root domain (from_cache), opened as worker */
    } else {
        /* shared->path is the absolute path; strip root_canon to get the
         * path relative to rootfd for openat2 RESOLVE_BENEATH. */
        const char *rel      = shared->path;
        size_t      root_len = strlen(conf->common.root_canon);
        if (root_len > 0
            && ngx_strncmp((u_char *) shared->path,
                           (u_char *) conf->common.root_canon,
                           root_len) == 0
            && shared->path[root_len] == '/')
        {
            rel = shared->path + root_len;
        }
        fd = brix_vfs_open_fd_at(conf->rootfd, rel, open_flags, 0);
    }

    if (fd < 0) {
        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, errno,
                       "brix: bound handle reopen failed handle=%d path=%s",
                       handle_index, shared->path);
        return NGX_DECLINED;
    }

    if (fstat(fd, &st) != 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, errno,
                       "brix: fstat failed on bound handle=%d",
                       handle_index);
        close(fd);
        return NGX_DECLINED;
    }

    if (st.st_dev != shared->device || st.st_ino != shared->inode) {
        close(fd);
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "brix: bound handle=%d path changed before reopen",
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

    if (brix_set_fhandle_path(ctx, c, handle_index, shared->path)
        != NGX_OK)
    {
        brix_free_fhandle(ctx, handle_index);
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "brix: bound handle=%d reopened shared path=%s",
                   handle_index, shared->path);
    return NGX_OK;
}

/* brix_ensure_read_handle — for an unbound session, NGX_OK iff the fd exists. For
 * a bound secondary, re-validate against the primary's shared entry every time: if
 * the primary closed/reused the slot, revoke (free + NGX_DECLINED); if stale but
 * still published, reopen a fresh matching fd. Invariant: a bound secondary never
 * reads from a handle no longer in the primary's published table. */

ngx_int_t
brix_ensure_read_handle(brix_ctx_t *ctx, ngx_connection_t *c,
    int handle_index)
{
    brix_shared_handle_entry_t shared;

    if (handle_index < 0 || handle_index >= BRIX_MAX_FILES) {
        return NGX_DECLINED;
    }

    if (!ctx->is_bound) {
        /* fd >= 0 (POSIX) OR a driver-backed object/remote handle (no kernel fd;
         * reads route through sd_obj.driver via the buffered serve path). */
        return (ctx->files[handle_index].fd >= 0
                || ctx->files[handle_index].sd_obj.driver != NULL)
               ? NGX_OK : NGX_DECLINED;
    }

    /*
     * A bound stream only follows the primary session's current handle table.
     * Re-check the shared slot on every read request so a primary close, reuse,
     * or session teardown immediately revokes the secondary's local fd.
     */
    if (!brix_session_handle_lookup_hint(ctx->bound_sessid, handle_index,
                                           &ctx->files[handle_index]
                                                .shared_handle_slot_hint,
                                           &shared))
    {
        if (ctx->files[handle_index].fd >= 0) {
            brix_free_fhandle(ctx, handle_index);
        }
        return NGX_DECLINED;
    }

    if (brix_local_file_matches_shared_handle(&ctx->files[handle_index],
                                                &shared))
    {
        return NGX_OK;
    }

    if (ctx->files[handle_index].fd >= 0
        || ctx->files[handle_index].path != NULL)
    {
        brix_free_fhandle(ctx, handle_index);
    }

    return brix_reopen_bound_read_handle(ctx, c, handle_index, &shared);
}

/* The handle-slot teardown machinery (brix_free_fhandle / brix_close_all_files
 * and their fhandle_* helpers) lives in the sibling fd_table_teardown.c. */

/* brix_validate_file_handle — 1 iff handle_index is in bounds and the slot has an
 * active fd; otherwise logs + sends kXR_FileNotOpen and returns 0. The prerequisite
 * check before any read/write capability check. */

ngx_flag_t
brix_validate_file_handle(brix_ctx_t *ctx, ngx_connection_t *c,
    int handle_index, const char *verb, ngx_uint_t op, ngx_int_t *rc)
{
    if (handle_index < 0 || handle_index >= BRIX_MAX_FILES
        || (ctx->files[handle_index].fd < 0
            && ctx->files[handle_index].sd_obj.driver == NULL
            && ctx->files[handle_index].staged == NULL))
    {
        /* A driver-backed handle (object/remote backend) is "open" with no kernel
         * fd — data I/O routes through sd_obj.driver, so fd < 0 is normal there.
         * A whole-object staged write handle (staged != NULL) is likewise "open"
         * with no fd — byte I/O routes through the staged handle (phase-70). */
        BRIX_BAIL_ERR(ctx, c, op, verb, "-", "-",
                        kXR_FileNotOpen, "invalid file handle", rc);
    }

    return 1;
}

/* brix_validate_read_handle — two phases: (1) brix_ensure_read_handle confirms
 * the fd and refreshes bound secondaries; (2) the readable capability bit. 1 iff
 * both pass, else logs + sends kXR_FileNotOpen/kXR_ServerError (phase 1) or
 * kXR_NotAuthorized (phase 2). Re-checking the bit per read guards against drift. */

ngx_flag_t
brix_validate_read_handle(brix_ctx_t *ctx, ngx_connection_t *c,
    int handle_index, const char *verb, ngx_uint_t op, ngx_int_t *rc)
{
    ngx_int_t ensure_rc;

    ensure_rc = brix_ensure_read_handle(ctx, c, handle_index);
    if (ensure_rc != NGX_OK) {
        if (ensure_rc == NGX_ERROR) {
            BRIX_BAIL_ERR(ctx, c, op, verb, "-", "-", kXR_ServerError,
                            "could not prepare file handle", rc);
        }

        BRIX_BAIL_ERR(ctx, c, op, verb, "-", "-", kXR_FileNotOpen,
                        "invalid file handle", rc);
    }

    /*
     * Authorization and path checks happened at open time.  Later handle I/O
     * verifies the capability bit recorded on the handle rather than resolving
     * the path again on every read.
     */
    if (!ctx->files[handle_index].readable) {
        BRIX_BAIL_ERR(ctx, c, op, verb, ctx->files[handle_index].path, "-",
                        kXR_NotAuthorized, "file not open for reading", rc);
    }

    return 1;
}

/* brix_validate_write_handle — brix_validate_file_handle plus the writable
 * capability bit. 1 iff both pass, else logs + sends kXR_NotAuthorized on
 * writable=0. Re-checking the bit per write guards against drift, as for reads. */

ngx_flag_t
brix_validate_write_handle(brix_ctx_t *ctx, ngx_connection_t *c,
    int handle_index, const char *verb, ngx_uint_t op, ngx_int_t *rc)
{
    if (!brix_validate_file_handle(ctx, c, handle_index, verb, op, rc)) {
        return 0;
    }

    if (!ctx->files[handle_index].writable) {
        BRIX_BAIL_ERR(ctx, c, op, verb, ctx->files[handle_index].path, "-",
                        kXR_NotAuthorized, "file not open for writing", rc);
    }

    return 1;
}

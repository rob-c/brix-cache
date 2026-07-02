#include "fd_table.h"
#include "fs/vfs/vfs.h"   /* xrootd_vfs_open_fd_at (handle-table confined open) */
#include "protocols/root/session/registry.h"
#include "fs/cache/writethrough_metrics.h"
#include "protocols/root/write/pgw_fob.h"
#include "fs/backend/csi_tagstore.h"
#include "protocols/root/zip/zip_member.h"   /* xrootd_zip_handle_cleanup (frees inflate stream) */
#include "protocols/ssi/ssi.h"          /* xrootd_ssi_handle_cleanup (timers + registry) */

#include <errno.h>
#include <string.h>
#include <unistd.h>

/* xrootd_alloc_fhandle — return the first free slot (fd < 0) in ctx->files; the
 * index becomes the one-byte on-wire fhandle, so it is bounded by XROOTD_MAX_FILES.
 * -1 when all slots are occupied. Single-owner per connection (event thread, no
 * locking); a slot is only reused once its fd is closed. */
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

/* xrootd_ctx_has_open_file — 1 if any handle slot is occupied (fd >= 0), else 0.
 * Used by the recv-loop drain gate: a connection with an open file is mid-transfer
 * (a streaming read parked between kXR_read chunks), so a draining worker must let
 * it finish rather than fast-teardown at the request boundary — a forced mid-stream
 * reconnect loses the in-flight fill. Single-owner per connection (event thread). */
int
xrootd_ctx_has_open_file(const xrootd_ctx_t *ctx)
{
    int handle_index;

    for (handle_index = 0; handle_index < XROOTD_MAX_FILES; handle_index++) {
        if (ctx->files[handle_index].fd >= 0) {
            return 1;
        }
    }

    return 0;
}

/* xrootd_set_fhandle_path — store a heap copy (ngx_alloc, NOT pool, so it outlives
 * the kXR_open request) of the canonical path in the slot, freeing any prior path
 * first; xrootd_free_fhandle owns the free. NGX_OK, or NGX_ERROR on bad bounds or
 * allocation failure. Heap (not pool) avoids fragmentation across open/close cycles. */
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

/* xrootd_local_file_matches_shared_handle — 1 iff the local fd still corresponds to
 * the primary's published handle (fd valid + readable, same device/inode/path), used
 * by xrootd_ensure_read_handle to decide whether a bound secondary must reopen. */

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

/* xrootd_reopen_bound_read_handle — reopen a bound secondary's stale fd to match the
 * primary's shared entry via a cache-aware confined open (O_RDONLY|O_NOCTTY|O_CLOEXEC),
 * refreshing all file metadata from the fresh fstat; NGX_DECLINED (revoke) if the
 * filesystem object's device/inode changed. */

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
        fd = xrootd_vfs_open_fd_at(conf->rootfd, rel, open_flags, 0);
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

/* xrootd_ensure_read_handle — for an unbound session, NGX_OK iff the fd exists. For
 * a bound secondary, re-validate against the primary's shared entry every time: if
 * the primary closed/reused the slot, revoke (free + NGX_DECLINED); if stale but
 * still published, reopen a fresh matching fd. Invariant: a bound secondary never
 * reads from a handle no longer in the primary's published table. */

ngx_int_t
xrootd_ensure_read_handle(xrootd_ctx_t *ctx, ngx_connection_t *c,
    int handle_index)
{
    xrootd_shared_handle_entry_t shared;

    if (handle_index < 0 || handle_index >= XROOTD_MAX_FILES) {
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
    if (!xrootd_session_handle_lookup_hint(ctx->bound_sessid, handle_index,
                                           &ctx->files[handle_index]
                                                .shared_handle_slot_hint,
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

/* fhandle_unlink_staging — remove a handle-owned staging temp (checkpoint journal
 * or POSC partial) through the VFS seam. `abs_path` is the absolute staging path;
 * strip `root_canon` to the export-relative key and confined-unlink it (the
 * teardown context has no request ctx, but the srv conf still gives root_canon +
 * rootfd). Falls back to a raw unlink only when the path is not under the export
 * root (no confinement is possible then). */
static void
fhandle_unlink_staging(const char *abs_path, const char *root_canon,
    ngx_log_t *log)
{
    size_t root_len = (root_canon != NULL) ? ngx_strlen(root_canon) : 0;

    if (root_len > 0
        && ngx_strncmp((u_char *) abs_path, (u_char *) root_canon, root_len) == 0
        && abs_path[root_len] == '/')
    {
        (void) xrootd_vfs_unlink_path(log, root_canon, abs_path + root_len);
        return;
    }
    (void) unlink(abs_path);  /* vfs-seam-allow: handle-owned staging temp not under the export root */
}

/* xrootd_free_fhandle — full teardown of one slot: close the fd, unpublish from
 * shared memory (unbound only), unlink checkpoint/POSC staging files, free the heap
 * path, and reset every field to its zero/null state. Called on session end, error
 * recovery, and kXR_close completion. */

void
xrootd_free_fhandle(xrootd_ctx_t *ctx, int handle_index)
{
    xrootd_file_t                *file;
    ngx_stream_xrootd_srv_conf_t *conf;
    const char                   *root_canon;
    ngx_log_t                    *tlog;

    if (handle_index < 0 || handle_index >= XROOTD_MAX_FILES) {
        return;
    }

    file = &ctx->files[handle_index];

    /* The teardown has no request ctx, but the srv conf still yields the export
     * root_canon so handle-owned staging temps can be confined-unlinked. */
    conf = ngx_stream_get_module_srv_conf(ctx->session, ngx_stream_xrootd_module);
    root_canon = (conf != NULL) ? conf->common.root_canon : NULL;
    tlog = (ctx->session != NULL && ctx->session->connection != NULL)
           ? ctx->session->connection->log : NULL;

    if (!ctx->is_bound && file->fd >= 0) {
        xrootd_session_handle_unpublish(ctx->sessid, handle_index);
    }

    if (file->sd_obj.driver != NULL) {
        /* Layer 3: a driver-backed handle owns its descriptor(s) and commits any
         * pending metadata (e.g. catalog size/mtime) in its own close(); do NOT
         * also raw-close file->fd, which is the driver's block-0 descriptor. */
        (void) file->sd_obj.driver->close(&file->sd_obj);
        file->sd_obj.driver = NULL;
        file->sd_obj.inst   = NULL;
        file->sd_obj.state  = NULL;
        file->sd_obj.fd     = -1;
    } else if (file->fd >= 0) {
        close(file->fd);
    }

    /* xmeta P3: flush + free the CSI engine (merges folded block CRCs
     * into the file's metadata record). */
    if (file->csi != NULL) {
        xrootd_csi_close((xrootd_csi_t *) file->csi);
        ngx_free(file->csi);
        file->csi = NULL;
    }

    /*
     * Checkpoint files are temporary rollback state owned by the handle.
     * Normal close/free removes any abandoned checkpoint path.
     */
    if (file->ckp_path != NULL) {
        fhandle_unlink_staging(file->ckp_path, root_canon, tlog);
        ngx_free(file->ckp_path);
    }

    /*
     * POSC cleanup: if posc_final_path is still set here the session ended
     * without a clean kXR_close (disconnect, error, or abandon).  Unlink the
     * temp staging file so partial writes are not left on disk.
     *
     * EXCEPTION — upload resume (is_resume): the partial is deterministic and
     * identity-keyed, so it is PRESERVED on a non-clean close.  That is the
     * whole mechanism: the same client reconnecting re-opens it in place (no
     * truncate) and resumes from its offset.  Abandoned partials are reclaimed
     * by an operator glob-clean ("*.xrdresume.*.part") rather than here.
     */
    if (file->posc_final_path != NULL) {
        if (file->path != NULL && !file->is_resume) {
            fhandle_unlink_staging(file->path, root_canon, tlog);
        }
        ngx_free(file->posc_final_path);
    }

    if (file->path != NULL) {
        ngx_free(file->path);
    }

    if (file->tpc_transfer_id != 0) {
        (void) xrootd_tpc_registry_remove(file->tpc_transfer_id, NULL);
    }

    xrootd_wt_mark_clean(ctx, handle_index);

    /* ZIP member handle: release the deflate inflate stream (if any) and clear
     * the zip_* state so a reused slot cannot be mistaken for a zip handle. */
    xrootd_zip_handle_cleanup(file);
    file->zip_mode        = 0;
    file->zip_method      = 0;
    file->zip_data_off    = 0;
    file->zip_comp_size   = 0;
    file->zip_uncomp_size = 0;
    file->zip_crc32       = 0;
    file->zip_logical_pos = 0;
    file->zip_comp_pos    = 0;

    file->fd             = -1;
    ngx_memzero(&file->sd_obj, sizeof(file->sd_obj));  /* Layer 3: clear driver obj */
    file->shared_handle_slot_hint = -1;  /* Phase 33 C2: drop the cached SHM slot */
    file->readable       = 0;
    file->writable       = 0;
    file->from_cache     = 0;
    file->bytes_read     = 0;
    file->bytes_written  = 0;
    file->open_time      = 0;
    file->path           = NULL;
    /* §7: cancel SSI async-deferral timers + unregister the session before the
     * .ssi pointer is dropped (runs on close + disconnect; NULL-safe). */
    xrootd_ssi_handle_cleanup(file->ssi);
    file->ssi            = NULL;   /* §7: SSI state is connection-pool owned */
    file->is_regular     = 0;
    file->device         = 0;
    file->inode          = 0;
    file->cached_size    = 0;
    file->read_last_end  = -1;
    file->read_ahead_end = 0;
    file->ckp_path       = NULL;
    file->ckp_size       = 0;
    file->posc_final_path = NULL;
    file->is_resume       = 0;
    file->tpc_destination = 0;
    file->tpc_armed       = 0;
    file->tpc_started     = 0;
    file->tpc_done        = 0;
    file->tpc_key[0]      = '\0';
    file->tpc_org[0]      = '\0';
    file->tpc_src_host[0] = '\0';
    file->tpc_src_port    = 0;
    file->tpc_src_path[0] = '\0';
    file->tpc_token_mode[0] = '\0';
    file->tpc_transfer_id = 0;
    file->wt_enabled      = 0;
    file->wt_policy       = 0;
    file->wt_mode_bits    = 0;
    file->wt_dirty_offset = -1;
    file->wt_bytes_written = 0;
    file->wt_flush_task    = NULL;
    file->wt_flush_pending = 0;
    file->wrts_enabled     = 0;
    file->wrts_head        = 0;
    file->wrts_count       = 0;
    file->wrts_gen         = 0;
    xrootd_pgw_fob_reset(file);
}

/* xrootd_close_all_files — xrootd_free_fhandle every slot; used at session
 * termination or error recovery when all handles must be released at once. */

void
xrootd_close_all_files(xrootd_ctx_t *ctx)
{
    int handle_index;

    for (handle_index = 0; handle_index < XROOTD_MAX_FILES; handle_index++) {
        xrootd_free_fhandle(ctx, handle_index);
    }
}

/* xrootd_validate_file_handle — 1 iff handle_index is in bounds and the slot has an
 * active fd; otherwise logs + sends kXR_FileNotOpen and returns 0. The prerequisite
 * check before any read/write capability check. */

ngx_flag_t
xrootd_validate_file_handle(xrootd_ctx_t *ctx, ngx_connection_t *c,
    int handle_index, const char *verb, ngx_uint_t op, ngx_int_t *rc)
{
    if (handle_index < 0 || handle_index >= XROOTD_MAX_FILES
        || (ctx->files[handle_index].fd < 0
            && ctx->files[handle_index].sd_obj.driver == NULL))
    {
        /* A driver-backed handle (object/remote backend) is "open" with no kernel
         * fd — data I/O routes through sd_obj.driver, so fd < 0 is normal there. */
        XROOTD_BAIL_ERR(ctx, c, op, verb, "-", "-",
                        kXR_FileNotOpen, "invalid file handle", rc);
    }

    return 1;
}

/* xrootd_validate_read_handle — two phases: (1) xrootd_ensure_read_handle confirms
 * the fd and refreshes bound secondaries; (2) the readable capability bit. 1 iff
 * both pass, else logs + sends kXR_FileNotOpen/kXR_ServerError (phase 1) or
 * kXR_NotAuthorized (phase 2). Re-checking the bit per read guards against drift. */

ngx_flag_t
xrootd_validate_read_handle(xrootd_ctx_t *ctx, ngx_connection_t *c,
    int handle_index, const char *verb, ngx_uint_t op, ngx_int_t *rc)
{
    ngx_int_t ensure_rc;

    ensure_rc = xrootd_ensure_read_handle(ctx, c, handle_index);
    if (ensure_rc != NGX_OK) {
        if (ensure_rc == NGX_ERROR) {
            XROOTD_BAIL_ERR(ctx, c, op, verb, "-", "-", kXR_ServerError,
                            "could not prepare file handle", rc);
        }

        XROOTD_BAIL_ERR(ctx, c, op, verb, "-", "-", kXR_FileNotOpen,
                        "invalid file handle", rc);
    }

    /*
     * Authorization and path checks happened at open time.  Later handle I/O
     * verifies the capability bit recorded on the handle rather than resolving
     * the path again on every read.
     */
    if (!ctx->files[handle_index].readable) {
        XROOTD_BAIL_ERR(ctx, c, op, verb, ctx->files[handle_index].path, "-",
                        kXR_NotAuthorized, "file not open for reading", rc);
    }

    return 1;
}

/* xrootd_validate_write_handle — xrootd_validate_file_handle plus the writable
 * capability bit. 1 iff both pass, else logs + sends kXR_NotAuthorized on
 * writable=0. Re-checking the bit per write guards against drift, as for reads. */

ngx_flag_t
xrootd_validate_write_handle(xrootd_ctx_t *ctx, ngx_connection_t *c,
    int handle_index, const char *verb, ngx_uint_t op, ngx_int_t *rc)
{
    if (!xrootd_validate_file_handle(ctx, c, handle_index, verb, op, rc)) {
        return 0;
    }

    if (!ctx->files[handle_index].writable) {
        XROOTD_BAIL_ERR(ctx, c, op, verb, ctx->files[handle_index].path, "-",
                        kXR_NotAuthorized, "file not open for writing", rc);
    }

    return 1;
}

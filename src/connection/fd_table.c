#include "fd_table.h"
#include "../session/registry.h"
#include "../cache/writethrough_metrics.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

/* ---- xrootd_alloc_fhandle — allocate next free file handle slot (0..XROOTD_MAX_FILES) ----
 *
 * WHAT: Scans ctx->files array from index 0 to XROOTD_MAX_FILES-1, returns first slot with fd < 0. The returned index becomes the on-wire fhandle byte sent to the client — bounded by XROOTD_MAX_FILES because the wire format reserves only one byte for the handle value. Returns -1 when all slots are occupied (client should retry or session has too many concurrent files). Security invariant: slot must have fd < 0 before allocation; never reuse a slot with active fd. Thread safety: single-owner per connection on nginx event thread — no locking required. Primary handles owned by TCP session; kXR_bind secondaries are exception (may read primary-published handle from shared memory). */
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

/* ---- xrootd_set_fhandle_path — store canonical path for file handle slot (heap-allocated, survives request lifecycle) ----
 *
 * WHAT: Validates handle bounds (0..XROOTD_MAX_FILES), allocates heap copy of path via ngx_alloc() (NOT pool-allocated so it survives past the kXR_open request), stores in ctx->files[handle_index].path. On collision with existing path, frees old buffer first. Must be freed with ngx_free() by xrootd_free_fhandle — never free directly. Returns NGX_OK on success, NGX_ERROR on invalid bounds or allocation failure. Security invariant: always heap-allocate to prevent pool fragmentation across multiple open/close cycles. Thread safety: single-owner per connection on nginx event thread — no locking required. */
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

/* ---- xrootd_local_file_matches_shared_handle — compare local file to shared memory entry ----
 *
 * WHAT: Validates that the local fd matches the shared handle metadata (device, inode, path). Returns 1 if all four fields match (fd valid, readable, same device/inode, same path), 0 otherwise. Used by xrootd_ensure_read_handle() to decide whether a bound secondary's local fd still corresponds to the primary's published handle. */

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

/* ---- xrootd_reopen_bound_read_handle — reopen local fd to match primary's published handle ----
 *
 * WHAT: Reopens the local file descriptor when a bound secondary's stale fd no longer matches the primary session's shared memory entry. Uses confined open (O_RDONLY|O_NOCTTY|O_CLOEXEC) with cache-aware path resolution. Validates device/inode after fstat — if the filesystem object changed, returns NGX_DECLINED to revoke access. Sets up all file metadata fields from the fresh stat result. */

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
        fd = xrootd_open_beneath(conf->rootfd, rel, open_flags, 0);
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

/* ---- xrootd_ensure_read_handle — validate and refresh bound secondary's file handle ----
 *
 * WHAT: For unbound sessions: returns NGX_OK if fd exists, NGX_DECLINED otherwise. For bound secondaries: continuously validates the shared memory entry — if primary session closed/reused this slot, revokes local fd via free_fhandle+declined. If stale but still published, reopens fresh fd matching device/inode/path. Critical invariant: bound secondaries must never read from a handle that no longer exists in the primary's published table. */

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

/* ---- xrootd_free_fhandle — release all resources owned by a file handle slot ----
 *
 * WHAT: Complete teardown of an allocated fhandle: closes fd, unpublishes from shared memory (if not bound), unlinks checkpoint/POSC staging files, frees heap-allocated path buffer. Resets ALL fields to zero/null state. Must be called on session end, error recovery, and kXR_close completion. Handles bound secondary cleanup via unlink only (no unpublish). */

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

    if (file->tpc_transfer_id != 0) {
        (void) xrootd_tpc_registry_remove(file->tpc_transfer_id, NULL);
    }

    xrootd_wt_mark_clean(ctx, handle_index);

    file->fd             = -1;
    file->shared_handle_slot_hint = -1;  /* Phase 33 C2: drop the cached SHM slot */
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
}

/* ---- xrootd_close_all_files — teardown every allocated file handle slot ----
 *
 * WHAT: Iterates all slots (0..XROOTD_MAX_FILES-1) and calls free_fhandle on each. Used during session termination or error recovery when all handles must be released simultaneously. */

void
xrootd_close_all_files(xrootd_ctx_t *ctx)
{
    int handle_index;

    for (handle_index = 0; handle_index < XROOTD_MAX_FILES; handle_index++) {
        xrootd_free_fhandle(ctx, handle_index);
    }
}

/* ---- xrootd_validate_file_handle — verify fhandle is open and valid ----
 *
 * WHAT: Basic validation check that handle_index is in bounds (0..XROOTD_MAX_FILES) AND the slot has an active fd (fd >= 0). Returns 1 if both conditions met, logs kXR_FileNotOpen error and sends response on failure. Used as prerequisite for all read/write operations before capability checks. */

ngx_flag_t
xrootd_validate_file_handle(xrootd_ctx_t *ctx, ngx_connection_t *c,
    int handle_index, const char *verb, ngx_uint_t op, ngx_int_t *rc)
{
    if (handle_index < 0 || handle_index >= XROOTD_MAX_FILES
        || ctx->files[handle_index].fd < 0)
    {
        XROOTD_BAIL_ERR(ctx, c, op, verb, "-", "-",
                        kXR_FileNotOpen, "invalid file handle", rc);
    }

    return 1;
}

/* ---- xrootd_validate_read_handle — validate fd exists AND is readable for read operation ----
 *
 * WHAT: Two-phase validation: (1) calls ensure_read_handle() to confirm fd exists + refresh bound secondaries' handles; (2) checks capability bit ctx->files[handle_index].readable. Returns 1 if both phases pass, logs kXR_FileNotOpen/kXR_ServerError on phase-1 failure or kXR_NotAuthorized on readable=0. Authorization was checked at open time — this re-verifies the capability flag on every read to prevent capability drift. */

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

/* ---- xrootd_validate_write_handle — validate fd exists AND is writable for write operation ----
 *
 * WHAT: Combines basic file handle validation (fd open, in bounds) with writable capability check. Returns 1 if both conditions met, logs kXR_NotAuthorized on writable=0. Same invariant as read validation: capability bit set at open time re-checked on every write to prevent drift from ACL changes or session state corruption. */

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

/* ---- xrootd_alloc_fhandle — HOW: Scans ctx->files array from index 0 to XROOTD_MAX_FILES-1 sequentially, returns first slot where files[i].fd < 0 (free). Returns -1 when all slots occupied. Wire format reserves one byte for handle value so bounded by XROOTD_MAX_FILES. Single-owner per connection on nginx event thread — no locking required. ---- */

/* ---- xrootd_set_fhandle_path — HOW: Validates handle_index in [0..XROOTD_MAX_FILES-1] AND path non-null (returns NGX_ERROR otherwise). Computes path_bytes = strlen(path)+1, allocates via ngx_alloc(path_bytes,c->log) (heap not pool for lifecycle survival). Copies path via ngx_memcpy into new buffer. If slot already has existing path, frees old buffer with ngx_free first. Stores pointer in ctx->files[handle_index].path. Returns NGX_OK on success, NGX_ERROR on bounds failure or allocation failure. Caller must free with ngx_free() via xrootd_free_fhandle — never free directly. ---- */

/* ---- xrootd_ensure_read_handle — HOW: For unbound sessions: returns NGX_OK if fd>=0 else NGX_DECLINED (no shared memory lookup). For bound secondaries: calls xrootd_session_handle_lookup(bound_sessid, handle_index, &shared) to fetch current primary entry — if not found AND local fd exists, frees via free_fhandle then returns NGX_DECLINED (primary revoked). If match confirmed via xrootd_local_file_matches_shared_handle() (fd valid+readable, same device/inode/path), returns NGX_OK. If mismatch: frees stale handle first, calls xrootd_reopen_bound_read_handle(ctx,c,handle_index,&shared) which opens O_RDONLY|O_NOCTTY|O_CLOEXEC with cache-aware confined open if shared->from_cache else via xrootd_open_confined(). Validates fstat device/inode match — if filesystem changed returns NGX_DECLINED. On fresh reopen success: sets all file metadata fields from stat result, calls set_fhandle_path for path storage. Returns result of reopen call. ---- */

/* ---- xrootd_free_fhandle — HOW: Validates handle_index bounds (returns immediately on invalid). For unbound sessions with fd>=0: unpublishes via xrootd_session_handle_unpublish(sessid, handle_index). Closes fd if >=0. Unlinks and frees ckp_path if non-null (checkpoint rollback staging). If posc_final_path set AND path set: unlink path then free posc_final_path (POSC partial write cleanup). Free path buffer with ngx_free. Resets ALL file fields to zero/null state including fd=-1, readable/writable=0, from_cache=0, bytes_read/bytes_written=0, open_time=0, path=NULL, is_regular=0, device/inode=0, cached_size=0, read_last_end=-1, read_ahead_end=0, ckp_path=NULL, ckp_size=0, posc_final_path=NULL, tpc_destination=0, tpc_armed/started/done=0, tpc_key/org/src_host/port/path/token_mode="", wt_enabled/policy/bits/dirty_offset=-1/bytes_written=0, flush_task=NULL. ---- */

/* ---- xrootd_close_all_files — HOW: Iterates handle_index from 0 to XROOTD_MAX_FILES-1, calls xrootd_free_fhandle(ctx, handle_index) on each slot sequentially. Used during session termination or error recovery when all handles must be released simultaneously. ---- */

/* ---- xrootd_validate_file_handle — HOW: Validates handle_index in [0..XROOTD_MAX_FILES-1] AND ctx->files[handle_index].fd >= 0 (both required). If either fails: logs access event via xrootd_log_access(verb,"-","-",op,kXR_FileNotOpen,"invalid file handle",0), increments error metric XROOTD_OP_ERR(ctx,op), sets *rc=xrootd_send_error(kXR_FileNotOpen,"invalid file handle"), returns 0. If both conditions met: returns 1. Used as prerequisite for all read/write operations before capability checks. ---- */

/* ---- xrootd_validate_read_handle — HOW: Phase 1: calls xrootd_ensure_read_handle(ctx,c,handle_index) to confirm fd exists and refresh bound secondaries' shared memory entry. If ensure_rc==NGX_ERROR: logs server error via xrootd_log_access(verb,"-","-",op,kXR_ServerError,"could not prepare file handle",0), increments XROOTD_OP_ERR, sets *rc=xrootd_send_error(kXR_ServerError,...), returns 0. If ensure_rc==NGX_DECLINED: logs kXR_FileNotOpen via xrootd_log_access(verb,"-","-",op,kXR_FileNotOpen,"invalid file handle",0), increments XROOTD_OP_ERR, sets *rc=xrootd_send_error(kXR_FileNotOpen,...), returns 0. Phase 2 (both pass): checks ctx->files[handle_index].readable capability bit — if false: logs kXR_NotAuthorized via xrootd_log_access(verb,path,"-",op,kXR_NotAuthorized,"file not open for reading",0), increments XROOTD_OP_ERR, sets *rc=xrootd_send_error(kXR_NotAuthorized,...), returns 0. If both phases pass: returns 1. Capability bit set at open time re-checked on every read to prevent drift from ACL changes or session state corruption. ---- */

/* ---- xrootd_validate_write_handle — HOW: Calls xrootd_validate_file_handle(ctx,c,handle_index,verb,op,rc) first (basic fd+bounds check) — if returns 0, propagates error via rc pointer and returns 0 immediately. If basic validation passes: checks ctx->files[handle_index].writable capability bit — if false: logs kXR_NotAuthorized via xrootd_log_access(verb,path,"-",op,kXR_NotAuthorized,"file not open for writing",0), increments XROOTD_OP_ERR, sets *rc=xrootd_send_error(kXR_NotAuthorized,...), returns 0. If both conditions met: returns 1. Same invariant as read validation — capability bit set at open time re-checked on every write to prevent drift. ---- */

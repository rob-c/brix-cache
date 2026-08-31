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

/* brix_fhandle_slot_live — 1 iff the slot is currently occupied by an open handle.
 * A slot is live when it has ANY of: a kernel fd (fd >= 0), a driver-backed object
 * (sd_obj.driver != NULL — remote/object backends are memory-served with fd < 0),
 * or a whole-object staged writer (writer != NULL). This is the SAME liveness
 * predicate brix_validate_file_handle uses; allocation and validation must agree,
 * else a driver-backed handle (fd stays -1) reads as "free" and a second open on
 * the same connection re-allocates its slot, collapsing distinct handles onto one
 * index (breaks clients that hold multiple concurrent opens — e.g. uproot). */
static ngx_inline int
brix_fhandle_slot_live(const brix_ctx_t *ctx, int handle_index)
{
    return ctx->files[handle_index].fd >= 0
        || ctx->files[handle_index].sd_obj.driver != NULL
        || ctx->files[handle_index].writer != NULL;
}

/* brix_alloc_fhandle — return the first free slot in ctx->files; the index becomes
 * the one-byte on-wire fhandle, so it is bounded by BRIX_MAX_FILES. -1 when all
 * slots are occupied. Single-owner per connection (event thread, no locking); a
 * slot is only reused once its handle is fully torn down (brix_free_fhandle). */
int
brix_alloc_fhandle(brix_ctx_t *ctx)
{
    int handle_index;

    /*
     * The XRootD wire handle stores this slot number in one byte.  Keep all
     * allocation/validation paths using the same bounded table.
     */
    for (handle_index = 0; handle_index < BRIX_MAX_FILES; handle_index++) {
        if (!brix_fhandle_slot_live(ctx, handle_index)) {
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
        if (brix_fhandle_slot_live(ctx, handle_index)) {
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

/* brix_bound_confined_open — cache-aware confined (re)open of a primary-published
 * shared entry's path with the given flags, validating the reopened object's
 * device/inode against the published tuple.  Returns a fresh caller-owned fd, or
 * -1 on open/fstat failure or a device/inode mismatch (path replaced since publish;
 * the fd is closed before returning).  Shared by the bound READ (O_RDONLY) and
 * bound WRITE (O_WRONLY) reopen paths so the confinement + stale-reference check
 * lives in exactly one place. */
static int
brix_bound_confined_open(brix_ctx_t *ctx, ngx_connection_t *c,
    const brix_shared_handle_entry_t *shared, int open_flags, struct stat *st)
{
    ngx_stream_brix_srv_conf_t *conf;
    int                         fd;

    conf = ngx_stream_get_module_srv_conf(ctx->session,
                                          ngx_stream_brix_module);
    if (conf == NULL) {
        return -1;
    }

    /*
     * The primary published a canonical, ACL-checked path.  The secondary
     * still opens it with the same confinement helper so a stale or corrupted
     * shared-memory entry cannot escape the configured export root.
     */
    if (shared->from_cache) {
        fd = open(shared->path, open_flags | O_NOFOLLOW);  /* vfs-seam-allow: separate server-managed cache-root domain (from_cache), opened as worker; O_NOFOLLOW so a stray symlink in the svc-owned cache tree is not followed */
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
        /* phase-105 (Appendix K.8): a bound data stream reopens a handle the
         * PRIMARY published, on a connection whose own endpoint decides what it
         * may do. A writable-looking bound handle must therefore meet this
         * server's write posture here — the gated form refuses a mutating
         * open_flags with EROFS and leaves a read-only reopen untouched. */
        brix_vfs_export_op_ctx_t opctx;

        brix_vfs_export_op_ctx_init(&opctx, c->log, conf->common.root_canon,
            brix_vfs_policy_from_write_enable(conf->common.allow_write),
            BRIX_PROTO_ROOT);
        fd = brix_vfs_export_open_fd_at(&opctx, conf->rootfd, rel, open_flags,
                                        0);
    }

    if (fd < 0) {
        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, errno,
                       "brix: bound handle confined open failed path=%s flags=%d",
                       shared->path, open_flags);
        return -1;
    }

    if (fstat(fd, st) != 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, errno,
                       "brix: fstat failed on bound reopen path=%s", shared->path);
        close(fd);
        return -1;
    }

    if (st->st_dev != shared->device || st->st_ino != shared->inode) {
        close(fd);
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "brix: bound handle path changed before reopen path=%s",
                       shared->path);
        return -1;
    }

    return fd;
}

/* brix_reopen_bound_read_handle — reopen a bound secondary's stale fd O_RDONLY to
 * match the primary's shared entry (via brix_bound_confined_open), refreshing all
 * file metadata from the fresh fstat; NGX_DECLINED (revoke) if the object's
 * device/inode changed. */

static ngx_int_t
brix_reopen_bound_read_handle(brix_ctx_t *ctx, ngx_connection_t *c,
    int handle_index, const brix_shared_handle_entry_t *shared)
{
    brix_file_t *file;
    struct stat  st;
    int          fd;

    if (!shared->readable || shared->path[0] == '\0') {
        return NGX_DECLINED;
    }

    fd = brix_bound_confined_open(ctx, c, shared,
                                  O_RDONLY | O_NOCTTY | O_CLOEXEC, &st);
    if (fd < 0) {
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

/* brix_local_file_matches_shared_write_handle — 1 iff the bound secondary's local
 * fd still matches the primary's published WRITABLE entry (same device/inode/path,
 * locally writable).  No size check: a write handle's size grows as bytes land, so
 * only object identity is validated (Phase 94). */
static ngx_flag_t
brix_local_file_matches_shared_write_handle(const brix_file_t *file,
    const brix_shared_handle_entry_t *shared)
{
    if (file->fd < 0 || file->path == NULL || !file->writable
        || !shared->writable)
    {
        return 0;
    }

    return file->device == shared->device
           && file->inode == shared->inode
           && ngx_strcmp(file->path, shared->path) == 0;
}

/* brix_reopen_bound_write_handle — Phase 94: reopen a bound secondary's fd O_WRONLY
 * to match the primary's published writable entry.  Disjoint-offset pwrites from
 * this fd are POSIX-safe against the primary's and other secondaries' fds on the
 * same inode.  NO O_CREAT/O_TRUNC — the primary already created the file at open, so
 * a substream write only fills its own byte range.  NGX_DECLINED on a device/inode
 * change (path replaced since publish). */

static ngx_int_t
brix_reopen_bound_write_handle(brix_ctx_t *ctx, ngx_connection_t *c,
    int handle_index, const brix_shared_handle_entry_t *shared)
{
    brix_file_t *file;
    struct stat  st;
    int          fd;

    if (!shared->writable || shared->path[0] == '\0') {
        return NGX_DECLINED;
    }

    fd = brix_bound_confined_open(ctx, c, shared,
                                  O_WRONLY | O_NOCTTY | O_CLOEXEC, &st);
    if (fd < 0) {
        return NGX_DECLINED;
    }

    file = &ctx->files[handle_index];
    file->fd             = fd;
    file->writable       = 1;
    /* Phase-105: the reopen above already refused unless this endpoint allows
     * writes (see brix_ensure_write_handle), so the secondary's handle carries
     * the same ALLOWED posture the primary's does — recorded, not re-derived,
     * because the per-op gate reads only the handle. */
    file->mutation_policy = BRIX_VFS_MUTATION_ALLOWED;
    file->readable       = shared->readable ? 1 : 0;
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
                   "brix: bound handle=%d reopened WRITABLE shared path=%s",
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

/* brix_revalidate_bound_write_handle — the bound-secondary half of
 * brix_ensure_write_handle. Re-checks the primary's published entry on every
 * write: an absent entry or a published read-only one revokes the local handle
 * (free + NGX_DECLINED); a stale-but-still-published one is reopened as a fresh
 * matching O_WRONLY fd. Callers have already established that ctx is bound and
 * that the server permits writes. */

static ngx_int_t
brix_revalidate_bound_write_handle(brix_ctx_t *ctx, ngx_connection_t *c,
    int handle_index)
{
    brix_shared_handle_entry_t shared;

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

    /* A published read-only handle is a data channel a bound conn may only read. */
    if (!shared.writable) {
        if (ctx->files[handle_index].fd >= 0
            && ctx->files[handle_index].writable)
        {
            brix_free_fhandle(ctx, handle_index);
        }
        return NGX_DECLINED;
    }

    if (brix_local_file_matches_shared_write_handle(&ctx->files[handle_index],
                                                      &shared))
    {
        return NGX_OK;
    }

    if (ctx->files[handle_index].fd >= 0
        || ctx->files[handle_index].path != NULL)
    {
        brix_free_fhandle(ctx, handle_index);
    }

    return brix_reopen_bound_write_handle(ctx, c, handle_index, &shared);
}

/* brix_ensure_write_handle — Phase 94 write-side mirror of brix_ensure_read_handle.
 * For an unbound (primary) session the write handle is already open locally, so
 * NGX_OK iff a kernel fd / driver object / staged writer exists. For a bound
 * secondary, re-validate against the primary's shared WRITABLE entry every write:
 * a published-read-only or absent entry → revoke (NGX_DECLINED); a stale-but-still-
 * published entry → reopen a fresh matching O_WRONLY fd. Invariant: a bound
 * secondary never writes a handle the primary did not publish as writable. */
ngx_int_t
brix_ensure_write_handle(brix_ctx_t *ctx, ngx_connection_t *c,
    int handle_index)
{
    ngx_stream_brix_srv_conf_t *conf;

    if (handle_index < 0 || handle_index >= BRIX_MAX_FILES) {
        return NGX_DECLINED;
    }

    /*
     * brix_read_only takes priority over EVERY write-side path, including this
     * one, and it does so directly rather than by implication.
     *
     * On a read-only server no writable handle can be published in the first
     * place (brix_open_mode_guard refuses a write open before a handle exists),
     * so the shared-entry lookup below would already decline — but that is a
     * DERIVED guarantee, and this function is reached from the recv-header hook
     * (brix_recv_write_hdr_hook) which runs BEFORE brix_dispatch_require_write
     * arms the allow_write gate. Checking allow_write here makes the ordering
     * irrelevant: no read-only server ever reaches an O_WRONLY reopen, whatever
     * a bound secondary sends and in whatever order.
     */
    conf = ngx_stream_get_module_srv_conf(ctx->session, ngx_stream_brix_module);
    if (conf == NULL || !conf->common.allow_write) {
        return NGX_DECLINED;
    }

    if (!ctx->is_bound) {
        return (ctx->files[handle_index].fd >= 0
                || ctx->files[handle_index].sd_obj.driver != NULL
                || ctx->files[handle_index].writer != NULL)
               ? NGX_OK : NGX_DECLINED;
    }

    return brix_revalidate_bound_write_handle(ctx, c, handle_index);
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
            && ctx->files[handle_index].writer == NULL))
    {
        /* A driver-backed handle (object/remote backend) is "open" with no kernel
         * fd — data I/O routes through sd_obj.driver, so fd < 0 is normal there.
         * A whole-object staged write handle (writer != NULL) is likewise "open"
         * with no fd — byte I/O routes through the write session (phase-70). */
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
    /* Phase 94: a bound secondary carrying a write reopens the primary's
     * published writable handle in this worker (mirror of the read path). A
     * primary session short-circuits (its handle is already open locally). */
    if (ctx->is_bound) {
        ngx_int_t ensure_rc = brix_ensure_write_handle(ctx, c, handle_index);
        if (ensure_rc != NGX_OK) {
            if (ensure_rc == NGX_ERROR) {
                BRIX_BAIL_ERR(ctx, c, op, verb, "-", "-", kXR_ServerError,
                                "could not prepare write handle", rc);
            }
            BRIX_BAIL_ERR(ctx, c, op, verb, "-", "-", kXR_FileNotOpen,
                            "invalid file handle", rc);
        }
    }

    if (!brix_validate_file_handle(ctx, c, handle_index, verb, op, rc)) {
        return 0;
    }

    if (!ctx->files[handle_index].writable) {
        BRIX_BAIL_ERR(ctx, c, op, verb, ctx->files[handle_index].path, "-",
                        kXR_NotAuthorized, "file not open for writing", rc);
    }

    /*
     * Phase-105: the endpoint gate for every handle-based mutation — kXR_write,
     * writev, pgwrite, truncate, sync, chkpoint and the CLONE destination all
     * reach the I/O core through this one validator, so gating here refuses
     * BEFORE a job is posted (W2) rather than after a worker thread has already
     * touched the file. The posture is the handle's own copy: a reload that
     * turns the export read-only under an open write handle is answered
     * kXR_fsReadOnly on the next op, and never with kXR_NotAuthorized, which
     * would be indistinguishable from an authorization failure.
     */
    if (brix_vfs_require_carried_mutation(
            ctx->files[handle_index].mutation_policy, BRIX_PROTO_ROOT,
            BRIX_VFS_MUTATE_WRITE) != NGX_OK)
    {
        BRIX_BAIL_ERR(ctx, c, op, verb, ctx->files[handle_index].path, "-",
                        kXR_fsReadOnly, "read-only export", rc);
    }

    return 1;
}

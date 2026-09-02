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

/* brix_files_ensure — lazily allocate the fixed handle table (see fd_table.h).
 * pcalloc zeroes the block, so only the two -1 sentinels need explicit init;
 * once allocated the address never changes (AIO tasks hold brix_file_t
 * pointers across worker threads, so a growable table would dangle them). */
ngx_int_t
brix_files_ensure(brix_ctx_t *ctx, ngx_connection_t *c)
{
    int  i;

    if (ctx->files != NULL) {
        return NGX_OK;
    }

    ctx->files = ngx_pcalloc(c->pool, BRIX_MAX_FILES * sizeof(brix_file_t));
    if (ctx->files == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < BRIX_MAX_FILES; i++) {
        ctx->files[i].fd = -1;                     /* fd < 0 == slot free */
        ctx->files[i].shared_handle_slot_hint = -1;  /* Phase 33 C2: no cache yet */
    }

    return NGX_OK;
}

/* brix_alloc_fhandle — return the first free slot in ctx->files; the index becomes
 * the one-byte on-wire fhandle, so it is bounded by BRIX_MAX_FILES. -1 when all
 * slots are occupied. Single-owner per connection (event thread, no locking); a
 * slot is only reused once its handle is fully torn down (brix_free_fhandle). */
int
brix_alloc_fhandle(brix_ctx_t *ctx)
{
    int handle_index;

    if (brix_files_ensure(ctx, ctx->session->connection) != NGX_OK) {
        return -1;
    }

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

    if (ctx->files == NULL) {
        return 0;
    }

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
        || path == NULL || ctx->files == NULL)
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

/* The bound-secondary machinery — brix_ensure_{read,write}_handle and the
 * shared-entry match/confined-reopen helpers behind them — lives in the
 * sibling fd_table_bound.c (split for the coding-standards §1 size cap). */


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
        || ctx->files == NULL
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

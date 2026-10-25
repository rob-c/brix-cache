/* VFS policy/authorization boundary for portable persisted lock transactions.
 * Non-local storage retains its existing credential-aware xattr implementation;
 * local mapped storage executes the same transaction in the owner's broker.
 * A declined dispatch never grants mutation authority.
 */
#include "vfs_internal.h"
#include "fs/backend/posix/lock_store.h"
#include "auth/impersonate/impersonate.h"

/* WHAT: Open the exact local inode selected by the export's storage owner.
 * WHY: Explicit POSIX instances must retain their root and N2N translation;
 * the implicit local path has no instance to supply either.
 * HOW: Use the confined VFS open for implicit storage, otherwise translate
 * through the existing N2N seam and ask the POSIX backend for a private fd.
 */
static int
lock_store_open(brix_vfs_ctx_t *ctx)
{
    char physical[PATH_MAX];

    if (ctx->sd == NULL) {
        return brix_vfs_open_fd(ctx->log, ctx->root_canon,
            brix_vfs_ctx_path(ctx), O_RDONLY | O_NONBLOCK | O_NOFOLLOW, 0);
    }
    if (brix_path_resolved_to_pfn(ctx, brix_vfs_ctx_path(ctx), physical,
                                 sizeof(physical)) != NGX_OK) {
        return -1;
    }
    return brix_sd_posix_open_lock_fd(ctx->sd, physical);
}

/* WHAT: Observe one completed local transaction without losing its errno.
 * WHY: Refusals and failed opens need the same accounting as successful writes.
 * HOW: Preserve errno, emit the existing VFS xattr observation, then restore it.
 */
static ngx_int_t
lock_store_observe(brix_vfs_ctx_t *ctx, uint64_t started, int result, size_t bytes)
{
    int saved_errno = result == 0 ? 0 : errno;
    brix_vfs_observe_ctx_op(ctx, brix_vfs_ctx_path(ctx), BRIX_METRIC_OP_XATTR,
        NULL, bytes, result == 0 ? NGX_OK : NGX_ERROR, saved_errno, started);
    errno = saved_errno;
    return result == 0 ? NGX_OK : NGX_ERROR;
}

/* WHAT: Encode one optional, bounded record or refuse malformed caller input.
 * WHY: The public VFS boundary must not scan past an unterminated field.
 * HOW: NULL means no record; check fixed-array bounds before shared encoding.
 */
static int
lock_store_encode(const brix_lock_record_t *record, char *output, size_t capacity)
{
    if (record == NULL) {
        output[0] = '\0';
        return 0;
    }
    if (record->token[0] == '\0'
        || memchr(record->token, 0, sizeof(record->token)) == NULL
        || memchr(record->owner, 0, sizeof(record->owner)) == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    if (brix_lock_record_encode(record, output, capacity) != NGX_OK) {
        errno = EOVERFLOW;
        return -1;
    }
    return 0;
}

/* WHAT: Preserve the exact snapshot on the expected side of compare/exchange.
 * WHY: Decoding may normalize a legacy expiry or ignore future fields; encoding
 * that semantic record would never match the persisted bytes being replaced.
 * HOW: Copy a bounded, NUL-free observed value; only constructed records encode.
 * Replacement records always use lock_store_encode, never this snapshot. */
static int
lock_store_expected(const brix_lock_record_t *record, char *output, size_t capacity)
{
    if (record == NULL || record->observed_length == 0) {
        return lock_store_encode(record, output, capacity);
    }
    if (record->observed_length >= sizeof(record->observed)
        || record->observed_length >= capacity
        || memchr(record->observed, '\0', record->observed_length) != NULL)
    {
        errno = EINVAL;
        return -1;
    }
    memcpy(output, record->observed, record->observed_length);
    output[record->observed_length] = '\0';
    return 0;
}

/* WHAT: Open one confined inode and apply the already-encoded transaction.
 * WHY: Descriptor lifetime and errno must remain independent of protocol code.
 * HOW: Nonblocking no-follow open, backend CAS, close, restore the verdict.
 */
static int
lock_store_change(brix_vfs_ctx_t *ctx, const char *previous, const char *next)
{
    int descriptor = lock_store_open(ctx);
    int result, saved_errno;

    if (descriptor < 0) {
        return -1;
    }
    result = brix_posix_lock_store_update_fd(descriptor,
        previous[0] == '\0' ? NULL : previous, strlen(previous),
        next[0] == '\0' ? NULL : next, strlen(next));
    saved_errno = result == 0 ? 0 : errno;
    (void) close(descriptor);
    errno = saved_errno;
    return result;
}

/* WHAT: Execute the exact encoded transaction in the mapped owner's helper.
 * WHY: A worker-held fd does not grant the owner's xattr write credentials.
 * HOW: Preserve the implicit root or translate through the configured POSIX
 * instance before using its broker-owned physical namespace. */
static int
lock_store_broker_change(brix_vfs_ctx_t *ctx, const char *previous, const char *next)
{
    char physical[PATH_MAX];

    if (ctx->sd == NULL) {
        return brix_imp_lock_store_update(ctx->log, ctx->root_canon,
            brix_vfs_ctx_path(ctx), previous, next);
    }
    if (brix_path_resolved_to_pfn(ctx, brix_vfs_ctx_path(ctx), physical,
                                 sizeof(physical)) != NGX_OK)
    {
        return -1;
    }
    return brix_sd_posix_broker_lock_store_update(ctx->sd, physical, previous, next);
}

/* WHAT: Change a local lock record after the normal VFS mutation gates.
 * WHY: Protocol code must not implement its own storage, authorization or
 * inode selection. The native xattr PAL intentionally keeps rejecting flags
 * which its kernel cannot implement for arbitrary, non-cooperating writers.
 * HOW: Gate first; route mapped local operations to the broker, otherwise
 * confined-open a fresh fd; execute the serialized backend transaction;
 * observe and preserve errno.
 */
ngx_int_t
brix_vfs_lock_store_update(brix_vfs_ctx_t *ctx,
    const brix_lock_record_t *expected, const brix_lock_record_t *replacement)
{
    char previous[BRIX_LOCK_XATTR_MAXLEN], next[BRIX_LOCK_XATTR_MAXLEN];
    uint64_t started = brix_vfs_now_ns();
    int result;

    if (brix_vfs_require_confined(ctx) != NGX_OK
        || brix_vfs_gate_mutation(ctx, BRIX_VFS_MUTATE_XATTR) != NGX_OK
        || brix_vfs_require_unlocked(ctx, BRIX_VFS_MUTATE_XATTR) != NGX_OK)
    {
        return lock_store_observe(ctx, started, -1, 0);
    }
    /* Match the existing xattr dispatch: POSIX has no backend-secret slots.
     * A default credential-directory pointer alone does not make it remote.
     * Broker identity and non-POSIX credential dispatch must stay authoritative. */
    if (brix_vfs_ctx_driver(ctx) != NULL) {
        errno = ENOTSUP;
        return NGX_DECLINED;
    }
    if (expected == NULL && replacement == NULL) {
        errno = EINVAL;
        return lock_store_observe(ctx, started, -1, 0);
    }
    if (lock_store_expected(expected, previous, sizeof(previous)) != 0
        || lock_store_encode(replacement, next, sizeof(next)) != 0) {
        return lock_store_observe(ctx, started, -1, 0);
    }
    result = brix_imp_client_active()
        ? lock_store_broker_change(ctx, previous, next)
        : lock_store_change(ctx, previous, next);
    return lock_store_observe(ctx, started, result, strlen(next));
}

/* Internal VFS observation helpers; include only through vfs_internal.h. */
#ifndef BRIX_VFS_INTERNAL_H
#error "include vfs_internal.h, not vfs_observe_internal.h directly"
#endif
#ifndef BRIX_VFS_OBSERVE_INTERNAL_H
#define BRIX_VFS_OBSERVE_INTERNAL_H

/* Pick the protocol label for this ctx's metrics, defaulting to
 * BRIX_PROTO_ROOT when ctx is NULL or its metrics_proto is out of range. */
static ngx_inline brix_proto_t
brix_vfs_metrics_proto(const brix_vfs_ctx_t *ctx)
{
    if (ctx == NULL || ctx->metrics_proto >= BRIX_PROTO_COUNT) {
        return BRIX_PROTO_ROOT;
    }

    return ctx->metrics_proto;
}

/* phase-56 D-1: a real monotonic timestamp in NANOseconds for op-latency.
 * Replaces the cached ngx_current_msec, which (a) only advances on event-loop
 * ticks — so a synchronous metadata op that never yields reported 0 µs — and
 * (b) is millisecond-resolution, quantizing the whole sub-ms band to 0/1000 µs.
 * CLOCK_MONOTONIC is vDSO-backed (~20 ns/call, lost in the syscalls the op
 * already makes) and gives honest sub-µs deltas. NOT CLOCK_MONOTONIC_COARSE —
 * that is also ~1-4 ms granularity and would only fix (a), not the resolution. */
static ngx_inline uint64_t
brix_vfs_now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000000000ull + (uint64_t) ts.tv_nsec;
}

/* Latency since start_ns in MICROseconds (start is an brix_vfs_now_ns()
 * snapshot). Clamps to 0 if the monotonic clock appears to have gone backwards. */
static ngx_inline ngx_msec_t
brix_vfs_elapsed_usec(uint64_t start_ns)
{
    uint64_t now_ns = brix_vfs_now_ns();

    if (now_ns < start_ns) {
        return 0;
    }

    return (ngx_msec_t) ((now_ns - start_ns) / 1000ull);
}

/* Post-op observer: derive the error class from rc/sys_errno, compute latency
 * from start_msec, then emit one metric (brix_metric_op_done) and one access
 * log line (brix_access_log_emit) for op. bytes is the transferred count;
 * result may be NULL. Borrows path (does not copy). Restores errno=sys_errno on
 * return so the caller can propagate it unchanged.
 *
 * ctx == NULL means there is no request context — an internal maintenance op
 * (e.g. the integrity code persisting checksum sidecars via the NULL-ctx
 * f-xattr variants). Those are not client I/O: observing them would default
 * the proto label to "stream" and misattribute s3/webdav-triggered sidecar
 * touches, so they are deliberately not metered or access-logged. */
static ngx_inline void
brix_vfs_observe_ctx_op_ex(const brix_vfs_ctx_t *ctx, const char *path,
    brix_metric_op_t op, const brix_vfs_io_result_t *result,
    size_t bytes, ngx_int_t rc, int sys_errno, uint64_t start_ns,
    unsigned meter_io)
{
    brix_err_class_t err;
    ngx_msec_t         latency_usec;

    if (ctx == NULL) {
        errno = sys_errno;
        return;
    }

    err = rc == NGX_OK ? BRIX_ERR_NONE
                       : brix_metric_err_from_errno(sys_errno);
    latency_usec = brix_vfs_elapsed_usec(start_ns);

    /* phase-106 W1 / phase-110 W1-W4: fold this op into the request's or
     * session's I/O monitor, which the uniform $brix_* variables read at log
     * time (io_monitor.h). NULL monitor = an unmonitored path (metadata-only
     * builders, internal maintenance) and is the common case; every helper
     * below is a silent no-op on NULL.
     *   - op/path/outcome: candidate primary op under the weight rule, on
     *     success AND failure (a failed stat on a GET of a missing file is the
     *     outcome the operator wants: op=stat status=not_found).
     *   - backend time: successful ops only — a failed op's latency is error
     *     handling, not backend service time.
     *   - received bytes: a successful WRITE's count is what the client sent
     *     (the staged PUT commit observes its total once; a GET's cache fill
     *     writes through its own unmonitored ctx, so it never lands here).
     *   - SERVED bytes are deliberately NOT folded here: the client-facing
     *     serve is zero-copy (sendfile / output filter) and never reaches this
     *     observer, so the plane books result->bytes_sent at its serve site.
     * Single-writer contract: see io_monitor.h. */
    brix_io_monitor_record_op(ctx->io_monitor, op, path, err);
    if (rc == NGX_OK) {
        brix_io_monitor_add_latency(ctx->io_monitor, latency_usec);
        if (op == BRIX_METRIC_OP_WRITE) {
            brix_io_monitor_add_received(ctx->io_monitor, bytes);
        }
    }

    /* meter_io == 0: the owning protocol books the unified io_ops/latency row
     * for this operation itself (data-plane READ/WRITE via *_metrics_response,
     * bytes via the per-protocol wire-ledger fold), so emitting it here too
     * would double-count. Backend byte totals and the access-log line stay
     * VFS-owned either way. */
    if (meter_io) {
        brix_metric_op_done(brix_vfs_metrics_proto(ctx), op, bytes,
                              latency_usec, err);
    }

    /* Per-backend storage byte totals (staged-commit writes, VFS-metered
     * reads). ctx->sd == NULL is the default-POSIX instance. */
    if (rc == NGX_OK && bytes > 0) {
        brix_metric_backend_bytes(
            ctx != NULL && ctx->sd != NULL ? brix_sd_backend_name(ctx->sd)
                                           : "posix",
            op, bytes);
    }

    brix_access_log_emit(ctx, path, op, result, bytes, err, latency_usec);

    errno = sys_errno;
}

/* Full observer: metric + backend bytes + access log. */
static ngx_inline void
brix_vfs_observe_ctx_op(const brix_vfs_ctx_t *ctx, const char *path,
    brix_metric_op_t op, const brix_vfs_io_result_t *result,
    size_t bytes, ngx_int_t rc, int sys_errno, uint64_t start_ns)
{
    brix_vfs_observe_ctx_op_ex(ctx, path, op, result, bytes, rc, sys_errno,
                                 start_ns, 1);
}

/* Handle-keyed convenience wrapper for brix_vfs_observe_ctx_op: pulls ctx and
 * path from fh (tolerating fh==NULL). Same errno-restoring semantics. */
static ngx_inline void
brix_vfs_observe_file_op(const brix_vfs_file_t *fh,
    brix_metric_op_t op, const brix_vfs_io_result_t *result,
    size_t bytes, ngx_int_t rc, int sys_errno, uint64_t start_ns)
{
    brix_vfs_observe_ctx_op(fh != NULL ? fh->ctx : NULL,
                              fh != NULL ? fh->path : NULL,
                              op, result, bytes, rc, sys_errno, start_ns);
}

#endif /* BRIX_VFS_OBSERVE_INTERNAL_H */

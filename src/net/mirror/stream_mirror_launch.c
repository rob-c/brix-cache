/*
 * stream_mirror_launch.c — Phase 24 XRootD stream mirror: eligibility gates and
 * per-target launch (see stream_mirror.h / stream_mirror_internal.h).
 *
 * WHAT: Owns the "should we mirror this request, and if so to whom" policy: the
 *       opcode->bit classifier, the replayability predicate, the write-op gate,
 *       the collapsed eligibility ladder, the per-target context allocation +
 *       request snapshot, and the public brix_stream_mirror_maybe() fan-out hook
 *       called after the primary handler has answered the client.
 * WHY:  split out (phase-79 file-size cap) from the async shadow-connection state
 *       machine in stream_mirror.c so each file owns one concept under the
 *       500-line cap.  This file decides WHAT to replay and hands a ready mir
 *       context to brix_mir_start(); stream_mirror.c owns HOW the shadow exchange
 *       runs.  The two share only the symbols in stream_mirror_internal.h.
 * HOW:  brix_stream_mirror_maybe -> brix_stream_mirror_eligible (guard ladder) ->
 *       per-target brix_stream_mirror_launch_target -> brix_mir_start.  Pure
 *       policy predicates (opcode_bit, request_replayable, write_op_allowed) feed
 *       the eligibility gate; the only side effects are the sample-drop metric
 *       and the launch itself.
 */
#include "stream_mirror.h"

#include <netdb.h>
#include <sys/socket.h>

#include "stream_mirror_internal.h"
#include "observability/metrics/metrics_macros.h"


/* opcode filter */
static ngx_uint_t
brix_mirror_opcode_bit(uint16_t reqid)
{
    switch (reqid) {
    case kXR_stat:    return BRIX_MIRROR_OP_STAT;
    case kXR_locate:  return BRIX_MIRROR_OP_LOCATE;
    case kXR_open:    return BRIX_MIRROR_OP_OPEN;
    case kXR_read:    return BRIX_MIRROR_OP_READ;
    case kXR_readv:   return BRIX_MIRROR_OP_READV;
    case kXR_dirlist: return BRIX_MIRROR_OP_DIRLIST;
    case kXR_statx:   return BRIX_MIRROR_OP_STATX;
    case kXR_query:   return BRIX_MIRROR_OP_QUERY;
    /* Write/mutation opcodes (Phase 24 write mirroring, gated by
     * brix_mirror_writes).  mkdir/rm/rmdir/mv/truncate/chmod are self-contained
     * path-based metadata ops replayable by this stateless mirror; data writes
     * (open-write/write/pgwrite/close) map to OP_WRITE but are handled by the
     * stateful write-mirror (W3), not here. */
    case kXR_mkdir:    return BRIX_MIRROR_OP_MKDIR;
    case kXR_rm:       return BRIX_MIRROR_OP_RM;
    case kXR_rmdir:    return BRIX_MIRROR_OP_RMDIR;
    case kXR_mv:       return BRIX_MIRROR_OP_MV;
    case kXR_truncate: return BRIX_MIRROR_OP_TRUNCATE;
    case kXR_chmod:    return BRIX_MIRROR_OP_CHMOD;
    default:          return 0;
    }
}

/* Write-implying open flags.  A read-path mirror must never replay these to a
 * shadow: they would create/truncate/append/mkdir on the official server. */
#define BRIX_MIRROR_OPEN_WRITE_FLAGS \
    (kXR_delete | kXR_new | kXR_open_updt | kXR_open_apnd | kXR_mkpath)

/*
 * Can this request be faithfully replayed to a fresh shadow session?
 *
 * The mirror is stateless — it opens a new connection, bootstraps, and sends ONE
 * saved request frame.  That only works for SELF-CONTAINED, side-effect-free
 * requests whose target lives entirely in the frame:
 *
 *   - locate / dirlist / query (incl. Qcksum) : path + args are in the payload.
 *   - stat / statx with dlen>0                : path-based (dlen==0 is by open
 *                                               handle and cannot be replayed).
 *   - open WITHOUT write flags                : a read-only open of a path.
 *
 * Handle-based ops (read, readv, stat/statx by handle) carry the CLIENT's file
 * handle, which is meaningless on the shadow's separate session, and write/
 * create opens would mutate the official server.  Neither is replayable by a
 * stateless mirror, so they are skipped — this is what lets the mirror "just
 * work" in front of an official xrootd instead of spuriously diverging.
 */
static int
brix_mirror_request_replayable(brix_ctx_t *ctx)
{
    switch (ctx->recv.cur_reqid) {
    case kXR_locate:
    case kXR_dirlist:
    case kXR_query:
        return 1;
    case kXR_stat:
    case kXR_statx:
        return ctx->recv.cur_dlen > 0;
    case kXR_open: {
        uint16_t options;     /* ClientOpenRequest.options — header byte 6 */
        ngx_memcpy(&options, ctx->recv.hdr_buf + 6, sizeof(options));
        options = ntohs(options);
        return (options & BRIX_MIRROR_OPEN_WRITE_FLAGS) == 0;
    }
    /* Metadata mutations (W1): self-contained and path-based — the path[s] live
     * in the payload, so a fresh shadow session replays them faithfully.
     * truncate may instead be by open-handle (dlen==0); that form is not
     * replayable, same as handle-based stat.  These reach here only when
     * brix_mirror_writes is on (gated in brix_stream_mirror_maybe). */
    case kXR_mkdir:
    case kXR_rm:
    case kXR_rmdir:
    case kXR_mv:
    case kXR_chmod:
    case kXR_truncate:
        return ctx->recv.cur_dlen > 0;
    default:
        return 0;
    }
}


/* launch hook (called from dispatch.c) */

/*
 * Is this write/mutation opcode cleared to proceed on the one-shot mirror?
 *
 * WHAT: for a WRITE-class @opbit, return 1 only when brix_mirror_writes is on
 *       AND the op is a self-contained metadata mutation (not OP_WRITE); for
 *       any non-write opcode return 1 unconditionally.
 * WHY:  write mirroring needs a second, independent gate beyond the opcode
 *       allowlist, and data writes (OP_WRITE) belong to the stateful write-
 *       mirror, never this stateless path — factoring it keeps the driver flat.
 * HOW:  short-circuits on the non-write case; otherwise checks the flag and
 *       excludes OP_WRITE.
 */
static int
brix_mirror_write_op_allowed(ngx_uint_t opbit,
    ngx_stream_brix_srv_conf_t *conf)
{
    if ((opbit & BRIX_MIRROR_OP_WRITE_ALL) == 0) {
        return 1;
    }
    if (!conf->mirror.mirror_writes || opbit == BRIX_MIRROR_OP_WRITE) {
        return 0;
    }
    return 1;
}

/*
 * Decide whether the current request is eligible to be mirrored at all.
 *
 * WHAT: run every fast-reject gate (feature off, opcode filtered, write-gate,
 *       non-replayable, oversized payload, sampling) and return 1 only when the
 *       request should proceed to per-target launch.
 * WHY:  collapses the whole guard ladder into one predicate so the launch
 *       driver expresses just "eligible? then fan out", not the policy.
 * HOW:  sequential early-returns; @opbit is returned to the caller so the launch
 *       path need not recompute it.  Emits the drop metric on sample loss.
 */
static int
brix_stream_mirror_eligible(brix_ctx_t *ctx,
    ngx_stream_brix_srv_conf_t *conf, ngx_uint_t *opbit_out)
{
    ngx_uint_t  opbit;

    if (!conf->mirror.enabled || conf->mirror.targets == NULL) {
        return 0;
    }

    opbit = brix_mirror_opcode_bit(ctx->recv.cur_reqid);
    /* Mirror all ops in opcode_mask (default ALL) that are not de-selected via
     * brix_mirror_exclude_opcodes. */
    if (opbit == 0
        || (conf->mirror.opcode_mask & opbit) == 0
        || (conf->mirror.opcode_exclude_mask & opbit) != 0)
    {
        return 0;
    }

    /* Second, independent guard for write/mutation opcodes: even if an operator
     * lists e.g. "mkdir" in brix_mirror_opcodes, it stays inert unless
     * brix_mirror_writes is explicitly on (and the shadow is an isolated
     * namespace).  OP_WRITE (data writes) is handled by the stateful write-mirror,
     * not this one-shot path, so it never proceeds here. */
    if (!brix_mirror_write_op_allowed(opbit, conf)) {
        return 0;
    }

    /* Only replay requests the shadow can answer standalone (path-based reads,
     * read-only opens, query/Qcksum).  Handle-based reads/readv/handle-stat and
     * write opens are skipped so the mirror never spuriously diverges against an
     * official xrootd — see brix_mirror_request_replayable(). */
    if (!brix_mirror_request_replayable(ctx)) {
        return 0;
    }

    /* Skip oversized payloads (write bodies); also a sanity guard. */
    if (ctx->recv.cur_dlen > BRIX_MIRROR_MAX_PAYLOAD) {
        return 0;
    }

    if (!brix_mirror_should_sample(conf->mirror.sample_pct)) {
        BRIX_MIR_METRIC_INC(mirror_stream_dropped_total);
        return 0;
    }

    *opbit_out = opbit;
    return 1;
}

/*
 * Allocate a mirror context, copy target + saved request into it, and start it.
 *
 * WHAT: for one resolved @target, create the mirror's private pool + ctx,
 *       snapshot the primary request frame (header, opcode, payload), and kick
 *       off brix_mir_start().  Unresolved targets and OOM are skipped silently.
 * WHY:  isolates the per-target allocation/snapshot from the fan-out loop, so
 *       the driver is a flat iteration and each launch owns its own cleanup.
 * HOW:  a fresh cycle-pool ctx (outlives the client conn); the request payload
 *       is copied now because ctx->recv.payload may be reused before the shadow
 *       exchange completes.
 */
static void
brix_stream_mirror_launch_target(brix_ctx_t *ctx,
    brix_mirror_target_t *target, ngx_stream_brix_srv_conf_t *conf,
    int primary_ok)
{
    ngx_pool_t            *pool;
    brix_stream_mirror_t  *mir;

    if (target->socklen == 0) {
        return;   /* unresolved target */
    }

    pool = ngx_create_pool(2048, ngx_cycle->log);
    if (pool == NULL) {
        return;
    }
    mir = ngx_pcalloc(pool, sizeof(*mir));
    if (mir == NULL) {
        ngx_destroy_pool(pool);
        return;
    }
    mir->pool        = pool;
    mir->log         = ngx_cycle->log;   /* outlives the client connection */
    mir->phase       = XRD_MIR_HANDSHAKE;
    mir->primary_ok  = primary_ok;
    mir->log_diverge = conf->mirror.log_diverge;
    mir->port        = target->port;
    mir->socklen     = target->socklen;
    ngx_memcpy(&mir->sockaddr, &target->sockaddr, target->socklen);
    ngx_cpystrn((u_char *) mir->host,
                target->host.data ? target->host.data
                                  : (u_char *) "?",
                sizeof(mir->host));

    /* Snapshot the request now — ctx->recv.payload may be reused by the next
     * request before the shadow exchange completes. */
    ngx_memcpy(mir->saved_hdr, ctx->recv.hdr_buf, 24);
    mir->saved_opcode = ctx->recv.cur_reqid;
    if (ctx->recv.payload != NULL && ctx->recv.cur_dlen > 0) {
        mir->saved_payload = ngx_palloc(pool, ctx->recv.cur_dlen);
        if (mir->saved_payload != NULL) {
            ngx_memcpy(mir->saved_payload, ctx->recv.payload, ctx->recv.cur_dlen);
            mir->saved_dlen = ctx->recv.cur_dlen;
        }
    }

    brix_mir_start(mir, conf->mirror.timeout_ms);
}

void
brix_stream_mirror_maybe(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, ngx_int_t primary_rc)
{
    brix_mirror_target_t *targets;
    ngx_uint_t              opbit = 0, i;
    int                     primary_ok;

    (void) c;

    if (!brix_stream_mirror_eligible(ctx, conf, &opbit)) {
        return;
    }
    (void) opbit;   /* eligibility owns opcode policy; driver just fans out */

    primary_ok = (primary_rc != NGX_ERROR);
    targets    = conf->mirror.targets->elts;

    for (i = 0; i < conf->mirror.targets->nelts; i++) {
        brix_stream_mirror_launch_target(ctx, &targets[i], conf, primary_ok);
    }
}

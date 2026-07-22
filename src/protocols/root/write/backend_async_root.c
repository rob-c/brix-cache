/*
 * backend_async_root.c — root:// park/resume adapter for the durable
 * backend-async mutation queue (see fs/xfer/backend_async_queue.{c,h}).
 *
 * WHAT: Bridges a kXR_rm / kXR_rmdir request into the backend-async queue: on
 *       enqueue the connection is parked in XRD_ST_WAITING_BAQ (the recv loop
 *       yields on that state, half-duplex, so no further PDU is read and the
 *       request's streamid stays current); when the batch flushes, the waker
 *       (baq_root_done) sends the real reply on that streamid and resumes reads.
 *
 * WHY:  The reply must be delivered LATE on the original streamid after the bulk
 *       backend flush. root:// is half-duplex per connection, so simply not
 *       replying parks the synchronous client in recv — exactly the "block until
 *       flush" contract — with no interim kXR_wait/waitresp needed.
 *
 * HOW:  One park record per connection (ctx->baq_park), reused across sequential
 *       async mutations (only one can be in flight at a time). It is the queue's
 *       opaque `client` token and is read back by the waker. On teardown the
 *       disconnect funnel calls brix_baq_drop_client(ctx->baq_park) so the flush
 *       never wakes a freed connection; the durable journal record stays on disk
 *       and replays at the next flush or at boot.
 *
 * NOTE: The queued syscall runs in the worker's own credential context at drain
 *       time (the per-request impersonation broker state is not captured across
 *       the park). Authorization is still enforced synchronously by brix_auth_gate
 *       BEFORE the enqueue, so an unauthorized mutation is never queued; but an
 *       export that relies on per-user impersonation for the mutation ITSELF
 *       should not enable brix_backend_async.
 */

#include "backend_async_root.h"
#include "protocols/root/response/response.h"        /* brix_send_ok / _error   */
#include "protocols/root/connection/event_sched.h"   /* brix_schedule_read_resume */
#include "core/compat/error_mapping.h"               /* brix_kxr_from_errno     */
#include "core/compat/err_strings.h"                 /* brix_kxr_err_string     */
#include "fs/xfer/backend_async_queue.h"             /* brix_baq_enqueue        */
#include "fs/path/path.h"                            /* brix_log_access         */

#include <errno.h>
#include <limits.h>
#include <stdio.h>

/* Per-connection park record: everything the waker needs to send the late reply
 * on the original streamid (which ctx->recv.cur_streamid still holds — the recv
 * loop reads no new PDU while WAITING_BAQ). */
typedef struct {
    brix_ctx_t       *ctx;
    ngx_connection_t *c;
    ngx_uint_t        op_id;               /* BRIX_OP_RM / _RMDIR / _MV slot     */
    const char       *verb;                /* "RM" / "RMDIR" / "MV" (static)     */
    brix_baq_op_t     baq_op;              /* for RMDIR ENOENT→OK idempotency    */
    char              resolved[PATH_MAX];  /* access-log path (src for MV)       */
    char              detail[PATH_MAX];    /* access-log detail ("-" or MV dst)  */
} brix_baq_root_park_t;

/*
 * baq_root_done — the queue waker for a parked root:// mutation.
 *
 * Runs when the batch flushes (deferred posted event on the size trigger, or the
 * coalesce timer on the time trigger). Sends the real result on the parked
 * connection and re-arms its read loop. Mirrors op_table.c's exec_rmdir: a
 * missing RMDIR target is success (stock do_Rmdir tolerates ENOENT).
 */
static void
baq_root_done(void *client, int op_errno)
{
    brix_baq_root_park_t *park = client;
    brix_ctx_t           *ctx  = park->ctx;
    ngx_connection_t     *c    = park->c;

    if (op_errno == ENOENT && park->baq_op == BRIX_BAQ_RMDIR) {
        op_errno = 0;                      /* idempotent_missing (rmdir parity) */
    }

    /* Set REQ_HEADER before sending: brix_send_* overrides to XRD_ST_SENDING on a
     * partial write, and the recv handoff gate yields on SENDING until it drains
     * — the same ordering the CMS/FRM resume paths use. */
    ctx->state = XRD_ST_REQ_HEADER;

    if (op_errno == 0) {
        brix_log_access(ctx, c, park->verb, park->resolved, park->detail,
                        1, kXR_ok, NULL, 0);
        BRIX_OP_OK(ctx, park->op_id);
        (void) brix_send_ok(ctx, c, NULL, 0);
    } else {
        uint16_t    code = brix_kxr_from_errno(op_errno);
        const char *msg  = brix_kxr_err_string(op_errno);

        brix_log_access(ctx, c, park->verb, park->resolved, park->detail,
                        0, code, msg, 0);
        BRIX_OP_ERR(ctx, park->op_id);
        (void) brix_send_error(ctx, c, code, msg);
    }

    /* Leave ctx->baq_park pointing at this record — it is reused for the next
     * async mutation on this connection (brix_baq_drop_client is a no-op when
     * nothing is queued, so an unrelated later disconnect stays safe). */
    (void) brix_schedule_read_resume(c);
}

int
brix_root_backend_async_try(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const brix_op_desc_t *d,
    const char *resolved)
{
    brix_baq_root_park_t *park;
    brix_baq_op_t         baq_op;

    if (!conf->backend_async) {
        return 0;                          /* feature off — run inline */
    }

    /* Only namespace-removal mutations are queueable today. Anything else (CHMOD,
     * MKDIR-via-other-paths, …) runs synchronously. */
    switch (d->opcode) {
    case kXR_rm:    baq_op = BRIX_BAQ_UNLINK; break;
    case kXR_rmdir: baq_op = BRIX_BAQ_RMDIR;  break;
    default:        return 0;
    }

    /* One reused park record per connection (only one mutation is ever parked at
     * a time — WAITING_BAQ yields the recv loop, so a second is never read). */
    park = ctx->baq_park;
    if (park == NULL) {
        park = ngx_pcalloc(c->pool, sizeof(*park));
        if (park == NULL) {
            return 0;                      /* OOM — fall back to inline */
        }
        ctx->baq_park = park;
    }
    park->ctx    = ctx;
    park->c      = c;
    park->op_id  = d->op_id;
    park->verb   = d->name;
    park->baq_op = baq_op;
    (void) snprintf(park->resolved, sizeof(park->resolved), "%s", resolved);
    park->detail[0] = '-';
    park->detail[1] = '\0';

    /* Park BEFORE enqueue so any teardown that races the enqueue sees a consistent
     * WAITING_BAQ state. The size-triggered drain is a deferred posted event, so
     * the waker cannot fire before this call returns. */
    ctx->state = XRD_ST_WAITING_BAQ;

    if (brix_baq_enqueue(baq_op, conf->common.root_canon, resolved,
                         NULL /* no dst */, 0 /* mode */,
                         conf->backend_async_batch, conf->backend_async_wait,
                         baq_root_done, park) != NGX_OK)
    {
        ctx->state = XRD_ST_REQ_HEADER;    /* enqueue refused — un-park, run inline */
        return 0;
    }

    return 1;                              /* parked; caller returns NGX_OK */
}

int
brix_root_backend_async_mv_try(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *src_resolved,
    const char *dst_resolved)
{
    brix_baq_root_park_t *park;

    if (!conf->backend_async) {
        return 0;                          /* feature off — run inline */
    }

    /* Reuse the per-connection park record (only one mutation is ever parked at
     * a time — WAITING_BAQ yields the recv loop). The caller has already gated on
     * a NON-EXISTENT destination, so this is a pure create: the queue's
     * overwrite=0 rename can only succeed or fail source-side (ENOENT/ENOSPC/…),
     * whose generic errno→kXR mapping matches mv_execute exactly. The dst-exists
     * ladder (EEXIST/EISDIR/ENOTEMPTY) never reaches here — those stay inline. */
    park = ctx->baq_park;
    if (park == NULL) {
        park = ngx_pcalloc(c->pool, sizeof(*park));
        if (park == NULL) {
            return 0;                      /* OOM — fall back to inline */
        }
        ctx->baq_park = park;
    }
    park->ctx    = ctx;
    park->c      = c;
    park->op_id  = BRIX_OP_MV;
    park->verb   = "MV";
    park->baq_op = BRIX_BAQ_RENAME;
    (void) snprintf(park->resolved, sizeof(park->resolved), "%s", src_resolved);
    (void) snprintf(park->detail, sizeof(park->detail), "%s", dst_resolved);

    ctx->state = XRD_ST_WAITING_BAQ;

    if (brix_baq_enqueue(BRIX_BAQ_RENAME, conf->common.root_canon, src_resolved,
                         dst_resolved, 0 /* mode */, conf->backend_async_batch,
                         conf->backend_async_wait, baq_root_done, park) != NGX_OK)
    {
        ctx->state = XRD_ST_REQ_HEADER;    /* enqueue refused — un-park, run inline */
        return 0;
    }

    return 1;                              /* parked; caller returns NGX_OK */
}

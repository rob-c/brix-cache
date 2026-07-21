/*
 * cms/recv_prepare.c — forwarded staging ops (kYR_prepadd / kYR_prepdel) for
 * the CMS client-side (manager-connection) receive path.  Phase-89 W2 / PR-6.
 *
 * WHAT: A manager forwards a client's stage-in request down to this data node
 * as kYR_prepadd (Pup padArgs: ident, reqid, notify, prty, mode, path) and a
 * cancellation as kYR_prepdel (pdlArgs: ident, reqid).  prepadd admits the
 * path into the durable stage-request registry (the same store kXR_prepare
 * and the Tape REST API use — the recall itself is faulted by the sd_frm
 * backend on read); prepdel deletes that admission.  Replies match stock cmsd
 * XrdCmsNode::do_PrepAdd/do_PrepDel: silent on success AND on an idempotent
 * no-op delete; kYR_error only for a refused/undecodable prepadd.
 *
 * WHY: Plane-B staging parity (phase-61 W2).  The manager's reqid is NOT the
 * registry's reqid — the registry mints its own "<seq>.<pid>@<host>" id — so
 * the ADR-2b sidecar (reqid_map) carries cms_reqid → engine_reqid plus the
 * notify/prty fields the registry view has no columns for.
 *
 * HOW: cms_prep_path_ok is the pure path gate (absolute, bounded, no "..";
 * the registry records logical paths, so a lexical gate is the confinement
 * seam here — no filesystem I/O happens at admission).  cms_node_exec_prepare
 * decodes via the shared rrdata/node_ops planner and routes on plan->action.
 */

#include "cms_internal.h"
#include "recv_internal.h"
#include "node_ops.h"               /* shared forwarded-op planner */
#include "rrdata.h"                 /* Pup decode of forwarded payloads */
#include "reqid_map.h"              /* ADR-2b cms↔engine reqid sidecar */
#include "fs/xfer/stage_request_registry.h"

#include <time.h>

/* cms_prep_path_ok — lexical confinement gate for a forwarded stage path:
 * absolute, shorter than the registry's LFN cap, and free of ".." segments
 * (a hostile manager must not park an escape path in the durable store that
 * a later recall would resolve). Returns 1 = acceptable. */
static int
cms_prep_path_ok(const char *path)
{
    if (path == NULL || path[0] != '/'
        || ngx_strlen(path) >= BRIX_STAGE_LFN_LEN)
    {
        return 0;
    }
    return ngx_strstr(path, "..") == NULL;
}

/* cms_prep_add — admit a forwarded prepadd into the stage-request registry
 * and record the manager's reqid in the sidecar map. kYR_error on refusal,
 * silent on success (stock cmsd contract). */
static ngx_int_t
cms_prep_add(ngx_brix_cms_ctx_t *ctx, uint32_t streamid,
    const brix_cms_rrdata_t *d, const brix_cms_node_plan_t *plan)
{
    brix_stage_registry_t       *reg = brix_stage_registry_singleton();
    brix_stage_request_view_t    v;
    char                         engine_reqid[BRIX_STAGE_REQID_LEN];
    char                         ident[BRIX_STAGE_DN_LEN];

    if (reg == NULL) {
        return ngx_brix_cms_send_error(ctx, streamid, CMS_ERR_EINVAL,
                                         "no staging engine");
    }
    if (!cms_prep_path_ok(plan->path)) {
        return ngx_brix_cms_send_error(ctx, streamid, CMS_ERR_EINVAL,
                                         "prep path denied");
    }

    ngx_memzero(&v, sizeof(v));
    v.lfn = plan->path;

    /* The padArgs ident is the manager-forwarded requester identity; it
     * becomes the owner key so a later owner-checked cancel matches. */
    if (d->ident != NULL && d->ident_len > 0
        && d->ident_len < sizeof(ident))
    {
        ngx_memcpy(ident, d->ident, d->ident_len);
        ident[d->ident_len] = '\0';
        v.requester_dn = ident;
    }

    if (ctx->conf->frm.stage_ttl > 0) {
        v.tod_expire = (int64_t) time(NULL)
                     + (int64_t) (ctx->conf->frm.stage_ttl / 1000);
    }

    if (brix_stage_request_add(reg, &v, engine_reqid,
                                 sizeof(engine_reqid),
                                 ctx->cycle->log) != NGX_OK)
    {
        return ngx_brix_cms_send_error(ctx, streamid, CMS_ERR_EINVAL,
                                         "stage admission refused");
    }

    brix_cms_reqid_map_put(plan->reqid, engine_reqid,
                             plan->notify, plan->prty);

    ngx_log_error(NGX_LOG_INFO, ctx->cycle->log, 0,
                  "brix: CMS prepadd \"%s\" admitted (cms reqid \"%s\" -> "
                  "engine \"%s\")", plan->path, plan->reqid, engine_reqid);
    return NGX_OK;                               /* silent success */
}

/* cms_prep_del — consume the sidecar mapping and delete the registry row.
 * Idempotent and silent either way (an unknown reqid is stock-cmsd silence,
 * not an error — the request may have been reaped already). */
static ngx_int_t
cms_prep_del(ngx_brix_cms_ctx_t *ctx, const brix_cms_node_plan_t *plan)
{
    brix_stage_registry_t  *reg = brix_stage_registry_singleton();
    char                     engine_reqid[BRIX_STAGE_REQID_LEN];

    if (reg != NULL
        && brix_cms_reqid_map_take(plan->reqid, engine_reqid,
                                     sizeof(engine_reqid)))
    {
        (void) brix_stage_request_delete(reg, engine_reqid, ctx->cycle->log);
        ngx_log_error(NGX_LOG_INFO, ctx->cycle->log, 0,
                      "brix: CMS prepdel cms reqid \"%s\" -> engine \"%s\" "
                      "deleted", plan->reqid, engine_reqid);
    }
    return NGX_OK;                               /* idempotent, silent */
}

/* cms_node_exec_prepare — decode-then-route entry point the opcode dispatcher
 * calls for kYR_prepadd / kYR_prepdel (declared in recv_internal.h). */
ngx_int_t
cms_node_exec_prepare(ngx_brix_cms_ctx_t *ctx, u_char code,
    uint32_t streamid, const u_char *payload, size_t plen)
{
    brix_cms_rrdata_t     d;
    brix_cms_node_plan_t  plan;

    if (brix_cms_rrdata_parse(code, payload, plen, &d) != 0
        || brix_cms_node_plan(code, &d, &plan) != 0)
    {
        return ngx_brix_cms_send_error(ctx, streamid, CMS_ERR_EINVAL,
                                         "badly formed request");
    }

    if (plan.action == XRDCMS_NACT_PREPADD) {
        return cms_prep_add(ctx, streamid, &d, &plan);
    }
    return cms_prep_del(ctx, &plan);
}

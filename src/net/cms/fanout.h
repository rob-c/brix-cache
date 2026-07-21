#ifndef BRIX_CMS_FANOUT_H
#define BRIX_CMS_FANOUT_H

/*
 * cms/fanout.h — Phase-89 W8: manager-side rm/rmdir fan-out to all holders.
 *
 * WHAT: With brix_cms_fanout on, a client kXR_rm/kXR_rmdir arriving at a
 *       manager is forwarded (brix_cms_forward_to_node) to EVERY registered
 *       node whose exports cover the path, instead of redirecting the client
 *       to a single node — stock cmsd's "rm from all holders" semantics.
 * WHY:  with replicated paths (two nodes exporting "/"), the shipped redirect
 *       deletes exactly one replica and leaves the rest live — a later locate
 *       resurrects the "deleted" file.  Fan-out removes every copy.
 * HOW:  the node executor is SILENT on success and answers kYR_error on
 *       failure, so success cannot be positively counted; aggregation is a
 *       deadline window (brix_cms_fanout_window): the client is parked
 *       (pending table + XRD_ST_WAITING_CMS), every kYR_error folds into the
 *       slot (first error's code+text win, arrival order), and the finalizer —
 *       the window timer, or early when every forwarded node has errored —
 *       answers kXR_ok when no error arrived, else kXR_error with the folded
 *       text.
 *
 * SCOPE (v1, deliberate): only rm/rmdir (single-path, no mode), and only when
 * THIS worker owns CMS connections to every registry holder of the path —
 * per-worker aggregation needs no cross-worker signalling (same per-worker
 * design as the pending table / W3 node list).  Anything else falls back to
 * the shipped single-node redirect, which is always safe.
 */

#include "core/ngx_brix_module.h"

/*
 * Try to fan a manager-mode kXR_rm/kXR_rmdir out to all holder nodes.
 * Returns NGX_DECLINED (== BRIX_DISPATCH_CONTINUE) when fan-out does not
 * engage — off, wrong opcode, <2 holders, or this worker cannot reach every
 * holder — so the caller falls through to the single-node redirect.  Returns
 * NGX_AGAIN after a successful park (reply comes from the finalizer), or a
 * send result on an immediate reply.
 */
ngx_int_t brix_cms_fanout_mutation(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *path);

/*
 * Fold one kYR_error reply from a forwarded node into its aggregation slot
 * (matched by the CMS streamid); finalizes early when every forwarded node
 * has answered.  No-op for a streamid with no live slot (late reply after the
 * window closed).
 */
void brix_cms_fanout_note_error(uint32_t streamid, uint32_t ecode,
    const char *text, ngx_log_t *log);

#endif /* BRIX_CMS_FANOUT_H */

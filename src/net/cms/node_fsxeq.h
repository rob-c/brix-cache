#ifndef BRIX_CMS_NODE_FSXEQ_H
#define BRIX_CMS_NODE_FSXEQ_H

/*
 * node_fsxeq.h — 2.0 F17: the operator program that REPLACES this data node's
 * built-in execution of a manager-forwarded namespace op (stock cms.fsxeq).
 *
 * WHAT: brix_cms_fsxeq_dispatch() is consulted once per forwarded op, after the
 *       read-only mutation gate and before the storage leg is chosen.  When the
 *       op has no program the caller keeps its built-in leg unchanged; when it
 *       has one, this file owns the whole rest of the op — validation, the run,
 *       and the cmsd-shaped reply.
 * WHY:  a site's namespace semantics (catalogue update, quota hook, tape-aware
 *       unlink) may not be POSIX.  The refusal this reverses was made on
 *       performance and blast-radius grounds, so both constraints survive as
 *       requirements: the program NEVER runs on the worker's own thread, and it
 *       is never handed a path the built-in leg would have refused.
 * HOW:  the run is one brix_subprocess_run() on an nginx thread-pool task —
 *       that runner puts the program under a double-forked agent (nginx's
 *       master would otherwise reap a worker's direct child and steal the exit
 *       status), in its own session, with every inherited descriptor closed,
 *       and it SIGKILLs the program's whole process group at
 *       brix_cms_fsxeq_timeout.  The completion handler answers the manager on
 *       the event loop; a program that hangs costs one thread-pool slot and one
 *       forwarded op, never the worker.
 */

#include "cms_internal.h"
#include "node_ops.h"

/*
 * Run the operator program for plan->action, if one is registered.
 *
 * *taken = 0: no program for this op — the caller proceeds with its built-in
 * storage leg and this function has neither replied nor logged.
 * *taken = 1: this function owns the op.  It has either posted the run (the
 * completion handler replies: silent on exit 0, kYR_error otherwise, exactly
 * like the built-in leg) or already answered a refusal.  The returned value is
 * the caller's return value.
 */
ngx_int_t brix_cms_fsxeq_dispatch(ngx_brix_cms_ctx_t *ctx, u_char code,
    uint32_t streamid, const brix_cms_node_plan_t *plan, int *taken);

#endif /* BRIX_CMS_NODE_FSXEQ_H */

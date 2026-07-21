#ifndef BRIX_CMS_RECV_INTERNAL_H
#define BRIX_CMS_RECV_INTERNAL_H

/*
 * cms/recv_internal.h — private cross-file contract for the CMS client-side
 * (manager-connection) receive path.
 *
 * WHAT: Declares the two entry points shared between the three translation
 * units that together implement the receive path of our connection UP to a CMS
 * manager — the forwarded-namespace-op executor (recv_forward.c), the opcode
 * frame handlers + dispatch table (recv_frame.c), and the read event loop
 * (recv.c).  ngx_brix_cms_process_frame() is the frame router called by the
 * read loop; cms_node_exec_forward() is the Plane-B mutation executor called by
 * the forwarded-op frame handler.
 *
 * WHY: recv.c was a single 828-line file spanning three distinct concerns
 * (Phase-79 file-size split): the forwarded-namespace-op storage machinery, the
 * opcode handlers + redirect/wake plumbing, and the read/framing event loop.
 * Splitting it into focused units keeps each file under the 500-line guideline
 * and lets each concern be reviewed in isolation.  The only cost is that two
 * functions that were `static` now cross a translation-unit boundary; those —
 * and only those — are declared here so the definer and the caller agree on the
 * prototype (a header-declared symbol MUST be non-static at its definition or
 * the link fails).
 *
 * HOW: Include after "cms_internal.h" (which provides ngx_brix_cms_ctx_t) and
 * "node_ops.h" (which provides brix_cms_node_plan_t).  Purely internal — never
 * included outside this module.
 *
 * Requires: cms_internal.h before inclusion.
 */

#include "cms_internal.h"

/* ---- recv_frame.c — opcode dispatch ---- */

/* Decode a complete CMS frame's streamid + rrCode from ctx->inbuf and dispatch
 * by opcode through the node-role frame table (PING→PONG, SPACE→AVAIL,
 * STATUS→suspend/resume, SELECT/TRY→client redirect, STATE→kYR_have probe,
 * forwarded namespace ops, UPDATE, DISC).  Unknown opcodes are silently
 * ignored.  Returns NGX_OK, or NGX_ERROR if a handler signalled a fatal error. */
ngx_int_t ngx_brix_cms_process_frame(ngx_brix_cms_ctx_t *ctx);

/* Wake the suspended XRootD client parked on a pending locate (streamid keys
 * the per-worker pending table): validate host, redirect, resume reading.
 * Shared by the two ingest paths that resolve a parked locate — kYR_select/
 * kYR_try from a parent manager (recv_frame.c) and kYR_have from a child node
 * (server_recv_frame.c, Phase-89 W3 state fan-out).  Safe no-op when the
 * streamid is no longer pending (timeout already woke the client). */
ngx_int_t brix_cms_wake_pending_session(ngx_log_t *log, uint32_t streamid,
    const char *host, uint16_t port);

/* Resolve a saved client fd to its live connection (NULL if gone).  The caller
 * must still recycle-guard with the saved c->number.  Shared by the locate wake
 * (recv_frame.c) and the Phase-89 W8 fan-out finalizer (fanout.c). */
ngx_connection_t *brix_cms_client_conn_by_fd(int fd);

/* ---- recv_forward.c — Plane-B forwarded namespace-op executor ---- */

/* Execute a manager-forwarded namespace op (kYR_chmod/mkdir/mkpath/mv/rm/rmdir/
 * trunc): decode the request, then route to the storage leg — a non-POSIX
 * export mutates through its driver's namespace slots, the default POSIX export
 * takes the kernel-confined *_beneath path.  Replies silent-on-success /
 * kYR_error-on-failure.  Returns the send result (NGX_OK / NGX_ERROR). */
ngx_int_t cms_node_exec_forward(ngx_brix_cms_ctx_t *ctx, u_char code,
    uint32_t streamid, const u_char *payload, size_t plen);

/* ---- recv_prepare.c — forwarded staging ops (Phase-89 W2) ---- */

/* Execute a manager-forwarded staging op (kYR_prepadd/kYR_prepdel): prepadd
 * admits the path into the durable stage-request registry and records the
 * manager's reqid in the ADR-2b sidecar map; prepdel consumes the mapping and
 * deletes the registry row (idempotent).  Silent on success, kYR_error on a
 * refused/undecodable prepadd. */
ngx_int_t cms_node_exec_prepare(ngx_brix_cms_ctx_t *ctx, u_char code,
    uint32_t streamid, const u_char *payload, size_t plen);

#endif /* BRIX_CMS_RECV_INTERNAL_H */

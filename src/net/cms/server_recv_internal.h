#ifndef BRIX_CMS_SERVER_RECV_INTERNAL_H
#define BRIX_CMS_SERVER_RECV_INTERNAL_H

/*
 * cms/server_recv_internal.h — private cross-file contract for the CMS
 * server-side receive path.
 *
 * WHAT: Declares the handful of entry points shared between the four
 * translation units that together implement an accepted CMS data-server
 * connection's receive path — the lifecycle/close helpers
 * (server_recv_lifecycle.c), the wire payload parsers (server_recv_parse.c),
 * the opcode frame handlers + dispatch table (server_recv_frame.c), and the
 * read/write event loop (server_recv.c).
 *
 * WHY: server_recv.c was a single 1038-line file spanning four distinct
 * concerns (Phase-79 file-size split).  Splitting it into focused units keeps
 * each file under the 500-line guideline and lets each concern be reviewed in
 * isolation.  The only cost is that a few functions that were `static` now
 * cross a translation-unit boundary; those — and only those — are declared here
 * so the definer and the caller agree on the prototype (a header-declared symbol
 * MUST be non-static at its definition or the link fails).
 *
 * HOW: Include after "server.h" (which provides brix_cms_srv_ctx_t and the
 * brix_sess_* types).  Purely internal — never included outside this module.
 *
 * Requires: server.h before inclusion.
 */

#include "server.h"

/* ---- server_recv_lifecycle.c — session end-hint + teardown + audit log ---- */

/* Record why this session is ending (first writer wins) so the eventual close
 * reports the correct brix_sess_end_t.  No-op if a hint is already set. */
void cms_srv_set_end_hint(brix_cms_srv_ctx_t *ctx, brix_sess_end_t why);

/* Shared fatal epilogue: record the end reason, then brix_cms_srv_close().
 * After this returns ctx->c is NULL and the caller must not touch the conn. */
void cms_srv_fail_close(brix_cms_srv_ctx_t *ctx, brix_sess_end_t why);

/* Emit a failed-registration audit line (host-mode auth failure, reason err). */
void cms_srv_log_auth_fail(brix_cms_srv_ctx_t *ctx, const char *err);

/* Emit the one-shot successful-registration audit sequence for this node. */
void cms_srv_log_registration(brix_cms_srv_ctx_t *ctx);

/* ---- server_recv_parse.c — CMS wire payload decoders ---- */

/* Parse a CmsLoginData LOGIN payload into ctx (free_mb/util_pct/port/paths).
 * Returns 1 on success, 0 on a malformed frame. */
int cms_srv_parse_login(brix_cms_srv_ctx_t *ctx,
    const u_char *payload, size_t payload_len);

/* Extract free_mb from a LOAD payload (PT_SHORT count, 6 CPU bytes, PT_INT). */
uint32_t cms_srv_parse_load_free_mb(const u_char *payload, size_t payload_len);

/* Extract free_mb + util_pct from an AVAIL/SPACE payload (two PT_INT scalars). */
void cms_srv_parse_avail(const u_char *payload, size_t payload_len,
    uint32_t *free_mb, uint32_t *util_pct);

/* ---- server_recv_frame.c — opcode dispatch ---- */

/* Route one complete frame (already framed in ctx->inbuf) by opcode.  A handler
 * that tears the connection down leaves ctx->c NULL; the read loop checks that
 * after every dispatch. */
void cms_srv_process_frame(brix_cms_srv_ctx_t *ctx, u_char code,
    uint32_t streamid, const u_char *payload, size_t payload_len);

#endif /* BRIX_CMS_SERVER_RECV_INTERNAL_H */

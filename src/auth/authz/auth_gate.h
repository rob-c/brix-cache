#ifndef XROOTD_PATH_AUTH_GATE_H
#define XROOTD_PATH_AUTH_GATE_H
#include "core/ngx_xrootd_module.h"

/*
 * xrootd_auth_gate — three-tier auth check for path-based operations.
 *
 * Centralises the repeated authdb → VO ACL → token-scope sequence that
 * appears in every namespace handler.  On the first failing tier the gate
 * sends a kXR_NotAuthorized wire response, stores the nginx return code in
 * ctx->write_rc, and returns NGX_DONE.  The caller must return ctx->write_rc
 * immediately:
 *
 *   if (xrootd_auth_gate(ctx, c, XROOTD_OP_MKDIR, "MKDIR",
 *                        reqpath, resolved, conf,
 *                        XROOTD_AUTH_MKDIR, 1) != NGX_OK) {
 *       return ctx->write_rc;
 *   }
 *
 * Parameters:
 *   op_id      — XROOTD_OP_* constant for metric tracking
 *   op_name    — verb for the access log ("MKDIR", "STAT", etc.)
 *   reqpath    — client-supplied path; used for token scope check
 *   resolved   — canonical path; used for authdb and VO ACL checks
 *   conf       — server config (carries vo_rules, authdb pointer)
 *   auth_level — XROOTD_AUTH_READ / _LOOKUP / _UPDATE / _DELETE / _MKDIR
 *   need_write — 1 if write token scope is required, 0 for read
 *
 * Returns NGX_OK when all tiers pass, NGX_DONE when one denies.
 */
ngx_int_t xrootd_auth_gate(xrootd_ctx_t *ctx, ngx_connection_t *c,
                            ngx_uint_t op_id, const char *op_name,
                            const char *reqpath, const char *resolved,
                            ngx_stream_xrootd_srv_conf_t *conf,
                            int auth_level, int need_write);

/*
 * xrootd_auth_gate_op — same as xrootd_auth_gate, but the caller supplies the
 * exact XrdAcc operation (xrootd_acc_op_t) used by the `xrdacc` engine.  Pass
 * XROOTD_AOP_ANY to derive it from auth_level (what xrootd_auth_gate does).
 * `native` always uses auth_level, so the operation only refines `xrdacc`
 * decisions (e.g. AOP_Create vs AOP_Update, AOP_Stage).
 */
ngx_int_t xrootd_auth_gate_op(xrootd_ctx_t *ctx, ngx_connection_t *c,
                            ngx_uint_t op_id, const char *op_name,
                            const char *reqpath, const char *resolved,
                            ngx_stream_xrootd_srv_conf_t *conf,
                            int auth_level, int need_write,
                            xrootd_acc_op_t aop);

/*
 * xrootd_authz_check — decision-only, format-aware authorization (xrdacc engine
 * or native authdb) for callers that send their own error response, e.g. TPC
 * dest-open and prepare.  Returns NGX_OK (allow) / NGX_ERROR (deny); sends
 * nothing on the wire.  Replaces a bare xrootd_check_authdb() so xrdacc applies
 * there too, with native behavior unchanged.
 *
 * Pass both paths: `reqpath` is the LOGICAL namespace path (what XrdAcc keys
 * off) and `resolved` is the backing FS path (what the native authdb keys off,
 * preserving the exact native call this replaces).
 */
ngx_int_t xrootd_authz_check(xrootd_ctx_t *ctx, ngx_connection_t *c,
                            ngx_stream_xrootd_srv_conf_t *conf,
                            const char *reqpath, const char *resolved,
                            const char *op_name, int auth_level,
                            xrootd_acc_op_t aop);

#endif /* XROOTD_PATH_AUTH_GATE_H */

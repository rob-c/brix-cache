#ifndef BRIX_PATH_AUTH_GATE_H
#define BRIX_PATH_AUTH_GATE_H
#include "core/ngx_brix_module.h"

/*
 * brix_auth_gate — three-tier auth check for path-based operations.
 *
 * Centralises the repeated authdb → VO ACL → token-scope sequence that
 * appears in every namespace handler.  On the first failing tier the gate
 * sends a kXR_NotAuthorized wire response, stores the nginx return code in
 * ctx->write_rc, and returns NGX_DONE.  The caller must return ctx->write_rc
 * immediately:
 *
 *   if (brix_auth_gate(ctx, c, BRIX_OP_MKDIR, "MKDIR",
 *                        reqpath, resolved, conf,
 *                        BRIX_AUTH_MKDIR, 1) != NGX_OK) {
 *       return ctx->write_rc;
 *   }
 *
 * Parameters:
 *   op_id      — BRIX_OP_* constant for metric tracking
 *   op_name    — verb for the access log ("MKDIR", "STAT", etc.)
 *   reqpath    — client-supplied path; used for token scope check
 *   resolved   — canonical path; used for authdb and VO ACL checks
 *   conf       — server config (carries vo_rules, authdb pointer)
 *   auth_level — BRIX_AUTH_READ / _LOOKUP / _UPDATE / _DELETE / _MKDIR
 *   need_write — 1 if write token scope is required, 0 for read
 *
 * Returns NGX_OK when all tiers pass, NGX_DONE when one denies.
 */
ngx_int_t brix_auth_gate(brix_ctx_t *ctx, ngx_connection_t *c,
                            ngx_uint_t op_id, const char *op_name,
                            const char *reqpath, const char *resolved,
                            ngx_stream_brix_srv_conf_t *conf,
                            int auth_level, int need_write);

/*
 * brix_auth_gate_op — same as brix_auth_gate, but the caller supplies the
 * exact XrdAcc operation (brix_acc_op_t) used by the `xrdacc` engine.  Pass
 * BRIX_AOP_ANY to derive it from auth_level (what brix_auth_gate does).
 * `native` always uses auth_level, so the operation only refines `xrdacc`
 * decisions (e.g. AOP_Create vs AOP_Update, AOP_Stage).
 */
ngx_int_t brix_auth_gate_op(brix_ctx_t *ctx, ngx_connection_t *c,
                            ngx_uint_t op_id, const char *op_name,
                            const char *reqpath, const char *resolved,
                            ngx_stream_brix_srv_conf_t *conf,
                            int auth_level, int need_write,
                            brix_acc_op_t aop);

/*
 * brix_authz_check — decision-only, format-aware authorization (xrdacc engine
 * or native authdb) for callers that send their own error response, e.g. TPC
 * dest-open and prepare.  Returns NGX_OK (allow) / NGX_ERROR (deny); sends
 * nothing on the wire.  Replaces a bare brix_check_authdb() so xrdacc applies
 * there too, with native behavior unchanged.
 *
 * Pass both paths: `reqpath` is the LOGICAL namespace path (what XrdAcc keys
 * off) and `resolved` is the backing FS path (what the native authdb keys off,
 * preserving the exact native call this replaces).
 */
ngx_int_t brix_authz_check(brix_ctx_t *ctx, ngx_connection_t *c,
                            ngx_stream_brix_srv_conf_t *conf,
                            const char *reqpath, const char *resolved,
                            const char *op_name, int auth_level,
                            brix_acc_op_t aop);

/* Decision-only identity form used by the VFS backstop. It composes the same
 * native/XrdAcc, VO and token-scope evaluators as the edge gate but owns no
 * wire response and consults no verdict cache. All pointers are borrowed. */
typedef struct {
    ngx_pool_t       *pool;
    ngx_log_t        *log;
    brix_identity_t  *identity;
    ngx_array_t      *authdb_rules;
    ngx_array_t      *vo_rules;
    void             *acc_tables;
    void             *acc_entity;
    ngx_uint_t        acc_format;
    const char       *peer_ip;
    const char       *logical_path;
    const char       *resolved_path;
    uint32_t          needed_privs;
    brix_acc_op_t     acc_op;
    int               need_write;
} brix_authz_identity_query_t;

/* Shared lazy identity-to-account mapping used by both the protocol-edge and
 * identity-only evaluators. The returned string is borrowed from `identity`
 * (or `dn`) and remains valid for the connection lifetime. */
const char *brix_authz_mapped_name(brix_identity_t *identity, const char *dn);

/* Construct (or return the connection-lifetime memo of) the XrdAcc entity
 * derived from an identity. A NULL identity yields an anonymous request-owned
 * entity so host/default rules retain the edge evaluator's semantics. */
void *brix_authz_acc_entity(ngx_pool_t *pool, brix_identity_t *identity,
    const char *peer);

ngx_int_t brix_authz_check_identity(const brix_authz_identity_query_t *query);

#endif /* BRIX_PATH_AUTH_GATE_H */

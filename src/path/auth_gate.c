/*
 * auth_gate.c — three-tier auth check for path-based operations.
 *
 * Called by every handler that performs a namespace or file operation on a
 * canonically-resolved path.  Checks authdb, VO ACL, and token scope in
 * order; sends the kXR_NotAuthorized response and returns NGX_DONE on the
 * first failure, storing the nginx return code in ctx->write_rc.
 */
#include "core/ngx_xrootd_module.h"
#include "auth_gate.h"
#include "auth_cache.h"
#include "auth_gate_l1.h"
#include "core/compat/crypto.h"
#include "acc/acc.h"
#include "metrics/metrics_macros.h"   /* Phase 51 (E6): auth-gate L1 counters */

/*
 * xrootd_acc_gate_engine — tier-1 authorization via the faithful XrdAcc engine
 * (when `xrootd_authdb_format xrdacc`).  Maps the handler's native privilege
 * level to an XrdAcc operation, builds the request entity from the resolved
 * identity (DN/subject as the user name, the FQAN-derived VO/role/group views,
 * and the peer address as the host), evaluates the per-worker tables, and
 * audits the verdict.  Fail-closed: a missing table set denies.
 */
static ngx_int_t
xrootd_acc_gate_engine(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, const char *path,
    const char *op_name, int auth_level, xrootd_acc_op_t op_in)
{
    xrootd_acc_entity_t  *ent;
    xrootd_acc_op_t       op;
    xrootd_acc_privs_t    privs;
    const char           *name, *host;
    const char           *vorg = "", *role = "", *grp = "";

    if (conf->acc_tables == NULL) {
        return NGX_ERROR;   /* xrdacc selected but authdb failed to load */
    }
    if (path == NULL) {
        path = "/";
    }

    /* Use the caller's explicit operation when given (e.g. create vs update,
     * stage); otherwise derive it from the native privilege level. */
    if (op_in != XROOTD_AOP_ANY) {
        op = op_in;
    }
    else if (auth_level & XROOTD_AUTH_DELETE)  { op = XROOTD_AOP_DELETE; }
    else if (auth_level & XROOTD_AUTH_MKDIR)   { op = XROOTD_AOP_MKDIR;  }
    else if (auth_level & XROOTD_AUTH_ADMIN)   { op = XROOTD_AOP_CHMOD;  }
    else if (auth_level & XROOTD_AUTH_UPDATE)  { op = XROOTD_AOP_UPDATE; }
    else if (auth_level & XROOTD_AUTH_READ)    { op = XROOTD_AOP_READ;   }
    else                                       { op = XROOTD_AOP_STAT;   }

    if (ctx->identity != NULL) {
        name = xrootd_identity_dn_cstr(ctx->identity);
        vorg = xrootd_identity_acc_vorg_cstr(ctx->identity);
        role = xrootd_identity_acc_role_cstr(ctx->identity);
        grp  = xrootd_identity_acc_group_cstr(ctx->identity);
    } else {
        name = (ctx->dn[0] != '\0') ? ctx->dn : "";
        vorg = ctx->vo_list;        /* best-effort when no structured identity */
    }
    host = (ctx->peer_ip[0] != '\0') ? ctx->peer_ip : "?";

    /* Opt-in reverse DNS for `h <host>`/`h .domain` rules: resolve the peer to
     * a hostname once per connection (cached on ctx), falling back to the IP
     * when there is no PTR record.  Off by default (XrdAccAccess::Resolve). */
    if (conf->acc_resolve_hosts) {
        if (!ctx->acc_host_done) {
            char hbuf[256];
            const char *h;

            ctx->acc_host_done = 1;
            h = xrootd_acc_resolve_peer(c->sockaddr, c->socklen,
                                        hbuf, sizeof(hbuf));
            if (h != NULL) {
                size_t  n = ngx_strlen(h);
                char   *dup = ngx_pnalloc(c->pool, n + 1);
                if (dup != NULL) {
                    ngx_memcpy(dup, h, n + 1);
                    ctx->acc_host = dup;
                }
            }
        }
        if (ctx->acc_host != NULL) {
            host = ctx->acc_host;
        }
    }

    ent = xrootd_acc_entity_build(c->pool, name, host,
                                  (name != NULL && name[0] != '\0'),
                                  vorg, role, grp);
    if (ent == NULL) {
        return NGX_ERROR;
    }

    privs = xrootd_acc_access(conf->acc_tables, ent, path, op);

    xrootd_acc_audit(c->log, conf->acc_audit, privs != XROOTD_ACC_PRIV_NONE,
                     op_name, name, host, path);

    return (privs != XROOTD_ACC_PRIV_NONE) ? NGX_OK : NGX_ERROR;
}

/*
 * xrootd_authz_check — decision-only, format-aware authorization for callers
 * that format their own error response (TPC dest-open, prepare).  Routes to the
 * XrdAcc engine when `xrootd_authdb_format xrdacc`, else the native authdb —
 * exactly matching the native call it replaces.  No wire response, no metric.
 *
 * Like xrootd_auth_gate_op, the two engines key off different paths: XrdAcc
 * authorizes the LOGICAL namespace path (reqpath) while the native authdb keys
 * off the backing FS path (resolved).  Callers pass both; native behavior is
 * unchanged (it still sees `resolved`).  Returns NGX_OK (allow) / NGX_ERROR.
 */
ngx_int_t
xrootd_authz_check(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, const char *reqpath,
    const char *resolved, const char *op_name, int auth_level,
    xrootd_acc_op_t aop)
{
    if (conf->acc_format == XROOTD_AUTHDB_FORMAT_XRDACC) {
        return xrootd_acc_gate_engine(ctx, c, conf,
                                      (reqpath != NULL) ? reqpath : resolved,
                                      op_name, auth_level, aop);
    }
    return xrootd_check_authdb(ctx, resolved, auth_level);
}

/*
 * Build the 32-byte auth-cache key from every input that determines the
 * verdict: the required authdb level and write flag, the XrdAcc operation, the
 * resolved and request paths, the peer host, the DN, the VO list, and the raw
 * token-scope claim.  Two requests therefore share a cache entry only when all
 * of those match — so a cached grant can never be replayed for a different
 * token, path, operation, host, or access level.
 *
 * `aop` and `host` are the XrdAcc engine's extra inputs (create vs update vs
 * stage decide differently for the same auth_level; `h`/domain rules key off
 * the peer).  Native callers pass AOP_ANY + "" so their keys are unchanged.
 * The peer IP keys the host because IP->hostname is deterministic per
 * connection, so it stands in for the resolved name without an early lookup.
 * Returns 1 on success, 0 if the components don't fit the staging buffer.
 */
static int
xrootd_auth_gate_cache_key(u_char key[32], int auth_level, int need_write,
    xrootd_acc_op_t aop, const char *host, const char *reqpath,
    const char *resolved, xrootd_ctx_t *ctx)
{
    u_char       buf[3 + 64 + 1 + PATH_MAX + PATH_MAX + 512 + 512 + 1024 + 8];
    size_t       n = 0;
    const char  *dn      = ctx->dn;
    const char  *vo      = ctx->vo_list;
    const char  *scope   = "";
    size_t       scope_len = 0;
    size_t       hl, rl, ql, dl, vl;

    if (ctx->identity != NULL && ctx->identity->scope_raw.len > 0) {
        scope     = (const char *) ctx->identity->scope_raw.data;
        scope_len = ctx->identity->scope_raw.len;
    }

    hl = host ? ngx_strlen(host) : 0;
    rl = resolved ? ngx_strlen(resolved) : 0;
    ql = reqpath  ? ngx_strlen(reqpath)  : 0;
    dl = dn ? ngx_strlen(dn) : 0;
    vl = vo ? ngx_strlen(vo) : 0;

    if (3 + hl + 1 + rl + 1 + ql + 1 + dl + 1 + vl + 1 + scope_len > sizeof(buf)) {
        return 0;
    }

    buf[n++] = (u_char) auth_level;
    buf[n++] = (u_char) need_write;
    buf[n++] = (u_char) aop;
    if (hl) { ngx_memcpy(buf + n, host, hl); n += hl; }
    buf[n++] = '\0';
    if (rl) { ngx_memcpy(buf + n, resolved, rl); n += rl; }
    buf[n++] = '\0';
    if (ql) { ngx_memcpy(buf + n, reqpath, ql); n += ql; }
    buf[n++] = '\0';
    if (dl) { ngx_memcpy(buf + n, dn, dl); n += dl; }
    buf[n++] = '\0';
    if (vl) { ngx_memcpy(buf + n, vo, vl); n += vl; }
    buf[n++] = '\0';
    if (scope_len) { ngx_memcpy(buf + n, scope, scope_len); n += scope_len; }

    return xrootd_sha256(buf, n, key);
}

/* Record a grant/deny verdict in the auth-result cache (no-op if disabled). */
static void
xrootd_auth_gate_cache_put(ngx_stream_xrootd_srv_conf_t *conf,
    const u_char key[32], int have_key, int allowed, int auth_level)
{
    xrootd_auth_cache_val_t cv;

    if (conf->auth_cache.kv == NULL || !have_key) {
        return;
    }
    cv.allowed    = (uint8_t) (allowed ? 1 : 0);
    cv.auth_level = (uint8_t) auth_level;
    cv.pad        = 0;
    (void) xrootd_kv_set(conf->auth_cache.kv, key, 32, &cv, sizeof(cv),
                         (ngx_msec_t) conf->auth_cache.ttl_secs * 1000);
    /* E2: also populate the per-worker L1 so the next hit skips the SHM lock. */
    xrootd_auth_l1_store(conf->auth_l1, key, &cv,
                         (ngx_msec_t) conf->auth_cache.ttl_secs * 1000);
}

ngx_int_t
xrootd_auth_gate_op(xrootd_ctx_t *ctx, ngx_connection_t *c,
                 ngx_uint_t op_id, const char *op_name,
                 const char *reqpath, const char *resolved,
                 ngx_stream_xrootd_srv_conf_t *conf,
                 int auth_level, int need_write, xrootd_acc_op_t aop)
{
    u_char           ac_key[32];
    int              ac_have_key = 0;
    int              is_xrdacc =
                         (conf->acc_format == XROOTD_AUTHDB_FORMAT_XRDACC);
    /* xrdacc verdicts also depend on the operation and peer host, so fold both
     * into the key (native passes AOP_ANY + "" → its keys are unchanged).  OS
     * group membership — the one remaining xrdacc input — is bounded by the
     * gidlifetime TTL, matching the auth-cache TTL, so a cached entry cannot
     * outlive a group change by more than the configured window. */
    xrootd_acc_op_t  key_aop  = is_xrdacc ? aop : XROOTD_AOP_ANY;
    const char      *key_host = is_xrdacc ? ctx->peer_ip : "";

    /* auth-result cache: fast path (E2: lockless L1, then SHM L2) */    if (conf->auth_cache.kv != NULL) {
        ac_have_key = xrootd_auth_gate_cache_key(ac_key, auth_level,
                                                 need_write, key_aop, key_host,
                                                 reqpath, resolved, ctx);
        if (ac_have_key) {
            xrootd_auth_cache_val_t cv;
            int                     got = 0;

            /* Lazily create the per-worker L1 (COW-private per worker). */
            if (conf->auth_l1 == NULL) {
                conf->auth_l1 = xrootd_auth_l1_create(ngx_cycle->pool, 0);
            }

            if (xrootd_auth_l1_lookup(conf->auth_l1, ac_key, &cv)) {
                got = 1;                       /* L1 hit — no SHM spinlock */
                XROOTD_RESIL_METRIC_INC(auth_l1_hits_total);
            } else {
                XROOTD_RESIL_METRIC_INC(auth_l1_misses_total);
                size_t cl = sizeof(cv);
                if (xrootd_kv_get(conf->auth_cache.kv, ac_key, sizeof(ac_key),
                                  &cv, &cl) == 1 && cl == sizeof(cv))
                {
                    got = 1;
                    /* Promote the L2 hit into L1 for the next presentation. */
                    xrootd_auth_l1_store(conf->auth_l1, ac_key, &cv,
                        (ngx_msec_t) conf->auth_cache.ttl_secs * 1000);
                }
            }

            if (got) {
                if (!cv.allowed) {
                    xrootd_log_access(ctx, c, op_name, resolved, "-",
                                      0, kXR_NotAuthorized,
                                      "auth cache: denied", 0);
                    XROOTD_OP_ERR(ctx, op_id);
                    ctx->write_rc = xrootd_send_error(ctx, c,
                        kXR_NotAuthorized, "not authorized");
                    return NGX_DONE;
                }
                return NGX_OK;             /* cached grant */
            }
        }
    }

    if (is_xrdacc) {
        /* XrdAcc authorizes the logical namespace path, not the backing FS path. */
        if (xrootd_acc_gate_engine(ctx, c, conf,
                                   (reqpath != NULL) ? reqpath : resolved,
                                   op_name, auth_level, aop) != NGX_OK)
        {
            xrootd_log_access(ctx, c, op_name, resolved, "-",
                              0, kXR_NotAuthorized, "xrdacc denied", 0);
            XROOTD_OP_ERR(ctx, op_id);
            xrootd_auth_gate_cache_put(conf, ac_key, ac_have_key, 0, auth_level);
            ctx->write_rc = xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                              "not authorized");
            return NGX_DONE;
        }
    } else if (xrootd_check_authdb(ctx, resolved, auth_level) != NGX_OK) {
        xrootd_log_access(ctx, c, op_name, resolved, "-",
                          0, kXR_NotAuthorized, "authdb denied", 0);
        XROOTD_OP_ERR(ctx, op_id);
        xrootd_auth_gate_cache_put(conf, ac_key, ac_have_key, 0, auth_level);
        ctx->write_rc = xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                          "authdb denied");
        return NGX_DONE;
    }

    if (xrootd_check_vo_acl_identity(c->log, resolved, conf->vo_rules,
                                     ctx->identity) != NGX_OK) {
        xrootd_log_access(ctx, c, op_name, resolved, "-",
                          0, kXR_NotAuthorized, "VO not authorized", 0);
        XROOTD_OP_ERR(ctx, op_id);
        xrootd_auth_gate_cache_put(conf, ac_key, ac_have_key, 0, auth_level);
        ctx->write_rc = xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                          "VO not authorized");
        return NGX_DONE;
    }

    if (xrootd_check_token_scope(ctx, reqpath, need_write) != NGX_OK) {
        xrootd_log_access(ctx, c, op_name, reqpath, "-",
                          0, kXR_NotAuthorized, "token scope denied", 0);
        XROOTD_OP_ERR(ctx, op_id);
        xrootd_auth_gate_cache_put(conf, ac_key, ac_have_key, 0, auth_level);
        ctx->write_rc = xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                          "token scope denied");
        return NGX_DONE;
    }

    xrootd_auth_gate_cache_put(conf, ac_key, ac_have_key, 1, auth_level);
    return NGX_OK;
}

/*
 * xrootd_auth_gate — the common entry point: same three-tier check, with the
 * XrdAcc operation derived from the native auth_level (AOP_ANY).  Callers that
 * need a precise XrdAcc operation (create vs update, rename, stage) use
 * xrootd_auth_gate_op() directly.
 */
ngx_int_t
xrootd_auth_gate(xrootd_ctx_t *ctx, ngx_connection_t *c,
                 ngx_uint_t op_id, const char *op_name,
                 const char *reqpath, const char *resolved,
                 ngx_stream_xrootd_srv_conf_t *conf,
                 int auth_level, int need_write)
{
    return xrootd_auth_gate_op(ctx, c, op_id, op_name, reqpath, resolved,
                               conf, auth_level, need_write, XROOTD_AOP_ANY);
}

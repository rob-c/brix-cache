/*
 * auth_gate.c — three-tier auth check for path-based operations.
 *
 * Called by every handler that performs a namespace or file operation on a
 * canonically-resolved path.  Checks authdb, VO ACL, and token scope in
 * order; sends the kXR_NotAuthorized response and returns NGX_DONE on the
 * first failure, storing the nginx return code in ctx->write_rc.
 */
#include "ngx_xrootd_module.h"
#include "path/auth_gate.h"
#include "path/auth_cache.h"
#include "compat/crypto.h"

/*
 * Build the 32-byte auth-cache key from every input that determines the
 * verdict: the required authdb level and write flag, the resolved and request
 * paths, the DN, the VO list, and the raw token-scope claim.  Two requests
 * therefore share a cache entry only when all of those match — so a cached
 * grant can never be replayed for a different token, path, or access level.
 * Returns 1 on success, 0 if the components don't fit the staging buffer.
 */
static int
xrootd_auth_gate_cache_key(u_char key[32], int auth_level, int need_write,
    const char *reqpath, const char *resolved, xrootd_ctx_t *ctx)
{
    u_char       buf[2 + PATH_MAX + PATH_MAX + 512 + 512 + 1024 + 8];
    size_t       n = 0;
    const char  *dn      = ctx->dn;
    const char  *vo      = ctx->vo_list;
    const char  *scope   = "";
    size_t       scope_len = 0;
    size_t       rl, ql, dl, vl;

    if (ctx->identity != NULL && ctx->identity->scope_raw.len > 0) {
        scope     = (const char *) ctx->identity->scope_raw.data;
        scope_len = ctx->identity->scope_raw.len;
    }

    rl = resolved ? ngx_strlen(resolved) : 0;
    ql = reqpath  ? ngx_strlen(reqpath)  : 0;
    dl = dn ? ngx_strlen(dn) : 0;
    vl = vo ? ngx_strlen(vo) : 0;

    if (2 + rl + 1 + ql + 1 + dl + 1 + vl + 1 + scope_len > sizeof(buf)) {
        return 0;
    }

    buf[n++] = (u_char) auth_level;
    buf[n++] = (u_char) need_write;
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
}

ngx_int_t
xrootd_auth_gate(xrootd_ctx_t *ctx, ngx_connection_t *c,
                 ngx_uint_t op_id, const char *op_name,
                 const char *reqpath, const char *resolved,
                 ngx_stream_xrootd_srv_conf_t *conf,
                 int auth_level, int need_write)
{
    u_char  ac_key[32];
    int     ac_have_key = 0;

    /* ---- auth-result cache: fast path ---- */
    if (conf->auth_cache.kv != NULL) {
        ac_have_key = xrootd_auth_gate_cache_key(ac_key, auth_level,
                                                 need_write, reqpath,
                                                 resolved, ctx);
        if (ac_have_key) {
            xrootd_auth_cache_val_t cv;
            size_t                  cl = sizeof(cv);

            if (xrootd_kv_get(conf->auth_cache.kv, ac_key, sizeof(ac_key),
                              &cv, &cl) == 1 && cl == sizeof(cv))
            {
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

    if (xrootd_check_authdb(ctx, resolved, auth_level) != NGX_OK) {
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

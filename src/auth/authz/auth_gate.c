/*
 * auth_gate.c — three-tier auth check for path-based operations.
 *
 * Called by every handler that performs a namespace or file operation on a
 * canonically-resolved path.  Checks authdb, VO ACL, and token scope in
 * order; sends the kXR_NotAuthorized response and returns NGX_DONE on the
 * first failure, storing the nginx return code in ctx->write_rc.
 */
#include "core/ngx_brix_module.h"
#include "auth_gate.h"
#include "auth_cache.h"
#include "auth_gate_l1.h"
#include "core/compat/crypto.h"
#include "auth/authz/acc/acc.h"
#include "observability/metrics/metrics_macros.h"   /* Phase 51 (E6): auth-gate L1 counters */

/*
 * auth_gate_ctx_t — file-local bundle of one authorization request's inputs.
 *
 * WHAT: the connection/session state (ctx, c, conf) plus the per-operation
 * parameters (op_id/op_name, the logical reqpath and backing resolved path,
 * the native auth_level + need_write flag, and the explicit XrdAcc op) that
 * the engine, cache-key, and gate helpers all read.
 * WHY: the auth-gate cluster was param-bloat — brix_acc_gate_engine took 7
 * params, brix_auth_gate_cache_key 7, and the extern brix_auth_gate_op 10.
 * Threading one const bundle through the STATIC helpers collapses that to a
 * single pointer while keeping the frozen extern signatures untouched.
 * HOW: brix_auth_gate_op builds it once (zero-initialised) from its frozen
 * parameters and passes a const pointer down; helpers never mutate it — the
 * only mutable per-request state (cache key bytes, verdict) lives in locals.
 */
typedef struct {
    brix_ctx_t                  *ctx;
    ngx_connection_t            *c;
    ngx_stream_brix_srv_conf_t  *conf;
    ngx_uint_t                   op_id;
    const char                  *op_name;
    const char                  *reqpath;   /* logical namespace path (xrdacc) */
    const char                  *resolved;  /* backing FS path (native authdb) */
    int                          auth_level;
    int                          need_write;
    brix_acc_op_t                aop;        /* explicit xrdacc op, or ANY */
} auth_gate_ctx_t;

/*
 * brix_acc_gate_select_op — map the request to an XrdAcc operation.
 *
 * WHAT: returns the caller's explicit operation when one was given, else
 * derives it from the native privilege level (delete > mkdir > admin >
 * update > read > stat).
 * WHY: isolates the branch ladder so the engine body stays flat; the
 * precedence order is verdict-load-bearing and must not change.
 * HOW: pure function of op_in/auth_level — no side effects.
 */
static brix_acc_op_t
brix_acc_gate_select_op(brix_acc_op_t op_in, int auth_level)
{
    if (op_in != BRIX_AOP_ANY)               { return op_in;           }
    if (auth_level & BRIX_AUTH_DELETE)       { return BRIX_AOP_DELETE; }
    if (auth_level & BRIX_AUTH_MKDIR)        { return BRIX_AOP_MKDIR;  }
    if (auth_level & BRIX_AUTH_ADMIN)        { return BRIX_AOP_CHMOD;  }
    if (auth_level & BRIX_AUTH_UPDATE)       { return BRIX_AOP_UPDATE; }
    if (auth_level & BRIX_AUTH_READ)         { return BRIX_AOP_READ;   }
    return BRIX_AOP_STAT;
}

/*
 * brix_acc_gate_identity — resolve the XrdAcc entity's name and VO views.
 *
 * WHAT: fills *name / *vorg / *role / *grp from the structured identity when
 * present, else from the best-effort login fields (DN + raw VO list).
 * WHY: extracts the identity-vs-login fallback out of the engine body; the
 * *role / *grp defaults ("") set by the caller survive the no-identity path.
 * HOW: reads ctx only; writes through the four out-params.
 */
static void
brix_acc_gate_identity(brix_ctx_t *ctx, const char **name,
    const char **vorg, const char **role, const char **grp)
{
    if (ctx->identity != NULL) {
        *name = brix_identity_dn_cstr(ctx->identity);
        *vorg = brix_identity_acc_vorg_cstr(ctx->identity);
        *role = brix_identity_acc_role_cstr(ctx->identity);
        *grp  = brix_identity_acc_group_cstr(ctx->identity);
    } else {
        *name = (ctx->login.dn[0] != '\0') ? ctx->login.dn : "";
        *vorg = ctx->login.vo_list;   /* best-effort when no structured identity */
    }
}

/*
 * brix_acc_gate_host — pick the host token for `h <host>`/`h .domain` rules.
 *
 * WHAT: returns the peer IP by default; when reverse-DNS resolution is
 * enabled (XrdAccAccess::Resolve), resolves the peer to a hostname once per
 * connection (cached on ctx) and returns that, falling back to the IP.
 * WHY: the opt-in PTR lookup was the engine's deepest nesting; hoisting it
 * keeps the per-connection caching side effect at the edge.
 * HOW: mutates only ctx->login.acc_host* (the connection-scoped cache); the
 * verdict-relevant return value is a borrowed string owned by ctx or "?".
 */
static const char *
brix_acc_gate_host(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    const char *host = (ctx->login.peer_ip[0] != '\0') ? ctx->login.peer_ip : "?";

    if (!conf->acc.resolve_hosts) {
        return host;
    }

    if (!ctx->login.acc_host_done) {
        char        hbuf[256];
        const char *h;

        ctx->login.acc_host_done = 1;
        h = brix_acc_resolve_peer(c->sockaddr, c->socklen, hbuf, sizeof(hbuf));
        if (h != NULL) {
            size_t  n   = ngx_strlen(h);
            char   *dup = ngx_pnalloc(c->pool, n + 1);
            if (dup != NULL) {
                ngx_memcpy(dup, h, n + 1);
                ctx->login.acc_host = dup;
            }
        }
    }

    return (ctx->login.acc_host != NULL) ? ctx->login.acc_host : host;
}

/*
 * brix_acc_gate_engine — tier-1 authorization via the faithful XrdAcc engine
 * (when `brix_authdb_format xrdacc`).  Maps the handler's native privilege
 * level to an XrdAcc operation, builds the request entity from the resolved
 * identity (DN/subject as the user name, the FQAN-derived VO/role/group views,
 * and the peer address as the host), evaluates the per-worker tables, and
 * audits the verdict.  Fail-closed: a missing table set denies.
 */
static ngx_int_t
brix_acc_gate_engine(const auth_gate_ctx_t *g, const char *path)
{
    brix_ctx_t                  *ctx  = g->ctx;
    ngx_connection_t            *c    = g->c;
    ngx_stream_brix_srv_conf_t  *conf = g->conf;
    brix_acc_entity_t           *ent;
    brix_acc_op_t                op;
    brix_acc_privs_t             privs;
    const char                  *name, *host;
    const char                  *vorg, *role = "", *grp = "";

    if (conf->acc.tables == NULL) {
        return NGX_ERROR;   /* xrdacc selected but authdb failed to load */
    }
    if (path == NULL) {
        path = "/";
    }

    /* Use the caller's explicit operation when given (e.g. create vs update,
     * stage); otherwise derive it from the native privilege level. */
    op = brix_acc_gate_select_op(g->aop, g->auth_level);

    brix_acc_gate_identity(ctx, &name, &vorg, &role, &grp);
    host = brix_acc_gate_host(ctx, c, conf);

    ent = brix_acc_entity_build(c->pool, name, host,
                                  (name != NULL && name[0] != '\0'),
                                  vorg, role, grp);
    if (ent == NULL) {
        return NGX_ERROR;
    }

    privs = brix_acc_access(conf->acc.tables, ent, path, op);

    brix_acc_audit(c->log, conf->acc.audit, privs != BRIX_ACC_PRIV_NONE,
                     g->op_name, name, host, path);

    return (privs != BRIX_ACC_PRIV_NONE) ? NGX_OK : NGX_ERROR;
}

/*
 * brix_authz_check — decision-only, format-aware authorization for callers
 * that format their own error response (TPC dest-open, prepare).  Routes to the
 * XrdAcc engine when `brix_authdb_format xrdacc`, else the native authdb —
 * exactly matching the native call it replaces.  No wire response, no metric.
 *
 * Like brix_auth_gate_op, the two engines key off different paths: XrdAcc
 * authorizes the LOGICAL namespace path (reqpath) while the native authdb keys
 * off the backing FS path (resolved).  Callers pass both; native behavior is
 * unchanged (it still sees `resolved`).  Returns NGX_OK (allow) / NGX_ERROR.
 */
ngx_int_t
brix_authz_check(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *reqpath,
    const char *resolved, const char *op_name, int auth_level,
    brix_acc_op_t aop)
{
    if (conf->acc.format == BRIX_AUTHDB_FORMAT_XRDACC) {
        auth_gate_ctx_t  g = {0};

        g.ctx        = ctx;
        g.c          = c;
        g.conf       = conf;
        g.op_name    = op_name;
        g.reqpath    = reqpath;
        g.resolved   = resolved;
        g.auth_level = auth_level;
        g.aop        = aop;

        return brix_acc_gate_engine(&g, (reqpath != NULL) ? reqpath : resolved);
    }
    return brix_check_authdb(ctx, resolved, auth_level);
}

/*
 * Build the 32-byte auth-cache key from every input that determines the
 * verdict: the required authdb level and write flag, the XrdAcc operation, the
 * resolved and request paths, the peer host, the DN, the VO list, and the raw
 * token-scope claim.  Two requests therefore share a cache entry only when all
 * of those match — so a cached grant can never be replayed for a different
 * token, path, operation, host, or access level.
 *
 * `key_aop` and `host` are the XrdAcc engine's extra inputs (create vs update
 * vs stage decide differently for the same auth_level; `h`/domain rules key off
 * the peer).  Native callers fold in AOP_ANY + "" so their keys are unchanged.
 * The peer IP keys the host because IP->hostname is deterministic per
 * connection, so it stands in for the resolved name without an early lookup.
 * Returns 1 on success, 0 if the components don't fit the staging buffer.
 */
static int
brix_auth_gate_cache_key(u_char key[32], const auth_gate_ctx_t *g,
    brix_acc_op_t key_aop, const char *host)
{
    brix_ctx_t  *ctx = g->ctx;
    u_char       buf[3 + 64 + 1 + PATH_MAX + PATH_MAX + 512 + 512 + 1024 + 8];
    size_t       n = 0;
    const char  *dn      = ctx->login.dn;
    const char  *vo      = ctx->login.vo_list;
    const char  *scope   = "";
    size_t       scope_len = 0;
    size_t       hl, rl, ql, dl, vl;

    if (ctx->identity != NULL && ctx->identity->scope_raw.len > 0) {
        scope     = (const char *) ctx->identity->scope_raw.data;
        scope_len = ctx->identity->scope_raw.len;
    }

    hl = host ? ngx_strlen(host) : 0;
    rl = g->resolved ? ngx_strlen(g->resolved) : 0;
    ql = g->reqpath  ? ngx_strlen(g->reqpath)  : 0;
    dl = dn ? ngx_strlen(dn) : 0;
    vl = vo ? ngx_strlen(vo) : 0;

    if (3 + hl + 1 + rl + 1 + ql + 1 + dl + 1 + vl + 1 + scope_len > sizeof(buf)) {
        return 0;
    }

    buf[n++] = (u_char) g->auth_level;
    buf[n++] = (u_char) g->need_write;
    buf[n++] = (u_char) key_aop;
    if (hl) { ngx_memcpy(buf + n, host, hl); n += hl; }
    buf[n++] = '\0';
    if (rl) { ngx_memcpy(buf + n, g->resolved, rl); n += rl; }
    buf[n++] = '\0';
    if (ql) { ngx_memcpy(buf + n, g->reqpath, ql); n += ql; }
    buf[n++] = '\0';
    if (dl) { ngx_memcpy(buf + n, dn, dl); n += dl; }
    buf[n++] = '\0';
    if (vl) { ngx_memcpy(buf + n, vo, vl); n += vl; }
    buf[n++] = '\0';
    if (scope_len) { ngx_memcpy(buf + n, scope, scope_len); n += scope_len; }

    return brix_sha256(buf, n, key);
}

/* Record a grant/deny verdict in the auth-result cache (no-op if disabled). */
static void
brix_auth_gate_cache_put(ngx_stream_brix_srv_conf_t *conf,
    const u_char key[32], int have_key, int allowed, int auth_level)
{
    brix_auth_cache_val_t cv;

    if (conf->auth_cache.kv == NULL || !have_key) {
        return;
    }
    cv.allowed    = (uint8_t) (allowed ? 1 : 0);
    cv.auth_level = (uint8_t) auth_level;
    cv.pad        = 0;
    (void) brix_kv_set(conf->auth_cache.kv, key, 32, &cv, sizeof(cv),
                         (ngx_msec_t) conf->auth_cache.ttl_secs * 1000);
    /* E2: also populate the per-worker L1 so the next hit skips the SHM lock. */
    brix_auth_l1_store(conf->auth_l1, key, &cv,
                         (ngx_msec_t) conf->auth_cache.ttl_secs * 1000);
}

/*
 * brix_auth_gate_deny — emit a uniform tier-deny outcome.
 *
 * WHAT: logs the access denial, bumps the op error metric, records the deny
 * verdict in the auth cache, sends the kXR_NotAuthorized wire response with
 * `msg`, stashes the return code in ctx->write_rc, and returns NGX_DONE.
 * WHY: every failing tier ran this identical five-step sequence; collapsing
 * it removes four near-duplicate blocks and keeps the deny path (and its wire
 * bytes / log strings) byte-identical across tiers — the security-load-bearing
 * default-deny contract.
 * HOW: `log_path` differs per tier (resolved vs reqpath), so the caller passes
 * it explicitly; ac_key/ac_have_key thread the already-computed cache key.
 */
static ngx_int_t
brix_auth_gate_deny(const auth_gate_ctx_t *g, const u_char ac_key[32],
    int ac_have_key, const char *log_path, const char *msg)
{
    brix_ctx_t  *ctx = g->ctx;

    brix_log_access(ctx, g->c, g->op_name, log_path, "-",
                      0, kXR_NotAuthorized, msg, 0);
    BRIX_OP_ERR(ctx, g->op_id);
    brix_auth_gate_cache_put(g->conf, ac_key, ac_have_key, 0, g->auth_level);
    ctx->write_rc = brix_send_error(ctx, g->c, kXR_NotAuthorized, msg);
    return NGX_DONE;
}

/*
 * brix_auth_gate_cache_probe — auth-result cache fast path (L1 then SHM L2).
 *
 * WHAT: computes the verdict key (folding the xrdacc-only op+host inputs) and,
 * on a hit, sets *out_verdict to the cached allow/deny; always sets *out_key
 * / *out_have_key so a subsequent miss can store the fresh verdict under the
 * same key.  Returns 1 when a cached verdict was found, 0 otherwise.
 * WHY: extracts the two-level cache lookup so brix_auth_gate_op reads as a
 * flat probe → evaluate → cache sequence; the E2 L1/L2 promotion and metric
 * counters stay verbatim.
 * HOW: lazily creates the per-worker L1; on an L2 hit it promotes into L1.
 * *out_have_key stays 0 when caching is disabled or the key overflows.
 */
static int
brix_auth_gate_cache_probe(const auth_gate_ctx_t *g, u_char out_key[32],
    int *out_have_key, int *out_verdict)
{
    ngx_stream_brix_srv_conf_t  *conf = g->conf;
    int             is_xrdacc = (conf->acc.format == BRIX_AUTHDB_FORMAT_XRDACC);
    /* xrdacc verdicts also depend on the operation and peer host, so fold both
     * into the key (native passes AOP_ANY + "" -> its keys are unchanged).  OS
     * group membership — the one remaining xrdacc input — is bounded by the
     * gidlifetime TTL, matching the auth-cache TTL, so a cached entry cannot
     * outlive a group change by more than the configured window. */
    brix_acc_op_t   key_aop  = is_xrdacc ? g->aop : BRIX_AOP_ANY;
    const char     *key_host = is_xrdacc ? g->ctx->login.peer_ip : "";
    brix_auth_cache_val_t  cv;

    *out_have_key = 0;

    if (conf->auth_cache.kv == NULL) {
        return 0;
    }

    *out_have_key = brix_auth_gate_cache_key(out_key, g, key_aop, key_host);
    if (!*out_have_key) {
        return 0;
    }

    /* Lazily create the per-worker L1 (COW-private per worker). */
    if (conf->auth_l1 == NULL) {
        conf->auth_l1 = brix_auth_l1_create(ngx_cycle->pool, 0);
    }

    if (brix_auth_l1_lookup(conf->auth_l1, out_key, &cv)) {
        BRIX_RESIL_METRIC_INC(auth_l1_hits_total);   /* L1 hit — no SHM spinlock */
    } else {
        size_t  cl = sizeof(cv);
        BRIX_RESIL_METRIC_INC(auth_l1_misses_total);
        if (brix_kv_get(conf->auth_cache.kv, out_key, 32, &cv, &cl) != 1
            || cl != sizeof(cv))
        {
            return 0;
        }
        /* Promote the L2 hit into L1 for the next presentation. */
        brix_auth_l1_store(conf->auth_l1, out_key, &cv,
            (ngx_msec_t) conf->auth_cache.ttl_secs * 1000);
    }

    *out_verdict = cv.allowed ? 1 : 0;
    return 1;
}

/*
 * brix_auth_gate_evaluate — run the three-tier check (authdb/xrdacc → VO ACL →
 * token scope) and emit the first denial.
 *
 * WHAT: on the first failing tier returns NGX_DONE (after brix_auth_gate_deny
 * has responded + stashed ctx->write_rc); returns NGX_OK when all tiers pass.
 * WHY: separates the slow-path policy evaluation from the cache plumbing so
 * neither exceeds the complexity gate; tier order and messages are frozen.
 * HOW: threads the pre-computed cache key so each deny records the verdict.
 */
static ngx_int_t
brix_auth_gate_evaluate(const auth_gate_ctx_t *g, const u_char ac_key[32],
    int ac_have_key)
{
    brix_ctx_t  *ctx = g->ctx;

    if (g->conf->acc.format == BRIX_AUTHDB_FORMAT_XRDACC) {
        /* XrdAcc authorizes the logical namespace path, not the backing FS path. */
        if (brix_acc_gate_engine(g, (g->reqpath != NULL) ? g->reqpath
                                                         : g->resolved) != NGX_OK)
        {
            return brix_auth_gate_deny(g, ac_key, ac_have_key,
                                         g->resolved, "xrdacc denied");
        }
    } else if (brix_check_authdb(ctx, g->resolved, g->auth_level) != NGX_OK) {
        return brix_auth_gate_deny(g, ac_key, ac_have_key,
                                     g->resolved, "authdb denied");
    }

    if (brix_check_vo_acl_identity(g->c->log, g->resolved, g->conf->vo_rules,
                                     ctx->identity) != NGX_OK) {
        return brix_auth_gate_deny(g, ac_key, ac_have_key,
                                     g->resolved, "VO not authorized");
    }

    if (brix_check_token_scope(ctx, g->reqpath, g->need_write) != NGX_OK) {
        return brix_auth_gate_deny(g, ac_key, ac_have_key,
                                     g->reqpath, "token scope denied");
    }

    return NGX_OK;
}

ngx_int_t
brix_auth_gate_op(brix_ctx_t *ctx, ngx_connection_t *c,
                 ngx_uint_t op_id, const char *op_name,
                 const char *reqpath, const char *resolved,
                 ngx_stream_brix_srv_conf_t *conf,
                 int auth_level, int need_write, brix_acc_op_t aop)
{
    auth_gate_ctx_t  g = {0};
    u_char           ac_key[32];
    int              ac_have_key = 0;
    int              verdict = 0;
    ngx_int_t        rc;

    g.ctx        = ctx;
    g.c          = c;
    g.conf       = conf;
    g.op_id      = op_id;
    g.op_name    = op_name;
    g.reqpath    = reqpath;
    g.resolved   = resolved;
    g.auth_level = auth_level;
    g.need_write = need_write;
    g.aop        = aop;

    /* auth-result cache: fast path (E2: lockless L1, then SHM L2). */
    if (brix_auth_gate_cache_probe(&g, ac_key, &ac_have_key, &verdict)) {
        if (!verdict) {
            brix_log_access(ctx, c, op_name, resolved, "-",
                              0, kXR_NotAuthorized,
                              "auth cache: denied", 0);
            BRIX_OP_ERR(ctx, op_id);
            ctx->write_rc = brix_send_error(ctx, c,
                kXR_NotAuthorized, "not authorized");
            return NGX_DONE;
        }
        return NGX_OK;             /* cached grant */
    }

    rc = brix_auth_gate_evaluate(&g, ac_key, ac_have_key);
    if (rc != NGX_OK) {
        return rc;
    }

    brix_auth_gate_cache_put(conf, ac_key, ac_have_key, 1, auth_level);
    return NGX_OK;
}

/*
 * brix_auth_gate — the common entry point: same three-tier check, with the
 * XrdAcc operation derived from the native auth_level (AOP_ANY).  Callers that
 * need a precise XrdAcc operation (create vs update, rename, stage) use
 * brix_auth_gate_op() directly.
 */
ngx_int_t
brix_auth_gate(brix_ctx_t *ctx, ngx_connection_t *c,
                 ngx_uint_t op_id, const char *op_name,
                 const char *reqpath, const char *resolved,
                 ngx_stream_brix_srv_conf_t *conf,
                 int auth_level, int need_write)
{
    return brix_auth_gate_op(ctx, c, op_id, op_name, reqpath, resolved,
                               conf, auth_level, need_write, BRIX_AOP_ANY);
}

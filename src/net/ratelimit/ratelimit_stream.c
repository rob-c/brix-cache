/*
 * ratelimit_stream.c — Phase 25 XRootD stream enforcement.
 *
 * The dispatch gate runs before each data-plane opcode handler.  Stat/ping/
 * close/sync and the session opcodes are never rate-limited (so keepalive and
 * health checks are unaffected).  A throttled request is answered with
 * kXR_wait(seconds) and the connection stays open for the client to retry;
 * the gate returns the send result so the dispatcher skips the handler.
 *
 * Returns NGX_DECLINED to proceed with normal dispatch.
 */
#include "ratelimit.h"
#include "protocols/root/response/response.h"          /* brix_send_wait */
#include "observability/metrics/metrics_macros.h"

#define BRIX_RL_METRIC_INC(field)                                          \
    do {                                                                     \
        ngx_brix_metrics_t *_m = brix_metrics_shared();                  \
        if (_m != NULL) { (void) ngx_atomic_fetch_add(&_m->field, 1); }      \
    } while (0)


/* Which opcodes carry request-count rate limiting. */
static int
rl_op_rate_limited(uint16_t reqid)
{
    switch (reqid) {
    case kXR_open:  case kXR_read:    case kXR_readv: case kXR_pgread:
    case kXR_write: case kXR_writev:  case kXR_pgwrite:
    case kXR_dirlist: case kXR_locate:
        return 1;
    default:
        return 0;   /* stat/statx/ping/close/sync/login/auth: never limited */
    }
}

/* True for opcodes whose request payload is the (raw) path — usable for
 * VOLUME-prefix matching.  Handle-bearing read/write ops are excluded. */
static int
rl_op_path_bearing(uint16_t reqid)
{
    switch (reqid) {
    case kXR_open: case kXR_dirlist: case kXR_locate:
        return 1;
    default:
        return 0;
    }
}

/* Copy the request path (payload up to '?' / NUL) into buf for a path-bearing
 * opcode; sets buf[0]='\0' otherwise. */
static void
rl_request_path(brix_ctx_t *ctx, char *buf, size_t bufsz)
{
    size_t n, i;

    buf[0] = '\0';
    if (!rl_op_path_bearing(ctx->recv.cur_reqid)
        || ctx->recv.payload == NULL || ctx->recv.cur_dlen == 0)
    {
        return;
    }
    n = (ctx->recv.cur_dlen < bufsz - 1) ? ctx->recv.cur_dlen : bufsz - 1;
    for (i = 0; i < n; i++) {
        u_char ch = ctx->recv.payload[i];
        if (ch == '\0' || ch == '?' || ch == '\n') { break; }
        buf[i] = (char) ch;
    }
    buf[i] = '\0';
}

/* ---- Resolve (and cache) the rate-limit key for one rule ----
 *
 * WHAT: Returns the enforcement key for rule i — either a cached
 * connection-constant key or a freshly computed one written into key_str.
 * Returns NULL when the rule does not match this request (VOLUME prefix miss
 * or key computation error), signalling the caller to skip the rule.
 *
 * WHY: Phase 33 C4 hot-path optimisation. Identity-stable rules (VO/ISSUER/
 * IP/DN) produce a connection-constant key; caching the first
 * BRIX_RL_RULE_CACHE_MAX of them on the ctx removes a per-read re-hash. VOLUME
 * rules are path-dependent and rules beyond the cache bound always recompute.
 * Isolating this keeps the gate loop free of the cache bookkeeping while
 * preserving the exact match/skip decision.
 *
 * HOW:
 *   1. A rule is cacheable when it is not a VOLUME rule and its index is below
 *      the cache bound.
 *   2. If cacheable and the cache slot is valid, return the cached key.
 *   3. Otherwise compute the key; on non-NGX_OK return NULL (rule skipped).
 *   4. If cacheable, populate and validate the cache slot, then return the key.
 */
static const char *
rl_resolve_key(brix_ctx_t *ctx, brix_rl_rule_t *rule, ngx_uint_t i,
    char *path, char *key_str, size_t key_str_sz)
{
    int cacheable;

    cacheable = (rule->key_type != BRIX_RL_KEY_VOLUME
                 && i < BRIX_RL_RULE_CACHE_MAX);

    if (cacheable && (ctx->rl.key_cache_valid & (1u << i))) {
        return ctx->rl.key_cache[i];
    }

    if (brix_rl_key_stream(rule, ctx, path, key_str, key_str_sz) != NGX_OK) {
        return NULL;   /* VOLUME prefix miss or error */
    }

    if (cacheable) {
        ngx_cpystrn((u_char *) ctx->rl.key_cache[i], (u_char *) key_str,
                    sizeof(ctx->rl.key_cache[i]));
        ctx->rl.key_cache_valid |= (1u << i);
    }
    return key_str;
}

/* ---- Enforce the request-rate dimension of one rule ----
 *
 * WHAT: If the rule caps request rate and this request exceeds it, emits the
 * throttle metric+log, stores the kXR_wait send result in *out_rc and returns
 * 1 (caller must return *out_rc). Returns 0 to proceed otherwise.
 *
 * WHY: Preserves the admit/reject decision of the original inline block — the
 * rate check runs only when req_rate > 0, and a throttled request answers with
 * kXR_wait(seconds) and stops dispatch.
 *
 * HOW:
 *   1. If req_rate > 0 and brix_rl_check reports NGX_AGAIN, throttle.
 *   2. Increment rl_throttled_stream_total, log the wait at INFO.
 *   3. Send kXR_wait(wait_sec) into *out_rc and return 1.
 *   4. Otherwise return 0.
 */
static int
rl_enforce_req_rate(brix_ctx_t *ctx, ngx_connection_t *c,
    brix_rl_rule_t *rule, const char *key, ngx_int_t *out_rc)
{
    uint32_t wait_sec;

    if (rule->req_rate > 0
        && brix_rl_check(rule, key, &wait_sec) == NGX_AGAIN)
    {
        BRIX_RL_METRIC_INC(rl_throttled_stream_total);
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
            "xrootd rate limit: kXR_wait %uD for op 0x%04xd (key=%s)",
            wait_sec, (int) ctx->recv.cur_reqid, key);
        *out_rc = brix_send_wait(ctx, c, wait_sec);
        return 1;
    }
    return 0;
}

/* ---- Enforce the bandwidth dimension of one rule ----
 *
 * WHAT: If the rule caps bandwidth and this request is over budget, throttles
 * (metric+log, *out_rc = kXR_wait, return 1). If within budget, records the
 * matched rule+key as the post-send charge target and returns 0. Rules with no
 * bandwidth cap return 0.
 *
 * WHY: Preserves the original decision AND its side effect: a bandwidth match
 * that is not throttled must remember the rule so brix_rl_charge_ctx() charges
 * the transferred bytes after the send.
 *
 * HOW:
 *   1. If the rule has no bandwidth cap, return 0.
 *   2. If brix_rl_bw_check reports NGX_AGAIN, throttle and return 1.
 *   3. Otherwise store bw_key/bw_rule as the charge target and return 0.
 */
static int
rl_enforce_bw_rate(brix_ctx_t *ctx, ngx_connection_t *c,
    brix_rl_rule_t *rule, const char *key, ngx_int_t *out_rc)
{
    uint32_t wait_sec;

    if (rule->bw_rate <= 0) {
        return 0;
    }

    if (brix_rl_bw_check(rule, key, &wait_sec) == NGX_AGAIN) {
        BRIX_RL_METRIC_INC(rl_throttled_stream_total);
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
            "xrootd rate limit: kXR_wait %uD (bandwidth, key=%s)",
            wait_sec, key);
        *out_rc = brix_send_wait(ctx, c, wait_sec);
        return 1;
    }

    /* Remember the matched bandwidth rule for the post-send charge. */
    ngx_cpystrn((u_char *) ctx->rl.bw_key, (u_char *) key,
                sizeof(ctx->rl.bw_key));
    ctx->rl.bw_rule = rule;
    return 0;
}

/* ---- Enforce the concurrency dimension of one rule ----
 *
 * WHAT: Reserves one in-flight connection slot for this principal on the first
 * matching concurrency rule. Over-cap throttles (*out_rc = kXR_wait(1),
 * return 1); on success records the slot for release and returns 0. Returns 0
 * when the rule has no concurrency cap or a slot is already held.
 *
 * WHY: Concurrency dimension (W7, stream). The stream plane has no per-request
 * teardown, so the slot is held for the CONNECTION's lifetime — acquired once
 * on the first matching rule and released exactly once in brix_on_disconnect()
 * via brix_rl_release_ctx(). This caps concurrent connections per principal;
 * over-cap answers kXR_wait so the client retries when a slot frees. The
 * once-per-connection guard (conc_rule == NULL) must be preserved exactly.
 *
 * HOW:
 *   1. If no concurrency cap or a slot is already held, return 0.
 *   2. If brix_rl_conc_acquire reports NGX_AGAIN, throttle and return 1.
 *   3. Otherwise record conc_key/conc_rule for later release and return 0.
 */
static int
rl_enforce_conc(brix_ctx_t *ctx, ngx_connection_t *c,
    brix_rl_rule_t *rule, const char *key, ngx_int_t *out_rc)
{
    if (rule->req_conc <= 0 || ctx->rl.conc_rule != NULL) {
        return 0;
    }

    if (brix_rl_conc_acquire(rule, key) == NGX_AGAIN) {
        BRIX_RL_METRIC_INC(rl_throttled_stream_total);
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
            "xrootd rate limit: kXR_wait (concurrency cap, key=%s)",
            key);
        *out_rc = brix_send_wait(ctx, c, 1);
        return 1;
    }

    ngx_cpystrn((u_char *) ctx->rl.conc_key, (u_char *) key,
                sizeof(ctx->rl.conc_key));
    ctx->rl.conc_rule = rule;
    return 0;
}

/* ---- Determine whether any VOLUME rule needs the request path ----
 *
 * WHAT: Copies the request path into path (via rl_request_path) when at least
 * one configured rule is a VOLUME (path-prefix) rule; otherwise leaves
 * path[0] = '\0'.
 *
 * WHY: Phase 33 C4: the request path is only needed to match VOLUME rules.
 * Reads — the hot path — are not path-bearing and have no VOLUME match, so the
 * payload copy is skipped entirely unless a VOLUME rule exists.
 *
 * HOW:
 *   1. Initialise path to empty.
 *   2. Scan rules; on the first VOLUME rule copy the request path and stop.
 */
static void
rl_maybe_load_path(brix_ctx_t *ctx, brix_rl_rule_t *rules, ngx_uint_t nelts,
    char *path, size_t path_sz)
{
    ngx_uint_t i;

    path[0] = '\0';
    for (i = 0; i < nelts; i++) {
        if (rules[i].key_type == BRIX_RL_KEY_VOLUME) {
            rl_request_path(ctx, path, path_sz);
            break;
        }
    }
}

ngx_int_t
brix_rl_stream_gate(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    brix_rl_rule_t *rules;
    ngx_uint_t        i;
    char              key_str[BRIX_RL_KEY_LEN];
    char              path[1024];
    ngx_int_t         rc;

    if (conf->rl_rules == NULL || conf->rl_rules->nelts == 0) {
        return NGX_DECLINED;
    }
    if (!rl_op_rate_limited(ctx->recv.cur_reqid)) {
        return NGX_DECLINED;
    }

    /* Reset any stale bandwidth charge target from the previous request. */
    ctx->rl.bw_rule = NULL;

    rules = conf->rl_rules->elts;
    rl_maybe_load_path(ctx, rules, conf->rl_rules->nelts, path, sizeof(path));

    for (i = 0; i < conf->rl_rules->nelts; i++) {
        const char *key;

        key = rl_resolve_key(ctx, &rules[i], i, path, key_str,
                             sizeof(key_str));
        if (key == NULL) { continue; }   /* rule does not match this request */

        if (rl_enforce_req_rate(ctx, c, &rules[i], key, &rc)) { return rc; }
        if (rl_enforce_bw_rate(ctx, c, &rules[i], key, &rc)) { return rc; }
        if (rl_enforce_conc(ctx, c, &rules[i], key, &rc)) { return rc; }
    }

    return NGX_DECLINED;
}

void
brix_rl_charge_ctx(brix_ctx_t *ctx, size_t nbytes)
{
    if (ctx->rl.bw_rule != NULL && ctx->rl.bw_key[0] != '\0') {
        brix_rl_charge_bytes((brix_rl_rule_t *) ctx->rl.bw_rule,
                               ctx->rl.bw_key, nbytes);
    }
}

void
brix_rl_release_ctx(brix_ctx_t *ctx)
{
    if (ctx->rl.conc_rule != NULL) {
        brix_rl_conc_release((brix_rl_rule_t *) ctx->rl.conc_rule,
                               ctx->rl.conc_key);
        ctx->rl.conc_rule = NULL;
        ctx->rl.conc_key[0] = '\0';
    }
}

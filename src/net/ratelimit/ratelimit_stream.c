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
    if (!rl_op_path_bearing(ctx->cur_reqid)
        || ctx->payload == NULL || ctx->cur_dlen == 0)
    {
        return;
    }
    n = (ctx->cur_dlen < bufsz - 1) ? ctx->cur_dlen : bufsz - 1;
    for (i = 0; i < n; i++) {
        u_char ch = ctx->payload[i];
        if (ch == '\0' || ch == '?' || ch == '\n') { break; }
        buf[i] = (char) ch;
    }
    buf[i] = '\0';
}

ngx_int_t
brix_rl_stream_gate(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    brix_rl_rule_t *rules;
    ngx_uint_t        i;
    char              key_str[BRIX_RL_KEY_LEN];
    char              path[1024];
    uint32_t          wait_sec;
    ngx_int_t         rc;

    if (conf->rl_rules == NULL || conf->rl_rules->nelts == 0) {
        return NGX_DECLINED;
    }
    if (!rl_op_rate_limited(ctx->cur_reqid)) {
        return NGX_DECLINED;
    }

    /* Reset any stale bandwidth charge target from the previous request. */
    ctx->rl_bw_rule = NULL;

    rules = conf->rl_rules->elts;

    /*
     * Phase 33 C4: the request path is only needed to match VOLUME (path-prefix)
     * rules.  Reads — the hot path — are not path-bearing and have no VOLUME
     * match, so skip the payload copy entirely unless a VOLUME rule exists.
     */
    path[0] = '\0';
    for (i = 0; i < conf->rl_rules->nelts; i++) {
        if (rules[i].key_type == BRIX_RL_KEY_VOLUME) {
            rl_request_path(ctx, path, sizeof(path));
            break;
        }
    }

    for (i = 0; i < conf->rl_rules->nelts; i++) {
        const char *key;
        int cacheable;

        /*
         * Phase 33 C4: identity-stable rules (VO/ISSUER/IP/DN) produce a
         * connection-constant key.  Cache the first BRIX_RL_RULE_CACHE_MAX such
         * keys on the ctx and reuse them, removing the per-read re-hash.  VOLUME
         * rules are path-dependent and rules beyond the cache bound recompute.
         */
        cacheable = (rules[i].key_type != BRIX_RL_KEY_VOLUME
                     && i < BRIX_RL_RULE_CACHE_MAX);

        if (cacheable && (ctx->rl_key_cache_valid & (1u << i))) {
            key = ctx->rl_key_cache[i];
        } else {
            rc = brix_rl_key_stream(&rules[i], ctx, path,
                                      key_str, sizeof(key_str));
            if (rc != NGX_OK) { continue; }   /* VOLUME prefix miss or error */
            key = key_str;
            if (cacheable) {
                ngx_cpystrn((u_char *) ctx->rl_key_cache[i], (u_char *) key_str,
                            sizeof(ctx->rl_key_cache[i]));
                ctx->rl_key_cache_valid |= (1u << i);
            }
        }

        if (rules[i].req_rate > 0) {
            if (brix_rl_check(&rules[i], key, &wait_sec) == NGX_AGAIN) {
                BRIX_RL_METRIC_INC(rl_throttled_stream_total);
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                    "xrootd rate limit: kXR_wait %uD for op 0x%04xd (key=%s)",
                    wait_sec, (int) ctx->cur_reqid, key);
                return brix_send_wait(ctx, c, wait_sec);
            }
        }

        if (rules[i].bw_rate > 0) {
            if (brix_rl_bw_check(&rules[i], key, &wait_sec) == NGX_AGAIN) {
                BRIX_RL_METRIC_INC(rl_throttled_stream_total);
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                    "xrootd rate limit: kXR_wait %uD (bandwidth, key=%s)",
                    wait_sec, key);
                return brix_send_wait(ctx, c, wait_sec);
            }
            /* Remember the matched bandwidth rule for the post-send charge. */
            ngx_cpystrn((u_char *) ctx->rl_bw_key, (u_char *) key,
                        sizeof(ctx->rl_bw_key));
            ctx->rl_bw_rule = &rules[i];
        }

        /*
         * Concurrency dimension (W7, stream): reserve one in-flight slot for
         * this connection's principal.  Unlike the HTTP plane (one slot per
         * request, released in the LOG phase) the stream plane has no per-request
         * teardown, so the slot is held for the CONNECTION's lifetime — acquired
         * once on the first matching rule and released exactly once in
         * brix_on_disconnect() via brix_rl_release_ctx().  This caps the
         * number of concurrent connections per principal; over-cap → kXR_wait so
         * the client retries when a slot frees.
         */
        if (rules[i].req_conc > 0 && ctx->rl_conc_rule == NULL) {
            if (brix_rl_conc_acquire(&rules[i], key) == NGX_AGAIN) {
                BRIX_RL_METRIC_INC(rl_throttled_stream_total);
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                    "xrootd rate limit: kXR_wait (concurrency cap, key=%s)",
                    key);
                return brix_send_wait(ctx, c, 1);
            }
            ngx_cpystrn((u_char *) ctx->rl_conc_key, (u_char *) key,
                        sizeof(ctx->rl_conc_key));
            ctx->rl_conc_rule = &rules[i];
        }
    }

    return NGX_DECLINED;
}

void
brix_rl_charge_ctx(brix_ctx_t *ctx, size_t nbytes)
{
    if (ctx->rl_bw_rule != NULL && ctx->rl_bw_key[0] != '\0') {
        brix_rl_charge_bytes((brix_rl_rule_t *) ctx->rl_bw_rule,
                               ctx->rl_bw_key, nbytes);
    }
}

void
brix_rl_release_ctx(brix_ctx_t *ctx)
{
    if (ctx->rl_conc_rule != NULL) {
        brix_rl_conc_release((brix_rl_rule_t *) ctx->rl_conc_rule,
                               ctx->rl_conc_key);
        ctx->rl_conc_rule = NULL;
        ctx->rl_conc_key[0] = '\0';
    }
}

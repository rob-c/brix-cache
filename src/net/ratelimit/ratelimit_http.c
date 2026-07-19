/*
 * ratelimit_http.c — Phase 25 HTTP/WebDAV enforcement.
 *
 * An NGX_HTTP_ACCESS_PHASE handler (registered after the auth handler so the
 * identity is populated) evaluates every rule attached to the location.  A
 * request-rate throttle returns 429 with Retry-After (unless `nodelay`); a
 * bandwidth rule that is already overflowing returns 429 too, and otherwise
 * stashes the matched rule + key on the request ctx so the body filter can
 * charge the actual bytes sent.
 */
#include "ratelimit.h"
#include "protocols/webdav/webdav.h"
#include "core/http/http_headers.h"
#include "observability/metrics/metrics_macros.h"

/* Size of the lazily-resolved VOLUME-rule path buffer (handler local +
 * rl_resolve_volume_path share this so the size is not passed as a param). */
#define BRIX_RL_PATH_LEN 1024

#define BRIX_RL_METRIC_INC(field)                                          \
    do {                                                                     \
        ngx_brix_metrics_t *_m = brix_metrics_shared();                  \
        if (_m != NULL) { (void) ngx_atomic_fetch_add(&_m->field, 1); }      \
    } while (0)


static ngx_int_t
rl_reject(ngx_http_request_t *r, brix_rl_rule_t *rule, uint32_t wait_sec,
    const char *key_str)
{
    BRIX_RL_METRIC_INC(rl_throttled_http_total);

    if (!rule->nodelay && wait_sec > 0) {
        char buf[NGX_INT_T_LEN + 1];
        ngx_snprintf((u_char *) buf, sizeof(buf), "%ud%Z", wait_sec);
        (void) brix_http_set_header(r, "Retry-After", buf, NULL);
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "xrootd rate limit: 429 for \"%V\" (key=%s, wait=%uD)",
        &r->uri, key_str, wait_sec);

    return NGX_HTTP_TOO_MANY_REQUESTS;
}

/*
 * WHAT:  Ensure the WebDAV request ctx exists, allocating+installing it lazily.
 * WHY:   The body/log phase charges bandwidth and releases concurrency slots
 *        via this ctx; the auth gate may not have created one (anonymous
 *        WebDAV), so a rate-limit dimension that needs to stash state must be
 *        able to conjure it on demand.
 * HOW:   Return the existing ctx unchanged; otherwise pcalloc from the request
 *        pool and install it, mirroring the original inline behaviour exactly
 *        (a failed pcalloc leaves the slot unset and returns NULL).
 */
static ngx_http_brix_webdav_req_ctx_t *
rl_ensure_ctx(ngx_http_request_t *r, ngx_http_brix_webdav_req_ctx_t *wctx)
{
    if (wctx != NULL) {
        return wctx;
    }
    wctx = ngx_pcalloc(r->pool, sizeof(*wctx));
    if (wctx != NULL) {
        ngx_http_set_ctx(r, wctx, ngx_http_brix_webdav_module);
    }
    return wctx;
}

/*
 * WHAT:  Resolve the request path lazily, only the first time a VOLUME rule is
 *        encountered.
 * WHY:   Only VOLUME rules key on the path; resolving it is a syscall we skip
 *        entirely when no such rule matches, and do at most once per request.
 * HOW:   No-op unless this is a VOLUME rule and the path has not been resolved
 *        yet; on resolve failure the buffer is emptied (rl_req.path aliases it),
 *        and *have_path is latched so the work never repeats.
 */
static void
rl_resolve_volume_path(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *lcf, const brix_rl_rule_t *rule,
    char *path, int *have_path)
{
    if (rule->key_type != BRIX_RL_KEY_VOLUME || *have_path) {
        return;
    }
    if (ngx_http_brix_webdav_resolve_path(r, lcf->common.root_canon,
            path, BRIX_RL_PATH_LEN) != NGX_OK)
    {
        path[0] = '\0';
    }
    *have_path = 1;
}

/*
 * WHAT:  Evaluate the bandwidth dimension of one rule.
 * WHY:   An already-overflowing bandwidth key rejects immediately; otherwise
 *        the matched rule+key are stashed so the log phase can charge the bytes
 *        actually sent.
 * HOW:   Pre-check; on NGX_AGAIN return the 429 verdict.  On pass, ensure a ctx
 *        (updating *wctx_p) and record the key+rule when one is available.
 *        Returns NGX_OK to continue, or the reject code to propagate.
 */
static ngx_int_t
rl_check_bw(ngx_http_request_t *r, brix_rl_rule_t *rule,
    const char *key_str, ngx_http_brix_webdav_req_ctx_t **wctx_p)
{
    ngx_http_brix_webdav_req_ctx_t *wctx;
    uint32_t                        wait_sec;

    if (rule->bw_rate <= 0) {
        return NGX_OK;
    }
    if (brix_rl_bw_check(rule, key_str, &wait_sec) == NGX_AGAIN) {
        return rl_reject(r, rule, wait_sec, key_str);
    }
    wctx = rl_ensure_ctx(r, *wctx_p);
    *wctx_p = wctx;
    if (wctx != NULL) {
        ngx_cpystrn((u_char *) wctx->rl_key_str, (u_char *) key_str,
                    sizeof(wctx->rl_key_str));
        wctx->rl_bw_rule = rule;
    }
    return NGX_OK;
}

/*
 * WHAT:  Evaluate the concurrency dimension (W7) of one rule.
 * WHY:   Reserve at most one in-flight slot per request so the log-phase
 *        release pairs exactly; an exhausted key rejects with 429.
 * HOW:   Skip unless the rule caps concurrency and no slot is held yet.  On
 *        acquire failure return the reject code.  On success, ensure a ctx to
 *        record the release target and latch *conc_held; if no ctx can be
 *        allocated, hand the slot back immediately rather than leak it.
 *        Returns NGX_OK to continue, or the reject code to propagate.
 */
static ngx_int_t
rl_check_conc(ngx_http_request_t *r, brix_rl_rule_t *rule,
    const char *key_str, ngx_http_brix_webdav_req_ctx_t **wctx_p,
    int *conc_held)
{
    ngx_http_brix_webdav_req_ctx_t *wctx;

    if (rule->req_conc <= 0 || *conc_held) {
        return NGX_OK;
    }
    if (brix_rl_conc_acquire(rule, key_str) == NGX_AGAIN) {
        return rl_reject(r, rule, 0, key_str);
    }
    wctx = rl_ensure_ctx(r, *wctx_p);
    *wctx_p = wctx;
    if (wctx != NULL) {
        ngx_cpystrn((u_char *) wctx->rl_conc_key, (u_char *) key_str,
                    sizeof(wctx->rl_conc_key));
        wctx->rl_conc_rule = rule;
        *conc_held = 1;
    } else {
        /* No ctx to stash the release target — give the slot back now rather
         * than leak it (degrades to no concurrency cap). */
        brix_rl_conc_release(rule, key_str);
    }
    return NGX_OK;
}

/*
 * WHAT:  Evaluate every rate-limit dimension of one matched rule.
 * WHY:   Keeps the per-rule verdict logic (rate → bandwidth → concurrency, in
 *        that short-circuit order) in one place so the loop body stays flat.
 * HOW:   Request-rate rejects on NGX_AGAIN; bandwidth and concurrency delegate
 *        to their helpers (which may update *wctx_p / *conc_held).  Returns
 *        NGX_OK to continue the loop, or a 429 code to return from the handler.
 */
static ngx_int_t
rl_apply_rule(ngx_http_request_t *r, brix_rl_rule_t *rule,
    const char *key_str, ngx_http_brix_webdav_req_ctx_t **wctx_p,
    int *conc_held)
{
    uint32_t  wait_sec;
    ngx_int_t rc;

    if (rule->req_rate > 0
        && brix_rl_check(rule, key_str, &wait_sec) == NGX_AGAIN)
    {
        return rl_reject(r, rule, wait_sec, key_str);
    }

    rc = rl_check_bw(r, rule, key_str, wctx_p);
    if (rc != NGX_OK) {
        return rc;
    }

    return rl_check_conc(r, rule, key_str, wctx_p, conc_held);
}

ngx_int_t
brix_rl_http_access_handler(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *lcf;
    ngx_http_brix_webdav_req_ctx_t  *wctx;
    brix_rl_rule_t                  *rules;
    rl_key_req_t                       rl_req;
    ngx_uint_t                         i;
    char                               key_str[BRIX_RL_KEY_LEN];
    char                               path[BRIX_RL_PATH_LEN];
    int                                have_path = 0;
    int                                conc_held = 0;   /* W7: one slot/request */
    ngx_int_t                          rc;

    if (r != r->main) {
        return NGX_DECLINED;       /* subrequests inherit the parent's verdict */
    }

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    if (lcf == NULL || lcf->rl_rules == NULL || lcf->rl_rules->nelts == 0) {
        return NGX_DECLINED;
    }
    wctx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);

    rules = lcf->rl_rules->elts;
    path[0] = '\0';

    /*
     * Resolve the identity handles once, before the per-rule loop: the unified
     * identity from the WebDAV ctx and the connection address.  brix_rl_key_http
     * then reads this bundle rather than re-deriving them per call.  `path` is
     * still filled lazily below (only VOLUME rules need it); rl_req.path aliases
     * the buffer so those rules see the resolved value.
     */
    rl_req.id   = wctx ? wctx->identity : NULL;
    rl_req.wctx = wctx;
    rl_req.ip   = &r->connection->addr_text;
    rl_req.path = path;

    for (i = 0; i < lcf->rl_rules->nelts; i++) {

        rl_resolve_volume_path(r, lcf, &rules[i], path, &have_path);

        rc = brix_rl_key_http(&rules[i], &rl_req, key_str, sizeof(key_str));
        if (rc != NGX_OK) { continue; }   /* volume prefix / key did not match */

        rc = rl_apply_rule(r, &rules[i], key_str, &wctx, &conc_held);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    return NGX_DECLINED;       /* allowed — fall through to the next phase */
}


/* bandwidth charge (LOG phase) * The WebDAV file-serve path sends bytes via a thread-pool/sendfile context
 * that does not reliably traverse a chained body filter, so bandwidth is
 * charged once per request in the log phase from the known response size. */
ngx_int_t
brix_rl_http_log_handler(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *lcf;
    ngx_http_brix_webdav_req_ctx_t  *wctx;
    off_t                              nbytes;

    if (r != r->main) {
        return NGX_OK;
    }
    lcf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    if (lcf == NULL) {
        return NGX_OK;
    }
    wctx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    if (wctx == NULL) {
        return NGX_OK;
    }

    /* W7 — release the concurrency slot exactly once (the log phase runs for
     * every finalized request, including errors/aborts, so this never leaks). */
    if (wctx->rl_conc_rule != NULL && wctx->rl_conc_key[0] != '\0') {
        brix_rl_conc_release((brix_rl_rule_t *) wctx->rl_conc_rule,
                               wctx->rl_conc_key);
        wctx->rl_conc_rule = NULL;
        wctx->rl_conc_key[0] = '\0';
    }

    if (wctx->rl_bw_rule == NULL || wctx->rl_key_str[0] == '\0') {
        return NGX_OK;
    }

    nbytes = r->headers_out.content_length_n;
    if (nbytes <= 0) {
        /* Fallback to bytes actually written on the connection minus headers
         * (best-effort when the length was not declared, e.g. chunked). */
        nbytes = (off_t) r->connection->sent - (off_t) r->header_size;
    }
    if (nbytes > 0) {
        brix_rl_charge_bytes((brix_rl_rule_t *) wctx->rl_bw_rule,
                               wctx->rl_key_str, (size_t) nbytes);
    }
    return NGX_OK;
}

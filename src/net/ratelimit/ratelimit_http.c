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

ngx_int_t
brix_rl_http_access_handler(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *lcf;
    ngx_http_brix_webdav_req_ctx_t  *wctx;
    brix_rl_rule_t                  *rules;
    ngx_uint_t                         i;
    char                               key_str[BRIX_RL_KEY_LEN];
    char                               path[1024];
    int                                have_path = 0;
    int                                conc_held = 0;   /* W7: one slot/request */
    uint32_t                           wait_sec;
    ngx_int_t                          rc;

    if (r != r->main) {
        return NGX_DECLINED;       /* subrequests inherit the parent's verdict */
    }

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    if (lcf == NULL || lcf->rl_rules == NULL || lcf->rl_rules->nelts == 0) {
        return NGX_DECLINED;
    }
    /*
     * In WebDAV proxy mode the webdav module's request-ctx slot is owned by the
     * proxy (webdav_proxy_ctx_t, set in proxy.c), NOT the rate-limit req_ctx.
     * Touching it here would acquire a concurrency slot the log phase can never
     * release (it would read the proxy ctx as a req_ctx → garbage rule pointer →
     * crash, see brix_rl_http_log_handler).  Rate limiting does not apply to
     * proxied requests; leave the slot to the proxy.
     */
    if (lcf->upstream_proxy) {
        return NGX_DECLINED;
    }
    wctx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);

    rules = lcf->rl_rules->elts;
    path[0] = '\0';

    for (i = 0; i < lcf->rl_rules->nelts; i++) {

        /* Resolve the request path lazily, only for VOLUME rules. */
        if (rules[i].key_type == BRIX_RL_KEY_VOLUME && !have_path) {
            if (ngx_http_brix_webdav_resolve_path(r, lcf->common.root_canon,
                    path, sizeof(path)) != NGX_OK)
            {
                path[0] = '\0';
            }
            have_path = 1;
        }

        rc = brix_rl_key_http(&rules[i], r, wctx, path,
                                key_str, sizeof(key_str));
        if (rc == NGX_DECLINED) { continue; }   /* volume prefix did not match */
        if (rc != NGX_OK)       { continue; }

        /* Request-rate dimension. */
        if (rules[i].req_rate > 0) {
            if (brix_rl_check(&rules[i], key_str, &wait_sec) == NGX_AGAIN) {
                return rl_reject(r, &rules[i], wait_sec, key_str);
            }
        }

        /* Bandwidth dimension: pre-check, then remember for the body filter. */
        if (rules[i].bw_rate > 0) {
            if (brix_rl_bw_check(&rules[i], key_str, &wait_sec) == NGX_AGAIN) {
                return rl_reject(r, &rules[i], wait_sec, key_str);
            }
            /* The body filter charges via the request ctx — allocate one if the
             * auth gate did not (e.g. anonymous WebDAV). */
            if (wctx == NULL) {
                wctx = ngx_pcalloc(r->pool, sizeof(*wctx));
                if (wctx != NULL) {
                    ngx_http_set_ctx(r, wctx, ngx_http_brix_webdav_module);
                }
            }
            if (wctx != NULL) {
                ngx_cpystrn((u_char *) wctx->rl_key_str, (u_char *) key_str,
                            sizeof(wctx->rl_key_str));
                wctx->rl_bw_rule = &rules[i];
            }
        }

        /* Concurrency dimension (W7): reserve one in-flight slot, released in
         * the log phase.  Only one slot per request so the pairing is exact. */
        if (rules[i].req_conc > 0 && !conc_held) {
            if (brix_rl_conc_acquire(&rules[i], key_str) == NGX_AGAIN) {
                return rl_reject(r, &rules[i], 0, key_str);
            }
            if (wctx == NULL) {
                wctx = ngx_pcalloc(r->pool, sizeof(*wctx));
                if (wctx != NULL) {
                    ngx_http_set_ctx(r, wctx, ngx_http_brix_webdav_module);
                }
            }
            if (wctx != NULL) {
                ngx_cpystrn((u_char *) wctx->rl_conc_key, (u_char *) key_str,
                            sizeof(wctx->rl_conc_key));
                wctx->rl_conc_rule = &rules[i];
                conc_held = 1;
            } else {
                /* No ctx to stash the release target — give the slot back now
                 * rather than leak it (degrades to no concurrency cap). */
                brix_rl_conc_release(&rules[i], key_str);
            }
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
    /*
     * In proxy mode the webdav module ctx slot holds a webdav_proxy_ctx_t, not
     * our req_ctx — reading rl_conc_rule/rl_conc_key off it would dereference a
     * garbage rule pointer (observed SIGSEGV in brix_rl_conc_release).  The
     * access handler likewise skips proxied locations, so there is never a slot
     * to release here.  Bail before interpreting the foreign ctx.
     */
    lcf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    if (lcf == NULL || lcf->upstream_proxy) {
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

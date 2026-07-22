#include "gsi_internal.h"
#include "delegation.h"
#include "protocols/root/session/registry.h"
#include "auth/crypto/ocsp.h"
#include "auth/crypto/gsi_verify.h"
#include <openssl/err.h>
#include <openssl/pem.h>

/*
 * Phase 51 (E4): per-worker in-flight GSI-handshake gauge.  A GSI handshake is
 * multi-round-trip (certreq → cert), so many can be parked in progress at once,
 * each holding ephemeral-DH + chain-verify CPU state.  Under a flood of
 * simultaneous handshakes that buries the single-threaded event loop, this caps
 * the number admitted concurrently per worker and sheds the excess with kXR_wait
 * (the client waits and retries).  Cache hits / already-authed sessions never
 * touch this.  Released EXACTLY ONCE — at auth completion OR at disconnect (the
 * guaranteed funnel) — gated by ctx->login.gsi_counted, so the gauge can never leak and
 * wedge auth.  Lock-free: per-worker, event-loop only.
 */
static ngx_uint_t  brix_gsi_inflight;

ngx_int_t
brix_gsi_inflight_admit(brix_ctx_t *ctx, ngx_int_t cap)
{
    if (ctx->login.gsi_counted) {
        return 1;                  /* already counted this handshake */
    }
    if (cap > 0 && brix_gsi_inflight >= (ngx_uint_t) cap) {
        return 0;                  /* over the cap — shed */
    }
    brix_gsi_inflight++;
    ctx->login.gsi_counted = 1;
    return 1;
}

void
brix_gsi_inflight_release(brix_ctx_t *ctx)
{
    if (ctx->login.gsi_counted) {
        if (brix_gsi_inflight > 0) {
            brix_gsi_inflight--;
        }
        ctx->login.gsi_counted = 0;
    }
}

/*
 * brix_gsi_complete_auth — finalize a successful GSI authentication once the
 * client's DN is known: per-identity rate limit, auth_done, identity/session
 * registration, and metrics. Factored so both the normal kXGC_cert path and the
 * §F6 delegation path (which completes only after kXGC_sigpxy) share one
 * completion. Returns via BRIX_RETURN_OK / BRIX_RETURN_ERR.
 */
ngx_int_t
brix_gsi_complete_auth(brix_ctx_t *ctx, ngx_connection_t *c,
                         ngx_stream_brix_srv_conf_t *conf)
{
    /* Phase 20: per-identity request rate limit, applied once the DN is known. */
    if (conf->rate_limit.kv != NULL) {
        const char *rl_id = conf->rate_limit.key_ip ? ctx->login.peer_ip : ctx->login.dn;

        if (brix_rate_limit_check(&conf->rate_limit, rl_id,
                                    ngx_strlen(rl_id)) != NGX_OK)
        {
            BRIX_RETURN_ERR(ctx, c, BRIX_OP_AUTH, "AUTH", "-", "gsi",
                              kXR_NotAuthorized, "rate limit exceeded");
        }
    }

    ctx->login.auth_done = 1;
    brix_gsi_inflight_release(ctx);   /* E4: handshake done — free the slot */
    if (ctx->identity != NULL) {
        if (brix_identity_set_dn(ctx->identity, c->pool, ctx->login.dn,
                                   BRIX_AUTHN_GSI) != NGX_OK
            || brix_identity_set_vos_csv(ctx->identity, c->pool,
                                           ctx->login.vo_list) != NGX_OK)
        {
            return brix_send_error(ctx, c, kXR_NoMemory,
                                     "identity allocation failed");
        }
    }
    brix_session_register(ctx->login.sessid, ctx->login.dn, ctx->login.vo_list, 0);

    /* Track unique user and VO at auth completion. */
    {
        ngx_brix_metrics_t *shm = brix_metrics_shared();
        if (shm != NULL) {
            size_t vo_len = strlen(ctx->login.primary_vo);
            if (vo_len > 0 && vo_len < sizeof(ctx->login.primary_vo)) {
                brix_track_vo_activity(shm, ctx->login.primary_vo, 0, 0);
                ngx_uint_t vi;
                for (vi = 0; vi < BRIX_VO_MAX_TRACKED; vi++) {
                    if (ngx_strncmp(shm->vo_global.slots[vi].name, ctx->login.primary_vo,
                                    BRIX_VO_NAME_LEN) == 0)
                    {
                        BRIX_ATOMIC_INC(&shm->vo_global.slots[vi].requests_total);
                        break;
                    }
                }
            }
            brix_track_unique_user(shm, ctx->login.dn, strlen(ctx->login.dn));
        }
    }

    {
        char dn_log[1024];

        brix_sanitize_log_string(ctx->login.dn, dn_log, sizeof(dn_log));
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "brix: GSI auth OK dn=\"%s\"", dn_log);
    }

    BRIX_RETURN_OK(ctx, c, BRIX_OP_AUTH, "AUTH", "-", "gsi", 0);
}

/*
 * gsi_auth_cred_route_t — one kXR_auth credtype dispatch row.
 *
 * WHY:  kXR_auth multiplexes every credential protocol through one opcode;
 *       a descriptor table keeps the routing flat and auditable instead of a
 *       branch ladder per protocol.
 *
 * HOW:  `name` is the wire credential tag; only the first `cmp_len` of the
 *       4 wire bytes are significant (3-char tags accept any 4th byte, the
 *       stock-client behavior). `mode`/`mode_alt` are the brix_auth modes
 *       that admit the protocol (equal when only one mode does); `deny_msg`
 *       is the kXR_NotAuthorized text when the mode is off. `handler` is the
 *       protocol's own kXR_auth handler; NULL marks the GSI row, whose step
 *       machine lives in this file (routing falls through to the caller).
 */
typedef struct {
    const char  *name;                       /* credtype tag ("ztn", ...)   */
    size_t       cmp_len;                    /* significant tag bytes (3|4) */
    ngx_uint_t   mode;                       /* admitting BRIX_AUTH_* mode  */
    ngx_uint_t   mode_alt;                   /* second admitting mode       */
    const char  *deny_msg;                   /* error when mode is off      */
    ngx_int_t  (*handler)(brix_ctx_t *ctx, ngx_connection_t *c,
                          ngx_stream_brix_srv_conf_t *conf);
} gsi_auth_cred_route_t;

/* Match order is load-bearing: it mirrors the original check ladder. */
static const gsi_auth_cred_route_t  gsi_auth_cred_routes[] = {
    { "ztn",  3, BRIX_AUTH_TOKEN, BRIX_AUTH_BOTH, "token auth not enabled",
      brix_handle_token_auth },
    { "sss",  3, BRIX_AUTH_SSS,   BRIX_AUTH_SSS,  "SSS auth not enabled",
      brix_handle_sss_auth },
    { "unix", 4, BRIX_AUTH_UNIX,  BRIX_AUTH_UNIX, "unix auth not enabled",
      brix_handle_unix_auth },
    { "krb5", 4, BRIX_AUTH_KRB5,  BRIX_AUTH_KRB5, "krb5 auth not enabled",
      brix_handle_krb5_auth },
    { "host", 4, BRIX_AUTH_HOST,  BRIX_AUTH_HOST, "host auth not enabled",
      brix_handle_host_auth },
    { "pwd",  4, BRIX_AUTH_PWD,   BRIX_AUTH_PWD,  "pwd auth not enabled",
      brix_handle_pwd_auth },
    { "gsi",  3, BRIX_AUTH_GSI,   BRIX_AUTH_BOTH, "GSI auth not enabled",
      NULL },
};

/*
 * gsi_auth_route_credtype — route a kXR_auth request by its 4-byte credtype.
 *
 * WHY:  Non-GSI protocols (ztn/sss/unix/krb5/host/pwd) each have their own
 *       handler; only GSI continues into this file's DH step machine.
 *       Isolating the routing keeps the dispatcher a pure step machine.
 *
 * HOW:  Reads the credtype from the wire, walks gsi_auth_cred_routes in
 *       order, enforces the configured auth mode (deny → kXR_NotAuthorized
 *       with the row's message), and invokes the row handler. Unknown tags
 *       are logged (sanitized) and denied. Returns NGX_DONE with *out_rc set
 *       to the final result, or NGX_OK when the credtype is GSI and GSI auth
 *       is enabled (the caller runs the GSI steps).
 */
static ngx_int_t
gsi_auth_route_credtype(brix_ctx_t *ctx, ngx_connection_t *c,
                        ngx_stream_brix_srv_conf_t *conf, ngx_int_t *out_rc)
{
    char        credtype[5];
    char        safe_credtype[32];
    ngx_uint_t  i;

    ngx_memcpy(credtype, ctx->recv.cur_body + 12, 4);
    credtype[4] = '\0';
    brix_sanitize_log_string(credtype, safe_credtype,
                               sizeof(safe_credtype));

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "brix: kXR_auth credtype=\"%s\" payloadlen=%d",
                   safe_credtype, (int) ctx->recv.cur_dlen);

    for (i = 0;
         i < sizeof(gsi_auth_cred_routes) / sizeof(gsi_auth_cred_routes[0]);
         i++)
    {
        const gsi_auth_cred_route_t *rt = &gsi_auth_cred_routes[i];

        if (ngx_memcmp(credtype, rt->name, rt->cmp_len) != 0) {
            continue;
        }

        if (conf->auth != rt->mode && conf->auth != rt->mode_alt) {
            *out_rc = brix_send_error(ctx, c, kXR_NotAuthorized,
                                        rt->deny_msg);
            return NGX_DONE;
        }

        if (rt->handler == NULL) {
            return NGX_OK;             /* GSI — continue in this file */
        }

        *out_rc = rt->handler(ctx, c, conf);
        return NGX_DONE;
    }

    ngx_log_error(NGX_LOG_WARN, c->log, 0,
                  "brix: kXR_auth unknown credtype=\"%s\"",
                  safe_credtype);
    *out_rc = brix_send_error(ctx, c, kXR_NotAuthorized,
                                "unsupported credential type");
    return NGX_DONE;
}

/*
 * gsi_auth_step_certreq — GSI step 1 (kXGC_certreq): send the server cert.
 *
 * WHY:  Round 1 of the two-round DH exchange; the server answers with its
 *       certificate + DH public so the client never sends its proxy in clear.
 *
 * HOW:  E4: admit this new handshake under the per-worker in-flight cap; shed
 *       the excess with kXR_wait so a handshake flood cannot bury the loop.
 */
static ngx_int_t
gsi_auth_step_certreq(brix_ctx_t *ctx, ngx_connection_t *c,
                      ngx_stream_brix_srv_conf_t *conf)
{
    if (!brix_gsi_inflight_admit(ctx, conf->gsi_max_inflight)) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "brix: GSI handshake shed — %i concurrent in-flight "
                      "(cap reached); asking client to retry",
                      conf->gsi_max_inflight);
        return brix_send_wait(ctx, c, 3);
    }
    return brix_gsi_send_cert(ctx, c);
}

/*
 * gsi_auth_step_sigpxy — GSI step kXGC_sigpxy: capture the delegated proxy.
 *
 * WHY:  §F6: the client's signed delegated proxy — only valid mid-delegation,
 *       after we sent kXGS_pxyreq. Auth was deferred at kXGC_cert time and
 *       completes here.
 *
 * HOW:  Rejects when no delegation is pending or the signed proxy fails to
 *       parse/verify; otherwise finalizes via brix_gsi_complete_auth.
 */
static ngx_int_t
gsi_auth_step_sigpxy(brix_ctx_t *ctx, ngx_connection_t *c,
                     ngx_stream_brix_srv_conf_t *conf)
{
    if (!ctx->gsi.deleg_await
        || brix_gsi_handle_sigpxy(ctx, c) != NGX_OK) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_AUTH, "AUTH", "-", "gsi",
                          kXR_NotAuthorized, "GSI proxy delegation failed");
    }
    return brix_gsi_complete_auth(ctx, c, conf);
}

/* brix_handle_auth_inner — the kXR_auth dispatcher: route by the 4-byte credtype
 * (ztn→token, sss→SSS, gsi→GSI, ... — gsi_auth_route_credtype), requiring
 * ctx->login.logged_in first. The GSI path runs the two-round DH exchange
 * (kXGC_certreq → server cert via gsi_auth_step_certreq; kXGC_cert →
 * encrypted proxy chain via gsi_auth_step_cert) so the client's cert is never
 * sent in clear, verifies the chain against the CA store with
 * X509_V_FLAG_ALLOW_PROXY_CERTS (+ optional OCSP), extracts the DN and optional
 * VOMS VO membership, then finalizes via brix_gsi_complete_auth (deferred to
 * gsi_auth_step_sigpxy when §F6 delegation is in flight). */
static ngx_int_t
brix_handle_auth_inner(brix_ctx_t *ctx, ngx_connection_t *c)
{
    ngx_stream_brix_srv_conf_t *conf;
    uint32_t                      gsi_step;
    ngx_int_t                     rc;

    if (!ctx->login.logged_in) {
        return brix_send_error(ctx, c, kXR_NotAuthorized,
                                 "login required before auth");
    }

    conf = ngx_stream_get_module_srv_conf(ctx->session,
                                          ngx_stream_brix_module);

    if (conf->auth == BRIX_AUTH_NONE) {
        ctx->login.auth_done = 1;
        return brix_send_ok(ctx, c, NULL, 0);
    }

    rc = NGX_ERROR;
    if (gsi_auth_route_credtype(ctx, c, conf, &rc) == NGX_DONE) {
        return rc;
    }

    if (conf->gsi_store == NULL) {
        return brix_send_error(ctx, c, kXR_NotAuthorized,
                                 "GSI not configured");
    }

    if (ctx->recv.payload == NULL || ctx->recv.cur_dlen < 8) {
        return brix_send_error(ctx, c, kXR_NotAuthorized,
                                 "empty GSI credential");
    }

    ngx_memcpy(&gsi_step, ctx->recv.payload + 4, 4);
    gsi_step = ntohl(gsi_step);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "brix: GSI kXR_auth step=%ud", (unsigned) gsi_step);

    if (gsi_step == (uint32_t) kXGC_certreq) {
        return gsi_auth_step_certreq(ctx, c, conf);
    }

    if (gsi_step == (uint32_t) kXGC_sigpxy) {
        return gsi_auth_step_sigpxy(ctx, c, conf);
    }

    if (gsi_step != (uint32_t) kXGC_cert) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "brix: unexpected GSI step %ud", (unsigned) gsi_step);
        return brix_send_error(ctx, c, kXR_NotAuthorized,
                                 "unexpected GSI auth step");
    }

    return gsi_auth_step_cert(ctx, c, conf);
}

/* brix_handle_auth — rate-limited public entry point for kXR_auth: reject once
 * auth_fail_count hits BRIX_MAX_AUTH_ATTEMPTS (brute-force / GSI CPU-amplification
 * guard), but skip the limit on the GSI certreq round (the server's cert response
 * is not a credential failure). Delegates to brix_handle_auth_inner, then resets
 * the counter on success or increments it on failure. */
ngx_int_t
brix_handle_auth(brix_ctx_t *ctx, ngx_connection_t *c)
{
    ngx_flag_t  was_auth_done;
    ngx_flag_t  is_certreq;
    ngx_int_t   rc;

    /*
     * Phase 33: start each GSI auth round with a clean per-thread OpenSSL error
     * queue.  GSI parsing intentionally provokes benign errors ("invalid key
     * length", PEM "no start line" at EOF) that the module never clears; a dirty
     * queue later corrupts nginx's TLS clean-close detection on the shared
     * worker.  Clearing here keeps those benign errors from leaking forward.
     */
    ERR_clear_error();

    /* Reject after repeated failures — guards against brute-force attempts
     * and CPU-amplification via costly GSI/OpenSSL/VOMS operations. */
    if (ctx->login.auth_fail_count >= BRIX_MAX_AUTH_ATTEMPTS) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "brix: %s: auth attempt limit reached, disconnecting",
                      ctx->login.user);
        return brix_send_error(ctx, c, kXR_NotAuthorized,
                                 "Too many authentication failures");
    }

    /*
     * GSI round 1 (kXGC_certreq) and pwd round 1: the server responds with
     * kXR_authmore (its certificate / its DH public) — a protocol continuation,
     * not a credential failure, so it must not count toward the attempt limit.
     */
    is_certreq = 0;
    if (ctx->recv.cur_dlen >= 8 && ctx->recv.payload != NULL) {
        const u_char *ctype = ctx->recv.cur_body + 12;
        if (ctype[0] == 'g' && ctype[1] == 's' && ctype[2] == 'i') {
            uint32_t step;
            ngx_memcpy(&step, ctx->recv.payload + 4, 4);
            is_certreq = (ntohl(step) == (uint32_t) kXGC_certreq);
        } else if (ctype[0] == 'p' && ctype[1] == 'w' && ctype[2] == 'd'
                   && ctype[3] == 0) {
            /* pwd round 1 is the puk-exchange (ctx->pwd.round still 0). */
            is_certreq = (ctx->pwd.round == 0);
        }
    }

    was_auth_done = ctx->login.auth_done;
    rc = brix_handle_auth_inner(ctx, c);

    if (!is_certreq) {
        if (!was_auth_done && ctx->login.auth_done) {
            ctx->login.auth_fail_count = 0;   /* successful auth resets the counter */
        } else if (!ctx->login.auth_done) {
            ctx->login.auth_fail_count++;     /* failed or protocol-level challenge */
        }
    }

    return rc;
}

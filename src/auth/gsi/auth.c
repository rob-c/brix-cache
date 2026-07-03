#include "gsi_internal.h"
#include "delegation.h"
#include "protocols/root/session/registry.h"
#include "auth/crypto/ocsp.h"
#include "auth/crypto/gsi_verify.h"
#include <openssl/err.h>

/*
 * Phase 51 (E4): per-worker in-flight GSI-handshake gauge.  A GSI handshake is
 * multi-round-trip (certreq → cert), so many can be parked in progress at once,
 * each holding ephemeral-DH + chain-verify CPU state.  Under a flood of
 * simultaneous handshakes that buries the single-threaded event loop, this caps
 * the number admitted concurrently per worker and sheds the excess with kXR_wait
 * (the client waits and retries).  Cache hits / already-authed sessions never
 * touch this.  Released EXACTLY ONCE — at auth completion OR at disconnect (the
 * guaranteed funnel) — gated by ctx->gsi_counted, so the gauge can never leak and
 * wedge auth.  Lock-free: per-worker, event-loop only.
 */
static ngx_uint_t  brix_gsi_inflight;

ngx_int_t
brix_gsi_inflight_admit(brix_ctx_t *ctx, ngx_int_t cap)
{
    if (ctx->gsi_counted) {
        return 1;                  /* already counted this handshake */
    }
    if (cap > 0 && brix_gsi_inflight >= (ngx_uint_t) cap) {
        return 0;                  /* over the cap — shed */
    }
    brix_gsi_inflight++;
    ctx->gsi_counted = 1;
    return 1;
}

void
brix_gsi_inflight_release(brix_ctx_t *ctx)
{
    if (ctx->gsi_counted) {
        if (brix_gsi_inflight > 0) {
            brix_gsi_inflight--;
        }
        ctx->gsi_counted = 0;
    }
}

/*
 * brix_gsi_complete_auth — finalize a successful GSI authentication once the
 * client's DN is known: per-identity rate limit, auth_done, identity/session
 * registration, and metrics. Factored so both the normal kXGC_cert path and the
 * §F6 delegation path (which completes only after kXGC_sigpxy) share one
 * completion. Returns via BRIX_RETURN_OK / BRIX_RETURN_ERR.
 */
static ngx_int_t
brix_gsi_complete_auth(brix_ctx_t *ctx, ngx_connection_t *c,
                         ngx_stream_brix_srv_conf_t *conf)
{
    /* Phase 20: per-identity request rate limit, applied once the DN is known. */
    if (conf->rate_limit.kv != NULL) {
        const char *rl_id = conf->rate_limit.key_ip ? ctx->peer_ip : ctx->dn;

        if (brix_rate_limit_check(&conf->rate_limit, rl_id,
                                    ngx_strlen(rl_id)) != NGX_OK)
        {
            BRIX_RETURN_ERR(ctx, c, BRIX_OP_AUTH, "AUTH", "-", "gsi",
                              kXR_NotAuthorized, "rate limit exceeded");
        }
    }

    ctx->auth_done = 1;
    brix_gsi_inflight_release(ctx);   /* E4: handshake done — free the slot */
    if (ctx->identity != NULL) {
        if (brix_identity_set_dn(ctx->identity, c->pool, ctx->dn,
                                   BRIX_AUTHN_GSI) != NGX_OK
            || brix_identity_set_vos_csv(ctx->identity, c->pool,
                                           ctx->vo_list) != NGX_OK)
        {
            return brix_send_error(ctx, c, kXR_NoMemory,
                                     "identity allocation failed");
        }
    }
    brix_session_register(ctx->sessid, ctx->dn, ctx->vo_list, 0);

    /* Track unique user and VO at auth completion. */
    {
        ngx_brix_metrics_t *shm = brix_metrics_shared();
        if (shm != NULL) {
            size_t vo_len = strlen(ctx->primary_vo);
            if (vo_len > 0 && vo_len < sizeof(ctx->primary_vo)) {
                brix_track_vo_activity(shm, ctx->primary_vo, 0, 0);
                ngx_uint_t vi;
                for (vi = 0; vi < BRIX_VO_MAX_TRACKED; vi++) {
                    if (ngx_strncmp(shm->vo_global.slots[vi].name, ctx->primary_vo,
                                    BRIX_VO_NAME_LEN) == 0)
                    {
                        BRIX_ATOMIC_INC(&shm->vo_global.slots[vi].requests_total);
                        break;
                    }
                }
            }
            brix_track_unique_user(shm, ctx->dn, strlen(ctx->dn));
        }
    }

    {
        char dn_log[1024];

        brix_sanitize_log_string(ctx->dn, dn_log, sizeof(dn_log));
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "brix: GSI auth OK dn=\"%s\"", dn_log);
    }

    BRIX_RETURN_OK(ctx, c, BRIX_OP_AUTH, "AUTH", "-", "gsi", 0);
}

/* brix_handle_auth_inner — the kXR_auth dispatcher: route by the 4-byte credtype
 * (ztn→token, sss→SSS, gsi→GSI), requiring ctx->logged_in first. The GSI path runs
 * the two-round DH exchange (kXGC_certreq → server cert via brix_gsi_send_cert;
 * kXGC_cert → encrypted proxy chain via brix_gsi_parse_x509) so the client's cert
 * is never sent in clear, verifies the chain against the CA store with
 * X509_V_FLAG_ALLOW_PROXY_CERTS (+ optional OCSP), extracts the DN and optional VOMS
 * VO membership, then finalizes via brix_gsi_complete_auth. */
static ngx_int_t
brix_handle_auth_inner(brix_ctx_t *ctx, ngx_connection_t *c)
{
    ngx_stream_brix_srv_conf_t *conf;
    STACK_OF(X509)               *chain;
    X509                         *leaf;
    brix_gsi_verify_result_t    verify_res;
    uint32_t                      gsi_step;

    if (!ctx->logged_in) {
        return brix_send_error(ctx, c, kXR_NotAuthorized,
                                 "login required before auth");
    }

    conf = ngx_stream_get_module_srv_conf(ctx->session,
                                          ngx_stream_brix_module);

    if (conf->auth == BRIX_AUTH_NONE) {
        ctx->auth_done = 1;
        return brix_send_ok(ctx, c, NULL, 0);
    }

    {
        char credtype[5];
        char safe_credtype[32];

        ngx_memcpy(credtype, ctx->cur_body + 12, 4);
        credtype[4] = '\0';
        brix_sanitize_log_string(credtype, safe_credtype,
                                   sizeof(safe_credtype));

        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "brix: kXR_auth credtype=\"%s\" payloadlen=%d",
                       safe_credtype, (int) ctx->cur_dlen);

        if (credtype[0] == 'z' && credtype[1] == 't' && credtype[2] == 'n') {
            if (conf->auth != BRIX_AUTH_TOKEN
                && conf->auth != BRIX_AUTH_BOTH)
            {
                return brix_send_error(ctx, c, kXR_NotAuthorized,
                                         "token auth not enabled");
            }
            return brix_handle_token_auth(ctx, c, conf);
        }

        if (credtype[0] == 's' && credtype[1] == 's' && credtype[2] == 's') {
            if (conf->auth != BRIX_AUTH_SSS) {
                return brix_send_error(ctx, c, kXR_NotAuthorized,
                                         "SSS auth not enabled");
            }
            return brix_handle_sss_auth(ctx, c, conf);
        }

        if (credtype[0] == 'u' && credtype[1] == 'n'
            && credtype[2] == 'i' && credtype[3] == 'x')
        {
            if (conf->auth != BRIX_AUTH_UNIX) {
                return brix_send_error(ctx, c, kXR_NotAuthorized,
                                         "unix auth not enabled");
            }
            return brix_handle_unix_auth(ctx, c, conf);
        }

        if (credtype[0] == 'k' && credtype[1] == 'r'
            && credtype[2] == 'b' && credtype[3] == '5')
        {
            if (conf->auth != BRIX_AUTH_KRB5) {
                return brix_send_error(ctx, c, kXR_NotAuthorized,
                                         "krb5 auth not enabled");
            }
            return brix_handle_krb5_auth(ctx, c, conf);
        }

        if (credtype[0] == 'h' && credtype[1] == 'o'
            && credtype[2] == 's' && credtype[3] == 't')
        {
            if (conf->auth != BRIX_AUTH_HOST) {
                return brix_send_error(ctx, c, kXR_NotAuthorized,
                                         "host auth not enabled");
            }
            return brix_handle_host_auth(ctx, c, conf);
        }

        if (credtype[0] == 'p' && credtype[1] == 'w'
            && credtype[2] == 'd' && credtype[3] == 0)
        {
            if (conf->auth != BRIX_AUTH_PWD) {
                return brix_send_error(ctx, c, kXR_NotAuthorized,
                                         "pwd auth not enabled");
            }
            return brix_handle_pwd_auth(ctx, c, conf);
        }

        if (credtype[0] != 'g' || credtype[1] != 's' || credtype[2] != 'i') {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "brix: kXR_auth unknown credtype=\"%s\"",
                          safe_credtype);
            return brix_send_error(ctx, c, kXR_NotAuthorized,
                                     "unsupported credential type");
        }

        if (conf->auth != BRIX_AUTH_GSI && conf->auth != BRIX_AUTH_BOTH) {
            return brix_send_error(ctx, c, kXR_NotAuthorized,
                                     "GSI auth not enabled");
        }
    }

    if (conf->gsi_store == NULL) {
        return brix_send_error(ctx, c, kXR_NotAuthorized,
                                 "GSI not configured");
    }

    if (ctx->payload == NULL || ctx->cur_dlen < 8) {
        return brix_send_error(ctx, c, kXR_NotAuthorized,
                                 "empty GSI credential");
    }

    ngx_memcpy(&gsi_step, ctx->payload + 4, 4);
    gsi_step = ntohl(gsi_step);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "brix: GSI kXR_auth step=%ud", (unsigned) gsi_step);

    if (gsi_step == (uint32_t) kXGC_certreq) {
        /* E4: admit this new handshake under the per-worker in-flight cap; shed
         * the excess with kXR_wait so a handshake flood cannot bury the loop. */
        if (!brix_gsi_inflight_admit(ctx, conf->gsi_max_inflight)) {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "brix: GSI handshake shed — %i concurrent in-flight "
                          "(cap reached); asking client to retry",
                          conf->gsi_max_inflight);
            return brix_send_wait(ctx, c, 3);
        }
        return brix_gsi_send_cert(ctx, c);
    }

    /* §F6: the client's signed delegated proxy — only valid mid-delegation, after
     * we sent kXGS_pxyreq. Capture it, then complete the deferred auth. */
    if (gsi_step == (uint32_t) kXGC_sigpxy) {
        if (!ctx->gsi_deleg_await
            || brix_gsi_handle_sigpxy(ctx, c) != NGX_OK) {
            BRIX_RETURN_ERR(ctx, c, BRIX_OP_AUTH, "AUTH", "-", "gsi",
                              kXR_NotAuthorized, "GSI proxy delegation failed");
        }
        return brix_gsi_complete_auth(ctx, c, conf);
    }

    if (gsi_step != (uint32_t) kXGC_cert) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "brix: unexpected GSI step %ud", (unsigned) gsi_step);
        return brix_send_error(ctx, c, kXR_NotAuthorized,
                                 "unexpected GSI auth step");
    }

    chain = brix_gsi_parse_x509(ctx, c);

    if (ctx->gsi_dh_key) {
        EVP_PKEY_free(ctx->gsi_dh_key);
        ctx->gsi_dh_key = NULL;
    }

    if (chain == NULL) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_AUTH, "AUTH", "-", "gsi",
                          kXR_NotAuthorized, "cannot parse GSI credential");
    }

    leaf = sk_X509_value(chain, 0);

    {
        STACK_OF(X509) *untrusted = NULL;
        ngx_int_t       gsi_rc;

        if (sk_X509_num(chain) > 1) {
            untrusted = sk_X509_dup(chain);
            sk_X509_delete(untrusted, 0);
        }

        gsi_rc = brix_gsi_verify_chain(c->log, conf->gsi_store,
                                          leaf, untrusted, 0, &verify_res);

        if (untrusted) {
            sk_X509_free(untrusted);
        }

        if (gsi_rc != NGX_OK) {
            /* brix_gsi_verify_chain already logged the specific error */
            brix_log_access(ctx, c, "AUTH", "-", "gsi",
                              0, kXR_NotAuthorized,
                              "certificate verification failed", 0);
            BRIX_OP_ERR(ctx, BRIX_OP_AUTH);
            sk_X509_pop_free(chain, X509_free);
            return brix_send_error(ctx, c, kXR_NotAuthorized,
                                     "certificate verification failed");
        }
    }

    /*
     * OCSP revocation check (Feature 8e).
     * The certificate chain is still valid at this point: leaf is chain[0],
     * its issuer is chain[1] (may be NULL for single-cert chains).
     */
    if (conf->ocsp_enable) {
        X509 *issuer = (sk_X509_num(chain) > 1)
                       ? sk_X509_value(chain, 1) : NULL;
        if (brix_ocsp_check_cert(c->log, leaf, issuer,
                                   (int)conf->ocsp_soft_fail) != 0)
        {
            brix_log_access(ctx, c, "AUTH", "-", "gsi",
                              0, kXR_NotAuthorized, "OCSP check failed", 0);
            BRIX_OP_ERR(ctx, BRIX_OP_AUTH);
            sk_X509_pop_free(chain, X509_free);
            return brix_send_error(ctx, c, kXR_NotAuthorized,
                                     "OCSP certificate check failed");
        }
    }

    if (strlen(verify_res.dn_buf) >= sizeof(ctx->dn)) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "brix: GSI DN too long (%uz bytes), truncating to %uz; "
                      "VO ACL rules may not match correctly",
                      strlen(verify_res.dn_buf), sizeof(ctx->dn) - 1);
    }
    ngx_cpystrn((u_char *) ctx->dn,
                (u_char *) verify_res.dn_buf,
                sizeof(ctx->dn));

    if (brix_voms_available()
        && conf->vomsdir.len > 0 && conf->voms_cert_dir.len > 0)
    {
        ngx_int_t voms_rc = brix_extract_voms_info(
            c->log, leaf, chain,
            &conf->vomsdir, &conf->voms_cert_dir,
            ctx->primary_vo, sizeof(ctx->primary_vo),
            ctx->vo_list, sizeof(ctx->vo_list));

        if (voms_rc == NGX_OK) {
            char vo_log[256];

            brix_sanitize_log_string(ctx->vo_list, vo_log, sizeof(vo_log));
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "brix: VOMS VO membership: %s", vo_log);
        }
    }

    /*
     * §F6 X.509 proxy delegation: when enabled, run an extra handshake round to
     * capture the client's delegated proxy BEFORE completing auth. The DN/VOMS are
     * already extracted (above) and the chain/leaf are still valid here; the GSI
     * session cipher was persisted by parse_x509. begin_delegation sends
     * kXGS_pxyreq (kXR_authmore) and auth completes when kXGC_sigpxy arrives.
     */
    if (conf->tpc_delegate && !ctx->gsi_deleg_await && ctx->gsi_sess_keylen > 0) {
        ngx_int_t drc = brix_gsi_begin_delegation(ctx, c, conf, leaf, chain);

        sk_X509_pop_free(chain, X509_free);
        if (drc != NGX_OK) {
            BRIX_RETURN_ERR(ctx, c, BRIX_OP_AUTH, "AUTH", "-", "gsi",
                              kXR_NotAuthorized, "GSI proxy delegation failed");
        }
        return NGX_OK;   /* kXGS_pxyreq sent; auth completes on kXGC_sigpxy */
    }

    sk_X509_pop_free(chain, X509_free);
    return brix_gsi_complete_auth(ctx, c, conf);
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
    if (ctx->auth_fail_count >= BRIX_MAX_AUTH_ATTEMPTS) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "brix: %s: auth attempt limit reached, disconnecting",
                      ctx->login_user);
        return brix_send_error(ctx, c, kXR_NotAuthorized,
                                 "Too many authentication failures");
    }

    /*
     * GSI round 1 (kXGC_certreq) and pwd round 1: the server responds with
     * kXR_authmore (its certificate / its DH public) — a protocol continuation,
     * not a credential failure, so it must not count toward the attempt limit.
     */
    is_certreq = 0;
    if (ctx->cur_dlen >= 8 && ctx->payload != NULL) {
        const u_char *ctype = ctx->cur_body + 12;
        if (ctype[0] == 'g' && ctype[1] == 's' && ctype[2] == 'i') {
            uint32_t step;
            ngx_memcpy(&step, ctx->payload + 4, 4);
            is_certreq = (ntohl(step) == (uint32_t) kXGC_certreq);
        } else if (ctype[0] == 'p' && ctype[1] == 'w' && ctype[2] == 'd'
                   && ctype[3] == 0) {
            /* pwd round 1 is the puk-exchange (ctx->pwd_round still 0). */
            is_certreq = (ctx->pwd_round == 0);
        }
    }

    was_auth_done = ctx->auth_done;
    rc = brix_handle_auth_inner(ctx, c);

    if (!is_certreq) {
        if (!was_auth_done && ctx->auth_done) {
            ctx->auth_fail_count = 0;   /* successful auth resets the counter */
        } else if (!ctx->auth_done) {
            ctx->auth_fail_count++;     /* failed or protocol-level challenge */
        }
    }

    return rc;
}

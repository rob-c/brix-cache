#include "gsi_internal.h"
#include "../session/registry.h"

/*
 * Top-level kXR_auth dispatcher.
 */

ngx_int_t
xrootd_handle_auth(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ngx_stream_xrootd_srv_conf_t *conf;
    STACK_OF(X509)               *chain;
    X509                         *leaf;
    X509_STORE_CTX               *vctx;
    char                         *dn_str;
    uint32_t                      gsi_step;
    int                           ok;

    if (!ctx->logged_in) {
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "login required before auth");
    }

    conf = ngx_stream_get_module_srv_conf(ctx->session,
                                          ngx_stream_xrootd_module);

    if (conf->auth == XROOTD_AUTH_NONE) {
        ctx->auth_done = 1;
        return xrootd_send_ok(ctx, c, NULL, 0);
    }

    {
        char credtype[5];
        char safe_credtype[32];

        ngx_memcpy(credtype, ctx->cur_body + 12, 4);
        credtype[4] = '\0';
        xrootd_sanitize_log_string(credtype, safe_credtype,
                                   sizeof(safe_credtype));

        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "xrootd: kXR_auth credtype=\"%s\" payloadlen=%d",
                       safe_credtype, (int) ctx->cur_dlen);

        if (credtype[0] == 'z' && credtype[1] == 't' && credtype[2] == 'n') {
            if (conf->auth != XROOTD_AUTH_TOKEN
                && conf->auth != XROOTD_AUTH_BOTH)
            {
                return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                         "token auth not enabled");
            }
            return xrootd_handle_token_auth(ctx, c, conf);
        }

        if (credtype[0] == 's' && credtype[1] == 's' && credtype[2] == 's') {
            if (conf->auth != XROOTD_AUTH_SSS) {
                return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                         "SSS auth not enabled");
            }
            return xrootd_handle_sss_auth(ctx, c, conf);
        }

        if (credtype[0] != 'g' || credtype[1] != 's' || credtype[2] != 'i') {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "xrootd: kXR_auth unknown credtype=\"%s\"",
                          safe_credtype);
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "unsupported credential type");
        }

        if (conf->auth != XROOTD_AUTH_GSI && conf->auth != XROOTD_AUTH_BOTH) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "GSI auth not enabled");
        }
    }

    if (conf->gsi_store == NULL) {
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "GSI not configured");
    }

    if (ctx->payload == NULL || ctx->cur_dlen < 8) {
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "empty GSI credential");
    }

    ngx_memcpy(&gsi_step, ctx->payload + 4, 4);
    gsi_step = ntohl(gsi_step);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: GSI kXR_auth step=%ud", (unsigned) gsi_step);

    if (gsi_step == (uint32_t) kXGC_certreq) {
        return xrootd_gsi_send_cert(ctx, c);
    }

    if (gsi_step != (uint32_t) kXGC_cert) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: unexpected GSI step %ud", (unsigned) gsi_step);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "unexpected GSI auth step");
    }

    chain = xrootd_gsi_parse_x509(ctx, c);

    if (ctx->gsi_dh_key) {
        EVP_PKEY_free(ctx->gsi_dh_key);
        ctx->gsi_dh_key = NULL;
    }

    if (chain == NULL) {
        xrootd_log_access(ctx, c, "AUTH", "-", "gsi",
                          0, kXR_NotAuthorized, "cannot parse GSI credential", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_AUTH);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "cannot parse GSI credential");
    }

    leaf = sk_X509_value(chain, 0);

    vctx = X509_STORE_CTX_new();
    if (vctx == NULL) {
        sk_X509_pop_free(chain, X509_free);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "internal OpenSSL error");
    }

    {
        STACK_OF(X509) *untrusted = NULL;

        if (sk_X509_num(chain) > 1) {
            untrusted = sk_X509_dup(chain);
            sk_X509_delete(untrusted, 0);
        }

        X509_STORE_CTX_init(vctx, conf->gsi_store, leaf, untrusted);
        X509_STORE_CTX_set_flags(vctx, X509_V_FLAG_ALLOW_PROXY_CERTS);

        ok = X509_verify_cert(vctx);

        if (untrusted) {
            sk_X509_free(untrusted);
        }
    }

    if (ok != 1) {
        int         verr = X509_STORE_CTX_get_error(vctx);
        const char *verr_str = X509_verify_cert_error_string(verr);

        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: GSI cert verification failed: %s", verr_str);
        xrootd_log_access(ctx, c, "AUTH", "-", "gsi",
                          0, kXR_NotAuthorized, verr_str, 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_AUTH);
        X509_STORE_CTX_free(vctx);
        sk_X509_pop_free(chain, X509_free);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "certificate verification failed");
    }

    X509_STORE_CTX_free(vctx);

    dn_str = X509_NAME_oneline(X509_get_subject_name(leaf), NULL, 0);
    if (dn_str) {
        if (strlen(dn_str) >= sizeof(ctx->dn)) {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "xrootd: GSI DN too long (%uz bytes), truncating to %uz; "
                          "VO ACL rules may not match correctly",
                          strlen(dn_str), sizeof(ctx->dn) - 1);
        }
        ngx_cpystrn((u_char *) ctx->dn,
                    (u_char *) dn_str,
                    sizeof(ctx->dn) - 1);
        OPENSSL_free(dn_str);
    }

    if (xrootd_voms_available()
        && conf->vomsdir.len > 0 && conf->voms_cert_dir.len > 0)
    {
        ngx_int_t voms_rc = xrootd_extract_voms_info(
            c->log, leaf, chain,
            &conf->vomsdir, &conf->voms_cert_dir,
            ctx->primary_vo, sizeof(ctx->primary_vo),
            ctx->vo_list, sizeof(ctx->vo_list));

        if (voms_rc == NGX_OK) {
            char vo_log[256];

            xrootd_sanitize_log_string(ctx->vo_list, vo_log, sizeof(vo_log));
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "xrootd: VOMS VO membership: %s", vo_log);
        }
    }

    sk_X509_pop_free(chain, X509_free);

    ctx->auth_done = 1;
    xrootd_session_register(ctx->sessid, ctx->dn, ctx->vo_list, 0);

    /* Track unique user and VO at auth completion. */
    {
        ngx_xrootd_metrics_t *shm = xrootd_metrics_shared();
        if (shm != NULL) {
            size_t vo_len = strlen(ctx->primary_vo);
            if (vo_len > 0 && vo_len < sizeof(ctx->primary_vo)) {
                xrootd_track_vo_activity(shm, ctx->primary_vo, 0, 0);
                /* Increment VO request count for this auth event. */
                ngx_uint_t vi;
                for (vi = 0; vi < XROOTD_VO_MAX_TRACKED; vi++) {
                    if (ngx_strncmp(shm->vo_global.slots[vi].name, ctx->primary_vo,
                                    XROOTD_VO_NAME_LEN) == 0)
                    {
                        XROOTD_ATOMIC_INC(&shm->vo_global.slots[vi].requests_total);
                        break;
                    }
                }
            }
            xrootd_track_unique_user(shm, ctx->dn, strlen(ctx->dn));
        }
    }

    {
        char dn_log[1024];

        xrootd_sanitize_log_string(ctx->dn, dn_log, sizeof(dn_log));
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "xrootd: GSI auth OK dn=\"%s\"", dn_log);
    }

    xrootd_log_access(ctx, c, "AUTH", "-", "gsi", 1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_AUTH);

    return xrootd_send_ok(ctx, c, NULL, 0);
}

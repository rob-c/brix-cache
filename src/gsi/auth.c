#include "gsi_internal.h"
#include "../session/registry.h"
#include "../crypto/ocsp.h"
#include "../crypto/gsi_verify.h"
#include <openssl/err.h>

/* ------------------------------------------------------------------ */
/* GSI Auth — Credential Routing, DH Key Exchange, Certificate Verification  */
/* ------------------------------------------------------------------ */
/*
 * WHAT: Implements the kXR_auth dispatcher for all client authentication requests (GSI/x509 proxy certs, bearer tokens/WLCG JWT, SSS shared secrets). Routes to specialized handlers based on credtype field extracted from wire payload. GSI path implements two-round DH key exchange protocol (kXGC_certreq→server cert response via xrootd_gsi_send_cert(), kXGC_cert→encrypted proxy chain parsed by xrootd_gsi_parse_x509()), verifies against configured CA store with X509_V_FLAG_ALLOW_PROXY_CERTS, extracts DN from verified leaf and optionally VOMS VO membership attributes. Token path validates JWT against configured JWKS via xrootd_handle_token_auth(). SSS path delegates to xrootd_handle_sss_auth() in src/sss/. Rate-limited public entry point guards against brute-force attempts.
 *
 * WHY: GSI authentication requires two-round DH key exchange to protect the client's proxy certificate from man-in-the-middle attacks. DN extraction enables VO ACL rule matching for path authorization. VOMS membership provides granular VO-level access control beyond basic DN-based rules. Session registration after auth_done=1 enables bind operations and CMS/manager mode cross-node communication. Rate limiting prevents CPU-amplification via costly GSI/OpenSSL/VOMS operations from brute-force attackers.
 *
 * HOW: xrootd_handle_auth() (public entry point) → validate auth_fail_count against XROOTD_MAX_AUTH_ATTEMPTS, detect certreq round to skip rate limit → call xrootd_handle_auth_inner(). Inner dispatcher → extract 4-byte credtype from payload +12 offset → route: ztn→token handler, sss→SSS handler, gsi→GSI path. GSI path → validate ctx->logged_in → check conf->auth method → extract gsi_step (kXGC_certreq vs kXGC_cert) → certreq→send server cert via xrootd_gsi_send_cert(), cert→parse x509 chain via xrootd_gsi_parse_x509() → verify against CA store with X509_V_FLAG_ALLOW_PROXY_CERTS for proxy certs → optional OCSP revocation check (conf->ocsp_enable) → extract DN from verified leaf → optional VOMS VO membership extraction → mark ctx->auth_done=1, register session in shared registry → track unique user/VO metrics. */
/* ---- kXR_auth dispatcher — top-level credential type routing and authentication ----
 *
 * WHAT: Central entry point for all client authentication requests (GSI/x509 proxy certs, bearer tokens/WLCG JWT, SSS shared secrets).
 *       Routes to specialized handlers based on credtype field extracted from wire payload. */

/* ---- Authentication credential types supported ----
 *
 * WHAT: Three credential types identified by 4-byte credtype field in kXR_auth payload:
 *   - "gsi" = Grid Security Infrastructure — multi-round DH key exchange over x509 proxy certs
 *   - "ztn" = WLCG bearer token — single-round JWT validation against configured JWKS
 *   - "sss" = Shared secret authentication — pre-shared password/secret for trusted environments */

/* ---- Authentication phase ordering (must be logged in first) ----
 *
 * WHY: kXR_auth occurs AFTER kXR_login establishes the session ID. Requires ctx->logged_in to prevent
 *      unauthenticated sessions from attempting credential exchange without proper session context. */

/* ---- Credential type routing pattern ----
 *
 * HOW: Extract 4-byte credtype from payload +12 offset, compare against configured auth method (conf->auth).
 *      Each credential type has its own handler: xrootd_handle_token_auth() for ztn, xrootd_handle_sss_auth() for sss. */

/* ---- GSI multi-step authentication flow ----
 *
 * WHAT: GSI authentication uses two-round protocol with DH key exchange for secure credential transfer:
 *   Round 1 (kXGC_certreq): Client requests server certificate — server responds via xrootd_gsi_send_cert()
 *   Round 2 (kXGC_cert): Client sends encrypted proxy cert chain using shared DH secret — parsed by xrootd_gsi_parse_x509() */

/* ---- GSI authentication invariant (GSISecureBucket protocol) ----
 *
 * WHY: The two-round pattern ensures the client's proxy certificate is encrypted with a DH shared secret,
 *      preventing man-in-the-middle attacks where an interceptor could read the raw certificate chain. */

/* ---- Certificate verification mechanism ----
 *
 * WHAT: After parsing the x509 proxy chain, creates X509_STORE_CTX and verifies against configured CA store.
 *       Uses X509_V_FLAG_ALLOW_PROXY_CERTS flag to permit proxy certificates (intermediate certs between leaf and root). */

/*---- Certificate verification error handling ----
 *
 * WHAT: On verification failure, extracts specific error code via X509_STORE_CTX_get_error() and provides human-readable string.
 *       Logs both debug-level warning and access-log entry with the specific verification failure reason (expired cert, revoked CRL, etc.). */

/*---- DN extraction from verified certificate leaf ----
 *
 * WHAT: Extracts the Subject Distinguished Name (DN) from the verified certificate's first element (leaf).
 *       The DN is stored in ctx->dn for VO ACL rule matching and session registration. Truncated to sizeof(ctx->dn)-1 bytes if too long. */

/*---- VOMS membership extraction (VO attribute extension) ----
 *
 * WHAT: After successful GSI authentication, optionally extracts Virtual Organization (VO) membership attributes from proxy cert extensions.
 *       Requires vomsdir and voms_cert_dir configuration for OSG/VO certificate validation infrastructure. Extracts to ctx->primary_vo and ctx->vo_list. */

/*---- Session registration after successful authentication ----
 *
 * WHAT: Marks ctx->auth_done = 1, registers the authenticated session in shared registry with DN and VO list for cluster coordination.
 *      This enables bind operations (secondary connections) and CMS/manager mode cross-node communication. */

/* ---- Function: xrootd_handle_auth() ----
 *
 * WHAT: Top-level kXR_auth dispatcher — routes by 4-byte credtype field (ztn=token, sss=SSS, gsi=GSI) to specialized handlers. GSI path implements two-round DH key exchange protocol (kXGC_certreq→server cert response, kXGC_cert→encrypted proxy chain), parses x509 chain via OpenSSL, verifies against configured CA store with X509_V_FLAG_ALLOW_PROXY_CERTS for intermediate proxy certs, extracts DN from verified leaf and optionally VOMS VO membership attributes. Marks ctx->auth_done=1 and registers authenticated session in shared registry after success. Tracks unique user/VO metrics at auth completion.
 *
 * WHY: The two-round GSI pattern ensures the client's proxy certificate is encrypted with a DH shared secret, preventing man-in-the-middle attacks. DN extraction enables VO ACL rule matching for path authorization. VOMS membership provides granular VO-level access control beyond basic DN-based rules. Session registration after auth_done=1 enables bind operations (secondary connections) and CMS/manager mode cross-node communication. Auth metrics tracking provides production visibility into authentication throughput per-VO and per-user. */

static ngx_int_t
xrootd_handle_auth_inner(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ngx_stream_xrootd_srv_conf_t *conf;
    STACK_OF(X509)               *chain;
    X509                         *leaf;
    xrootd_gsi_verify_result_t    verify_res;
    uint32_t                      gsi_step;

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

        if (credtype[0] == 'u' && credtype[1] == 'n'
            && credtype[2] == 'i' && credtype[3] == 'x')
        {
            if (conf->auth != XROOTD_AUTH_UNIX) {
                return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                         "unix auth not enabled");
            }
            return xrootd_handle_unix_auth(ctx, c, conf);
        }

        if (credtype[0] == 'k' && credtype[1] == 'r'
            && credtype[2] == 'b' && credtype[3] == '5')
        {
            if (conf->auth != XROOTD_AUTH_KRB5) {
                return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                         "krb5 auth not enabled");
            }
            return xrootd_handle_krb5_auth(ctx, c, conf);
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
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_AUTH, "AUTH", "-", "gsi",
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

        gsi_rc = xrootd_gsi_verify_chain(c->log, conf->gsi_store,
                                          leaf, untrusted, 0, &verify_res);

        if (untrusted) {
            sk_X509_free(untrusted);
        }

        if (gsi_rc != NGX_OK) {
            /* xrootd_gsi_verify_chain already logged the specific error */
            xrootd_log_access(ctx, c, "AUTH", "-", "gsi",
                              0, kXR_NotAuthorized,
                              "certificate verification failed", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_AUTH);
            sk_X509_pop_free(chain, X509_free);
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
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
        if (xrootd_ocsp_check_cert(c->log, leaf, issuer,
                                   (int)conf->ocsp_soft_fail) != 0)
        {
            xrootd_log_access(ctx, c, "AUTH", "-", "gsi",
                              0, kXR_NotAuthorized, "OCSP check failed", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_AUTH);
            sk_X509_pop_free(chain, X509_free);
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "OCSP certificate check failed");
        }
    }

    if (strlen(verify_res.dn_buf) >= sizeof(ctx->dn)) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: GSI DN too long (%uz bytes), truncating to %uz; "
                      "VO ACL rules may not match correctly",
                      strlen(verify_res.dn_buf), sizeof(ctx->dn) - 1);
    }
    ngx_cpystrn((u_char *) ctx->dn,
                (u_char *) verify_res.dn_buf,
                sizeof(ctx->dn));

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

    /* Phase 20: per-identity request rate limit, applied once the DN is known. */
    if (conf->rate_limit.kv != NULL) {
        const char *rl_id = conf->rate_limit.key_ip ? ctx->peer_ip : ctx->dn;

        if (xrootd_rate_limit_check(&conf->rate_limit, rl_id,
                                    ngx_strlen(rl_id)) != NGX_OK)
        {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_AUTH, "AUTH", "-", "gsi",
                              kXR_NotAuthorized, "rate limit exceeded");
        }
    }

    ctx->auth_done = 1;
    if (ctx->identity != NULL) {
        if (xrootd_identity_set_dn(ctx->identity, c->pool, ctx->dn,
                                   XROOTD_AUTHN_GSI) != NGX_OK
            || xrootd_identity_set_vos_csv(ctx->identity, c->pool,
                                           ctx->vo_list) != NGX_OK)
        {
            return xrootd_send_error(ctx, c, kXR_NoMemory,
                                     "identity allocation failed");
        }
    }
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

    XROOTD_RETURN_OK(ctx, c, XROOTD_OP_AUTH, "AUTH", "-", "gsi", 0);
}

/* ---- xrootd_handle_auth — rate-limited public entry point ---- */
/* ---- Function: xrootd_handle_auth() ----
 * WHAT: Rate-limited public entry point for kXR_auth — validates auth_fail_count against XROOTD_MAX_AUTH_ATTEMPTS to reject brute-force attempts and CPU-amplification via costly GSI/OpenSSL/VOMS operations. Detects GSI round 1 (kXGC_certreq) to skip rate limit since server cert response is not a credential failure. Calls xrootd_handle_auth_inner() for actual dispatch, then updates auth_fail_count: resets to zero on successful auth, increments on failed or protocol-level challenge (skipping certreq round).
 * WHY: Rate limiting prevents brute-force attackers from exhausting CPU via expensive GSI certificate verification chains and VOMS attribute extraction. Certreq round exclusion ensures the two-round GSI handshake completes without counting server's first response as a failure.
 */
ngx_int_t
xrootd_handle_auth(xrootd_ctx_t *ctx, ngx_connection_t *c)
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
    if (ctx->auth_fail_count >= XROOTD_MAX_AUTH_ATTEMPTS) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: %s: auth attempt limit reached, disconnecting",
                      ctx->login_user);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "Too many authentication failures");
    }

    /*
     * GSI round 1 (kXGC_certreq): the server responds with kXR_authmore
     * carrying its certificate — this is not a credential failure and must
     * not count toward the limit.
     */
    is_certreq = 0;
    if (ctx->cur_dlen >= 8 && ctx->payload != NULL) {
        const u_char *ctype = ctx->cur_body + 12;
        if (ctype[0] == 'g' && ctype[1] == 's' && ctype[2] == 'i') {
            uint32_t step;
            ngx_memcpy(&step, ctx->payload + 4, 4);
            is_certreq = (ntohl(step) == (uint32_t) kXGC_certreq);
        }
    }

    was_auth_done = ctx->auth_done;
    rc = xrootd_handle_auth_inner(ctx, c);

    if (!is_certreq) {
        if (!was_auth_done && ctx->auth_done) {
            ctx->auth_fail_count = 0;   /* successful auth resets the counter */
        } else if (!ctx->auth_done) {
            ctx->auth_fail_count++;     /* failed or protocol-level challenge */
        }
    }

    return rc;
}

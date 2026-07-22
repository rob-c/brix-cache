#include "gsi_internal.h"
#include "delegation.h"
#include "protocols/root/session/registry.h"
#include "auth/crypto/ocsp.h"
#include "auth/crypto/gsi_verify.h"
#include <openssl/err.h>
#include <openssl/pem.h>

/*
 * gsi_promote_fullproxy — validate an OPTIONAL client-pushed full proxy
 * (kXRS_x509_fullproxy, phase-70 §5.1) captured during kXGC_cert and, if it
 * passes, promote its bytes to ctx->deleg_proxy_pem for backend PASSTHROUGH.
 *
 * WHY:  A node can only replay x509 upstream if the user voluntarily hands over
 *       a full proxy (chain + private key). This is the wire-receive + identity
 *       gate for that opt-in: it MUST NOT let a session present a proxy for a
 *       different identity, and MUST NOT accept a key over cleartext.
 *
 * HOW:  Runs only after the front door proved the GSI identity (ctx->login.dn
 *       is set). Rejects the login when the captured proxy fails any check;
 *       silently no-ops when nothing was captured (the common case).
 *       Checks: (1) transport is TLS (roots://) — a private key never crosses
 *       cleartext; (2) the PEM parses to a cert chain AND a private key;
 *       (3) the supplied leaf/EEC subject is a parent of the authenticated
 *       proxy DN (ctx->login.dn begins with it) — no identity swap. On success
 *       the raw bytes move to ctx->deleg_proxy_pem (borrowed by the binder).
 *       Returns NGX_OK to proceed, NGX_ERROR to reject the login.
 */
static ngx_int_t
gsi_promote_fullproxy(brix_ctx_t *ctx, ngx_connection_t *c)
{
    BIO      *bio;
    X509     *leaf;
    EVP_PKEY *key = NULL;
    char     *subj;
    int       dn_ok;

    if (ctx->gsi.client_fullproxy_pem == NULL) {
        return NGX_OK;                         /* nothing supplied — normal */
    }

    /* (1) TLS-only: a full proxy carries a private key; never over cleartext. */
    if (c->ssl == NULL) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "brix: GSI full-proxy passthrough rejected: "
                      "supplied over cleartext (roots:// required)");
        return NGX_ERROR;
    }

    /* (2) Parse the chain leaf and the private key from the same PEM. */
    bio = BIO_new_mem_buf(ctx->gsi.client_fullproxy_pem,
                          (int) ctx->gsi.client_fullproxy_len);
    if (bio == NULL) {
        return NGX_ERROR;
    }
    leaf = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (leaf != NULL) {
        (void) BIO_reset(bio);
        key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    }
    BIO_free(bio);
    if (leaf == NULL || key == NULL) {
        X509_free(leaf);
        EVP_PKEY_free(key);
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "brix: GSI full-proxy passthrough rejected: "
                      "PEM missing cert chain or private key");
        return NGX_ERROR;
    }
    EVP_PKEY_free(key);                         /* only presence is checked here */

    /* (3) Identity gate: the authenticated proxy DN must sit beneath the
     * supplied leaf/EEC subject — the user may only pass through a proxy for
     * their own identity, never elevate to another. */
    subj = X509_NAME_oneline(X509_get_subject_name(leaf), NULL, 0);
    dn_ok = (subj != NULL
             && ngx_strncmp(ctx->login.dn, subj, ngx_strlen(subj)) == 0);
    OPENSSL_free(subj);
    X509_free(leaf);

    if (!dn_ok) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "brix: GSI full-proxy passthrough rejected: "
                      "supplied proxy identity does not match authenticated DN");
        return NGX_ERROR;
    }

    /* Passed: hand the bytes to the session ctx for the root:// VFS binder.
     * Copy into c->pool so the lifetime matches the rest of the session ctx,
     * then release the heap capture. Never logged. */
    ctx->deleg_proxy_pem.data = ngx_pnalloc(c->pool,
                                            ctx->gsi.client_fullproxy_len);
    if (ctx->deleg_proxy_pem.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(ctx->deleg_proxy_pem.data, ctx->gsi.client_fullproxy_pem,
               ctx->gsi.client_fullproxy_len);
    ctx->deleg_proxy_pem.len = ctx->gsi.client_fullproxy_len;

    OPENSSL_cleanse(ctx->gsi.client_fullproxy_pem, ctx->gsi.client_fullproxy_len);
    free(ctx->gsi.client_fullproxy_pem);
    ctx->gsi.client_fullproxy_pem = NULL;
    ctx->gsi.client_fullproxy_len = 0;

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "brix: GSI full-proxy passthrough accepted for backend "
                  "delegation (identity verified)");
    return NGX_OK;
}

/*
 * gsi_cert_deny — shared deny tail for the kXGC_cert step.
 *
 * WHY:  Every post-parse failure in the cert step must emit the same
 *       access-log line shape, bump the AUTH error metric, free the parsed
 *       chain, and answer kXR_NotAuthorized — one helper keeps the deny
 *       paths byte-identical.
 *
 * HOW:  `log_msg` goes to the access log, `err_msg` to the wire error (they
 *       differ for the OCSP case). Frees `chain`; returns the send rc.
 */
static ngx_int_t
gsi_cert_deny(brix_ctx_t *ctx, ngx_connection_t *c, STACK_OF(X509) *chain,
              const char *log_msg, const char *err_msg)
{
    brix_log_access(ctx, c, "AUTH", "-", "gsi",
                      0, kXR_NotAuthorized, log_msg, 0);
    BRIX_OP_ERR(ctx, BRIX_OP_AUTH);
    sk_X509_pop_free(chain, X509_free);
    return brix_send_error(ctx, c, kXR_NotAuthorized, err_msg);
}

/*
 * gsi_cert_verify — verify the parsed client chain against the CA store.
 *
 * WHY:  The chain-verify call needs the non-leaf certs split out as the
 *       untrusted stack; isolating the dup/verify/free sequence keeps the
 *       cert step linear.
 *
 * HOW:  Builds the untrusted stack (chain minus leaf) when present, runs
 *       brix_gsi_verify_chain (RFC 3820 proxies accepted, DN/VOMS material
 *       returned in *verify_res), frees the dup, and returns the verify rc
 *       (brix_gsi_verify_chain already logged any specific error).
 */
static ngx_int_t
gsi_cert_verify(ngx_connection_t *c, ngx_stream_brix_srv_conf_t *conf,
                STACK_OF(X509) *chain, X509 *leaf,
                brix_gsi_verify_result_t *verify_res)
{
    STACK_OF(X509) *untrusted = NULL;
    ngx_int_t       gsi_rc;

    if (sk_X509_num(chain) > 1) {
        untrusted = sk_X509_dup(chain);
        sk_X509_delete(untrusted, 0);
    }

    gsi_rc = brix_gsi_verify_chain(c->log, conf->gsi_store,
                                      leaf, untrusted, 0, verify_res,
                                      0 /* GSI: accept RFC 3820 proxies */);

    if (untrusted) {
        sk_X509_free(untrusted);
    }

    return gsi_rc;
}

/*
 * gsi_cert_capture_dn — copy the verified DN into the session identity.
 *
 * WHY:  The DN is the session's authorization identity; an over-long DN is
 *       truncated (buffer-bounded) but operators must be warned because VO
 *       ACL rules may then fail to match.
 *
 * HOW:  Warns when the verified DN exceeds ctx->login.dn, then bounded-copies
 *       it with ngx_cpystrn.
 */
static void
gsi_cert_capture_dn(brix_ctx_t *ctx, ngx_connection_t *c,
                    const brix_gsi_verify_result_t *verify_res)
{
    if (strlen(verify_res->dn_buf) >= sizeof(ctx->login.dn)) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "brix: GSI DN too long (%uz bytes), truncating to %uz; "
                      "VO ACL rules may not match correctly",
                      strlen(verify_res->dn_buf), sizeof(ctx->login.dn) - 1);
    }
    ngx_cpystrn((u_char *) ctx->login.dn,
                (u_char *) verify_res->dn_buf,
                sizeof(ctx->login.dn));
}

/*
 * gsi_cert_extract_voms — best-effort VOMS VO-membership extraction.
 *
 * WHY:  VO membership drives authdb group rules; extraction is optional
 *       (only when VOMS support is built in and both directories are
 *       configured) and never fails the login.
 *
 * HOW:  Runs brix_extract_voms_info into ctx->login.{primary_vo,vo_list};
 *       on success logs the (sanitized) membership list at INFO.
 */
static void
gsi_cert_extract_voms(brix_ctx_t *ctx, ngx_connection_t *c,
                      ngx_stream_brix_srv_conf_t *conf,
                      X509 *leaf, STACK_OF(X509) *chain)
{
    ngx_int_t voms_rc;

    if (!brix_voms_available()
        || conf->vomsdir.len == 0 || conf->voms_cert_dir.len == 0)
    {
        return;
    }

    voms_rc = brix_extract_voms_info(
        c->log, leaf, chain,
        &conf->vomsdir, &conf->voms_cert_dir,
        ctx->login.primary_vo, sizeof(ctx->login.primary_vo),
        ctx->login.vo_list, sizeof(ctx->login.vo_list));

    if (voms_rc == NGX_OK) {
        char vo_log[256];

        brix_sanitize_log_string(ctx->login.vo_list, vo_log, sizeof(vo_log));
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "brix: VOMS VO membership: %s", vo_log);
    }
}

/*
 * gsi_auth_step_cert — GSI step 2 (kXGC_cert): the client's proxy chain.
 *
 * WHY:  Round 2 of the DH exchange carries the client's encrypted proxy
 *       chain — the security-load-bearing heart of GSI auth: parse, chain
 *       verify (+ optional OCSP), DN capture, optional full-proxy
 *       passthrough, VOMS extraction, then either begin §F6 delegation or
 *       complete the auth.
 *
 * HOW:  Linear pipeline with early-return denies (gsi_cert_deny frees the
 *       chain on every failure). The ephemeral DH key is freed as soon as
 *       parse_x509 has consumed it. When tpc_delegate is on and a session
 *       cipher was persisted, begin_delegation sends kXGS_pxyreq
 *       (kXR_authmore) and auth completes when kXGC_sigpxy arrives;
 *       otherwise brix_gsi_complete_auth finalizes immediately.
 */
ngx_int_t
gsi_auth_step_cert(brix_ctx_t *ctx, ngx_connection_t *c,
                   ngx_stream_brix_srv_conf_t *conf)
{
    STACK_OF(X509)            *chain;
    X509                      *leaf;
    brix_gsi_verify_result_t   verify_res;

    chain = brix_gsi_parse_x509(ctx, c);

    if (ctx->gsi.dh_key) {
        EVP_PKEY_free(ctx->gsi.dh_key);
        ctx->gsi.dh_key = NULL;
    }

    if (chain == NULL) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_AUTH, "AUTH", "-", "gsi",
                          kXR_NotAuthorized, "cannot parse GSI credential");
    }

    leaf = sk_X509_value(chain, 0);

    if (gsi_cert_verify(c, conf, chain, leaf, &verify_res) != NGX_OK) {
        /* brix_gsi_verify_chain already logged the specific error */
        return gsi_cert_deny(ctx, c, chain,
                             "certificate verification failed",
                             "certificate verification failed");
    }

    /*
     * OCSP revocation check (Feature 8e).
     * The certificate chain is still valid at this point: leaf is chain[0],
     * its issuer is chain[1] (may be NULL for single-cert chains).
     */
    if (conf->ocsp.enable) {
        X509 *issuer = (sk_X509_num(chain) > 1)
                       ? sk_X509_value(chain, 1) : NULL;
        if (brix_ocsp_check_cert(c->log, leaf, issuer,
                                   (int)conf->ocsp.soft_fail,
                                   (int)conf->ocsp.require_nonce) != 0)
        {
            return gsi_cert_deny(ctx, c, chain,
                                 "OCSP check failed",
                                 "OCSP certificate check failed");
        }
    }

    gsi_cert_capture_dn(ctx, c, &verify_res);

    /* phase-70 §5.1: validate + promote an OPTIONAL client-pushed full proxy
     * now that the identity DN is known. A supplied-but-invalid proxy fails the
     * login (never silently downgrades to service cred). */
    if (gsi_promote_fullproxy(ctx, c) != NGX_OK) {
        return gsi_cert_deny(ctx, c, chain,
                             "full-proxy passthrough rejected",
                             "full-proxy passthrough rejected");
    }

    gsi_cert_extract_voms(ctx, c, conf, leaf, chain);

    /*
     * §F6 X.509 proxy delegation: when enabled, run an extra handshake round to
     * capture the client's delegated proxy BEFORE completing auth. The DN/VOMS are
     * already extracted (above) and the chain/leaf are still valid here; the GSI
     * session cipher was persisted by parse_x509. begin_delegation sends
     * kXGS_pxyreq (kXR_authmore) and auth completes when kXGC_sigpxy arrives.
     */
    if (conf->tpc_delegate && !ctx->gsi.deleg_await && ctx->gsi.sess_keylen > 0) {
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

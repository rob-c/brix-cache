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
static ngx_int_t
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
static ngx_int_t
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

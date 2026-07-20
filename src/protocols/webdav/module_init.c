/*
 * module_init.c - extracted concern
 * Phase-38 split of module.c; behavior-identical.
 */
#include "webdav_module_internal.h"
#include "core/seccomp/seccomp.h"    /* brix_seccomp_install_once */
#include "protocols/cvmfs/cvmfs.h"   /* $brix_protocol: cvmfs claim */
#include "auth/crypto/store_policy.h" /* brix_px_classify, brix_x509_oneline */
#include "fs/backend/ucred.h"         /* brix_sd_ucred_key / _resolve */


/*
 * Directive table for the WebDAV HTTP module.  Mechanical: each entry binds a
 * config keyword to a setter and (usually) a field offset in the location conf.
 * Most use stock nginx setters (set_flag/str/num/sec/msec_slot); the handful of
 * custom handlers above (CORS origin list, proxy auth/upstream, open_file_cache)
 * and the cross-module setters (mirror, rate-limit, KV, token-cache) appear
 * where they are grouped by feature.  Defaults/merge live in config.c.
 */


/* Preconfiguration: register the $brix_protocol variable. */
/*
 * Resolve $brix_protocol for the current request: "webdav", "s3", "cvmfs",
 * or "http". Precedence is webdav > s3 > cvmfs > plain http, decided by
 * which sibling module is enabled in this request's location conf (WebDAV
 * wins if several somehow apply). The labels are the central proto_list.h
 * dash_names; "http" is the nothing-claimed fallback. Used in log_format /
 * proxy decisions to label the served protocol.
 */
ngx_int_t
brix_http_protocol_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_brix_webdav_loc_conf_t *wdcf;
    ngx_http_s3_loc_conf_t            *scf;
    ngx_http_brix_cvmfs_loc_conf_t  *ccf;
    const char                        *label;
    size_t                             len;

    (void) data;

    label = "http";
    len = sizeof("http") - 1;

    wdcf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    scf = ngx_http_get_module_loc_conf(r, ngx_http_brix_s3_module);
    ccf = ngx_http_get_module_loc_conf(r, ngx_http_brix_cvmfs_module);
    if (wdcf != NULL && wdcf->common.enable) {
        label = "webdav";
        len = sizeof("webdav") - 1;
    } else if (scf != NULL && scf->common.enable) {
        label = "s3";
        len = sizeof("s3") - 1;
    } else if (ccf != NULL && ccf->cvmfs.enable) {
        label = "cvmfs";
        len = sizeof("cvmfs") - 1;
    }

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) label;

    return NGX_OK;
}


/*
 * delegated_cred_find_eec — locate the end-entity certificate of the
 * TLS-verified peer: the leaf itself when the client authenticated with a
 * bare cert, else the first non-proxy cert (brix_px_classify) in the
 * presented chain (RFC 3820 proxies chain leaf → parent proxies → EEC).
 * Returns a BORROWED reference (owned by `leaf`'s refcount or by the
 * connection's chain) or NULL when every presented cert is a proxy.
 */
static X509 *
delegated_cred_find_eec(SSL *sc, X509 *leaf)
{
    STACK_OF(X509)  *chain;
    int              i, n;

    if (brix_px_classify(leaf) == BRIX_PX_NONE) {
        return leaf;
    }

    /* Server side: SSL_get_peer_cert_chain excludes the leaf. */
    chain = SSL_get_peer_cert_chain(sc);
    n = (chain != NULL) ? sk_X509_num(chain) : 0;

    for (i = 0; i < n; i++) {
        X509 *cert = sk_X509_value(chain, i);

        if (brix_px_classify(cert) == BRIX_PX_NONE) {
            return cert;
        }
    }

    return NULL;
}


/*
 * $brix_delegated_cred — the verified client's delegated-credential path.
 *
 * WHAT: resolves the per-user credential file stored by the delegation
 * endpoint (delegation.c): EEC DN of the TLS-verified client chain →
 * brix_sd_ucred_key ("x5h-" + SHA-256 prefix) → <storage_credential_dir>/
 * <key>.pem, expiry-checked.  Empty when anything is missing — FAIL CLOSED.
 *
 * WHY: replaces the hand-maintained `map $ssl_client_s_dn_legacy` block in
 * credential-forwarding gateways (ARC-CE front proxy): the map duplicated
 * the ucred key derivation per user and had to be regenerated + reloaded on
 * every new user, and could not expiry-check the file it named.  With this
 * variable, `proxy_ssl_certificate $brix_delegated_cred` picks up a new
 * user's credential the moment delegation stores it.
 *
 * HOW: identity comes from the TLS layer directly (SSL_get_verify_result
 * must be X509_V_OK — same signal as $ssl_client_verify), NOT from brix
 * request auth, so the variable works in plain proxy_pass locations with no
 * brix handler.  The EEC is found by skipping RFC 3820 proxy certs
 * (delegation stores under the EEC DN — the delegation endpoint refuses
 * proxy-authenticated uploads).  Kind must be x509 (.pem): bearer/s3/ceph
 * files cannot feed proxy_ssl_certificate.  Expired → empty, with an info
 * log naming the DN so operators can see who must re-delegate.
 */
ngx_int_t
brix_http_delegated_cred_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_brix_webdav_loc_conf_t *wdcf;
    ngx_connection_t                  *c;
    X509                              *leaf, *eec;
    ngx_str_t                         *dir;
    brix_sd_ucred_t                    cred;
    ngx_int_t                          rc;
    size_t                             len;
    u_char                            *p;
    char                               dn[BRIX_UCRED_PRINC_MAX];
    char                               key[BRIX_UCRED_KEY_MAX];
    char                               dirbuf[BRIX_UCRED_PATH_MAX];

    (void) data;

    /* Fail-closed default: a valid, empty value ("" == no credential). */
    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) "";

    c = r->connection;

    if (c->ssl == NULL
        || SSL_get_verify_result(c->ssl->connection) != X509_V_OK)
    {
        return NGX_OK;
    }

    leaf = SSL_get_peer_certificate(c->ssl->connection);
    if (leaf == NULL) {
        return NGX_OK;
    }

    dn[0] = '\0';
    eec = delegated_cred_find_eec(c->ssl->connection, leaf);
    if (eec != NULL) {
        brix_x509_oneline(X509_get_subject_name(eec), dn, sizeof(dn));
    }
    X509_free(leaf);

    if (dn[0] == '\0') {
        return NGX_OK;
    }

    wdcf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    dir = &wdcf->common.storage_credential_dir;

    if (dir->len == 0 || dir->len >= sizeof(dirbuf)) {
        return NGX_OK;
    }
    ngx_memcpy(dirbuf, dir->data, dir->len);
    dirbuf[dir->len] = '\0';

    if (brix_sd_ucred_key(dn, key, sizeof(key)) != NGX_OK) {
        return NGX_OK;
    }

    /* resolve() leaves fields untouched on its not-found path — zero first
     * so the expired-credential log below never reads garbage. */
    ngx_memzero(&cred, sizeof(cred));

    rc = brix_sd_ucred_resolve(dirbuf, key, &cred);

    if (rc != NGX_OK || cred.is_bearer || cred.is_s3 || cred.is_ceph) {
        if (rc == NGX_DECLINED && cred.expired) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "brix_delegated_cred: stored credential for "
                          "\"%s\" has expired — re-delegation required", dn);
        }
        /* A bearer/s3/ceph credential may have resolved here (this variable
         * only surfaces the x509 proxy PATH); erase any secret we decline. */
        brix_sd_ucred_wipe(&cred);
        return NGX_OK;
    }

    len = ngx_strlen(cred.path);
    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        brix_sd_ucred_wipe(&cred);
        return NGX_ERROR;
    }
    ngx_memcpy(p, cred.path, len);

    v->len = len;
    v->data = p;

    brix_sd_ucred_wipe(&cred);   /* x509 proxy PATH exported; erase residue */
    return NGX_OK;
}


ngx_int_t
brix_http_add_protocol_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t *var;
    ngx_str_t            name = ngx_string("brix_protocol");
    ngx_str_t            cred_name = ngx_string("brix_delegated_cred");

    var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = brix_http_protocol_variable;
    var->data = 0;

    /* Per-request cacheable: the TLS identity cannot change mid-request. */
    var = ngx_http_add_variable(cf, &cred_name, 0);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = brix_http_delegated_cred_variable;
    var->data = 0;

    return NGX_OK;
}


ngx_int_t
ngx_http_brix_webdav_preconfiguration(ngx_conf_t *cf)
{
    return brix_http_add_protocol_variables(cf);
}


ngx_int_t
ngx_http_brix_webdav_init_process(ngx_cycle_t *cycle)
{
    curl_global_init(CURL_GLOBAL_DEFAULT);

    /* Install the process-global seccomp filter (idempotent).  For an HTTP-only
     * config the stream init_process early-returns before its own install, so
     * this is where WebDAV/S3/cvmfs workers get filtered.  Placed AFTER
     * curl_global_init so that one-shot setup is not itself filtered.  Fails the
     * worker closed if an audit/enforce filter cannot be built. */
    if (brix_seccomp_install_once(cycle) != NGX_OK) {
        return NGX_ERROR;
    }
    return NGX_OK;
}


void
ngx_http_brix_webdav_exit_process(ngx_cycle_t *cycle)
{
    (void) cycle;
    curl_global_cleanup();
}

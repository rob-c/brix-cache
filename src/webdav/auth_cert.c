/*
 * auth_cert.c - GSI/x509 proxy certificate verification and TLS auth cache.
 */

#include "webdav.h"

#include <ngx_http_ssl_module.h>

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

/*
 * Per-TLS-connection auth result cache.
 *
 * GSI/x509 certificate chain verification is expensive (multi-CA chain
 * traversal, CRL checks).  Once verified, the result is cached in an
 * OpenSSL ex_data slot attached to both the SSL object (session lifetime) and
 * the SSL_SESSION (resumption across connections).
 *
 * Lifecycle: allocated by webdav_verify_proxy_cert on first request; freed by
 *   webdav_tls_auth_cache_free when the SSL object or session is freed by
 *   OpenSSL.  Do NOT free this struct directly.
 *
 * IMPORTANT — reuse_logged: set to 1 after the first "resumed cert auth" log
 *   message so that TLS session resumptions only log once rather than once per
 *   request on a long-lived connection.
 */
typedef struct {
    ngx_http_xrootd_webdav_loc_conf_t *conf;    /* location config at auth time */
    X509_STORE                        *store;    /* CA store used (borrowed from conf) */
    ngx_uint_t                         verify_depth; /* depth limit used */
    ngx_uint_t                         reuse_logged;  /* 1 after first "resumed" log */
    char                               dn[1024];      /* verified subject DN */
} ngx_http_xrootd_webdav_tls_auth_cache_t;

static int webdav_ssl_auth_cache_index = -1;
static int webdav_ssl_session_auth_cache_index = -1;

static void
webdav_tls_auth_cache_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                           int idx, long argl, void *argp)
{
    (void) parent;
    (void) ad;
    (void) idx;
    (void) argl;
    (void) argp;

    if (ptr != NULL) {
        OPENSSL_free(ptr);
    }
}

ngx_int_t
webdav_auth_init_ssl_indices(ngx_log_t *log)
{
    if (webdav_ssl_auth_cache_index < 0) {
        webdav_ssl_auth_cache_index = SSL_get_ex_new_index(0, NULL, NULL,
                                                           NULL, NULL);
        if (webdav_ssl_auth_cache_index < 0) {
            ngx_log_error(NGX_LOG_EMERG, log, 0,
                          "xrootd_webdav: SSL_get_ex_new_index() failed");
            return NGX_ERROR;
        }
    }

    if (webdav_ssl_session_auth_cache_index < 0) {
        webdav_ssl_session_auth_cache_index =
            SSL_SESSION_get_ex_new_index(0, NULL, NULL, NULL,
                                         webdav_tls_auth_cache_free);
        if (webdav_ssl_session_auth_cache_index < 0) {
            ngx_log_error(NGX_LOG_EMERG, log, 0,
                          "xrootd_webdav: SSL_SESSION_get_ex_new_index() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

static ngx_int_t
webdav_str_equal(const ngx_str_t *a, const ngx_str_t *b)
{
    if (a->len != b->len) {
        return 0;
    }

    if (a->len == 0) {
        return 1;
    }

    return ngx_memcmp(a->data, b->data, a->len) == 0;
}

static void
webdav_free_verify_resources(X509_STORE_CTX *vctx, X509 *leaf)
{
    if (vctx) {
        X509_STORE_CTX_free(vctx);
    }
    if (leaf) {
        X509_free(leaf);
    }
}

static ngx_int_t
webdav_cache_matches(ngx_http_xrootd_webdav_tls_auth_cache_t *cache,
                     ngx_http_xrootd_webdav_loc_conf_t *conf)
{
    return cache != NULL
           && cache->conf == conf
           && cache->store == conf->ca_store
           && cache->verify_depth == conf->verify_depth
           && cache->dn[0] != '\0';
}

static void
webdav_mark_req_verified(ngx_http_xrootd_webdav_req_ctx_t *ctx,
                         const char *dn, const char *source)
{
    if (dn != NULL) {
        ngx_cpystrn((u_char *) ctx->dn, (u_char *) dn, sizeof(ctx->dn));
    }

    ctx->verified = 1;
    ctx->auth_source = source;
}

static void
webdav_log_auth_cache_reuse(ngx_http_request_t *r,
                            ngx_http_xrootd_webdav_tls_auth_cache_t *cache,
                            const char *cache_name)
{
    if (cache->reuse_logged) {
        return;
    }

    cache->reuse_logged = 1;
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "xrootd_webdav: GSI auth reused from TLS %s cache",
                  cache_name);
}

static ngx_int_t
webdav_store_tls_auth_cache(ngx_http_request_t *r, SSL *ssl,
                            ngx_http_xrootd_webdav_loc_conf_t *conf,
                            const char *dn)
{
    ngx_http_xrootd_webdav_tls_auth_cache_t *cache;
    SSL_SESSION                             *sess;

    if (webdav_ssl_auth_cache_index < 0 || dn == NULL || dn[0] == '\0') {
        return NGX_OK;
    }

    cache = SSL_get_ex_data(ssl, webdav_ssl_auth_cache_index);
    if (!webdav_cache_matches(cache, conf)) {
        cache = ngx_pcalloc(r->connection->pool, sizeof(*cache));
        if (cache == NULL) {
            return NGX_ERROR;
        }

        cache->conf = conf;
        cache->store = conf->ca_store;
        cache->verify_depth = conf->verify_depth;
        ngx_cpystrn((u_char *) cache->dn, (u_char *) dn, sizeof(cache->dn));

        if (SSL_set_ex_data(ssl, webdav_ssl_auth_cache_index, cache) == 0) {
            return NGX_ERROR;
        }
    }

    if (webdav_ssl_session_auth_cache_index < 0) {
        return NGX_OK;
    }

    sess = SSL_get0_session(ssl);
    if (sess != NULL) {
        ngx_http_xrootd_webdav_tls_auth_cache_t *scache;

        scache = SSL_SESSION_get_ex_data(sess,
                                         webdav_ssl_session_auth_cache_index);
        if (scache == NULL) {
            scache = OPENSSL_malloc(sizeof(*scache));
            if (scache == NULL) {
                return NGX_ERROR;
            }
            ngx_memzero(scache, sizeof(*scache));

            scache->conf = conf;
            scache->store = conf->ca_store;
            scache->verify_depth = conf->verify_depth;
            ngx_cpystrn((u_char *) scache->dn, (u_char *) dn,
                        sizeof(scache->dn));

            if (SSL_SESSION_set_ex_data(sess,
                                        webdav_ssl_session_auth_cache_index,
                                        scache) == 0)
            {
                OPENSSL_free(scache);
                return NGX_ERROR;
            }
        }

        if (!webdav_cache_matches(scache, conf)) {
            scache->conf = conf;
            scache->store = conf->ca_store;
            scache->verify_depth = conf->verify_depth;
            ngx_cpystrn((u_char *) scache->dn, (u_char *) dn,
                        sizeof(scache->dn));
        }
    }

    return NGX_OK;
}

static ngx_int_t
webdav_try_cached_tls_auth(ngx_http_request_t *r, SSL *ssl,
                           ngx_http_xrootd_webdav_loc_conf_t *conf,
                           ngx_http_xrootd_webdav_req_ctx_t *ctx)
{
    ngx_http_xrootd_webdav_tls_auth_cache_t *cache;
    SSL_SESSION                             *sess;

    if (webdav_ssl_auth_cache_index >= 0) {
        cache = SSL_get_ex_data(ssl, webdav_ssl_auth_cache_index);
        if (webdav_cache_matches(cache, conf)) {
            webdav_mark_req_verified(ctx, cache->dn, "tls-connection");
            webdav_log_auth_cache_reuse(r, cache, "connection");
            return NGX_OK;
        }
    }

    if (webdav_ssl_session_auth_cache_index >= 0) {
        sess = SSL_get0_session(ssl);
        if (sess != NULL) {
            cache = SSL_SESSION_get_ex_data(
                sess, webdav_ssl_session_auth_cache_index);
            if (webdav_cache_matches(cache, conf)) {
                webdav_mark_req_verified(ctx, cache->dn, "tls-session");
                if (webdav_store_tls_auth_cache(r, ssl, conf, cache->dn)
                    != NGX_OK)
                {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                webdav_log_auth_cache_reuse(r, cache, "session");
                return NGX_OK;
            }
        }
    }

    return NGX_DECLINED;
}

static ngx_int_t
webdav_nginx_verify_compatible(ngx_http_request_t *r,
                               ngx_http_xrootd_webdav_loc_conf_t *conf)
{
    ngx_http_ssl_srv_conf_t *sslcf;

    if (conf->cadir.len != 0 || conf->cafile.len == 0) {
        return 0;
    }

    sslcf = ngx_http_get_module_srv_conf(r, ngx_http_ssl_module);
    if (sslcf == NULL || sslcf->verify == 0) {
        return 0;
    }

    if (!webdav_str_equal(&conf->cafile, &sslcf->client_certificate)
        && !webdav_str_equal(&conf->cafile, &sslcf->trusted_certificate))
    {
        return 0;
    }

    if (conf->crl.len != 0 && !webdav_str_equal(&conf->crl, &sslcf->crl)) {
        return 0;
    }

    return 1;
}

static ngx_int_t
webdav_finish_verified_cert(ngx_http_request_t *r,
                            ngx_http_xrootd_webdav_loc_conf_t *conf,
                            ngx_http_xrootd_webdav_req_ctx_t *ctx,
                            SSL *ssl, X509 *leaf, const char *source)
{
    char *dn;

    dn = X509_NAME_oneline(X509_get_subject_name(leaf), NULL, 0);
    if (dn != NULL) {
        webdav_mark_req_verified(ctx, dn, source);
        (void) webdav_store_tls_auth_cache(r, ssl, conf, dn);
        OPENSSL_free(dn);
    } else {
        webdav_mark_req_verified(ctx, "", source);
    }

    {
        char dn_log[1024];

        xrootd_sanitize_log_string(ctx->dn, dn_log, sizeof(dn_log));
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "xrootd_webdav: GSI auth OK source=%s dn=\"%s\"",
                      source, dn_log);
    }

    return NGX_OK;
}

ngx_int_t
webdav_verify_proxy_cert(ngx_http_request_t *r,
                         ngx_http_xrootd_webdav_loc_conf_t *conf)
{
    ngx_http_xrootd_webdav_req_ctx_t *ctx;
    SSL              *ssl;
    X509             *leaf = NULL;
    STACK_OF(X509)   *chain = NULL;
    X509_STORE_CTX   *vctx = NULL;
    int               ok = 0;
    long              verify_result;
    ngx_int_t         cache_rc;

    ctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
    if (ctx != NULL) {
        return ctx->verified ? NGX_OK : NGX_HTTP_FORBIDDEN;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_http_set_ctx(r, ctx, ngx_http_xrootd_webdav_module);

    if (r->connection->ssl == NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "xrootd_webdav: non-TLS connection, cannot verify GSI");
        return NGX_HTTP_FORBIDDEN;
    }

    ssl = r->connection->ssl->connection;

    cache_rc = webdav_try_cached_tls_auth(r, ssl, conf, ctx);
    if (cache_rc == NGX_OK) {
        return NGX_OK;
    }
    if (cache_rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return cache_rc;
    }

    leaf = SSL_get_peer_certificate(ssl);
    if (leaf == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "xrootd_webdav: no client certificate presented");
        return NGX_HTTP_FORBIDDEN;
    }

    verify_result = SSL_get_verify_result(ssl);
    if (verify_result == X509_V_OK
        && webdav_nginx_verify_compatible(r, conf))
    {
        ngx_int_t rc;

        rc = webdav_finish_verified_cert(r, conf, ctx, ssl, leaf, "nginx");
        webdav_free_verify_resources(NULL, leaf);
        return rc;
    }

    chain = SSL_get_peer_cert_chain(ssl);

    if (conf->ca_store == NULL) {
        webdav_free_verify_resources(NULL, leaf);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "xrootd_webdav: cached CA store is unavailable");
        return NGX_HTTP_FORBIDDEN;
    }

    vctx = X509_STORE_CTX_new();
    if (vctx == NULL) {
        webdav_free_verify_resources(NULL, leaf);
        return NGX_HTTP_FORBIDDEN;
    }

    if (!X509_STORE_CTX_init(vctx, conf->ca_store, leaf, chain)) {
        webdav_free_verify_resources(vctx, leaf);
        return NGX_HTTP_FORBIDDEN;
    }

    X509_STORE_CTX_set_flags(vctx, X509_V_FLAG_ALLOW_PROXY_CERTS);

    if ((ngx_uint_t) conf->verify_depth > 0) {
        X509_STORE_CTX_set_depth(vctx, (int) conf->verify_depth);
    }

    ok = X509_verify_cert(vctx);
    if (!ok) {
        int verr = X509_STORE_CTX_get_error(vctx);

        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "xrootd_webdav: proxy cert verification failed: %s",
                      X509_verify_cert_error_string(verr));
        webdav_free_verify_resources(vctx, leaf);
        return NGX_HTTP_FORBIDDEN;
    }

    cache_rc = webdav_finish_verified_cert(r, conf, ctx, ssl, leaf, "manual");
    webdav_free_verify_resources(vctx, leaf);
    return cache_rc;
}

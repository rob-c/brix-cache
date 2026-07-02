/*
 * auth_cert.c - GSI/x509 proxy certificate verification and TLS auth cache.
 */

#include "webdav.h"
#include "auth/crypto/gsi_verify.h"
#include "core/ngx_xrootd_module.h"

#include <ngx_http_ssl_module.h>

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include "core/compat/alloc_guard.h"

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

/*
 *
 * WHAT: OpenSSL ex_data cleanup callback that frees the TLS auth cache structure when the SSL object or session is destroyed. Called automatically by OpenSSL during resource deallocation — never called directly by application code.
 *
 * WHY: The TLS auth cache must be freed exactly when its parent (SSL object or SSL_SESSION) is destroyed to prevent memory leaks across long-lived connections and TLS session resumptions. */
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

/*
 *
 * WHAT: Initializes OpenSSL ex_data indices for attaching TLS auth cache data to both SSL objects and SSL sessions. These indices are global static values that allow OpenSSL to store arbitrary data (the auth cache struct) alongside each SSL connection without requiring additional memory allocation by the application.
 *
 * WHY: The GSI cert verification is expensive (multi-CA chain traversal, CRL checks). Once verified, caching the result in an ex_data slot avoids re-verifying on every request within the same TLS session — this dramatically reduces CPU cost for long-lived connections where clients make many requests after a single initial certificate check. */
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

/*
 *
 * WHAT: Compares two ngx_str_t structures for equality by first checking length, then byte-by-byte content. Handles the special case of empty strings (length 0) which are always considered equal regardless of data pointer values. This is safer than using memcmp directly because empty strings with different pointers could pass memcmp if both buffers happen to contain zero bytes.
 *
 * WHY: nginx uses ngx_str_t for string representation (not null-terminated C strings). Comparing these requires length-aware operations — strlen/strcpy would fail on non-null-terminated ngx_str_t structures per the FAQ rules in AGENTS.md. */
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

/*
 *
 * WHAT: Cleanup callback that frees OpenSSL X509_STORE_CTX and X509 certificate objects after verification completes. Handles NULL pointers gracefully — only frees non-NULL resources to prevent double-free or NULL-deref crashes during error paths.
 *
 * WHY: Every successful cert verification path must clean up allocated resources before returning. This shared cleanup function ensures consistent resource release across both "nginx-compatible" and "manual verification" code paths without duplicating free logic. */
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

/*
 *
 * WHAT: Validates that a cached TLS auth result is still valid for the current request by checking five conditions: cache exists, config reference matches, CA store pointer matches, verify depth setting matches, and DN was successfully verified (non-empty). Returns NGX_TRUE only when ALL conditions are satisfied.
 *
 * WHY: The auth cache must be invalidated whenever configuration changes — if conf->ca_store or conf->verify_depth changed between requests, the cached verification result may no longer apply to the current certificate chain. This check prevents serving stale cache results after configuration reloads. */
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

/*
 *
 * WHAT: Marks the request context as verified by copying the subject DN into ctx->dn, setting ctx->verified=1, and recording the authentication source ("nginx" for compatible mode or "manual" for explicit verification). This is called after successful certificate validation to signal that subsequent requests in this session can skip full re-verification.
 *
 * WHY: The request context is attached to the HTTP request via ngx_http_set_ctx() — marking it verified allows webdav_verify_proxy_cert() to return immediately on later requests without repeating the expensive chain traversal and CRL check. This is the core mechanism that enables TLS auth caching across a connection's lifetime. */
static xrootd_identity_t *
webdav_ensure_identity(ngx_http_request_t *r,
                       ngx_http_xrootd_webdav_req_ctx_t *ctx)
{
    if (ctx->identity == NULL) {
        ctx->identity = xrootd_identity_alloc(r->pool);
    }

    return ctx->identity;
}

static ngx_int_t
webdav_mark_req_verified(ngx_http_request_t *r,
                         ngx_http_xrootd_webdav_req_ctx_t *ctx,
                         const char *dn, const char *source)
{
    xrootd_identity_t *identity;

    if (dn != NULL) {
        ngx_cpystrn((u_char *) ctx->dn, (u_char *) dn, sizeof(ctx->dn));
    }

    ctx->verified = 1;
    ctx->auth_source = source;

    identity = webdav_ensure_identity(r, ctx);
    if (identity == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return xrootd_identity_set_dn(identity, r->pool, ctx->dn,
                                  XROOTD_AUTHN_GSI) == NGX_OK
           ? NGX_OK : NGX_HTTP_INTERNAL_SERVER_ERROR;
}

/*
 *
 * WHAT: Logs a single informational message when TLS auth cache is reused (either from connection or session), but only logs the first time per request to avoid flooding operator logs with repetitive messages on long-lived connections. Uses reuse_logged flag to ensure exactly one "resumed" log entry per request regardless of how many times the cache is hit during that request.
 *
 * WHY: Operators monitoring access logs need visibility into when auth caching kicks in (indicating reduced CPU load), but must not be flooded with messages on every subsequent request within a TLS session resumption. This single-log-per-request approach provides observability without log noise. */
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

/*
 *
 * WHAT: Stores the verified DN into both SSL object ex_data (for connection lifetime) and optionally SSL_SESSION ex_data (for session resumption across connections). First checks if a cache already exists for this SSL object; if it doesn't match current config, allocates a new one. Then stores into the session-level cache as well so that TLS session resumptions carry the verified DN forward to new TCP connections.
 *
 * WHY: Enables two-tier caching: (1) connection-level cache avoids re-verification during a single TCP session's requests; (2) session-level cache allows resumption across different TCP sessions (e.g., after network interruption or client reconnect). Both tiers share the same DN but have independent lifetimes — this maximizes caching benefit while respecting OpenSSL session semantics. */
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
        XROOTD_PCALLOC_OR_RETURN(cache, r->connection->pool, sizeof(*cache), NGX_ERROR);

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
            if (webdav_mark_req_verified(r, ctx, cache->dn, "tls-connection")
                != NGX_OK)
            {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
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
                if (webdav_mark_req_verified(r, ctx, cache->dn, "tls-session")
                    != NGX_OK)
                {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
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
        if (webdav_mark_req_verified(r, ctx, dn, source) != NGX_OK) {
            OPENSSL_free(dn);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        (void) webdav_store_tls_auth_cache(r, ssl, conf, dn);
        OPENSSL_free(dn);
    } else {
        if (webdav_mark_req_verified(r, ctx, "", source) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    {
        char dn_log[1024];

        xrootd_sanitize_log_string(ctx->dn, dn_log, sizeof(dn_log));
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "xrootd_webdav: GSI auth OK source=%s dn=\"%s\"",
                      source, dn_log);
    }

    /* Optional VOMS VO extraction — non-fatal; NGX_DECLINED means no VOMS
     * attributes in the proxy cert, which is normal for plain grid proxies. */
    if (conf->vomsdir.len > 0 && conf->voms_cert_dir.len > 0
        && xrootd_voms_available())
    {
        STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl);
        char primary_vo[256] = "";
        char vo_list[1024]   = "";

        (void) xrootd_extract_voms_info(r->connection->log, leaf, chain,
                                        &conf->vomsdir, &conf->voms_cert_dir,
                                        primary_vo, sizeof(primary_vo),
                                        vo_list, sizeof(vo_list));
        if (ctx->identity != NULL && vo_list[0] != '\0'
            && xrootd_identity_set_vos_csv(ctx->identity, r->pool, vo_list)
               != NGX_OK)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        if (primary_vo[0] != '\0') {
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                          "xrootd_webdav: VOMS primary_vo=\"%s\"", primary_vo);
        }
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
    xrootd_gsi_verify_result_t  verify_res;
    long              verify_result;
    ngx_int_t         cache_rc;

    ctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
    if (ctx != NULL) {
        return ctx->verified ? NGX_OK : NGX_HTTP_FORBIDDEN;
    }

    XROOTD_PCALLOC_OR_RETURN(ctx, r->pool, sizeof(*ctx), NGX_HTTP_INTERNAL_SERVER_ERROR);
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

    if (xrootd_gsi_verify_chain(r->connection->log, conf->ca_store,
                                 leaf, chain, conf->verify_depth,
                                 &verify_res) != NGX_OK)
    {
        /* xrootd_gsi_verify_chain already logged the specific error */
        webdav_free_verify_resources(NULL, leaf);
        return NGX_HTTP_FORBIDDEN;
    }

    cache_rc = webdav_finish_verified_cert(r, conf, ctx, ssl, leaf, "manual");
    webdav_free_verify_resources(NULL, leaf);
    return cache_rc;
}

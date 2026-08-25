#include "ftp_gateway.h"
#include "ftp_module_internal.h"

#include "auth/crypto/pki_build.h"

#include <sys/stat.h>
#include <openssl/ssl.h>

/*
 * ftp_module_gsi.c — GridFTP gateway RFC 2228 GSI security-layer setup: build
 * the host TLS context (cert/key) and the client-proxy trust store from the
 * brix_gridftp_gsi / _certificate / _certificate_key / _trusted_ca directives.
 * Split verbatim from ftp_module.c; brix_ftp_build_gsi() is the config-time
 * seam invoked by brix_ftp_merge_conf() (ftp_module.c).
 */


/* Pool cleanup: release the raw SSL_CTX at cycle teardown. */
static void
brix_ftp_ssl_ctx_cleanup(void *data)
{
    SSL_CTX *ctx = data;

    if (ctx != NULL) {
        SSL_CTX_free(ctx);
    }
}

/*
 * WHAT: Validate and copy all configured GSI file-system paths.
 * WHY: Bound every NUL-terminated path before passing it to libc/OpenSSL.
 * HOW: Require cert/key/CA, check fixed-buffer limits, then copy each value.
 */
static ngx_int_t
brix_ftp_gsi_paths(ngx_conf_t *cf, ngx_stream_brix_ftp_srv_conf_t *conf,
    char *cert, size_t cert_cap, char *key, size_t key_cap,
    char *ca, size_t ca_cap)
{
    if (conf->certificate.len == 0 || conf->certificate_key.len == 0
        || conf->trusted_ca.len == 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_gridftp_gsi requires brix_gridftp_certificate, "
            "brix_gridftp_certificate_key and brix_gridftp_trusted_ca");
        return NGX_ERROR;
    }
    if (conf->certificate.len >= cert_cap
        || conf->certificate_key.len >= key_cap
        || conf->trusted_ca.len >= ca_cap)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "brix_gridftp_gsi certificate/key/CA path too long");
        return NGX_ERROR;
    }
    ngx_memcpy(cert, conf->certificate.data, conf->certificate.len);
    cert[conf->certificate.len] = '\0';
    ngx_memcpy(key, conf->certificate_key.data, conf->certificate_key.len);
    key[conf->certificate_key.len] = '\0';
    ngx_memcpy(ca, conf->trusted_ca.data, conf->trusted_ca.len);
    ca[conf->trusted_ca.len] = '\0';
    return NGX_OK;
}


/*
 * WHAT: Allocate the callback-free TLS context used by the mem-BIO GSI engine.
 * WHY: nginx SSL callbacks assume connection ex-data that this engine lacks.
 * HOW: Create a generic TLS context, register pool cleanup, and pin TLS 1.2.
 */
static SSL_CTX *
brix_ftp_gsi_ssl_ctx(ngx_conf_t *cf)
{
    SSL_CTX             *ctx;
    ngx_pool_cleanup_t  *cln;

    ctx = SSL_CTX_new(TLS_method());
    if (ctx == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "brix_gridftp_gsi: SSL_CTX_new failed");
        return NULL;
    }
    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    cln->handler = brix_ftp_ssl_ctx_cleanup;
    cln->data = ctx;
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    return ctx;
}


/*
 * WHAT: Load and validate the GridFTP host certificate and private key.
 * WHY: Refuse configuration before any session can use mismatched credentials.
 * HOW: Load the PEM chain and key, then require OpenSSL's key-pair check.
 */
static ngx_int_t
brix_ftp_gsi_host_credentials(ngx_conf_t *cf, SSL_CTX *ctx,
    const char *cert, const char *key)
{
    if (SSL_CTX_use_certificate_chain_file(ctx, cert) == 1
        && SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) == 1
        && SSL_CTX_check_private_key(ctx) == 1)
    {
        return NGX_OK;
    }
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "brix_gridftp_gsi: cannot load host cert %s / key %s",
                       cert, key);
    return NGX_ERROR;
}


/* brix_ftp_build_gsi — construct the host TLS context (cert/key) and the client
 * proxy trust store once the GSI directives are known.  Unlike root:// / WebDAV
 * TLS, the mem-BIO GSSAPI engine (gsi_mech.c) drives handshakes on a bare SSL
 * object with no nginx connection attached, so we must NOT use ngx_ssl_create():
 * it installs nginx info/servername callbacks that deref an ngx_connection_t via
 * SSL ex-data our SSL never has, crashing mid-handshake.  A plain OpenSSL
 * SSL_CTX (as in the phase-82 interop probe) sidesteps every such callback. */
char *
brix_ftp_build_gsi(ngx_conf_t *cf, ngx_stream_brix_ftp_srv_conf_t *conf)
{
    struct stat          stbuf;
    int                  ca_is_dir;
    char                 ca_raw[PATH_MAX];
    char                 cert_raw[PATH_MAX];
    char                 key_raw[PATH_MAX];
    SSL_CTX             *ctx;

    if (brix_ftp_gsi_paths(cf, conf, cert_raw, sizeof(cert_raw),
                           key_raw, sizeof(key_raw), ca_raw, sizeof(ca_raw))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    conf->tls_ctx = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
    if (conf->tls_ctx == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->tls_ctx->log = cf->log;

    /* Version-flexible method (not TLS_server_method): the same context serves
     * both roles — the control channel and the passive data channel accept
     * (SSL_accept), while a gsiftp↔gsiftp TPC source leg connects out on the
     * data channel (SSL_connect).  A server-only context makes SSL_connect fail
     * with "called a function you should not call". */
    ctx = brix_ftp_gsi_ssl_ctx(cf);
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }
    if (brix_ftp_gsi_host_credentials(cf, ctx, cert_raw, key_raw) != NGX_OK) {
        return NGX_CONF_ERROR;
    }
    conf->tls_ctx->ctx = ctx;

    ca_is_dir = (stat(ca_raw, &stbuf) == 0 && S_ISDIR(stbuf.st_mode)); /* vfs-seam-allow: trust-anchor path (CApath dir vs CAfile bundle), not export storage */

    conf->ca_store = brix_build_ca_store_cached(cf->cycle, cf->log,
        ca_is_dir ? ca_raw : NULL,          /* CApath (hashed dir) */
        ca_is_dir ? NULL : ca_raw,          /* or CAfile bundle    */
        NULL,                                /* no CRL for the POC  */
        X509_V_FLAG_ALLOW_PROXY_CERTS,       /* RFC 3820 proxies    */
        NULL, BRIX_SP_MODE_OFF, BRIX_CRL_MODE_OFF);
    if (conf->ca_store == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_gridftp_gsi: cannot build CA trust store from %s", ca_raw);
        return NGX_CONF_ERROR;
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "brix: GridFTP gsiftp security enabled (cert=%V ca=%s)",
        &conf->certificate, ca_raw);
    return NGX_CONF_OK;
}

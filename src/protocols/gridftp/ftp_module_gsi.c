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
    ngx_pool_cleanup_t  *cln;

    if (conf->certificate.len == 0 || conf->certificate_key.len == 0
        || conf->trusted_ca.len == 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_gridftp_gsi requires brix_gridftp_certificate, "
            "brix_gridftp_certificate_key and brix_gridftp_trusted_ca");
        return NGX_CONF_ERROR;
    }
    if (conf->certificate.len >= sizeof(cert_raw)
        || conf->certificate_key.len >= sizeof(key_raw))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_gridftp_gsi certificate/key path too long");
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(cert_raw, conf->certificate.data, conf->certificate.len);
    cert_raw[conf->certificate.len] = '\0';
    ngx_memcpy(key_raw, conf->certificate_key.data, conf->certificate_key.len);
    key_raw[conf->certificate_key.len] = '\0';

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
    ctx = SSL_CTX_new(TLS_method());
    if (ctx == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_gridftp_gsi: SSL_CTX_new failed");
        return NGX_CONF_ERROR;
    }
    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        SSL_CTX_free(ctx);
        return NGX_CONF_ERROR;
    }
    cln->handler = brix_ftp_ssl_ctx_cleanup;
    cln->data = ctx;

    /* TLS 1.2 only: the GSI ADAT flow depends on the 1.2 flight shape (the
     * mem-BIO engine also pins this per-connection). */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);

    if (SSL_CTX_use_certificate_chain_file(ctx, cert_raw) != 1
        || SSL_CTX_use_PrivateKey_file(ctx, key_raw, SSL_FILETYPE_PEM) != 1
        || SSL_CTX_check_private_key(ctx) != 1)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_gridftp_gsi: cannot load host cert %s / key %s",
            cert_raw, key_raw);
        return NGX_CONF_ERROR;
    }
    conf->tls_ctx->ctx = ctx;

    if (conf->trusted_ca.len >= sizeof(ca_raw)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_gridftp_trusted_ca path too long");
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(ca_raw, conf->trusted_ca.data, conf->trusted_ca.len);
    ca_raw[conf->trusted_ca.len] = '\0';
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

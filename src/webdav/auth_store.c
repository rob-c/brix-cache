/*
 * auth_store.c - CA and CRL store construction for WebDAV x509 auth.
 */

#include "webdav.h"
#include "../crypto/pki_build.h"

#include <limits.h>

/*
 * webdav_build_ca_store — build an X509_STORE from WebDAV loc_conf paths.
 *
 * Converts the ngx_str_t config fields (cadir, cafile, crl) to NUL-terminated
 * C strings and delegates to xrootd_build_ca_store().  No ALLOW_PROXY_CERTS —
 * WebDAV x509 auth does not accept GSI proxy certificate chains.
 */
X509_STORE *
webdav_build_ca_store(ngx_log_t *log,
                      ngx_http_xrootd_webdav_loc_conf_t *conf,
                      int *crl_count_out)
{
    char        cadir_buf[PATH_MAX];
    char        cafile_buf[PATH_MAX];
    char        crl_buf[PATH_MAX];
    const char *cadir  = NULL;
    const char *cafile = NULL;
    const char *crl    = NULL;

    if (conf->cadir.len > 0) {
        if (conf->cadir.len >= sizeof(cadir_buf)) {
            return NULL;
        }
        ngx_memcpy(cadir_buf, conf->cadir.data, conf->cadir.len);
        cadir_buf[conf->cadir.len] = '\0';
        cadir = cadir_buf;
    }

    if (conf->cafile.len > 0) {
        if (conf->cafile.len >= sizeof(cafile_buf)) {
            return NULL;
        }
        ngx_memcpy(cafile_buf, conf->cafile.data, conf->cafile.len);
        cafile_buf[conf->cafile.len] = '\0';
        cafile = cafile_buf;
    }

    if (conf->crl.len > 0) {
        if (conf->crl.len >= sizeof(crl_buf)) {
            return NULL;
        }
        ngx_memcpy(crl_buf, conf->crl.data, conf->crl.len);
        crl_buf[conf->crl.len] = '\0';
        crl = crl_buf;
    }

    return xrootd_build_ca_store(log, cadir, cafile, crl, 0, crl_count_out);
}

/*
 * auth_store.c - CA and CRL store construction for WebDAV x509 auth.
 */

#include "webdav.h"
#include "auth/crypto/pki_build.h"
#include "core/compat/cstr.h"

#include <limits.h>

/*
 * webdav_build_ca_store — build an X509_STORE from WebDAV loc_conf paths.
 *
 * Converts the ngx_str_t config fields (cadir, cafile, crl) to NUL-terminated
 * C strings and delegates to brix_build_ca_store().  No ALLOW_PROXY_CERTS —
 * WebDAV x509 auth does not accept GSI proxy certificate chains.
 */
X509_STORE *
webdav_build_ca_store(ngx_log_t *log,
                      ngx_http_brix_webdav_loc_conf_t *conf,
                      int *crl_count_out)
{
    char        cadir_buf[PATH_MAX];
    char        cafile_buf[PATH_MAX];
    char        crl_buf[PATH_MAX];
    const char *cadir  = NULL;
    const char *cafile = NULL;
    const char *crl    = NULL;

    if (conf->cadir.len > 0) {
        if (brix_str_cbuf(cadir_buf, sizeof(cadir_buf), &conf->cadir) == NULL) {
            return NULL;
        }
        cadir = cadir_buf;
    }

    if (conf->cafile.len > 0) {
        if (brix_str_cbuf(cafile_buf, sizeof(cafile_buf), &conf->cafile)
            == NULL)
        {
            return NULL;
        }
        cafile = cafile_buf;
    }

    if (conf->crl.len > 0) {
        if (brix_str_cbuf(crl_buf, sizeof(crl_buf), &conf->crl) == NULL) {
            return NULL;
        }
        crl = crl_buf;
    }

    return brix_build_ca_store(log, cadir, cafile, crl, 0, crl_count_out,
                               (brix_sp_mode_t) conf->signing_policy_mode,
                               (int) conf->crl_mode);
}

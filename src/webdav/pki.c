#include "webdav.h"
#include "../crypto/pki_check.h"

/*
 * WebDAV module-specific PKI/CRL consistency checks.
 */

ngx_int_t
webdav_check_pki_consistency(ngx_log_t *log,
    ngx_http_xrootd_webdav_loc_conf_t *conf)
{
    const char         *ca_path = NULL;
    const char         *crl_path;

    if (conf->cafile.len > 0) {
        ca_path = (char *) conf->cafile.data;

    } else if (conf->cadir.len > 0) {
        ca_path = (char *) conf->cadir.data;
    }

    crl_path = (conf->crl.len > 0) ? (char *) conf->crl.data : NULL;

    return xrootd_pki_check_paths(log, ca_path, crl_path, "xrootd_webdav");
}

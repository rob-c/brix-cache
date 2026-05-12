#include "../ngx_xrootd_module.h"
#include "../crypto/pki_check.h"

/*
 * Stream module-specific PKI/CRL consistency checks.
 */

ngx_int_t
xrootd_check_pki_consistency_stream(ngx_log_t *log,
    ngx_stream_xrootd_srv_conf_t *xcf)
{
    const char         *ca_path;
    const char         *crl_path;

    ca_path = (xcf->trusted_ca.len > 0) ? (char *) xcf->trusted_ca.data : NULL;
    crl_path = (xcf->crl.len > 0) ? (char *) xcf->crl.data : NULL;

    return xrootd_pki_check_paths(log, ca_path, crl_path, "xrootd");
}

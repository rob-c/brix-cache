#include "core/ngx_xrootd_module.h"
#include "auth/crypto/pki_check.h"

/*
 *
 * WHAT: Performs PKI/CRL consistency validation for the stream module (native XRootD protocol). Reads
 *       the configured trusted CA path and CRL path from stream configuration, then delegates to
 *       xrootd_pki_check_paths() which loads certificates, verifies cross-signatures between CA certs
 *       and CRLs, and logs any mismatches as warnings. Returns NGX_OK regardless of issues found —
 *       the server starts even with broken CRL so operators can fix it without downtime.
 *
 * WHY: The stream module needs its own PKI consistency check function because nginx configuration uses
 *       separate structure types (ngx_stream_xrootd_srv_conf_t vs ngx_http_xrootd_webdav_loc_conf_t) for
 *       stream and HTTP modules. This wrapper extracts the correct fields from the stream config and
 *       calls the shared crypto/pki_check.c implementation without requiring module-specific logic. */
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

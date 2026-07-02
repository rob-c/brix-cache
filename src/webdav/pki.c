#include "webdav.h"
#include "auth/crypto/pki_check.h"

/*
 * pki.c - WebDAV module-specific PKI/CRL consistency checks.
 *
 * WHAT: Validate CA certificate file/directory and CRL path configuration at postconfiguration time — ensures PKI infrastructure is correct before nginx accepts any traffic. Called during `nginx -t` validation phase to prevent deployment with missing or misconfigured certificates.
 *
 * WHY: WebDAV GSI/x509 proxy certificate authentication requires valid CA trust chain. Missing CA file/directory causes runtime auth failures for all clients — rejecting traffic silently instead of failing at startup prevents silent degradation in production deployments. CRL (Certificate Revocation List) validation ensures revoked certificates are rejected immediately rather than being accepted until the next restart cycle. Per AGENTS.md INVARIANT: config validation must cause `nginx -t` to fail with explicit `emerg` errors before any traffic is accepted.
 *
 * HOW: Select CA source from conf->cafile (single file path) or conf->cadir (directory containing multiple certificates). Extract CRL path from conf->crl if configured, otherwise pass NULL for no CRL requirement. Delegate validation to xrootd_pki_check_paths() helper from ../crypto/pki_check.h — this is the centralized PKI check utility that validates file existence, format correctness, and OpenSSL store loadability. Returns NGX_OK on valid configuration or NGX_ERROR with log error message when paths are missing/invalid.
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

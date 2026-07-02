#ifndef XROOTD_VOMS_HTTP_H
#define XROOTD_VOMS_HTTP_H

/*
 * voms_http.h — lightweight VOMS extraction declaration for HTTP handlers.
 *
 * WHAT: Declares xrootd_extract_voms_info() without pulling in the full
 *       stream-module umbrella header (ngx_xrootd_module.h), which drags in
 *       ngx_stream.h and stream-specific types incompatible with HTTP modules.
 *
 * WHY: WebDAV auth_cert.c needs to call VOMS extraction after X.509 proxy
 *      chain verification, but including ngx_xrootd_module.h from HTTP code
 *      causes type redefinition conflicts with nginx's HTTP layer.
 *
 * HOW: This thin header re-declares only xrootd_extract_voms_info() using
 *      types already available in every HTTP module (ngx_core.h + OpenSSL).
 *      The implementation lives in src/voms/extract.c, which is compiled into
 *      NGX_ADDON_SRCS and linked into the module regardless of which header
 *      declares the prototype.
 *
 * Usage:
 *   - Include this header in HTTP handler code that calls VOMS extraction.
 *   - Do NOT include ngx_xrootd_module.h alongside this header — they both
 *     declare xrootd_extract_voms_info() and will conflict.
 */

#include <ngx_core.h>
#include <openssl/x509.h>

/*
 * xrootd_extract_voms_info — extract VOMS VO/FQAN attributes from an X.509
 * proxy certificate after the GSI chain has been verified.
 *
 * Parameters:
 *   log           nginx log for warning/error messages
 *   leaf          the end-entity (leaf) certificate of the proxy chain
 *   chain         the full certificate chain (may include leaf as first entry)
 *   vomsdir       VOMS server certificate directory (e.g. /etc/grid-security/vomsdir)
 *   cert_dir      trusted CA certificate directory  (e.g. /etc/grid-security/certificates)
 *   primary_vo    output buffer — filled with the first VO name found
 *   primary_vo_sz size of primary_vo buffer in bytes
 *   vo_list       output buffer — filled with comma-separated list of all VOs
 *   vo_list_sz    size of vo_list buffer in bytes
 *
 * Returns:
 *   NGX_OK       — at least one VOMS VO/FQAN was extracted
 *   NGX_DECLINED — no VOMS extensions found (cert has no VO attributes)
 *   NGX_ERROR    — VOMS library error or invalid parameters
 */
ngx_int_t xrootd_extract_voms_info(ngx_log_t *log, X509 *leaf,
    STACK_OF(X509) *chain, const ngx_str_t *vomsdir, const ngx_str_t *cert_dir,
    char *primary_vo, size_t primary_vo_sz,
    char *vo_list, size_t vo_list_sz);

#endif /* XROOTD_VOMS_HTTP_H */

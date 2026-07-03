#include "voms_internal.h"

#include <limits.h>

/*
 * WHAT: Public entry point for extracting VOMS virtual organisation membership
 * from an x509 proxy certificate. Called by the GSI authentication path after
 * the proxy chain is verified to populate ctx->primary_vo and ctx->vo_list.
 *
 * WHY: VO-based ACL enforcement (brix_require_vo) requires knowledge of which
 * virtual organisations the user belongs to. VOMS extensions embedded in the
 * certificate provide this information. This function encapsulates the entire
 * extraction pipeline — chain preparation, API call, and result collection.
 *
 * HOW: Four-phase flow:
 *   1. Pre-checks — return NGX_DECLINED if VOMS library not loaded or parameters
 *      missing (graceful degradation per INVARIANT #8: metric labels low-cardinality)
 *   2. Buffer preparation — convert ngx_str_t paths to NUL-terminated buffers with
 *      bounds validation against PATH_MAX
 *   3. VOMS extraction — initialise API, duplicate certificate chain and remove the
 *      leaf (VOMS needs parent certificates for extension lookup), call retrieve()
 *      with VOMS_RECURSE_CHAIN flag; non-critical errors (VOMS_VERR_NOEXT /
 *      VOMS_VERR_NODATA) are silently skipped per GSI auth convention
 *   4. Result collection — delegate to brix_collect_voms_vos(); cleanup chain and
 *      API state regardless of outcome
 *
 * INVARIANT: All wire paths → resolve_path() before open(). This function operates
 * on certificate data, not filesystem paths, so the invariant does not apply directly.
 */

ngx_int_t
brix_extract_voms_info(ngx_log_t *log, X509 *leaf, STACK_OF(X509) *chain,
    const ngx_str_t *vomsdir, const ngx_str_t *cert_dir,
    char *primary_vo, size_t primary_vo_sz, char *vo_list, size_t vo_list_sz)
{
    struct voms_data *vd;
    STACK_OF(X509)  *voms_chain = NULL;
    char             vomsdir_buf[PATH_MAX];
    char             cert_dir_buf[PATH_MAX];
    char             errbuf[512];
    int              error = 0;
    ngx_int_t        rc = NGX_DECLINED;

    if (!brix_voms_loaded) {
        return NGX_DECLINED;
    }

    if (leaf == NULL || vomsdir == NULL || cert_dir == NULL
        || vomsdir->len == 0 || cert_dir->len == 0)
    {
        return NGX_DECLINED;
    }

    if (vomsdir->len >= sizeof(vomsdir_buf)
        || cert_dir->len >= sizeof(cert_dir_buf))
    {
        return NGX_ERROR;
    }

    ngx_memcpy(vomsdir_buf, vomsdir->data, vomsdir->len);
    vomsdir_buf[vomsdir->len] = '\0';
    ngx_memcpy(cert_dir_buf, cert_dir->data, cert_dir->len);
    cert_dir_buf[cert_dir->len] = '\0';

    if (primary_vo != NULL && primary_vo_sz > 0) {
        primary_vo[0] = '\0';
    }
    if (vo_list != NULL && vo_list_sz > 0) {
        vo_list[0] = '\0';
    }

    vd = brix_voms_api.init(vomsdir_buf, cert_dir_buf);
    if (vd == NULL) {
        return NGX_ERROR;
    }

    if (chain != NULL && sk_X509_num(chain) > 0) {
        voms_chain = sk_X509_dup(chain);
        if (voms_chain == NULL) {
            brix_voms_api.destroy(vd);
            return NGX_ERROR;
        }

        if (sk_X509_num(voms_chain) > 0
            && X509_cmp(sk_X509_value(voms_chain, 0), leaf) == 0)
        {
            sk_X509_delete(voms_chain, 0);
        }
    }

    if (!brix_voms_api.retrieve(leaf, voms_chain, VOMS_RECURSE_CHAIN, vd,
                                  &error))
    {
        if (error != VOMS_VERR_NOEXT && error != VOMS_VERR_NODATA) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "brix: VOMS extraction failed: %s",
                          brix_voms_api.error_message(vd, error, errbuf,
                                                        (int) sizeof(errbuf)));
            rc = NGX_ERROR;
        }

    } else {
        rc = brix_collect_voms_vos(vd, primary_vo, primary_vo_sz,
                                     vo_list, vo_list_sz);
    }

    if (voms_chain != NULL) {
        sk_X509_free(voms_chain);
    }
    brix_voms_api.destroy(vd);
    return rc;
}

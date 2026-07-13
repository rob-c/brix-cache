#include "voms_internal.h"

#include <limits.h>

/*
 * WHAT: Caller-owned output destinations for extracted VO membership — the
 * primary VO name and the comma-separated VO/FQAN list, each with its buffer
 * size.
 *
 * WHY: Bundling the four output parameters into one struct keeps the internal
 * helpers within the ≤5-parameter limit without changing the frozen public
 * signature of brix_extract_voms_info().
 *
 * HOW: Populated once in the entry point from its parameters and passed by
 * pointer to the reset and retrieve/collect helpers.
 */
typedef struct {
    char   *primary_vo;
    size_t  primary_vo_sz;
    char   *vo_list;
    size_t  vo_list_sz;
} brix_voms_out_t;

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

/*
 * WHAT: Validate that VOMS extraction can proceed and that the caller-supplied
 * directory paths fit their fixed on-stack buffers.
 *
 * WHY: Splits the pre-flight guard ladder out of the main entry point so the
 * latter stays under the complexity cap. Preserves the original two-tier
 * disposition exactly: unavailable/missing inputs degrade gracefully
 * (NGX_DECLINED) while over-length paths are a hard error (NGX_ERROR).
 *
 * HOW: Mirror the original guard order — VOMS library loaded, mandatory
 * non-empty inputs present, then path lengths bounded below the destination
 * buffer size. Returns NGX_OK when extraction may continue.
 */
static ngx_int_t
brix_voms_precheck(X509 *leaf, const ngx_str_t *vomsdir,
    const ngx_str_t *cert_dir, size_t buf_sz)
{
    if (!brix_voms_loaded) {
        return NGX_DECLINED;
    }

    if (leaf == NULL || vomsdir == NULL || cert_dir == NULL
        || vomsdir->len == 0 || cert_dir->len == 0)
    {
        return NGX_DECLINED;
    }

    if (vomsdir->len >= buf_sz || cert_dir->len >= buf_sz) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * WHAT: Copy an ngx_str_t path into a NUL-terminated on-stack buffer.
 *
 * WHY: The VOMS init() API takes C strings; ngx_str_t is not NUL-terminated.
 * Factored out to avoid duplicating the copy-and-terminate idiom per path.
 *
 * HOW: Bounds have already been validated by brix_voms_precheck(); copy the
 * bytes and append the terminator.
 */
static void
brix_voms_path_to_buf(const ngx_str_t *src, char *dst)
{
    ngx_memcpy(dst, src->data, src->len);
    dst[src->len] = '\0';
}

/*
 * WHAT: Reset the caller's primary-VO and VO-list output buffers to empty.
 *
 * WHY: Callers expect well-defined (empty) output even when no VOMS data is
 * found. Keeping this together documents the output contract in one place.
 *
 * HOW: Terminate each buffer at offset 0 when present and non-zero-sized.
 */
static void
brix_voms_reset_outputs(const brix_voms_out_t *out)
{
    if (out->primary_vo != NULL && out->primary_vo_sz > 0) {
        out->primary_vo[0] = '\0';
    }
    if (out->vo_list != NULL && out->vo_list_sz > 0) {
        out->vo_list[0] = '\0';
    }
}

/*
 * WHAT: Duplicate the verified certificate chain and drop the leaf, producing
 * the parent-only stack that the VOMS retrieve() call expects.
 *
 * WHY: VOMS looks up the AC extension in the parent certificates, so the leaf
 * (index 0, matching *leaf) must be removed. Isolating this keeps the pointer
 * juggling and its NULL/empty edge cases out of the main flow.
 *
 * HOW: For a non-empty chain, sk_X509_dup() the stack; on allocation failure
 * signal via *ok = 0 (caller must clean up the API handle). If the duplicated
 * head equals the leaf, delete it. A NULL/empty input yields a NULL chain,
 * which is valid input to retrieve(). Sets *ok = 1 on success.
 */
static STACK_OF(X509) *
brix_voms_build_parent_chain(STACK_OF(X509) *chain, X509 *leaf, int *ok)
{
    STACK_OF(X509) *voms_chain = NULL;

    *ok = 1;

    if (chain == NULL || sk_X509_num(chain) <= 0) {
        return NULL;
    }

    voms_chain = sk_X509_dup(chain);
    if (voms_chain == NULL) {
        *ok = 0;
        return NULL;
    }

    if (sk_X509_num(voms_chain) > 0
        && X509_cmp(sk_X509_value(voms_chain, 0), leaf) == 0)
    {
        sk_X509_delete(voms_chain, 0);
    }

    return voms_chain;
}

/*
 * WHAT: Perform the VOMS retrieve() call and, on success, collect the VO/FQAN
 * results into the caller's buffers.
 *
 * WHY: Concentrates the retrieve/error/collect decision in one helper so the
 * entry point reads as a linear pipeline. Preserves the original disposition:
 * VOMS_VERR_NOEXT / VOMS_VERR_NODATA are silently ignored (NGX_DECLINED per
 * initial rc); other retrieve failures WARN-log and return NGX_ERROR.
 *
 * HOW: Call retrieve() with VOMS_RECURSE_CHAIN. On failure, classify the error;
 * on success, delegate to brix_collect_voms_vos(). Uses a local error buffer for
 * the human-readable message.
 */
static ngx_int_t
brix_voms_retrieve_and_collect(ngx_log_t *log, X509 *leaf,
    STACK_OF(X509) *voms_chain, struct voms_data *vd,
    const brix_voms_out_t *out)
{
    char      errbuf[512];
    int       error = 0;

    if (!brix_voms_api.retrieve(leaf, voms_chain, VOMS_RECURSE_CHAIN, vd,
                                  &error))
    {
        if (error != VOMS_VERR_NOEXT && error != VOMS_VERR_NODATA) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "brix: VOMS extraction failed: %s",
                          brix_voms_api.error_message(vd, error, errbuf,
                                                        (int) sizeof(errbuf)));
            return NGX_ERROR;
        }

        return NGX_DECLINED;
    }

    return brix_collect_voms_vos(vd, out->primary_vo, out->primary_vo_sz,
                                   out->vo_list, out->vo_list_sz);
}

ngx_int_t
brix_extract_voms_info(ngx_log_t *log, X509 *leaf, STACK_OF(X509) *chain,
    const ngx_str_t *vomsdir, const ngx_str_t *cert_dir,
    char *primary_vo, size_t primary_vo_sz, char *vo_list, size_t vo_list_sz)
{
    struct voms_data *vd;
    STACK_OF(X509)  *voms_chain = NULL;
    char             vomsdir_buf[PATH_MAX];
    char             cert_dir_buf[PATH_MAX];
    int              chain_ok = 0;
    ngx_int_t        rc;
    brix_voms_out_t  out;

    out.primary_vo = primary_vo;
    out.primary_vo_sz = primary_vo_sz;
    out.vo_list = vo_list;
    out.vo_list_sz = vo_list_sz;

    rc = brix_voms_precheck(leaf, vomsdir, cert_dir, sizeof(vomsdir_buf));
    if (rc != NGX_OK) {
        return rc;
    }

    brix_voms_path_to_buf(vomsdir, vomsdir_buf);
    brix_voms_path_to_buf(cert_dir, cert_dir_buf);
    brix_voms_reset_outputs(&out);

    vd = brix_voms_api.init(vomsdir_buf, cert_dir_buf);
    if (vd == NULL) {
        return NGX_ERROR;
    }

    voms_chain = brix_voms_build_parent_chain(chain, leaf, &chain_ok);
    if (!chain_ok) {
        brix_voms_api.destroy(vd);
        return NGX_ERROR;
    }

    rc = brix_voms_retrieve_and_collect(log, leaf, voms_chain, vd, &out);

    if (voms_chain != NULL) {
        sk_X509_free(voms_chain);
    }
    brix_voms_api.destroy(vd);
    return rc;
}

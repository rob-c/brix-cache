#include "voms_internal.h"
#include <limits.h>

/*
 * extract.c — VO / FQAN extraction from a verified proxy chain
 *
 * WHAT: brix_extract_voms_fqans (the full form) and brix_extract_voms_info
 *       (VO views only), declared in ngx_brix_module.h and voms_http.h.
 * WHY:  Every GSI path (root://, davs://, gsiftp://, cvmfs) fills the
 *       connection identity's VO and FQAN views from here after the proxy
 *       chain has been verified; VO-scoped authorization (brix_require_vo,
 *       the authdb selectors) reads those views.
 * HOW:  brix_voms_retrieve over the shared native engine with the module's
 *       trust: the VOMS server chain against the brix_voms_cert_dir store and
 *       the configured brix_vomsdir LSC files. Only entries whose verdict is
 *       BRIX_VOMS_OK reach the views. A proxy without the extension yields
 *       NGX_DECLINED (a plain grid proxy); an extension that fails
 *       verification is logged at WARN and yields NGX_ERROR with empty views.
 */

static ngx_int_t
brix_voms_precheck(const brix_voms_in_t *in, const ngx_str_t *vomsdir,
    const ngx_str_t *cert_dir)
{
    if (in == NULL || in->leaf == NULL || vomsdir == NULL || cert_dir == NULL
        || vomsdir->len == 0 || cert_dir->len == 0)
    {
        return NGX_DECLINED;
    }
    if (vomsdir->len >= PATH_MAX || cert_dir->len >= PATH_MAX) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

static void
brix_voms_reset_outputs(const brix_voms_out_t *out)
{
    if (out->primary_vo != NULL && out->primary_vo_sz > 0) {
        out->primary_vo[0] = '\0';
    }
    if (out->vo_list != NULL && out->vo_list_sz > 0) {
        out->vo_list[0] = '\0';
    }
    if (out->fqan_list != NULL && out->fqan_list_sz > 0) {
        out->fqan_list[0] = '\0';
    }
}

/* One WARN line per rejected AC: the VO it claimed and why it was refused,
 * with the AC's own strings sanitised before they reach the log. */
static void
brix_voms_log_rejections(ngx_log_t *log, const brix_voms_result_t *res)
{
    int  i;
    char vo[64];

    for (i = 0; i < res->n; i++) {
        const brix_voms_entry_t *e = &res->entries[i];

        if (e->verdict == BRIX_VOMS_OK) {
            continue;
        }
        brix_sanitize_log_string(e->vo, vo, sizeof(vo));
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix: VOMS attribute certificate for VO \"%s\" rejected: %s",
                      vo, brix_voms_strerror(e->verdict));
    }
}

ngx_int_t
brix_extract_voms_fqans(ngx_log_t *log, const brix_voms_in_t *in,
    const ngx_str_t *vomsdir, const ngx_str_t *cert_dir,
    const brix_voms_out_t *out)
{
    brix_voms_trust_t   trust;
    brix_voms_result_t *res = NULL;
    brix_voms_status_t  status;
    char                vomsdir_buf[PATH_MAX];
    ngx_int_t           rc;

    rc = brix_voms_precheck(in, vomsdir, cert_dir);
    if (rc != NGX_OK) {
        return rc;
    }
    brix_voms_reset_outputs(out);
    ngx_memcpy(vomsdir_buf, vomsdir->data, vomsdir->len);
    vomsdir_buf[vomsdir->len] = '\0';

    trust.store = brix_voms_trust_store(log, cert_dir);
    if (trust.store == NULL) {
        return NGX_ERROR;   /* fail closed: no CA directory, no VO */
    }
    trust.vomsdir = vomsdir_buf;
    trust.now = 0;
    trust.skew_seconds = BRIX_VOMS_SKEW_SECONDS;

    status = brix_voms_retrieve(in->leaf, in->chain, &trust, &res);
    X509_STORE_free(trust.store);
    if (status == BRIX_VOMS_ERR_NOEXT) {
        return NGX_DECLINED;   /* a plain grid proxy */
    }
    if (res == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix: VOMS extension rejected: %s", brix_voms_strerror(status));
        return NGX_ERROR;
    }
    brix_voms_log_rejections(log, res);
    rc = (status == BRIX_VOMS_OK) ? brix_collect_voms_vos(res, out) : NGX_ERROR;
    brix_voms_result_free(res);
    return rc;
}

ngx_int_t
brix_extract_voms_info(ngx_log_t *log, X509 *leaf, STACK_OF(X509) *chain,
    const ngx_str_t *vomsdir, const ngx_str_t *cert_dir,
    char *primary_vo, size_t primary_vo_sz, char *vo_list, size_t vo_list_sz)
{
    brix_voms_in_t   in;
    brix_voms_out_t  out;

    in.leaf = leaf;
    in.chain = chain;
    ngx_memzero(&out, sizeof(out));
    out.primary_vo = primary_vo;
    out.primary_vo_sz = primary_vo_sz;
    out.vo_list = vo_list;
    out.vo_list_sz = vo_list_sz;
    return brix_extract_voms_fqans(log, &in, vomsdir, cert_dir, &out);
}

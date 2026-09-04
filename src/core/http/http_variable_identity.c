/* Identity and configured-origin handlers for the HTTP `$brix_*` surface. */
#include "core/http/http_variables_internal.h"

#include "fs/backend/sd.h"
#include "observability/metrics/unified.h"
#include "protocols/s3/s3.h"
#include "protocols/webdav/webdav.h"

extern ngx_module_t ngx_http_brix_webdav_module;
extern ngx_module_t ngx_http_brix_s3_module;

/*
 * brix_request_identity — the verified identity of this request, or NULL.
 *
 * There is no shared per-request identity record (phase-106 W1 as-built note):
 * each protocol keeps its own request ctx, so this probes them the same way
 * $brix_protocol probes loc confs. cvmfs/oci/rpm carry no brix_identity_t —
 * their planes are anonymous-or-token-subject-only — and report NULL here.
 */
brix_identity_t *
brix_request_identity(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_req_ctx_t *wctx;
    ngx_http_s3_req_ctx_t            *sctx;

    wctx = ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    if (wctx != NULL && wctx->identity != NULL) {
        return wctx->identity;
    }
    sctx = ngx_http_get_module_ctx(r, ngx_http_brix_s3_module);
    if (sctx != NULL && sctx->identity != NULL) {
        return sctx->identity;
    }
    return NULL;
}


/*
 * brix_var_set_str — publish an ngx_str_t owned by the request pool.
 *
 * No copy: identity strings are pool-allocated for the request and the pool
 * outlives the log phase. An empty value reports the sentinel so "no VO" and
 * "VO named the empty string" cannot be conflated in a log field.
 */
static ngx_int_t
brix_var_set_str(ngx_http_variable_value_t *v, const ngx_str_t *val)
{
    if (val == NULL || val->len == 0) {
        return brix_var_set_static(v, "-", 0);
    }
    v->len = (unsigned) val->len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = val->data;
    return NGX_OK;
}


/* Field selector for the identity-shaped variables (one handler per SHAPE —
 * six copies of fetch/NULL-check/read is the cloned-logic shape the
 * duplication guard rejects). */


static const ngx_str_t *
brix_identity_field(brix_identity_t *id, brix_http_idvar_e which)
{
    ngx_str_t *first;

    switch (which) {
    case BRIX_HV_DN:     return &id->dn;
    case BRIX_HV_VO:     return &id->vo_csv;
    case BRIX_HV_SUB:    return &id->subject;
    case BRIX_HV_ISSUER: return &id->issuer;
    case BRIX_HV_FQAN:
        /* The PRIMARY FQAN — the first entry of the verified list, matching
         * the VOMS convention that the first FQAN is the operative one. The
         * full list is $brix_vo. */
        if (id->vo_list == NULL || id->vo_list->nelts == 0) {
            return NULL;
        }
        first = id->vo_list->elts;
        return &first[0];
    }
    return NULL;
}


/* $brix_dn / $brix_vo / $brix_fqan / $brix_token_sub / $brix_token_issuer. */
ngx_int_t
brix_var_identity_str(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    brix_identity_t *id = brix_request_identity(r);

    if (id == NULL) {
        return brix_var_set_static(v, "-", 0);
    }
    return brix_var_set_str(v, brix_identity_field(id, (brix_http_idvar_e) data));
}


/*
 * $brix_auth_method — how the request authenticated, in the SAME vocabulary
 * as the Prometheus auth label and the JSON access log
 * (brix_metric_auth_method_name), so one parsing rule serves all three.
 */
ngx_int_t
brix_var_auth_method(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    brix_identity_t *id = brix_request_identity(r);

    (void) data;
    if (id == NULL) {
        return brix_var_set_static(v, "-", 0);
    }
    return brix_var_set_static(v,
        brix_metric_auth_method_name(id->auth_method), 0);
}


/*
 * brix_request_shared_conf — the active brix plane's shared preamble, found
 * the same way $brix_protocol finds its label: probe each protocol's loc conf
 * for the enabled one. Only webdav and s3 embed the preamble.
 */
ngx_http_brix_shared_conf_t *
brix_request_shared_conf(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *wdcf;
    ngx_http_s3_loc_conf_t            *scf;

    wdcf = ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    if (wdcf != NULL && wdcf->common.enable) {
        return &wdcf->common;
    }
    scf = ngx_http_get_module_loc_conf(r, ngx_http_brix_s3_module);
    if (scf != NULL && scf->common.enable) {
        return &scf->common;
    }
    return NULL;
}


/* $brix_tier — the storage-driver family serving this location ("posix",
 * "s3", "http", "xroot", ...): the resolved instance's own name, so config
 * sugar and the tier grammar cannot make the label drift from what runs. */
ngx_int_t
brix_var_tier(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_brix_shared_conf_t *common = brix_request_shared_conf(r);

    (void) data;
    if (common == NULL) {
        return brix_var_set_static(v, "-", 0);
    }
    if (common->storage_instance != NULL) {
        return brix_var_set_static(v,
            brix_sd_backend_name(common->storage_instance), 0);
    }
    /* NULL instance = the default POSIX backend (vfs.h contract). */
    return brix_var_set_static(v, "posix", 0);
}


/*
 * $brix_origin — the configured origin, with any userinfo stripped.
 *
 * SECURITY: a remote storage_backend URL may carry user:pass@ userinfo, and a
 * variable is loggable — so everything up to and including a '@' in the
 * authority is removed before publishing. Never the raw config string.
 */
ngx_int_t
brix_var_origin(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_brix_shared_conf_t *common = brix_request_shared_conf(r);
    ngx_str_t                      shown;
    u_char                        *at, *end, *slash;

    (void) data;
    if (common == NULL || common->storage_backend.len == 0) {
        return brix_var_set_static(v, "-", 0);
    }

    shown = common->storage_backend;
    end = shown.data + shown.len;
    /* Userinfo can only appear before the first path slash after "//". */
    slash = ngx_strlchr(shown.data, end, '/');
    while (slash != NULL && slash + 1 < end && slash[1] == '/') {
        slash = ngx_strlchr(slash + 2, end, '/');
        break;
    }
    at = ngx_strlchr(shown.data, slash != NULL ? slash : end, '@');
    if (at != NULL) {
        shown.len -= (size_t) (at + 1 - shown.data);
        shown.data = at + 1;
    }
    return brix_var_set_str(v, &shown);
}


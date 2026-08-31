/*
 * http_variables.c — registration and get_handlers for the $brix_* HTTP
 * variable surface (phase 106 W1).
 *
 * WHAT: brix_http_add_variables() registers every $brix_* variable the HTTP
 *       planes expose, and implements the handlers whose state is not owned by
 *       a single protocol.
 *
 * WHY:  See http_variables.h. Registration is owned by the COMMON module so
 *       one registration serves every HTTP protocol and the variable's
 *       existence does not depend on which protocol module happens to be
 *       loaded.
 *
 * HOW:  Handlers follow three rules, which apply to every variable added here
 *       (phase 106, "variable-handler trap"):
 *
 *         1. Never allocate from a pool that may already be gone. A handler
 *            can run in the log phase, so every value below is either a static
 *            string or memory owned by the request that outlives logging.
 *         2. Always tolerate a missing request ctx. A request may never have
 *            reached brix at all (rejected by `deny`, served by another
 *            module), in which case the handler reports "-" rather than
 *            dereferencing NULL. ngx_http_brix_cvmfs_ctx_t may legitimately be
 *            absent even inside a cvmfs location.
 *         3. State the cacheability. Anything derived from the connection or
 *            the matched location is per-request cacheable; anything derived
 *            from the data plane changes as the request proceeds and is marked
 *            NOCACHEABLE.
 *
 *       SECURITY: no variable here may expose credential material — a token,
 *       a macaroon, a private key, or a raw Authorization value. Variables are
 *       an exfiltration surface because an operator can log them or copy them
 *       into a proxied header. Identity variables expose the SUBJECT, never
 *       the credential that proved it. ($brix_delegated_cred, registered
 *       elsewhere, predates this rule and is the single reviewed exception.)
 */
#include "core/http/http_variables.h"
#include "core/http/http_headers.h"        /* brix_http_request_is_tls */

#include "protocols/cvmfs/cvmfs.h"         /* cvmfs request ctx: cache_status */
#include "protocols/webdav/webdav.h"       /* webdav req ctx: identity        */
#include "protocols/s3/s3.h"               /* s3 req ctx: identity            */
#include "protocols/oci/oci.h"             /* oci req ctx: disp               */
#include "protocols/rpm/rpm.h"             /* rpm req ctx: disp               */
#include "observability/metrics/unified.h" /* brix_metric_auth_method_name    */
#include "fs/backend/sd.h"                 /* brix_sd_backend_name            */

extern ngx_module_t ngx_http_brix_cvmfs_module;
extern ngx_module_t ngx_http_brix_webdav_module;
extern ngx_module_t ngx_http_brix_s3_module;
extern ngx_module_t ngx_http_brix_oci_module;
extern ngx_module_t ngx_http_brix_rpm_module;


const char *
brix_cache_status_name(brix_cache_status_e status)
{
    switch (status) {
    case BRIX_CACHE_STATUS_HIT:    return "HIT";
    case BRIX_CACHE_STATUS_MISS:   return "MISS";
    case BRIX_CACHE_STATUS_BYPASS: return "BYPASS";
    case BRIX_CACHE_STATUS_NEGHIT: return "NEGHIT";
    case BRIX_CACHE_STATUS_NONE:   break;
    }
    return "-";
}


/*
 * brix_var_set_static — hand nginx a constant string as a variable value.
 *
 * Every handler in this file resolves to a static string, so this is the one
 * place that fills the value struct. `no_cacheable` is the caller's decision
 * and is passed in rather than assumed.
 */
static ngx_int_t
brix_var_set_static(ngx_http_variable_value_t *v, const char *s,
    ngx_uint_t no_cacheable)
{
    v->len = (unsigned) ngx_strlen(s);
    v->valid = 1;
    v->no_cacheable = no_cacheable ? 1 : 0;
    v->not_found = 0;
    v->data = (u_char *) s;
    return NGX_OK;
}


/*
 * cvmfs_cache_status — translate the cvmfs plane's own disposition into the
 * shared vocabulary.
 *
 * The cvmfs plane tracked a cache disposition (T16, $cvmfs_cache) before the
 * shared surface existed, using its own spelling. Mapping here rather than
 * changing the cvmfs plane keeps $cvmfs_cache byte-identical for anyone
 * already logging it, while $brix_cache_status reports the shared vocabulary.
 * FILL is nginx's MISS: went to the origin and populated.
 */
static brix_cache_status_e
cvmfs_cache_status(ngx_uint_t cvmfs_status)
{
    switch (cvmfs_status) {
    case BRIX_CVMFS_CACHE_HIT:  return BRIX_CACHE_STATUS_HIT;
    case BRIX_CVMFS_CACHE_FILL: return BRIX_CACHE_STATUS_MISS;
    case BRIX_CVMFS_CACHE_NEG:  return BRIX_CACHE_STATUS_NEGHIT;
    default:                    return BRIX_CACHE_STATUS_NONE;
    }
}


/*
 * $brix_cache_status — HIT / MISS / BYPASS / NEGHIT / "-".
 *
 * Reports the cache disposition in nginx's own $upstream_cache_status
 * vocabulary so existing dashboards and log parsers work unchanged.
 *
 * Today only the cvmfs plane tracks a per-request disposition, so other planes
 * report "-" (no cache decision was reached). That is honest rather than
 * misleading: "-" cannot be mistaken for a MISS, so a hit-rate computed from
 * this variable is never silently wrong — it is simply empty for planes that
 * do not yet report. Extending a plane means giving it a disposition and
 * adding its arm here; the variable's name, vocabulary and log_format do not
 * change when that happens, which is the whole point of registering it now.
 *
 * NOCACHEABLE: the disposition is a data-plane outcome and is not known until
 * the request has been served.
 */
/*
 * oci_rpm_cache_status — the oci/rpm outcome enums share one layout
 * (hit/fill/local/refused/error) and one mapping: "local" is a HIT (served
 * from the local store with no origin contact); "refused"/"error" are not
 * cache dispositions at all and report the sentinel.
 */
static brix_cache_status_e
oci_rpm_cache_status(ngx_uint_t disp)
{
    switch (disp) {
    case 0: /* HIT   */ return BRIX_CACHE_STATUS_HIT;
    case 1: /* FILL  */ return BRIX_CACHE_STATUS_MISS;
    case 2: /* LOCAL */ return BRIX_CACHE_STATUS_HIT;
    default:            return BRIX_CACHE_STATUS_NONE;
    }
}


static brix_cache_status_e
brix_request_cache_status(ngx_http_request_t *r)
{
    ngx_http_brix_cvmfs_ctx_t *cctx;
    ngx_http_brix_oci_ctx_t   *octx;
    ngx_http_brix_rpm_ctx_t   *rctx;

    cctx = ngx_http_get_module_ctx(r, ngx_http_brix_cvmfs_module);
    if (cctx != NULL) {
        return cvmfs_cache_status(cctx->cache_status);
    }
    octx = ngx_http_get_module_ctx(r, ngx_http_brix_oci_module);
    if (octx != NULL) {
        return oci_rpm_cache_status((ngx_uint_t) octx->disp);
    }
    rctx = ngx_http_get_module_ctx(r, ngx_http_brix_rpm_module);
    if (rctx != NULL) {
        return oci_rpm_cache_status((ngx_uint_t) rctx->disp);
    }
    return BRIX_CACHE_STATUS_NONE;
}


static ngx_int_t
brix_var_cache_status(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    (void) data;
    return brix_var_set_static(v,
        brix_cache_status_name(brix_request_cache_status(r)), 1);
}


/*
 * $brix_tls — "on" when the request arrived over TLS, "off" otherwise.
 *
 * nginx's own $https covers the plain case, but brix serves planes where TLS
 * can be established by brix itself (the stream-side upgrade has no $https
 * equivalent), and a single spelling that means the same thing on every plane
 * is what lets one log_format serve them all.
 *
 * Per-request cacheable: a connection cannot change transport mid-request.
 */
static ngx_int_t
brix_var_tls(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    (void) data;
    return brix_var_set_static(v,
        brix_http_request_is_tls(r) ? "on" : "off", 0);
}


/*
 * brix_request_identity — the verified identity of this request, or NULL.
 *
 * There is no shared per-request identity record (phase-106 W1 as-built note):
 * each protocol keeps its own request ctx, so this probes them the same way
 * $brix_protocol probes loc confs. cvmfs/oci/rpm carry no brix_identity_t —
 * their planes are anonymous-or-token-subject-only — and report NULL here.
 */
static brix_identity_t *
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
typedef enum {
    BRIX_HV_DN = 0,
    BRIX_HV_VO,
    BRIX_HV_FQAN,
    BRIX_HV_SUB,
    BRIX_HV_ISSUER
} brix_http_idvar_e;


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
static ngx_int_t
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
static ngx_int_t
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
static ngx_http_brix_shared_conf_t *
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
static ngx_int_t
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
static ngx_int_t
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


static ngx_http_variable_t  brix_http_variables[] = {
    { ngx_string("brix_cache_status"), NULL, brix_var_cache_status,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("brix_tls"), NULL, brix_var_tls, 0, 0, 0 },
    { ngx_string("brix_dn"), NULL, brix_var_identity_str, BRIX_HV_DN, 0, 0 },
    { ngx_string("brix_vo"), NULL, brix_var_identity_str, BRIX_HV_VO, 0, 0 },
    { ngx_string("brix_fqan"), NULL, brix_var_identity_str,
      BRIX_HV_FQAN, 0, 0 },
    /* $brix_sub / $brix_issuer, not $brix_token_*: the values are the
     * verified subject/issuer whatever the auth method, and a token_-
     * prefixed name would need an R10 credential-denylist exception for a
     * value that is not credential material — better to keep the denylist
     * tight than to grow its allowlist. (Deviation from plan Appendix A,
     * recorded in the phase doc.) */
    { ngx_string("brix_sub"), NULL, brix_var_identity_str,
      BRIX_HV_SUB, 0, 0 },
    { ngx_string("brix_issuer"), NULL, brix_var_identity_str,
      BRIX_HV_ISSUER, 0, 0 },
    { ngx_string("brix_auth_method"), NULL, brix_var_auth_method, 0, 0, 0 },
    { ngx_string("brix_tier"), NULL, brix_var_tier, 0, 0, 0 },
    { ngx_string("brix_origin"), NULL, brix_var_origin, 0, 0, 0 },
      ngx_http_null_variable
};


ngx_int_t
brix_http_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t *v, *nv;

    for (v = brix_http_variables; v->name.len; v++) {
        nv = ngx_http_add_variable(cf, &v->name, v->flags);
        if (nv == NULL) {
            return NGX_ERROR;
        }
        nv->get_handler = v->get_handler;
        nv->data = v->data;
    }

    return NGX_OK;
}

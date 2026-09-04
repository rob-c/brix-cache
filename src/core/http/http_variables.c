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
#include "core/http/http_variables_internal.h"
#include "core/http/http_headers.h"        /* brix_http_request_is_tls */
#include "core/config/http_common.h"       /* ngx_http_brix_common_module (ctx home) */
#include "fs/vfs/vfs.h"                     /* brix_vfs_ctx_t (monitor bind)   */
#include "observability/metrics/io_monitor.h" /* brix_io_monitor_t            */

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


/*
 * brix_var_set_static — hand nginx a constant string as a variable value.
 *
 * Every handler in this file resolves to a static string, so this is the one
 * place that fills the value struct. `no_cacheable` is the caller's decision
 * and is passed in rather than assumed.
 */
ngx_int_t
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
 * The cvmfs plane tracked a cache disposition (T16) before the shared surface
 * existed, using its own spelling, and it keeps that spelling internally:
 * ctx->cache_status is read by cvmfs_var_origin() and the cvmfs metrics.
 * Mapping here rather than renaming the plane's enum keeps the translation in
 * ONE place, so a new disposition is one arm to add, not a plane-wide edit.
 * FILL is nginx's MISS: went to the origin and populated. (Phase 112 removed
 * the plane's own $cvmfs_cache variable; this is now the only reader.)
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
    brix_io_monitor_t          *m;

    /* phase-110 W1: the data planes (WebDAV/S3) record their disposition on
     * the request's I/O monitor at the VFS cache decision
     * (brix_vfs_observe_cache_result). First arm, so a cache-enabled export
     * answers HIT/MISS/BYPASS here; the plane-specific probes below stay for
     * the planes that keep their own disposition. */
    m = ngx_http_get_module_ctx(r, ngx_http_brix_common_module);
    if (m != NULL && m->cache != BRIX_CACHE_STATUS_NONE) {
        return m->cache;
    }

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
        brix_metric_cache_status_name(brix_request_cache_status(r)), 1);
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
    /* Data-plane set (phase-106 W1 second commit, completed in phase-110):
     * these read the per-request I/O monitor, so all NOCACHEABLE. Every name
     * below is also registered on the stream plane (phase-110 rule 1; guarded
     * by check_directive_registry R11). */
    { ngx_string("brix_bytes_served"), NULL, brix_var_bytes_served,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("brix_bytes_received"), NULL, brix_var_monitor_u64,
      BRIX_HV_BYTES_RECEIVED, NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("brix_backend_time"), NULL, brix_var_backend_time,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("brix_checksum"), NULL, brix_var_checksum,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("brix_op"), NULL, brix_var_op, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("brix_ops"), NULL, brix_var_monitor_u64,
      BRIX_HV_OPS, NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("brix_path"), NULL, brix_var_path,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("brix_status"), NULL, brix_var_status,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("brix_user"), NULL, brix_var_user, 0, 0, 0 },
    /* The one transport twin (rule 6): $request_time / $session_time under a
     * single name. */
    { ngx_string("brix_duration"), NULL, brix_var_duration, 0, 0, 0 },
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

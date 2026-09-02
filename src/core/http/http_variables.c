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


/*
 * ---- The data-plane I/O monitor: $brix_bytes_served / $brix_backend_time /
 *      $brix_checksum ------------------------------------------------------
 *
 * Unlike the identity/config variables above, these three report values the
 * data plane produces while serving — bytes moved, backend time, page-CRC —
 * which no HTTP plane retained per-request. The retention layer is a single
 * brix_io_monitor_t on the request pool, allocated ON THE EVENT LOOP and stored
 * in ngx_http_brix_common_module's request-ctx slot (the common module owns the
 * variable surface, and no plane uses its ctx slot). The VFS post-op observer
 * folds each op into it; these handlers read it at log time. See io_monitor.h
 * for the single-writer/thread contract.
 */

/* Get-or-create the request's monitor. MUST be first called on the event loop
 * (it allocates on r->pool). NULL only on allocation failure. */
static brix_io_monitor_t *
brix_http_monitor_get(ngx_http_request_t *r)
{
    brix_io_monitor_t *m = ngx_http_get_module_ctx(r, ngx_http_brix_common_module);

    if (m != NULL) {
        return m;
    }
    m = ngx_pcalloc(r->pool, sizeof(*m));
    if (m == NULL) {
        return NULL;
    }
    ngx_http_set_ctx(r, m, ngx_http_brix_common_module);
    return m;
}


/* phase-110 W7: the client address as a NUL-terminated string on r->pool.
 * r->connection->addr_text is NOT guaranteed NUL-terminated (ngx_sock_ntop
 * writes the address but not a terminator), so copy it once — the established
 * pattern (guard_audit_http.c). Event-loop only (allocates on r->pool). */
static const char *
brix_http_peer_cstr(ngx_http_request_t *r)
{
    ngx_connection_t *c;
    u_char           *p;
    size_t            n;

    if (r == NULL || r->connection == NULL
        || r->connection->addr_text.len == 0)
    {
        return NULL;
    }
    c = r->connection;
    p = ngx_pnalloc(r->pool, c->addr_text.len + 1);
    if (p == NULL) {
        return NULL;
    }
    n = c->addr_text.len;
    ngx_memcpy(p, c->addr_text.data, n);
    p[n] = '\0';
    return (const char *) p;
}


void
brix_http_monitor_bind(ngx_http_request_t *r, brix_vfs_ctx_t *vctx)
{
    if (r == NULL || vctx == NULL) {
        return;
    }
    /* Idempotent: create once, then every data-plane ctx of the request shares
     * the same accumulator so bytes/latency sum across its ops. */
    vctx->io_monitor = brix_http_monitor_get(r);
    /* W7: attach the client address for the JSON access log's `remote`, from
     * this same event-loop bind (r->pool alloc is safe here). */
    if (vctx->peer == NULL) {
        vctx->peer = brix_http_peer_cstr(r);
    }
}


/* Peek without creating — for the log-phase handlers, which must not allocate
 * and must tolerate a request that never bound a monitor (served with no brix
 * data op, or by another module). */
static brix_io_monitor_t *
brix_http_monitor_peek(ngx_http_request_t *r)
{
    return ngx_http_get_module_ctx(r, ngx_http_brix_common_module);
}


void
brix_http_monitor_record_served(ngx_http_request_t *r, off_t bytes)
{
    if (r == NULL || bytes <= 0) {
        return;
    }
    /* Peek, not create: the data-plane ctx bind already created the monitor on
     * the event loop before the serve. If it somehow did not, dropping the
     * count is safer than allocating from a possibly-thread context here. This
     * is the AUTHORITATIVE served-byte source (the serve is zero-copy and never
     * reaches the per-op VFS observer). */
    brix_io_monitor_add_served(brix_http_monitor_peek(r), (size_t) bytes);
}


/*
 * $brix_bytes_served — total bytes brix moved through its VFS for this request.
 *
 * The brix-measured figure, distinct from nginx's $body_bytes_sent (which is
 * what left the socket, after range trimming and on-the-wire framing); logging
 * both lets an operator see cache/backend read amplification. "-" when brix
 * moved no bytes (a metadata request, a 304, a request brix never served).
 * NOCACHEABLE: a data-plane outcome, unknown until the request is served.
 */
static ngx_int_t
brix_var_bytes_served(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    brix_io_monitor_t *m = brix_http_monitor_peek(r);
    u_char              *p;

    (void) data;
    /* "-" not "0": a request that ran a brix op but served nothing (a 404, a
     * metadata op, a 304) served no bytes — that is "no serve happened", not a
     * measured zero. Gate on the served count itself, not on `any`. */
    if (m == NULL || m->bytes == 0) {
        return brix_var_set_static(v, "-", 1);
    }
    p = ngx_pnalloc(r->pool, NGX_INT64_LEN);
    if (p == NULL) {
        return brix_var_set_static(v, "-", 1);
    }
    v->data = p;
    v->len = (unsigned) (ngx_sprintf(p, "%uL", m->bytes) - p);
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    return NGX_OK;
}


/*
 * $brix_backend_time — time brix spent in its own VFS I/O for this request,
 * in SECONDS with millisecond precision, deliberately the SAME format as
 * nginx's $request_time so the two sit side by side in a log line and subtract
 * cleanly. It measures backend/storage service time (summed across the
 * request's ops), which $request_time does not isolate — on a cache hit it is
 * near zero, on a cold miss it is the origin fetch. "-" when brix did no I/O.
 * NOCACHEABLE.
 */
static ngx_int_t
brix_var_backend_time(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    brix_io_monitor_t *m = brix_http_monitor_peek(r);
    u_char              *p;
    uint64_t             usec, sec, ms;

    (void) data;
    if (m == NULL || !m->any) {
        return brix_var_set_static(v, "-", 1);
    }
    usec = (uint64_t) m->backend_usec;
    sec  = usec / 1000000ULL;
    ms   = (usec % 1000000ULL) / 1000ULL;
    p = ngx_pnalloc(r->pool, NGX_INT64_LEN + sizeof(".000"));
    if (p == NULL) {
        return brix_var_set_static(v, "-", 1);
    }
    v->data = p;
    v->len = (unsigned) (ngx_sprintf(p, "%uL.%03uL", sec, ms) - p);
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    return NGX_OK;
}


void
brix_http_monitor_record_checksum(ngx_http_request_t *r, const char *alg,
    const char *hex)
{
    if (r == NULL) {
        return;
    }
    /* Peek: the plane reports a checksum only for a request it served, whose
     * data-plane ctx build already created the monitor on the event loop. */
    brix_io_monitor_record_checksum(brix_http_monitor_peek(r), alg, hex);
}


/*
 * $brix_checksum — the file checksum brix REPORTED to the client for this
 * request (the WebDAV `Digest` response header, the root kXR_Qcksum reply),
 * rendered "alg:hex" so the algorithm travels with the digits and is never
 * misread as adler32/md5 (INVARIANT #9: encode at the edge). "-" when the
 * request reported none — a plain GET without Want-Digest computes nothing, and
 * saying so is what makes the field safe to log unconditionally.
 * NOCACHEABLE (known only once the plane has answered).
 */
static ngx_int_t
brix_var_checksum(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    brix_io_monitor_t *m = brix_http_monitor_peek(r);

    (void) data;
    if (m == NULL || !m->have_checksum) {
        return brix_var_set_static(v, "-", 1);
    }
    /* The monitor's buffer lives on r->pool (it IS the monitor) and outlives
     * the log phase — no copy needed. */
    v->data = (u_char *) m->checksum;
    v->len = (unsigned) m->checksum_len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    return NGX_OK;
}


/*
 * $brix_op — the brix operation that describes this request, in the SAME
 * vocabulary as the JSON access log's "op" and the io_ops{op} Prometheus label
 * (brix_metric_op_name): read / write / stat / dirlist / delete / mkdir /
 * rename / xattr / copy / tpc. This is what $request_method cannot say: a TPC
 * transfer and a plain COPY are both "COPY" to nginx, a GetObject and a
 * ListBucket are both "GET". Chosen by the weight rule in io_monitor.h (the
 * data or composite op of the request, never an incidental stat). "-" when no
 * brix op ran. NOCACHEABLE.
 */
static ngx_int_t
brix_var_op(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    brix_io_monitor_t *m = brix_http_monitor_peek(r);

    (void) data;
    if (m == NULL || !m->have_op) {
        return brix_var_set_static(v, "-", 1);
    }
    return brix_var_set_static(v, brix_metric_op_name(m->op), 1);
}


/*
 * $brix_path — the CONFINED, RESOLVED export-relative path of the primary op:
 * the string the JSON access log prints, not the client's URL ($uri) and not a
 * storage-absolute path. SECURITY: it is copied from brix_vfs_ctx_path() after
 * resolve_path() has confined it, so a traversal probe logs the refused path
 * or "-", never anything outside the export; and it can carry no userinfo (it
 * is a path, not a URL). Bounded to BRIX_IO_MONITOR_PATH_MAX — a longer path
 * is truncated, never dropped. NOCACHEABLE.
 */
static ngx_int_t
brix_var_path(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    brix_io_monitor_t *m = brix_http_monitor_peek(r);

    (void) data;
    if (m == NULL || m->path_len == 0) {
        return brix_var_set_static(v, "-", 1);
    }
    v->data = (u_char *) m->path;
    v->len = (unsigned) m->path_len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    return NGX_OK;
}


/*
 * $brix_status — the brix OUTCOME CLASS of the request, plane-neutral, in the
 * SAME vocabulary as the JSON access log's "status" and the io_ops{status}
 * label (brix_metric_err_name): ok / not_found / forbidden / io / other.
 * $status is an HTTP code on one plane and a stream code on the other, and a
 * brix refusal that never became a response has neither; this is the one word
 * that means the same thing everywhere (a read-only-export refusal is
 * "forbidden" on WebDAV, S3 and root:// alike). Source: the outcome recorded
 * with the primary op, else the mutation gate's / plane's explicit record,
 * else — for a request brix refused before any VFS op ran (401/403/404 from
 * the auth or resolve step) — the class of the HTTP status it answered with
 * (brix_metric_err_from_http_status). "-" only when brix never ran at all.
 * NOCACHEABLE.
 */
static ngx_int_t
brix_var_status(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    brix_io_monitor_t *m = brix_http_monitor_peek(r);
    brix_err_class_t    err;

    (void) data;
    if (m != NULL && (m->have_op || m->err != BRIX_ERR_NONE)) {
        /* The primary op's own outcome — the most specific answer. */
        err = m->err;
    } else if (r->headers_out.status != 0
               && brix_request_shared_conf(r) != NULL) {
        /* brix owns this location but refused/served at the HTTP layer before
         * any VFS op ran (a 403 allow_write refusal at the access phase, a 401
         * auth refusal): classify the status brix answered with, so the outcome
         * is never a bare "-" for a request brix demonstrably handled. */
        err = brix_metric_err_from_http_status(r->headers_out.status);
    } else {
        return brix_var_set_static(v, "-", 1);
    }
    return brix_var_set_static(v, brix_metric_err_name(err), 1);
}


/*
 * $brix_user — the mapped LOCAL account this request runs as (the
 * impersonation target resolved from the grid-mapfile / mapping policy), or
 * "-" when the identity did not map. Distinct from $brix_sub (WHO the client
 * is) — this is WHAT the storage saw. An account name, not a credential (R10
 * review note). Per-request cacheable: mapping is decided once at authz.
 */
static ngx_int_t
brix_var_user(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    brix_identity_t *id = brix_request_identity(r);

    (void) data;
    if (id == NULL || !id->mapped_resolved || id->mapped_user[0] == '\0') {
        return brix_var_set_static(v, "-", 0);
    }
    /* mapped_user is an array inside the identity, which is request-pool
     * memory that outlives the log phase. */
    v->data = (u_char *) id->mapped_user;
    v->len = (unsigned) ngx_strlen(id->mapped_user);
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}


/* Shared shape for the plain unsigned counters ($brix_bytes_received,
 * $brix_ops): render a uint64 from the monitor, "-" when the event did not
 * happen. `data` selects the field. */
typedef enum {
    BRIX_HV_BYTES_RECEIVED = 0,
    BRIX_HV_OPS
} brix_http_monitor_u64_e;


static ngx_int_t
brix_var_monitor_u64(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    brix_io_monitor_t *m = brix_http_monitor_peek(r);
    u_char              *p;
    uint64_t             n;

    if (m == NULL || !m->any) {
        return brix_var_set_static(v, "-", 1);
    }
    switch ((brix_http_monitor_u64_e) data) {
    case BRIX_HV_BYTES_RECEIVED:
        /* "-" not "0": a GET received no body — nothing happened. */
        if (m->bytes_received == 0) {
            return brix_var_set_static(v, "-", 1);
        }
        n = m->bytes_received;
        break;
    case BRIX_HV_OPS:
    default:
        n = (uint64_t) m->ops;
        break;
    }
    p = ngx_pnalloc(r->pool, NGX_INT64_LEN);
    if (p == NULL) {
        return brix_var_set_static(v, "-", 1);
    }
    v->data = p;
    v->len = (unsigned) (ngx_sprintf(p, "%uL", n) - p);
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    return NGX_OK;
}


/*
 * $brix_duration — wall time of the whole request, seconds.mmm, byte-identical
 * to nginx's $request_time (same clock, same formula:
 * ngx_http_variable_request_time). It exists for ONE reason: nginx spells this
 * fact $request_time on HTTP and $session_time on stream, and a log_format
 * that must serve both planes needs one name (phase-110 rule 6 — the only
 * transport fact brix twins). Per-request cacheable within the log phase.
 */
static ngx_int_t
brix_var_duration(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    u_char          *p;
    ngx_time_t      *tp;
    ngx_msec_int_t   ms;

    (void) data;
    p = ngx_pnalloc(r->pool, NGX_TIME_T_LEN + 4);
    if (p == NULL) {
        return brix_var_set_static(v, "-", 1);
    }
    tp = ngx_timeofday();
    ms = (ngx_msec_int_t) ((tp->sec - r->start_sec) * 1000
                           + (tp->msec - r->start_msec));
    ms = ngx_max(ms, 0);
    v->data = p;
    v->len = (unsigned) (ngx_sprintf(p, "%T.%03M", (time_t) ms / 1000,
                                     ms % 1000) - p);
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
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

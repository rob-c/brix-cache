/* Per-request I/O-monitor handlers for the HTTP `$brix_*` surface. */
#include "core/http/http_variables.h"
#include "core/http/http_variables_internal.h"

#include "fs/vfs/vfs.h"
#include "observability/metrics/io_monitor.h"
#include "observability/metrics/unified.h"

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
ngx_int_t
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
ngx_int_t
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
ngx_int_t
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
ngx_int_t
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
ngx_int_t
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
ngx_int_t
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
ngx_int_t
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


ngx_int_t
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
ngx_int_t
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


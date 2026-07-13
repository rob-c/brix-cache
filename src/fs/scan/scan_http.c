/*
 * scan_http.c — admin HTTP endpoint for the storage-scan engine.
 *
 * WHAT: GET /xrootd/api/v1/scan?mode=dump|verify|fill|compare&path=<rel>&alg=<a>
 *       Streams one NDJSON record per object plus a final summary record.
 * WHY:  gives an admin a confined, auth-gated way to dump/verify/backfill
 *       checksums across a subtree on any backend (POSIX/pblock/Ceph) — the
 *       engine rides the VFS seam so no backend-specific code lives here.
 * HOW:  mirrors the admin file-browser (dashboard/files.c): admin-auth +
 *       openat2 RESOLVE_BENEATH confinement under brix_scan_root. v1 runs the
 *       walk synchronously and emits one buffered NDJSON body (bounded by
 *       brix_scan_max_files). Off-loading to the thread pool + chunked
 *       streaming + the byte-rate throttle is the next increment (the throttle
 *       math and ordered-emit buffer already exist in scan_throttle/scan_emit).
 *
 * NOTE: this is the ONLY nginx-coupled file in src/scan/.
 */
#include "scan_engine.h"
#include "scan_record.h"

#include "observability/dashboard/dashboard_http.h"
#include "fs/path/beneath.h"
#include "core/http/http_headers.h"   /* brix_http_source_offer (AGPL sec.13) */
#include "protocols/root/protocol/opcodes.h"
#include "fs/vfs/vfs.h"                  /* brix_sd_caps, brix_vfs_enumerate_catalog */
#include "fs/vfs/vfs_backend_registry.h" /* brix_vfs_backend_resolve (export→instance) */

#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/statvfs.h>
#include <unistd.h>

/*
 * WHAT: one query-arg read request — the name to fetch, the caller's output
 *       buffer + size, and a default to apply when the arg is absent/empty.
 * WHY:  scan_arg previously took these five as loose parameters (6 params with
 *       `r`), tripping the param-count gate; grouping them keeps every call site
 *       self-documenting and drops scan_arg to two params.
 * HOW:  a plain value struct; the request handle `r` stays a separate parameter
 *       because it is request context, not part of the arg specification.
 */
typedef struct {
    const char *name;      /* query key */
    size_t      namelen;   /* length of `name` */
    char       *out;       /* caller output buffer */
    size_t      outsz;     /* capacity of `out` */
    const char *dflt;      /* value when arg absent/empty (NULL ⇒ leave empty) */
} scan_arg_spec_t;

/*
 * WHAT: read query arg `spec->name` (URL-decoded) into `spec->out[spec->outsz]`.
 * WHY:  every query field the scan endpoint accepts flows through one bounded,
 *       NUL-rejecting reader so no field can overflow or smuggle an embedded NUL.
 * HOW:  absent/empty ⇒ apply `spec->dflt`; otherwise URL-unescape into the
 *       buffer. NGX_ERROR only on overflow / embedded NUL.
 */
static ngx_int_t
scan_arg(ngx_http_request_t *r, const scan_arg_spec_t *spec)
{
    ngx_str_t raw;
    u_char   *dst, *src;
    size_t    n;

    if (ngx_http_arg(r, (u_char *) spec->name, spec->namelen, &raw) != NGX_OK
        || raw.len == 0)
    {
        if (spec->dflt != NULL) {
            if (ngx_strlen(spec->dflt) >= spec->outsz) {
                return NGX_ERROR;
            }
            ngx_memcpy(spec->out, spec->dflt, ngx_strlen(spec->dflt) + 1);
        } else {
            spec->out[0] = '\0';
        }
        return NGX_OK;
    }
    if (raw.len >= spec->outsz) {
        return NGX_ERROR;
    }
    dst = (u_char *) spec->out;
    src = raw.data;
    ngx_unescape_uri(&dst, &src, raw.len, 0);
    n = (size_t) (dst - (u_char *) spec->out);
    spec->out[n] = '\0';
    if (ngx_strlchr((u_char *) spec->out,
                    (u_char *) spec->out + n, '\0') != NULL)
    {
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* The ?path arg, normalized relative to the scan root ("/" ⇒ "." anchor). */
static ngx_int_t
scan_get_path(ngx_http_request_t *r, char *out, size_t outsz)
{
    scan_arg_spec_t spec = { "path", 4, out, outsz, "." };
    char           *p;

    if (scan_arg(r, &spec) != NGX_OK) {
        return NGX_ERROR;
    }
    p = out;
    while (*p == '/') {
        p++;
    }
    if (*p == '\0') {
        ngx_memcpy(out, ".", 2);
    } else if (p != out) {
        ngx_memmove(out, p, strlen(p) + 1);
    }
    return NGX_OK;
}

/* Map an engine kXR error code to an HTTP status. */
static ngx_int_t
scan_err_http(uint16_t code)
{
    switch (code) {
    case kXR_NotFound:      return NGX_HTTP_NOT_FOUND;
    case kXR_NotAuthorized: return NGX_HTTP_FORBIDDEN;
    case kXR_ArgInvalid:    return NGX_HTTP_BAD_REQUEST;
    case kXR_NoMemory:      return NGX_HTTP_INSUFFICIENT_STORAGE;
    default:                return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
}

/* Send the assembled NDJSON body (len bytes from `body`, pool-owned). */
static ngx_int_t
scan_send(ngx_http_request_t *r, u_char *body, size_t len)
{
    ngx_buf_t   *b;
    ngx_chain_t  out;
    ngx_int_t    rc;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = (off_t) len;
    r->headers_out.content_type = (ngx_str_t) ngx_string("application/x-ndjson");
    r->headers_out.content_type_len = r->headers_out.content_type.len;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b = ngx_pcalloc(r->pool, sizeof(*b));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    b->pos = b->start = body;
    b->last = b->end = body + len;
    b->memory = 1;
    b->last_buf = 1;
    out.buf = b;
    out.next = NULL;
    return ngx_http_output_filter(r, &out);
}

/* health (C1): one record with the scan root's filesystem capacity. The scan
 * endpoint sees the POSIX export root (not the SD driver), so backend is
 * "posix"; driver/cluster facts (Ceph HEALTH_OK, OSDs) are a Phase-4 add. */
static ngx_int_t
scan_health(ngx_http_request_t *r, const char *root_canon)
{
    struct statvfs vfs;
    char           line[256];
    u_char        *body;
    uint64_t       total, freeb, used;
    int            n;

    if (statvfs(root_canon, &vfs) != 0) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    total = (uint64_t) vfs.f_blocks * vfs.f_frsize;
    freeb = (uint64_t) vfs.f_bavail * vfs.f_frsize;
    used = total - (uint64_t) vfs.f_bfree * vfs.f_frsize;

    n = brix_scan_record_health(line, sizeof(line), "posix", total, freeb, used);
    if (n < 0) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    body = ngx_palloc(r->pool, (size_t) n + 1);
    if (body == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(body, line, (size_t) n);
    body[n] = '\n';
    return scan_send(r, body, (size_t) n + 1);
}

/*
 * WHAT: the fully-parsed, validated scan request — walk options plus the
 *       normalized relative path and a copy of the raw mode string (for logs).
 * WHY:  lets the query-parsing phase hand a single ready-to-run value to the
 *       walk phase, keeping the orchestrator flat and the phases independently
 *       readable.
 * HOW:  populated once by scan_parse_query; `mode_raw` mirrors the ?mode arg so
 *       the warning log reproduces the caller's spelling verbatim.
 */
typedef struct {
    brix_scan_opts_t opts;
    char             relpath[PATH_MAX];
    char             mode_raw[16];
} scan_request_t;

/*
 * WHAT: the buffer + summary produced by a completed walk, ready to render.
 * WHY:  scan_run_walk owns a malloc'd `buf` and a summary; bundling them lets
 *       the render phase both emit and free without extra out-params.
 * HOW:  `buf`/`cap`/`used` are the engine's heap NDJSON accumulator (freed by
 *       the render phase); `summary` feeds the trailing summary record.
 */
typedef struct {
    u_char             *buf;
    size_t              cap;
    size_t              used;
    brix_scan_summary_t summary;
} scan_result_t;

/*
 * WHAT: the walk's error sink — a kXR code plus a human message buffer.
 * WHY:  the engine reports failures via a (code, msg, msglen) triple; bundling
 *       them keeps scan_run_walk within the param gate and lets the orchestrator
 *       pass one value to the log + status mapper.
 * HOW:  zero-initialised by the orchestrator; on a failed walk `code`→HTTP and
 *       `msg` is logged verbatim.
 */
typedef struct {
    uint16_t code;
    char     msg[160];
} scan_err_t;

/*
 * WHAT: read + validate the ?mode arg into `req->mode_raw`; returns an HTTP
 *       status. Does NOT map the mode string to an enum — the caller inspects
 *       `mode_raw` for the `health` point-query first.
 * WHY:  `health` must be recognised before mode→enum parsing (it is not a walk
 *       mode), matching the pre-refactor order exactly.
 * HOW:  NGX_OK ⇒ `mode_raw` is a non-empty, bounds-checked string.
 */
static ngx_int_t
scan_read_mode(ngx_http_request_t *r, scan_request_t *req)
{
    scan_arg_spec_t spec = { "mode", 4, req->mode_raw,
                             sizeof(req->mode_raw), NULL };

    ngx_memzero(&req->opts, sizeof(req->opts));
    if (scan_arg(r, &spec) != NGX_OK || req->mode_raw[0] == '\0') {
        return NGX_HTTP_BAD_REQUEST;
    }
    return NGX_OK;
}

/*
 * WHAT: parse + validate the remaining query args (mode enum, alg, path,
 *       max_files) into `req`; returns an HTTP status.
 * WHY:  isolates request-shape validation from the walk so each rejection maps
 *       to one early return with a clear code.
 * HOW:  requires `req->mode_raw` already read by scan_read_mode. NGX_OK ⇒ req
 *       fully populated; any bad field ⇒ the matching 4xx. Frozen behavior:
 *       same fields, same defaults, same bounds as before.
 */
static ngx_int_t
scan_parse_query(ngx_http_request_t *r,
                 ngx_http_brix_dashboard_loc_conf_t *conf,
                 scan_request_t *req)
{
    scan_arg_spec_t alg_spec = { "alg", 3, req->opts.alg,
                                 sizeof(req->opts.alg), "adler32" };
    char            maxbuf[24];
    scan_arg_spec_t max_spec = { "max_files", 9, maxbuf, sizeof(maxbuf), NULL };

    if (brix_scan_mode_parse(req->mode_raw, &req->opts.mode) != NGX_OK) {
        return NGX_HTTP_BAD_REQUEST;
    }
    if (scan_arg(r, &alg_spec) != NGX_OK) {
        return NGX_HTTP_BAD_REQUEST;
    }
    if (scan_get_path(r, req->relpath, sizeof(req->relpath)) != NGX_OK) {
        return NGX_HTTP_BAD_REQUEST;
    }

    /* max_files: per-request value lowers but never raises the operator cap. */
    req->opts.max_files = conf->scan_max_files;
    req->opts.max_depth = 1024;   /* effectively-full recursion (small depth) */
    if (scan_arg(r, &max_spec) == NGX_OK && maxbuf[0] != '\0')
    {
        ngx_uint_t rq = (ngx_uint_t) ngx_atoi((u_char *) maxbuf,
                                              ngx_strlen(maxbuf));
        if (rq != (ngx_uint_t) NGX_ERROR && rq > 0 && rq < req->opts.max_files) {
            req->opts.max_files = rq;
        }
    }
    return NGX_OK;
}

/*
 * WHAT: run the scan, choosing catalog-native enumeration vs the confined POSIX
 *       walk, and fill `res` with the NDJSON buffer + summary.
 * WHY:  a catalog backend (Ceph/RADOS) answers inventory/verify through its OWN
 *       object catalog (no rootfd, no namespace walk); every other export/mode
 *       runs the confined POSIX walk. Keeping the dispatch here leaves the
 *       orchestrator agnostic to backend shape.
 * HOW:  returns the engine rc; on error `*err_code`/`err_msg` carry the kXR
 *       reason. `res->buf` may be set even on error and is freed by the caller.
 */
static ngx_int_t
scan_run_walk(ngx_http_request_t *r,
              ngx_http_brix_dashboard_loc_conf_t *conf,
              scan_request_t *req, scan_result_t *res, scan_err_t *err)
{
    brix_sd_instance_t *sd;
    int                 rootfd;
    ngx_int_t           rc;

    sd = brix_vfs_backend_resolve(conf->scan_root_canon, r->connection->log);
    if (req->opts.mode == BRIX_SCAN_INVENTORY && sd != NULL
        && (brix_sd_caps(sd) & BRIX_SD_CAP_CATALOG))
    {
        return brix_scan_run_inventory(r->connection->log, sd, &req->opts,
                                       &res->buf, &res->cap, &res->used,
                                       &res->summary, &err->code,
                                       err->msg, sizeof(err->msg));
    }
    if (req->opts.mode == BRIX_SCAN_VERIFY && sd != NULL
        && (brix_sd_caps(sd) & BRIX_SD_CAP_CATALOG))
    {
        /* Verify checksums of every object the backend physically holds, reading
         * bytes through the driver (Ceph: libradosstriper-reassembled). */
        return brix_scan_run_verify_catalog(r->connection->log, sd, &req->opts,
                                            &res->buf, &res->cap, &res->used,
                                            &res->summary, &err->code,
                                            err->msg, sizeof(err->msg));
    }

    rootfd = brix_beneath_open_root(conf->scan_root_canon);
    if (rootfd < 0) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    rc = brix_scan_run(r->connection->log, rootfd, req->relpath, &req->opts,
                       &res->buf, &res->cap, &res->used, &res->summary,
                       &err->code, err->msg, sizeof(err->msg));
    close(rootfd);
    return rc;
}

/*
 * WHAT: assemble the pool-owned response body (file records + summary line) and
 *       stream it; frees the engine's heap buffer either way.
 * WHY:  keeps all body-assembly + free bookkeeping in one place so the walk
 *       phase never has to think about the response encoding.
 * HOW:  copy `res->buf[0..used]`, append the summary record + newline, send.
 *       NDJSON output bytes are frozen.
 */
static ngx_int_t
scan_render(ngx_http_request_t *r, scan_result_t *res)
{
    char    sumline[256];
    int     sumlen;
    u_char *body;

    sumlen = brix_scan_record_summary(sumline, sizeof(sumline), &res->summary);
    if (sumlen < 0) {
        if (res->buf != NULL) {
            ngx_free(res->buf);
        }
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    body = ngx_palloc(r->pool, res->used + (size_t) sumlen + 1);
    if (body == NULL) {
        if (res->buf != NULL) {
            ngx_free(res->buf);
        }
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (res->used > 0) {
        ngx_memcpy(body, res->buf, res->used);
    }
    ngx_memcpy(body + res->used, sumline, (size_t) sumlen);
    body[res->used + (size_t) sumlen] = '\n';
    if (res->buf != NULL) {
        ngx_free(res->buf);
    }

    return scan_send(r, body, res->used + (size_t) sumlen + 1);
}

/* GET /xrootd/api/v1/scan */
ngx_int_t
ngx_http_brix_dashboard_scan_handler(ngx_http_request_t *r)
{
    ngx_http_brix_dashboard_loc_conf_t *conf;
    scan_request_t  req;
    scan_result_t   res;
    scan_err_t      err;
    ngx_int_t       rc;
    uint64_t        t0;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_brix_dashboard_module);
    if (conf->scan_root_canon[0] == '\0') {
        return NGX_HTTP_NOT_FOUND;   /* feature disabled */
    }
    rc = ngx_http_brix_dashboard_check_auth(r, conf, 0);
    if (rc != NGX_OK) {
        return rc;
    }
    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }
    brix_http_source_offer(r);

    rc = scan_read_mode(r, &req);
    if (rc != NGX_OK) {
        return rc;
    }
    /* health is a point query about the root, not a walk — recognised before
     * mode→enum parsing (it is not a walk mode). */
    if (strcmp(req.mode_raw, "health") == 0) {
        return scan_health(r, conf->scan_root_canon);
    }
    rc = scan_parse_query(r, conf, &req);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_memzero(&res, sizeof(res));
    ngx_memzero(&err, sizeof(err));
    t0 = ngx_current_msec;

    rc = scan_run_walk(r, conf, &req, &res, &err);
    if (rc != NGX_OK) {
        if (res.buf != NULL) {
            ngx_free(res.buf);
        }
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "scan %s %s: %s", req.mode_raw, req.relpath, err.msg);
        return scan_err_http(err.code);
    }

    res.summary.elapsed_s = (double) (ngx_current_msec - t0) / 1000.0;
    return scan_render(r, &res);
}

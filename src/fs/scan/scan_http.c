/*
 * scan_http.c — admin HTTP endpoint for the storage-scan engine.
 *
 * WHAT: GET /xrootd/api/v1/scan?mode=dump|verify|fill|compare&path=<rel>&alg=<a>
 *       Streams one NDJSON record per object plus a final summary record.
 * WHY:  gives an admin a confined, auth-gated way to dump/verify/backfill
 *       checksums across a subtree on any backend (POSIX/pblock/Ceph) — the
 *       engine rides the VFS seam so no backend-specific code lives here.
 * HOW:  mirrors the admin file-browser (dashboard/files.c): admin-auth +
 *       openat2 RESOLVE_BENEATH confinement under xrootd_scan_root. v1 runs the
 *       walk synchronously and emits one buffered NDJSON body (bounded by
 *       xrootd_scan_max_files). Off-loading to the thread pool + chunked
 *       streaming + the byte-rate throttle is the next increment (the throttle
 *       math and ordered-emit buffer already exist in scan_throttle/scan_emit).
 *
 * NOTE: this is the ONLY nginx-coupled file in src/scan/.
 */
#include "scan_engine.h"
#include "scan_record.h"

#include "observability/dashboard/dashboard_http.h"
#include "fs/path/beneath.h"
#include "core/compat/http_headers.h"   /* xrootd_http_source_offer (AGPL sec.13) */
#include "protocol/opcodes.h"
#include "fs/vfs.h"                  /* xrootd_sd_caps, xrootd_vfs_enumerate_catalog */
#include "fs/vfs_backend_registry.h" /* xrootd_vfs_backend_resolve (export→instance) */

#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/statvfs.h>
#include <unistd.h>

/* Read query arg `name` (URL-decoded) into out[outsz]; falls back to `dflt`
 * (may be NULL ⇒ leaves out empty). NGX_ERROR only on overflow / embedded NUL. */
static ngx_int_t
scan_arg(ngx_http_request_t *r, const char *name, size_t namelen,
         char *out, size_t outsz, const char *dflt)
{
    ngx_str_t raw;
    u_char   *dst, *src;
    size_t    n;

    if (ngx_http_arg(r, (u_char *) name, namelen, &raw) != NGX_OK
        || raw.len == 0)
    {
        if (dflt != NULL) {
            if (ngx_strlen(dflt) >= outsz) {
                return NGX_ERROR;
            }
            ngx_memcpy(out, dflt, ngx_strlen(dflt) + 1);
        } else {
            out[0] = '\0';
        }
        return NGX_OK;
    }
    if (raw.len >= outsz) {
        return NGX_ERROR;
    }
    dst = (u_char *) out;
    src = raw.data;
    ngx_unescape_uri(&dst, &src, raw.len, 0);
    n = (size_t) (dst - (u_char *) out);
    out[n] = '\0';
    if (ngx_strlchr((u_char *) out, (u_char *) out + n, '\0') != NULL) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* The ?path arg, normalized relative to the scan root ("/" ⇒ "." anchor). */
static ngx_int_t
scan_get_path(ngx_http_request_t *r, char *out, size_t outsz)
{
    char *p;

    if (scan_arg(r, "path", 4, out, outsz, ".") != NGX_OK) {
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

    n = xrootd_scan_record_health(line, sizeof(line), "posix", total, freeb, used);
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

/* GET /xrootd/api/v1/scan */
ngx_int_t
ngx_http_xrootd_dashboard_scan_handler(ngx_http_request_t *r)
{
    ngx_http_xrootd_dashboard_loc_conf_t *conf;
    xrootd_scan_opts_t      opts;
    xrootd_scan_summary_t   summary;
    char                    relpath[PATH_MAX];
    char                    modebuf[16];
    char                    maxbuf[24];
    int                     rootfd;
    xrootd_sd_instance_t   *sd;
    u_char                 *buf = NULL;
    size_t                  cap = 0, used = 0;
    u_char                 *body;
    char                    sumline[256];
    int                     sumlen;
    uint16_t                err_code = 0;
    char                    err_msg[160] = "";
    ngx_int_t               rc;
    uint64_t                t0;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_dashboard_module);
    if (conf->scan_root_canon[0] == '\0') {
        return NGX_HTTP_NOT_FOUND;   /* feature disabled */
    }
    rc = ngx_http_xrootd_dashboard_check_auth(r, conf, 0);
    if (rc != NGX_OK) {
        return rc;
    }
    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }
    xrootd_http_source_offer(r);

    ngx_memzero(&opts, sizeof(opts));
    if (scan_arg(r, "mode", 4, modebuf, sizeof(modebuf), NULL) != NGX_OK
        || modebuf[0] == '\0')
    {
        return NGX_HTTP_BAD_REQUEST;
    }
    /* health is a point query about the root, not a walk. */
    if (strcmp(modebuf, "health") == 0) {
        return scan_health(r, conf->scan_root_canon);
    }
    if (xrootd_scan_mode_parse(modebuf, &opts.mode) != NGX_OK) {
        return NGX_HTTP_BAD_REQUEST;
    }
    if (scan_arg(r, "alg", 3, opts.alg, sizeof(opts.alg), "adler32") != NGX_OK) {
        return NGX_HTTP_BAD_REQUEST;
    }
    if (scan_get_path(r, relpath, sizeof(relpath)) != NGX_OK) {
        return NGX_HTTP_BAD_REQUEST;
    }

    /* max_files: per-request value lowers but never raises the operator cap. */
    opts.max_files = conf->scan_max_files;
    opts.max_depth = 1024;   /* effectively-full recursion (export depth is small) */
    if (scan_arg(r, "max_files", 9, maxbuf, sizeof(maxbuf), NULL) == NGX_OK
        && maxbuf[0] != '\0')
    {
        ngx_uint_t req = (ngx_uint_t) ngx_atoi((u_char *) maxbuf,
                                               ngx_strlen(maxbuf));
        if (req != (ngx_uint_t) NGX_ERROR && req > 0 && req < opts.max_files) {
            opts.max_files = req;
        }
    }

    ngx_memzero(&summary, sizeof(summary));
    t0 = ngx_current_msec;

    /* A catalog-native backend (e.g. Ceph/RADOS) answers `inventory` by
     * enumerating its OWN object catalog through the SD `enumerate` verb — no
     * POSIX rootfd, no namespace walk. Every other export (and every other mode)
     * runs the confined POSIX walk. */
    sd = xrootd_vfs_backend_resolve(conf->scan_root_canon, r->connection->log);
    if (opts.mode == XROOTD_SCAN_INVENTORY && sd != NULL
        && (xrootd_sd_caps(sd) & XROOTD_SD_CAP_CATALOG))
    {
        rc = xrootd_scan_run_inventory(r->connection->log, sd, &opts,
                                       &buf, &cap, &used, &summary,
                                       &err_code, err_msg, sizeof(err_msg));
    } else if (opts.mode == XROOTD_SCAN_VERIFY && sd != NULL
               && (xrootd_sd_caps(sd) & XROOTD_SD_CAP_CATALOG))
    {
        /* Verify checksums of every object the backend physically holds, reading
         * bytes through the driver (Ceph: libradosstriper-reassembled). */
        rc = xrootd_scan_run_verify_catalog(r->connection->log, sd, &opts,
                                            &buf, &cap, &used, &summary,
                                            &err_code, err_msg, sizeof(err_msg));
    } else {
        rootfd = xrootd_beneath_open_root(conf->scan_root_canon);
        if (rootfd < 0) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        rc = xrootd_scan_run(r->connection->log, rootfd, relpath, &opts,
                             &buf, &cap, &used, &summary,
                             &err_code, err_msg, sizeof(err_msg));
        close(rootfd);
    }

    if (rc != NGX_OK) {
        if (buf != NULL) {
            ngx_free(buf);
        }
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "scan %s %s: %s", modebuf, relpath, err_msg);
        return scan_err_http(err_code);
    }

    summary.elapsed_s = (double) (ngx_current_msec - t0) / 1000.0;
    sumlen = xrootd_scan_record_summary(sumline, sizeof(sumline), &summary);
    if (sumlen < 0) {
        if (buf != NULL) {
            ngx_free(buf);
        }
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Assemble the pool-owned response = file records + summary line. */
    body = ngx_palloc(r->pool, used + (size_t) sumlen + 1);
    if (body == NULL) {
        if (buf != NULL) {
            ngx_free(buf);
        }
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (used > 0) {
        ngx_memcpy(body, buf, used);
    }
    ngx_memcpy(body + used, sumline, (size_t) sumlen);
    body[used + (size_t) sumlen] = '\n';
    if (buf != NULL) {
        ngx_free(buf);
    }

    return scan_send(r, body, used + (size_t) sumlen + 1);
}

/*
 * sd_http.c — read-only HTTP(S) source storage driver (phase-63 C-4). See header.
 *
 * A thin driver over the injected xrootd_s3_transport_t (the same vtable the S3
 * driver uses): `open`/`stat` HEAD the URL for the size, `pread` issues a byte
 * Range GET. No SigV4, no auth — plain anonymous HTTP. No kernel fd ⇒ memory-served.
 */

#include "sd_http.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define SD_HTTP_PREAD_MAX  (8LL * 1024 * 1024)
#define SD_HTTP_BASE_MAX   512                  /* URL base path prefix */
#define SD_HTTP_PATH_MAX   2048                 /* full URL path = base + key */
#define SD_HTTP_AUTH_MAX   4160                 /* "Authorization: Bearer <tok>\r\n" */

typedef struct {
    char                         host[256];
    int                          port;
    int                          tls;
    char                         base_path[SD_HTTP_BASE_MAX];
    const xrootd_s3_transport_t *transport;
    void                        *tctx;
    int                          timeout_ms;
    char                         auth_hdr[SD_HTTP_AUTH_MAX]; /* §14 bearer hdr or "" */
} sd_http_inst_state;

typedef struct {
    char path[SD_HTTP_PATH_MAX];   /* full URL path: base_path + key */
} sd_http_obj_state;

/* Per-staged-write state: HTTP has no streaming PUT through this transport, so the
 * object is buffered and PUT whole at commit (a remote stage/cache store of typical
 * file sizes; very large objects are a multipart follow-up). */
typedef struct {
    char     path[SD_HTTP_PATH_MAX];
    u_char  *buf;
    size_t   len;
    size_t   cap;
} sd_http_staged_state;

/* Compose the full URL path "base_path + key" (key already carries a leading '/'). */
static void
sd_http_full_path(const sd_http_inst_state *is, const char *key, char *dst,
    size_t cap)
{
    snprintf(dst, cap, "%s%s", is->base_path, (key != NULL && key[0]) ? key : "/");
}

/* HEAD `path` → *size_out (−1 if no Content-Length). 0, or −1 with errno. */
static int
sd_http_head_size(sd_http_inst_state *is, const char *path, int64_t *size_out)
{
    xrootd_s3_resp_t resp;
    char             errbuf[256], cl[32];

    if (is->transport->request(is->tctx, is->host, is->port, is->tls, "HEAD",
                               path, is->auth_hdr[0] ? is->auth_hdr : NULL,
                               NULL, 0, is->timeout_ms, &resp,
                               errbuf, sizeof(errbuf)) != 0)
    {
        errno = EIO;
        return -1;
    }
    if (resp.status == 404) {
        is->transport->resp_free(&resp);
        errno = ENOENT;
        return -1;
    }
    if (resp.status != 200) {
        is->transport->resp_free(&resp);
        errno = (resp.status == 403 || resp.status == 401) ? EACCES : EIO;
        return -1;
    }
    if (is->transport->resp_header(&resp, "Content-Length", cl, sizeof(cl)) == 0) {
        *size_out = (int64_t) strtoll(cl, NULL, 10);
    } else {
        *size_out = -1;
    }
    is->transport->resp_free(&resp);
    return 0;
}

static xrootd_sd_obj_t *
sd_http_open(xrootd_sd_instance_t *inst, const char *path, int sd_flags,
    mode_t mode, int *err_out)
{
    sd_http_inst_state *is = inst->state;
    sd_http_obj_state  *st;
    xrootd_sd_obj_t    *obj;
    int64_t             size = 0;
    char                full[SD_HTTP_PATH_MAX];

    (void) mode;

    /* Read-only source: refuse any write/create/trunc intent. */
    if (sd_flags & (XROOTD_SD_O_WRITE | XROOTD_SD_O_CREATE | XROOTD_SD_O_TRUNC
                    | XROOTD_SD_O_APPEND))
    {
        if (err_out) { *err_out = EROFS; }
        return NULL;
    }

    sd_http_full_path(is, path, full, sizeof(full));
    if (sd_http_head_size(is, full, &size) != 0) {
        if (err_out) { *err_out = errno; }
        return NULL;
    }

    st  = calloc(1, sizeof(*st));
    obj = calloc(1, sizeof(*obj));
    if (st == NULL || obj == NULL) {
        free(st);
        free(obj);
        if (err_out) { *err_out = ENOMEM; }
        return NULL;
    }
    snprintf(st->path, sizeof(st->path), "%s", full);

    obj->driver     = inst->driver;
    obj->inst       = inst;
    obj->fd         = NGX_INVALID_FILE;     /* no kernel fd — memory-served */
    obj->state      = st;
    obj->heap_shell = 1;
    obj->snap.size  = (off_t) size;
    obj->snap.mode  = S_IFREG | 0444;
    obj->snap.is_reg = 1;
    return obj;
}

static ngx_int_t
sd_http_close(xrootd_sd_obj_t *obj)
{
    if (obj != NULL && obj->state != NULL) {
        free(obj->state);
        obj->state = NULL;
    }
    return NGX_OK;
}

static ssize_t
sd_http_pread(xrootd_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    sd_http_inst_state *is = obj->inst->state;
    sd_http_obj_state  *st = obj->state;
    xrootd_s3_resp_t    resp;
    char                errbuf[256], hdrs[SD_HTTP_AUTH_MAX + 80];
    const void         *body;
    size_t              blen = 0, n;
    int64_t             end;

    if (len == 0) {
        return 0;
    }
    if (len > (size_t) SD_HTTP_PREAD_MAX) {
        len = (size_t) SD_HTTP_PREAD_MAX;
    }
    end = (int64_t) off + (int64_t) len - 1;
    snprintf(hdrs, sizeof(hdrs), "Range: bytes=%lld-%lld\r\n%s",
             (long long) off, (long long) end, is->auth_hdr);

    if (is->transport->request(is->tctx, is->host, is->port, is->tls, "GET",
                               st->path, hdrs, NULL, 0, is->timeout_ms, &resp,
                               errbuf, sizeof(errbuf)) != 0)
    {
        errno = EIO;
        return -1;
    }
    if (resp.status == 416) {
        is->transport->resp_free(&resp);
        return 0;                              /* range past EOF → EOF (0) */
    }
    if (resp.status != 206 && resp.status != 200) {
        is->transport->resp_free(&resp);
        errno = (resp.status == 404) ? ENOENT : EIO;
        return -1;
    }
    body = is->transport->resp_body(&resp, &blen);
    if (body == NULL || blen == 0) {
        is->transport->resp_free(&resp);
        return 0;                              /* EOF / empty range */
    }

    /* 206 → body is exactly the requested range, starting at `off`. 200 → the
     * origin ignored the Range header and returned the WHOLE object from byte 0
     * (stock python http.server, some proxies), so the bytes we want begin at
     * `off` within `body`; past EOF that is a short read of 0. Slicing here keeps
     * a correct, terminating fill loop against either kind of origin. */
    if (resp.status == 200) {
        if ((size_t) off >= blen) {
            is->transport->resp_free(&resp);
            return 0;                          /* requested range past EOF */
        }
        body  = (const char *) body + off;
        blen -= (size_t) off;
    }
    n = (blen < len) ? blen : len;
    memcpy(buf, body, n);
    is->transport->resp_free(&resp);
    return (ssize_t) n;
}

static ngx_int_t
sd_http_fstat(xrootd_sd_obj_t *obj, xrootd_sd_stat_t *out)
{
    *out = obj->snap;
    return NGX_OK;
}

static ngx_int_t
sd_http_stat(xrootd_sd_instance_t *inst, const char *path,
    xrootd_sd_stat_t *out)
{
    sd_http_inst_state *is = inst->state;
    int64_t             size = 0;
    char                full[SD_HTTP_PATH_MAX];

    sd_http_full_path(is, path, full, sizeof(full));
    if (sd_http_head_size(is, full, &size) != 0) {
        return NGX_ERROR;                       /* errno set by head_size */
    }
    ngx_memzero(out, sizeof(*out));
    out->size   = (off_t) size;
    out->mode   = S_IFREG | 0444;
    out->is_reg = 1;
    return NGX_OK;
}

/* ---- write path (SP3): the HTTP origin as a writable cache / stage store. A
 * staged write buffers the object and PUTs it whole at commit (atomic from the
 * reader's view); unlink is a DELETE (eviction + post-flush stage cleanup). */

static xrootd_sd_staged_t *
sd_http_staged_open(xrootd_sd_instance_t *inst, const char *final_path,
    mode_t mode, int *err_out)
{
    sd_http_inst_state   *is = inst->state;
    sd_http_staged_state *ss;
    xrootd_sd_staged_t   *h;

    (void) mode;
    ss = calloc(1, sizeof(*ss));
    h  = calloc(1, sizeof(*h));
    if (ss == NULL || h == NULL) {
        free(ss);
        free(h);
        if (err_out) { *err_out = ENOMEM; }
        return NULL;
    }
    sd_http_full_path(is, final_path, ss->path, sizeof(ss->path));
    h->inst  = inst;
    h->state = ss;
    return h;
}

static ssize_t
sd_http_staged_write(xrootd_sd_staged_t *h, const void *buf, size_t len,
    off_t off)
{
    sd_http_staged_state *ss = h->state;

    /* Sequential append only (whole-object PUT has no random write). */
    if ((size_t) off != ss->len) {
        errno = ESPIPE;
        return -1;
    }
    if (ss->len + len > ss->cap) {
        size_t  ncap = ss->cap ? ss->cap * 2 : (1u << 20);
        u_char *nbuf;

        while (ncap < ss->len + len) {
            ncap *= 2;
        }
        nbuf = realloc(ss->buf, ncap);
        if (nbuf == NULL) {
            errno = ENOMEM;
            return -1;
        }
        ss->buf = nbuf;
        ss->cap = ncap;
    }
    ngx_memcpy(ss->buf + ss->len, buf, len);
    ss->len += len;
    return (ssize_t) len;
}

static ngx_int_t
sd_http_staged_commit(xrootd_sd_staged_t *h, int noreplace)
{
    sd_http_staged_state *ss = h->state;
    sd_http_inst_state   *is = h->inst->state;
    xrootd_s3_resp_t      resp;
    char                  errbuf[256];
    ngx_int_t             rc = NGX_OK;

    (void) noreplace;                          /* HTTP PUT always replaces */
    if (is->transport->request(is->tctx, is->host, is->port, is->tls, "PUT",
                               ss->path, is->auth_hdr[0] ? is->auth_hdr : NULL,
                               ss->buf, ss->len, is->timeout_ms, &resp,
                               errbuf, sizeof(errbuf)) != 0)
    {
        free(ss->buf);
        free(ss);
        free(h);
        errno = EIO;
        return NGX_ERROR;
    }
    if (resp.status != 200 && resp.status != 201 && resp.status != 204) {
        errno = (resp.status == 403 || resp.status == 401) ? EACCES : EIO;
        rc = NGX_ERROR;
    }
    is->transport->resp_free(&resp);
    free(ss->buf);
    free(ss);
    free(h);
    return rc;
}

static void
sd_http_staged_abort(xrootd_sd_staged_t *h)
{
    sd_http_staged_state *ss = h->state;

    free(ss->buf);
    free(ss);
    free(h);
}

static ngx_int_t
sd_http_unlink(xrootd_sd_instance_t *inst, const char *path, int is_dir)
{
    sd_http_inst_state *is = inst->state;
    xrootd_s3_resp_t    resp;
    char                errbuf[256], full[SD_HTTP_PATH_MAX];

    (void) is_dir;
    sd_http_full_path(is, path, full, sizeof(full));
    if (is->transport->request(is->tctx, is->host, is->port, is->tls, "DELETE",
                               full, is->auth_hdr[0] ? is->auth_hdr : NULL,
                               NULL, 0, is->timeout_ms, &resp,
                               errbuf, sizeof(errbuf)) != 0)
    {
        errno = EIO;
        return NGX_ERROR;
    }
    /* Idempotent: 204/200 ok, 404 already gone. */
    if (resp.status != 204 && resp.status != 200 && resp.status != 404) {
        is->transport->resp_free(&resp);
        errno = EIO;
        return NGX_ERROR;
    }
    is->transport->resp_free(&resp);
    return NGX_OK;
}

/* Read + write: an HTTP/WebDAV origin as a read source and a writable cache_store /
 * stage_store (buffered whole-object PUT + DELETE). */
static const xrootd_sd_driver_t xrootd_sd_http_driver = {
    .name  = "http",
    .caps  = XROOTD_SD_CAP_RANGE_READ | XROOTD_SD_CAP_RANDOM_WRITE,
    .open  = sd_http_open,
    .close = sd_http_close,
    .pread = sd_http_pread,
    .fstat = sd_http_fstat,
    .stat  = sd_http_stat,
    .unlink        = sd_http_unlink,
    .staged_open   = sd_http_staged_open,
    .staged_write  = sd_http_staged_write,
    .staged_commit = sd_http_staged_commit,
    .staged_abort  = sd_http_staged_abort,
};

xrootd_sd_instance_t *
xrootd_sd_http_create(const xrootd_sd_http_cfg_t *cfg, ngx_log_t *log)
{
    xrootd_sd_instance_t *inst;
    sd_http_inst_state   *is;

    if (cfg == NULL || cfg->host == NULL || cfg->host[0] == '\0'
        || cfg->port <= 0 || cfg->port > 65535 || cfg->transport == NULL)
    {
        errno = EINVAL;
        return NULL;
    }
    inst = calloc(1, sizeof(*inst));
    is   = calloc(1, sizeof(*is));
    if (inst == NULL || is == NULL) {
        free(inst);
        free(is);
        errno = ENOMEM;
        return NULL;
    }
    snprintf(is->host, sizeof(is->host), "%s", cfg->host);
    is->port = cfg->port;
    is->tls  = cfg->tls;
    snprintf(is->base_path, sizeof(is->base_path), "%s",
             (cfg->base_path != NULL) ? cfg->base_path : "");
    is->transport  = cfg->transport;
    is->tctx       = cfg->tctx;
    is->timeout_ms = (cfg->timeout_ms > 0) ? cfg->timeout_ms : 60000;
    if (cfg->bearer_token != NULL && cfg->bearer_token[0] != '\0') {
        snprintf(is->auth_hdr, sizeof(is->auth_hdr),
                 "Authorization: Bearer %s\r\n", cfg->bearer_token);
    }

    inst->driver = &xrootd_sd_http_driver;
    inst->log    = log;
    inst->pool   = NULL;
    inst->state  = is;
    return inst;
}

void
xrootd_sd_http_destroy(xrootd_sd_instance_t *inst)
{
    if (inst == NULL) {
        return;
    }
    free(inst->state);
    free(inst);
}

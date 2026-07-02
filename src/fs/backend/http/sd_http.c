/*
 * sd_http.c — read-only HTTP(S) source storage driver (phase-63 C-4). See header.
 *
 * A thin driver over the injected xrootd_s3_transport_t (the same vtable the S3
 * driver uses): `open`/`stat` HEAD the URL for the size, `pread` issues a byte
 * Range GET. No SigV4, no auth — plain anonymous HTTP. No kernel fd ⇒ memory-served.
 */

#include "sd_http.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define SD_HTTP_PREAD_MAX  (8LL * 1024 * 1024)
#define SD_HTTP_BASE_MAX   512                  /* URL base path prefix */
#define SD_HTTP_PATH_MAX   2048                 /* full URL path = base + key */
#define SD_HTTP_AUTH_MAX   4160                 /* "Authorization: Bearer <tok>\r\n" */

/* One ranked origin endpoint (phase-68 T11). fail_score is an integer EWMA of
 * transport failures (0 = healthy, decays 7/8 per outcome); rank is the
 * selection preference the T19 policies write (0 = most preferred). */
typedef struct {
    char  host[256];
    int   port;
    int   tls;
    char  base_path[SD_HTTP_BASE_MAX];
    int   fail_score;
    _Atomic int rank;                 /* T19 selection preference; relaxed */
} sd_http_endpoint;

/* Health breaks ties inside a rank; a preferred-but-sick endpoint is only
 * overridden after ~16 consecutive failures — preference is policy, health
 * is protection (phase-68 T19 contract). */
#define SD_HTTP_RANK_WEIGHT 4096

typedef struct {
    sd_http_endpoint             eps[SD_HTTP_EP_MAX];
    int                          n_eps;
    const xrootd_s3_transport_t *transport;
    void                        *tctx;
    int                          timeout_ms;
    unsigned                     probe_tick;  /* half-open recovery probe clock */
    char                         auth_hdr[SD_HTTP_AUTH_MAX]; /* §14 bearer hdr or "" */
} sd_http_inst_state;

typedef struct {
    char key[SD_HTTP_PATH_MAX];    /* export-relative key (leading '/'); the
                                      full URL path is composed per endpoint */
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

/* Compose the WRITE-target URL path: writes (staged PUT, DELETE) always go
 * to endpoint 0 — failing a write over to another origin would split-brain
 * the store; read failover (sd_http_request_fo) never applies here. */
static void
sd_http_write_path(const sd_http_inst_state *is, const char *key, char *dst,
    size_t cap)
{
    snprintf(dst, cap, "%s%s", is->eps[0].base_path,
             (key != NULL && key[0]) ? key : "/");
}

/* Effective pick score: policy rank first, health inside a rank. */
static int
sd_http_ep_score(const sd_http_endpoint *ep)
{
    return atomic_load_explicit((_Atomic int *) &ep->rank,
                                memory_order_relaxed)
         * SD_HTTP_RANK_WEIGHT + ep->fail_score;
}

/* Pick the best endpoint (lowest effective score, order-stable ties). */
static sd_http_endpoint *
sd_http_pick(sd_http_inst_state *is)
{
    sd_http_endpoint *best = &is->eps[0];
    int               i;

    for (i = 1; i < is->n_eps; i++) {
        if (sd_http_ep_score(&is->eps[i]) < sd_http_ep_score(best)) {
            best = &is->eps[i];
        }
    }
    return best;
}

/* Rank-preferred endpoint ignoring health — the half-open probe target. */
static sd_http_endpoint *
sd_http_preferred(sd_http_inst_state *is)
{
    sd_http_endpoint *best = &is->eps[0];
    int               i;

    for (i = 1; i < is->n_eps; i++) {
        if (atomic_load_explicit(&is->eps[i].rank, memory_order_relaxed)
            < atomic_load_explicit(&best->rank, memory_order_relaxed))
        {
            best = &is->eps[i];
        }
    }
    return best;
}

/* Record one transport outcome: score = score*7/8 + (ok ? 0 : 256). */
static void
sd_http_score(sd_http_endpoint *ep, int ok)
{
    ep->fail_score = ep->fail_score * 7 / 8 + (ok ? 0 : 256);
}

/* One request with read-failover (phase-68 T11): try the best endpoint, then
 * ONE alternate on a TRANSPORT failure (an HTTP 4xx is NOT a transport
 * failure — the object genuinely isn't there; do not mask it by failing
 * over). `extra_hdrs` is the pre-joined header block (Range and/or auth).
 * On success *used (when non-NULL) names the endpoint that answered. */
static int
sd_http_request_fo(sd_http_inst_state *is, const char *method, const char *key,
    const char *extra_hdrs, xrootd_s3_resp_t *resp, sd_http_endpoint **used)
{
    sd_http_endpoint *ep = sd_http_pick(is);
    sd_http_endpoint *first;
    char              full[SD_HTTP_PATH_MAX], errbuf[256];
    int               attempt, rc, i;

    /* Half-open recovery: scores only move on outcomes, so a benched origin
     * would stay benched forever. Every 4th request re-tries the rank-
     * preferred endpoint; a recovered origin earns its score back (and the
     * in-loop failover still answers the client if it is still down). */
    if (is->n_eps > 1 && (++is->probe_tick & 3u) == 0) {
        sd_http_endpoint *pref = sd_http_preferred(is);

        if (pref->fail_score > 0) {
            ep = pref;
        }
    }
    first = ep;

    for (attempt = 0; attempt < 2; attempt++) {
        snprintf(full, sizeof(full), "%s%s", ep->base_path,
                 (key != NULL && key[0]) ? key : "/");
        rc = is->transport->request(is->tctx, ep->host, ep->port, ep->tls,
                                    method, full, extra_hdrs, NULL, 0,
                                    is->timeout_ms, resp,
                                    errbuf, sizeof(errbuf));
        sd_http_score(ep, rc == 0);
        if (rc == 0) {
            if (used != NULL) {
                *used = ep;
            }
            return 0;
        }
        if (is->n_eps < 2) {
            break;
        }
        /* next-best endpoint distinct from the first attempt */
        ep = NULL;
        for (i = 0; i < is->n_eps; i++) {
            if (&is->eps[i] == first) {
                continue;
            }
            if (ep == NULL
                || sd_http_ep_score(&is->eps[i]) < sd_http_ep_score(ep))
            {
                ep = &is->eps[i];
            }
        }
        if (ep == NULL) {
            break;
        }
    }
    errno = EIO;
    return -1;
}

/* HEAD `key` → *size_out (−1 if no Content-Length). 0, or −1 with errno. */
static int
sd_http_head_size(sd_http_inst_state *is, const char *key, int64_t *size_out)
{
    xrootd_s3_resp_t resp;
    char             cl[32];

    if (sd_http_request_fo(is, "HEAD", key,
                           is->auth_hdr[0] ? is->auth_hdr : NULL,
                           &resp, NULL) != 0)
    {
        return -1;                              /* errno = EIO */
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

    (void) mode;

    /* Read-only source: refuse any write/create/trunc intent. */
    if (sd_flags & (XROOTD_SD_O_WRITE | XROOTD_SD_O_CREATE | XROOTD_SD_O_TRUNC
                    | XROOTD_SD_O_APPEND))
    {
        if (err_out) { *err_out = EROFS; }
        return NULL;
    }

    if (sd_http_head_size(is, path, &size) != 0) {
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
    snprintf(st->key, sizeof(st->key), "%s",
             (path != NULL && path[0]) ? path : "/");

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
    char                hdrs[SD_HTTP_AUTH_MAX + 80];
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

    if (sd_http_request_fo(is, "GET", st->key, hdrs, &resp, NULL) != 0) {
        return -1;                              /* errno = EIO */
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

    if (sd_http_head_size(is, path, &size) != 0) {
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
    sd_http_write_path(is, final_path, ss->path, sizeof(ss->path));
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
    if (is->transport->request(is->tctx, is->eps[0].host, is->eps[0].port,
                               is->eps[0].tls, "PUT",
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
    sd_http_write_path(is, path, full, sizeof(full));
    if (is->transport->request(is->tctx, is->eps[0].host, is->eps[0].port,
                               is->eps[0].tls, "DELETE",
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

/* ---- T19/T20 selection + introspection API -------------------------------- */

/* 1 iff `inst` is an sd_http instance (guards the accessors below). */
static int
sd_http_instance_is(const xrootd_sd_instance_t *inst)
{
    return inst != NULL && inst->driver == &xrootd_sd_http_driver;
}

/* Push selection ranks (rank 0 = most preferred; order = endpoint order).
 * Written on the event loop, read by fill threads — relaxed atomics. */
void
sd_http_set_ranks(xrootd_sd_instance_t *inst, const int *ranks, int n)
{
    sd_http_inst_state *is;
    int                 i;

    if (!sd_http_instance_is(inst)) {
        return;
    }
    is = inst->state;
    for (i = 0; i < is->n_eps && i < n; i++) {
        atomic_store_explicit(&is->eps[i].rank, ranks[i],
                              memory_order_relaxed);
    }
}

/* Endpoint inventory for the RTT prober (copies, no ngx types). */
int
sd_http_endpoint_list(xrootd_sd_instance_t *inst, char hosts[][256],
    int *ports, int max)
{
    sd_http_inst_state *is;
    int                 i, n;

    if (!sd_http_instance_is(inst)) {
        return 0;
    }
    is = inst->state;
    n = (is->n_eps < max) ? is->n_eps : max;
    for (i = 0; i < n; i++) {
        memcpy(hosts[i], is->eps[i].host, sizeof(is->eps[i].host));
        ports[i] = is->eps[i].port;
    }
    return n;
}

/* Endpoint count (0 for a non-http instance). */
int
sd_http_n_endpoints(xrootd_sd_instance_t *inst)
{
    return sd_http_instance_is(inst)
         ? ((sd_http_inst_state *) inst->state)->n_eps : 0;
}

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
    snprintf(is->eps[0].host, sizeof(is->eps[0].host), "%s", cfg->host);
    is->eps[0].port = cfg->port;
    is->eps[0].tls  = cfg->tls;
    snprintf(is->eps[0].base_path, sizeof(is->eps[0].base_path), "%s",
             (cfg->base_path != NULL) ? cfg->base_path : "");
    is->n_eps = 1;
    if (cfg->extra != NULL && cfg->n_extra > 0) {
        int i, n = cfg->n_extra;

        if (n > SD_HTTP_EP_MAX - 1) {
            n = SD_HTTP_EP_MAX - 1;
        }
        for (i = 0; i < n; i++) {
            const xrootd_sd_http_ep_cfg_t *ec = &cfg->extra[i];

            if (ec->host == NULL || ec->host[0] == '\0' || ec->port <= 0
                || ec->port > 65535)
            {
                continue;
            }
            snprintf(is->eps[is->n_eps].host, sizeof(is->eps[0].host), "%s",
                     ec->host);
            is->eps[is->n_eps].port = ec->port;
            is->eps[is->n_eps].tls  = ec->tls;
            snprintf(is->eps[is->n_eps].base_path,
                     sizeof(is->eps[0].base_path), "%s",
                     (ec->base_path != NULL) ? ec->base_path : "");
            is->n_eps++;
        }
    }
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

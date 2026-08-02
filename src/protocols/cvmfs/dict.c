/* dict.c — the phase-87 G3 trained shared-dictionary endpoint + wire coding.
 *
 * WHAT: GET/HEAD /cvmfs/<repo>/.cvmfs-dict/(current|<40-hex id>) (gated
 *       brix_cvmfs_dict, default off): lazily train a zstd dictionary per
 *       worker from a bounded sample of this repo's CACHE-RESIDENT CAS
 *       objects and serve it with its self-certifying id (X-Brix-Dict-Id =
 *       sha1 of the dict bytes). CAS GETs that carry a matching X-Brix-Dict
 *       request header may then be answered dict-coded (Content-Encoding:
 *       zstd-dict) when that is strictly smaller than identity.
 * WHY:  CVMFS repos are millions of SMALL similar objects (catalogs,
 *       manifests, headers) — per-object compression has nothing to seed
 *       from, but a dictionary trained on the corpus does. The coding is a
 *       reversible transform of the STORED bytes, so the client's CAS
 *       verify runs on exactly what it always ran on: a wrong or hostile
 *       dictionary can only FAIL decode (zstd embeds/checks the dictID),
 *       never emit wrong bytes — the client falls back to identity.
 * HOW:  training samples CACHE-RESIDENT objects only, enumerated through the
 *       cache tier's own adapter (brix_cstore_scan over the decorator's
 *       cstore — the sd chain's opendir forwards to the ORIGIN, which cannot
 *       list): COMPLETE objects under this repo's data/ of (0, 64KiB] are
 *       read into a bounded arena, then ZDICT-trained (shared/cvmfs/dict).
 *       The trained dict is cached per worker on lcf (COW after fork — no
 *       SHM, no new globals); a failed training is memoized with a
 *       retry-after so a cold or tiny repo cannot be used to hammer the
 *       sampler. Every failure path is fail-open to identity serving.
 */
#include "cvmfs.h"
#include "cvmfs_module_internal.h"

#include "cvmfs/dict/dict.h"
#include "core/http/http_headers.h"
#include "fs/backend/cache/sd_cache.h"     /* brix_sd_cache_cstore */
#include "fs/cache/cstore.h"
#include "fs/vfs/vfs.h"

#include <stdlib.h>
#include <string.h>

#define CVMFS_DICT_REPO_SLOTS      4     /* per-worker trained repos (LRU-free:
                                            first-come; extra repos serve
                                            identity — a cache serves O(few)
                                            hot repos in practice)            */
#define CVMFS_DICT_REPO_NAME_MAX   128
#define CVMFS_DICT_TRAIN_SAMPLES   256u  /* sample-count cap                  */
#define CVMFS_DICT_TRAIN_MIN       8u    /* below this ZDICT can't generalize */
#define CVMFS_DICT_SAMPLE_MAX      (64u * 1024u)        /* per-sample cap    */
#define CVMFS_DICT_ARENA_MAX       (8u * 1024u * 1024u) /* whole-corpus cap  */
#define CVMFS_DICT_RETRY_SEC       60    /* failed-training memo lifetime     */

/* One per-repo trained-dictionary slot (worker-private). */
typedef struct {
    char           repo[CVMFS_DICT_REPO_NAME_MAX];  /* fqrn, NUL-terminated */
    char           id[CVMFS_DICT_ID_HEXLEN + 1];    /* sha1 hex of bytes    */
    unsigned char *bytes;          /* malloc'd, worker lifetime              */
    size_t         len;            /* 0 = not trained (yet / failed)         */
    time_t         retry_at;       /* no re-train before this on failure     */
    unsigned       used:1;
} cvmfs_dict_entry_t;

typedef struct {
    cvmfs_dict_entry_t repos[CVMFS_DICT_REPO_SLOTS];
} cvmfs_dict_state_t;

static int
cvmfs_dict_hexlc(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

/* Find (or, when `create`, claim) the worker-private slot for this repo.
 * NULL when the table is full or the name is oversize — callers treat that
 * as "no dictionary" and serve identity. */
static cvmfs_dict_entry_t *
cvmfs_dict_slot(ngx_http_brix_cvmfs_loc_conf_t *lcf, const char *repo,
    size_t repo_len, int create)
{
    cvmfs_dict_state_t *st = lcf->cvmfs.dict_state;
    ngx_uint_t            i;

    if (repo_len == 0 || repo_len >= CVMFS_DICT_REPO_NAME_MAX) {
        return NULL;
    }
    if (st == NULL) {
        if (!create) {
            return NULL;
        }
        st = calloc(1, sizeof(*st));
        if (st == NULL) {
            return NULL;
        }
        lcf->cvmfs.dict_state = st;
    }
    for (i = 0; i < CVMFS_DICT_REPO_SLOTS; i++) {
        if (st->repos[i].used
            && strncmp(st->repos[i].repo, repo, repo_len) == 0
            && st->repos[i].repo[repo_len] == '\0')
        {
            return &st->repos[i];
        }
    }
    if (!create) {
        return NULL;
    }
    for (i = 0; i < CVMFS_DICT_REPO_SLOTS; i++) {
        if (!st->repos[i].used) {
            memcpy(st->repos[i].repo, repo, repo_len);
            st->repos[i].repo[repo_len] = '\0';
            st->repos[i].used = 1;
            return &st->repos[i];
        }
    }
    return NULL;
}

/* Scan state for one training pass (request-lifetime). */
typedef struct {
    brix_cstore_t *cs;
    const char      *repo;         /* NOT NUL-terminated — length-bounded  */
    size_t           repo_len;
    unsigned char   *arena;
    size_t           arena_used;
    size_t          *sizes;
    unsigned         n;
} cvmfs_dict_sample_ctx_t;

/* cstore visitor: read one COMPLETE resident CAS object of this repo into
 * the arena. Every skip is silent (never fatal); early-stops the scan once
 * the sample cap is reached. */
static ngx_int_t
cvmfs_dict_sample_visit(const char *key, const brix_cache_cinfo_t *ci,
    const brix_sd_stat_t *stx, void *ud)
{
    cvmfs_dict_sample_ctx_t *sc = ud;
    const char                *p = key;
    brix_sd_obj_t            *obj;
    size_t                     want, off;
    int                        verr = 0;

    if (ci == NULL || !(ci->flags & BRIX_CINFO_F_COMPLETE)) {
        return NGX_OK;                 /* orphan/partial — never sample */
    }
    if (*p == '/') {
        p++;
    }
    if (strncmp(p, "cvmfs/", sizeof("cvmfs/") - 1) != 0) {
        return NGX_OK;
    }
    p += sizeof("cvmfs/") - 1;
    if (strncmp(p, sc->repo, sc->repo_len) != 0
        || strncmp(p + sc->repo_len, "/data/", sizeof("/data/") - 1) != 0)
    {
        return NGX_OK;                 /* other repo / non-CAS entry */
    }
    if (stx == NULL
        || stx->size <= 0
        || (size_t) stx->size > CVMFS_DICT_SAMPLE_MAX
        || (size_t) stx->size > CVMFS_DICT_ARENA_MAX - sc->arena_used)
    {
        return NGX_OK;
    }
    want = (size_t) stx->size;

    obj = brix_cstore_serve_open(sc->cs, key, &verr);
    if (obj == NULL) {
        return NGX_OK;                 /* vanished under us — skip */
    }
    for (off = 0; off < want; ) {
        ssize_t rd = obj->driver->pread(obj, sc->arena + sc->arena_used + off,
                                        want - off, (off_t) off);
        if (rd <= 0) {
            brix_sd_obj_release(obj);
            return NGX_OK;             /* short read — discard sample */
        }
        off += (size_t) rd;
    }
    brix_sd_obj_release(obj);

    sc->sizes[sc->n++] = want;
    sc->arena_used    += want;
    return (sc->n >= CVMFS_DICT_TRAIN_SAMPLES) ? NGX_DONE : NGX_OK;
}

/* Train this repo's dictionary from resident CAS samples. On success the
 * entry holds malloc'd dict bytes + id; on any failure the entry stays
 * untrained with a retry-after memo. All scratch is request-pool, so an
 * aborted scan leaks nothing past the request. */
static void
cvmfs_dict_train_repo(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf, const char *repo, size_t repo_len,
    cvmfs_dict_entry_t *e)
{
    brix_sd_instance_t      *sd;
    brix_cstore_t           *cs;
    unsigned char             *arena, *dict_tmp;
    size_t                     sizes[CVMFS_DICT_TRAIN_SAMPLES];
    size_t                     dict_len = 0;
    size_t                     arena_used;
    unsigned                   n;
    cvmfs_dict_sample_ctx_t  sc;

    e->retry_at = ngx_time() + CVMFS_DICT_RETRY_SEC;   /* assume failure */

    sd = cvmfs_resolve_sd(r, lcf);
    cs = (sd != NULL) ? brix_sd_cache_cstore(sd) : NULL;
    if (cs == NULL) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "cvmfs-dict: repo=%*s not trained (no cache tier to sample)",
            repo_len, repo);
        return;
    }

    arena = ngx_pnalloc(r->pool, CVMFS_DICT_ARENA_MAX);
    dict_tmp = ngx_pnalloc(r->pool, CVMFS_DICT_TARGET_BYTES);
    if (arena == NULL || dict_tmp == NULL) {
        return;
    }

    ngx_memzero(&sc, sizeof(sc));
    sc.cs       = cs;
    sc.repo     = repo;
    sc.repo_len = repo_len;
    sc.arena    = arena;
    sc.sizes    = sizes;
    (void) brix_cstore_scan(cs, cvmfs_dict_sample_visit, &sc);
    n          = sc.n;
    arena_used = sc.arena_used;

    if (n < CVMFS_DICT_TRAIN_MIN) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "cvmfs-dict: repo=%*s not trained (resident samples=%ui < %ui)",
            repo_len, repo, (ngx_uint_t) n, (ngx_uint_t) CVMFS_DICT_TRAIN_MIN);
        return;
    }

    if (cvmfs_dict_train(arena, sizes, n, dict_tmp,
                         CVMFS_DICT_TARGET_BYTES, &dict_len) != 0
        || cvmfs_dict_id(dict_tmp, dict_len, e->id) != 0)
    {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "cvmfs-dict: repo=%*s training failed (samples=%ui bytes=%uz)",
            repo_len, repo, (ngx_uint_t) n, arena_used);
        return;
    }

    e->bytes = malloc(dict_len);
    if (e->bytes == NULL) {
        return;
    }
    memcpy(e->bytes, dict_tmp, dict_len);
    e->len      = dict_len;
    e->retry_at = 0;

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "cvmfs-dict: repo=%*s trained id=%s bytes=%uz samples=%ui "
        "corpus=%uz", repo_len, repo, e->id, dict_len, (ngx_uint_t) n,
        arena_used);
}

/* Send `body` (worker-lifetime memory) as a 200 with the dict headers. */
static ngx_int_t
cvmfs_dict_send(ngx_http_request_t *r, cvmfs_dict_entry_t *e)
{
    ngx_chain_t  out;
    ngx_buf_t   *b;
    ngx_int_t    rc;

    r->headers_out.status           = NGX_HTTP_OK;
    r->headers_out.content_length_n = (off_t) e->len;
    ngx_str_set(&r->headers_out.content_type, "application/octet-stream");
    r->headers_out.content_type_len = r->headers_out.content_type.len;
    if (brix_http_set_header(r, "X-Brix-Dict-Id", e->id, NULL) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    b->memory        = 1;
    b->pos           = e->bytes;
    b->last          = e->bytes + e->len;
    b->start         = b->pos;
    b->end           = b->last;
    b->last_buf      = 1;
    b->last_in_chain = 1;
    out.buf  = b;
    out.next = NULL;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
    return ngx_http_output_filter(r, &out);
}

ngx_int_t
brix_cvmfs_dict_handle(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf)
{
    ngx_http_brix_cvmfs_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_cvmfs_module);
    cvmfs_dict_entry_t          *e;
    const char                   *id;
    size_t                        id_len, i;
    int                           want_current;

    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* rel = ".cvmfs-dict/<id>"; <id> is "current" or a 40-hex dict id */
    id     = ctx->url.rel + sizeof(".cvmfs-dict/") - 1;
    id_len = ctx->url.rel_len - (sizeof(".cvmfs-dict/") - 1);
    want_current = (id_len == sizeof("current") - 1
                    && memcmp(id, "current", id_len) == 0);
    if (!want_current) {
        if (id_len != CVMFS_DICT_ID_HEXLEN) {
            return NGX_HTTP_BAD_REQUEST;
        }
        for (i = 0; i < id_len; i++) {
            if (!cvmfs_dict_hexlc(id[i])) {
                return NGX_HTTP_BAD_REQUEST;
            }
        }
    }

    e = cvmfs_dict_slot(lcf, ctx->url.repo, ctx->url.repo_len, 1);
    if (e == NULL) {
        return NGX_HTTP_NOT_FOUND;
    }

    if (e->len == 0) {
        if (ngx_time() < e->retry_at) {
            return NGX_HTTP_NOT_FOUND;      /* memoized failure — no retrain */
        }
        cvmfs_dict_train_repo(r, lcf, ctx->url.repo, ctx->url.repo_len, e);
        if (e->len == 0) {
            return NGX_HTTP_NOT_FOUND;
        }
    }

    if (!want_current
        && ngx_memcmp(id, e->id, CVMFS_DICT_ID_HEXLEN) != 0)
    {
        return NGX_HTTP_NOT_FOUND;          /* a superseded/foreign dict id */
    }

    return cvmfs_dict_send(r, e);
}

/* Stat the target and read it into fresh request-pool buffers (`*out` is
 * capped at srclen: the coded serve must WIN or compress fails).
 * -1 = identity serve. */
static int
cvmfs_dict_load(ngx_http_request_t *r, brix_vfs_file_t *fh,
    brix_vfs_stat_t *vst, size_t *srclen, unsigned char **src,
    unsigned char **out)
{
    size_t off, n;

    if (brix_vfs_file_stat(fh, vst) != NGX_OK
        || vst->is_directory
        || vst->size <= 0
        || (size_t) vst->size > CVMFS_DICT_MAX_OBJ)
    {
        return -1;
    }
    n = (size_t) vst->size;

    *src = ngx_pnalloc(r->pool, n);
    *out = ngx_pnalloc(r->pool, n);
    if (*src == NULL || *out == NULL) {
        return -1;
    }
    for (off = 0; off < n; ) {
        ssize_t rd = brix_vfs_file_pread(fh, *src + off, n - off, (off_t) off);
        if (rd <= 0) {
            return -1;
        }
        off += (size_t) rd;
    }
    *srclen = n;
    return 0;
}

/* Emit the committed dict-coded response (headers + single in-memory buf). */
static ngx_int_t
cvmfs_dict_emit(ngx_http_request_t *r, time_t mtime, const char *id,
    unsigned char *out, size_t srclen, size_t outlen)
{
    ngx_table_elt_t *h = NULL;
    ngx_chain_t      chain;
    ngx_buf_t       *b;
    ngx_int_t        rc;

    r->headers_out.status             = NGX_HTTP_OK;
    r->headers_out.content_length_n   = (off_t) outlen;
    r->headers_out.last_modified_time = mtime;
    ngx_str_set(&r->headers_out.content_type, "application/octet-stream");
    r->headers_out.content_type_len   = r->headers_out.content_type.len;

    if (brix_http_set_header(r, "Content-Encoding", "zstd-dict", &h) != NGX_OK
        || brix_http_set_header(r, "X-Brix-Dict-Id", id, NULL) != NGX_OK
        || brix_http_set_header(r, "Vary", "X-Brix-Dict", NULL) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    r->headers_out.content_encoding = h;

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    b->memory        = 1;
    b->pos           = out;
    b->last          = out + outlen;
    b->start         = b->pos;
    b->end           = b->last;
    b->last_buf      = 1;
    b->last_in_chain = 1;
    chain.buf  = b;
    chain.next = NULL;

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
        "cvmfs-dict: coded serve %uz -> %uz id=%s", srclen, outlen, id);

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
    return ngx_http_output_filter(r, &chain);
}

ngx_int_t
brix_cvmfs_dict_try_serve(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf, ngx_http_brix_cvmfs_ctx_t *ctx,
    brix_vfs_file_t *fh)
{
    cvmfs_dict_entry_t *e;
    brix_vfs_stat_t     vst;
    ngx_str_t           want;
    unsigned char      *src, *out;
    size_t              srclen, outlen = 0;

    if (!lcf->cvmfs.dict
        || r->method != NGX_HTTP_GET
        || ctx == NULL
        || ctx->url.cls != CVMFS_URL_CAS
        || r->headers_in.range != NULL)
    {
        return NGX_DECLINED;
    }

    want = brix_http_get_header(r, "X-Brix-Dict");
    if (want.len != CVMFS_DICT_ID_HEXLEN) {
        return NGX_DECLINED;
    }
    /* lookup only — the data path NEVER trains (bounded per-request work) */
    e = cvmfs_dict_slot(lcf, ctx->url.repo, ctx->url.repo_len, 0);
    if (e == NULL || e->len == 0
        || ngx_memcmp(want.data, e->id, CVMFS_DICT_ID_HEXLEN) != 0)
    {
        return NGX_DECLINED;      /* unknown/superseded id → identity serve */
    }

    if (cvmfs_dict_load(r, fh, &vst, &srclen, &src, &out) != 0) {
        return NGX_DECLINED;
    }

    if (cvmfs_dict_compress(e->bytes, e->len, src, srclen, out, srclen,
                            &outlen) != 0)
    {
        return NGX_DECLINED;      /* no gain (or error) → identity serve */
    }

    /* commit: from here the response is ours and fh is consumed */
    brix_vfs_close(fh, r->connection->log);

    return cvmfs_dict_emit(r, vst.mtime, e->id, out, srclen, outlen);
}

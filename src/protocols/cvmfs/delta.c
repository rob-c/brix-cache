/* delta.c — phase-87 G10 cross-revision delta transfer (server leg).
 *
 * WHAT: a CAS data GET carrying `X-Brix-Delta-Base: <40-hex>` (the sha1 of
 *       a CAS object the client already holds — typically the revision-N
 *       catalog while fetching the N+1 catalog) may be answered as a zstd
 *       DELTA of the target against that base (Content-Encoding: zstd-delta)
 *       when the base is cache-RESIDENT and the delta is strictly smaller
 *       than identity.  Gated brix_cvmfs_delta (default off).
 * WHY:  frequent-publish repos (nightlies, calibration) republish catalogs
 *       that are 99% identical to the previous revision; shipping the whole
 *       object every time is RTT+bandwidth waste the client can prove it
 *       doesn't need.  A delta against the client's own held base captures
 *       exactly the changed bytes.
 * HOW:  the delta IS the G3 dictionary codec with the base object as a raw-
 *       content zstd dictionary (cvmfs_dict_compress — zstd loads non-ZDICT
 *       bytes as a raw prefix, i.e. patch-from semantics), so no new codec
 *       exists.  The base is resolved through the cache tier's own cstore
 *       (cinfo COMPLETE + serve_open): a miss NEVER fans out to the origin —
 *       this endpoint cannot amplify one GET into extra origin fetches, the
 *       client just gets the whole object (NGX_DECLINED ⇒ identity serve).
 *       TRUST IS UNCHANGED: the coding is a reversible transform of the
 *       STORED bytes, and a raw-content dictionary has no embedded dictID,
 *       so a client reconstructing against the wrong base gets bytes whose
 *       CAS hash does not match the name — its ordinary CAS verify rejects
 *       them and it refetches whole.  The delta path adds no trust surface;
 *       it only ever changes how many bytes cross the wire.
 */
#include "cvmfs.h"
#include "cvmfs_module_internal.h"

#include "cvmfs/dict/dict.h"
#include "core/http/http_headers.h"
#include "fs/backend/cache/sd_cache.h"     /* brix_sd_cache_cstore */
#include "fs/cache/cstore.h"
#include "fs/cache/cinfo.h"
#include "fs/vfs/vfs.h"

#include <stdio.h>
#include <string.h>

/* Base/target size cap: the win case is catalogs (100s of KiB — a few MiB);
 * 4 MiB each keeps base+target+output request-pool buffering bounded at
 * 12 MiB and both sides inside zstd level-19's 8 MiB match window without
 * advanced-parameter plumbing. */
#define CVMFS_DELTA_MAX_OBJ   (4u * 1024u * 1024u)
#define CVMFS_DELTA_HEXLEN    40u

static int
cvmfs_delta_hexlc(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

/* Read the whole resident base object into `buf` through the cstore's own
 * serve path (resident-only by construction). 0 on success, -1 on any
 * short/failed read — callers treat that as "no base" and serve identity. */
static int
cvmfs_delta_read_base(brix_cstore_t *cs, const char *key,
    unsigned char *buf, size_t len)
{
    brix_sd_obj_t *obj;
    size_t           off;
    int              verr = 0;

    obj = brix_cstore_serve_open(cs, key, &verr);
    if (obj == NULL) {
        return -1;
    }
    for (off = 0; off < len; ) {
        ssize_t rd = obj->driver->pread(obj, buf + off, len - off, (off_t) off);
        if (rd <= 0) {
            brix_sd_obj_release(obj);
            return -1;
        }
        off += (size_t) rd;
    }
    brix_sd_obj_release(obj);
    return 0;
}

/* Parse + validate the opt-in header into `base_id` (NUL-terminated
 * lowercase 40-hex). -1 = no usable opt-in (identity serve); base == target
 * names a zero delta, so identity is already optimal there too. */
static int
cvmfs_delta_base_id(ngx_http_request_t *r, ngx_http_brix_cvmfs_ctx_t *ctx,
    char *base_id)
{
    ngx_str_t base;
    size_t    i;

    base = brix_http_get_header(r, "X-Brix-Delta-Base");
    if (base.len != CVMFS_DELTA_HEXLEN) {
        return -1;
    }
    for (i = 0; i < base.len; i++) {
        if (!cvmfs_delta_hexlc((char) base.data[i])) {
            return -1;
        }
    }
    if (ngx_memcmp(base.data, ctx->url.cas_hex, CVMFS_DELTA_HEXLEN) == 0) {
        return -1;
    }
    memcpy(base_id, base.data, CVMFS_DELTA_HEXLEN);
    base_id[CVMFS_DELTA_HEXLEN] = '\0';
    return 0;
}

/* Resolve the RESIDENT base: cache store, per-repo key and COMPLETE bounded
 * cinfo. NULL = no usable base (identity serve) — a miss NEVER fans out. */
static brix_cstore_t *
cvmfs_delta_resolve_base(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf, ngx_http_brix_cvmfs_ctx_t *ctx,
    const char *base_id, char *basekey, size_t keycap, size_t *baselen)
{
    brix_sd_instance_t *sd;
    brix_cstore_t      *cs;
    brix_cache_cinfo_t  ci;

    sd = cvmfs_resolve_sd(r, lcf);
    cs = (sd != NULL) ? brix_sd_cache_cstore(sd) : NULL;
    if (cs == NULL) {
        return NULL;
    }

    /* The base inherits the TARGET's suffix class: a catalog's (…C) delta
     * base is the previous catalog, a plain chunk's base a plain chunk. */
    if ((size_t) snprintf(basekey, keycap,
                          "/cvmfs/%.*s/data/%.2s/%.38s%.*s",
                          (int) ctx->url.repo_len, ctx->url.repo,
                          base_id, base_id + 2,
                          ctx->url.cas_suffix != 0 ? 1 : 0,
                          &ctx->url.cas_suffix) >= keycap)
    {
        return NULL;
    }

    /* Residency gate: COMPLETE cinfo, bounded size, NO origin fan-out. */
    if (brix_cstore_cinfo_load(cs, basekey, &ci) != NGX_OK
        || !(ci.flags & BRIX_CINFO_F_COMPLETE)
        || ci.size == 0
        || ci.size > CVMFS_DELTA_MAX_OBJ)
    {
        return NULL;
    }
    *baselen = (size_t) ci.size;
    return cs;
}

/* Stat the target and read base + target into fresh request-pool buffers
 * (`*out` is capped at srclen: the delta must WIN or compress fails).
 * -1 = identity serve. */
static int
cvmfs_delta_load(ngx_http_request_t *r, brix_cstore_t *cs,
    const char *basekey, size_t baselen, brix_vfs_file_t *fh,
    brix_vfs_stat_t *vst, size_t *srclen,
    unsigned char **basebuf, unsigned char **src, unsigned char **out)
{
    size_t off, n;

    if (brix_vfs_file_stat(fh, vst) != NGX_OK
        || vst->is_directory
        || vst->size <= 0
        || (size_t) vst->size > CVMFS_DELTA_MAX_OBJ)
    {
        return -1;
    }
    n = (size_t) vst->size;

    *basebuf = ngx_pnalloc(r->pool, baselen);
    *src     = ngx_pnalloc(r->pool, n);
    *out     = ngx_pnalloc(r->pool, n);
    if (*basebuf == NULL || *src == NULL || *out == NULL) {
        return -1;
    }

    if (cvmfs_delta_read_base(cs, basekey, *basebuf, baselen) != 0) {
        return -1;                /* vanished/short under us — identity serve */
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

/* Emit the committed delta-coded response (headers + single in-memory buf). */
static ngx_int_t
cvmfs_delta_emit(ngx_http_request_t *r, time_t mtime, const char *base_id,
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

    if (brix_http_set_header(r, "Content-Encoding", "zstd-delta", &h) != NGX_OK
        || brix_http_set_header(r, "X-Brix-Delta-Base", base_id, NULL) != NGX_OK
        || brix_http_set_header(r, "Vary", "X-Brix-Delta-Base", NULL) != NGX_OK)
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
        "cvmfs-delta: coded serve %uz -> %uz base=%s", srclen, outlen,
        base_id);

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
    return ngx_http_output_filter(r, &chain);
}

ngx_int_t
brix_cvmfs_delta_try_serve(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf, ngx_http_brix_cvmfs_ctx_t *ctx,
    brix_vfs_file_t *fh)
{
    brix_cstore_t   *cs;
    brix_vfs_stat_t  vst;
    unsigned char   *basebuf, *src, *out;
    char             basekey[512];
    char             base_id[CVMFS_DELTA_HEXLEN + 1];
    size_t           baselen, srclen, outlen = 0;

    if (!lcf->cvmfs.delta
        || r->method != NGX_HTTP_GET
        || ctx == NULL
        || ctx->url.cls != CVMFS_URL_CAS
        || ctx->url.cas_hex_len != CVMFS_DELTA_HEXLEN
        || r->headers_in.range != NULL)
    {
        return NGX_DECLINED;
    }

    if (cvmfs_delta_base_id(r, ctx, base_id) != 0) {
        return NGX_DECLINED;
    }

    cs = cvmfs_delta_resolve_base(r, lcf, ctx, base_id, basekey,
                                  sizeof(basekey), &baselen);
    if (cs == NULL) {
        return NGX_DECLINED;
    }

    if (cvmfs_delta_load(r, cs, basekey, baselen, fh, &vst, &srclen,
                         &basebuf, &src, &out) != 0)
    {
        return NGX_DECLINED;
    }

    if (cvmfs_dict_compress(basebuf, baselen, src, srclen, out, srclen,
                            &outlen) != 0)
    {
        return NGX_DECLINED;      /* no gain (or error) → identity serve */
    }

    /* commit: from here the response is ours and fh is consumed */
    brix_vfs_close(fh, r->connection->log);

    return cvmfs_delta_emit(r, vst.mtime, base_id, out, srclen, outlen);
}

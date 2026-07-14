/*
 * usermeta.c — S3 user-defined object metadata (x-amz-meta-*).
 *
 * WHAT: Persist the x-amz-meta-<name> headers a client sends on PutObject /
 *       CopyObject, and echo them back on GET/HEAD — the S3 user-metadata
 *       contract every SDK relies on, and the slot the advisory unix-attr codec
 *       (x-amz-meta-xrd-unixattr) rides in for object-store POSIX-attr parity.
 * WHY:  The gateway stored none, so metadata round-trips silently dropped. The
 *       backend-metadata-parity work needs a real S3 endpoint that keeps user
 *       metadata so the shared sd_s3 driver's get/set-meta validate end-to-end
 *       and the S3 export backend reaches getattr/xattr parity.
 * HOW:  The whole user-metadata set is one URL-encoded "k=v&k=v" blob stored in
 *       a dedicated xattr (user.s3.usermeta) beside the object, via the VFS
 *       xattr surface (impersonation-correct, exactly like object tagging in
 *       tagging.c). Keys are lowercased (AWS contract). Invisible to every other
 *       code path; no new on-disk structure.
 */

#include "s3.h"
#include "usermeta.h"
#include "core/compat/uri.h"
#include "fs/vfs/vfs.h"

#include <errno.h>
#include <string.h>

#define S3_USERMETA_XATTR    "user.s3.usermeta"
#define S3_USERMETA_PREFIX   "x-amz-meta-"
#define S3_USERMETA_BLOB_MAX 16384   /* AWS user-metadata limit is 2 KiB; generous */
#define S3_USERMETA_KV_MAX   2048

/*
 * s3_user_meta_vfs_ctx — transient VFS request descriptor for the (resolved,
 * confined) object path, so the metadata xattr ops route through the VFS xattr
 * surface (metrics + access-log + impersonation), exactly like s3_tag_vfs_ctx.
 */
static void
s3_user_meta_vfs_ctx(ngx_http_request_t *r, const char *fs_path,
    ngx_http_s3_loc_conf_t *cf, brix_vfs_ctx_t *vctx)
{
    ngx_http_s3_req_ctx_t *s3ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_s3_module);
    int is_tls = 0;

#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif

    brix_vfs_ctx_init(vctx, r->pool, r->connection->log, BRIX_PROTO_S3,
        cf->common.root_canon, cf->cache_root_canon, cf->common.allow_write,
        is_tls, (s3ctx != NULL) ? s3ctx->identity : NULL, fs_path);
}

/* Read the stored metadata blob into out (NUL-terminated). Returns length, 0 if
 * none, -1 on error (denied / missing object). */
static ssize_t
s3_user_meta_load(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    const char *fs_path, char *out, size_t outsz)
{
    brix_vfs_ctx_t vctx;
    ssize_t          n;

    s3_user_meta_vfs_ctx(r, fs_path, cf, &vctx);
    n = brix_vfs_getxattr(&vctx, S3_USERMETA_XATTR, out, outsz - 1);
    if (n < 0) {
        /* phase74-fp: ENOTSUP == EOPNOTSUPP on Linux but they are distinct
         * errnos on other POSIX systems — both are checked deliberately for
         * portability, so the "equivalent nested operands" finding is moot. */
        /* NOLINTNEXTLINE(misc-redundant-expression) */
        if (errno == ENODATA || errno == ENOTSUP || errno == EOPNOTSUPP) {
            return 0;   /* object readable, just carries no user metadata */
        }
        return -1;
    }
    out[n] = '\0';
    return n;
}

/* Persist the metadata blob beside the object. Returns NGX_OK / NGX_ERROR. */
static ngx_int_t
s3_user_meta_store(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf,
    const char *fs_path, const char *blob, size_t blob_len)
{
    brix_vfs_ctx_t vctx;

    s3_user_meta_vfs_ctx(r, fs_path, cf, &vctx);
    return brix_vfs_setxattr(&vctx, S3_USERMETA_XATTR, blob, blob_len, 0)
               == NGX_OK ? NGX_OK : NGX_ERROR;
}

/*
 * s3_user_meta_append_kv — append one already-lowercased key and its raw value
 * to the "k=v&k=v" blob under construction.
 *
 * WHAT: Emits a "&" separator (only when *pos already holds a prior pair), then
 *       the percent-encoded key, a "=", and the percent-encoded value, advancing
 *       *pos past the bytes written. Returns NGX_OK, or NGX_ERROR if any encode
 *       fails or the result would overflow the out/outsz buffer.
 * WHY:  Keeping the separator/encode/'='/encode arithmetic in one linear helper
 *       is what lets the header-scan loop stay under the complexity cap — the
 *       loop decides which headers qualify, this owns the byte-exact framing so
 *       '=', '&' and spaces can never break the stored form.
 * HOW:  1. When *pos is non-zero, bounds-check and write the '&' joiner.
 *       2. URL-encode the key (empty passthrough set) and bounds-checked copy it.
 *       3. Write the '=' delimiter.
 *       4. URL-encode the value and bounds-checked copy it.
 *       5. Publish the advanced cursor back through *pos.
 */
static ngx_int_t
s3_user_meta_append_kv(char *out, size_t outsz, size_t *pos,
    const char *klow, size_t knlen, const u_char *val, size_t vallen)
{
    char   enc[1024];
    size_t cursor = *pos;
    size_t n;

    if (cursor != 0) {
        if (cursor + 1 >= outsz) {
            return NGX_ERROR;
        }
        out[cursor++] = '&';
    }

    if (brix_http_urlencode((u_char *) klow, knlen, enc, sizeof(enc), "") < 0) {
        return NGX_ERROR;
    }
    n = ngx_strlen(enc);
    if (cursor + n + 1 >= outsz) {
        return NGX_ERROR;
    }
    ngx_memcpy(out + cursor, enc, n);
    cursor += n;
    out[cursor++] = '=';

    if (brix_http_urlencode(val, vallen, enc, sizeof(enc), "") < 0) {
        return NGX_ERROR;
    }
    n = ngx_strlen(enc);
    if (cursor + n >= outsz) {
        return NGX_ERROR;
    }
    ngx_memcpy(out + cursor, enc, n);
    cursor += n;

    *pos = cursor;
    return NGX_OK;
}

/*
 * s3_user_meta_blob_from_headers — collect every x-amz-meta-<name> request
 * header into one URL-encoded "k=v&k=v" blob (key lowercased, both components
 * percent-encoded so '=', '&' and spaces never break the stored form). Sets
 * *any when at least one header was found. Returns NGX_OK / NGX_ERROR (overflow).
 */
static ngx_int_t
s3_user_meta_blob_from_headers(ngx_http_request_t *r, char *out, size_t outsz,
    size_t *out_len, int *any)
{
    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *h    = part->elts;
    const size_t     plen = sizeof(S3_USERMETA_PREFIX) - 1;
    size_t           pos  = 0;
    ngx_uint_t       i;

    *any = 0;
    for (i = 0; /* void */; i++) {
        const u_char *kname;
        size_t        knlen, j;
        char          klow[256];

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h    = part->elts;
            i    = 0;
        }

        if (h[i].key.len <= plen
            || ngx_strncasecmp(h[i].key.data, (u_char *) S3_USERMETA_PREFIX,
                               plen) != 0)
        {
            continue;
        }

        kname = h[i].key.data + plen;
        knlen = h[i].key.len - plen;
        if (knlen == 0 || knlen >= sizeof(klow)) {
            continue;
        }
        if (h[i].value.len > S3_USERMETA_KV_MAX) {
            return NGX_ERROR;
        }
        for (j = 0; j < knlen; j++) {
            klow[j] = (char) ngx_tolower(kname[j]);
        }

        if (s3_user_meta_append_kv(out, outsz, &pos, klow, knlen,
                                   h[i].value.data, h[i].value.len) != NGX_OK)
        {
            return NGX_ERROR;
        }
        *any = 1;
    }

    out[pos]  = '\0';
    *out_len  = pos;
    return NGX_OK;
}

ngx_int_t
s3_apply_put_user_metadata(ngx_http_request_t *r, const char *fs_path,
    const char *root_canon)
{
    ngx_http_s3_loc_conf_t *cf =
        ngx_http_get_module_loc_conf(r, ngx_http_brix_s3_module);
    char   blob[S3_USERMETA_BLOB_MAX];
    size_t blob_len = 0;
    int    any      = 0;

    (void) root_canon;   /* cf carries the canonical root */

    if (s3_user_meta_blob_from_headers(r, blob, sizeof(blob), &blob_len, &any)
            != NGX_OK)
    {
        return NGX_ERROR;
    }
    if (!any) {
        return NGX_OK;   /* a plain PUT with no user metadata */
    }
    return s3_user_meta_store(r, cf, fs_path, blob, blob_len);
}

void
s3_echo_user_metadata(ngx_http_request_t *r, const char *fs_path)
{
    ngx_http_s3_loc_conf_t *cf =
        ngx_http_get_module_loc_conf(r, ngx_http_brix_s3_module);
    char    blob[S3_USERMETA_BLOB_MAX];
    ssize_t blen;
    char   *p, *amp;

    blen = s3_user_meta_load(r, cf, fs_path, blob, sizeof(blob));
    if (blen <= 0) {
        return;   /* error, denied, or no user metadata — nothing to echo */
    }

    p = blob;
    while (*p != '\0') {
        char  kbuf[256], vbuf[S3_USERMETA_KV_MAX + 1];
        char *eq;

        amp = strchr(p, '&');
        if (amp != NULL) {
            *amp = '\0';
        }
        eq = strchr(p, '=');
        if (eq != NULL) {
            *eq = '\0';
            if (brix_http_urldecode((u_char *) p, ngx_strlen(p), kbuf,
                    sizeof(kbuf), BRIX_URLDECODE_PLUS_TO_SPACE)
                        == BRIX_URLDECODE_OK
                && brix_http_urldecode((u_char *) (eq + 1),
                    ngx_strlen(eq + 1), vbuf, sizeof(vbuf),
                    BRIX_URLDECODE_PLUS_TO_SPACE) == BRIX_URLDECODE_OK
                && kbuf[0] != '\0')
            {
                /* The header NAME must outlive this stack frame: set_header
                 * copies the value but stores the key pointer as-is, so build
                 * "x-amz-meta-<name>" in the request pool. */
                size_t  pfx = sizeof(S3_USERMETA_PREFIX) - 1;
                size_t  klen = ngx_strlen(kbuf);
                u_char *hdr = ngx_pnalloc(r->pool, pfx + klen + 1);

                if (hdr != NULL) {
                    ngx_memcpy(hdr, S3_USERMETA_PREFIX, pfx);
                    ngx_memcpy(hdr + pfx, kbuf, klen);
                    hdr[pfx + klen] = '\0';
                    (void) s3_set_header(r, (const char *) hdr, vbuf);
                }
            }
        }
        if (amp == NULL) {
            break;
        }
        p = amp + 1;
    }
}

ngx_int_t
s3_user_meta_copy(ngx_http_request_t *r, const char *src_fs_path,
    const char *dst_fs_path)
{
    ngx_http_s3_loc_conf_t *cf =
        ngx_http_get_module_loc_conf(r, ngx_http_brix_s3_module);
    char    blob[S3_USERMETA_BLOB_MAX];
    ssize_t blen;

    blen = s3_user_meta_load(r, cf, src_fs_path, blob, sizeof(blob));
    if (blen <= 0) {
        return NGX_OK;   /* source carries none — nothing to copy */
    }
    return s3_user_meta_store(r, cf, dst_fs_path, blob, (size_t) blen);
}

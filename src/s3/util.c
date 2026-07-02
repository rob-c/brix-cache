/*
 * util.c - shared helpers: path resolve, ETag, error response.
 */

#include "s3.h"
#include "compat/etag.h"
#include "compat/http_headers.h"
#include "compat/http_xml.h"
#include "compat/integrity_info.h"
#include "compat/path.h"
#include "compat/xml.h"

#include <sys/stat.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * Build a transient S3 VFS request descriptor for an already-resolved confined
 * path.  Shared by the PUT (put.c) and POST-object (post_object.c) write paths,
 * which previously carried byte-identical private copies.  Pulls pool/log, the
 * TLS flag, and the authenticated identity from the request; roots and the
 * write gate from the loc-conf.  rootfd stays -1 (transient confined open).
 */
void
s3_build_vfs_ctx(ngx_http_request_t *r, const char *fs_path,
    ngx_http_s3_loc_conf_t *cf, xrootd_vfs_ctx_t *vctx)
{
    ngx_http_s3_req_ctx_t *s3ctx;
    int                    is_tls = 0;

    s3ctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_s3_module);

#if (NGX_HTTP_SSL)
    is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif

    xrootd_vfs_ctx_init(vctx, r->pool, r->connection->log, XROOTD_PROTO_S3,
        cf->common.root_canon, cf->cache_root_canon, cf->common.allow_write,
        is_tls, (s3ctx != NULL) ? s3ctx->identity : NULL, fs_path);
}

/*
 * Response header helper
 * */

/*
 * s3_set_header — allocate and set an HTTP response header.
 *
 * Thin wrapper around xrootd_http_set_header(). key must be a string
 * literal (hash=1 optimization). val is copied into the request pool.
 */
ngx_int_t
s3_set_header(ngx_http_request_t *r, const char *key, const char *val)
{
    return xrootd_http_set_header(r, key, val, NULL);
}

/*
 * Filesystem path resolution
 * */

int
/*
 * s3_resolve_key — resolve an S3 object key to a filesystem path.
 *
 * Steps:
 *   1. Strip leading slashes from the key (S3 URLs have /bucket/key).
 *   2. Prepend exactly one slash so decoded_path starts with /.
 *   3. Call xrootd_http_resolve_path() which canonicalizes, URL-decodes,
 *      and confines the path to root.
 *
 * Returns: 1 on success (path is confined), 0 if escape detected or
 * buffer overflow.
 */
s3_resolve_key(const char *root, const char *key, char *out, size_t outsz)
{
    char key_path[PATH_MAX];
    int  n;

    /* Strip leading slashes; prepend exactly one so decoded_path starts with /. */
    while (*key == '/')
        key++;

    n = snprintf(key_path, sizeof(key_path), "/%s", key);
    if (n < 0 || (size_t) n >= sizeof(key_path))
        return 0;

    return xrootd_http_resolve_path(root, key_path, out, outsz) == 0 ? 1 : 0;
}

/*
 * ETag generation  (synthetic: "mtime-size")
 * */

void
/*
 * s3_etag — generate an S3-style ETag from stat metadata.
 *
 * Format: "mtime-size" (quoted string containing modification time
 * and file size). This is a synthetic ETag since S3 normally uses
 * MD5 of content — here we use mtime+size as a stable identifier
 * consistent with XrdClS3 expectations.
 */
s3_etag(const struct stat *st, char *buf, size_t bufsz)
{
    xrootd_http_etag_str(buf, bufsz, st->st_mtime, st->st_size, 0);
}

/*
 * XML error response
 * */

ngx_int_t
/*
 * s3_send_xml_error — S3 wrapper around xrootd_http_send_xml_error.
 *
 * Delegates XML building and sending to the compat-layer helper; increments the
 * S3 internal-error metric on OOM so S3 callers don't need to track that case.
 */
s3_send_xml_error(ngx_http_request_t *r,
                   ngx_uint_t status,
                   const char *code,
                   const char *message)
{
    ngx_int_t  rc;

    rc = xrootd_http_send_xml_error(r, status, code, message);
    if (rc == NGX_HTTP_INTERNAL_SERVER_ERROR) {
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]);
    }
    return rc;
}

/*
 * s3_fail — bump the diagnostic events_total[event] counter, then send the S3 XML
 * error. Folds the recurring "metric-inc + return s3_send_xml_error(...)" idiom
 * into one call so the per-event metric and the error response can't drift apart.
 */
ngx_int_t
s3_fail(ngx_http_request_t *r, ngx_uint_t status, const char *code,
        const char *message, int event)
{
    XROOTD_S3_METRIC_INC(events_total[event]);
    return s3_send_xml_error(r, status, code, message);
}

/*
 * CRC-64/NVME object checksum (AWS x-amz-checksum-crc64nvme)
 * */

/*
 * s3_object_crc64nvme_b64 — compute (or cache-read) an object's CRC-64/NVME and
 * base64-encode it in the AWS x-amz-checksum-crc64nvme wire form.
 *
 * WHAT: Produces the 12-char base64 of the 8 big-endian CRC-64/NVME bytes for the
 *       open fd into out (needs >= 13 bytes). Uses the xattr integrity cache, so
 *       the value computed at upload time is reused on later reads.
 * WHY:  AWS S3 clients (SDK/CLI default integrity) send and expect this checksum;
 *       it is base64-of-bytes, NOT hex like the root:///WebDAV digest forms.
 * HOW:  xrootd_integrity_get_fd("crc64nvme") returns the 16-hex value (from cache
 *       or freshly computed); strtoull → uint64 → 8 big-endian bytes →
 *       ngx_encode_base64. cache_only=1 declines (NGX_DECLINED) on a cache miss
 *       instead of paying a full-file read — used on the GET/HEAD echo path.
 * Returns NGX_OK (out filled), NGX_DECLINED (cache_only miss), or NGX_ERROR.
 */
ngx_int_t
s3_object_crc64nvme_b64(ngx_http_request_t *r, int fd, const char *path,
    ngx_flag_t cache_only, char *out, size_t outsz)
{
    xrootd_integrity_info_t info;
    xrootd_integrity_opts_t iopts;
    uint64_t                crc;
    unsigned char           be[8];
    ngx_str_t               src, dst;
    ngx_int_t               rc;
    int                     i;

    if (out == NULL || outsz < (size_t) (ngx_base64_encoded_length(8) + 1)) {
        return NGX_ERROR;
    }

    ngx_memzero(&iopts, sizeof(iopts));
    iopts.allow_xattr_cache    = 1;
    iopts.update_xattr_cache   = cache_only ? 0 : 1;
    iopts.require_regular_file = 1;
    iopts.no_compute           = cache_only ? 1 : 0;

    rc = xrootd_integrity_get_fd(r->connection->log, fd, NULL, path, "crc64nvme",
                                 &iopts, &info);
    if (rc != NGX_OK) {
        return rc;   /* NGX_DECLINED (cache-only miss) or NGX_ERROR */
    }

    /* info.hex is the 16-char lowercase crc64nvme; convert to the raw u64 and
     * emit the 8 big-endian bytes base64-encoded (the AWS wire format). */
    crc = (uint64_t) strtoull(info.hex, NULL, 16);
    for (i = 0; i < 8; i++) {
        be[i] = (unsigned char) (crc >> (56 - 8 * i));
    }
    src.data = be;
    src.len  = sizeof(be);
    dst.data = (u_char *) out;
    ngx_encode_base64(&dst, &src);
    out[dst.len] = '\0';
    return NGX_OK;
}

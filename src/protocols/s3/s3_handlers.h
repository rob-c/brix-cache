/*
 * s3/s3_handlers.h
 *
 * Internal S3 sub-handler prototypes called from handler.c: object GET/HEAD,
 * the ListObjects V1/V2 handlers, and the directory-walk / listing building
 * blocks (list_walk.c, list_common.c) they share.  Split out of s3.h so the
 * S3 API surface is grouped by concern and each file is individually
 * reviewable.  Includes s3.h for the shared request/config/entry types.
 */

#ifndef NGX_HTTP_S3_HANDLERS_H
#define NGX_HTTP_S3_HANDLERS_H

#include "s3.h"

/* GET /bucket/key → file download */
ngx_int_t s3_handle_get(ngx_http_request_t *r,
                         const char *fs_path,
                         ngx_http_s3_loc_conf_t *cf);

/* GET /bucket/?list-type=2 → ListObjectsV2 */
ngx_int_t s3_handle_list(ngx_http_request_t *r,
                          ngx_http_s3_loc_conf_t *cf);

/* GET /bucket (no list-type) → ListObjects V1 (list_objects_v1.c). Shares the
 * s3_walk()/entry_cmp() walker with V2; differs only in marker pagination and
 * the V1 XML element names (Marker/NextMarker, no KeyCount/continuation token). */
ngx_int_t s3_handle_list_v1(ngx_http_request_t *r,
                          ngx_http_s3_loc_conf_t *cf);

/* HEAD /bucket → HeadBucket: 200 + x-amz-bucket-region, else 404 (object.c). */
ngx_int_t s3_handle_head_bucket(ngx_http_request_t *r,
                          ngx_http_s3_loc_conf_t *cf);

/* GET /bucket?location → GetBucketLocation XML for the configured region. */
ngx_int_t s3_handle_get_bucket_location(ngx_http_request_t *r,
                          ngx_http_s3_loc_conf_t *cf);

/* list_walk.c — directory walker and key comparator */

/*
 * Recursively scan dir_path (filesystem), appending object/CommonPrefix entries
 * into the growable `entries` array (elements are s3_entry_t) until it reaches
 * max_entries. key_prefix is the key path accumulated so far; filter_prefix/
 * delimiter apply the ListObjects prefix/delimiter semantics (NULL/"" = none).
 *
 * phase-45 W1: classification uses readdir d_type (an lstat fallback only on
 * DT_UNKNOWN), and NO size/mtime/etag stat is done here — those are filled
 * lazily by s3_entry_fill_stat() for the emitted page only.  Key strings are
 * pooled from entries->pool at their true length.  Directory sentinels are
 * omitted; symlinks are never listed or traversed.  Returns entries->nelts.
 */
int s3_walk(ngx_log_t *log, const char *root, const char *dir_path,
    const char *key_prefix, const char *filter_prefix, const char *delimiter,
    ngx_array_t *entries, int max_entries);
/* qsort(3) comparator: lexicographic strcmp on s3_entry_t.key (a char *). */
int entry_cmp(const void *a, const void *b);
/*
 * phase-45 W1: lazily fill size/mtime/etag for one emitted OBJECT entry by
 * lstat'ing (confined) root + "/" + e->key.  No-op for CommonPrefixes.  Returns
 * NGX_OK (filled) or NGX_DECLINED (entry vanished or is no longer a regular
 * file — the caller skips it, matching the eager walker's stat-failure skip).
 */
ngx_int_t s3_entry_fill_stat(ngx_pool_t *pool, ngx_log_t *log,
    const char *root, s3_entry_t *e);

/* list_common.c — building blocks shared verbatim by the V1/V2 list emitters
 * (they differ only in pagination param + a few element names). */

/* Parse `max-keys`, clamped to (0, default_max); default_max when absent/invalid
 * (1000 floor when default_max is non-positive). */
int s3_list_parse_max_keys(ngx_http_request_t *r, int default_max);

/* Acquire the sorted (key + is_prefix) listing for (root, prefix, delimiter):
 * per-worker cache or s3_walk()+qsort(entry_cmp), then cache it. *items and
 * *total describe a sorted array. NGX_OK, or NGX_ERROR on allocation failure. */
ngx_int_t s3_list_collect_sorted(ngx_http_request_t *r,
    ngx_http_s3_loc_conf_t *cf, const char *prefix, const char *delimiter,
    s3_entry_t **items, int *total);

/* Skip entries whose key <= start_after (NULL/"" = from start), then take up to
 * max_keys. Fills *start_idx and *end_idx; returns 1 if truncated, else 0. */
int s3_list_paginate(const s3_entry_t *items, int total, const char *start_after,
    int max_keys, int *start_idx, int *end_idx);

/* Append the Contents/CommonPrefixes body for [start_idx, end_idx) into the flat
 * XML buffer (cursor *xml_len_io); lazily stats + skips vanished objects. Counts
 * land in *contents_out and *prefixes_out. NGX_OK, or 500 on buffer overflow. */
ngx_int_t s3_list_emit_entries(ngx_http_request_t *r,
    ngx_http_s3_loc_conf_t *cf, s3_entry_t *items, int start_idx, int end_idx,
    int url_encode, int fetch_owner, u_char *xml, size_t *xml_len_io,
    size_t xml_capacity, int *contents_out, int *prefixes_out);

/* Response tail: copy XML into a buffer, record list metrics, send as XML. */
ngx_int_t s3_list_finalize(ngx_http_request_t *r, const u_char *xml,
    size_t xml_len, int contents, int prefixes, int truncated);

/* HEAD /bucket/key → metadata */
ngx_int_t s3_handle_head(ngx_http_request_t *r,
                          const char *fs_path,
                          ngx_http_s3_loc_conf_t *cf);

#endif /* NGX_HTTP_S3_HANDLERS_H */

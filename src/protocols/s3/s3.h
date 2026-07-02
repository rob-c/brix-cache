/*
 * s3.h — internal types for the nginx S3-compatible object storage module.
 *
 * Implements the subset of the AWS S3 REST API used by XrdClS3 (the XRootD
 * S3 client plugin).  Clients talk path-style URLs:
 *
 *   GET  /bucket/key           → GetObject (file download)
 *   GET  /bucket/?list-type=2  → ListObjectsV2 (directory listing)
 *   HEAD /bucket/key           → HeadObject
 *   PUT  /bucket/key           → PutObject
 *   DELETE /bucket/key         → DeleteObject
 *
 * Authentication is AWS Signature Version 4 (HMAC-SHA256), optional.
 * If xrootd_s3_access_key is not configured, anonymous access is allowed.
 *
 * Directory sentinels: XrdClS3 marks directories by creating a zero-byte
 * object named ".xrdcls3.dirsentinel".  On a PUT of a sentinel the module
 * creates the parent directory on disk.  Sentinels are omitted from listings.
 */
/*
 * ============================================================
 * WHAT: Internal types and declarations for the S3-compatible module.
 * ============================================================
 *
 * This header is the API boundary between module.c (the nginx module entry)
 * point) and every S3 operation file (handler, get, put, list, multipart,
 * copy, delete_objects). All internal sub-handlers, metrics functions,
 * auth helpers, and utility declarations live here.
 *
 * The config struct ngx_http_s3_loc_conf_t carries per-location settings:
 * enable flag, filesystem root, bucket name to strip, SigV4 credentials,
 * allow_write gate, max_keys pagination limit, and the resolved canonical
 * root path.
 * ============================================================
 */

#ifndef NGX_HTTP_S3_H
#define NGX_HTTP_S3_H

#include <ngx_http.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <limits.h>
#include <sys/types.h>

#include <ngx_thread_pool.h>

#include "observability/metrics/metrics.h"
#include "core/compat/protocol_caps.h"
#include "fs/vfs/vfs.h"             /* xrootd_vfs_ctx_t for s3_build_vfs_ctx() */
#include "core/config/shared_conf.h"
#include "core/compat/namespace_ops.h"
#include "auth/authz/acc/acc.h"
#include "core/http/etag.h"
#include "core/compat/error_mapping.h"
#include "core/http/http_xml.h"
#include "core/compat/log.h"
#include "core/compat/range.h"
#include "core/compat/time.h"
#include "core/compat/uri.h"
#include "core/compat/xml.h"
#include "core/types/identity.h"

/* -------------------------------------------------------------------------
 * Configuration
 * ---------------------------------------------------------------------- */

typedef struct {
    ngx_http_xrootd_shared_conf_t common; /* enable, root, root_canon, allow_write,
                                             thread_pool_name, thread_pool */
    ngx_str_t    cache_root;  /* optional read-through cache root path */
    char         cache_root_canon[PATH_MAX]; /* canonical cache root; "" = disabled */
    ngx_str_t    bucket;      /* bucket name to strip from request path  */
    ngx_str_t    access_key;  /* AWS access key ID (empty → anonymous)   */
    ngx_str_t    secret_key;  /* AWS secret access key                   */
    ngx_str_t    region;      /* region for SigV4 scope (default "us-east-1") */
    ngx_flag_t   allow_unsigned_session_token; /* accept STS token with static secret */
    ngx_flag_t   verify_chunk_signatures; /* W6a: cryptographically verify the
                                           * per-chunk SigV4 signature on
                                           * aws-chunked streaming uploads
                                           * (default off; reject ⇒ 403) */
    ngx_flag_t   list_cache;     /* W6c: cache sorted ListObjects results per
                                  * worker (default off) */
    ngx_msec_t   list_cache_ttl; /* W6c: staleness bound for a cached listing */
    ngx_int_t    max_keys;    /* max objects per list page (default 1000)*/
    ngx_int_t    mpu_max_age; /* [xrootd_s3_mpu_max_age 0] Phase 39 (WS8): seconds
                                 a multipart staging dir may be idle before the
                                 incomplete-MPU reaper (run on InitiateMultipart)
                                 removes it.  0 = disabled.  Recommended 604800
                                 (7d, AWS-parity). */

    /* ---- ZIP member access (phase-57 W2) ----
     * [xrootd_s3_zip_access on|off] — opt-in, off by default.  A GetObject whose
     * query carries "?xrdcl.unzip=<member>" serves that member of the archive
     * object (stored + deflate).  zip_cd_max_bytes caps the central-directory
     * read (bomb guard; default 16 MiB). */
    ngx_flag_t   zip_access;
    size_t       zip_cd_max_bytes;

    /* ---- XrdAcc authorization engine (off by default) ---- */
    xrootd_acc_http_t  acc;    /* settings + per-worker state */
} ngx_http_s3_loc_conf_t;

typedef struct {
    char               fs_path[PATH_MAX];
    xrootd_identity_t *identity;
    /* W6b: PutObject with `If-None-Match: *` — commit must be atomic
     * create-if-absent (renameat2 RENAME_NOREPLACE); EEXIST → 412. */
    unsigned           exclusive_create:1;
    /* W6a: SigV4 material retained from auth so the aws-chunked decoder can
     * verify each chunk's signature.  Set only when a signed request was
     * authenticated (have_sigv4=1); the streaming verifier needs the seed
     * signature + signing key + scope/date that auth computed and would
     * otherwise discard. */
    unsigned           have_sigv4:1;
    u_char             sigv4_signing_key[32];
    char               sigv4_seed_signature[65]; /* hex, 64 chars + NUL  */
    char               sigv4_amz_date[32];        /* YYYYMMDDTHHMMSSZ     */
    char               sigv4_scope[96];           /* date/region/s3/aws4_request */
} ngx_http_s3_req_ctx_t;

/* Sentinel filename created by XrdClS3 mkdir */
#define S3_DIR_SENTINEL ".xrdcls3.dirsentinel"

/* Max object key length (maps to filesystem path) */
#define S3_MAX_KEY  4096

/* Max query param value length */
#define S3_MAX_PARAM 2048

/* Max entries collected by s3_walk before sorting/pagination */
#define S3_LIST_MAX_ENTRIES  65536

/*
 * S3 list query parse policy (shared by V1/V2 and list_common.c): URL-decode the
 * value, + → space, reject embedded NUL, allow an empty value (e.g. delimiter=).
 * Expands to XROOTD_HTTP_QUERY_* flags — callers must include compat/http_query.h.
 */
#define S3_LIST_QUERY_FLAGS \
    (XROOTD_HTTP_QUERY_DECODE_VALUE | XROOTD_HTTP_QUERY_PLUS_TO_SPACE \
     | XROOTD_HTTP_QUERY_REJECT_NUL | XROOTD_HTTP_QUERY_ALLOW_EMPTY)

/*
 * s3_entry_t — one object or CommonPrefix returned by ListObjects (V1/V2).
 * is_prefix == 1 means this entry represents a directory delimiter
 * (e.g. "photos/" when delimiter="/"), not an actual file.
 *
 * phase-45 W1: `key` is a pool-allocated, right-sized string — NOT an inline
 * 4 KiB buffer — so a growable array of these costs O(actual key bytes), not a
 * fixed 273 MB.  `size`/`mtime`/`etag` are filled LAZILY (s3_entry_fill_stat),
 * only for the entries actually emitted on the requested page, never for the
 * whole walked subtree.
 */
typedef struct {
    char    *key;
    unsigned is_prefix;
    off_t    size;
    time_t   mtime;
    char     etag[48];
} s3_entry_t;

/*
 * XML_APPEND / XML_APPEND_ELEM — flat-buffer XML building macros.
 *
 * Both reference local variables `xml` (u_char *), `xml_len` (size_t),
 * and `xml_capacity` (size_t) that must be in scope at each call site.
 * On overflow or encode error the macro returns NGX_HTTP_INTERNAL_SERVER_ERROR.
 */
#define XML_APPEND(fmt, ...) do { \
    int _xml_n = snprintf((char *) xml + xml_len, xml_capacity - xml_len, \
                          fmt, ##__VA_ARGS__); \
    if (_xml_n < 0 || (size_t) _xml_n >= xml_capacity - xml_len) { \
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]); \
        return NGX_HTTP_INTERNAL_SERVER_ERROR; \
    } \
    xml_len += (size_t) _xml_n; \
} while (0)

#define XML_APPEND_ELEM(name, value, value_len) do { \
    size_t _xml_written; \
    if (xrootd_xml_write_text_element((name), \
            (const unsigned char *)(value), (value_len), \
            XROOTD_XML_ESCAPE_APOS_ENTITY, \
            xml + xml_len, xml_capacity - xml_len, \
            &_xml_written) != 0) \
    { \
        XROOTD_S3_METRIC_INC(events_total[XROOTD_S3_EVENT_INTERNAL_ERROR]); \
        return NGX_HTTP_INTERNAL_SERVER_ERROR; \
    } \
    xml_len += _xml_written; \
} while (0)

/* -------------------------------------------------------------------------
 * Module symbol (defined in module.c, referenced by handler/put)
 * ---------------------------------------------------------------------- */

extern ngx_module_t ngx_http_xrootd_s3_module;

/* Operation Registry (operation_table.c) */
extern const xrootd_http_operation_t xrootd_s3_operations[];
extern const ngx_uint_t xrootd_s3_operations_count;

/*
 * Confined filesystem operations (defined in path/resolve_confined_ops.c).
 * All take a PRE-CANONICALIZED root (root_canon) and an already-resolved
 * absolute path; they re-enforce root confinement at the kernel layer
 * (openat2 RESOLVE_BENEATH, with O_NOFOLLOW parent-fd + *at() fallback) so
 * a symlink swapped in after path resolution cannot escape root.  Each sets
 * errno on failure.
 */

/* Open a file under confinement. Returns an fd (NOT pool-managed — caller
 * must close()) or -1 on error. flags/mode as for open(2). */
int xrootd_open_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, int flags, mode_t mode);
/* unlinkat() under confinement; is_dir != 0 → AT_REMOVEDIR. 0 ok, -1 error. */
int xrootd_unlink_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, int is_dir);
/* mkdirat() under confinement. Returns 0 on success, -1 on error. */
int xrootd_mkdir_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, mode_t mode);
/* renameat() with BOTH endpoints confined under the same root. 0 ok, -1 err. */
int xrootd_rename_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *src_resolved, const char *dst_resolved);
/* linkat() hard-link with BOTH endpoints confined under the same root.
 * Returns 0 on success, -1 on error. */
int xrootd_link_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *src_resolved, const char *dst_resolved);

/* -------------------------------------------------------------------------
 * Handler entry points (called from module.c)
 * ---------------------------------------------------------------------- */

/*
 * nginx CONTENT-phase handler for the whole S3 API. Parses URI → bucket+key,
 * verifies SigV4, then dispatches by method/query (list, get, head, put,
 * delete, multipart, copy). Returns NGX_DECLINED if S3 is disabled for the
 * location; otherwise an HTTP status or NGX_DONE (async PUT/POST body read).
 * Write ops are rejected (403) before body read when allow_write is off.
 */
ngx_int_t ngx_http_s3_handler(ngx_http_request_t *r);

/* -------------------------------------------------------------------------
 * Internal sub-handlers (called from handler.c)
 * ---------------------------------------------------------------------- */

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

/* -------------------------------------------------------------------------
 * Conditional requests + response-header overrides (conditional.c, phase-43 W3)
 * ---------------------------------------------------------------------- */

/*
 * Evaluate If-Match / If-None-Match / If-Modified-Since / If-Unmodified-Since
 * against the object's synthetic ETag (mtime+size) and mtime, with S3 semantics.
 * Returns NGX_DECLINED when the caller should proceed to serve (no conditional
 * headers, or all passed); otherwise a 304/412 response has already been sent
 * and the returned rc must be propagated by the caller.
 */
ngx_int_t s3_handle_conditional(ngx_http_request_t *r, time_t mtime, off_t size);

/*
 * Evaluate If-None-Match / If-Match on a PutObject before the body is read
 * (create-if-absent / overwrite-if-match).  Returns NGX_DECLINED to proceed, or
 * a 412 rc already sent to the client.
 */
ngx_int_t s3_put_precondition(ngx_http_request_t *r, const char *root_canon,
                          const char *fs_path);

/* True when a PutObject carries `If-None-Match: *` (atomic create-if-absent).
 * W6b: the commit then uses renameat2(RENAME_NOREPLACE) and maps EEXIST → 412. */
int s3_put_is_exclusive_create(ngx_http_request_t *r);

/* Apply response-content-type/-disposition/-encoding/-language/-cache-control/
 * -expires query overrides into headers_out (control bytes rejected). */
void s3_apply_response_overrides(ngx_http_request_t *r);

/* Serve pre-header hook (xrootd_http_pre_header_fn) that applies the response-*
 * overrides just before the GET response headers are sent. */
void s3_get_pre_header(ngx_http_request_t *r, ngx_fd_t fd, off_t file_size,
                          void *userdata);

/* DELETE /bucket/key */
ngx_int_t s3_handle_delete(ngx_http_request_t *r,
                             const char *fs_path,
                             ngx_http_s3_loc_conf_t *cf);

/* PUT body callback (registered by handler.c) */
void s3_put_body_handler(ngx_http_request_t *r);

/*
 * Resolve (and cache into the loc-conf) the async-I/O thread pool for this
 * location, mirroring the WebDAV COPY/MOVE lazy-resolution pattern (the S3
 * postconfiguration only resolves it for server-level confs, not location
 * blocks).  Returns NULL when no pool is available — callers then run the
 * blocking work synchronously on the event loop. (put.c)
 */
ngx_thread_pool_t *s3_thread_pool(ngx_http_s3_loc_conf_t *cf);

/* POST /bucket/ multipart/form-data browser upload */
void s3_post_object_body_handler(ngx_http_request_t *r);

/* -------------------------------------------------------------------------
 * Metrics
 * ---------------------------------------------------------------------- */

/* Resolve the request to its operation-table entry and return that op's
 * XROOTD_S3_METHOD_* slot, or XROOTD_S3_METHOD_OTHER if unmatched. */
ngx_uint_t s3_metrics_method_slot(ngx_http_request_t *r);
/* Increment requests_total[slot] (out-of-range slot clamped to OTHER). */
void s3_metrics_request_method(ngx_uint_t method_slot);
/* Increment responses_total[slot][status-class of http_status]; also feeds the
 * unified per-op metric. http_status is a real HTTP code, not a handler rc. */
void s3_metrics_response_status(ngx_uint_t method_slot, ngx_uint_t http_status);
/* Map handler_rc → effective HTTP status, then record the response counter.
 * No-op when handler_rc == NGX_DONE (async path counts in its own callback). */
void s3_metrics_response_method(ngx_http_request_t *r,
    ngx_uint_t method_slot, ngx_int_t handler_rc);
/* As s3_metrics_response_method() but returns handler_rc unchanged (call-site
 * convenience: `return s3_metrics_return_method(...);`). */
ngx_int_t s3_metrics_return_method(ngx_http_request_t *r,
    ngx_uint_t method_slot, ngx_int_t handler_rc);
/* As s3_metrics_response_method() then ngx_http_finalize_request(r, handler_rc).
 * Use from async body callbacks that own request finalization (no return). */
void s3_metrics_finalize_request_method(ngx_http_request_t *r,
    ngx_uint_t method_slot, ngx_int_t handler_rc);

/* -------------------------------------------------------------------------
 * Authentication
 * ---------------------------------------------------------------------- */

/*
 * Verify the AWS Signature Version 4 Authorization header.
 * Returns NGX_OK on success, NGX_HTTP_FORBIDDEN on failure.
 * If cf->access_key.len == 0, always returns NGX_OK (anonymous).
 */
ngx_int_t s3_verify_sigv4(ngx_http_request_t *r,
                           ngx_http_s3_loc_conf_t *cf,
                           xrootd_identity_t *identity);

/* -------------------------------------------------------------------------
 * XML helpers
 * ---------------------------------------------------------------------- */

/* Send a standard S3 XML error response */
ngx_int_t s3_send_xml_error(ngx_http_request_t *r,
                              ngx_uint_t status,
                              const char *code,
                              const char *message);

/* Increment the events_total[event] counter, then send the S3 XML error — the
 * common "bump a diagnostic metric and return an error" idiom in one call.
 * `event` is an XROOTD_S3_EVENT_* index. */
ngx_int_t s3_fail(ngx_http_request_t *r,
                  ngx_uint_t status,
                  const char *code,
                  const char *message,
                  int event);


/* -------------------------------------------------------------------------
 * Utility
 * ---------------------------------------------------------------------- */

/* Allocate and set a response header (key must be a string literal). */
ngx_int_t s3_set_header(ngx_http_request_t *r, const char *key,
    const char *val);


/*
 * Resolve a key to an absolute filesystem path.
 * Returns 1 on success, 0 if the key escapes the root or is invalid.
 * out must be at least PATH_MAX bytes.
 */
int s3_resolve_key(const char *root, const char *key, char *out, size_t outsz);

/* multipart.c */

/* Return 1 if <key> is present as a bare flag (no '=') in r->args, else 0. */
int s3_has_query_flag(ngx_http_request_t *r, const char *key);
/* Copy query parameter <key>'s value into out (NUL-terminated, truncated to
 * outsz). Returns 1 on success, 0 if absent or value empty. */
int s3_get_query_param(ngx_http_request_t *r, const char *key, char *out, size_t outsz);
/* Build the hidden MPU staging dir path (".<basename>.mpu-<upload_id>" beside
 * fs_path) into out_dir; always NUL-terminates within outsz. */
void s3_get_mpu_dir(const char *fs_path, const char *upload_id, char *out_dir, size_t outsz);
/* InitiateMultipartUpload: mint an opaque hex upload_id, create the confined
 * 0700 staging dir, send the XML result. Returns HTTP status (500 on error). */
ngx_int_t s3_handle_multipart_initiate(ngx_http_request_t *r, const char *fs_path, ngx_http_s3_loc_conf_t *cf, const char *key_str);
/* AbortMultipartUpload: validate upload_id, recursively remove staging dir.
 * Returns 204; 400 invalid id, 404 NoSuchUpload, 500 on removal failure. */
ngx_int_t s3_handle_multipart_abort(ngx_http_request_t *r, const char *fs_path, ngx_http_s3_loc_conf_t *cf, const char *upload_id);
/* CompleteMultipartUpload async body callback: concatenate part.1..part.N in
 * ascending order into a temp file, atomically rename to the object, best-effort
 * clean staging, send CompleteMultipartUploadResult XML. Owns finalization. */
void s3_multipart_complete_body_handler(ngx_http_request_t *r);
/* ListParts: enumerate staged "part.<N>" files, sort, paginate (part-number-marker
 * + max-parts), emit ListPartsResult XML. Returns HTTP status. */
ngx_int_t s3_handle_list_parts(ngx_http_request_t *r, const char *fs_path, ngx_http_s3_loc_conf_t *cf, const char *key_str);
/* ListMultipartUploads: scan bucket root for ".<key>.mpu-<id>" staging dirs,
 * sort by key, paginate, emit ListMultipartUploadsResult XML. Returns status. */
ngx_int_t s3_handle_list_multipart_uploads(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf);
/* UploadPartCopy: copy a confined source (x-amz-copy-source) into staged
 * part.<part_num>, emit CopyPartResult XML. Returns HTTP status (500 unlinks
 * the partial part). */
ngx_int_t s3_handle_upload_part_copy(ngx_http_request_t *r, const char *fs_path, ngx_http_s3_loc_conf_t *cf, const char *upload_id, int part_num);

/* copy.c */

/* CopyObject: server-side copy of x-amz-copy-source (confined) to dst_fs_path
 * via copy_file_range (read/write fallback), staged temp+rename. Emits
 * CopyObjectResult XML. Returns HTTP status. */
ngx_int_t s3_handle_copy_object(ngx_http_request_t *r, const char *dst_fs_path, ngx_http_s3_loc_conf_t *cf);

/* delete_objects.c */

/* DeleteObjects (POST ?delete) async body callback: parse the <Delete> XML
 * (max 1000 keys, 1 MiB body), unlink each (rmdir fallback for dirs), emit a
 * DeleteResult with per-key Deleted/Error. Owns request finalization. */
void s3_delete_objects_body_handler(ngx_http_request_t *r);

/*
 * Populate an ETag string (format: "\"mtime-size\"") for a stat result.
 * buf must be at least 40 bytes.
 */
void s3_etag(const struct stat *st, char *buf, size_t bufsz);

/* Initialise *vctx as a transient (rootfd=-1) S3 VFS request descriptor for the
 * already-resolved confined path fs_path, taking pool/log/TLS/identity from r
 * and roots/write-gate from cf.  Shared by the PUT and POST-object write paths. */
void s3_build_vfs_ctx(ngx_http_request_t *r, const char *fs_path,
    ngx_http_s3_loc_conf_t *cf, xrootd_vfs_ctx_t *vctx);

/* AWS S3 full-object checksum headers (this gateway supports CRC-64/NVME). */
#define S3_HDR_CHECKSUM_CRC64NVME  "x-amz-checksum-crc64nvme"
#define S3_HDR_CHECKSUM_TYPE       "x-amz-checksum-type"
/* base64 of 8 bytes = 12 chars + NUL; round up for safety. */
#define S3_CRC64NVME_B64_MAX       16

/*
 * Compute (or cache-read) an object's CRC-64/NVME for the open fd and base64-
 * encode the 8 big-endian bytes into out (>= S3_CRC64NVME_B64_MAX) — the AWS
 * x-amz-checksum-crc64nvme wire form. cache_only=1 returns NGX_DECLINED on a
 * cache miss instead of computing (read path). Returns NGX_OK / NGX_DECLINED /
 * NGX_ERROR.
 */
ngx_int_t s3_object_crc64nvme_b64(ngx_http_request_t *r, int fd,
    const char *path, ngx_flag_t cache_only, char *out, size_t outsz);

/* -------------------------------------------------------------------------
 * Multi-algorithm full-object checksums (checksum.c, phase-43 W1)
 * ---------------------------------------------------------------------- */

/* Declared request/echo headers for the additional AWS checksum algorithms. */
#define S3_HDR_SDK_CHECKSUM_ALGO  "x-amz-sdk-checksum-algorithm"
#define S3_HDR_CHECKSUM_MODE      "x-amz-checksum-mode"
/* base64(sha256)=44 chars + NUL; covers every supported algorithm. */
#define S3_CHECKSUM_B64_MAX       48

/* Outcome of s3_put_checksum_apply. */
typedef enum {
    S3_CKSUM_OK = 0,    /* verified or echoed                                  */
    S3_CKSUM_MISMATCH,  /* supplied value mismatched — object removed; 400     */
    S3_CKSUM_CONFLICT,  /* ambiguous / unsupported algorithm selection — 400   */
    S3_CKSUM_ERROR      /* our own compute failed — proceed without the header */
} s3_cksum_result_t;

/* Compute (or cache-read) alg_name for fd and base64-encode the raw digest into
 * out (>= S3_CHECKSUM_B64_MAX) — the AWS x-amz-checksum-* wire form.  Works for
 * crc32/crc32c/sha1/sha256/crc64nvme.  cache_only=1 → NGX_DECLINED on a miss. */
ngx_int_t s3_checksum_b64(ngx_http_request_t *r, int fd, const char *path,
    const char *alg_name, ngx_flag_t cache_only, char *out, size_t outsz);

/* Verify the client-selected full-object checksum (any supported algorithm) for
 * the just-committed object and echo it; see checksum.c for the result codes. */
s3_cksum_result_t s3_put_checksum_apply(ngx_http_request_t *r,
    const char *fs_path, const char *root_canon);

/* Verify+echo a checksum carried in an aws-chunked trailer (phase-43 W0); same
 * result contract as s3_put_checksum_apply. */
s3_cksum_result_t s3_put_trailer_checksum_apply(ngx_http_request_t *r,
    const char *fs_path, const char *root_canon, const char *algo_token,
    const char *value);

/* GET/HEAD echo: always emits a cached crc64nvme; with x-amz-checksum-mode:
 * ENABLED also emits every other cached algorithm. */
void s3_echo_object_checksums(ngx_http_request_t *r, int fd, const char *path);

#endif /* NGX_HTTP_S3_H */

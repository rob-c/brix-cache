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

#include "../metrics/metrics.h"
#include "../compat/protocol_caps.h"
#include "../config/shared_conf.h"
#include "../compat/namespace_ops.h"
#include "../compat/etag.h"
#include "../compat/error_mapping.h"
#include "../compat/http_xml.h"
#include "../compat/log.h"
#include "../compat/range.h"
#include "../compat/time.h"
#include "../compat/uri.h"
#include "../compat/xml.h"
#include "../types/identity.h"

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
    ngx_int_t    max_keys;    /* max objects per list page (default 1000)*/
} ngx_http_s3_loc_conf_t;

typedef struct {
    char               fs_path[PATH_MAX];
    xrootd_identity_t *identity;
} ngx_http_s3_req_ctx_t;

/* Sentinel filename created by XrdClS3 mkdir */
#define S3_DIR_SENTINEL ".xrdcls3.dirsentinel"

/* Max object key length (maps to filesystem path) */
#define S3_MAX_KEY  4096

/* Max query param value length */
#define S3_MAX_PARAM 2048

/* Max entries collected by s3_walk before sorting/pagination */
#define S3_LIST_MAX_ENTRIES  65536

/* One entry in a ListObjectsV2 response */
typedef struct {
    char    key[S3_MAX_KEY];
    int     is_prefix;
    off_t   size;
    time_t  mtime;
    char    etag[48];
} s3_entry_t;

/* s3_entry_t — one object or prefix returned by ListObjectsV2. is_prefix == 1 means this entry represents a directory delimiter (e.g. "photos/" when delimiter="/"), not an actual file. */

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

/* list_walk.c — directory walker and key comparator */

/*
 * Recursively scan dir_path (filesystem), appending objects/CommonPrefixes
 * into entries[] starting at *count, never exceeding max_entries. key_prefix
 * is the key path accumulated so far; filter_prefix/delimiter apply the
 * ListObjectsV2 prefix/delimiter semantics (NULL = none). Directory sentinels
 * are omitted. *count is advanced in place; returns the new total *count
 * (0 if dir_path cannot be opened). Best-effort: unreadable/overlong entries
 * are silently skipped.
 */
int s3_walk(const char *root, const char *dir_path, const char *key_prefix,
    const char *filter_prefix, const char *delimiter, s3_entry_t *entries,
    int max_entries, int *count);
/* qsort(3) comparator: lexicographic strcmp on s3_entry_t.key. */
int entry_cmp(const void *a, const void *b);

/* HEAD /bucket/key → metadata */
ngx_int_t s3_handle_head(ngx_http_request_t *r,
                          const char *fs_path,
                          ngx_http_s3_loc_conf_t *cf);

/* DELETE /bucket/key */
ngx_int_t s3_handle_delete(ngx_http_request_t *r,
                             const char *fs_path,
                             ngx_http_s3_loc_conf_t *cf);

/* PUT body callback (registered by handler.c) */
void s3_put_body_handler(ngx_http_request_t *r);

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

#endif /* NGX_HTTP_S3_H */

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

#ifndef NGX_HTTP_S3_H
#define NGX_HTTP_S3_H

#include <ngx_http.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <limits.h>
#include <sys/types.h>

#include "../metrics/metrics.h"

/* -------------------------------------------------------------------------
 * Configuration
 * ---------------------------------------------------------------------- */

typedef struct {
    ngx_flag_t   enable;
    ngx_str_t    root;        /* filesystem export root                  */
    ngx_str_t    bucket;      /* bucket name to strip from request path  */
    ngx_str_t    access_key;  /* AWS access key ID (empty → anonymous)   */
    ngx_str_t    secret_key;  /* AWS secret access key                   */
    ngx_str_t    region;      /* region for SigV4 scope (default "us-east-1") */
    ngx_flag_t   allow_write; /* allow PUT and DELETE                    */
    ngx_int_t    max_keys;    /* max objects per list page (default 1000)*/
    char         root_canon[PATH_MAX];
} ngx_http_s3_loc_conf_t;

/* Sentinel filename created by XrdClS3 mkdir */
#define S3_DIR_SENTINEL ".xrdcls3.dirsentinel"

/* Max object key length (maps to filesystem path) */
#define S3_MAX_KEY  4096

/* Max query param value length */
#define S3_MAX_PARAM 2048

/* -------------------------------------------------------------------------
 * Module symbol (defined in module.c, referenced by handler/put)
 * ---------------------------------------------------------------------- */

extern ngx_module_t ngx_http_xrootd_s3_module;

int xrootd_open_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, int flags, mode_t mode);
int xrootd_unlink_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, int is_dir);
int xrootd_mkdir_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, mode_t mode);
int xrootd_rename_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *src_resolved, const char *dst_resolved);
int xrootd_link_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *src_resolved, const char *dst_resolved);

/* -------------------------------------------------------------------------
 * Handler entry points (called from module.c)
 * ---------------------------------------------------------------------- */

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

/* -------------------------------------------------------------------------
 * Metrics
 * ---------------------------------------------------------------------- */

ngx_uint_t s3_metrics_method_slot(ngx_http_request_t *r);
void s3_metrics_request_method(ngx_uint_t method_slot);
void s3_metrics_response_status(ngx_uint_t method_slot, ngx_uint_t http_status);
void s3_metrics_response_method(ngx_http_request_t *r,
    ngx_uint_t method_slot, ngx_int_t handler_rc);
ngx_int_t s3_metrics_return_method(ngx_http_request_t *r,
    ngx_uint_t method_slot, ngx_int_t handler_rc);
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
                           ngx_http_s3_loc_conf_t *cf);

/* -------------------------------------------------------------------------
 * XML helpers
 * ---------------------------------------------------------------------- */

/* Send a standard S3 XML error response */
ngx_int_t s3_send_xml_error(ngx_http_request_t *r,
                              ngx_uint_t status,
                              const char *code,
                              const char *message);

/* Append XML-escaped string to buf */
void s3_xml_escape(ngx_buf_t *b, const u_char *s, size_t len);

/* -------------------------------------------------------------------------
 * Utility
 * ---------------------------------------------------------------------- */

/*
 * Resolve a key to an absolute filesystem path.
 * Returns 1 on success, 0 if the key escapes the root or is invalid.
 * out must be at least PATH_MAX bytes.
 */
int s3_resolve_key(const char *root, const char *key, char *out, size_t outsz);

/*
 * URL-decode src (application/x-www-form-urlencoded or percent-encoding)
 * into dst.  Returns the decoded length, or -1 on error.
 */
ssize_t s3_urldecode(const u_char *src, size_t slen, u_char *dst, size_t dsz);

/* multipart.c */
int s3_has_query_flag(ngx_http_request_t *r, const char *key);
int s3_get_query_param(ngx_http_request_t *r, const char *key, char *out, size_t outsz);
void s3_get_mpu_dir(const char *fs_path, const char *upload_id, char *out_dir, size_t outsz);
ngx_int_t s3_handle_multipart_initiate(ngx_http_request_t *r, const char *fs_path, ngx_http_s3_loc_conf_t *cf, const char *key_str);
ngx_int_t s3_handle_multipart_abort(ngx_http_request_t *r, const char *fs_path, ngx_http_s3_loc_conf_t *cf, const char *upload_id);
void s3_multipart_complete_body_handler(ngx_http_request_t *r);
ngx_int_t s3_handle_list_parts(ngx_http_request_t *r, const char *fs_path, ngx_http_s3_loc_conf_t *cf, const char *key_str);
ngx_int_t s3_handle_list_multipart_uploads(ngx_http_request_t *r, ngx_http_s3_loc_conf_t *cf);
ngx_int_t s3_handle_upload_part_copy(ngx_http_request_t *r, const char *fs_path, ngx_http_s3_loc_conf_t *cf, const char *upload_id, int part_num);

/*
 * Populate an ETag string (format: "\"mtime-size\"") for a stat result.
 * buf must be at least 40 bytes.
 */
void s3_etag(const struct stat *st, char *buf, size_t bufsz);

/*
 * Format a UTC timestamp from time_t as ISO 8601 (S3 format):
 * "2023-08-21T11:02:53.000Z"
 * buf must be at least 25 bytes.
 */
void s3_iso8601(time_t t, char *buf, size_t bufsz);

#endif /* NGX_HTTP_S3_H */

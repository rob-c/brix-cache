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
 * If brix_s3_access_key is not configured, anonymous access is allowed.
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
#include "fs/vfs/vfs.h"             /* brix_vfs_ctx_t for s3_build_vfs_ctx() */
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
#include "observability/sesslog/sesslog.h"

/* -------------------------------------------------------------------------
 * Configuration
 * ---------------------------------------------------------------------- */

typedef struct {
    ngx_http_brix_shared_conf_t common; /* enable, root, root_canon, allow_write,
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
    ngx_int_t    mpu_max_age; /* [brix_s3_mpu_max_age 0] Phase 39 (WS8): seconds
                                 a multipart staging dir may be idle before the
                                 incomplete-MPU reaper (run on InitiateMultipart)
                                 removes it.  0 = disabled.  Recommended 604800
                                 (7d, AWS-parity). */

    /* ---- ZIP member access (phase-57 W2) ----
     * [brix_s3_zip_access on|off] — opt-in, off by default.  A GetObject whose
     * query carries "?xrdcl.unzip=<member>" serves that member of the archive
     * object (stored + deflate).  zip_cd_max_bytes caps the central-directory
     * read (bomb guard; default 16 MiB). */
    ngx_flag_t   zip_access;
    size_t       zip_cd_max_bytes;

    /* ---- XrdAcc authorization engine (off by default) ---- */
    brix_acc_http_t  acc;    /* settings + per-worker state */

    /* ---- WLCG bearer-token authentication (off by default) ----
     * When brix_s3_token on, the auth gate in s3_verify_sigv4 intercepts Bearer
     * Authorization headers before SigV4; the two modes are mutually exclusive
     * per request (INVARIANT §6).  token_enable=1 makes the port enforcing: a
     * request that carries neither Bearer nor SigV4 credentials is rejected with
     * 403 AccessDenied rather than passing anonymously. */
    ngx_flag_t       token_enable;                /* brix_s3_token on|off           */
    ngx_str_t        token_jwks;                  /* path to JWKS public-key file    */
    ngx_str_t        token_issuer;                /* expected "iss" claim            */
    ngx_str_t        token_audience;              /* expected "aud" claim            */
    ngx_int_t        token_clock_skew;            /* exp/nbf grace period in seconds */
    brix_jwks_key_t  jwks_keys[BRIX_MAX_JWKS_KEYS]; /* loaded at config time        */
    int              jwks_key_count;              /* valid keys in jwks_keys[]       */
} ngx_http_s3_loc_conf_t;

typedef struct {
    char               fs_path[PATH_MAX];
    brix_identity_t *identity;
    /* Raw JWT bytes captured verbatim for backend PASSTHROUGH (phase-70 §5.4);
     * borrowed into r->pool by s3_verify_bearer, valid for the request. Empty
     * unless bearer auth succeeded. Never logged. */
    ngx_str_t          bearer_token;
    /* User-supplied full x509 proxy PEM (chain + key) captured from the
     * X-Brix-Delegate-Proxy header for backend PASSTHROUGH (phase-70 §5.1);
     * validated (TLS-only + leaf-DN==identity) at the auth gate, borrowed into
     * r->pool. Empty unless the client opted in. Never logged. */
    ngx_str_t          deleg_proxy_pem;
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
    brix_sess_xfer_t   sess_xfer;                 /* request data move audit */
    unsigned           sess_xfer_started:1;
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
 * Expands to BRIX_HTTP_QUERY_* flags — callers must include compat/http_query.h.
 */
#define S3_LIST_QUERY_FLAGS \
    (BRIX_HTTP_QUERY_DECODE_VALUE | BRIX_HTTP_QUERY_PLUS_TO_SPACE \
     | BRIX_HTTP_QUERY_REJECT_NUL | BRIX_HTTP_QUERY_ALLOW_EMPTY)

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
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]); \
        return NGX_HTTP_INTERNAL_SERVER_ERROR; \
    } \
    xml_len += (size_t) _xml_n; \
} while (0)

#define XML_APPEND_ELEM(name, value, value_len) do { \
    size_t _xml_written; \
    if (brix_xml_write_text_element((name), \
            (const unsigned char *)(value), (value_len), \
            BRIX_XML_ESCAPE_APOS_ENTITY, \
            xml + xml_len, xml_capacity - xml_len, \
            &_xml_written) != 0) \
    { \
        BRIX_S3_METRIC_INC(events_total[BRIX_S3_EVENT_INTERNAL_ERROR]); \
        return NGX_HTTP_INTERNAL_SERVER_ERROR; \
    } \
    xml_len += _xml_written; \
} while (0)

/* -------------------------------------------------------------------------
 * Module symbol (defined in module.c, referenced by handler/put)
 * ---------------------------------------------------------------------- */

extern ngx_module_t ngx_http_brix_s3_module;

/* Operation Registry (operation_table.c) */
extern const brix_http_operation_t brix_s3_operations[];
extern const ngx_uint_t brix_s3_operations_count;

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
int brix_open_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, int flags, mode_t mode);
/* unlinkat() under confinement; is_dir != 0 → AT_REMOVEDIR. 0 ok, -1 error. */
int brix_unlink_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, int is_dir);
/* mkdirat() under confinement. Returns 0 on success, -1 on error. */
int brix_mkdir_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, mode_t mode);
/* renameat() with BOTH endpoints confined under the same root. 0 ok, -1 err. */
int brix_rename_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *src_resolved, const char *dst_resolved);
/* linkat() hard-link with BOTH endpoints confined under the same root.
 * Returns 0 on success, -1 on error. */
int brix_link_confined_canon(ngx_log_t *log, const char *root_canon,
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
 *   Object GET/HEAD, ListObjects V1/V2, and the directory-walk / listing
 *   building blocks — split into s3_handlers.h so this file stays focused on
 *   the config/context types; included after those types are defined.
 * ---------------------------------------------------------------------- */
#include "s3_handlers.h"

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

/* Serve pre-header hook (brix_http_pre_header_fn) that applies the response-*
 * overrides just before the GET response headers are sent. */
void s3_get_pre_header(ngx_http_request_t *r, ngx_fd_t fd, off_t file_size,
                          void *userdata);

/* DELETE /bucket/key */
ngx_int_t s3_handle_delete(ngx_http_request_t *r,
                             const char *fs_path,
                             ngx_http_s3_loc_conf_t *cf);

/* Emit the DELETE response for a completed unlink (op_errno 0 = removed).
 * Shared by the synchronous handler and the async-queue wake. (object_meta.c) */
ngx_int_t s3_delete_respond(ngx_http_request_t *r, int op_errno);

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
 * BRIX_S3_METHOD_* slot, or BRIX_S3_METHOD_OTHER if unmatched. */
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
void s3_sess_begin_request(ngx_http_request_t *r, ngx_uint_t method_slot);
void s3_sess_attempt_request(ngx_http_request_t *r, ngx_uint_t method_slot);

/* -------------------------------------------------------------------------
 * Authentication
 * ---------------------------------------------------------------------- */

/*
 * Verify the AWS Signature Version 4 Authorization header.
 * Returns NGX_OK on success, NGX_HTTP_FORBIDDEN on failure.
 * If cf->access_key.len == 0, always returns NGX_OK (anonymous).
 * When cf->token_enable is set, Bearer tokens are intercepted before SigV4
 * (INVARIANT §6: the two auth schemes are mutually exclusive per request).
 */
ngx_int_t s3_verify_sigv4(ngx_http_request_t *r,
                           ngx_http_s3_loc_conf_t *cf,
                           brix_identity_t *identity);

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
 * `event` is an BRIX_S3_EVENT_* index. */
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
int s3_resolve_key(const char *root, const char *key, char *out, size_t outsz,
    unsigned allow_internal);

/* Multipart, copy, delete-objects, and checksum operation declarations were
 * split out (phase-79 file-size burndown) into s3_ops.h, included here so every
 * s3.h consumer still sees them. */
#include "s3_ops.h"

#endif /* NGX_HTTP_S3_H */

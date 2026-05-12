#ifndef XROOTD_WEBDAV_H
#define XROOTD_WEBDAV_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if (NGX_THREADS)
#include <ngx_thread_pool.h>
#endif

#include <stdint.h>
#include <sys/stat.h>

#include "../metrics/metrics.h"
#include "../token/token.h"
#include "tpc_config.h"
#include "tpc_cred.h"

typedef struct x509_store_st X509_STORE;

#define WEBDAV_MAX_PATH          4096
#define WEBDAV_FD_TABLE_SIZE     16
#define WEBDAV_PUT_COPY_BUFSZ    (1024 * 1024)
#define WEBDAV_PUT_COPY_CHUNK    (16 * 1024 * 1024)
#define WEBDAV_TPC_MAX_HEADERS   64
#define WEBDAV_TPC_MAX_ARGS      (32 + WEBDAV_TPC_MAX_HEADERS * 2)

#define WEBDAV_LOCK_TABLE_SIZE   1024
#define WEBDAV_LOCK_TOKEN_LEN    64
#define WEBDAV_LOCK_OWNER_LEN    1024

typedef enum {
    WEBDAV_AUTH_NONE,
    WEBDAV_AUTH_OPTIONAL,
    WEBDAV_AUTH_REQUIRED,
} webdav_auth_t;

typedef enum {
    WEBDAV_PROXY_AUTH_ANONYMOUS,  /* strip Authorization from forwarded request */
    WEBDAV_PROXY_AUTH_FORWARD,    /* pass Authorization header through unchanged */
    WEBDAV_PROXY_AUTH_TOKEN,      /* replace Authorization with static Bearer token */
} webdav_proxy_auth_t;

/* --- WebDAV LOCK structures --- */

typedef struct {
    char        path[WEBDAV_MAX_PATH];
    char        token[WEBDAV_LOCK_TOKEN_LEN];
    char        owner[WEBDAV_LOCK_OWNER_LEN];
    ngx_msec_t  expires;             /* absolute time (msec) when lock expires */
    unsigned    exclusive:1;
    unsigned    depth_infinity:1;
    unsigned    in_use:1;
} webdav_lock_entry_t;

typedef struct {
    ngx_shmtx_sh_t       lock;
    webdav_lock_entry_t  slots[WEBDAV_LOCK_TABLE_SIZE];
} webdav_lock_table_t;


/*
 * Per-location WebDAV configuration.  Populated from nginx directives during
 * the configuration phase (cf->pool lifetime).
 *
 * Lifetime: nginx worker lifetime (allocated in cf->pool at startup).
 */
typedef struct {
    ngx_flag_t     enable;          /* 1 if xrootd_webdav is on for this loc */
    ngx_str_t      root;            /* configured export root path (may contain
                                     * nginx variables; use root_canon for ops) */

    /* --- X.509 / GSI authentication --- */
    ngx_str_t      cadir;           /* directory of trusted CA PEM files */
    ngx_str_t      cafile;          /* single trusted CA bundle PEM file */
    ngx_str_t      crl;             /* directory of CRL PEM files */
    ngx_uint_t     verify_depth;    /* max proxy chain depth for VOMS proxies;
                                     * RFC 3820 §4 recommends <= 3 for WLCG */
    ngx_uint_t     auth;            /* webdav_auth_t: NONE/OPTIONAL/REQUIRED */
    ngx_flag_t     proxy_certs;     /* 1 to accept RFC 3820 proxy certificates */
    X509_STORE    *ca_store;        /* loaded trust store; built at postconfiguration;
                                     * NULL if no CA dir/file configured */

    /* --- Write permissions --- */
    ngx_flag_t     allow_write;     /* 1 to allow PUT/DELETE/MKCOL/MOVE/COPY */
    ngx_flag_t     tpc;             /* 1 to allow HTTP-TPC (third-party copy) */

    /* --- HTTP-TPC (curl-based pull) settings --- */
    ngx_str_t      tpc_curl;        /* path to curl binary */
    ngx_str_t      tpc_cert;        /* client cert PEM for TPC pull */
    ngx_str_t      tpc_key;         /* private key PEM for TPC pull */
    ngx_str_t      tpc_cadir;       /* CA dir for TPC pull verification */
    ngx_str_t      tpc_cafile;      /* CA bundle for TPC pull verification */
    ngx_uint_t     tpc_timeout;     /* curl --max-time in seconds */

    /* --- HTTP-TPC OAuth2/OIDC credential delegation --- */
    ngx_http_xrootd_tpc_conf_t tpc_cred;

    /* --- Bearer token (WLCG/SciToken) settings --- */
    ngx_str_t      token_jwks;      /* path to JWKS file for RS256 validation */
    ngx_str_t      token_issuer;    /* required "iss" claim; "" to skip check */
    ngx_str_t      token_audience;  /* required "aud" claim; "" to skip check */
    ngx_str_t      token_macaroon_secret;     /* [xrootd_webdav_macaroon_secret <hex>] */
    ngx_str_t      token_macaroon_secret_old; /* [xrootd_webdav_macaroon_secret_old <hex>]
                                                 grace-period key accepted alongside the
                                                 primary secret during key rotation. */
    xrootd_jwks_key_t  jwks_keys[XROOTD_MAX_JWKS_KEYS]; /* loaded RSA pub keys */
    int                 jwks_key_count;  /* number of valid entries in jwks_keys */

    /* --- Thread pool for async PUT writes --- */
    ngx_str_t           thread_pool_name; /* nginx thread_pool directive name */
#if (NGX_THREADS)
    ngx_thread_pool_t  *thread_pool;  /* resolved at postconfiguration; NULL
                                       * if NGX_THREADS disabled or not configured */
#endif

    /* --- CORS settings --- */
    ngx_array_t        *cors_origins;    /* allowed origins (ngx_str_t array) */
    ngx_flag_t          cors_credentials; /* Access-Control-Allow-Credentials */
    ngx_uint_t          cors_max_age;     /* Access-Control-Max-Age in seconds */

    /* Canonicalised absolute path corresponding to root; resolved at
     * postconfiguration.  Use this (not root) for all filesystem operations.
     * WEBDAV_MAX_PATH bytes, NUL-terminated.  Never free() this buffer —
     * it is embedded in the struct allocated from cf->pool. */
    char                root_canon[WEBDAV_MAX_PATH];

    /* --- WebDAV LOCK shared memory --- */
    ngx_shm_zone_t     *lock_shm_zone;
    ngx_uint_t          lock_timeout;    /* max lock timeout in seconds */

    /* --- Upstream HTTP(S) proxy --- */
    ngx_flag_t                    upstream_proxy;      /* xrootd_webdav_proxy on/off */
    ngx_str_t                     upstream_url;        /* xrootd_webdav_proxy_upstream URL */
    ngx_str_t                     upstream_host;       /* host[:port] for Host: header */
    ngx_str_t                     upstream_url_base;   /* scheme://host:port */
    ngx_uint_t                    upstream_auth;       /* webdav_proxy_auth_t */
    ngx_str_t                     upstream_auth_token; /* Bearer token value (TOKEN mode) */
    ngx_flag_t                    upstream_ssl;        /* 1 if https:// upstream */
    ngx_http_upstream_conf_t      upstream_conf;       /* timeouts, buffer_size, etc. */
    ngx_http_upstream_resolved_t *upstream_resolved;   /* pre-resolved address */
#if (NGX_HTTP_SSL)
    ngx_ssl_t                    *upstream_ssl_ctx;    /* SSL context for https upstream */
#endif
} ngx_http_xrootd_webdav_loc_conf_t;

/*
 * Per-request authentication context.  Lifetime: r->pool (request scope).
 *
 * Set by webdav_verify_proxy_cert() or webdav_verify_bearer_token() during
 * the auth gate in ngx_http_xrootd_webdav_handler().
 */
typedef struct {
    int            verified;     /* 1 if auth was accepted, 0 if anonymous */
    char           dn[1024];     /* Distinguished Name from cert or token sub;
                                  * NUL-terminated; empty string if anonymous */
    const char    *auth_source;  /* "cert", "token", or "anonymous" — static
                                  * string; do not free() */
    int            token_auth;   /* 1 if auth came from a bearer token */
    int            token_scope_count;  /* number of valid entries in token_scopes */
    xrootd_token_scope_t  token_scopes[XROOTD_MAX_TOKEN_SCOPES];
                                 /* parsed scope list from the bearer token */
    
    /* LOCK context */
    unsigned       lock_depth_infinity:1;
    char           lock_owner[WEBDAV_LOCK_OWNER_LEN];
} ngx_http_xrootd_webdav_req_ctx_t;

/*
 * One slot in the per-connection fd cache.
 *
 * The fd-cache avoids repeated open()/fstat()/close() for hot files (e.g.
 * a PROPFIND + GET pair on the same URI).  It is connection-scoped: fds here
 * live until the HTTP connection is closed or explicitly evicted.
 *
 * IMPORTANT — fhandle scope: an fd cached here is a live kernel file
 * descriptor, not an XRootD 4-byte fhandle.  It is valid only for the
 * lifetime of the HTTP connection.  Do not cache these fds across connections.
 */
typedef struct {
    ngx_fd_t    fd;                  /* open file descriptor; NGX_INVALID_FILE
                                      * when this slot is empty */
    char        path[WEBDAV_MAX_PATH]; /* canonicalised absolute filesystem path,
                                        * NUL-terminated */
    uint64_t    uri_hash;            /* FNV-1a hash of the decoded URI for O(1)
                                      * lookup in webdav_fd_table_get_by_uri() */
    ino_t       ino;                 /* inode number — used with dev to detect
                                      * whether the file was replaced on disk */
    dev_t       dev;                 /* device ID — paired with ino for
                                      * cross-mount uniqueness */
    ngx_msec_t  open_time;          /* ngx_current_msec when the fd was inserted;
                                      * used by the LRU eviction policy */
} webdav_fd_entry_t;

/*
 * Per-connection fd cache table.
 *
 * WEBDAV_FD_TABLE_SIZE slots (16) is intentionally small — the typical HTTP
 * connection issues a PROPFIND followed by one or a few GETs.  The small size
 * bounds kernel fd consumption to 16 per HTTP connection.
 *
 * Lifetime: allocated in c->pool; freed when the HTTP connection closes.
 * Do NOT share this table across connections.
 */
typedef struct {
    webdav_fd_entry_t  fds[WEBDAV_FD_TABLE_SIZE]; /* fd slots */
    int                count;  /* number of currently occupied slots */
} webdav_fd_table_t;

extern ngx_module_t ngx_http_xrootd_webdav_module;

size_t xrootd_sanitize_log_string(const char *in, char *out, size_t outsz);
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

/* Module wiring */
void *ngx_http_xrootd_webdav_create_loc_conf(ngx_conf_t *cf);
char *ngx_http_xrootd_webdav_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
ngx_int_t ngx_http_xrootd_webdav_postconfiguration(ngx_conf_t *cf);
ngx_int_t ngx_http_xrootd_webdav_handler(ngx_http_request_t *r);

/* Path and XML utilities */
ngx_int_t ngx_http_xrootd_webdav_resolve_path(ngx_http_request_t *r,
    const char *root_canon, char *out, size_t outsz);
ngx_int_t webdav_resolve_destination_path(ngx_log_t *log, const char *op_label,
    const char *root_canon, const char *decoded_path, char *out, size_t outsz);
ngx_int_t webdav_resolve_stat(ngx_http_request_t *r, char *path,
    size_t pathsz, struct stat *sb);
void ngx_http_xrootd_webdav_log_safe_path(ngx_log_t *log, ngx_uint_t level,
    ngx_err_t err, const char *prefix, const char *path);
ngx_int_t webdav_urldecode(const u_char *src, size_t src_len,
    char *dst, size_t dst_sz);
char *webdav_escape_xml_text(ngx_pool_t *pool, const char *src);
void webdav_http_date(time_t t, char *buf, size_t sz);
void webdav_iso8601_date(time_t t, char *buf, size_t sz);
ngx_int_t webdav_add_last_modified(ngx_http_request_t *r, time_t mtime);
void webdav_etag_str(char *buf, size_t bufsz, time_t mtime, off_t size);
ngx_int_t webdav_add_etag(ngx_http_request_t *r, time_t mtime, off_t size);
ngx_int_t webdav_add_cors_headers(ngx_http_request_t *r);
ngx_int_t webdav_lock_init_shm(ngx_shm_zone_t *shm_zone, void *data);
ngx_int_t webdav_check_locks(ngx_http_request_t *r, const char *path,
    int need_write);
ngx_int_t webdav_lock_append_discovery(ngx_http_request_t *r, const char *path,
    ngx_chain_t **head, ngx_chain_t **tail);
ngx_int_t webdav_lock_append_supported(ngx_http_request_t *r,
    ngx_chain_t **head, ngx_chain_t **tail);
ngx_uint_t webdav_metrics_method(ngx_http_request_t *r);
void webdav_metrics_request(ngx_http_request_t *r);
void webdav_metrics_response(ngx_http_request_t *r, ngx_int_t rc);
ngx_int_t webdav_metrics_return(ngx_http_request_t *r, ngx_int_t rc);
void webdav_metrics_finalize_request(ngx_http_request_t *r, ngx_int_t rc);

/* Authentication */
ngx_int_t webdav_auth_init_ssl_indices(ngx_log_t *log);
X509_STORE *webdav_build_ca_store(ngx_log_t *log,
    ngx_http_xrootd_webdav_loc_conf_t *conf, int *crl_count_out);
ngx_int_t webdav_verify_proxy_cert(ngx_http_request_t *r,
    ngx_http_xrootd_webdav_loc_conf_t *conf);
ngx_int_t webdav_verify_bearer_token(ngx_http_request_t *r,
    ngx_http_xrootd_webdav_loc_conf_t *conf);
ngx_int_t webdav_check_token_write_scope(ngx_http_request_t *r,
    const char *method_name);
ngx_int_t webdav_check_pki_consistency(ngx_log_t *log,
    ngx_http_xrootd_webdav_loc_conf_t *conf);

/* HTTP methods */
ngx_int_t webdav_handle_options(ngx_http_request_t *r);
ngx_int_t webdav_handle_head(ngx_http_request_t *r, int send_body);
ngx_int_t webdav_handle_get(ngx_http_request_t *r);
void webdav_handle_put_body(ngx_http_request_t *r);
ngx_int_t webdav_handle_delete(ngx_http_request_t *r);
ngx_int_t webdav_delete_path_recursive(ngx_log_t *log, const char *root_canon,
    const char *path);
ngx_int_t webdav_handle_mkcol(ngx_http_request_t *r);
ngx_int_t webdav_handle_propfind(ngx_http_request_t *r);
ngx_int_t webdav_handle_proppatch(ngx_http_request_t *r);
ngx_buf_t *webdav_propfind_append(ngx_pool_t *pool, ngx_chain_t **head,
    ngx_chain_t **tail, const char *fmt, ...);
ngx_int_t webdav_handle_move(ngx_http_request_t *r);
ngx_int_t webdav_handle_copy(ngx_http_request_t *r);
void webdav_handle_lock(ngx_http_request_t *r);
ngx_int_t webdav_handle_unlock(ngx_http_request_t *r);

/* FD cache and file I/O helpers */
ngx_int_t webdav_fd_table_init_ssl_index(ngx_log_t *log);
webdav_fd_table_t *webdav_get_fd_table(ngx_connection_t *c);
ngx_fd_t webdav_fd_table_get(webdav_fd_table_t *t, const char *path,
    const struct stat *sb);
void webdav_fd_table_put(webdav_fd_table_t *t, const char *path,
    const struct stat *sb, ngx_fd_t fd, uint64_t uri_hash);
void webdav_fd_table_evict(webdav_fd_table_t *t, const char *path);
char *webdav_strnstr(const char *s1, const char *s2, size_t len);
uint64_t webdav_uri_hash(const char *s);
ngx_fd_t webdav_fd_table_get_by_uri(webdav_fd_table_t *t, uint64_t uri_hash,
    struct stat *sb_out, const char **path_out);
void webdav_fadvise_willneed(ngx_log_t *log, ngx_fd_t fd, off_t offset,
    size_t len);
ngx_int_t webdav_write_full(ngx_fd_t fd, u_char *buf, size_t len);
ngx_int_t webdav_copy_spooled_file(ngx_http_request_t *r, ngx_fd_t dst_fd,
    ngx_buf_t *buf, const char *path, u_char **scratch);

/* HTTP-TPC */
void ngx_http_xrootd_webdav_tpc_create_loc_conf(
    ngx_http_xrootd_webdav_loc_conf_t *conf);
void ngx_http_xrootd_webdav_tpc_merge_loc_conf(
    ngx_http_xrootd_webdav_loc_conf_t *conf,
    ngx_http_xrootd_webdav_loc_conf_t *prev);
ngx_table_elt_t *webdav_tpc_find_header(ngx_http_request_t *r,
    const char *name, size_t name_len);
ngx_flag_t webdav_tpc_str_has_ctl(const u_char *data, size_t len);
ngx_int_t webdav_tpc_header_value_equals(ngx_str_t *value,
    const char *literal);
char *webdav_tpc_pstrndup0(ngx_pool_t *pool, const u_char *data, size_t len);
ngx_int_t webdav_tpc_collect_transfer_headers(ngx_http_request_t *r,
    ngx_array_t **out);
ngx_int_t webdav_tpc_run_curl_pull(ngx_http_request_t *r,
    ngx_http_xrootd_webdav_loc_conf_t *conf, const char *source_url,
    const char *tmp_path, ngx_array_t *transfer_headers);
ngx_int_t webdav_tpc_run_curl_push(ngx_http_request_t *r,
    ngx_http_xrootd_webdav_loc_conf_t *conf, const char *dest_url,
    const char *local_path, ngx_array_t *transfer_headers);
ngx_int_t ngx_http_xrootd_webdav_tpc_handle_copy(ngx_http_request_t *r);

/* Upstream HTTP(S) proxy */
ngx_int_t webdav_proxy_handler(ngx_http_request_t *r);
ngx_int_t webdav_proxy_parse_upstream_url(ngx_conf_t *cf,
    ngx_http_xrootd_webdav_loc_conf_t *conf);

/* HTTP-TPC credential delegation */
xrootd_tpc_cred_mode_e webdav_tpc_cred_parse_mode(const char *value, size_t len);
ngx_int_t webdav_tpc_cred_obtain_token(ngx_http_request_t *r,
    xrootd_tpc_cred_mode_e mode, const char *source_url,
    const char *subject_token, const char *scope, ngx_str_t *token_out);
const char *webdav_tpc_cred_metric_name(xrootd_tpc_cred_metrics_e idx);

#endif /* XROOTD_WEBDAV_H */

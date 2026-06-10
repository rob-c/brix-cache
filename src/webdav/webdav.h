#ifndef XROOTD_WEBDAV_H
#define XROOTD_WEBDAV_H

/*
 * webdav.h — Shared types, configuration structs, and function declarations for the
 * nginx HTTP WebDAV module (davs:// endpoint).
 *
 * WHAT: Declares all shared data structures used across WebDAV source files:
 *       location-level config (`ngx_http_xrootd_webdav_loc_conf_t`), per-request
 *       auth context (`ngx_http_xrootd_webdav_req_ctx_t`), lock table entry and
 *       shared-memory table, authentication enums, and constants. Also declares
 *       every public function across the WebDAV module — path resolution, URI
 *       utilities, XML escaping, metrics, authentication, HTTP method handlers,
 *       file I/O helpers, HTTP-TPC (third-party copy), upstream proxy, and
 *       credential delegation.
 *
 * WHY: This header is included by every webdav source file so that all modules see
 *      the same types in a single include. It also includes xrdhttp.h so that both
 *      WebDAV and XrdHttp types coexist — pointer casting between req_ctx_t and
 *      xrdhttp_req_ctx_t relies on layout compatibility (C11 §6.7.2.1p15). Without
 *      this unified header, each file would need to re-declare overlapping types.
 *
 * HOW: The header is organized into sections by responsibility:
 *       1. Includes — nginx core + module headers, shared protocol/compat headers
 *       2. Constants — path max, fd table size, lock sizes, TPC limits
 *       3. Enums — auth modes (NONE/OPTIONAL/REQUIRED), proxy auth modes
 *       4. LOCK structures — entry and shared-memory table
 *       5. Location config struct — all directives mapped to fields with inline comments
 *       6. Per-request context struct — auth results, token scopes, lock metadata
 *       7. Module wiring — create/merge loc conf, postconfig, access handler, content handler
 *       8. Operation registry — extern declarations for the operation capability table
 *       9. Path/URI/XML/logging utilities — resolve_path, urldecode, escape_xml, cors
 *       10. Authentication — ca store build, cert verification, bearer token validation
 *       11. HTTP method handlers — options, head, get, put, delete, mkcol, propfind, move, copy, lock, unlock
 *       12. File I/O helpers — fadvise, write_full, spooled file copy
 *       13. HTTP-TPC — header macros, curl pull/push, thread task posting, COPY handler
 *       14. Upstream proxy — handler, URL parsing
 *       15. Credential delegation — mode parse, token obtain, metric names
 *       16. Capability table macro — XROOTD_WEBDAV_ALLOW_FLAGS()
 *
 * INCLUDES: xrdhttp.h is included here so all webdav source files see both types in
 *           a single include. See src/webdav/xrdhttp.h for the XrdHttp extension API.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <ngx_thread_pool.h>

#include <stdint.h>
#include <sys/stat.h>

#include "../metrics/metrics.h"
#include "../compat/error_mapping.h"
#include "../compat/http_headers.h"
#include "../compat/log.h"
#include "../token/token.h"
#include "../types/identity.h"
#include "tpc_config.h"
#include "tpc_cred.h"
#include "../compat/path.h"
#include "../compat/protocol_caps.h"
#include "../config/shared_conf.h"

#include <ngx_open_file_cache.h>

/* XrdHttp protocol extension API — included here so all webdav source
 * files see both the webdav and xrdhttp types in a single include. */
#include "xrdhttp.h"

typedef struct x509_store_st X509_STORE;

#define WEBDAV_MAX_PATH          XROOTD_PATH_MAX
#define WEBDAV_FD_TABLE_SIZE     16
#define WEBDAV_PUT_COPY_BUFSZ    (1024 * 1024)
#define WEBDAV_PUT_COPY_CHUNK    (16 * 1024 * 1024)
#define WEBDAV_TPC_MAX_HEADERS   64

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
    ngx_http_xrootd_shared_conf_t common; /* enable, root, root_canon, allow_write,
                                             thread_pool_name, thread_pool */

    /* --- Optional read-through cache root --- */
    ngx_str_t   cache_root;               /* [xrootd_webdav_cache_root /path] */
    char        cache_root_canon[PATH_MAX]; /* realpath-resolved form; "" = disabled */

    /* --- VOMS VO extraction (optional; requires libvomsapi) --- */
    ngx_str_t   vomsdir;       /* [xrootd_webdav_vomsdir /etc/grid-security/vomsdir] */
    ngx_str_t   voms_cert_dir; /* [xrootd_webdav_voms_cert_dir /etc/grid-security/certificates] */

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

    /* --- Write permissions / TPC --- */
    ngx_flag_t     tpc;             /* 1 to allow HTTP-TPC (third-party copy) */

    /* --- HTTP-TPC SSRF policy --- */
    ngx_flag_t     tpc_allow_local;   /* 0: reject loopback+link-local targets */
    ngx_flag_t     tpc_allow_private; /* 0: reject RFC-1918 / ULA targets */

    /* --- HTTP-TPC (curl-based pull) settings --- */
    ngx_str_t      tpc_curl;        /* path to curl binary */
    ngx_str_t      tpc_cert;        /* client cert PEM for TPC pull */
    ngx_str_t      tpc_key;         /* private key PEM for TPC pull */
    ngx_str_t      tpc_cadir;       /* CA dir for TPC pull verification */
    ngx_str_t      tpc_cafile;      /* CA bundle for TPC pull verification */
    ngx_uint_t     tpc_timeout;     /* curl --max-time in seconds */
    ngx_uint_t     tpc_marker_interval; /* seconds between Perf Markers; 0 = 201 only */
    ngx_uint_t     tpc_max_streams;     /* max parallel streams per pull; 0 = single */

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

    /* --- CORS settings --- */
    ngx_array_t        *cors_origins;    /* allowed origins (ngx_str_t array) */
    ngx_flag_t          cors_credentials; /* Access-Control-Allow-Credentials */
    ngx_uint_t          cors_max_age;     /* Access-Control-Max-Age in seconds */

    /* --- WebDAV LOCK shared memory --- */
    ngx_shm_zone_t     *lock_shm_zone;
    ngx_uint_t          lock_timeout;    /* max lock timeout in seconds */

    /* --- Open file cache --- */
    ngx_open_file_cache_t  *open_file_cache;
    ngx_uint_t              open_file_cache_valid;
    ngx_uint_t              open_file_cache_min_uses;
    ngx_flag_t              open_file_cache_errors;
    ngx_flag_t              open_file_cache_events;

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
    /* XrdHttp per-request context — MUST be first member so that a pointer
     * to this struct can be safely cast to xrdhttp_req_ctx_t * via C struct
     * layout rule (C11 §6.7.2.1p15). */
    xrdhttp_req_ctx_t  xrdhttp;

    int            verified;     /* 1 if auth was accepted, 0 if anonymous */
    xrootd_identity_t *identity; /* canonical Phase 2 identity object */
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
ngx_int_t ngx_http_xrootd_webdav_access_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_xrootd_webdav_handler(ngx_http_request_t *r);

/* Operation Registry (operation_table.c) */
extern const xrootd_http_operation_t xrootd_webdav_operations[];
extern const ngx_uint_t xrootd_webdav_operations_count;

/* Path, URI, XML, and logging utilities */
ngx_int_t ngx_http_xrootd_webdav_resolve_path(ngx_http_request_t *r,
    const char *root_canon, char *out, size_t outsz);
ngx_int_t webdav_resolve_destination_path(ngx_log_t *log, const char *op_label,
    const char *root_canon, const char *decoded_path, char *out, size_t outsz);
ngx_int_t webdav_resolve_stat(ngx_http_request_t *r, char *path,
    size_t pathsz, struct stat *sb);
ngx_int_t webdav_urldecode(const u_char *src, size_t src_len,
    char *dst, size_t dst_sz);
ngx_int_t webdav_destination_extract_path(const u_char *dest_data,
    size_t dest_len, const u_char **path_out, size_t *path_len_out);
char *webdav_escape_xml_text(ngx_pool_t *pool, const char *src);
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
ngx_int_t webdav_handle_search(ngx_http_request_t *r);
ngx_int_t webdav_handle_acl(ngx_http_request_t *r);

ngx_int_t webdav_handle_move(ngx_http_request_t *r);
ngx_int_t webdav_handle_copy(ngx_http_request_t *r);
void webdav_handle_lock(ngx_http_request_t *r);
ngx_int_t webdav_handle_unlock(ngx_http_request_t *r);

/* Macaroon token issuance endpoints (macaroon_endpoint.c) */
ngx_int_t webdav_handle_macaroon_discovery(ngx_http_request_t *r);
void webdav_handle_macaroon_token(ngx_http_request_t *r);

/* Dead WebDAV properties persisted as filesystem extended attributes. */
ngx_int_t webdav_dead_prop_set(ngx_http_request_t *r, const char *path,
    const char *ns, const char *local, const char *xml, size_t xml_len);
ngx_int_t webdav_dead_prop_remove(ngx_http_request_t *r, const char *path,
    const char *ns, const char *local);
ngx_int_t webdav_dead_prop_append_value(ngx_http_request_t *r,
    const char *path, const char *ns, const char *local,
    ngx_chain_t **head, ngx_chain_t **tail, ngx_flag_t *found);
ngx_int_t webdav_dead_prop_append_empty(ngx_http_request_t *r,
    const char *ns, const char *local, ngx_chain_t **head,
    ngx_chain_t **tail);
ngx_int_t webdav_dead_props_append_all(ngx_http_request_t *r,
    const char *path, ngx_chain_t **head, ngx_chain_t **tail,
    ngx_flag_t names_only);
ngx_flag_t webdav_dead_prop_is_protected_dav(const char *local);
void webdav_dead_props_copy(ngx_log_t *log, const char *src, const char *dst);

/* File I/O helpers */
void webdav_fadvise_willneed(ngx_log_t *log, ngx_fd_t fd, off_t offset,
    size_t len);
ngx_int_t webdav_write_full(ngx_fd_t fd, u_char *buf, size_t len);
ngx_int_t webdav_copy_spooled_file(ngx_http_request_t *r, ngx_fd_t dst_fd,
    ngx_buf_t *buf, const char *path, u_char **scratch);

/* Max parallel streams for HTTP-TPC multi-stream pull (X-Number-Of-Streams). */
#define XROOTD_TPC_MAX_STREAMS  16

/*
 * Progress counters shared between the curl background thread and the
 * nginx event-loop poll timer during 202-streaming TPC transfers.
 * Allocated from r->pool before the thread is posted; valid until
 * ngx_http_finalize_request is called.
 */
typedef struct {
    volatile ngx_atomic_t  bytes_per_stream[XROOTD_TPC_MAX_STREAMS];
    volatile ngx_atomic_t  completed;  /* 1 when thread is done */
    ngx_int_t              result;     /* HTTP status; set before completed=1 */
    ngx_uint_t             n_streams;
    off_t                  total_size; /* from HEAD; -1 if unknown */
} tpc_ms_progress_t;

/* HTTP-TPC */
void ngx_http_xrootd_webdav_tpc_create_loc_conf(
    ngx_http_xrootd_webdav_loc_conf_t *conf);
void ngx_http_xrootd_webdav_tpc_merge_loc_conf(
    ngx_http_xrootd_webdav_loc_conf_t *conf,
    ngx_http_xrootd_webdav_loc_conf_t *prev);
/* TPC header lookup, value comparison, and NUL-copy helpers.
 * Macro aliases to compat equivalents — call sites unchanged, no wrapper functions. */
#define webdav_tpc_find_header(r, name, name_len) \
    xrootd_http_find_header(r, name, name_len)
#define webdav_tpc_str_has_ctl(data, len) \
    xrootd_http_str_has_ctl(data, len)
#define webdav_tpc_header_value_equals(value, literal) \
    xrootd_http_header_value_equals(value, literal)

static inline char *
webdav_tpc_pstrndup0(ngx_pool_t *pool, const u_char *data, size_t len)
{
    char *out = ngx_pnalloc(pool, len + 1);
    if (out != NULL) {
        ngx_memcpy(out, data, len);
        out[len] = '\0';
    }
    return out;
}
ngx_int_t webdav_tpc_collect_transfer_headers(ngx_http_request_t *r,
    ngx_array_t **out);
ngx_int_t webdav_tpc_run_curl_pull(ngx_log_t *log,
    ngx_http_xrootd_webdav_loc_conf_t *conf, const char *source_url,
    const char *tmp_path, ngx_array_t *transfer_headers,
    uint64_t transfer_id);
ngx_int_t webdav_tpc_run_curl_push(ngx_log_t *log,
    ngx_http_xrootd_webdav_loc_conf_t *conf, const char *dest_url,
    const char *local_path, ngx_array_t *transfer_headers,
    uint64_t transfer_id);
ngx_int_t webdav_tpc_post_thread_task(ngx_http_request_t *r,
    ngx_http_xrootd_webdav_loc_conf_t *conf,
    int is_push, ngx_flag_t existed, ngx_flag_t overwrite,
    const char *url, const char *local_path, const char *dest_path,
    ngx_array_t *transfer_headers, ngx_uint_t n_streams);
ngx_int_t webdav_tpc_run_curl_pull_multi(ngx_log_t *log,
    ngx_http_xrootd_webdav_loc_conf_t *conf,
    const char *source_url, const char *tmp_path,
    ngx_array_t *transfer_headers, ngx_uint_t n_streams,
    uint64_t transfer_id, tpc_ms_progress_t *progress);
/* 202-streaming TPC with Performance-Markers and optional multi-stream.
 * Returns NGX_DONE (202 sent, poll timer running) or NGX_DECLINED (no thread
 * pool configured; caller falls back to the 201 path). */
ngx_int_t webdav_tpc_marker_start(ngx_http_request_t *r,
    ngx_http_xrootd_webdav_loc_conf_t *conf, ngx_uint_t n_streams,
    const char *url, const char *tmp_path, const char *final_path,
    ngx_flag_t is_pull, ngx_flag_t overwrite, ngx_flag_t existed,
    ngx_array_t *transfer_headers, uint64_t transfer_id);
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

/* Operation capability table (operation_table.c) */
#include "../compat/protocol_caps.h"
extern const xrootd_http_operation_t xrootd_webdav_operations[];
extern const ngx_uint_t              xrootd_webdav_operations_count;
#define XROOTD_WEBDAV_ALLOW_FLAGS(conf)                                    \
    (XROOTD_PROTO_OP_READ | XROOTD_PROTO_OP_LIST                           \
     | ((conf)->common.allow_write                                          \
            ? (XROOTD_PROTO_OP_WRITE | XROOTD_PROTO_OP_LOCK) : 0)         \
     | ((conf)->tpc ? XROOTD_PROTO_OP_TPC : 0))

#endif /* XROOTD_WEBDAV_H */

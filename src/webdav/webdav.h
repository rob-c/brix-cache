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
#include "../acc/acc.h"
#include "tpc_config.h"
#include "tpc_cred.h"
#include "../compat/path.h"
#include "../compat/protocol_caps.h"
#include "../config/shared_conf.h"
#include "../shm/kv.h"
#include "../mirror/mirror.h"
#include "../shm/rate_limit.h"

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

/* --- WebDAV xattr-based lock constants --- */
#define WEBDAV_LOCK_XATTR_KEY    "user.nginx_xrootd.lock"
#define WEBDAV_LOCK_XATTR_MAXLEN  512

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

/* --- WebDAV xattr-based lock entry --- */

typedef struct {
    char        token[64];           /* full opaquelocktoken:UUID string */
    char        owner[256];          /* DN or free-form owner */
    int64_t     expires;             /* absolute expiry, Unix WALL-CLOCK seconds
                                      * (ngx_time()-based, NOT the monotonic
                                      * ngx_current_msec): a persisted lock must
                                      * keep meaningful expiry across a machine
                                      * reboot, where the monotonic clock resets. */
    unsigned    exclusive:1;
    unsigned    depth_infinity:1;
    unsigned    is_null:1;           /* lock-null: the lock created a zero-byte
                                      * placeholder on a non-existent resource
                                      * (RFC 4918 §9.10.1); reaped on UNLOCK/expiry
                                      * while the resource is still empty. */
} webdav_lock_xattr_t;

/*
 * Per-location WebDAV configuration.  Populated from nginx directives during
 * the configuration phase (cf->pool lifetime).
 *
 * Lifetime: nginx worker lifetime (allocated in cf->pool at startup).
 */

/* §3 XrdDig: one named, read-only diagnostic export. `dir` is the operator's
 * argument; `canon` is its realpath at config time (the RESOLVE_BENEATH anchor). */
typedef struct {
    ngx_str_t name;
    ngx_str_t dir;
    ngx_str_t canon;
} xrootd_dig_export_t;

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
    ngx_flag_t     tape_rest;       /* 1 to serve the WLCG /api/v1 Tape REST API */
    ngx_flag_t     upload_resume;   /* [xrootd_webdav_upload_resume on|off] default
                                     * ON.  When on, a Content-Range PUT writes its
                                     * chunk to a persistent identity-keyed partial
                                     * at the given offset and commits only when the
                                     * upload is complete; a 409 reports X-Upload-
                                     * Offset.  Lets a davs:// upload resume across
                                     * an nginx restart.  See src/webdav/put.c. */
    ngx_str_t      upload_stage_dir;      /* [xrootd_webdav_stage_dir <path>] optional
                                     * fast-cache staging device; empty = stage
                                     * adjacent to the destination. */
    char           upload_stage_dir_canon[PATH_MAX];

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
    /* Phase 39 (WS4): HTTP-TPC stall bounding for a slow/black-holed remote.
     * Both default 0 (off) = current behaviour.  When both > 0 they map to
     * CURLOPT_LOW_SPEED_LIMIT/TIME: abort a transfer that stays below
     * tpc_low_speed_bytes B/s for tpc_low_speed_secs, WITHOUT killing a
     * slow-but-progressing one.  (A fixed CURLOPT_CONNECTTIMEOUT + TCP keepalive
     * are always applied — see tpc_curl_apply_stall_bounds.) */
    ngx_uint_t     tpc_low_speed_bytes; /* CURLOPT_LOW_SPEED_LIMIT (B/s); 0 = off */
    ngx_uint_t     tpc_low_speed_secs;  /* CURLOPT_LOW_SPEED_TIME (s);   0 = off */
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
    ngx_flag_t          http_query_token; /* accept ?authz=<token> (default on) */
    ngx_int_t           macaroon_max_validity; /* seconds cap for macaroon-request */
    ngx_str_t           macaroon_location;      /* location: caveat (issuer URI) */
    ngx_str_t           checksum_on_write; /* §8.3 alg list to persist at PUT (off="") */
    ngx_uint_t          checksum_xattr_format; /* §8.x XROOTD_CKS_FMT_TEXT|XRDCKS */
    ngx_flag_t          dig_enable;        /* §3 XrdDig remote diagnostics (default off) */
    ngx_array_t        *dig_exports;       /* §3 of xrootd_dig_export_t (name→canon dir) */
    ngx_str_t           dig_auth_file;     /* §3 principal→export allow-file (fail-closed) */

    /* --- CORS settings --- */
    ngx_array_t        *cors_origins;    /* allowed origins (ngx_str_t array) */
    ngx_flag_t          cors_credentials; /* Access-Control-Allow-Credentials */
    ngx_uint_t          cors_max_age;     /* Access-Control-Max-Age in seconds */

    /* --- ZIP member access (phase-57 W2) ---
     * [xrootd_webdav_zip_access on|off] — opt-in, off by default.  A GET whose
     * query carries "?xrdcl.unzip=<member>" serves that member of the archive
     * (stored + deflate).  Unlike root://, an HTTP client cannot self-inflate,
     * so the server must extract.  zip_cd_max_bytes caps the central-directory
     * read (bomb guard; default 16 MiB). */
    ngx_flag_t          zip_access;
    size_t              zip_cd_max_bytes;

    /* --- WebDAV LOCK --- */
    ngx_uint_t          lock_timeout;    /* max lock timeout in seconds */
    ngx_flag_t          lock_startup_sweep; /* on = remove all persisted lock
                                             * xattrs under the export root at
                                             * startup (restores ephemeral,
                                             * RFC 4918 §10.1 semantics). off by
                                             * default: locks survive restart */

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
    ngx_http_upstream_resolved_t *upstream_resolved;   /* pre-resolved address (backend[0]) */
#if (NGX_HTTP_SSL)
    ngx_ssl_t                    *upstream_ssl_ctx;    /* SSL context for https upstream */
#endif

    /* ---- Phase 21 Step D: multi-backend proxy (round-robin + health) ---- */
    ngx_array_t                  *upstream_urls;       /* ngx_str_t[] from the directive */
    ngx_array_t                  *upstream_backends;   /* xrootd_webdav_backend_t[] */
    ngx_atomic_t                  upstream_rr;         /* per-worker round-robin cursor */
    ngx_uint_t                    upstream_max_fails;  /* [xrootd_webdav_proxy_max_fails N] */
    ngx_msec_t                    upstream_fail_timeout; /* [..._proxy_fail_timeout Ns] */

    /* ---- Phase 23: dynamic SHM backend pool (runtime add/remove/drain) ---- */
    ngx_flag_t                    proxy_pool_enabled;  /* [xrootd_webdav_proxy_dynamic on] */

    /* ---- Phase 20: shared-memory caches & rate limiting ---- */
    xrootd_kv_t                  *token_cache_kv; /* [xrootd_token_cache zone=]
                                                     JWT validation cache (L2/SHM); NULL = off */
    /* Phase 50: always-on per-worker L1 token-validation cache (lockless),
     * lazily created on first token auth — see token/worker_cache.h. */
    struct xrootd_token_l1_s     *token_l1;
    xrootd_rate_limit_conf_t      rate_limit;     /* [xrootd_rate_limit zone= rate= burst= key=]
                                                     per-IP request throttle; kv NULL = off */

    /* ---- Phase 21 Step C: OIDC token introspection (revocation) ---- */
    ngx_str_t      introspect_url;       /* [..._token_introspect_url <url>] (display/doc) */
    ngx_str_t      introspect_loc;       /* [..._token_introspect_loc /internal] internal URI */
    ngx_uint_t     introspect_ttl;       /* [..._token_introspect_ttl N] revoke-cache TTL (s) */
    ngx_flag_t     introspect_fail_open; /* [..._token_introspect_fail_open on|off] */
    xrootd_kv_t   *revoke_kv;            /* [..._revoke_cache zone=] revoked-token cache */

    /* ---- Phase 24: traffic mirroring (off by default) ---- */
    xrootd_mirror_conf_t      mirror;            /* [xrootd_mirror_url, _mirror_*] */
    ngx_http_upstream_conf_t  mirror_upstream_conf; /* shadow upstream defaults */
#if (NGX_HTTP_SSL)
    ngx_ssl_t                *mirror_ssl_ctx;    /* TLS ctx for https shadow targets */
#endif

    /* ---- Phase 25: advanced rate limiting (off by default) ---- */
    ngx_array_t              *rl_rules;          /* xrootd_rl_rule_t[] from
                                                  [xrootd_rate_limit_rule /
                                                   _bandwidth_limit]; NULL = off */

    /* ---- XrdAcc authorization engine (off by default) ---- */
    xrootd_acc_http_t         acc;               /* settings + per-worker state */

    /* Per-socket TCP congestion control (e.g. "bbr") applied to the HTTP
     * connection before the GET body is served; empty = kernel default.  The
     * sender's CC governs download throughput, and BBR ignores the spurious loss
     * signals packet reordering induces. [xrootd_tcp_congestion] */
    ngx_str_t                 tcp_congestion;
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
    char           lock_owner[256];

    /* Phase 21 Step C — OIDC introspection state (auth_request-style). */
    unsigned       introspect_done:1;    /* subrequest finished */
    unsigned       introspect_active:1;  /* 1 = token active (allow) */

    /* Phase 24 — traffic mirror state. */
    unsigned          mirror_fired:1;    /* main req: mirror subrequests issued */
    unsigned          is_mirror:1;       /* this request IS a mirror subrequest */
    ngx_uint_t        mirror_target_idx; /* which conf->mirror.targets[] entry */
    ngx_uint_t        primary_status;    /* main req: final HTTP status (divergence) */
    ngx_http_status_t mirror_status;     /* scratch for the shadow response parser */

    /* Phase 25 — bandwidth charge target set by the rate-limit access handler;
     * consumed by the body filter.  rl_bw_rule is an xrootd_rl_rule_t* (void to
     * avoid pulling ratelimit.h into this header). */
    void             *rl_bw_rule;
    char              rl_key_str[128];

    /* W7 — concurrency slot acquired by the rate-limit access handler and
     * released in the log phase (always runs → leak-free).  rl_conc_rule is an
     * xrootd_rl_rule_t* (void here for the same header-isolation reason). */
    void             *rl_conc_rule;
    char              rl_conc_key[128];
} ngx_http_xrootd_webdav_req_ctx_t;

extern ngx_module_t ngx_http_xrootd_webdav_module;

/* Escape control bytes/quotes/backslashes/non-ASCII in `in` to \xNN, writing a
 * NUL-terminated result into out[outsz] (truncated to fit).  Returns the number
 * of bytes written (excluding the NUL).  Use on any wire-derived string before
 * logging. */
size_t xrootd_sanitize_log_string(const char *in, char *out, size_t outsz);
/*
 * Confined filesystem operations.  All take a pre-canonicalised root_canon
 * (from xrootd_get_canonical_root) and absolute `resolved` paths the caller has
 * already confirmed live under it; each enforces a second, kernel-level
 * confinement layer (openat2 RESOLVE_BENEATH, else O_NOFOLLOW fallback) so a
 * symlink swapped in after resolution still cannot escape the export root.
 * Return values mirror the underlying syscall: open returns the fd (caller MUST
 * close it — it is NOT pool-managed), the rest return 0 on success; all return
 * -1 with errno set on failure.  flags/mode follow open(2) (mode used only with
 * O_CREAT — do not pass permission bits in the flags slot).
 */
int xrootd_open_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, int flags, mode_t mode);
/* unlinkat under confinement; is_dir != 0 adds AT_REMOVEDIR (rmdir). */
int xrootd_unlink_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, int is_dir);
/* mkdirat under confinement (single level; parent must already exist). */
int xrootd_mkdir_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, mode_t mode);
/* renameat under confinement; BOTH src and dst parents are confined. */
int xrootd_rename_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *src_resolved, const char *dst_resolved);
/* linkat (hard link) under confinement; BOTH src and dst parents are confined. */
int xrootd_link_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *src_resolved, const char *dst_resolved);

/* Module wiring */
/* Allocate+default-init the loc conf (cf->pool); returns it, or NULL on OOM. */
void *ngx_http_xrootd_webdav_create_loc_conf(ngx_conf_t *cf);
/* Inherit unset child fields from parent; returns NGX_CONF_OK or
 * NGX_CONF_ERROR (also where invalid combinations are diagnosed). */
char *ngx_http_xrootd_webdav_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
/* Register the access/content handlers, init SSL ex_data indices, and build the
 * CA store.  Returns NGX_OK or NGX_ERROR (fails `nginx -t`). */
ngx_int_t ngx_http_xrootd_webdav_postconfiguration(ngx_conf_t *cf);
/* ACCESS-phase gate: CORS, request metrics, rate limit, then the auth gate
 * (cert/token) + write-scope check.  NGX_DECLINED if module disabled, NGX_OK to
 * allow, an NGX_HTTP_* status to reject. */
ngx_int_t ngx_http_xrootd_webdav_access_handler(ngx_http_request_t *r);
/* CONTENT-phase handler: routes the (already authorised) request to the
 * per-method handler.  NGX_DECLINED for unknown methods (-> 405); otherwise an
 * NGX_HTTP_* status, or NGX_DONE when a handler finalised the request itself. */
ngx_int_t ngx_http_xrootd_webdav_handler(ngx_http_request_t *r);

/* Phase 21 Step C — OIDC token introspection (revocation). */
/* Extra ACCESS-phase handler: checks the bearer token against the revocation
 * cache, firing an introspection subrequest on miss.  NGX_DECLINED (allow /
 * not configured), NGX_HTTP_FORBIDDEN (revoked), NGX_AGAIN (suspended until the
 * subrequest completes), or NGX_ERROR. */
ngx_int_t webdav_introspect_access_handler(ngx_http_request_t *r);
/* Directive setter for `xrootd_webdav_revoke_cache zone=<name>`; binds the
 * named SHM kv zone into conf->revoke_kv. */
char     *webdav_conf_revoke_cache(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/* Operation Registry (operation_table.c) */
extern const xrootd_http_operation_t xrootd_webdav_operations[];
extern const ngx_uint_t xrootd_webdav_operations_count;

/* Path, URI, XML, and logging utilities */
/* Canonical helper (see HELPERS): url-decode r->uri, strip trailing slashes,
 * and resolve+confine under root_canon into out[outsz].  NGX_OK, else an
 * NGX_HTTP_* status (404/403/414/500/400-on-NUL). */
ngx_int_t ngx_http_xrootd_webdav_resolve_path(ngx_http_request_t *r,
    const char *root_canon, char *out, size_t outsz);
/* Resolve an already-decoded Destination path (COPY/MOVE target) under
 * root_canon.  Same as above but maps a non-existent parent to
 * NGX_HTTP_CONFLICT (409) per RFC 4918.  op_label/log are advisory. */
ngx_int_t webdav_resolve_destination_path(ngx_log_t *log, const char *op_label,
    const char *root_canon, const char *decoded_path, char *out, size_t outsz);
/* resolve_path + stat in one call: fills path[pathsz] and, if sb != NULL,
 * sb (via the VFS layer).  NGX_OK; 404 if missing, 500 on other stat error,
 * or the resolve error.  sb fields beyond size/mtime/ctime/mode/ino are zeroed. */
ngx_int_t webdav_resolve_stat(ngx_http_request_t *r, char *path,
    size_t pathsz, struct stat *sb);
/* Percent-decode src[src_len] into NUL-terminated dst[dst_sz], rejecting
 * embedded NULs.  NGX_OK / 414 overflow / 400 NUL byte / 500. */
ngx_int_t webdav_urldecode(const u_char *src, size_t src_len,
    char *dst, size_t dst_sz);
/* Strip a leading scheme://authority from a Destination header value; on NGX_OK
 * *path_out points INTO dest_data (no copy) and *path_len_out is its length.
 * NGX_HTTP_BAD_REQUEST if the path part would be empty. */
ngx_int_t webdav_destination_extract_path(const u_char *dest_data,
    size_t dest_len, const u_char **path_out, size_t *path_len_out);
/* XML-escape a C string for response bodies (& < > " ' as entities, control
 * bytes as %XX).  Result allocated from `pool`; NULL on OOM or NULL args. */
char *webdav_escape_xml_text(ngx_pool_t *pool, const char *src);
/* Sole CORS entry point (see HELPERS): emit Access-Control-* per the request
 * Origin and config.  Always NGX_OK (no/denied Origin folded to OK) except
 * NGX_ERROR on allocation failure. */
ngx_int_t webdav_add_cors_headers(ngx_http_request_t *r);
/* Lock xattr encode/decode/read/write/delete (prop_xattr.c) */
/* Serialise a lock entry to the pipe-delimited xattr value form in out[outsz].
 * NGX_OK, or NGX_ERROR if it would not fit. */
ngx_int_t webdav_lock_xattr_encode(const webdav_lock_xattr_t *e,
    char *out, size_t outsz);
/* Parse a stored lock value raw[rawlen] back into *e.  NGX_OK; NGX_DECLINED if
 * empty/oversized or no token field was found (not a valid lock record). */
ngx_int_t webdav_lock_xattr_decode(const char *raw, size_t rawlen,
    webdav_lock_xattr_t *e);
/* setxattr the encoded lock onto `path`.  Pass flags=XATTR_CREATE for atomic
 * cross-worker lock acquisition: NGX_DECLINED means another worker won the race
 * (EEXIST -> caller maps to 423).  NGX_OK / NGX_ERROR otherwise.  Takes the
 * request (not just a log) so the lock xattr is written as the mapped user under
 * impersonation (root_canon is derived from the request's loc conf). */
ngx_int_t webdav_lock_xattr_write(ngx_http_request_t *r, const char *path,
    const webdav_lock_xattr_t *e, int flags);
/* getxattr+decode the lock on `path`.  NGX_OK; NGX_DECLINED if no lock present
 * (or path gone); NGX_ERROR on a real getxattr fault. */
ngx_int_t webdav_lock_xattr_read(ngx_http_request_t *r, const char *path,
    webdav_lock_xattr_t *e);
/* removexattr the lock on `path`.  Idempotent: NGX_OK even if absent; NGX_ERROR
 * only on an unexpected fault. */
ngx_int_t webdav_lock_xattr_delete(ngx_http_request_t *r, const char *path);

/*
 * webdav_lock_startup_sweep — recursively remove every persisted lock xattr
 * (WEBDAV_LOCK_XATTR_KEY) under root_canon.  Used at startup when
 * xrootd_webdav_lock_startup_sweep is on, to restore ephemeral lock semantics.
 * Returns the number of lock xattrs removed.
 */
ngx_uint_t webdav_lock_startup_sweep(ngx_log_t *log, const char *root_canon);

/* Walk path -> export root checking each level's lock xattr (O(path_depth)
 * getxattr calls); expired locks are lazily deleted in passing.  NGX_HTTP_LOCKED
 * if an unexpired lock not matched by the request If header covers `path`; 500
 * on a getxattr fault; NGX_OK otherwise.  need_write is currently advisory. */
ngx_int_t webdav_check_locks(ngx_http_request_t *r, const char *path,
    int need_write);
/* webdav_check_locks() plus, when `path` is a directory, a recursive descendant
 * scan (opendir walk).  Use for DELETE/COPY/MOVE on collections so a lock on any
 * child blocks the op.  Same return codes as webdav_check_locks(). */
ngx_int_t webdav_check_locks_tree(ngx_http_request_t *r, const char *path);
/* Append <D:lockdiscovery> for `path` to the head/tail chain (r->pool), reading
 * the live lock xattr (empty element if none/expired; owner XML-escaped; expired
 * locks lazily deleted).  NGX_OK / NGX_ERROR on chain alloc failure. */
ngx_int_t webdav_lock_append_discovery(ngx_http_request_t *r, const char *path,
    ngx_chain_t **head, ngx_chain_t **tail);
/* Append the static <D:supportedlock> element (exclusive+shared write) to the
 * head/tail chain (r->pool).  NGX_OK / NGX_ERROR on chain alloc failure. */
ngx_int_t webdav_lock_append_supported(ngx_http_request_t *r,
    ngx_chain_t **head, ngx_chain_t **tail);
/* Classify the request method into the WebDAV metric slot (the requests_total
 * index); XROOTD_WEBDAV_METHOD_OTHER for unrecognised verbs. */
ngx_uint_t webdav_metrics_method(ngx_http_request_t *r);
/* Count this request's arrival (requests_total[method]). */
void webdav_metrics_request(ngx_http_request_t *r);
/* Record the outcome (responses_total[method][status-class] + unified op),
 * deriving the status from rc/headers_out.  No-op when rc == NGX_DONE (the
 * request already accounted for itself). */
void webdav_metrics_response(ngx_http_request_t *r, ngx_int_t rc);
/* webdav_metrics_response(r, rc) then return rc — convenience for handler tails. */
ngx_int_t webdav_metrics_return(ngx_http_request_t *r, ngx_int_t rc);
/* Emit a status-only (empty-body) response — set status + zero content length,
 * send the header, and finalise via the send_special result (records response
 * metrics).  Finalises the request: must be the caller's last action on `r`.
 * Set any extra headers (e.g. Location for 201) before calling. */
void webdav_send_status_only(ngx_http_request_t *r, ngx_uint_t status);
/* webdav_metrics_response(r, rc) then ngx_http_finalize_request(r, rc) — for
 * async/self-finalising paths. */
void webdav_metrics_finalize_request(ngx_http_request_t *r, ngx_int_t rc);

/* Authentication */
/* Allocate the global SSL/SSL_SESSION ex_data indices used to cache TLS auth
 * results; call once at postconfig.  NGX_OK / NGX_ERROR. */
ngx_int_t webdav_auth_init_ssl_indices(ngx_log_t *log);
/* Build an X509_STORE from conf->cadir/cafile/crl (no proxy-cert chains for
 * plain WebDAV x509).  Returns the store (caller/postconfig owns it) or NULL;
 * *crl_count_out receives the number of CRLs loaded. */
X509_STORE *webdav_build_ca_store(ngx_log_t *log,
    ngx_http_xrootd_webdav_loc_conf_t *conf, int *crl_count_out);
/* Auth gate (see HELPERS): verify the peer's GSI/X.509 (proxy) cert against
 * conf->ca_store, allocating+caching the req ctx and identity.  Result is
 * memoised per TLS session.  NGX_OK; 403 (no/invalid cert or non-TLS); 500. */
ngx_int_t webdav_verify_proxy_cert(ngx_http_request_t *r,
    ngx_http_xrootd_webdav_loc_conf_t *conf);
/* Auth gate (see HELPERS): validate the Bearer token (JWKS JWT or macaroon,
 * with old-secret grace-period fallback) and stash claims/scopes in the req
 * ctx.  NGX_OK; NGX_DECLINED if no token/keys configured (try other auth);
 * 401 invalid; 500. */
ngx_int_t webdav_verify_bearer_token(ngx_http_request_t *r,
    ngx_http_xrootd_webdav_loc_conf_t *conf);
/* For token-authed mutating methods, require a write scope covering r->uri
 * (matched against the decoded URI path, not the filesystem path).  NGX_OK if
 * granted OR auth was not token-based; NGX_HTTP_FORBIDDEN otherwise. */
ngx_int_t webdav_check_token_write_scope(ngx_http_request_t *r,
    const char *method_name);
/* Postconfig-time validation of CA/CRL paths so misconfiguration fails
 * `nginx -t`.  NGX_OK / NGX_ERROR. */
ngx_int_t webdav_check_pki_consistency(ngx_log_t *log,
    ngx_http_xrootd_webdav_loc_conf_t *conf);

/* HTTP methods.  Unless noted, each fully handles its method and returns NGX_OK
 * or an NGX_HTTP_* status for the dispatcher to finalise; the `void` ones own
 * the response and finalise the request themselves (async/body paths). */
/* OPTIONS: emit DAV/DASL/Allow headers (Allow derived from the live op table). */
ngx_int_t webdav_handle_options(ngx_http_request_t *r);
/* HEAD/GET-metadata: resolve+stat, set Content-Length/Type/Last-Modified/ETag
 * and send headers; send_body=0 (or r->header_only) emits no body. */
ngx_int_t webdav_handle_head(ngx_http_request_t *r, int send_body);
/* GET a file body (range/multipart aware, cache-backed); 403 on a directory. */
ngx_int_t webdav_handle_get(ngx_http_request_t *r);
/* PUT: body read callback — streams the request body to the destination file
 * and finalises the request (it self-finalises; do not also return its rc). */
void webdav_handle_put_body(ngx_http_request_t *r);
/* DELETE: lock-checked recursive removal (204, or 404/409/500). */
ngx_int_t webdav_handle_delete(ngx_http_request_t *r);
/* Recursively remove the tree at `path` under confinement (no request/lock
 * context).  Returns the underlying remove-tree result. */
ngx_int_t webdav_delete_path_recursive(ngx_log_t *log, const char *root_canon,
    const char *path);
/* MKCOL: create one collection (201; 409 if parent missing, 405 if exists). */
ngx_int_t webdav_handle_mkcol(ngx_http_request_t *r);
/* PROPFIND: 207 Multi-Status (Depth 0/1) incl. live + dead properties + locks. */
ngx_int_t webdav_handle_propfind(ngx_http_request_t *r);
/* PROPPATCH: set/remove dead (xattr) properties; rejects protected DAV: props. */
ngx_int_t webdav_handle_proppatch(ngx_http_request_t *r);
/* SEARCH (RFC 5323 DAV:basicsearch) over the request-URI scope. */
ngx_int_t webdav_handle_search(ngx_http_request_t *r);
/* ACL: read-only export — always 403 with a cannot-modify-protected-property
 * error body (client-side ACL mutation is not permitted). */
ngx_int_t webdav_handle_acl(ngx_http_request_t *r);

/* MOVE: lock-checked rename within the export (201/204; may finalise -> NGX_DONE). */
ngx_int_t webdav_handle_move(ngx_http_request_t *r);
/* COPY: in-export copy (NOT third-party — see tpc_handle_copy for Source/Dest). */
ngx_int_t webdav_handle_copy(ngx_http_request_t *r);
/* LOCK: create/refresh a lock and send the lockdiscovery body; self-finalises. */
void webdav_handle_lock(ngx_http_request_t *r);
/* UNLOCK: remove the lock named by the Lock-Token header (204; 400/409/412). */
ngx_int_t webdav_handle_unlock(ngx_http_request_t *r);

/* Macaroon token issuance endpoints (macaroon_endpoint.c) */
/* GET /.well-known/oauth-authorization-server discovery document. */
ngx_int_t webdav_handle_macaroon_discovery(ngx_http_request_t *r);
/* POST /.oauth2/token: mint a scoped macaroon; self-finalises the request. */
void webdav_handle_macaroon_token(ngx_http_request_t *r);
/* POST <path> with Content-Type: application/macaroon-request (dCache/XrdMacaroons
 * convention): mint a macaroon from a JSON {caveats[],validity} body, returning the
 * dCache {macaroon, uri{...}} shape. Self-finalises the request. */
void webdav_handle_macaroon_request(ngx_http_request_t *r);

/* §3 XrdDig: GET/HEAD /.well-known/dig/<export>/<rel> — read-only, RESOLVE_BENEATH-
 * confined, allow-file-gated exposure of whitelisted server files. Returns an HTTP
 * status, or NGX_DECLINED when dig is disabled / the path is not a dig path (so
 * normal WebDAV handling proceeds). Defined in src/dig/dig.c. */
ngx_int_t xrootd_dig_handle(ngx_http_request_t *r);

/* Dead WebDAV properties persisted as filesystem extended attributes.
 * `xml` for set() must be already-escaped, well-formed XML — it is stored and
 * echoed back verbatim.  ns/local identify the property (namespace URI + local
 * name); head/tail are an ngx_chain_t accumulator for response XML. */
/* PROPPATCH set: store xml[xml_len] as the property's xattr value.  NGX_OK;
 * NGX_ERROR (errno ENAMETOOLONG if the name/value is over the cap). */
ngx_int_t webdav_dead_prop_set(ngx_http_request_t *r, const char *path,
    const char *ns, const char *local, const char *xml, size_t xml_len);
/* PROPPATCH remove: delete the property's xattr.  Idempotent (absent -> NGX_OK). */
ngx_int_t webdav_dead_prop_remove(ngx_http_request_t *r, const char *path,
    const char *ns, const char *local);
/* PROPFIND: if the named property exists, append its stored XML and set *found=1;
 * a missing property is NGX_OK with *found=0 (caller reports 404 in-multistatus).
 * NGX_ERROR only on a real fault. */
ngx_int_t webdav_dead_prop_append_value(ngx_http_request_t *r,
    const char *path, const char *ns, const char *local,
    ngx_chain_t **head, ngx_chain_t **tail, ngx_flag_t *found);
/* PROPFIND propname: append an empty self-closing element for one name.
 * NGX_OK / NGX_ERROR. */
ngx_int_t webdav_dead_prop_append_empty(ngx_http_request_t *r,
    const char *ns, const char *local, ngx_chain_t **head,
    ngx_chain_t **tail);
/* PROPFIND allprop/propname: enumerate every dead property on `path`, appending
 * name (names_only) or name+value.  NGX_OK (incl. none present) / NGX_ERROR. */
ngx_int_t webdav_dead_props_append_all(ngx_http_request_t *r,
    const char *path, ngx_chain_t **head, ngx_chain_t **tail,
    ngx_flag_t names_only);
/* True if `local` is a protected (server-managed) DAV: property that PROPPATCH
 * may not touch; the caller has already matched the DAV: namespace, so this is
 * effectively a non-NULL guard returning 1. */
ngx_flag_t webdav_dead_prop_is_protected_dav(const char *local);
/* Copy all dead properties from src to dst (so they travel with COPY/MOVE);
 * best-effort, no return value. */
void webdav_dead_props_copy(ngx_log_t *log, const char *src, const char *dst);

/* File I/O helpers */
/* Advisory POSIX_FADV_WILLNEED readahead hint; best-effort, no-op if
 * unsupported or len==0. */
void webdav_fadvise_willneed(ngx_log_t *log, ngx_fd_t fd, off_t offset,
    size_t len);
/* write(2) the whole buffer, retrying EINTR/short writes.  NGX_OK / NGX_ERROR
 * (errno set; EIO on a 0-byte write). */
ngx_int_t webdav_write_full(ngx_fd_t fd, u_char *buf, size_t len, off_t offset);
/* Copy a spooled PUT temp file (buf->file) into dst_fd, preferring zero-copy
 * copy_file_range with a pread+write fallback.  `scratch` is an optional reused
 * fallback buffer slot (may be ignored).  NGX_OK / NGX_ERROR. */
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
/* Set the TPC-related loc-conf fields to NGX_CONF_UNSET[_UINT] (called from the
 * module's create_loc_conf). */
void ngx_http_xrootd_webdav_tpc_create_loc_conf(
    ngx_http_xrootd_webdav_loc_conf_t *conf);
/* Merge the TPC-related fields, inheriting unset values from `prev` and applying
 * defaults (called from the module's merge_loc_conf). */
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

/* Copy data[len] into a fresh NUL-terminated `pool` buffer; NULL on OOM. */
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
/* Gather every "TransferHeaderX-Foo: bar" request header into a fresh r->pool
 * ngx_array_t of ngx_str_t "X-Foo: bar" (NUL-terminated), capped at
 * WEBDAV_TPC_MAX_HEADERS, for forwarding by curl.  *out set on NGX_OK; 400 if a
 * name/value has control bytes or the cap is exceeded; NGX_ERROR on OOM. */
ngx_int_t webdav_tpc_collect_transfer_headers(ngx_http_request_t *r,
    ngx_array_t **out);
/* Blocking single-stream curl pull (source_url -> tmp_path); runs on a thread,
 * not the event loop.  transfer_id keys the live-transfer registry; bumps the
 * TPC success/error metric.  NGX_OK / NGX_HTTP_* on failure. */
ngx_int_t webdav_tpc_run_curl_pull(ngx_log_t *log,
    ngx_http_xrootd_webdav_loc_conf_t *conf, const char *source_url,
    const char *tmp_path, ngx_array_t *transfer_headers,
    uint64_t transfer_id);
/* Blocking curl push (local_path -> dest_url); thread-only, mirror of the pull
 * above.  NGX_OK / NGX_HTTP_* on failure. */
ngx_int_t webdav_tpc_run_curl_push(ngx_log_t *log,
    ngx_http_xrootd_webdav_loc_conf_t *conf, const char *dest_url,
    const char *local_path, ngx_array_t *transfer_headers,
    uint64_t transfer_id);
/* Post a curl pull/push to conf->common.thread_pool (the 201 non-marker path).
 * local_path/dest_path are copied into the task ctx (caller stack buffers safe to
 * reuse).  On NGX_DONE it has taken a request ref (r->main->count++) and the
 * done-handler finalises; the caller must propagate NGX_DONE.  NGX_DECLINED if no
 * thread pool (use the sync path); 503 if the transfer registry is full;
 * NGX_ERROR on alloc/post failure or bad args. */
ngx_int_t webdav_tpc_post_thread_task(ngx_http_request_t *r,
    ngx_http_xrootd_webdav_loc_conf_t *conf,
    int is_push, ngx_flag_t existed, ngx_flag_t overwrite,
    const char *url, const char *local_path, const char *dest_path,
    ngx_array_t *transfer_headers, ngx_uint_t n_streams);
/* Blocking parallel-range curl_multi pull into tmp_path: HEADs for size, splits
 * into n_streams disjoint ranges each pwrite-ing in place (no merge), capped at
 * XROOTD_TPC_MAX_STREAMS.  Falls back to single-stream when size is unknown or
 * n_streams <= 1.  progress may be NULL; when set, each stream atomically updates
 * bytes_per_stream[i] for the poll timer.  NGX_OK / NGX_HTTP_* on failure. */
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
/* HTTP-TPC COPY dispatcher: routes by Source (pull, https only) vs Destination
 * (push) header, parses X-Number-Of-Streams (capped at conf->tpc_max_streams),
 * stages a pull through a temp file (atomic rename/link on success, unlink on
 * failure), and tries marker -> thread-pool -> sync tiers.  NGX_OK (201/204 sent
 * via webdav_send_no_body), an NGX_HTTP_* status for the dispatcher to finalise,
 * or NGX_DONE when an async (202 marker / thread) path self-finalises. */
ngx_int_t ngx_http_xrootd_webdav_tpc_handle_copy(ngx_http_request_t *r);

/* Upstream HTTP(S) proxy */
/* Content-phase handler (proxy mode): create the nginx upstream, pick a backend
 * (dynamic SHM pool or static round-robin array), set ssl per backend, and start
 * the request via xrootd_http_read_body.  Returns NGX_DONE on the async upstream
 * path; an NGX_HTTP_* status (500 OOM, 503 no live backend) on setup failure. */
ngx_int_t webdav_proxy_handler(ngx_http_request_t *r);
/* Backward-compat single-URL config parser; thin wrapper over
 * webdav_proxy_build_backends.  NGX_OK / NGX_ERROR. */
ngx_int_t webdav_proxy_parse_upstream_url(ngx_conf_t *cf,
    ngx_http_xrootd_webdav_loc_conf_t *conf);
/* Postconfig: build conf->upstream_backends (cf->pool) from upstream_urls (or the
 * legacy single upstream_url), apply upstream_conf timeout/buffer defaults, wire
 * the TLS ctx, and point the legacy upstream_* aliases at backend[0].  NGX_ERROR
 * (fails nginx -t) when no usable backend; NGX_OK otherwise. */
ngx_int_t webdav_proxy_build_backends(ngx_conf_t *cf,
    ngx_http_xrootd_webdav_loc_conf_t *conf);
/* Directive setter: xrootd_webdav_proxy_upstream <url> [<url> ...]; */
char *webdav_conf_proxy_upstream(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/* HTTP-TPC credential delegation */
/* Map a Credential-mode token value[len] to the enum; "none"/"oidc-agent"/
 * "token-exchange" recognised, else XROOTD_TPC_CRED_UNKNOWN. */
xrootd_tpc_cred_mode_e webdav_tpc_cred_parse_mode(const char *value, size_t len);
/* Obtain a delegated bearer token for the TPC transfer via the given mode
 * (oidc-agent fetch, or RFC 8693 token-exchange of subject_token at the
 * configured token_endpoint), validating the result.  On NGX_OK *token_out is
 * filled from r->pool (NUL-terminated); bumps the tpc_cred started/success/error
 * metrics.  NGX_ERROR on misconfig, missing subject token, fetch, or validation
 * failure. */
ngx_int_t webdav_tpc_cred_obtain_token(ngx_http_request_t *r,
    xrootd_tpc_cred_mode_e mode, const char *source_url,
    const char *subject_token, const char *scope, ngx_str_t *token_out);
/* Static metric-name string for a tpc_cred metric index (never NULL; do not
 * free). */
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

/*
 * webdav_send_no_body — send a complete response with no body.
 *
 * Covers the common case: status + Content-Length: 0 + send_header + send_special.
 * Used by DELETE, MKCOL, COPY, MOVE, LOCK unlock, TPC success paths.
 */
static inline ngx_int_t
webdav_send_no_body(ngx_http_request_t *r, ngx_uint_t status)
{
    r->headers_out.status           = status;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);
    return ngx_http_send_special(r, NGX_HTTP_LAST);
}

#endif /* XROOTD_WEBDAV_H */

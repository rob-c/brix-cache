#ifndef BRIX_WEBDAV_H
#define BRIX_WEBDAV_H

/*
 * webdav.h — Shared types, configuration structs, and function declarations for the
 * nginx HTTP WebDAV module (davs:// endpoint).
 *
 * WHAT: Declares all shared data structures used across WebDAV source files:
 *       location-level config (`ngx_http_brix_webdav_loc_conf_t`), per-request
 *       auth context (`ngx_http_brix_webdav_req_ctx_t`), lock table entry and
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
 *       16. Capability table macro — BRIX_WEBDAV_ALLOW_FLAGS()
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

#include "observability/metrics/metrics.h"
#include "core/compat/error_mapping.h"
#include "core/http/http_headers.h"
#include "core/compat/log.h"
#include "auth/token/token.h"
#include "core/types/identity.h"
#include "auth/authz/acc/acc.h"
#include "tpc_config.h"
#include "tpc_cred.h"
#include "core/compat/path.h"
#include "core/compat/protocol_caps.h"
#include "core/config/shared_conf.h"
#include "core/shm/kv.h"
#include "net/mirror/mirror.h"
#include "core/shm/rate_limit.h"

#include <ngx_open_file_cache.h>

/* XrdHttp protocol extension API — included here so all webdav source
 * files see both the webdav and xrdhttp types in a single include. */
#include "xrdhttp.h"

typedef struct x509_store_st X509_STORE;

#define WEBDAV_MAX_PATH          BRIX_PATH_MAX
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
} brix_dig_export_t;

typedef struct {
    ngx_http_brix_shared_conf_t common; /* enable, root, root_canon, allow_write,
                                             thread_pool_name, thread_pool */

    /* --- Optional read-through cache root --- */
    ngx_str_t   cache_root;               /* [brix_webdav_cache_root /path] */
    char        cache_root_canon[PATH_MAX]; /* realpath-resolved form; "" = disabled */

    /* --- VOMS VO extraction (optional; requires libvomsapi) --- */
    ngx_str_t   vomsdir;       /* [brix_webdav_vomsdir /etc/grid-security/vomsdir] */
    ngx_str_t   voms_cert_dir; /* [brix_webdav_voms_cert_dir /etc/grid-security/certificates] */

    /* --- X.509 / GSI authentication --- */
    ngx_str_t      cadir;           /* directory of trusted CA PEM files */
    ngx_str_t      cafile;          /* single trusted CA bundle PEM file */
    ngx_str_t      crl;             /* directory of CRL PEM files */
    ngx_uint_t     signing_policy_mode; /* [brix_webdav_signing_policy] BRIX_SP_MODE_* */
    ngx_uint_t     crl_mode;        /* [brix_webdav_crl_mode] BRIX_CRL_MODE_* */
    ngx_uint_t     verify_depth;    /* max proxy chain depth for VOMS proxies;
                                     * RFC 3820 §4 recommends <= 3 for WLCG */
    ngx_uint_t     auth;            /* webdav_auth_t: NONE/OPTIONAL/REQUIRED */
    ngx_flag_t     proxy_certs;     /* 1 to accept RFC 3820 proxy certificates */
    X509_STORE    *ca_store;        /* loaded trust store; built at postconfiguration;
                                     * NULL if no CA dir/file configured */

    /* --- Write permissions / TPC --- */
    ngx_flag_t     tpc;             /* 1 to allow HTTP-TPC (third-party copy) */
    ngx_flag_t     tape_rest;       /* 1 to serve the WLCG /api/v1 Tape REST API */
    ngx_flag_t     upload_resume;   /* [brix_webdav_upload_resume on|off] default
                                     * ON.  When on, a Content-Range PUT writes its
                                     * chunk to a persistent identity-keyed partial
                                     * at the given offset and commits only when the
                                     * upload is complete; a 409 reports X-Upload-
                                     * Offset.  Lets a davs:// upload resume across
                                     * an nginx restart.  See src/webdav/put.c. */
    ngx_str_t      upload_stage_dir;      /* [brix_webdav_stage_dir <path>] optional
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
    ngx_http_brix_tpc_conf_t tpc_cred;

    /* --- Bearer token (WLCG/SciToken) settings --- */
    ngx_str_t      token_jwks;      /* path to JWKS file for RS256 validation */
    ngx_str_t      token_issuer;    /* required "iss" claim; "" to skip check */
    ngx_str_t      token_audience;  /* required "aud" claim; "" to skip check */
    ngx_int_t      token_clock_skew; /* [brix_webdav_token_clock_skew 30] seconds of
                                        exp grace; NGX_CONF_UNSET = inherit/default
                                        (BRIX_TOKEN_CLOCK_SKEW_SECS); max 300 */
    ngx_str_t      token_config;    /* [brix_webdav_token_config <scitokens.cfg>]
                                       multi-issuer registry (phase-59 W1) */
    void          *token_registry;  /* brix_token_registry_t* or NULL */
    ngx_str_t      token_macaroon_secret;     /* [brix_webdav_macaroon_secret <hex>] */
    ngx_str_t      token_macaroon_secret_old; /* [brix_webdav_macaroon_secret_old <hex>]
                                                 grace-period key accepted alongside the
                                                 primary secret during key rotation. */
    brix_jwks_key_t  jwks_keys[BRIX_MAX_JWKS_KEYS]; /* loaded RSA pub keys */
    int                 jwks_key_count;  /* number of valid entries in jwks_keys */
    ngx_flag_t          http_query_token; /* accept ?authz=<token> (default on) */
    ngx_int_t           macaroon_max_validity; /* seconds cap for macaroon-request */
    ngx_str_t           macaroon_location;      /* location: caveat (issuer URI) */
    ngx_str_t           checksum_on_write; /* §8.3 alg list to persist at PUT (off="") */
    ngx_uint_t          checksum_xattr_format; /* §8.x BRIX_CKS_FMT_TEXT|XRDCKS */
    ngx_flag_t          dig_enable;        /* §3 XrdDig remote diagnostics (default off) */
    ngx_array_t        *dig_exports;       /* §3 of brix_dig_export_t (name→canon dir) */
    ngx_str_t           dig_auth_file;     /* §3 principal→export allow-file (fail-closed) */

    /* --- CORS settings --- */
    ngx_array_t        *cors_origins;    /* allowed origins (ngx_str_t array) */
    ngx_flag_t          cors_credentials; /* Access-Control-Allow-Credentials */
    ngx_uint_t          cors_max_age;     /* Access-Control-Max-Age in seconds */

    /* --- ZIP member access (phase-57 W2) ---
     * [brix_webdav_zip_access on|off] — opt-in, off by default.  A GET whose
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
    ngx_flag_t                    upstream_proxy;      /* brix_webdav_proxy on/off */
    ngx_str_t                     upstream_url;        /* brix_webdav_proxy_upstream URL */
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
    ngx_array_t                  *upstream_backends;   /* brix_webdav_backend_t[] */
    ngx_atomic_t                  upstream_rr;         /* per-worker round-robin cursor */
    ngx_uint_t                    upstream_max_fails;  /* [brix_webdav_proxy_max_fails N] */
    ngx_msec_t                    upstream_fail_timeout; /* [..._proxy_fail_timeout Ns] */

    /* ---- Phase 23: dynamic SHM backend pool (runtime add/remove/drain) ---- */
    ngx_flag_t                    proxy_pool_enabled;  /* [brix_webdav_proxy_dynamic on] */

    /* ---- Phase 20: shared-memory caches & rate limiting ---- */
    brix_kv_t                  *token_cache_kv; /* [brix_token_cache zone=]
                                                     JWT validation cache (L2/SHM); NULL = off */
    /* Phase 50: always-on per-worker L1 token-validation cache (lockless),
     * lazily created on first token auth — see token/worker_cache.h. */
    struct brix_token_l1_s     *token_l1;
    brix_rate_limit_conf_t      rate_limit;     /* [brix_rate_limit zone= rate= burst= key=]
                                                     per-IP request throttle; kv NULL = off */

    /* ---- Phase 21 Step C: OIDC token introspection (revocation) ---- */
    ngx_str_t      introspect_url;       /* [..._token_introspect_url <url>] (display/doc) */
    ngx_str_t      introspect_loc;       /* [..._token_introspect_loc /internal] internal URI */
    ngx_uint_t     introspect_ttl;       /* [..._token_introspect_ttl N] revoke-cache TTL (s) */
    ngx_flag_t     introspect_fail_open; /* [..._token_introspect_fail_open on|off] */
    brix_kv_t   *revoke_kv;            /* [..._revoke_cache zone=] revoked-token cache */

    /* ---- Phase 24: traffic mirroring (off by default) ---- */
    brix_mirror_conf_t      mirror;            /* [brix_mirror_url, _mirror_*] */
    ngx_http_upstream_conf_t  mirror_upstream_conf; /* shadow upstream defaults */
#if (NGX_HTTP_SSL)
    ngx_ssl_t                *mirror_ssl_ctx;    /* TLS ctx for https shadow targets */
#endif

    /* ---- Phase 25: advanced rate limiting (off by default) ---- */
    ngx_array_t              *rl_rules;          /* brix_rl_rule_t[] from
                                                  [brix_rate_limit_rule /
                                                   _bandwidth_limit]; NULL = off */

    /* ---- XrdAcc authorization engine (off by default) ---- */
    brix_acc_http_t         acc;               /* settings + per-worker state */

    /* Per-socket TCP congestion control (e.g. "bbr") applied to the HTTP
     * connection before the GET body is served; empty = kernel default.  The
     * sender's CC governs download throughput, and BBR ignores the spurious loss
     * signals packet reordering induces. [brix_tcp_congestion] */
    ngx_str_t                 tcp_congestion;
} ngx_http_brix_webdav_loc_conf_t;

/*
 * Per-request authentication context.  Lifetime: r->pool (request scope).
 *
 * Set by webdav_verify_proxy_cert() or webdav_verify_bearer_token() during
 * the auth gate in ngx_http_brix_webdav_handler().
 */
typedef struct {
    /* XrdHttp per-request context — MUST be first member so that a pointer
     * to this struct can be safely cast to xrdhttp_req_ctx_t * via C struct
     * layout rule (C11 §6.7.2.1p15). */
    xrdhttp_req_ctx_t  xrdhttp;

    int            verified;     /* 1 if auth was accepted, 0 if anonymous */
    brix_identity_t *identity; /* canonical Phase 2 identity object */
    char           dn[1024];     /* Distinguished Name from cert or token sub;
                                  * NUL-terminated; empty string if anonymous */
    const char    *auth_source;  /* "cert", "token", or "anonymous" — static
                                  * string; do not free() */
    int            token_auth;   /* 1 if auth came from a bearer token */
    int            token_scope_count;  /* number of valid entries in token_scopes */
    brix_token_scope_t  token_scopes[BRIX_MAX_TOKEN_SCOPES];
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
     * consumed by the body filter.  rl_bw_rule is an brix_rl_rule_t* (void to
     * avoid pulling ratelimit.h into this header). */
    void             *rl_bw_rule;
    char              rl_key_str[128];

    /* W7 — concurrency slot acquired by the rate-limit access handler and
     * released in the log phase (always runs → leak-free).  rl_conc_rule is an
     * brix_rl_rule_t* (void here for the same header-isolation reason). */
    void             *rl_conc_rule;
    char              rl_conc_key[128];
} ngx_http_brix_webdav_req_ctx_t;

extern ngx_module_t ngx_http_brix_webdav_module;

/* Escape control bytes/quotes/backslashes/non-ASCII in `in` to \xNN, writing a
 * NUL-terminated result into out[outsz] (truncated to fit).  Returns the number
 * of bytes written (excluding the NUL).  Use on any wire-derived string before
 * logging. */
size_t brix_sanitize_log_string(const char *in, char *out, size_t outsz);
/*
 * Confined filesystem operations.  All take a pre-canonicalised root_canon
 * (from brix_get_canonical_root) and absolute `resolved` paths the caller has
 * already confirmed live under it; each enforces a second, kernel-level
 * confinement layer (openat2 RESOLVE_BENEATH, else O_NOFOLLOW fallback) so a
 * symlink swapped in after resolution still cannot escape the export root.
 * Return values mirror the underlying syscall: open returns the fd (caller MUST
 * close it — it is NOT pool-managed), the rest return 0 on success; all return
 * -1 with errno set on failure.  flags/mode follow open(2) (mode used only with
 * O_CREAT — do not pass permission bits in the flags slot).
 */
int brix_open_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, int flags, mode_t mode);
/* unlinkat under confinement; is_dir != 0 adds AT_REMOVEDIR (rmdir). */
int brix_unlink_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, int is_dir);
/* mkdirat under confinement (single level; parent must already exist). */
int brix_mkdir_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *resolved, mode_t mode);
/* renameat under confinement; BOTH src and dst parents are confined. */
int brix_rename_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *src_resolved, const char *dst_resolved);
/* linkat (hard link) under confinement; BOTH src and dst parents are confined. */
int brix_link_confined_canon(ngx_log_t *log, const char *root_canon,
    const char *src_resolved, const char *dst_resolved);

/* Resolve (lazily, per worker) the storage-driver instance for this export: a
 * "pblock" backend is created on first use and cached on the loc conf; "posix"/
 * unset returns NULL (the default POSIX path). Returned as void* (an
 * brix_sd_instance_t*) to keep the SD types out of this header; assign it to a
 * VFS ctx's `sd`. The cache is per worker process (copy-on-write conf), so each
 * worker owns its own SQLite connection. */
void *brix_webdav_backend_instance(
    ngx_http_brix_webdav_loc_conf_t *conf, ngx_log_t *log);

/* Module wiring */
/* Allocate+default-init the loc conf (cf->pool); returns it, or NULL on OOM. */
void *ngx_http_brix_webdav_create_loc_conf(ngx_conf_t *cf);
/* Inherit unset child fields from parent; returns NGX_CONF_OK or
 * NGX_CONF_ERROR (also where invalid combinations are diagnosed). */
char *ngx_http_brix_webdav_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
/* Register the access/content handlers, init SSL ex_data indices, and build the
 * CA store.  Returns NGX_OK or NGX_ERROR (fails `nginx -t`). */
ngx_int_t ngx_http_brix_webdav_postconfiguration(ngx_conf_t *cf);
/* ACCESS-phase gate: CORS, request metrics, rate limit, then the auth gate
 * (cert/token) + write-scope check.  NGX_DECLINED if module disabled, NGX_OK to
 * allow, an NGX_HTTP_* status to reject. */
ngx_int_t ngx_http_brix_webdav_access_handler(ngx_http_request_t *r);
/* CONTENT-phase handler: routes the (already authorised) request to the
 * per-method handler.  NGX_DECLINED for unknown methods (-> 405); otherwise an
 * NGX_HTTP_* status, or NGX_DONE when a handler finalised the request itself. */
ngx_int_t ngx_http_brix_webdav_handler(ngx_http_request_t *r);

/* Phase 21 Step C — OIDC token introspection (revocation). */
/* Extra ACCESS-phase handler: checks the bearer token against the revocation
 * cache, firing an introspection subrequest on miss.  NGX_DECLINED (allow /
 * not configured), NGX_HTTP_FORBIDDEN (revoked), NGX_AGAIN (suspended until the
 * subrequest completes), or NGX_ERROR. */
ngx_int_t webdav_introspect_access_handler(ngx_http_request_t *r);
/* Directive setter for `brix_webdav_revoke_cache zone=<name>`; binds the
 * named SHM kv zone into conf->revoke_kv. */
char     *webdav_conf_revoke_cache(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/* Operation Registry (operation_table.c) */
extern const brix_http_operation_t brix_webdav_operations[];
extern const ngx_uint_t brix_webdav_operations_count;

/* Path / URI / XML request-shaping utilities: confined path + Destination
 * resolvers, resolve+stat, percent-decode, Destination scheme strip, XML escape,
 * and the sole CORS entry point — split into webdav_path.h (included after the
 * shared request/config types). */
#include "webdav_path.h"
/* WebDAV LOCK: xattr-backed lock record primitives, startup sweep, path/tree
 * lock checks, and lockdiscovery/supportedlock body builders — split into
 * webdav_lock.h (included after the shared lock-record/request types). */
#include "webdav_lock.h"
/* WebDAV per-request metric helpers (method-slot classify, request/response
 * counters, status-only + finalise tails) — split into webdav_metrics.h
 * (included after the shared request types). */
#include "webdav_metrics.h"

/* Authentication (webdav_auth.h) */
#include "webdav_auth.h"

/* WebDAV HTTP-method handlers (OPTIONS/HEAD/GET/PUT/DELETE/MKCOL/PROPFIND/
 * PROPPATCH/SEARCH/ACL/MOVE/COPY/LOCK/UNLOCK), macaroon token endpoints, and
 * the XrdDig entry point — split into webdav_methods.h (included after the
 * shared request/config types). */
#include "webdav_methods.h"

/* Dead WebDAV properties (xattr-backed PROPPATCH/PROPFIND + COPY/MOVE carry-over)
 * and the low-level PUT/copy file-I/O helpers — split into webdav_props.h
 * (included after the shared request types). */
#include "webdav_props.h"

/* HTTP third-party-copy (TPC): multi-stream cap + shared progress struct, curl
 * pull/push/multi workers, 202-marker streaming, the COPY dispatcher, and the
 * OAuth2/OIDC credential-delegation helpers — split into webdav_tpc.h.  WebDAV
 * reverse-proxy mode is split into webdav_proxy.h.  Both included after the
 * shared request/config types. */
#include "webdav_tpc.h"
#include "webdav_proxy.h"

/* Operation capability table (operation_table.c) */
#include "core/compat/protocol_caps.h"
extern const brix_http_operation_t brix_webdav_operations[];
extern const ngx_uint_t              brix_webdav_operations_count;
#define BRIX_WEBDAV_ALLOW_FLAGS(conf)                                    \
    (BRIX_PROTO_OP_READ | BRIX_PROTO_OP_LIST                           \
     | ((conf)->common.allow_write                                          \
            ? (BRIX_PROTO_OP_WRITE | BRIX_PROTO_OP_LOCK) : 0)         \
     | ((conf)->tpc ? BRIX_PROTO_OP_TPC : 0))

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

#endif /* BRIX_WEBDAV_H */

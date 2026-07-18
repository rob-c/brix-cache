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
#include "observability/sesslog/sesslog.h"

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

/* The ngx_http_brix_webdav_loc_conf_t struct was split out (phase-79 file-size
 * burndown) into webdav_loc_conf.h, included here so every webdav.h consumer
 * sees the identical type at the same point. */
#include "webdav_loc_conf.h"

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
    /* Raw JWT bytes captured verbatim for backend PASSTHROUGH (phase-70 §5.4);
     * borrowed into r->pool by webdav_verify_bearer_token, valid for the request.
     * Empty unless token auth succeeded. Never logged. */
    ngx_str_t      bearer_token;
    /* User-supplied full x509 proxy PEM (chain + key) captured from the
     * X-Brix-Delegate-Proxy header for backend PASSTHROUGH (phase-70 §5.1);
     * validated (TLS-only + leaf-DN==identity) at the auth gate, borrowed into
     * r->pool. Empty unless the client opted in. Never logged. */
    ngx_str_t      deleg_proxy_pem;
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

    /* Session-lifecycle audit transfer record for request-sized data moves. */
    brix_sess_xfer_t  sess_xfer;
    unsigned          sess_xfer_started:1;
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

/* Directive setters for native WebDAV authorization (read parity with root://).
 * brix_webdav_authdb <file> parses a u/g/p rule file into conf->authdb_rules;
 * brix_webdav_require_vo <path> <vo> appends a VO ACL rule to conf->vo_rules. */
char     *webdav_conf_authdb(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char     *webdav_conf_require_vo(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* brix_client_certificate_folder <dir> — parse-time auto-pick of the stock
 * ssl_client_certificate from an OpenSSL hashed CA dir, matched against the
 * issuer of the server's own ssl_certificate leaf. */
char     *webdav_conf_client_cert_folder(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/* brix_proxy_ssl_capath <dir> — hashed CA dir for the proxy back leg: seeds
 * the stock proxy_ssl_trusted_certificate at parse time (one <hash>.N file)
 * and records the dir for the postconfiguration upstream-SSL_CTX add. */
char     *webdav_conf_proxy_ssl_capath(ngx_conf_t *cf, ngx_command_t *cmd,
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

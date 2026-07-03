#ifndef BRIX_HTTPGUARD_GUARD_HTTP_H
#define BRIX_HTTPGUARD_GUARD_HTTP_H

/*
 * guard_http.h — HTTP adapter for the pure-C bad-actor guard core.
 *
 * WHAT: declares ngx_http_brix_guard_module — the brix_guard* directives,
 *   per-location config (a built guard_ruleset_t + audit-log file), the
 *   ACCESS-phase classify handler (pre-backend bounce) and the LOG-phase
 *   audit handler — plus the guard_request_t builder they share.
 * WHY:  one nginx HTTP module guards both ARC and XrdHttp/WebDAV backends
 *   behind stock proxy_pass; only the `profile` differs. All classification
 *   logic lives in src/net/guard/ (pure C) — this module only normalizes
 *   ngx_http_request_t into guard_request_t and enforces the verdict.
 * HOW:  ACCESS phase runs guard_classify_pre and returns 403/444 on BOUNCE
 *   (backend never touched); LOG phase maps the response status to an
 *   outcome, runs guard_classify_post, and appends one guard_audit_format
 *   line to the configured audit log for fail2ban.
 *
 * Directives (all NGX_HTTP_LOC_CONF, inheritable):
 *   brix_guard                    on|off      enable classification
 *   brix_guard_profile           <name>       "arc" | "xrdhttp" grammar defaults
 *   brix_guard_default_signatures on|off      built-in scanner set (default on)
 *   brix_guard_bounce_status     403|444      pre-backend bounce code (default 444)
 *   brix_guard_audit_log         <path>       fail2ban audit line destination
 *   brix_guard_signature         <substr>     extra blocklist substring (repeatable)
 *   brix_guard_valid_prefix      <prefix>     namespace prefix (repeatable)
 *   brix_guard_valid_method      <m> [m...]   restrict allowed HTTP methods
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "net/guard/guard.h"

typedef struct {
    ngx_flag_t        enable;          /* brix_guard on|off */
    ngx_str_t         profile;         /* "arc" | "xrdhttp" */
    ngx_flag_t        default_sigs;    /* brix_guard_default_signatures */
    ngx_int_t         bounce_status;   /* 403 | 444 */
    ngx_open_file_t  *audit_log;       /* brix_guard_audit_log */
    guard_ruleset_t   ruleset;         /* built at merge time */
    ngx_array_t      *extra_sigs;      /* ngx_str_t, operator additions */
    ngx_array_t      *prefixes;        /* ngx_str_t, operator prefixes */
    ngx_array_t      *methods;         /* ngx_str_t, operator methods */
} ngx_http_brix_guard_loc_conf_t;

/* Per-request state carried from ACCESS phase to LOG phase. */
typedef struct {
    guard_reason_t    pre_reason;      /* NONE unless pre-bounced */
    unsigned          bounced:1;
} ngx_http_brix_guard_ctx_t;

/* Stack scratch sizes for the request builder (sanitizer may expand every
 * byte to \xNN, so the path buffer is generous). */
#define BRIX_GUARD_PATH_BUF  1024
#define BRIX_GUARD_IP_BUF    64

extern ngx_module_t ngx_http_brix_guard_module;

/* classify_handler.c */
ngx_int_t ngx_http_brix_guard_access_handler(ngx_http_request_t *r);
/* audit_handler.c */
ngx_int_t ngx_http_brix_guard_log_handler(ngx_http_request_t *r);
/* guard_http_req.c */
void ngx_http_brix_guard_build_request(ngx_http_request_t *r,
    ngx_http_brix_guard_loc_conf_t *lcf, guard_request_t *out,
    char *pathbuf, size_t pathbuf_sz, char *ipbuf, size_t ipbuf_sz);
void ngx_http_brix_guard_write_audit(ngx_http_request_t *r,
    ngx_http_brix_guard_loc_conf_t *lcf, const guard_request_t *req,
    guard_reason_t reason);

/* Shared sanitizer — defined in src/fs/path/helpers.c, linked from the stream
 * module into the same binary (same forward-decl precedent as
 * src/core/compat/log.c). */
size_t brix_sanitize_log_string(const char *in, char *out, size_t outsz);

#endif /* BRIX_HTTPGUARD_GUARD_HTTP_H */

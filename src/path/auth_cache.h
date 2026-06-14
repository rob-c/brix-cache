/*
 * auth_cache.h — cross-worker cache of the combined auth-gate decision.
 *
 * xrootd_auth_gate() runs three scans per request (authdb rules, VO ACL,
 * token scope).  For hot data paths a pilot repeatedly hits the same
 * {operation, path, identity} tuple and gets the same answer every time.
 * This caches the boolean grant/deny so the repeated scans are skipped.
 *
 * The cache key (built in auth_gate.c) folds in every input to the decision —
 * auth_level, need_write, resolved path, request path, DN, VO list and the
 * raw token scope claim — so two requests only share a cache entry when they
 * would genuinely reach the same verdict.  TTL is short (default 30 s) so a
 * config reload (which zeroes the zone) and any rule change converge quickly.
 */
#ifndef XROOTD_PATH_AUTH_CACHE_H
#define XROOTD_PATH_AUTH_CACHE_H

#include "shm/kv.h"

/* Per-conf settings, filled by xrootd_auth_cache_directive(). */
typedef struct {
    xrootd_kv_t *kv;        /* NULL = disabled */
    ngx_uint_t   ttl_secs;  /* entry lifetime in seconds */
} xrootd_auth_cache_conf_t;

/* Cached decision value (3 bytes). */
typedef struct {
    uint8_t allowed;        /* 1 = grant, 0 = deny */
    uint8_t auth_level;     /* XROOTD_AUTH_* that produced the verdict */
    uint8_t pad;
} xrootd_auth_cache_val_t;

#define XROOTD_AUTH_CACHE_DEFAULT_TTL  30   /* seconds */

/*
 * xrootd_auth_cache_directive() — setter for
 *   xrootd_auth_cache zone=<name> [ttl=<seconds>];
 * Writes the xrootd_auth_cache_conf_t at cmd->offset.  Stream-only (the auth
 * gate runs on the root:// path).
 */
char *xrootd_auth_cache_directive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

#endif /* XROOTD_PATH_AUTH_CACHE_H */

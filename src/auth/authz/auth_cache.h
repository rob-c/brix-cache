/*
 * auth_cache.h — cross-worker cache of the combined auth-gate decision.
 *
 * brix_auth_gate() runs three scans per request (authdb rules, VO ACL,
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
#ifndef BRIX_PATH_AUTH_CACHE_H
#define BRIX_PATH_AUTH_CACHE_H

#include "core/shm/kv.h"

/* Per-conf settings, filled by brix_auth_cache_directive(). */
typedef struct {
    brix_kv_t *kv;        /* NULL = disabled */
    ngx_uint_t   ttl_secs;  /* entry lifetime in seconds */
} brix_auth_cache_conf_t;

/* Cached decision value (3 bytes). */
typedef struct {
    uint8_t allowed;        /* 1 = grant, 0 = deny */
    uint8_t auth_level;     /* BRIX_AUTH_* that produced the verdict */
    uint8_t pad;
} brix_auth_cache_val_t;

#define BRIX_AUTH_CACHE_DEFAULT_TTL  30   /* seconds */

/*
 * brix_auth_cache_directive() — setter for
 *   brix_auth_cache zone=<name> [ttl=<seconds>];
 * Writes the brix_auth_cache_conf_t at cmd->offset.  Stream-only (the auth
 * gate runs on the root:// path).
 */
char *brix_auth_cache_directive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

#endif /* BRIX_PATH_AUTH_CACHE_H */

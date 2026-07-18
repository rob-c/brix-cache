/* ---- File: src/core/negcache/negcache.h — negative-path backoff (ngx side) ----
 *
 * E-4 DoS resilience. The ngx-facing half of the negative-path backoff: it owns
 * the cross-worker SHM slot array + mutex, derives the connection's principal
 * hash (token subject → GSI DN → client IP, in that order), and drives the
 * ngx-free core (negcache_core.h). The kXR handlers call note_miss() at a
 * kXR_NotFound outcome; a non-zero return is the kXR_wait backoff to send in
 * place of the NotFound.
 */
#ifndef BRIX_NEGCACHE_H
#define BRIX_NEGCACHE_H

#include <ngx_config.h>
#include <ngx_core.h>

struct brix_ctx_s;

/*
 * Per-server backoff rule (offsetof target of the brix_negcache_backoff
 * directive). threshold == 0 means the feature is disabled for the block.
 */
typedef struct {
    ngx_uint_t  threshold;   /* misses within the window that trip backoff    */
    ngx_uint_t  window_ms;   /* sliding-window length (ms)                    */
    ngx_uint_t  backoff_s;   /* kXR_wait seconds sent once tripped            */
} brix_negcache_conf_t;

/*
 * Directive setter for `brix_negcache_backoff off | <threshold> <window_s>
 * <wait_s>`. Registered in the stream module command table.
 */
char *brix_negcache_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/*
 * Config-time: register the negative-path backoff SHM zone. Idempotent — call
 * once from postconfiguration when any server enables brix_negcache_backoff.
 */
ngx_int_t brix_negcache_configure(ngx_conf_t *cf);

/*
 * Runtime: record one missing-path lookup for the current connection's
 * principal and return the kXR_wait seconds to impose (0 = allow the NotFound
 * through). `threshold`/`backoff_s` are the server's configured values and
 * `window_ms` is its window in milliseconds. Fail-open: returns 0 whenever the
 * SHM zone is unattached, so the miss falls through to the normal NotFound.
 */
unsigned brix_negcache_note_miss(struct brix_ctx_s *ctx, unsigned threshold,
    unsigned window_ms, unsigned backoff_s);

#endif /* BRIX_NEGCACHE_H */

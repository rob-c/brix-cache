/*
 * test_shared_thread_pool.c — brix_shared_thread_pool() lazy-resolve contract.
 *
 * The helper (src/core/config/shared_conf.h) resolves a merged common loc-conf's
 * async-I/O thread pool by name at first use and caches the handle, so a protocol
 * enabled per-`location` (whose common.thread_pool is left NULL by postconfig,
 * which only wires server-level enabled loc-confs) still offloads instead of
 * silently falling back to a synchronous, event-loop-blocking transfer. This
 * pins the four branches the WebDAV TPC / PUT paths depend on:
 *   1. NULL common            -> NULL (no crash)
 *   2. unresolved + default   -> looks up "default", caches the hit
 *   3. second call            -> returns the cache WITHOUT a second lookup
 *   4. explicit pool name     -> honours common.thread_pool_name
 *   5. no such pool           -> NULL (caller must run synchronously), not cached
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "core/config/shared_conf.h"

#include <stdio.h>
#include <string.h>

static int failures;
#define CHECK(cond, msg) \
    do { if (!(cond)) { \
        fprintf(stderr, "FAIL: %s\n", (msg)); failures++; \
    } } while (0)

/* ---- stubs for the two nginx symbols the inline reaches ---- */

volatile ngx_cycle_t *ngx_cycle;         /* the inline casts away volatile */

/* ngx_thread_pool_t is opaque in the public header, so sentinel pointers stand
 * in for the two resolvable pools — identity is all the helper depends on. */
static int  get_calls;
static char default_slot, named_slot;
#define DEFAULT_POOL ((ngx_thread_pool_t *) &default_slot)
#define NAMED_POOL   ((ngx_thread_pool_t *) &named_slot)

ngx_thread_pool_t *
ngx_thread_pool_get(ngx_cycle_t *cycle, ngx_str_t *name)
{
    (void) cycle;
    get_calls++;
    if (name->len == 7 && ngx_strncmp(name->data, "default", 7) == 0) {
        return DEFAULT_POOL;
    }
    if (name->len == 6 && ngx_strncmp(name->data, "mypool", 6) == 0) {
        return NAMED_POOL;
    }
    return NULL;                          /* unknown pool name */
}

/* --------------------------------------------------------------------------- */

int main(void)
{
    /* 1. NULL common must not dereference. */
    CHECK(brix_shared_thread_pool(NULL) == NULL, "NULL common -> NULL");

    /* 2. unresolved conf, no explicit name -> resolves "default" and caches. */
    {
        ngx_http_brix_shared_conf_t c;
        ngx_memzero(&c, sizeof c);        /* thread_pool NULL, name len 0 */
        get_calls = 0;
        ngx_thread_pool_t *p = brix_shared_thread_pool(&c);
        CHECK(p == DEFAULT_POOL, "default-name lookup resolves the default pool");
        CHECK(get_calls == 1, "exactly one lookup on first resolve");
        CHECK(c.thread_pool == DEFAULT_POOL, "resolved handle cached onto conf");

        /* 3. second call returns the cache without another lookup. */
        ngx_thread_pool_t *p2 = brix_shared_thread_pool(&c);
        CHECK(p2 == DEFAULT_POOL, "cached handle returned");
        CHECK(get_calls == 1, "no second lookup once cached");
    }

    /* 4. explicit thread_pool_name is honoured. */
    {
        ngx_http_brix_shared_conf_t c;
        ngx_memzero(&c, sizeof c);
        ngx_str_set(&c.thread_pool_name, "mypool");
        get_calls = 0;
        ngx_thread_pool_t *p = brix_shared_thread_pool(&c);
        CHECK(p == NAMED_POOL, "named lookup resolves the named pool");
        CHECK(c.thread_pool == NAMED_POOL, "named handle cached");
    }

    /* 5. unknown pool -> NULL (sync fallback) and NOT cached, so a later
     *    directive that adds the pool can still resolve on a subsequent call. */
    {
        ngx_http_brix_shared_conf_t c;
        ngx_memzero(&c, sizeof c);
        ngx_str_set(&c.thread_pool_name, "absent");
        get_calls = 0;
        ngx_thread_pool_t *p = brix_shared_thread_pool(&c);
        CHECK(p == NULL, "unknown pool -> NULL");
        CHECK(c.thread_pool == NULL, "a NULL result is not cached");
        (void) brix_shared_thread_pool(&c);
        CHECK(get_calls == 2, "an unresolved pool is retried, not cached");
    }

    if (failures) { fprintf(stderr, "%d check(s) failed\n", failures); return 1; }
    printf("brix_shared_thread_pool lazy-resolve contract: PASS\n");
    return 0;
}

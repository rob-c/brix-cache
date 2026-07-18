/* ---- File: src/core/negcache/negcache.c — negative-path backoff (ngx side) ----
 *
 * Owns the cross-worker SHM slot array (slab-allocated via brix_shm_table_alloc
 * so it never clobbers the slab-pool header — INVARIANT #10, same contract as
 * every other nginx-xrootd SHM zone; see core/compat/shm_slots.c) and its
 * mutex, derives the connection's principal hash, and drives the ngx-free core
 * (negcache_core.c). See negcache.h for the contract and E-4 rationale.
 */

#include "core/ngx_brix_module.h"        /* brix_ctx_t (identity + login) umbrella */
#include "core/negcache/negcache.h"
#include "core/negcache/negcache_core.h"
#include "core/compat/shm_slots.h"

#include <ngx_shmtx.h>
#include <string.h>

extern ngx_module_t  ngx_stream_brix_module;

/*
 * 8192 direct-mapped slots (~128 KiB) is ample: the table only ever holds
 * principals that are actively *missing* paths, and a throttle tolerates
 * collisions gracefully. Fixed so the zone size is known without a directive.
 */
#define NEGCACHE_SLOTS  8192u


typedef struct {
    ngx_shmtx_sh_t        lock;      /* MUST be first (slab-safe contract)   */
    ngx_uint_t            capacity;
    brix_negcache_slot_t  slots[1];  /* flexible: [capacity]                 */
} negcache_table_t;


static ngx_shm_zone_t  *negcache_zone;
static ngx_shmtx_t      negcache_mtx;


static negcache_table_t *
negcache_table(void)
{
    if (negcache_zone == NULL
        || negcache_zone->data == NULL
        || negcache_zone->data == (void *) 1)
    {
        return NULL;
    }
    return (negcache_table_t *) negcache_zone->data;
}


static ngx_int_t
negcache_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    negcache_table_t *tbl;
    ngx_flag_t        fresh;

    tbl = brix_shm_table_alloc(shm_zone, data,
                                 sizeof(negcache_table_t)
                                     + (size_t) (NEGCACHE_SLOTS - 1)
                                         * sizeof(brix_negcache_slot_t),
                                 &negcache_mtx, &fresh);
    if (tbl == NULL) {
        return NGX_ERROR;
    }
    if (fresh) {
        tbl->capacity = NEGCACHE_SLOTS;
        /* helper already zeroed the table (key == 0 → all slots empty) */
    }
    return NGX_OK;
}


char *
brix_negcache_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    brix_negcache_conf_t *nc = (brix_negcache_conf_t *)
                                   ((char *) conf + cmd->offset);
    ngx_str_t            *value = cf->args->elts;
    ngx_int_t             thr, win, back;

    /* "off": explicit disable (threshold 0). */
    if (cf->args->nelts == 2
        && value[1].len == 3 && ngx_strncmp(value[1].data, "off", 3) == 0)
    {
        nc->threshold = 0;
        nc->window_ms = 0;
        nc->backoff_s = 0;
        return NGX_CONF_OK;
    }

    if (cf->args->nelts != 4) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_negcache_backoff: expected \"off\" or"
            " \"<threshold> <window_seconds> <wait_seconds>\"");
        return NGX_CONF_ERROR;
    }

    thr  = ngx_atoi(value[1].data, value[1].len);
    win  = ngx_atoi(value[2].data, value[2].len);
    back = ngx_atoi(value[3].data, value[3].len);

    if (thr == NGX_ERROR || thr < 1
        || win == NGX_ERROR || win < 1 || win > 86400
        || back == NGX_ERROR || back < 1 || back > 3600)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_negcache_backoff: threshold >= 1, window_seconds 1..86400"
            " and wait_seconds 1..3600 required");
        return NGX_CONF_ERROR;
    }

    nc->threshold = (ngx_uint_t) thr;
    nc->window_ms = (ngx_uint_t) win * 1000;
    nc->backoff_s = (ngx_uint_t) back;
    return NGX_CONF_OK;
}


ngx_int_t
brix_negcache_configure(ngx_conf_t *cf)
{
    ngx_str_t  zone_name = ngx_string("brix_negcache");
    size_t     zone_size;

    if (negcache_zone != NULL) {
        return NGX_OK;               /* idempotent */
    }

    zone_size = brix_shm_zone_size(sizeof(negcache_table_t)
                                     + (size_t) (NEGCACHE_SLOTS - 1)
                                         * sizeof(brix_negcache_slot_t));
    negcache_zone = ngx_shared_memory_add(cf, &zone_name, zone_size,
                                          &ngx_stream_brix_module);
    if (negcache_zone == NULL) {
        return NGX_ERROR;
    }
    negcache_zone->init = negcache_init_zone;
    negcache_zone->data = (void *) 1;
    return NGX_OK;
}


/*
 * FNV-1a32 over the principal string, seeded by a dimension tag so a token
 * subject and a client IP that happen to share bytes never collide. The tag
 * also keeps the three principal classes in disjoint hash sub-spaces.
 */
static uint32_t
negcache_fnv(char tag, const u_char *s, size_t n)
{
    uint32_t h = 2166136261u;
    size_t   i;

    h ^= (uint32_t) (u_char) tag;
    h *= 16777619u;
    for (i = 0; i < n; i++) {
        h ^= (uint32_t) s[i];
        h *= 16777619u;
    }
    return h;
}


unsigned
brix_negcache_note_miss(brix_ctx_t *ctx, unsigned threshold,
    unsigned window_ms, unsigned backoff_s)
{
    negcache_table_t       *tbl = negcache_table();
    brix_negcache_params_t  p;
    uint32_t                h;
    unsigned                wait;

    if (tbl == NULL || ctx == NULL) {
        return 0;                    /* zone unattached → fail open */
    }

    /*
     * Principal, most-specific first: an authenticated token subject, else a
     * GSI subject DN, else the client IP so an unauthenticated bulk harvester
     * is always bucketed (mirrors the rate-limiter's invariant-5 IP fallback).
     */
    if (ctx->identity != NULL && ctx->identity->subject.len > 0) {
        h = negcache_fnv('s', ctx->identity->subject.data,
                         ctx->identity->subject.len);
    } else if (ctx->login.dn[0] != '\0') {
        h = negcache_fnv('d', (u_char *) ctx->login.dn,
                         ngx_strlen(ctx->login.dn));
    } else {
        h = negcache_fnv('p', (u_char *) ctx->login.peer_ip,
                         ngx_strlen(ctx->login.peer_ip));
    }

    p.threshold = threshold;
    p.window_ms = window_ms;
    p.backoff_s = backoff_s;

    ngx_shmtx_lock(&negcache_mtx);
    wait = brix_negcache_core_note(tbl->slots, (unsigned) tbl->capacity, h,
                                   (uint64_t) ngx_current_msec, &p);
    ngx_shmtx_unlock(&negcache_mtx);
    return wait;
}

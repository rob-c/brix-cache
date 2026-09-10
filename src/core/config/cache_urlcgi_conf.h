/*
 * cache_urlcgi_conf.h — brix_cache_urlcgi (2.0 F5, upstream pfc.urlcgi).
 *
 * WHAT: The per-server clamp pair for each of the two per-open client cache
 *   hints a root:// open may carry as CGI — pfc.blocksize=<bytes> (the slice
 *   granule a NEW partial object is created with) and pfc.prefetch=<blocks>
 *   (that handle's background-prefetch runway) — plus its init/merge/adopt
 *   helpers, so the http and stream conf planes and the cache policy share
 *   one shape.
 *
 * WHY: Upstream's `pfc.urlcgi [blocksize {ignore|min max}] [prefetch
 *   {ignore|min max}]` lets a client tune both per open while the operator
 *   bounds what may be asked for; the default is both ignored. Same grammar,
 *   same default. Encoding: *_max == 0 means "the hint is ignored" (a real
 *   clamp always has max >= 1), so the merge/adopt sentinels
 *   (NGX_CONF_UNSET_SIZE / NGX_CONF_UNSET_UINT = "not set in this block")
 *   never collide with a configured value.
 */
#ifndef BRIX_CACHE_URLCGI_CONF_H
#define BRIX_CACHE_URLCGI_CONF_H

/* Lightweight nginx-core types only (included by shared_conf.h and tier.h). */
#include <ngx_config.h>
#include <ngx_core.h>

/* The slice-engine granule: brix_cache_slice_size and every urlcgi blocksize
 * bound must be a positive multiple of it, and a clamped pfc.blocksize hint
 * is rounded down to it. */
#define BRIX_CACHE_SLICE_GRANULE  (1024 * 1024)

typedef struct {
    size_t      bs_min;   /* blocksize clamp floor, bytes (1m multiple)        */
    size_t      bs_max;   /* ...ceiling; 0 = pfc.blocksize ignored;
                           * NGX_CONF_UNSET_SIZE = not set in this block       */
    ngx_uint_t  pf_min;   /* prefetch clamp floor, blocks (0 = client may
                           * switch speculation off for its handle)            */
    ngx_uint_t  pf_max;   /* ...ceiling; 0 = pfc.prefetch ignored;
                           * NGX_CONF_UNSET_UINT = not set in this block       */
} brix_cache_urlcgi_conf_t;

static ngx_inline void
brix_cache_urlcgi_conf_init(brix_cache_urlcgi_conf_t *u)
{
    u->bs_min = 0;
    u->bs_max = NGX_CONF_UNSET_SIZE;
    u->pf_min = 0;
    u->pf_max = NGX_CONF_UNSET_UINT;
}

/* Merge: each (min, max) pair inherits from the enclosing block as a UNIT
 * (the max sentinel marks "not set here"); the outermost default is ignored. */
static ngx_inline void
brix_cache_urlcgi_conf_merge(brix_cache_urlcgi_conf_t *conf,
    const brix_cache_urlcgi_conf_t *prev)
{
    if (conf->bs_max == NGX_CONF_UNSET_SIZE) {
        conf->bs_min = prev->bs_min;
        conf->bs_max = (prev->bs_max == NGX_CONF_UNSET_SIZE) ? 0 : prev->bs_max;
    }
    if (conf->pf_max == NGX_CONF_UNSET_UINT) {
        conf->pf_min = prev->pf_min;
        conf->pf_max = (prev->pf_max == NGX_CONF_UNSET_UINT) ? 0 : prev->pf_max;
    }
}

/* Adopt (cross-plane unification, brix_shared_adopt_unified): a pair the
 * destination never set takes the source's, again as a unit. */
static ngx_inline void
brix_cache_urlcgi_conf_adopt(brix_cache_urlcgi_conf_t *dst,
    const brix_cache_urlcgi_conf_t *src)
{
    if (dst->bs_max == NGX_CONF_UNSET_SIZE && src->bs_max != NGX_CONF_UNSET_SIZE) {
        dst->bs_min = src->bs_min;
        dst->bs_max = src->bs_max;
    }
    if (dst->pf_max == NGX_CONF_UNSET_UINT && src->pf_max != NGX_CONF_UNSET_UINT) {
        dst->pf_min = src->pf_min;
        dst->pf_max = src->pf_max;
    }
}

/* The policy value: a conf that reaches tier registration unmerged (sentinel
 * still present) behaves like the merged default — ignored. */
static ngx_inline brix_cache_urlcgi_conf_t
brix_cache_urlcgi_conf_effective(const brix_cache_urlcgi_conf_t *c)
{
    brix_cache_urlcgi_conf_t e = *c;

    if (e.bs_max == NGX_CONF_UNSET_SIZE) {
        e.bs_max = 0;
    }
    if (e.pf_max == NGX_CONF_UNSET_UINT) {
        e.pf_max = 0;
    }
    return e;
}

#endif /* BRIX_CACHE_URLCGI_CONF_H */

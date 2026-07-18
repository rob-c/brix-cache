/*
 * tier_directives.h — X-macro for the phase-64 composable tier grammar
 * directive table (<pfx>{cache_store,cache_cold_store,stage,stage_store,
 * stage_flush,cache_max_object,cache_evict_at,cache_evict_to,
 * cache_index_cache,cache_meta,cache_slice_size}).
 *
 * WHAT: BRIX_TIER_DIRECTIVES(pfx, conf_t, ctx, conf_off) expands to the eleven
 *       ngx_command_t initializers every protocol module declares for its
 *       tier grammar, all writing into the embedded
 *       ngx_http_brix_shared_conf_t `common` preamble.
 * WHY:  root:// (brix_*), WebDAV (brix_webdav_*) and S3 (brix_s3_*) declared
 *       byte-identical tables differing only in prefix, conf struct and
 *       context flags — a cross-protocol parity bug magnet and a triple audit
 *       surface. One macro guarantees the grammars cannot drift.
 * HOW:  The including module writes e.g.
 *           BRIX_TIER_DIRECTIVES("brix_s3_", ngx_http_s3_loc_conf_t,
 *                                NGX_HTTP_LOC_CONF, NGX_HTTP_LOC_CONF_OFFSET),
 *       inside its commands[] array. The shared sync/async and meta-mode enum
 *       tables are static per including TU (replacing the per-module twins).
 *       cvmfs deliberately exposes only cache_store and is NOT converted.
 */

#ifndef NGX_BRIX_TIER_DIRECTIVES_H
#define NGX_BRIX_TIER_DIRECTIVES_H

#include "core/config/shared_conf.h"   /* brix_conf_set_store_slot */

/* brix_*_stage_flush sync|async (0 = sync, 1 = async). */
static ngx_conf_enum_t  brix_tier_stage_flush_enum[] = {
    { ngx_string("sync"),  0 },
    { ngx_string("async"), 1 },
    { ngx_null_string,     0 }
};

/* brix_*_cache_meta map (BRIX_CMETA_* in fs/cache/cstore.h). */
static ngx_conf_enum_t  brix_tier_cache_meta_enum[] = {
    { ngx_string("auto"),    0 },
    { ngx_string("local"),   1 },
    { ngx_string("xattr"),   2 },
    { ngx_string("sidecar"), 3 },
    { ngx_null_string,       0 }
};

#define BRIX_TIER_DIRECTIVES(pfx, conf_t, ctx, conf_off)                      \
    { ngx_string(pfx "cache_store"),   /* <store-url> [credential=][block_size=] */ \
      (ctx) | NGX_CONF_TAKE1234,                                              \
      brix_conf_set_store_slot,                                               \
      conf_off,                                                               \
      offsetof(conf_t, common.cache_store),                                   \
      (void *) offsetof(conf_t, common.cache_store_args) },                   \
    { ngx_string(pfx "cache_cold_store"), /* <store-url> [credential=] — phase-85 \
                                           * F7 cold tier under cache_store */ \
      (ctx) | NGX_CONF_TAKE1234,                                              \
      brix_conf_set_store_slot,                                               \
      conf_off,                                                               \
      offsetof(conf_t, common.cache_cold_store),                              \
      (void *) offsetof(conf_t, common.cache_cold_store_args) },              \
    { ngx_string(pfx "stage"),         /* on|off: enable the write-stage tier */ \
      (ctx) | NGX_CONF_FLAG,                                                  \
      ngx_conf_set_flag_slot,                                                 \
      conf_off,                                                               \
      offsetof(conf_t, common.stage_enable),                                  \
      NULL },                                                                 \
    { ngx_string(pfx "stage_store"),   /* <store-url> [credential=][block_size=] */ \
      (ctx) | NGX_CONF_TAKE1234,                                              \
      brix_conf_set_store_slot,                                               \
      conf_off,                                                               \
      offsetof(conf_t, common.stage_store),                                   \
      (void *) offsetof(conf_t, common.stage_store_args) },                   \
    { ngx_string(pfx "stage_flush"),   /* sync|async write-back to the backend */ \
      (ctx) | NGX_CONF_TAKE1,                                                 \
      ngx_conf_set_enum_slot,                                                 \
      conf_off,                                                               \
      offsetof(conf_t, common.stage_flush_async),                             \
      brix_tier_stage_flush_enum },                                           \
    { ngx_string(pfx "cache_max_object"), /* <size>: skip caching larger objects */ \
      (ctx) | NGX_CONF_TAKE1,                                                 \
      ngx_conf_set_off_slot,                                                  \
      conf_off,                                                               \
      offsetof(conf_t, common.cache_max_object),                              \
      NULL },                                                                 \
    { ngx_string(pfx "cache_evict_at"),   /* <pct> full -> begin evicting */  \
      (ctx) | NGX_CONF_TAKE1,                                                 \
      ngx_conf_set_num_slot,                                                  \
      conf_off,                                                               \
      offsetof(conf_t, common.cache_evict_at),                                \
      NULL },                                                                 \
    { ngx_string(pfx "cache_evict_to"),   /* <pct>: eviction target */        \
      (ctx) | NGX_CONF_TAKE1,                                                 \
      ngx_conf_set_num_slot,                                                  \
      conf_off,                                                               \
      offsetof(conf_t, common.cache_evict_to),                                \
      NULL },                                                                 \
    { ngx_string(pfx "cache_index_cache"), /* <n>: per-worker cinfo L1 entries */ \
      (ctx) | NGX_CONF_TAKE1,                                                 \
      ngx_conf_set_size_slot,                                                 \
      conf_off,                                                               \
      offsetof(conf_t, common.cache_index_cache),                             \
      NULL },                                                                 \
    { ngx_string(pfx "cache_meta"),       /* auto|local|xattr|sidecar */      \
      (ctx) | NGX_CONF_TAKE1,                                                 \
      ngx_conf_set_enum_slot,                                                 \
      conf_off,                                                               \
      offsetof(conf_t, common.cache_meta_mode),                               \
      brix_tier_cache_meta_enum },                                            \
    { ngx_string(pfx "cache_slice_size"), /* <size> (0 = whole-file) */       \
      (ctx) | NGX_CONF_TAKE1,                                                 \
      ngx_conf_set_size_slot,                                                 \
      conf_off,                                                               \
      offsetof(conf_t, common.cache_slice_size),                              \
      NULL }

#endif /* NGX_BRIX_TIER_DIRECTIVES_H */

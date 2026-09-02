/*
 * tier_directives.h — X-macro for the phase-64 composable tier grammar
 * directive table (<pfx>{cache_store,cache_cold_store,stage,stage_store,
 * stage_flush,cache_max_object,cache_evict_at,cache_evict_to,
 * cache_index_cache,cache_meta,cache_slice_size,cache_global_cas,
 * cache_passthrough,cache_passthrough_max,cache_prefetch,
 * cache_prefetch_window,cache_only_if_cached,vfs_spill_path,vfs_spill_max,
 * durable_publish,lock_enforcement}).
 *
 * WHAT: BRIX_TIER_DIRECTIVES(pfx, conf_t, ctx, conf_off) expands to the 21
 *       ngx_command_t initializers for the tier grammar, all writing into the
 *       embedded ngx_http_brix_shared_conf_t `common` preamble.  The
 *       authoritative name list is the `ngx_string(pfx "...")` tokens in the
 *       macro body below — tools/ci/check_directive_registry.py parses THIS
 *       header for it, so adding an entry here is picked up with no hand-edit.
 * WHY:  root://, WebDAV and S3 once declared byte-identical tables differing
 *       only in prefix, conf struct and context flags — a cross-protocol parity
 *       bug magnet and a triple audit surface. One macro guarantees the grammars
 *       cannot drift.
 * HOW:  Post-unification (2026-07 grammar + phase-101) the macro is instantiated
 *       ONCE per plane with the BARE "brix_" prefix — HTTP via the shared common
 *       module (http_common.c) and stream via directives_tier.h — so every HTTP
 *       protocol inherits the one registration through the common preamble rather
 *       than re-instantiating with its own prefix.  The shared sync/async and
 *       meta-mode enum tables are static per including TU.  cvmfs deliberately
 *       exposes only cache_store and is NOT converted.
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

/* brix_lock_enforcement (phase-107 C7): does a live foreign WebDAV lock refuse
 * mutations on every plane (strict — the default), warn-and-allow outside
 * WebDAV (advisory), or bind WebDAV-only as before C7 (off). Values are
 * brix_vfs_lock_enforcement_t (fs/vfs/vfs_policy.h); 0 = strict fails toward
 * enforcement. */
static ngx_conf_enum_t  brix_lock_enforcement_enum[] = {
    { ngx_string("strict"),   0 },
    { ngx_string("advisory"), 1 },
    { ngx_string("off"),      2 },
    { ngx_null_string,        0 }
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
      NULL },                                                                 \
    { ngx_string(pfx "cache_global_cas"), /* on|off: phase-87 G13 cross-repo  \
                                           * hardlink dedup of verified CAS */ \
      (ctx) | NGX_CONF_FLAG,                                                  \
      ngx_conf_set_flag_slot,                                                 \
      conf_off,                                                               \
      offsetof(conf_t, common.cache_global_cas),                              \
      NULL },                                                                 \
    { ngx_string(pfx "cache_passthrough"), /* on|off: phase-92 store-then-    \
                                            * evict of admission-declined     \
                                            * remote objects */               \
      (ctx) | NGX_CONF_FLAG,                                                  \
      ngx_conf_set_flag_slot,                                                 \
      conf_off,                                                               \
      offsetof(conf_t, common.cache_passthrough),                             \
      NULL },                                                                 \
    { ngx_string(pfx "cache_passthrough_max"), /* <size>: spool cap for a     \
                                                * passthrough fill (0 = the   \
                                                * cache_max_object cap) */     \
      (ctx) | NGX_CONF_TAKE1,                                                 \
      ngx_conf_set_off_slot,                                                  \
      conf_off,                                                               \
      offsetof(conf_t, common.cache_passthrough_max),                         \
      NULL },                                                                 \
    { ngx_string(pfx "cache_prefetch"),   /* <n>: max in-flight background    \
                                           * block-prefetch jobs per worker   \
                                           * (0 = off) */                     \
      (ctx) | NGX_CONF_TAKE1,                                                 \
      ngx_conf_set_num_slot,                                                  \
      conf_off,                                                               \
      offsetof(conf_t, common.cache_prefetch),                                \
      NULL },                                                                 \
    { ngx_string(pfx "cache_prefetch_window"), /* <size>: max bytes one       \
                                                * WILLNEED hint may queue for \
                                                * background fill */          \
      (ctx) | NGX_CONF_TAKE1,                                                 \
      ngx_conf_set_size_slot,                                                 \
      conf_off,                                                               \
      offsetof(conf_t, common.cache_prefetch_window),                         \
      NULL },                                                                 \
    { ngx_string(pfx "cache_uvkeep"),   /* <time>: age out a never-verified   \
                                         * cache entry past this age so the    \
                                         * next open revalidates (0 = off) */  \
      (ctx) | NGX_CONF_TAKE1,                                                  \
      ngx_conf_set_sec_slot,                                                   \
      conf_off,                                                                \
      offsetof(conf_t, common.cache_uvkeep),                                  \
      NULL },                                                                 \
    { ngx_string(pfx "cache_only_if_cached"), /* on|off: a read MISS returns  \
                                               * ENOENT instead of filling    \
                                               * from the origin */           \
      (ctx) | NGX_CONF_FLAG,                                                  \
      ngx_conf_set_flag_slot,                                                 \
      conf_off,                                                               \
      offsetof(conf_t, common.cache_only_if_cached),                          \
      NULL },                                                                 \
    { ngx_string(pfx "vfs_spill_path"), /* <abs path>: writer reorder scratch \
                                         * root (phase-107 C1) — validated    \
                                         * absolute + OUTSIDE every export    \
                                         * root at nginx -t */                \
      (ctx) | NGX_CONF_TAKE1,                                                 \
      ngx_conf_set_str_slot,                                                  \
      conf_off,                                                               \
      offsetof(conf_t, common.vfs_spill_path),                                \
      NULL },                                                                 \
    { ngx_string(pfx "vfs_spill_max"),  /* <size>: cap ONE spill's span       \
                                         * (0 = unlimited; else >= 1m) */     \
      (ctx) | NGX_CONF_TAKE1,                                                 \
      ngx_conf_set_size_slot,                                                 \
      conf_off,                                                               \
      offsetof(conf_t, common.vfs_spill_max),                                 \
      NULL },                                                                 \
    { ngx_string(pfx "durable_publish"), /* on|off: fsync the published       \
                                          * name's PARENT DIRECTORY at every  \
                                          * publish (phase-107 C3); off = a   \
                                          * crash may lose the name */        \
      (ctx) | NGX_CONF_FLAG,                                                  \
      ngx_conf_set_flag_slot,                                                 \
      conf_off,                                                               \
      offsetof(conf_t, common.durable_publish),                               \
      NULL },                                                                 \
    { ngx_string(pfx "lock_enforcement"), /* strict|advisory|off: does a live \
                                           * foreign WebDAV lock refuse       \
                                           * mutations on every plane         \
                                           * (phase-107 C7) */                \
      (ctx) | NGX_CONF_TAKE1,                                                 \
      ngx_conf_set_enum_slot,                                                 \
      conf_off,                                                               \
      offsetof(conf_t, common.lock_enforcement),                              \
      brix_lock_enforcement_enum }

/*
 * BRIX_BACKEND_ASYNC_DIRECTIVES(pfx, conf_t, ctx, conf_off) — the three-directive
 * grammar for the durable async backend-op queue, writing into the shared `common`
 * preamble so the http-plane protocols (S3, WebDAV) declare it byte-identically.
 * The root:// stream plane declares the same triple against its own srv-conf.
 */
#define BRIX_BACKEND_ASYNC_DIRECTIVES(pfx, conf_t, ctx, conf_off)             \
    { ngx_string(pfx "backend_async"),   /* on|off: queue namespace mutations */ \
      (ctx) | NGX_CONF_FLAG,                                                  \
      ngx_conf_set_flag_slot,                                                 \
      conf_off,                                                               \
      offsetof(conf_t, common.backend_async),                                 \
      NULL },                                                                 \
    { ngx_string(pfx "backend_async_batch"), /* N: flush once this many queued */ \
      (ctx) | NGX_CONF_TAKE1,                                                 \
      ngx_conf_set_num_slot,                                                  \
      conf_off,                                                               \
      offsetof(conf_t, common.backend_async_batch),                           \
      NULL },                                                                 \
    { ngx_string(pfx "backend_async_wait"),  /* time backstop (e.g. 200ms) */ \
      (ctx) | NGX_CONF_TAKE1,                                                 \
      ngx_conf_set_msec_slot,                                                 \
      conf_off,                                                               \
      offsetof(conf_t, common.backend_async_wait),                            \
      NULL }

#endif /* NGX_BRIX_TIER_DIRECTIVES_H */

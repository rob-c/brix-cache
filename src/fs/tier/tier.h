#ifndef XROOTD_FS_TIER_H
#define XROOTD_FS_TIER_H

/*
 * tier.h — the composable storage-tier model (phase-64 §2).
 *
 * WHAT: The POD types that describe a node's storage stack as up to three
 *       orthogonal TIERS — backend, cache_store, stage_store — each a complete
 *       self-describing filesystem addressed by { driver, location, credential }.
 *       Declares the parsed per-tier config (xrootd_tier_cfg_t), the per-export
 *       stack (xrootd_tier_stack_t) that the registry memoises, the cache/stage
 *       policy PODs, the capability-gap report, and the four public entry points
 *       (parse_store / status / build / build_stack).
 *
 * WHY:  Before phase-64 the registry carried flat backend[16] / origin_x / staging
 *       fields and the cache was a separate, scheme-dispatched subsystem. The tier
 *       model unifies them: every tier is one xrootd_sd_instance_t, the registry
 *       composes them top-down (cache → stage → backend), and the VFS consumes the
 *       composed top BLIND — no handler, VFS op, or cache module branches on a
 *       driver/protocol/tier (P3, G4/G5). The cache and stage tiers are OPTIONAL,
 *       except a nearline (tape) backend REQUIRES a cache tier as its recall
 *       target (P4, §9.4).
 *
 * HOW:  tier_config.c parses a "<scheme>:<location> [credential=][block_size=]"
 *       store URL into an xrootd_tier_cfg_t and reports each tier's readiness
 *       against a per-role capability contract (§2.2) — a missing slot is a
 *       tracked "needs development" task, never a blocker (P1). tier_build.c is
 *       the single driver-name dispatch that turns one cfg into a bound SD
 *       instance, and composes the three into the stack's top via the sd_cache /
 *       sd_stage decorators. See docs/refactor/phase-64-fully-tiered-composable-
 *       storage.md (§2, §4, §5, §8, Appendix I/L).
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <regex.h>

#include "fs/backend/sd.h"                     /* xrootd_sd_instance_t */
#include "fs/cache/verify.h"                /* xrootd_cache_verify_mode_e */
#include "fs/cache/writethrough_decision.h" /* xrootd_wt_decision_fn */
#include "core/config/credential_block.h"     /* xrootd_credential_t */
#include "core/types/config.h"                /* XROOTD_WT_MODE_SYNC/_ASYNC */

/* ---- tier role ------------------------------------------------------------ */

typedef enum {
    XROOTD_TIER_BACKEND = 0,   /* the authoritative source filesystem            */
    XROOTD_TIER_CACHE   = 1,   /* the read-cache store (fronts the backend)      */
    XROOTD_TIER_STAGE   = 2    /* the write-stage store (buffers, then flushes)  */
} xrootd_tier_role_t;

/* The cinfo/meta encoding mode (policy.meta_mode below) is one of the
 * XROOTD_CMETA_* constants defined in cache/cstore.h (their semantic owner). */

/* ---- one parsed tier ------------------------------------------------------
 * Filled by xrootd_tier_parse_store from a store-URL directive. `driver` is the
 * resolved SD driver name (root/roots→"xroot", http/https→"http", else literal).
 * For a local tier (posix/pblock) `path` is the confined export directory and
 * host is ""; for a remote tier `host`:`port` is the authority and `path` is the
 * URL/bucket/pool remainder. */
typedef struct {
    xrootd_tier_role_t          role;
    char                        driver[16];   /* posix|pblock|xroot|http|s3|rados|tape */
    char                        host[256];    /* remote authority; "" when local   */
    int                         port;
    int                         tls;          /* roots:// / https → 1               */
    char                        path[1024];   /* dir | /sub | /bucket | /pool[/ns]  */
    const xrootd_credential_t  *credential;   /* §14; NULL = anonymous              */
    size_t                      block_size;   /* pblock object block size (0 = def) */
    unsigned                    nearline:1;   /* tape:// — async-recall reads (§9)  */
    unsigned                    configured:1; /* a store URL was parsed for this tier */
} xrootd_tier_cfg_t;

/* ---- cache policy (§2.3) — fresh fields, no legacy conf borrowed (P2) ----- */
typedef struct {
    off_t                       max_file_size;   /* xrootd_cache_max_object        */
    ngx_uint_t                  evict_at;        /* percent-full that triggers evict */
    ngx_uint_t                  evict_to;        /* percent-full target after evict  */
    xrootd_cache_verify_mode_e  verify;          /* off | best-effort | require      */
    regex_t                    *include_regex;   /* xrootd_cache_include             */
    ngx_array_t                *deny_prefixes;   /* xrootd_cache_deny  (ngx_str_t[]) */
    ngx_array_t                *allow_prefixes;  /* xrootd_cache_allow (ngx_str_t[]) */
    time_t                      dirty_max_age;   /* stale-dirty reaper horizon       */
    size_t                      slice_size;      /* 0 = whole-file caching           */
    int                         meta_mode;       /* XROOTD_CMETA_*                   */
    int                         batch_cinfo;     /* -1 auto | 0 per-op | 1 on-commit */
    size_t                      l1_entries;      /* per-worker cinfo LRU size        */
    unsigned                    enabled:1;       /* xrootd_cache on                  */
} xrootd_cache_policy_t;

/* ---- stage policy (§2.4) — the kept write-through decision, re-homed ------- */
typedef struct {
    int                         flush_mode;      /* XROOTD_WT_MODE_SYNC | _ASYNC     */
    xrootd_wt_decision_fn       fn;              /* per-path/size flush decision     */
    void                       *decision_conf;   /* opaque cfg for fn                */
    unsigned                    enabled:1;       /* xrootd_stage on                  */
} xrootd_stage_policy_t;

/* ---- the per-export stack -------------------------------------------------
 * The three parsed tier cfgs + their policies, plus the lazily-composed top of
 * stack (cache(stage(backend))) memoised per worker by tier_build_stack. */
typedef struct {
    xrootd_tier_cfg_t      backend;
    xrootd_tier_cfg_t      cache_store;
    xrootd_tier_cfg_t      stage_store;
    xrootd_cache_policy_t  cache;
    xrootd_stage_policy_t  stage;
    xrootd_sd_instance_t  *composed;            /* top-of-stack, lazy per worker     */
} xrootd_tier_stack_t;

/* ---- capability-gap report + readiness (§2.2, Appendix L) ------------------ */

/* The first missing slot/cap that keeps a tier from serving its role, plus the
 * sub-project that will add it — the "needs development" payload (P1). */
typedef struct {
    char slot[32];     /* the first NULL vtable slot, or "" */
    char cap[24];      /* the first missing capability, or "" */
    char sp_item[16];  /* the sub-project that closes the gap, e.g. "SP3" */
} xrootd_tier_gap_t;

typedef enum {
    XROOTD_TIER_READY     = 0,   /* the driver has every slot+cap for the role     */
    XROOTD_TIER_NEEDS_DEV = 1    /* a slot/cap is missing — tracked dev task (P1)  */
} xrootd_tier_status_t;

/* ---- public API ----------------------------------------------------------- */

/* Parse a "<scheme>:<location> [credential=<n>] [block_size=<n>]" store URL into
 * *out (§4.2, Appendix L). `url` is the store-url token; `args` (may be NULL)
 * carries the trailing credential=/block_size= params. On a malformed URL,
 * unknown scheme, or unknown/absent credential this writes a message into
 * err[errcap] and returns NGX_ERROR (operator error, Appendix F). On success it
 * sets out->configured and returns NGX_OK. Pure parse — no instance is built. */
ngx_int_t xrootd_tier_parse_store(ngx_conf_t *cf, ngx_str_t *url,
    ngx_array_t *args, xrootd_tier_role_t role, xrootd_tier_cfg_t *out,
    char *err, size_t errcap);

/* Report whether the driver bound for tier `t` satisfies its role's capability
 * contract (§2.2). `probe` is a built instance of the tier's driver. Returns
 * XROOTD_TIER_READY, or XROOTD_TIER_NEEDS_DEV with *gap_out filled (the first
 * missing slot/cap + the closing sub-project). A NEEDS_DEV tier is held inactive
 * with a [warn] — never a crash (P1). */
xrootd_tier_status_t xrootd_tier_status(const xrootd_tier_cfg_t *t,
    xrootd_sd_instance_t *probe, xrootd_tier_gap_t *gap_out);

/* Build one bound SD instance for tier `t` — the SINGLE driver-name dispatch
 * (§5, Appendix C). Returns a malloc/pool-owned instance, or NULL (errno set) for
 * a driver that is not yet implemented as a primary ("needs development") or an
 * init failure. */
xrootd_sd_instance_t *xrootd_tier_build(const xrootd_tier_cfg_t *t,
    ngx_log_t *log);

/* Compose the stack's top of stack (cache → stage → backend) from `s`, memoising
 * it in s->composed (per worker). Enforces tape-requires-cache (P4/G8): a
 * nearline backend with no cache_store returns NULL. Returns the composed top
 * (the backend itself when neither cache nor stage is configured), or NULL on a
 * build failure. */
xrootd_sd_instance_t *xrootd_tier_build_stack(xrootd_tier_stack_t *s,
    ngx_log_t *log);

/* ---- registry glue (phase-64 config wiring) -------------------------------
 * These register a parsed cache/stage tier on the per-export backend registry
 * (vfs_backend_registry.c) at config time, so xrootd_vfs_backend_resolve composes
 * an sd_cache / sd_stage decorator over the backend per worker. *cfg and *policy
 * are copied; a no-op for an empty/unknown root. Declared here (with the tier
 * types) to keep the widely-included registry header free of tier.h. */
void xrootd_vfs_backend_config_cache_store(const char *root_canon,
    const xrootd_tier_cfg_t *cfg, const xrootd_cache_policy_t *policy);

void xrootd_vfs_backend_config_stage_store(const char *root_canon,
    const xrootd_tier_cfg_t *cfg, const xrootd_stage_policy_t *policy);

#endif /* XROOTD_FS_TIER_H */

/*
 * reqid_map.h — CMS↔engine request-id sidecar map (Phase-89 W2 / ADR-2b).
 *
 * WHAT: A small SHM slot table keyed by the MANAGER's prepadd reqid (the id a
 *       cmsd manager echoes in kYR_prepdel), holding the ENGINE reqid the
 *       stage-request registry minted for that admission plus the two padArgs
 *       fields the registry's live view has no columns for: notify and prty.
 *
 * WHY:  The stage-request registry is the durable truth for a request's
 *       lifecycle, but it keys by its own "<seq>.<pid>@<host>" reqid — a
 *       forwarded kYR_prepdel only carries the manager's id.  ADR-2b (phase-89
 *       App C.0.1) keeps the registry view untouched and carries the mapping
 *       (and notify/prty) in this sidecar instead of widening the durable
 *       record.  SHM, not per-worker: the prepdel may arrive on a different
 *       worker's manager connection than the prepadd did after a reconnect.
 *
 * HOW:  fnv1a open-addressing over BRIX_CMS_REQID_MAP_SLOTS (power of two),
 *       last-writer-wins per cms reqid, entries lazily expired after
 *       BRIX_CMS_REQID_MAP_TTL_MS (the engine reap horizon — a mapping older
 *       than that points at a request the registry reaper has already
 *       retired).  Table created via the brix_shm_table_* helpers
 *       (INVARIANT #10, never a bare ngx_shmtx_create); zone registered by
 *       brix_cms_reqid_map_configure() appended LAST in
 *       postconf_shared_registries (zone order is the reload contract).
 */
#ifndef BRIX_CMS_REQID_MAP_H
#define BRIX_CMS_REQID_MAP_H

#include <ngx_config.h>
#include <ngx_core.h>

#define BRIX_CMS_REQID_MAP_SLOTS    512     /* power of two */
#define BRIX_CMS_REQID_KEY_MAX      64      /* manager reqid text */
#define BRIX_CMS_REQID_ENGINE_MAX   64      /* = BRIX_STAGE_REQID_LEN */
#define BRIX_CMS_REQID_NOTIFY_MAX   256     /* padArgs notify target */
#define BRIX_CMS_REQID_PRTY_MAX     16      /* padArgs priority text */
#define BRIX_CMS_REQID_MAP_TTL_MS   (24 * 60 * 60 * 1000)

typedef struct {
    uint32_t     key_hash;
    char         cms_reqid[BRIX_CMS_REQID_KEY_MAX];
    char         engine_reqid[BRIX_CMS_REQID_ENGINE_MAX];
    char         notify[BRIX_CMS_REQID_NOTIFY_MAX];
    char         prty[BRIX_CMS_REQID_PRTY_MAX];
    ngx_msec_t   expires;
    ngx_uint_t   in_use;
} brix_cms_reqid_entry_t;

typedef struct {
    ngx_shmtx_sh_t           lock;    /* must be first (shm_slots contract) */
    brix_cms_reqid_entry_t   slots[BRIX_CMS_REQID_MAP_SLOTS];
} brix_cms_reqid_table_t;

/* Register the SHM zone (cheap, always created — like the pending table). */
ngx_int_t brix_cms_reqid_map_configure(ngx_conf_t *cf);

/* Record cms_reqid → engine_reqid (+ optional notify/prty; NULL = empty).
 * Last-writer-wins for a repeated cms_reqid; full-table fallback overwrites
 * the home slot (bounded eviction). */
void brix_cms_reqid_map_put(const char *cms_reqid, const char *engine_reqid,
    const char *notify, const char *prty);

/* Look up AND REMOVE the mapping for cms_reqid (a prepdel consumes it).
 * Returns 1 with engine_reqid copied out, 0 on miss/expired. */
int brix_cms_reqid_map_take(const char *cms_reqid, char *engine_reqid_out,
    size_t engine_reqid_sz);

#endif /* BRIX_CMS_REQID_MAP_H */

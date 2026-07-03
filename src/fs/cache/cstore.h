#ifndef BRIX_CACHE_CSTORE_H
#define BRIX_CACHE_CSTORE_H

/*
 * cstore.h - the cache's one storage adapter (phase-64 section 6.1).
 *
 * WHAT: The ONLY code that touches a cache-store driver. It turns a generic SD
 *       instance (the cache_store tier - any driver: posix, pblock, a roots://
 *       cache server, s3, ...) into the small set of operations the read cache
 *       needs: open a fill sink, write/commit/abort it, open a served object,
 *       pread it, evict it, load/store its cinfo record, scan the store, and
 *       report free space. Every cache policy module (admit, evict, reap, verify)
 *       drives the store through THIS adapter and never through a driver directly
 *       (P3, review gate G5).
 *
 * WHY:  Before phase-64 the cache hard-coded a local POSIX tree (.cinfo sidecars,
 *       raw unlink, statvfs) and a per-scheme origin fetch. Routing every store
 *       touch through one adapter makes the cache driver-agnostic: the same
 *       eviction/fill/serve logic runs whether the store is a local SSD or a
 *       remote cache server, with the cinfo record living LOCAL (sidecar files) or
 *       as a store xattr (SP2) - a transport choice, not a format change.
 *
 * HOW:  the fill and serve calls forward to store->driver staged_x/open/pread/
 *       close; evict to unlink; scan to opendir/readdir/stat; freespace to statvfs
 *       (LOCAL)
 *       or the driver (SP2). cinfo_load/store keep the record: LOCAL writes the
 *       byte-identical "<obj>.cinfo" sidecar through the existing cinfo.c codec and
 *       a per-worker write-through L1 (cinfo_l1.h); XATTR/SIDECAR land in SP2. SP1
 *       implements LOCAL mode fully (a posix cache store is byte-identical to the
 *       pre-phase-64 tree). See docs/refactor/phase-64-fully-tiered-composable-
 *       storage.md (section 6, Appendix C/I/K).
 */

#include <ngx_core.h>

#include <limits.h>   /* PATH_MAX */

#include "cinfo.h"     /* brix_cache_cinfo_t (the cinfo record) */
#include "cinfo_l1.h"  /* brix_cinfo_l1_t (the write-through L1) */
#include "fs/backend/sd.h"  /* brix_sd_instance_t / _obj_t / _staged_t */

/* cinfo/meta encoding mode (section 6.3). AUTO resolves from the store's caps at
 * init: a store with a known local POSIX dir -> LOCAL (sidecar files next to the
 * object, byte-identical to pre-phase-64); any store advertising CAP_XATTR ->
 * XATTR (the cinfo blob lives in user.xrd.cinfo on the store, SP2); otherwise ->
 * SIDECAR (a co-located <key>.xrdcinfo object, SP2). */
#define BRIX_CMETA_AUTO    0
#define BRIX_CMETA_LOCAL   1
#define BRIX_CMETA_XATTR   2
#define BRIX_CMETA_SIDECAR 3

/* The cache-store adapter (held by value in sd_cache_inst_state, Appendix I). */
typedef struct {
    brix_sd_instance_t *store;        /* the cache_store tier instance          */
    int                   meta_mode;    /* BRIX_CMETA_* (resolved, never AUTO)   */
    int                   batch_cinfo;  /* -1 auto | 0 per-op | 1 batch-on-commit  */
    brix_cinfo_l1_t    *l1;           /* per-worker write-through cinfo cache    */
    char                  local_root[PATH_MAX];  /* LOCAL mode: the posix store dir */
    ngx_log_t            *log;
} brix_cstore_t;

/* Eviction / reaper visitor: called once per cached object with the store's stat
 * (`stx`, always valid — size/mtime for the candidate) and its cinfo (`ci`, or
 * NULL when the object has no loadable .cinfo — an orphan/partial; the policy
 * still sees it so coverage matches a raw scan). Return NGX_OK to continue the
 * scan, anything else to stop early. */
typedef ngx_int_t (*brix_cstore_visit_fn)(const char *key,
    const brix_cache_cinfo_t *ci, const brix_sd_stat_t *stx, void *ctx);

/* ---- lifecycle ------------------------------------------------------------ */

/* Initialise *cs over the cache `store` instance. `local_root` is the store's
 * absolute directory for LOCAL mode (NULL for a non-local store). `meta_mode` is
 * BRIX_CMETA_AUTO to resolve from the store's caps, or a forced mode. Builds the
 * per-worker L1 (l1_entries, 0 = default). Returns NGX_OK, or NGX_ERROR (errno
 * set) on a resolution failure (e.g. AUTO resolved to a mode this build does not
 * implement yet - a tracked "needs development", section 8.4). */
ngx_int_t brix_cstore_init(brix_cstore_t *cs, brix_sd_instance_t *store,
    const char *local_root, int meta_mode, size_t l1_entries, int batch_cinfo,
    ngx_log_t *log);

/* Release the L1 (the store instance is borrowed - not freed here). NULL-safe. */
void brix_cstore_cleanup(brix_cstore_t *cs);

/* The store's authoritative local POSIX directory (LOCAL meta_mode), or NULL for a
 * non-local store (s3/rados/remote — it has no local dir). This is the ONLY safe
 * source for "where does this cache physically live"; the reaper/state layer keys
 * off it and MUST decline filesystem reaping when it is NULL, never guess a path
 * from the advertised cache_root. NULL-safe. */
const char *brix_cstore_local_root(const brix_cstore_t *cs);

/* ---- fill spine (a cache miss writes the object into the store) ------------ */

/* Open a fill sink for `key` (a staged write on the store). Returns the store's
 * staged handle, or NULL (errno set). The handle carries its own store inst, so
 * fill_write/commit/abort dispatch through it without the cstore. */
brix_sd_staged_t *brix_cstore_fill_open(brix_cstore_t *cs, const char *key,
    mode_t mode);

/* Write `len` bytes at `off` into the fill sink. Returns bytes written, or -1. */
ssize_t brix_cstore_fill_write(brix_sd_staged_t *st, const void *buf,
    size_t len, off_t off);

/* Publish the filled object atomically (consumes `st` on NGX_OK). The cinfo is
 * recorded separately by the caller via cinfo_store (Appendix J2). */
ngx_int_t brix_cstore_fill_commit(brix_sd_staged_t *st);

/* Drop a partial fill (consumes `st`). Best-effort. */
void brix_cstore_fill_abort(brix_sd_staged_t *st);

/* ---- serve (a cache hit reads the object back) ---------------------------- */

/* Open the cached object `key` for reading. Returns a store-backed read object
 * (its ->driver is the store, so pread bypasses any decorator), or NULL + *err. */
brix_sd_obj_t *brix_cstore_serve_open(brix_cstore_t *cs, const char *key,
    int *err);

/* Fill one missing block `blk` of a partial object (source -> cache store). The
 * decorator supplies this because the SOURCE is a decorator concern, not the pure
 * store adapter's; `ctx` is the decorator's per-object state. Returns 0 / -1. */
typedef int (*brix_cstore_fill_block_fn)(void *ctx, uint64_t blk);

/* Serve a byte range from a partial object on the LOCAL cache store (section 6.5):
 * consult the present `bitmap`, fill any block the range touches that is absent via
 * `fill`(ctx, blk), then read `len` bytes at `off` from the cache object `cache_fd`
 * (through the POSIX store driver — the store keeps its own bytes). `nblocks`/
 * `block_size`/`size` describe the object geometry. A short read past `size` is a
 * 0/short return. Returns bytes read, or -1 (errno). The bitmap-consult + range
 * loop lives here (one cache serve path); the source fill stays in the decorator. */
ssize_t brix_cstore_serve_pread(int cache_fd, const uint8_t *bitmap,
    uint64_t nblocks, uint32_t block_size, off_t size, void *buf, size_t len,
    off_t off, brix_cstore_fill_block_fn fill, void *ctx);

/* Open (creating + sizing sparse) the LOCAL cache object for `key` read-write, for
 * incremental slice/partial fills (section 6.5). Writes the object's local path
 * into path_out (used to record present blocks in the cinfo). Returns an fd, or -1
 * (errno; ENOTSUP for a non-LOCAL store - partial caching needs random write to the
 * cache object). */
int brix_cstore_partial_open(brix_cstore_t *cs, const char *key, mode_t mode,
    off_t size, char *path_out, size_t path_cap);

/* ---- evict / cinfo / scan / freespace ------------------------------------- */

/* Remove the cached object `key` and its cinfo record (and drop it from the L1).
 * Idempotent: NGX_OK even when already absent. */
ngx_int_t brix_cstore_evict(brix_cstore_t *cs, const char *key);

/* Load `key`'s cinfo header into *ci (L1 first, then the store). Returns NGX_OK,
 * NGX_DECLINED when no record exists, or NGX_ERROR on a store I/O failure. */
ngx_int_t brix_cstore_cinfo_load(brix_cstore_t *cs, const char *key,
    brix_cache_cinfo_t *ci);

/* Store `key`'s cinfo header (write-through: the store record + the L1). Returns
 * NGX_OK or NGX_ERROR (errno set). */
ngx_int_t brix_cstore_cinfo_store(brix_cstore_t *cs, const char *key,
    const brix_cache_cinfo_t *ci);

/* Visit every cached key with its cinfo (for eviction / the reaper). Returns
 * NGX_OK after a full walk, or the visitor's early-stop code. */
ngx_int_t brix_cstore_scan(brix_cstore_t *cs, brix_cstore_visit_fn visit,
    void *ctx);

/* Report the store's total / available bytes. Returns NGX_OK with total and avail
 * filled, or NGX_DECLINED when the store cannot report it yet (a non-local store -
 * needs a statf slot, SP2). */
ngx_int_t brix_cstore_freespace(brix_cstore_t *cs, uint64_t *total,
    uint64_t *avail);

#endif /* BRIX_CACHE_CSTORE_H */

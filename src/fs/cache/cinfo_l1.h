#ifndef XROOTD_CACHE_CINFO_L1_H
#define XROOTD_CACHE_CINFO_L1_H

/*
 * cinfo_l1.h - the per-worker write-through cinfo cache (phase-64 section 6.4).
 *
 * WHAT: A bounded per-worker LRU keyed by cache-object key -> the cinfo HEADER
 *       record (xrootd_cache_cinfo_t validity/stats/digest, no bitmap). It is the
 *       control-plane fast path the cstore reads cinfo through, so a warm hit on a
 *       REMOTE cache store costs no store round-trip and a fill batches one cinfo
 *       write on commit instead of one per block (section 6.4).
 *
 * WHY:  When the cache store is a remote driver (roots:// / s3:// / a WebDAV
 *       server, SP2), reading the per-object cinfo via getxattr on every open
 *       would add a round-trip to each request. The L1 turns that into a local
 *       hash lookup; misses fall through to the store, and a fill mutates the L1
 *       header then writes it through once. For a LOCAL (posix) store the L1 is a
 *       cheap accelerator over the on-disk .cinfo and stays optional.
 *
 * HOW:  A small malloc-owned hash table (FNV-1a over the key) with an intrusive
 *       MRU-at-head doubly-linked LRU list; inserting past the bound evicts the
 *       tail. Malloc-owned (no nginx pool) so it is safe to touch from the cache
 *       fill worker thread, exactly like the sd_cache / cstore state it backs. One
 *       instance per cstore per worker. See docs/refactor/phase-64-fully-tiered-
 *       composable-storage.md (section 6.4, Appendix I).
 */

#include <ngx_core.h>

#include "cinfo.h"   /* xrootd_cache_cinfo_t (the cached header record) */

/* Opaque per-worker LRU handle. The public shape is just an indirection so the
 * cstore can hold one by value-pointer (Appendix I), with the table hidden. */
typedef struct {
    void *opaque;
} xrootd_cinfo_l1_t;

/* Build an L1 cache holding up to `max_entries` cinfo headers (0 selects a sane
 * default). Returns a malloc-owned handle, or NULL (errno set). */
xrootd_cinfo_l1_t *xrootd_cinfo_l1_create(size_t max_entries, ngx_log_t *log);

/* Free an L1 cache and every entry it holds. NULL-safe. */
void xrootd_cinfo_l1_destroy(xrootd_cinfo_l1_t *l1);

/* Look up `key`. On a hit copy the cached header into *out, promote it to MRU, and
 * return NGX_OK; on a miss return NGX_DECLINED (*out untouched). NULL l1 ->
 * NGX_DECLINED (the cache is simply absent). */
ngx_int_t xrootd_cinfo_l1_get(xrootd_cinfo_l1_t *l1, const char *key,
    xrootd_cache_cinfo_t *out);

/* Insert or update `key` -> *hdr (write-through), promoting it to MRU; evicts the
 * LRU tail when the bound is exceeded. NULL l1 / NULL hdr -> no-op. */
void xrootd_cinfo_l1_put(xrootd_cinfo_l1_t *l1, const char *key,
    const xrootd_cache_cinfo_t *hdr);

/* Drop `key` from the cache (on eviction / unlink / a failed fill). Idempotent. */
void xrootd_cinfo_l1_drop(xrootd_cinfo_l1_t *l1, const char *key);

#endif /* XROOTD_CACHE_CINFO_L1_H */

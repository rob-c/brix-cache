/* cas_store.h — content-addressed local POSIX object store (pure C, no ngx).
 *
 * WHAT: a "put bytes under their content hash, get them back by hash" store on a
 *       local directory, with atomic writes, a byte quota with LRU eviction, and
 *       an optional dirfd mode for overlay-cache mounts.
 * WHY:  the CVMFS client caches every immutable object it fetches; identity IS
 *       the content hash, so the store is crash-safe (temp+rename) and
 *       mirror-agnostic. A running byte counter makes the quota fill-guard O(1).
 *       The dirfd mode lets the cache live INSIDE the FUSE mountpoint (reached via
 *       a preserved fd) so `<mountdir>/.brixcache` survives the overlay mount.
 * HOW:  every op is an `*at` call on a base fd — AT_FDCWD with absolute paths
 *       (dir mode) or a preserved dirfd with relative paths (dirfd mode). Standard
 *       CVMFS `<2hex>/<rest>[suffix]` layout. libc + POSIX only.
 */
#ifndef BRIX_CAS_STORE_H
#define BRIX_CAS_STORE_H

#include <stddef.h>
#include <sys/types.h>

struct brix_cas_pack;    /* packed backend (cas_pack.h) */

typedef struct {
    char  root[512];     /* absolute root (dir mode); "" in dirfd mode */
    int   dirfd;         /* >=0 = openat-relative to this fd; -1 = absolute */
    long  quota_bytes;   /* high watermark; 0 = unbounded */
    long  cur_bytes;     /* running total (O(1) fill-guard) */
    int   no_fsync;      /* batch mode: skip the per-put fsync; the caller owns
                          * ONE durability barrier (brix_plat_sync_tree) before
                          * publishing any reference to the stored objects */
    struct brix_cas_pack *pack;   /* non-NULL = packed backend (phase-87 G4);
                                   * every op below dispatches to it */
} brix_cas_store_t;

/* Bind the store to an absolute `root` (created if absent) with an optional byte
 * quota. Returns 0 on success, -1 (errno set). */
int brix_cas_init(brix_cas_store_t *s, const char *root, long quota_bytes);

/* Bind the store to an already-open directory fd (openat-relative mode); the
 * caller owns `dirfd`. Returns 0/-1. */
int brix_cas_init_at(brix_cas_store_t *s, int dirfd, long quota_bytes);

/* Packed-backend variants (phase-87 G4/G5): same contract as the two inits
 * above, but objects land in log-structured segments under <root>/pack/.
 * `seg_bytes<=0` = default segment size; `tiering` enables G5 zstd cold
 * packing + hot promotion. Callers use the ordinary brix_cas_* ops. */
int brix_cas_init_packed(brix_cas_store_t *s, const char *root, long quota_bytes,
                         long seg_bytes, int tiering);
int brix_cas_init_packed_at(brix_cas_store_t *s, int dirfd, long quota_bytes,
                            long seg_bytes, int tiering);

/* Release backend resources (flat mode holds none; packed mode flushes and
 * frees). The struct may be re-init'ed afterwards. */
void brix_cas_destroy(brix_cas_store_t *s);

/* Object path for `key` ("<root>/<2>/<rest>" in dir mode, "<2>/<rest>" in dirfd
 * mode). Returns bytes written or -1. `key` must be >= 3 chars. */
int brix_cas_path(const brix_cas_store_t *s, const char *key, char *buf, size_t buflen);

/* 1 if present, 0 if not. */
int brix_cas_has(const brix_cas_store_t *s, const char *key);

/* Open read-only; returns an fd (caller closes) or -1 (errno set). */
int brix_cas_open(const brix_cas_store_t *s, const char *key);

/* Atomically store `len` bytes for `key` (temp + fsync + rename; the fsync is
 * skipped in no_fsync batch mode — see the struct field). Idempotent.
 * Updates the byte counter and auto-reaps to the low watermark if the store now
 * exceeds its quota. Returns 0/-1 (errno set). */
int brix_cas_put(brix_cas_store_t *s, const char *key, const void *data, size_t len);

/* Remove the object stored for `key` (and adjust the byte counter). Returns 0 if
 * removed, -1 if absent or on error (errno set). */
int brix_cas_del(brix_cas_store_t *s, const char *key);

/* Total bytes currently stored (walks the tree). */
long brix_cas_size(const brix_cas_store_t *s);

/* Evict least-recently-accessed objects until at or below `target_bytes`; also
 * refreshes the byte counter. Returns the number removed, or -1 (errno set). */
int brix_cas_reap(brix_cas_store_t *s, long target_bytes);

/* If a quota is set and the store exceeds it, reap to 75% of quota. Returns the
 * number of objects removed (0 if not over quota). */
int brix_cas_enforce_quota(brix_cas_store_t *s);

#endif /* BRIX_CAS_STORE_H */

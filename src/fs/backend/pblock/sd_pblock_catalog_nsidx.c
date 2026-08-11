/*
 * sd_pblock_catalog_nsidx.c — phase-88 W4: the shared-mmap namespace cache.
 *
 * WHAT: Promotes the worker-local heap nscache (sd_pblock_catalog.c) to a
 *       cross-process table: the same direct-mapped, positive-entry
 *       path→pblock_meta cache, but living in a mmap'd <root>/catalog.bxi
 *       every worker maps MAP_SHARED. One worker's fill warms all workers;
 *       one worker's invalidation is seen by all workers — a strict coherence
 *       upgrade over the heap table, whose invalidations never crossed the
 *       process boundary.
 *
 * WHY:  The metadata characterisation (pblock-metadata-performance.md) pinned
 *       pblock_catalog_lookup as the #1 SQLite consumer; the heap cache halved
 *       it per worker but stays cold per process and incoherent across them.
 *       The cvmfs pathidx (shared/cvmfs/index/pathidx.c) proved the mmap
 *       mechanics — fixed entries, FNV addressing, crash-tolerant validation —
 *       for a FROZEN revision; a live-mutable catalog needs the coherent-cache
 *       variant of that idea, not a snapshot.
 *
 * HOW:  Lock-free throughout (no mutex, no nginx SHM zone — INVARIANT 10 has
 *       no surface here): each entry carries a seqlock (CAS even→odd claims
 *       the writer role, +1 releases; a contended claim just skips — the cache
 *       is best-effort), the header carries two atomic u64s: `gen` (the
 *       fill-after-miss guard the heap cache already used) and `epoch`
 *       (clear-all in O(1): entries stamp the epoch they were written under;
 *       a stale stamp reads as invalid). First live opener — flock(EX|NB)
 *       succeeds on the sidecar, kernel drops flocks on death so a crashed
 *       fleet never wedges — bumps the epoch, killing any residue from an
 *       unclean shutdown; every opener then holds a SH flock as its liveness
 *       signal. Any init/validation failure disarms silently: the catalog
 *       falls back to the heap cache, correctness unchanged.
 *       ngx-free (libc + atomics); BRIX_HAVE_SQLITE-gated like its includers.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/* Like its catalog siblings this TU is pure libc + sqlite3 — no sd.h, no ngx
 * surface — so the standalone catalog harness compiles it with nothing but
 * -DBRIX_HAVE_SQLITE=1. */
#if BRIX_HAVE_SQLITE

#include "sd_pblock_catalog.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "sd_pblock_catalog_internal.h"

#define NSIDX_MAGIC    0x494e5842u          /* "BXNI" */
#define NSIDX_VERSION  1u

/* One shared entry. `seq` is the per-entry seqlock (even = stable, odd = a
 * writer is inside); `epoch` must match the header's for the entry to be
 * live, which makes clear-all a single atomic increment. */
typedef struct {
    uint32_t    seq;
    uint32_t    valid;
    uint64_t    epoch;
    char        path[PBLOCK_NSCACHE_PATHMAX];
    pblock_meta meta;
} nsidx_ent_t;

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t buckets;
    uint32_t entsize;                       /* ABI guard across mixed builds */
    uint64_t gen;                           /* fill-after-miss guard         */
    uint64_t epoch;                         /* clear-all generation          */
    uint64_t reserved[4];
} nsidx_hdr_t;

_Static_assert(sizeof(nsidx_hdr_t) == 64,
               "the sidecar header is a fixed 64-byte ABI");

#define NSIDX_FILE_SIZE \
    (sizeof(nsidx_hdr_t) + PBLOCK_NSCACHE_BUCKETS * sizeof(nsidx_ent_t))

/* ---- little accessors ----------------------------------------------------- */

static nsidx_hdr_t *
nsidx_hdr(pblock_catalog *cat)
{
    return (nsidx_hdr_t *) cat->nsidx;
}

static nsidx_ent_t *
nsidx_ent(pblock_catalog *cat, const char *path)
{
    uint64_t h = 1469598103934665603ull;
    const unsigned char *cursor;

    for (cursor = (const unsigned char *) path; *cursor != '\0'; cursor++) {
        h ^= *cursor;
        h *= 1099511628211ull;
    }
    return (nsidx_ent_t *) ((char *) cat->nsidx + sizeof(nsidx_hdr_t))
           + (h & (PBLOCK_NSCACHE_BUCKETS - 1));
}

/* nsidx_claim — CAS the entry's seqlock even→odd (the writer role). Returns
 * the claimed (odd) value, or 0 when the entry is contended — the caller just
 * skips its best-effort write. */
static uint32_t
nsidx_claim(nsidx_ent_t *e)
{
    uint32_t s = __atomic_load_n(&e->seq, __ATOMIC_ACQUIRE);

    if (s & 1u) {
        return 0;
    }
    if (!__atomic_compare_exchange_n(&e->seq, &s, s + 1u, 0,
                                     __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
    {
        return 0;
    }
    return s + 1u;
}

/* nsidx_release — publish the write: seqlock odd→even. */
static void
nsidx_release(nsidx_ent_t *e, uint32_t claimed)
{
    __atomic_store_n(&e->seq, claimed + 1u, __ATOMIC_RELEASE);
}

/* nsidx_install — claim + write a positive entry under the current epoch.
 * Best-effort: a contended entry is simply skipped. */
static void
nsidx_install(pblock_catalog *cat, const char *path, const pblock_meta *meta)
{
    nsidx_ent_t *e = nsidx_ent(cat, path);
    uint32_t     claimed = nsidx_claim(e);

    if (claimed == 0) {
        return;
    }
    snprintf(e->path, sizeof(e->path), "%s", path);
    e->meta  = *meta;
    e->valid = 1;
    __atomic_store_n(&e->epoch,
                     __atomic_load_n(&nsidx_hdr(cat)->epoch, __ATOMIC_ACQUIRE),
                     __ATOMIC_RELEASE);
    nsidx_release(e, claimed);
}

/* nsidx_drop — claim + invalidate whatever occupies the bucket (direct-mapped:
 * dropping a colliding tenant only costs it a refill). */
static void
nsidx_drop(pblock_catalog *cat, const char *path)
{
    nsidx_ent_t *e = nsidx_ent(cat, path);
    uint32_t     claimed = nsidx_claim(e);

    if (claimed == 0) {
        return;
    }
    e->valid = 0;
    nsidx_release(e, claimed);
}

/* ---- the nscache_* dispatch surface --------------------------------------- */

int
nsidx_get(pblock_catalog *cat, const char *path, pblock_meta *out)
{
    nsidx_ent_t *e = nsidx_ent(cat, path);
    nsidx_ent_t  snap;
    uint32_t     s1, s2;

    s1 = __atomic_load_n(&e->seq, __ATOMIC_ACQUIRE);
    if (s1 & 1u) {
        return 0;                       /* a writer is inside — miss */
    }
    memcpy(&snap, e, sizeof(snap));
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    s2 = __atomic_load_n(&e->seq, __ATOMIC_ACQUIRE);
    if (s1 != s2 || !snap.valid
        || snap.epoch != __atomic_load_n(&nsidx_hdr(cat)->epoch,
                                         __ATOMIC_ACQUIRE)
        || strncmp(snap.path, path, sizeof(snap.path)) != 0)
    {
        return 0;
    }
    if (out != NULL) {
        *out = snap.meta;
    }
    return 1;
}

uint64_t
nsidx_gen(pblock_catalog *cat)
{
    return __atomic_load_n(&nsidx_hdr(cat)->gen, __ATOMIC_ACQUIRE);
}

void
nsidx_store(pblock_catalog *cat, const char *path, const pblock_meta *meta,
    uint64_t gen)
{
    /* Fill-after-miss: install only while no invalidation landed since the
     * caller snapshotted `gen`; re-check afterwards and retract on a race —
     * the row read under the old generation may already be stale. */
    if (nsidx_gen(cat) != gen) {
        return;
    }
    nsidx_install(cat, path, meta);
    if (nsidx_gen(cat) != gen) {
        nsidx_drop(cat, path);
    }
}

void
nsidx_put(pblock_catalog *cat, const char *path, const pblock_meta *meta)
{
    nsidx_install(cat, path, meta);
    __atomic_add_fetch(&nsidx_hdr(cat)->gen, 1, __ATOMIC_ACQ_REL);
}

void
nsidx_inval(pblock_catalog *cat, const char *path)
{
    nsidx_drop(cat, path);
    __atomic_add_fetch(&nsidx_hdr(cat)->gen, 1, __ATOMIC_ACQ_REL);
}

void
nsidx_clear(pblock_catalog *cat)
{
    /* O(1) clear-all: entries stamped under an older epoch read as invalid. */
    __atomic_add_fetch(&nsidx_hdr(cat)->epoch, 1, __ATOMIC_ACQ_REL);
    __atomic_add_fetch(&nsidx_hdr(cat)->gen, 1, __ATOMIC_ACQ_REL);
}

/* ---- lifecycle ------------------------------------------------------------ */

/* nsidx_init_hdr — first-live-opener initialisation: lay down (or revalidate)
 * the header and bump the epoch so residue from an unclean shutdown — e.g. a
 * committed write whose cache install never happened — can never be served. */
static int
nsidx_init_hdr(void *map)
{
    nsidx_hdr_t *hdr = map;

    if (hdr->magic != 0 && (hdr->magic != NSIDX_MAGIC
                            || hdr->version != NSIDX_VERSION
                            || hdr->buckets != PBLOCK_NSCACHE_BUCKETS
                            || hdr->entsize != sizeof(nsidx_ent_t)))
    {
        return -1;                      /* an alien/mixed-build sidecar */
    }
    hdr->buckets = PBLOCK_NSCACHE_BUCKETS;
    hdr->entsize = (uint32_t) sizeof(nsidx_ent_t);
    hdr->version = NSIDX_VERSION;
    __atomic_store_n(&hdr->magic, NSIDX_MAGIC, __ATOMIC_RELEASE);
    __atomic_add_fetch(&hdr->epoch, 1, __ATOMIC_ACQ_REL);
    __atomic_add_fetch(&hdr->gen, 1, __ATOMIC_ACQ_REL);
    return 0;
}

/* First opener resets the header; a joiner verifies the existing one is a
 * compatible layout (magic/version/geometry). Returns 0, -1 on a bad layout. */
static int
nsidx_init_or_verify(void *map, int first)
{
    const nsidx_hdr_t *hdr;

    if (first) {
        return nsidx_init_hdr(map) == 0 ? 0 : -1;
    }
    hdr = map;
    if (__atomic_load_n(&hdr->magic, __ATOMIC_ACQUIRE) != NSIDX_MAGIC
        || hdr->version != NSIDX_VERSION
        || hdr->buckets != PBLOCK_NSCACHE_BUCKETS
        || hdr->entsize != sizeof(nsidx_ent_t))
    {
        return -1;
    }
    return 0;
}

int
pblock_catalog_nsidx_arm(pblock_catalog *cat, const char *root)
{
    char         path[PATH_MAX];
    void        *map;
    struct stat  stx;
    int          fd, first;

    if (cat == NULL || root == NULL || cat->nsidx != NULL) {
        errno = EINVAL;
        return -1;
    }
    if (snprintf(path, sizeof(path), "%s/catalog.bxi", root)
        >= (int) sizeof(path))
    {
        errno = ENAMETOOLONG;
        return -1;
    }
    fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) {
        return -1;
    }

    /* flock(EX|NB) succeeding means no other live opener exists (the kernel
     * drops flocks on process death, so this is crash-honest); the winner
     * resets, everyone converges on a SH lock as their liveness mark. */
    first = flock(fd, LOCK_EX | LOCK_NB) == 0;

    if (ftruncate(fd, (off_t) NSIDX_FILE_SIZE) != 0
        || fstat(fd, &stx) != 0 || stx.st_size < (off_t) NSIDX_FILE_SIZE)
    {
        close(fd);
        return -1;
    }
    map = mmap(NULL, NSIDX_FILE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
               fd, 0);
    if (map == MAP_FAILED) {
        close(fd);
        return -1;
    }

    if (nsidx_init_or_verify(map, first) != 0) {
        munmap(map, NSIDX_FILE_SIZE);
        close(fd);
        errno = EINVAL;
        return -1;
    }

    if (flock(fd, LOCK_SH) != 0) {      /* EX holders downgrade; joiners take SH */
        munmap(map, NSIDX_FILE_SIZE);
        close(fd);
        return -1;
    }

    cat->nsidx    = map;
    cat->nsidx_fd = fd;
    return 0;
}

void
nsidx_close(pblock_catalog *cat)
{
    if (cat == NULL || cat->nsidx == NULL) {
        return;
    }
    munmap(cat->nsidx, NSIDX_FILE_SIZE);
    close(cat->nsidx_fd);               /* releases the SH liveness flock */
    cat->nsidx    = NULL;
    cat->nsidx_fd = -1;
}

#else

/* ISO C forbids an empty translation unit; a no-sqlite build compiles this
 * file to nothing but this placeholder (same contract as sd_pblock.c). */
typedef int brix_sd_pblock_catalog_nsidx_disabled_t;

#endif /* BRIX_HAVE_SQLITE */

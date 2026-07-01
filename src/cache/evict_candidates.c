#include "evict_internal.h"
#include "cache_storage.h"
#include "cinfo.h"                 /* dirty-extent guard: never evict un-flushed data */
#include "../shared/safe_size.h"   /* Phase 27 W1: overflow-checked size math */

/* Phase 27 F9: upper bound on the eviction-candidate set so the growth loop
 * cannot allocate without limit even if the scanned tree is enormous. */
#define XROOTD_EVICT_MAX_CANDIDATES  (4u * 1024u * 1024u)

#include <errno.h>
#include <netinet/in.h>


/* Internal forward declarations (private to this file). */
/* xrootd_cache_fs_usage — query filesystem occupancy via statvfs.
 *
 * Reads filesystem statistics from the cache root directory using
 *       statvfs() and computes total, available, used bytes plus occupancy
 *       as parts-per-million (ppm). The ppm value is compared against
 *       conf->cache_eviction_threshold to decide whether eviction runs.
 *
 * WHY: Cache eviction needs an accurate occupancy measurement that accounts
 *      for reserved blocks (root-only space) — f_bavail excludes those,
 *      while f_blocks counts all blocks including reserved. Using f_frsize
 *      as the block size multiplier gives correct byte totals on modern
 *      filesystems.
 *
 * HOW: statvfs(root, &vfs) → extract f_frsize/f_bsize/f_blocks/f_bavail
 *      → compute total=blocks*block_size, available=avail_blocks*block_size,
 *      → used = total - available, occupancy_ppm = (used/total)*1000000.
 *      Returns NGX_OK on success, NGX_ERROR if statvfs fails or total is zero
 *      (empty filesystem).
 */
static ngx_int_t xrootd_cache_add_candidate(xrootd_cache_evict_list_t *list,
    const char *path, const struct stat *st);
static int xrootd_cache_skip_name(const char *name);

ngx_int_t
xrootd_cache_fs_usage(const char *root, xrootd_cache_fs_usage_t *usage)
{
    struct statvfs  vfs;
    uint64_t        block_size;
    uint64_t        blocks;
    uint64_t        avail_blocks;

    if (statvfs(root, &vfs) != 0 || vfs.f_blocks == 0) {
        return NGX_ERROR;
    }

    block_size = vfs.f_frsize ? (uint64_t) vfs.f_frsize
                              : (uint64_t) vfs.f_bsize;
    blocks = (uint64_t) vfs.f_blocks;
    avail_blocks = (uint64_t) vfs.f_bavail;

    usage->total = blocks * block_size;
    usage->available = avail_blocks * block_size;
    usage->used = (blocks - avail_blocks) * block_size;
    usage->occupancy_ppm = (ngx_uint_t)
        (((long double) usage->used * 1000000.0L) / (long double) usage->total);

    return NGX_OK;
}

ngx_int_t
xrootd_cache_usage_measure(xrootd_cstore_t *cs, const char *root,
    xrootd_cache_fs_usage_t *usage)
{
    uint64_t total = 0;
    uint64_t avail = 0;

    /* Prefer the store adapter so the measurement is driver-agnostic; only LOCAL
     * stores answer today (SP2 adds the non-local statf slot), and a LOCAL store
     * statvfs's the same dir as the fallback — so this is byte-identical now. */
    if (cs != NULL
        && xrootd_cstore_freespace(cs, &total, &avail) == NGX_OK
        && total > 0)
    {
        usage->total       = total;
        usage->available   = avail;
        usage->used        = (total >= avail) ? (total - avail) : 0;
        usage->occupancy_ppm = (ngx_uint_t)
            (((long double) usage->used * 1000000.0L) / (long double) total);
        return NGX_OK;
    }

    return xrootd_cache_fs_usage(root, usage);
}

/*
 * xrootd_cache_try_evict_lock — acquire an exclusive eviction lock via
 * a sentinel file created with O_CREAT | O_EXCL.
 *
 * The lock prevents two nginx worker processes from running concurrent cache
 * evictions, which could lead to both workers evicting the same file and
 * double-counting bytes.
 *
 * Stale lock handling: if the lock file is older than conf->cache_lock_timeout
 * seconds, it is treated as abandoned (worker crashed) and removed.
 *
 * Returns:
 *   NGX_OK      — lock acquired (caller must call xrootd_cache_evict_unlock).
 *   NGX_DECLINED — another worker holds a fresh lock; skip eviction.
 *   NGX_ERROR   — unexpected OS error.
 */
ngx_int_t
xrootd_cache_try_evict_lock(ngx_stream_xrootd_srv_conf_t *conf,
    char *lock_path, size_t lock_pathsz, ngx_log_t *log)
{
    int          n;
    int          fd;
    struct stat st;
    time_t      now;

    n = snprintf(lock_path, lock_pathsz, "%s/%s",
                 (char *) conf->cache_root.data,
                 XROOTD_CACHE_EVICT_LOCK_NAME);
    if (n < 0 || (size_t) n >= lock_pathsz) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }

    fd = open(lock_path, O_CREAT | O_EXCL | O_WRONLY | O_NOCTTY | O_CLOEXEC, 0600);
    if (fd >= 0) {
        close(fd);
        return NGX_OK;
    }

    if (errno != EEXIST) {
        ngx_log_error(NGX_LOG_WARN, log, errno,
                      "xrootd: cache eviction lock create failed \"%s\"",
                      lock_path);
        return NGX_ERROR;
    }

    if (stat(lock_path, &st) != 0) {
        return NGX_DECLINED;
    }

    now = time(NULL);
    if (now <= st.st_mtime
        || now - st.st_mtime <= conf->cache_lock_timeout)
    {
        return NGX_DECLINED;
    }

    ngx_log_error(NGX_LOG_WARN, log, 0,
                  "xrootd: removing stale cache eviction lock \"%s\"",
                  lock_path);
    if (unlink(lock_path) != 0 && errno != ENOENT) {
        return NGX_DECLINED;
    }

    fd = open(lock_path, O_CREAT | O_EXCL | O_WRONLY | O_NOCTTY | O_CLOEXEC, 0600);
    if (fd < 0) {
        return NGX_DECLINED;
    }

    close(fd);
    return NGX_OK;
}

void
xrootd_cache_evict_unlock(const char *lock_path)
{
    if (lock_path[0] != '\0') {
        unlink(lock_path);
    }
}
/* xrootd_cache_evict_unlock — release the eviction sentinel lock.
 *
 * Removes the eviction lock sentinel file created by
 *       xrootd_cache_try_evict_lock(). Called after an eviction pass completes
 *      (whether files were evicted or skipped) so the next worker can acquire
 *      the lock.
 *
 * WHY: The lock is a single-file O_CREAT|O_EXCL sentinel — unlink() releases
 *      it. Must be called exactly once per successful lock acquisition to
 *      prevent the lock file from persisting indefinitely and blocking all
 *      future eviction passes.
 */

/*
 * xrootd_cache_skip_name — filter special names during cache eviction scan.
 *
 * WHAT: Returns 1 (skip) for names that must not be evicted or processed:
 *   - "." and ".." (parent directory entries)
 *   - The eviction lock sentinel file name
 *   - Files ending with the partial-cache suffix (*.part)
 *   - Files ending with the lock-file suffix (*.lock)
 *
 * WHY: Prevents accidental deletion of critical infrastructure files during
 *      cache eviction. Partial cache files are in-flight transfers that must
 *      not be interrupted; lock files prevent concurrent evictions.
 *
 * HOW: Sequential strcmp checks against known special names, then suffix
 *      comparison for *.part and *.lock patterns. Returns 0 (include) if none
 *      match.
 */
static int
xrootd_cache_skip_name(const char *name)
{
    size_t name_len;
    size_t suffix_len;

    if (name[0] == '\0'
        || strcmp(name, ".") == 0
        || strcmp(name, "..") == 0
        || strcmp(name, XROOTD_CACHE_EVICT_LOCK_NAME) == 0)
    {
        return 1;
    }

    name_len = strlen(name);

    suffix_len = sizeof(XROOTD_CACHE_PART_SUFFIX) - 1;
    if (name_len >= suffix_len
        && strcmp(name + name_len - suffix_len, XROOTD_CACHE_PART_SUFFIX) == 0)
    {
        return 1;
    }

    suffix_len = sizeof(XROOTD_CACHE_LOCK_SUFFIX) - 1;
    if (name_len >= suffix_len
        && strcmp(name + name_len - suffix_len, XROOTD_CACHE_LOCK_SUFFIX) == 0)
    {
        return 1;
    }

    suffix_len = sizeof(".meta") - 1;
    if (name_len >= suffix_len
        && strcmp(name + name_len - suffix_len, ".meta") == 0)
    {
        return 1;
    }

    /* .cinfo sidecars are cache STATE, not cache data — the dirty/present-bitmap
     * record. Evicting one orphans its data file's write-back-dirty protection
     * (the next pass would no longer see the file as dirty and could reap it) and
     * loses the present-block bitmap. Never a candidate; it is removed only with
     * its data file by xrootd_cache_evict_one(). */
    suffix_len = sizeof(".cinfo") - 1;
    if (name_len >= suffix_len
        && strcmp(name + name_len - suffix_len, ".cinfo") == 0)
    {
        return 1;
    }

    return 0;
}

static ngx_int_t
xrootd_cache_add_candidate(xrootd_cache_evict_list_t *list, const char *path,
    const struct stat *st)
{
    xrootd_cache_evict_candidate_t *elts;
    char                           *evicted;
    char                           *copy;
    size_t                          len;
    size_t                          new_cap;

    if (list->protect_path != NULL
        && strcmp(path, list->protect_path) == 0)
    {
        return NGX_OK;
    }

    if (list->nelts == list->cap) {
        size_t elts_sz;

        new_cap = list->cap ? list->cap * 2 : 128;

        /* Phase 27 F9/W1: bound the candidate set and use overflow-checked size
         * math so a pathological scan cannot wrap new_cap*sizeof into a tiny
         * allocation that the loop then overruns. */
        if (new_cap > XROOTD_EVICT_MAX_CANDIDATES
            || xrootd_size_mul(new_cap, sizeof(list->elts[0]), &elts_sz)
               != NGX_OK)
        {
            return NGX_ERROR;
        }

        /*
         * Grow evicted before elts: if elts realloc succeeds but evicted
         * fails we would lose the original elts pointer (realloc freed it).
         * Growing the smaller array first avoids that dangling-pointer hazard.
         */
        evicted = realloc(list->evicted, new_cap * sizeof(char));
        if (evicted == NULL) {
            return NGX_ERROR;
        }
        list->evicted = evicted;

        elts = realloc(list->elts, elts_sz);
        if (elts == NULL) {
            /* evicted grew but elts didn't; cap stays at old value so the
             * next add call triggers a fresh grow attempt. */
            return NGX_ERROR;
        }
        list->elts = elts;
        list->cap  = new_cap;
    }

    len = strlen(path);
    if (len == (size_t)-1) {
        return NGX_ERROR;
    }
    copy = malloc(len + 1);
    if (copy == NULL) {
        return NGX_ERROR;
    }
    memcpy(copy, path, len + 1);

    list->elts[list->nelts].path  = copy;
    list->elts[list->nelts].size  = st->st_size;
    list->elts[list->nelts].atime = st->st_atime;
    list->elts[list->nelts].mtime = st->st_mtime;
    list->evicted[list->nelts]    = 0;
    list->nelts++;

    return NGX_OK;
}
/* xrootd_cache_add_candidate — append a candidate to the eviction list.
 *
 * Adds a file path and its stat metadata (size, atime, mtime) to the
 *       eviction candidate list. First checks whether this is the protected
 *       path (the lock sentinel itself) and skips it immediately.
 *
 * WHY: The candidate list grows dynamically via realloc — each new entry
 *      needs both a strdup'd path string and a struct slot. Growing the
 *      smaller evicted[] array before elts[] avoids the dangling-pointer
 *      hazard where elts realloc frees the original but evicted realloc fails.
 *
 * HOW: Check protect_path → if list full, grow arrays (evicted first, then
 *      elts) → strdup path → populate candidate struct fields → increment nelts.
 *      Returns NGX_OK on success, NGX_ERROR if memory allocation fails or
 *      strlen returns -1 (invalid path).
 */
/* evict_collect_visit — cstore_scan visitor: one call per cached object with its
 * store stat (`stx`) and cinfo (`ci`, NULL for an orphan/partial). Applies the
 * same policy the raw scan did — skip control/sidecar names, never collect a key
 * with un-flushed local writes (dirty .cinfo at the state path), add the rest as
 * eviction candidates keyed by cache_root + key. Returns NGX_OK to continue the
 * scan, NGX_ERROR to stop (candidate-array growth failure). */
static ngx_int_t
evict_collect_visit(const char *key, const xrootd_cache_cinfo_t *ci,
    const xrootd_sd_stat_t *stx, void *ctx)
{
    xrootd_cache_evict_list_t *list = ctx;
    const char                *name;
    char                       childpath[PATH_MAX];
    char                       sidecar[PATH_MAX];
    const char                *base;
    uint64_t                   dlo, dhi, dsince;
    struct stat                synth;
    int                        n;

    (void) ci;   /* dirty guard reads the state-root sidecar for exact parity */

    name = strrchr(key, '/');
    name = (name != NULL) ? name + 1 : key;
    if (xrootd_cache_skip_name(name)) {
        return NGX_OK;
    }

    n = snprintf(childpath, sizeof(childpath), "%s%s", list->cache_root, key);
    if (n < 0 || (size_t) n >= sizeof(childpath)) {
        return NGX_OK;                         /* unrepresentable — skip this key */
    }

    /* Never evict a file with un-flushed local writes (dirty .cinfo). The .cinfo
     * lives at the state path (== childpath for a co-located cache). */
    base = childpath;
    if (xrootd_cache_sidecar_path(list->cache_root, list->state_root,
                                  childpath, sidecar, sizeof(sidecar)) == 0)
    {
        base = sidecar;
    }
    if (xrootd_cache_cinfo_dirty_extent(base, &dlo, &dhi, &dsince) == NGX_OK) {
        return NGX_OK;                         /* dirty — keep */
    }

    /* Synthesize a stat for the candidate: driver stat has no atime, so the LRU
     * score uses mtime (a deterministic, monotone proxy; record_access bumps both
     * the cache-file mtime and the .cinfo). */
    ngx_memzero(&synth, sizeof(synth));
    synth.st_size  = stx->size;
    synth.st_mtime = stx->mtime;
    synth.st_atime = stx->mtime;
    return (xrootd_cache_add_candidate(list, childpath, &synth) == NGX_OK)
           ? NGX_OK : NGX_ERROR;
}

/* xrootd_cache_collect_dir — collect every eviction candidate in the cache store.
 *
 * WHAT: Builds the candidate list for an eviction pass by walking the whole cache
 *       store and adding each non-dirty regular object (path = cache_root + key).
 * WHY:  Cache eviction must consider every cached file regardless of nesting; the
 *       walk + per-object policy now run through the `cstore` adapter so the policy
 *       layer never touches a store driver directly (phase-64 P3/G5).
 * HOW:  xrootd_cstore_scan() recurses the store via the driver (skipping sidecars)
 *       and calls evict_collect_visit() per object with its stat + cinfo; the
 *       visitor applies the skip/dirty filter and adds candidates. `keydir` is kept
 *       for the public signature but the scan always starts at the store root (its
 *       only caller passes "/"). Returns NGX_OK, or NGX_ERROR if the store has no
 *       cstore (cache off) or the scan stopped on a growth failure. */
ngx_int_t
xrootd_cache_collect_dir(xrootd_cache_evict_list_t *list, const char *keydir,
    ngx_log_t *log)
{
    (void) keydir;   /* cstore_scan walks the whole store from its root */
    (void) log;

    if (list->cstore == NULL) {
        return NGX_ERROR;
    }
    return xrootd_cstore_scan((xrootd_cstore_t *) list->cstore,
                              evict_collect_visit, list);
}
/* xrootd_cache_candidate_cmp — sort comparator for eviction candidates.
 *
 * qsort-compatible comparison function that orders candidates by
 *       oldest access time first, then oldest modification time as tiebreaker,
 *       then alphabetical path name as final tiebreaker.
 *
 * WHY: Eviction policy is "oldest-first" — files accessed longest ago are
 *      least likely to be needed again. atime is the primary sort key because
 *      it reflects actual usage recency; mtime breaks ties when two files
 *      have identical access times; path name provides deterministic ordering.
 *
 * HOW: Compare atime (ascending) → if equal compare mtime (ascending)
 *      → if equal strcmp on path strings. Returns -1/0/+1 for qsort semantics.
 */

int
xrootd_cache_candidate_cmp(const void *a, const void *b)
{
    const xrootd_cache_evict_candidate_t *ca = a;
    const xrootd_cache_evict_candidate_t *cb = b;

    if (ca->atime < cb->atime) { return -1; }
    if (ca->atime > cb->atime) { return 1; }
    if (ca->mtime < cb->mtime) { return -1; }
    if (ca->mtime > cb->mtime) { return 1; }
    return strcmp(ca->path, cb->path);
}

void
xrootd_cache_free_candidates(xrootd_cache_evict_list_t *list)
{
    size_t i;

    for (i = 0; i < list->nelts; i++) {
        free(list->elts[i].path);
    }
    free(list->elts);
    free(list->evicted);
    list->elts    = NULL;
    list->evicted = NULL;
    list->nelts   = 0;
    list->cap     = 0;
}
/* xrootd_cache_free_candidates — release all memory from the eviction list.
 *
 * Frees every allocated resource in the evict_list_t struct: individual
 *       path strings, the candidate array itself, and the evicted[] tracking
 *       bitmap. Resets all fields to NULL/zero so the list can be reused.
 *
 * WHY: The candidate list uses malloc (not ngx_palloc) because it operates
 *      outside nginx's request pool lifecycle — eviction runs on a timer
 *      independent of any HTTP/stream request. Must free all allocations
 *      explicitly to avoid memory leaks across repeated eviction passes.
 */

#include "evict_internal.h"

#include <errno.h>
#include <netinet/in.h>


/* Internal forward declarations (private to this file). */
/* ---- xrootd_cache_fs_usage — query filesystem occupancy via statvfs ----
 *
 * WHAT: Reads filesystem statistics from the cache root directory using
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
/* ---- xrootd_cache_evict_unlock — release the eviction sentinel lock ----
 *
 * WHAT: Removes the eviction lock sentinel file created by
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
        new_cap = list->cap ? list->cap * 2 : 128;

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

        elts = realloc(list->elts, new_cap * sizeof(list->elts[0]));
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
/* ---- xrootd_cache_add_candidate — append a candidate to the eviction list ----
 *
 * WHAT: Adds a file path and its stat metadata (size, atime, mtime) to the
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
/* ---- xrootd_cache_collect_dir — recursively scan directory for eviction candidates ----
 *
 * WHAT: Walks a directory tree (recursively) collecting all regular files
 *       as eviction candidates. Filters out special names (. / .. / lock sentinel
 *       / *.part / *.lock), skips non-regular entries, and recurses into
 *       subdirectories.
 *
 * WHY: Cache eviction must consider every cached file regardless of directory
 *      nesting level. Recursive scan ensures files deep in the tree are
 *      included in the candidate list so oldest-first eviction can pick them.
 *      The root_dev check prevents candidates from other mounted filesystems
 *      from being evicted (e.g., a tmpfs mount under cache root).
 *
 * HOW: opendir(dir) → readdir loop → skip_name() filter → snprintf child path
 *      → lstat(child, &st) → dev check → if directory recurse collect_dir()
 *      → if regular file add_candidate(). On any error sets rc=NGX_ERROR but
 *      continues scanning remaining entries. closedir(dp) at end.
 */

ngx_int_t
xrootd_cache_collect_dir(xrootd_cache_evict_list_t *list, const char *dir,
    ngx_log_t *log)
{
    DIR           *dp;
    struct dirent *de;
    char           child[PATH_MAX];
    struct stat    st;
    int            n;
    ngx_int_t      rc;

    dp = opendir(dir);
    if (dp == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, errno,
                      "xrootd: cache eviction cannot open directory \"%s\"",
                      dir);
        return NGX_ERROR;
    }

    rc = NGX_OK;

    while ((de = readdir(dp)) != NULL) {
        if (xrootd_cache_skip_name(de->d_name)) {
            continue;
        }

        n = snprintf(child, sizeof(child), "%s/%s", dir, de->d_name);
        if (n < 0 || (size_t) n >= sizeof(child)) {
            rc = NGX_ERROR;
            continue;
        }

        if (lstat(child, &st) != 0) {
            if (errno != ENOENT) {
                ngx_log_error(NGX_LOG_WARN, log, errno,
                              "xrootd: cache eviction lstat failed \"%s\"",
                              child);
                rc = NGX_ERROR;
            }
            continue;
        }

        if (st.st_dev != list->root_dev) {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            if (xrootd_cache_collect_dir(list, child, log) != NGX_OK) {
                rc = NGX_ERROR;
            }
            continue;
        }

        if (!S_ISREG(st.st_mode)) {
            continue;
        }

        if (xrootd_cache_add_candidate(list, child, &st) != NGX_OK) {
            rc = NGX_ERROR;
            break;
        }
    }

    closedir(dp);
    return rc;
}
/* ---- xrootd_cache_candidate_cmp — sort comparator for eviction candidates ----
 *
 * WHAT: qsort-compatible comparison function that orders candidates by
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
/* ---- xrootd_cache_free_candidates — release all memory from the eviction list ----
 *
 * WHAT: Frees every allocated resource in the evict_list_t struct: individual
 *       path strings, the candidate array itself, and the evicted[] tracking
 *       bitmap. Resets all fields to NULL/zero so the list can be reused.
 *
 * WHY: The candidate list uses malloc (not ngx_palloc) because it operates
 *      outside nginx's request pool lifecycle — eviction runs on a timer
 *      independent of any HTTP/stream request. Must free all allocations
 *      explicitly to avoid memory leaks across repeated eviction passes.
 */

#include "cache_internal.h"
#include "../manager/registry.h"

#if (NGX_THREADS)

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>

#define xrootd_cache_metric_add(ctx, member, value)                      \
    do {                                                                 \
        if ((ctx) != NULL && (ctx)->metrics != NULL) {                    \
            ngx_atomic_fetch_add(&(ctx)->metrics->member,                 \
                                 (ngx_atomic_int_t) (value));             \
        }                                                                \
    } while (0)

typedef struct {
    char   *path;    /* heap-allocated absolute path; freed by
                      * xrootd_cache_free_candidates() */
    off_t   size;    /* file size in bytes (from lstat) */
    time_t  atime;   /* last access time — primary LRU sort key */
    time_t  mtime;   /* last modification time — secondary sort key */
} xrootd_cache_evict_candidate_t;

typedef struct {
    xrootd_cache_evict_candidate_t *elts;  /* dynamically grown array */
    size_t                          nelts; /* number of valid entries */
    size_t                          cap;   /* allocated capacity */
    dev_t                           root_dev;      /* only evict files on
                                                    * this device */
    const char                     *protect_path;  /* skip this path even
                                                    * if oldest (in-flight) */
    char                           *evicted;       /* parallel bool array:
                                                    * 1 if already unlinked */
} xrootd_cache_evict_list_t;

typedef struct {
    uint64_t    total;           /* filesystem total bytes */
    uint64_t    used;            /* bytes in use (blocks - bavail) */
    uint64_t    available;       /* bytes available to unprivileged user */
    ngx_uint_t  occupancy_ppm;   /* used/total in parts-per-million (0-1000000) */
} xrootd_cache_fs_usage_t;

static ngx_int_t xrootd_cache_fs_usage(const char *root,
    xrootd_cache_fs_usage_t *usage);
static ngx_int_t xrootd_cache_try_evict_lock(ngx_stream_xrootd_srv_conf_t *conf,
    char *lock_path, size_t lock_pathsz, ngx_log_t *log);
static void xrootd_cache_evict_unlock(const char *lock_path);
static ngx_int_t xrootd_cache_collect_dir(xrootd_cache_evict_list_t *list,
    const char *dir, ngx_log_t *log);
static ngx_int_t xrootd_cache_add_candidate(xrootd_cache_evict_list_t *list,
    const char *path, const struct stat *st);
static int xrootd_cache_candidate_cmp(const void *a, const void *b);
static int xrootd_cache_skip_name(const char *name);
static void xrootd_cache_free_candidates(xrootd_cache_evict_list_t *list);
static ngx_int_t xrootd_cache_evict_one(xrootd_cache_fill_t *t,
    xrootd_cache_evict_list_t *list, size_t idx, ngx_log_t *log,
    xrootd_cache_fs_usage_t *usage, ngx_uint_t *evicted_files,
    uint64_t *evicted_bytes);

static ngx_int_t
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
static ngx_int_t
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

static void
xrootd_cache_evict_unlock(const char *lock_path)
{
    if (lock_path[0] != '\0') {
        unlink(lock_path);
    }
}

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

static ngx_int_t
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

static int
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

static void
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


static ngx_int_t
xrootd_cache_evict_one(xrootd_cache_fill_t *t,
    xrootd_cache_evict_list_t *list, size_t idx, ngx_log_t *log,
    xrootd_cache_fs_usage_t *usage, ngx_uint_t *evicted_files,
    uint64_t *evicted_bytes)
{
    if (unlink(list->elts[idx].path) != 0) {
        if (errno != ENOENT) {
            ngx_log_error(NGX_LOG_WARN, log, errno,
                          "xrootd: cache eviction unlink failed \"%s\"",
                          list->elts[idx].path);
            xrootd_cache_metric_add(t->ctx, cache_eviction_errors_total, 1);
        }

        return NGX_OK;
    }

    list->evicted[idx] = 1;
    (*evicted_files)++;
    if (list->elts[idx].size > 0) {
        *evicted_bytes += (uint64_t) list->elts[idx].size;
    }

    if (t->conf->manager_mode && t->c != NULL
        && t->c->local_sockaddr != NULL)
    {
        const char *fs_path   = list->elts[idx].path;
        const char *root      = (const char *) t->conf->cache_root.data;
        size_t      root_len  = t->conf->cache_root.len;

        if (ngx_strncmp(fs_path, root, root_len) == 0
            && fs_path[root_len] == '/')
        {
            u_char   addr_buf[NGX_SOCKADDR_STRLEN];
            size_t   addr_len;
            uint16_t self_port;

            addr_len = ngx_sock_ntop(t->c->local_sockaddr,
                                     t->c->local_socklen,
                                     addr_buf, sizeof(addr_buf) - 1, 0);
            addr_buf[addr_len] = '\0';
            self_port = 0;
            if (t->c->local_sockaddr->sa_family == AF_INET) {
                self_port = ntohs(
                    ((struct sockaddr_in *) t->c->local_sockaddr)->sin_port);
            } else if (t->c->local_sockaddr->sa_family == AF_INET6) {
                self_port = ntohs(
                    ((struct sockaddr_in6 *) t->c->local_sockaddr)->sin6_port);
            }
            xrootd_srv_unregister_path((const char *) addr_buf, self_port,
                                       fs_path + root_len);
        }
    }

    if (xrootd_cache_fs_usage((char *) t->conf->cache_root.data, usage)
        != NGX_OK)
    {
        xrootd_cache_metric_add(t->ctx, cache_eviction_errors_total, 1);
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * xrootd_cache_evict_if_needed — evict cached files when the filesystem
 * occupancy exceeds the configured threshold.
 *
 * Called from the cache-fill thread after each completed download.  The
 * function is a no-op if the cache is not enabled or the threshold is 0.
 *
 * Eviction strategy (two-pass LRU):
 *   Pass 1 (optional): evict files larger than cache_max_file_size, oldest
 *     first.  Large cold files free the most space fastest.
 *   Pass 2: evict any remaining files oldest-atime-first until the filesystem
 *     occupancy drops below the threshold.
 *
 * protect_path is the file currently being filled (if any) — it is not
 * a candidate for eviction even if it is the oldest file.
 *
 * The occupancy_ppm threshold is checked twice: once before acquiring the
 * lock and once after, to avoid unnecessary lock contention when multiple
 * workers race to evict.
 *
 * Thread safety: this function runs in a thread-pool thread, not the nginx
 *   event loop.  All filesystem operations are safe to call there.  The
 *   metrics increments use ngx_atomic_fetch_add() which is thread-safe.
 */
void
xrootd_cache_evict_if_needed(xrootd_cache_fill_t *t, const char *protect_path,
    ngx_log_t *log)
{
    xrootd_cache_fs_usage_t      usage;
    xrootd_cache_evict_list_t    list;
    struct stat                  root_st;
    char                         lock_path[PATH_MAX];
    ngx_uint_t                   threshold;
    size_t                       i;
    ngx_uint_t                   evicted_files;
    uint64_t                     evicted_bytes;
    ngx_int_t                    evict_rc;

    if (t == NULL || t->conf == NULL || !t->conf->cache) {
        return;
    }

    threshold = t->conf->cache_eviction_threshold;
    if (threshold == 0 || threshold >= 1000000) {
        return;
    }

    if (xrootd_cache_fs_usage((char *) t->conf->cache_root.data, &usage)
        != NGX_OK)
    {
        xrootd_cache_metric_add(t->ctx, cache_eviction_errors_total, 1);
        return;
    }

    if (usage.occupancy_ppm <= threshold) {
        return;
    }

    ngx_memzero(lock_path, sizeof(lock_path));
    if (xrootd_cache_try_evict_lock(t->conf, lock_path, sizeof(lock_path),
                                    log) != NGX_OK)
    {
        return;
    }

    if (xrootd_cache_fs_usage((char *) t->conf->cache_root.data, &usage)
        != NGX_OK)
    {
        xrootd_cache_metric_add(t->ctx, cache_eviction_errors_total, 1);
        xrootd_cache_evict_unlock(lock_path);
        return;
    }

    if (usage.occupancy_ppm <= threshold) {
        xrootd_cache_evict_unlock(lock_path);
        return;
    }

    if (stat((char *) t->conf->cache_root.data, &root_st) != 0) {
        xrootd_cache_metric_add(t->ctx, cache_eviction_errors_total, 1);
        xrootd_cache_evict_unlock(lock_path);
        return;
    }

    ngx_memzero(&list, sizeof(list));
    list.root_dev = root_st.st_dev;
    list.protect_path = protect_path;

    if (xrootd_cache_collect_dir(&list, (char *) t->conf->cache_root.data,
                                 log) != NGX_OK)
    {
        xrootd_cache_metric_add(t->ctx, cache_eviction_errors_total, 1);
    }

    if (list.nelts > 1) {
        qsort(list.elts, list.nelts, sizeof(list.elts[0]),
              xrootd_cache_candidate_cmp);
    }

    evicted_files = 0;
    evicted_bytes = 0;
    evict_rc = NGX_OK;

/*
 * Two-pass eviction:
 *   Pass 1 — evict files above cache_max_file_size first (oldest first).
 *             Large files are usually not worth keeping after they've grown
 *             cold; evicting them first frees the most space fastest.
 *   Pass 2 — evict any remaining files oldest first until we drop below
 *             the occupancy threshold.
 *
 * When cache_max_file_size is 0 (no size limit), pass 1 is skipped and
 * pass 2 degrades to the original single-pass LRU behaviour.
 */

    /* Pass 1: large files only (size > cache_max_file_size), oldest first */
    if (t->conf->cache_max_file_size > 0) {
        for (i = 0; i < list.nelts && usage.occupancy_ppm > threshold
             && evict_rc == NGX_OK; i++)
        {
            if (list.elts[i].size <= t->conf->cache_max_file_size) {
                continue;
            }
            evict_rc = xrootd_cache_evict_one(t, &list, i, log, &usage,
                                              &evicted_files, &evicted_bytes);
        }
    }

    /* Pass 2: remaining files (or all files if no size limit), oldest first */
    for (i = 0; i < list.nelts && usage.occupancy_ppm > threshold
         && evict_rc == NGX_OK; i++)
    {
        if (list.evicted[i]) {
            continue;
        }
        evict_rc = xrootd_cache_evict_one(t, &list, i, log, &usage,
                                          &evicted_files, &evicted_bytes);
    }

    if (evicted_files > 0) {
        xrootd_cache_metric_add(t->ctx, cache_evictions_total, evicted_files);
        xrootd_cache_metric_add(t->ctx, cache_evicted_bytes_total,
                                evicted_bytes);
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
                      "xrootd: cache eviction removed %ui files, %uL bytes, "
                      "occupancy=0.%06ui threshold=0.%06ui",
                      evicted_files, (uint64_t) evicted_bytes,
                      usage.occupancy_ppm, threshold);
    }

    xrootd_cache_free_candidates(&list);
    xrootd_cache_evict_unlock(lock_path);
}

#endif /* NGX_THREADS */

/*
 * list_walk.c — S3 ListObjects filesystem walker, comparator, and lazy stat.
 *
 * WHAT: Three functions used by the V1/V2 list emitters
 *   (list_objects_v2.c / list_objects_v1.c):
 *   - s3_walk(): recursive directory walker that appends object (is_prefix=0)
 *     and CommonPrefix (is_prefix=1) entries into a growable array, respecting
 *     prefix, delimiter, and sentinel filters.
 *   - entry_cmp(): qsort comparator for lexicographic key ordering.
 *   - s3_entry_fill_stat(): lazily fill size/mtime/ETag for ONE emitted object.
 *
 * WHY (phase-45 W1): the previous walker `lstat`'d EVERY entry in the whole
 *   prefix subtree and stored them in a fixed `s3_entry_t[65536]` (~273 MB per
 *   request, key[4096] inline) — both costs grew with the bucket, not the page.
 *   ListObjects requires a globally-sorted key set to paginate, so the *names*
 *   must still be walked; but `size`/`mtime`/`ETag` are only needed for the
 *   ≤max-keys objects actually emitted. So this walker:
 *     1. classifies dir/file/symlink from readdir's `d_type` with NO stat
 *        (an `lstat` fallback only on `DT_UNKNOWN`, e.g. some NFS mounts), and
 *     2. collects only a pooled, right-sized key + the is_prefix flag,
 *   and the caller `lstat`s just the emitted page slice via s3_entry_fill_stat().
 *   → `lstat` count drops from O(objects in subtree) to O(page); the entry
 *   store drops from a fixed 273 MB to O(actual key bytes).
 *
 * The symlink-skip security property is preserved: a `DT_LNK` entry is skipped
 * outright, and a `DT_UNKNOWN` entry is `lstat`'d and skipped if `S_ISLNK` — a
 * symlink is never listed as an object nor recursed into (it could otherwise
 * leak another tenant's tree or the host filesystem).
 */


#include "s3.h"
#include "../compat/fs_walk.h"
#include "../path/path.h"
#include <errno.h>
#include <stdlib.h>

#include <sys/stat.h>
#include <dirent.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <time.h>

/* -------------------------------------------------------------------------
 * qsort comparator — lexicographic key order
 * ---------------------------------------------------------------------- */

int
entry_cmp(const void *a, const void *b)
{
    return strcmp(((const s3_entry_t *) a)->key,
                  ((const s3_entry_t *) b)->key);
}

/* -------------------------------------------------------------------------
 * Push a (pooled, right-sized) key into the growable entry array
 * ---------------------------------------------------------------------- */

static int
s3_walk_push(ngx_array_t *entries, const char *key, unsigned is_prefix)
{
    size_t       len = strlen(key);
    char        *kdup;
    s3_entry_t  *e;

    kdup = ngx_pnalloc(entries->pool, len + 1);
    if (kdup == NULL) {
        return -1;
    }
    ngx_memcpy(kdup, key, len + 1);

    e = ngx_array_push(entries);
    if (e == NULL) {
        return -1;
    }
    e->key       = kdup;
    e->is_prefix = is_prefix;
    e->size      = 0;
    e->mtime     = 0;
    e->etag[0]   = '\0';
    return 0;
}

/* -------------------------------------------------------------------------
 * Classify a directory entry: 1 = dir, 2 = regular file, 0 = skip.
 * Uses readdir d_type (no syscall); falls back to a confined lstat only on
 * DT_UNKNOWN.  Symlinks (and FIFO/SOCK/CHR/BLK) are skipped.
 * ---------------------------------------------------------------------- */

static int
s3_walk_classify(ngx_log_t *log, const char *root, const char *child_path,
    unsigned char d_type)
{
    struct stat sb;

    switch (d_type) {
    case DT_DIR:
        return 1;
    case DT_REG:
        return 2;
    case DT_LNK:
        return 0;   /* never list or traverse a symlink */
    case DT_UNKNOWN:
        if (xrootd_lstat_confined_canon(log, root, child_path, &sb, 1) != 0) {
            return 0;
        }
        if (S_ISDIR(sb.st_mode)) {
            return 1;
        }
        if (S_ISREG(sb.st_mode)) {
            return 2;
        }
        return 0;   /* symlink / special → skip */
    default:
        return 0;   /* FIFO/SOCK/CHR/BLK → skip */
    }
}

/* -------------------------------------------------------------------------
 * Recursive directory walker — appends entries, returns the running total
 * ---------------------------------------------------------------------- */

int
s3_walk(ngx_log_t  *log,           /* request log (for the access gate)   */
        const char *root,          /* filesystem root (== root_canon)     */
        const char *dir_path,      /* filesystem path to scan    */
        const char *key_prefix,    /* key prefix so far          */
        const char *filter_prefix, /* ListObjects prefix param   */
        const char *delimiter,     /* hierarchy delimiter        */
        ngx_array_t *entries,      /* growable output array      */
        int         max_entries)   /* hard cap on entries        */
{
    DIR            *dh;
    struct dirent  *de;
    char            child_path[PATH_MAX];
    char            child_key[S3_MAX_KEY];
    /* Cache lengths once — avoids repeated strlen() in the readdir loop. */
    size_t          fp_len  = filter_prefix ? strlen(filter_prefix) : 0;
    size_t          del_len = delimiter     ? strlen(delimiter)      : 0;

    /*
     * Phase 40 confidentiality gate: under impersonation the worker uid may be
     * able to readdir() a directory the MAPPED user cannot.  Ask the broker to
     * open it as the mapped user first; on denial skip the whole subtree rather
     * than enumerate it with the worker's credentials.  No-op when off.
     */
    if (xrootd_dirlist_access_ok(log, root, dir_path) != NGX_OK) {
        return (int) entries->nelts;
    }

    /* Enumerate AS THE MAPPED USER under impersonation (broker fdopendir); off
     * impersonation this is a bare opendir(). */
    dh = xrootd_opendir_confined_canon(log, root, dir_path);
    if (dh == NULL) {
        return (int) entries->nelts;
    }

    while ((de = readdir(dh)) != NULL && (int) entries->nelts < max_entries) {
        int kind;

        if (xrootd_fs_is_dot_entry(de->d_name)) {
            continue; /* skip . and .. */
        }

        /* Build filesystem path */
        if ((size_t) snprintf(child_path, sizeof(child_path), "%s/%s",
                              dir_path, de->d_name) >= sizeof(child_path)) {
            continue;
        }

        /* Build key relative to root */
        if (key_prefix[0] != '\0') {
            if ((size_t) snprintf(child_key, sizeof(child_key), "%s/%s",
                                  key_prefix, de->d_name) >= sizeof(child_key)) {
                continue;
            }
        } else {
            if (strlen(de->d_name) >= sizeof(child_key)) {
                continue;
            }
            memcpy(child_key, de->d_name, strlen(de->d_name) + 1);
        }

        /*
         * phase-45 W1: classify from readdir d_type (no stat); lstat only on
         * DT_UNKNOWN.  Symlinks are skipped here (kind==0) — the same outcome
         * the old eager lstat produced via S_ISLNK matching neither branch.
         */
        kind = s3_walk_classify(log, root, child_path, de->d_type);
        if (kind == 0) {
            continue;
        }

        if (kind == 1) {   /* directory */
            if (del_len > 0) {
                /* Build "dir_key/" to check against filter_prefix */
                char prefix_entry[S3_MAX_KEY];
                if ((size_t) snprintf(prefix_entry, sizeof(prefix_entry), "%s/",
                                      child_key) >= sizeof(prefix_entry)) {
                    continue;
                }
                size_t pe_len = strlen(prefix_entry);

                /*
                 * Recurse if filter_prefix starts with this dir (i.e. the
                 * user-supplied prefix descends into this directory).
                 */
                if (fp_len > 0 && fp_len >= pe_len
                    && strncmp(filter_prefix, prefix_entry, pe_len) == 0) {
                    s3_walk(log, root, child_path, child_key,
                            filter_prefix, delimiter, entries, max_entries);
                    continue;
                }

                /* Emit as CommonPrefix if it matches or starts with filter */
                if (fp_len > 0
                    && strncmp(prefix_entry, filter_prefix, fp_len) != 0) {
                    continue;
                }
                /* CommonPrefix carries no size/mtime/etag (S3 spec) — no stat. */
                if (s3_walk_push(entries, prefix_entry, 1) != 0) {
                    break;
                }
            } else {
                /* No delimiter: recurse unconditionally */
                s3_walk(log, root, child_path, child_key,
                        filter_prefix, delimiter, entries, max_entries);
            }
        } else {           /* kind == 2: regular file */
            /* Skip directory sentinel */
            if (strcmp(de->d_name, S3_DIR_SENTINEL) == 0) {
                continue;
            }
            /* Filter by prefix */
            if (fp_len > 0 && strncmp(child_key, filter_prefix, fp_len) != 0) {
                continue;
            }
            /* With delimiter, skip entries that have a delimiter after prefix
             * (they belong under a CommonPrefix subtree, not at this level). */
            if (del_len > 0) {
                const char *after_prefix = child_key + fp_len;
                if (strstr(after_prefix, delimiter) != NULL) {
                    continue;
                }
            }

            /* phase-45 W1: collect the key only; size/mtime/etag are filled
             * lazily for the emitted page via s3_entry_fill_stat(). */
            if (s3_walk_push(entries, child_key, 0) != 0) {
                break;
            }
        }
    }

    closedir(dh);
    return (int) entries->nelts;
}

/* -------------------------------------------------------------------------
 * Lazy per-object stat — called only for the entries actually emitted
 * ---------------------------------------------------------------------- */

ngx_int_t
s3_entry_fill_stat(ngx_log_t *log, const char *root, s3_entry_t *e)
{
    char        fs_path[PATH_MAX];
    struct stat sb;

    if (e->is_prefix) {
        return NGX_OK;   /* CommonPrefix: no size/mtime/etag */
    }

    /* The walk built keys relative to root, so the filesystem path of an object
     * is always root + "/" + key (see s3_walk's child_path/child_key). */
    if ((size_t) snprintf(fs_path, sizeof(fs_path), "%s/%s", root, e->key)
        >= sizeof(fs_path)) {
        return NGX_DECLINED;
    }

    /* nofollow lstat (confined): if the entry vanished or is no longer a
     * regular file (e.g. swapped for a symlink after the walk), skip it —
     * matching the eager walker's stat-failure / symlink skip. */
    if (xrootd_lstat_confined_canon(log, root, fs_path, &sb, 1) != 0
        || !S_ISREG(sb.st_mode)) {
        return NGX_DECLINED;
    }

    e->size  = sb.st_size;
    e->mtime = sb.st_mtime;
    s3_etag(&sb, e->etag, sizeof(e->etag));
    return NGX_OK;
}

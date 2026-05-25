/*
 * list_walk.c — S3 ListObjectsV2 filesystem walker and comparator.
 *
 * WHAT: Two functions used exclusively by s3_handle_list() in
 *   list_objects_v2.c:
 *   - entry_cmp(): qsort comparator for lexicographic key ordering.
 *   - s3_walk(): recursive directory walker that populates entries[]
 *     with objects (is_prefix=0) and common prefixes (is_prefix=1),
 *     respecting prefix, delimiter, and sentinel filters.
 *
 * WHY: S3 ListObjectsV2 requires deterministic pagination — the
 *   continuation-token linear scan depends on entries being sorted.
 *   The walker must distinguish objects from directory-like common
 *   prefixes using the delimiter parameter (typically "/"), skip
 *   .xrdcls3.dirsentinel files, and apply prefix filtering at both
 *   the key level and the filesystem path level to avoid unnecessary
 *   recursion into non-matching subdirectories.
 *
 * HOW:
 *   entry_cmp(): strcmp on s3_entry_t->key fields — standard qsort
 *     comparator producing ascending lexicographic order.
 *   s3_walk(): opendir(dir_path) → readdir loop, for each entry:
 *     1. Skip . and .. entries (xrootd_fs_is_dot_entry).
 *     2. Build child_path and child_key relative to root.
 *     3. stat() the child — skip on failure.
 *     4. If directory: with delimiter, emit as CommonPrefix if
 *        prefix_entry matches filter_prefix; recurse only if
 *        filter_prefix starts with prefix_entry (avoid wasted traversal).
 *        Without delimiter: recurse unconditionally.
 *     5. If regular file: skip .xrdcls3.dirsentinel, apply prefix
 *        filter, skip entries containing delimiter after prefix
 *        (they belong under a CommonPrefix). Emit object with size,
 *        mtime, and etag.
 */


#include "s3.h"
#include "../compat/fs_walk.h"
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
 * Recursive directory walker — fills entries[], returns count
 * ---------------------------------------------------------------------- */

int
s3_walk(const char *root,          /* filesystem root            */
        const char *dir_path,      /* filesystem path to scan    */
        const char *key_prefix,    /* key prefix so far          */
        const char *filter_prefix, /* ListObjectsV2 prefix param */
        const char *delimiter,     /* hierarchy delimiter        */
        s3_entry_t *entries,       /* output array               */
        int         max_entries,   /* size of entries[]          */
        int        *count)         /* current fill index         */
{
    DIR            *dh;
    struct dirent  *de;
    struct stat     sb;
    char            child_path[PATH_MAX];
    char            child_key[S3_MAX_KEY];
    /* Cache lengths once — avoids repeated strlen() in the readdir loop. */
    size_t          fp_len  = filter_prefix ? strlen(filter_prefix) : 0;
    size_t          del_len = delimiter     ? strlen(delimiter)      : 0;

    dh = opendir(dir_path);
    if (dh == NULL) {
        return 0;
    }

    while ((de = readdir(dh)) != NULL && *count < max_entries) {
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

        if (stat(child_path, &sb) != 0) {
            continue;
        }

        if (S_ISDIR(sb.st_mode)) {
            if (del_len > 0) {
                /* Build "dir_key/" to check against filter_prefix */
                char prefix_entry[S3_MAX_KEY];
                if ((size_t) snprintf(prefix_entry, sizeof(prefix_entry), "%s/",
                                      child_key) >= sizeof(prefix_entry)) {
                    continue;
                }
                size_t pe_len = strlen(prefix_entry);

                /* Two-phase prefix check:
                 * Phase 1 (line 130): recurse into this dir only if filter_prefix
                 *   starts with prefix_entry — avoids walking subdirs that can't match.
                 * Phase 2 (line 138): emit as CommonPrefix if prefix_entry starts with
                 *   filter_prefix — this is the S3 <CommonPrefixes> response element. */


                /*
                 * Recurse if filter_prefix starts with this dir (i.e. the
                 * user-supplied prefix descends into this directory).
                 * Example: dir="dlist_x", prefix="dlist_x/" → recurse.
                 */
                if (fp_len > 0 && fp_len >= pe_len
                    && strncmp(filter_prefix, prefix_entry, pe_len) == 0) {
                    s3_walk(root, child_path, child_key,
                            filter_prefix, delimiter, entries, max_entries, count);
                    continue;
                }

                /* Emit as CommonPrefix if it matches or starts with filter */
                if (fp_len > 0
                    && strncmp(prefix_entry, filter_prefix, fp_len) != 0) {
                    continue;
                }
                s3_entry_t *e = &entries[*count];
                ngx_cpystrn((u_char *) e->key, (u_char *) prefix_entry,
                            sizeof(e->key));
                e->is_prefix = 1;
                e->size      = 0;
                e->mtime     = sb.st_mtime;

                /* CommonPrefix has no size/mtime/etag — S3 spec requires empty values. */

                e->etag[0]   = '\0';
                (*count)++;
            } else {
                /* No delimiter: recurse unconditionally */
                s3_walk(root, child_path, child_key,
                        filter_prefix, delimiter, entries, max_entries, count);
            }
        } else if (S_ISREG(sb.st_mode)) {
            /* Skip directory sentinel */

                /* .xrdcls3.dirsentinel files mark directories as S3 objects — omit them
                 * from listings since the CommonPrefix already represents that hierarchy. */

            if (strcmp(de->d_name, S3_DIR_SENTINEL) == 0) {
                continue;
            }
            /* Filter by prefix */
            if (fp_len > 0 && strncmp(child_key, filter_prefix, fp_len) != 0) {
                continue;
            }
            /* With delimiter, skip entries that have delimiter after prefix */
            if (del_len > 0) {
                const char *after_prefix = child_key + fp_len;
                if (strstr(after_prefix, delimiter) != NULL) {

                    /* The key contains a '/' after the prefix — this object lives under
                     * a CommonPrefix subtree, not at the current level. Skip it; it will
                     * appear as a <CommonPrefixes> element instead. */

                    /* belongs under a CommonPrefix — skip */
                    continue;
                }
            }

            s3_entry_t *e = &entries[*count];
            ngx_cpystrn((u_char *) e->key, (u_char *) child_key,
                        sizeof(e->key));
            e->is_prefix = 0;
            e->size      = sb.st_size;
            e->mtime     = sb.st_mtime;

            struct stat *stp = &sb;
            s3_etag(stp, e->etag, sizeof(e->etag));
            (*count)++;
        }
    }

    closedir(dh);
    return *count;
}


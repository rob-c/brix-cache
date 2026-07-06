/*
 * reserved_names.h — the single source of truth for INTERNAL on-disk artifact
 * names that must NEVER be exposed to a client.
 *
 * WHAT: brix_is_internal_name(path) returns non-zero when the final path
 *   component is a service-internal metadata/staging artifact — a cache sidecar
 *   (.cinfo / .xrdcinfo / .meta), a stage-out crash-recovery marker (.commit),
 *   or an in-flight upload temp (…​.xrd-tmp.… / …​.xrdresume.…). These files can
 *   land inside a client-visible export namespace: the upload temps do so by
 *   default (when no separate stage dir is configured, they sit adjacent to the
 *   target file), and the cache sidecars do so if the cache/state tree is
 *   misconfigured under an export root.
 *
 * WHY: Every client-facing enumeration (root:// dirlist, WebDAV PROPFIND/SEARCH,
 *   S3 ListObjects) and every direct-access-by-name path (root:// open/stat/
 *   statx, WebDAV GET/HEAD, S3 GetObject) must treat these as invisible — a
 *   listing skips them and a direct request returns NotFound — so their
 *   contents, sizes, mtimes, and even their existence (which leaks residency /
 *   in-progress-upload activity) never reach a client. This is the one predicate
 *   all of those checkpoints call, so the reserved set is defined exactly once.
 *   The internal cache scanner (cstore) uses the same predicate to skip sidecars
 *   when enumerating cached objects.
 *
 * NOTE: these suffixes/infixes are RESERVED — a client-supplied name that matches
 *   is treated as internal (hidden / NotFound). The patterns are XRootD-specific
 *   and distinctive to keep collisions with genuine user data negligible.
 *
 * HOW: pure lexical test on the basename; no allocation, no I/O. Accepts either a
 *   full path or a bare name (the basename is located internally).
 */
#ifndef BRIX_FS_PATH_RESERVED_NAMES_H
#define BRIX_FS_PATH_RESERVED_NAMES_H

#include <string.h>

static inline int
brix_name_has_suffix(const char *name, size_t n, const char *suf, size_t suflen)
{
    return n >= suflen && memcmp(name + n - suflen, suf, suflen) == 0;
}

static inline int
brix_is_internal_name(const char *path)
{
    const char *name;
    size_t      n;

    if (path == NULL) {
        return 0;
    }
    name = strrchr(path, '/');
    name = (name != NULL) ? name + 1 : path;   /* basename */
    n = strlen(name);
    if (n == 0) {
        return 0;
    }

    /* Cache metadata sidecars (block-present bitmap + origin metadata). */
    if (brix_name_has_suffix(name, n, ".cinfo", 6)
        || brix_name_has_suffix(name, n, ".xrdcinfo", 9)
        || brix_name_has_suffix(name, n, ".meta", 5))
    {
        return 1;
    }
    /* Stage-out crash-recovery marker (records a pending commit's final path). */
    if (brix_name_has_suffix(name, n, ".commit", 7)) {
        return 1;
    }
    /* In-flight upload temps: <base>.xrd-tmp.<pid>.<rand> (atomic direct write)
     * and <base>.xrdresume.<hash>.part (resumable Content-Range PUT). Matched by
     * their distinctive infix so the trailing pid/hash/.part does not matter. */
    if (strstr(name, ".xrd-tmp.") != NULL
        || strstr(name, ".xrdresume.") != NULL)
    {
        return 1;
    }

    return 0;
}

#endif /* BRIX_FS_PATH_RESERVED_NAMES_H */

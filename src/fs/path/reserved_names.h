/*
 * reserved_names.h — the single source of truth for INTERNAL on-disk artifact
 * names that must NEVER be exposed to a client.
 *
 * WHAT: brix_is_internal_name(path) returns non-zero when ANY component of the
 *   path is a service-internal metadata/staging artifact — a cache sidecar
 *   (.cinfo / .xrdcinfo / .meta), a stage-out crash-recovery marker (.commit),
 *   or an in-flight upload temp (…​.xrd-tmp.… / …​.xrdresume.…). These files can
 *   land inside a client-visible export namespace: the upload temps do so by
 *   default (when no separate stage dir is configured, they sit adjacent to the
 *   target file), and the cache sidecars do so if the cache/state tree is
 *   misconfigured under an export root.
 *
 * WHY: Every client-facing enumeration (root:// dirlist, WebDAV PROPFIND/SEARCH,
 *   S3 ListObjects) and every direct-access-by-name path (root:// open/stat/
 *   statx/rm/rmdir/chmod/mv/truncate, WebDAV GET/HEAD, S3 GetObject) must treat
 *   these as invisible — a listing skips them and a direct request returns
 *   NotFound — so their contents, sizes, mtimes, and even their existence (which
 *   leaks residency / in-progress-upload activity) never reach a client. This is
 *   the one predicate all of those checkpoints call, so the reserved set is
 *   defined exactly once. The internal cache scanner (cstore) uses the same
 *   predicate to skip sidecars when enumerating cached objects.
 *
 *   EVERY component is tested, not just the last one, because the reserved set
 *   contains names a DIRECTORY can carry (an .meta/ state tree, a .commit/
 *   staging dir): hiding only the directory entry itself while serving
 *   "/adir.meta/inside.txt" on request would leave the whole subtree reachable
 *   by name — and invisible in every listing, which is exactly the shape a
 *   client cannot be told about but can still read.
 *
 * NOTE: these suffixes/infixes are RESERVED — a client-supplied name that matches
 *   is treated as internal (hidden / NotFound). The patterns are XRootD-specific
 *   and distinctive to keep collisions with genuine user data negligible.
 *
 * HOW: pure lexical walk over the '/'-separated components; no allocation, no
 *   I/O. Accepts either a full path or a bare name (a dirent, which is one
 *   component and therefore costs exactly the old single test).
 */
#ifndef BRIX_FS_PATH_RESERVED_NAMES_H
#define BRIX_FS_PATH_RESERVED_NAMES_H

#include <string.h>

static inline int
brix_name_has_suffix(const char *name, size_t n, const char *suf, size_t suflen)
{
    return n >= suflen && memcmp(name + n - suflen, suf, suflen) == 0;
}

/* Bounded infix search: the component is a SLICE of the caller's path, so it is
 * not NUL-terminated and strstr() would run past its end into the next one. */
static inline int
brix_name_has_infix(const char *name, size_t n, const char *inf, size_t inflen)
{
    size_t i;

    if (n < inflen) {
        return 0;
    }
    for (i = 0; i + inflen <= n; i++) {
        if (memcmp(name + i, inf, inflen) == 0) {
            return 1;
        }
    }
    return 0;
}

/* One path component, given as (pointer, length) — no NUL required. */
static inline int
brix_component_is_internal(const char *name, size_t n)
{
    if (n == 0) {
        return 0;
    }

    /* Cache metadata sidecars (block-present bitmap + origin metadata) and the
     * XrdOssCsi per-page-checksum tag sidecar (.xrdt: written by stock XRootD
     * deployments and the CSI migration tooling next to the data file; xmeta
     * superseded it here, but interop trees still carry them). */
    if (brix_name_has_suffix(name, n, ".cinfo", 6)
        || brix_name_has_suffix(name, n, ".xrdcinfo", 9)
        || brix_name_has_suffix(name, n, ".meta", 5)
        || brix_name_has_suffix(name, n, ".xrdt", 5))
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
    if (brix_name_has_infix(name, n, ".xrd-tmp.", 9)
        || brix_name_has_infix(name, n, ".xrdresume.", 11))
    {
        return 1;
    }

    return 0;
}

static inline int
brix_is_internal_name(const char *path)
{
    const char *p;
    const char *slash;
    size_t      n;

    if (path == NULL) {
        return 0;
    }

    p = path;
    while (*p != '\0') {
        while (*p == '/') {          /* leading and repeated separators */
            p++;
        }
        slash = strchr(p, '/');
        n = (slash != NULL) ? (size_t) (slash - p) : strlen(p);
        if (brix_component_is_internal(p, n)) {
            return 1;
        }
        if (slash == NULL) {
            break;
        }
        p = slash + 1;
    }

    return 0;
}

#endif /* BRIX_FS_PATH_RESERVED_NAMES_H */

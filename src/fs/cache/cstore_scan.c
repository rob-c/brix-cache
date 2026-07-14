/*
 * cstore_scan.c - the cache-store namespace walk (split from cstore.c).
 *
 * The scan is the sole namespace-walk for scan/evict: it recurses the store's
 * directory tree, skips metadata sidecars, and presents each cached object to
 * an eviction/reaper visitor exactly once. Split out of cstore.c verbatim to
 * keep each file under the size cap; every symbol it crosses to (the store
 * adapter type, the visitor typedef, brix_cstore_cinfo_load) is declared in
 * cstore.h, so no internal header is required.
 */
#include "cstore.h"
#include "fs/meta/xmeta_carrier.h"   /* the unified record: xattr/sidecar carrier */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

/* ---- scan ----------------------------------------------------------------- */

/* True when `name` is a cstore metadata sidecar rather than a cached object. */
static int
cstore_is_sidecar(const char *name)
{
    size_t n = strlen(name);

    return (n >= 6 && strcmp(name + n - 6, ".cinfo") == 0)
        || (n >= 5 && strcmp(name + n - 5, ".meta") == 0)
        || (n >= 9 && strcmp(name + n - 9, ".xrdcinfo") == 0);
}

/*
 * WHAT:  Decide whether a readdir entry name should be skipped by the scan.
 * WHY:   The scan must never surface the "." / ".." pseudo-entries, empty
 *        names, or metadata sidecars as cached objects.
 * HOW:   Pure name predicate — true when the entry is not a cached object.
 */
static int
cstore_scan_skip(const char *name)
{
    return name[0] == '\0' || strcmp(name, ".") == 0
        || strcmp(name, "..") == 0 || cstore_is_sidecar(name);
}

/*
 * WHAT:  Join `dirkey` and a child `name` into out[cap] (the child's store key).
 * WHY:   Nested scan keys are built the same everywhere: exactly one '/' between
 *        the parent key and the entry name, regardless of a trailing slash.
 * HOW:   Snprintf with a conditional separator; returns 0 on success, -1 when
 *        the result is empty or would overflow (caller skips the entry).
 */
static int
cstore_scan_child_key(const char *dirkey, size_t dklen, const char *name,
    char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s%s%s", dirkey,
                     (dklen > 0 && dirkey[dklen - 1] == '/') ? "" : "/", name);

    return (n > 0 && (size_t) n < cap) ? 0 : -1;
}

/* Forward decl: cstore_scan_child recurses into subdirs via cstore_scan_dir. */
static ngx_int_t cstore_scan_dir(brix_cstore_t *cs, const char *dirkey,
    brix_cstore_visit_fn visit, void *ctx);

/*
 * WHAT:  Handle one already-keyed child: recurse into dirs, visit regulars.
 * WHY:   Keeps the scan loop flat — the per-entry stat + dispatch (recurse vs
 *        visit) is a single cohesive step with its own early-returns.
 * HOW:   Stat the child through the store driver; a missing stat slot or a
 *        failed stat is a silent skip (NGX_OK). Directories recurse; regular
 *        objects are handed to the visitor with their cinfo when present (NULL
 *        for orphan/partial) and always the store stat, so an eviction policy
 *        sees the same set a raw driver scan would.
 */
static ngx_int_t
cstore_scan_child(brix_cstore_t *cs, const char *childkey,
    brix_cstore_visit_fn visit, void *ctx)
{
    brix_sd_stat_t stx;

    if (cs->store->driver->stat == NULL
        || cs->store->driver->stat(cs->store, childkey, &stx) != NGX_OK)
    {
        return NGX_OK;                          /* unstattable: skip, keep going */
    }
    if (stx.is_dir) {
        return cstore_scan_dir(cs, childkey, visit, ctx);
    }
    if (stx.is_reg) {
        brix_cache_cinfo_t ci;
        int loaded = (brix_cstore_cinfo_load(cs, childkey, &ci) == NGX_OK);

        return visit(childkey, loaded ? &ci : NULL, &stx, ctx);
    }
    return NGX_OK;                              /* neither dir nor regular: skip */
}

/*
 * WHAT:  Recursively visit cached objects beneath `dirkey` on the store.
 * WHY:   Sole namespace-walk for scan/evict; every cached object under the root
 *        must be presented to the visitor exactly once.
 * HOW:   Opendir (a missing dir is not an error), then for each non-skipped
 *        entry build its child key and dispatch it via cstore_scan_child; stop
 *        early when the visitor or a subdir returns non-OK.
 */
static ngx_int_t
cstore_scan_dir(brix_cstore_t *cs, const char *dirkey,
    brix_cstore_visit_fn visit, void *ctx)
{
    brix_sd_dir_t    *d;
    brix_sd_dirent_t  de;
    ngx_int_t           rc = NGX_OK;
    int                 err = 0;
    size_t              dklen = strlen(dirkey);

    d = cs->store->driver->opendir(cs->store, dirkey, &err);
    if (d == NULL) {
        return (err == ENOENT) ? NGX_OK : NGX_ERROR;
    }

    while (cs->store->driver->readdir(d, &de) == NGX_OK) {
        char childkey[PATH_MAX];

        if (cstore_scan_skip(de.name)) {
            continue;
        }
        if (cstore_scan_child_key(dirkey, dklen, de.name, childkey,
                                  sizeof(childkey)) != 0)
        {
            continue;
        }
        rc = cstore_scan_child(cs, childkey, visit, ctx);
        if (rc != NGX_OK) {
            break;                              /* visitor / subdir stopped early */
        }
    }

    cs->store->driver->closedir(d);
    return rc;
}

ngx_int_t
brix_cstore_scan(brix_cstore_t *cs, brix_cstore_visit_fn visit, void *ctx)
{
    if (cs == NULL || cs->store == NULL || visit == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    if (cs->store->driver->opendir == NULL || cs->store->driver->readdir == NULL
        || cs->store->driver->closedir == NULL)
    {
        errno = ENOSYS;                         /* store lacks DIRS - needs dev */
        return NGX_DECLINED;
    }
    return cstore_scan_dir(cs, "/", visit, ctx);
}

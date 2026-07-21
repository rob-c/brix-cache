/*
 * sd_ceph_dir.c — Ceph/RADOS driver: directory iteration over the flat key
 * namespace (phase-89 §B.1, stripe-collapse listing).
 *
 * WHAT: The opendir/readdir/closedir vtable slots. RADOS has no directory
 *       tree, so opendir synthesizes one level of a hierarchical listing from
 *       the pool's object catalog: it drives sd_ceph_enumerate (which already
 *       collapses libradosstriper stripes to one entry per logical file and
 *       recovers export-relative logical paths), keeps only the entries under
 *       the requested directory, and collapses each to its first path
 *       component — a component with a '/' remainder becomes a synthetic
 *       subdirectory entry, emitted once. The collapsed set is stored sorted
 *       and deduplicated in the dir handle; readdir walks the snapshot.
 *
 * WHY:  Gives kXR_dirlist / WebDAV PROPFIND depth-1 / the cache eviction scan
 *       a real listing on a rados export with zero protocol-layer changes —
 *       they all ride the VFS dir seam, which dispatches on these slots.
 *       Directories are SYNTHETIC (phase-89 ADR-1: no marker objects): a
 *       directory exists iff at least one object lives under its prefix, so
 *       opendir of an empty non-root prefix reports ENOENT, exactly the S3
 *       model.
 *
 * HOW:  One bounded enumerate pass per opendir. The snapshot is capped
 *       (SD_CEPH_DIR_MAX_ENTRIES) and the enumeration aborts with E2BIG when
 *       the cap is hit — a truncated-but-"complete" listing is never returned
 *       (fail-closed, no silent caps). Entry names live in one malloc'd set
 *       freed by closedir (a listing is transient; the instance pool must not
 *       grow per opendir). The classification helper (sd_ceph_path_child) is
 *       pure and unit-tested standalone in sd_ceph_unittest.c.
 */
#include "sd_ceph.h"
#include "sd_ceph_compat.h"   /* sd_ceph_path_child (pure, unit-tested) */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "sd_ceph_internal.h"

#if BRIX_HAVE_CEPH

#include <rados/librados.h>

/* Ceiling on one directory snapshot. Exceeding it fails the opendir (E2BIG)
 * rather than returning a silently truncated listing. */
#define SD_CEPH_DIR_MAX_ENTRIES 65536

/* Driver-private dir state: the sorted, deduplicated one-level snapshot. */
typedef struct {
    char       **names;      /* malloc'd array of malloc'd entry names */
    ngx_uint_t   count;
    ngx_uint_t   cap;
    ngx_uint_t   pos;
} sd_ceph_dir_state_t;

/* Collect context threaded through the enumerate callback. */
typedef struct {
    const char          *dir;      /* normalized listing directory */
    sd_ceph_dir_state_t *ds;
    int                  err;      /* E2BIG / ENOMEM when the pass aborted */
} sd_ceph_dir_collect_t;

static void
sd_ceph_dir_state_free(sd_ceph_dir_state_t *ds)
{
    ngx_uint_t i;

    if (ds->names != NULL) {
        for (i = 0; i < ds->count; i++) {
            free(ds->names[i]);
        }
        free(ds->names);
        ds->names = NULL;
    }
    ds->count = 0;
}

/* sd_ceph_dir_insert — insert `name` into the sorted snapshot, dropping
 * duplicates (the same first component recurs once per object under it).
 * Returns 0 on success/duplicate, or an errno (E2BIG at the snapshot ceiling,
 * ENOMEM on allocation failure). */
static int
sd_ceph_dir_insert(sd_ceph_dir_state_t *ds, const char *name)
{
    ngx_uint_t  lo = 0, hi = ds->count;
    size_t      n;
    char       *dup;

    while (lo < hi) {
        ngx_uint_t mid = lo + (hi - lo) / 2;
        int        cmp = strcmp(name, ds->names[mid]);

        if (cmp == 0) {
            return 0;                          /* duplicate — already listed */
        }
        if (cmp < 0) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }

    if (ds->count >= SD_CEPH_DIR_MAX_ENTRIES) {
        return E2BIG;
    }
    if (ds->count == ds->cap) {
        ngx_uint_t  ncap = (ds->cap == 0) ? 64 : ds->cap * 2;
        char      **nn = realloc(ds->names, ncap * sizeof(char *));

        if (nn == NULL) {
            return ENOMEM;
        }
        ds->names = nn;
        ds->cap   = ncap;
    }

    n = strlen(name) + 1;
    dup = malloc(n);
    if (dup == NULL) {
        return ENOMEM;
    }
    memcpy(dup, name, n);

    memmove(ds->names + lo + 1, ds->names + lo,
            (ds->count - lo) * sizeof(char *));
    ds->names[lo] = dup;
    ds->count++;
    return 0;
}

/* sd_ceph_dir_collect — per-object enumerate callback: keep one-level children
 * of the listing directory. Orphans (path == NULL: keys outside the export's
 * key prefix) are not listable and never leak into a listing. Returns non-zero
 * only to abort the pass on a hard bound (recorded in ctx->err). */
static int
sd_ceph_dir_collect(void *ctx, const brix_sd_catalog_ent_t *ent)
{
    sd_ceph_dir_collect_t *c = ctx;
    char                   name[sizeof(((brix_sd_dirent_t *) 0)->name)];
    int                    rc;

    if (ent->path == NULL) {
        return 0;
    }
    if (sd_ceph_path_child(c->dir, ent->path, name, sizeof(name)) == 0) {
        return 0;                              /* not under this directory */
    }
    rc = sd_ceph_dir_insert(c->ds, name);
    if (rc != 0) {
        c->err = rc;
        return 1;                              /* abort — fail the opendir */
    }
    return 0;
}

brix_sd_dir_t *
sd_ceph_opendir(brix_sd_instance_t *inst, const char *path, int *err_out)
{
    char                   norm[1024];
    sd_ceph_dir_state_t    snap;
    sd_ceph_dir_collect_t  c;
    brix_sd_dir_t         *dir;
    sd_ceph_dir_state_t   *ds;

    if (sd_ceph_normalize(path, norm, sizeof(norm)) != 0) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }

    ngx_memzero(&snap, sizeof(snap));
    c.dir = norm;
    c.ds  = &snap;
    c.err = 0;

    if (sd_ceph_enumerate(inst, 0, sd_ceph_dir_collect, &c) != NGX_OK) {
        if (err_out != NULL) { *err_out = errno; }
        sd_ceph_dir_state_free(&snap);
        return NULL;
    }
    if (c.err != 0) {
        if (err_out != NULL) { *err_out = c.err; }
        errno = c.err;
        sd_ceph_dir_state_free(&snap);
        return NULL;
    }

    /* Synthetic directories exist only while non-empty (ADR-1); the export
     * root always exists. */
    if (snap.count == 0 && !(norm[0] == '/' && norm[1] == '\0')) {
        if (err_out != NULL) { *err_out = ENOENT; }
        errno = ENOENT;
        sd_ceph_dir_state_free(&snap);
        return NULL;
    }

    dir = ngx_pcalloc(inst->pool, sizeof(*dir));
    ds  = ngx_pcalloc(inst->pool, sizeof(*ds));
    if (dir == NULL || ds == NULL) {
        if (err_out != NULL) { *err_out = ENOMEM; }
        errno = ENOMEM;
        sd_ceph_dir_state_free(&snap);
        return NULL;
    }

    *ds = snap;                                /* snapshot ownership → handle */
    dir->inst  = inst;
    dir->state = ds;
    return dir;
}

ngx_int_t
sd_ceph_readdir(brix_sd_dir_t *d, brix_sd_dirent_t *out)
{
    sd_ceph_dir_state_t *ds = d->state;
    size_t               n;

    if (ds == NULL || ds->pos >= ds->count) {
        return NGX_DONE;
    }
    n = strlen(ds->names[ds->pos]) + 1;        /* insert bounded to name[256] */
    memcpy(out->name, ds->names[ds->pos], n);
    ds->pos++;
    return NGX_OK;
}

ngx_int_t
sd_ceph_closedir(brix_sd_dir_t *d)
{
    sd_ceph_dir_state_t *ds = d->state;

    if (ds != NULL) {
        sd_ceph_dir_state_free(ds);
    }
    return NGX_OK;
}

#endif /* BRIX_HAVE_CEPH */

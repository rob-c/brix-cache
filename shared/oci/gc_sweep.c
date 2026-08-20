/* gc_sweep.c — the registry GC sweep phase (see gc.h): the CAS, judged
 * against the COMPLETE live set the mark phase built. Nothing in here may
 * run before that walk has finished — a blob judged against a partial live
 * set is a blob deleted because the pass had not yet read the manifest that
 * names it.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "oci/gc_internal.h"

#include "oci/digest.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>


/* One two-character CAS fan-out directory. */
static void
gc_blob_fanout(brix_oci_gc_t *c, const char *dir)
{
    char           path[PATH_MAX];
    DIR           *d = opendir(dir);
    struct dirent *e;
    off_t          size;

    if (d == NULL) {
        return;
    }
    while ((e = readdir(d)) != NULL) {
        if (!brix_oci_gc_is_hex(e->d_name)
            || brix_oci_gc_fmt(path, sizeof(path), "%s/%s", dir,
                              e->d_name) != 0)
        {
            continue;
        }
        if (brix_oci_gc_set_has(&c->live, e->d_name)) {
            c->st.blobs_live++;
        } else if (!brix_oci_gc_reapable(c, path, &size)) {
            c->st.blobs_young++;            /* a push may still name it */
        } else {
            brix_oci_gc_reap(c, path, size, &c->st.blobs_swept);
        }
    }
    closedir(d);
}


/* One algorithm's whole CAS tree: its two-character fan-out directories.
 * A tree that does not exist is a tree the store never wrote a blob into —
 * not an error, and nothing to sweep. */
static int
gc_sweep_blobs_alg(brix_oci_gc_t *c, const char *alg)
{
    char           dir[PATH_MAX], sub[PATH_MAX];
    DIR           *d;
    struct dirent *e;

    if (brix_oci_gc_fmt(dir, sizeof(dir), "%s/blobs/%s", c->root, alg) != 0) {
        snprintf(c->err, sizeof(c->err), "store path too long");
        return -1;
    }
    d = opendir(dir);
    if (d == NULL) {
        if (errno == ENOENT) {
            return 0;
        }
        snprintf(c->err, sizeof(c->err), "%.400s: %s", dir,
                 strerror(errno));
        return -1;
    }
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] != '.'
            && brix_oci_gc_fmt(sub, sizeof(sub), "%s/%s", dir,
                              e->d_name) == 0
            && brix_oci_gc_isdir(sub))
        {
            gc_blob_fanout(c, sub);
        }
    }
    closedir(d);
    return 0;
}


int
brix_oci_gc_sweep_blobs(brix_oci_gc_t *c)
{
    int a, rc = 0;

    for (a = 0; rc == 0 && a < BRIX_OCI_ALG_COUNT; a++) {
        rc = gc_sweep_blobs_alg(c, brix_oci_alg_name((brix_oci_alg_t) a));
    }
    return rc;
}

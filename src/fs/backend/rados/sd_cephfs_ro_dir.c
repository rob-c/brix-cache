/*
 * sd_cephfs_ro_dir.c — directory iteration for the read-only CephFS-via-RADOS
 * driver ("cephfsro").
 *
 * WHAT: The opendir/readdir/closedir vtable ops split out of sd_cephfs_ro.c.
 *       Directory listing enumerates every leaf-fragment omap of the directory
 *       inode, paging the dentry keys and recovering each entry name by stripping
 *       the trailing "_<snapid>" suffix.
 *
 * WHY:  Keeps the omap-paging state machine (fragment cursor + buffered page) in
 *       its own auditable unit; it shares only the driver state and the
 *       resolve/retry helpers (via sd_cephfs_ro_internal.h) with the rest of the
 *       driver. See sd_cephfs_ro.c for the driver-level narrative.
 *
 * The whole driver compiles only when the build found librados (BRIX_HAVE_CEPH);
 * otherwise this is an empty translation unit.
 */
#include "sd_ceph.h"

#if BRIX_HAVE_CEPH

#include "cephfs_layout.h"
#include "sd_cephfs_ro_internal.h"

#include <rados/librados.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define CEPHFS_READDIR_PAGE   256             /* omap keys fetched per round       */

/* per-opendir: the directory inode + its leaf fragments, plus an omap-paging
 * cursor and one buffered page of entry names. */
typedef struct {
    uint64_t  ino;
    uint32_t  frags[CEPHFS_MAX_FRAGS];
    uint32_t  nfrags;
    uint32_t  fi;                                   /* current fragment index   */
    char      last_key[256];                        /* omap pagination cursor   */
    int       more_in_frag;                         /* current frag has more    */
    char      names[CEPHFS_READDIR_PAGE][256];      /* buffered page            */
    uint32_t  npage;
    uint32_t  pi;                                   /* next page slot to return */
} cephfsro_dir_t;

/* ---- directory iteration -------------------------------------------------- */

static int cephfsro_dir_fetch_page(cephfsro_state_t *st, cephfsro_dir_t *ds);

brix_sd_dir_t *
cephfsro_opendir(brix_sd_instance_t *inst, const char *path, int *err_out)
{
    cephfsro_state_t *st = inst->state;
    cephfs_dentry_t   dn;
    brix_sd_dir_t  *d;
    cephfsro_dir_t   *ds;
    int               rc = cephfsro_resolve_retry(st, path, &dn);

    if (rc != 0) {
        if (err_out != NULL) { *err_out = (rc == 1) ? ENOENT : errno; }
        return NULL;
    }
    if (dn.kind != CEPHFS_DENTRY_PRIMARY || !cephfs_mode_is_dir(dn.inode.mode)) {
        if (err_out != NULL) { *err_out = ENOTDIR; }
        return NULL;
    }

    d  = ngx_pcalloc(inst->pool, sizeof(*d));
    ds = ngx_pcalloc(inst->pool, sizeof(*ds));
    if (d == NULL || ds == NULL) {
        if (err_out != NULL) { *err_out = ENOMEM; }
        return NULL;
    }
    ds->ino    = dn.inode.ino;
    ds->nfrags = (dn.nfrags < CEPHFS_MAX_FRAGS) ? dn.nfrags : CEPHFS_MAX_FRAGS;
    if (ds->nfrags == 0) { ds->nfrags = 1; ds->frags[0] = 0; }
    else { memcpy(ds->frags, dn.frag_enc, ds->nfrags * sizeof(uint32_t)); }

    /* prime the first fragment's page so readdir starts serving immediately */
    if (cephfsro_dir_fetch_page(st, ds) != 0) {
        if (err_out != NULL) { *err_out = errno; }
        return NULL;
    }

    d->inst  = inst;
    d->state = ds;
    return d;
}

/* Strip the trailing "_<snapid>" (e.g. "_head") from a dir omap key to recover
 * the dentry name. Copies up to the last '_' into out. Returns 0, or -1 if the
 * key has no '_' (not a dentry key — caller should skip it). */
static int
cephfsro_key_to_name(const char *key, char *out, size_t cap)
{
    const char *us = strrchr(key, '_');
    size_t      n;

    if (us == NULL) { return -1; }
    n = (size_t) (us - key);
    if (n == 0 || n + 1 > cap) { return -1; }
    memcpy(out, key, n);
    out[n] = '\0';
    return 0;
}

/* Fetch the next page of dentry names for the directory's current fragment into
 * ds->names[], advancing the omap cursor. Returns 0 on success (npage set, may be
 * 0), -1/errno on a RADOS error. */
static int
cephfsro_dir_fetch_page(cephfsro_state_t *st, cephfsro_dir_t *ds)
{
    rados_ioctx_t      meta = sd_ceph_conn_ioctx(st->meta);
    char               oid[64];
    rados_omap_iter_t  it = NULL;
    rados_read_op_t    op;
    int                prval = 0, rc;
    unsigned char      pmore = 0;
    char              *k = NULL, *v = NULL;
    size_t             vlen = 0;

    ds->npage = 0;
    ds->pi    = 0;

    snprintf(oid, sizeof(oid), "%llx.%08llx",
             (unsigned long long) ds->ino,
             (unsigned long long) ds->frags[ds->fi]);

    {
        int attempt;
        for (attempt = 0; ; attempt++) {
            op = rados_create_read_op();
            rados_read_op_omap_get_vals2(op, ds->last_key[0] ? ds->last_key : "",
                                         "", CEPHFS_READDIR_PAGE, &it, &pmore,
                                         &prval);
            rc = rados_read_op_operate(op, meta, oid, 0);
            if (rc >= 0) { break; }
            rados_release_read_op(op);
            if (-rc == ENOENT) { ds->more_in_frag = 0; return 0; } /* no such frag */
            if (cephfsro_is_transient(-rc) && attempt < st->max_retry) {
                cephfsro_backoff(attempt);
                continue;
            }
            errno = -rc;
            return -1;
        }
    }
    while (it != NULL && rados_omap_get_next(it, &k, &v, &vlen) == 0 && k != NULL) {
        char name[256];
        (void) v; (void) vlen;
        if (ds->npage < CEPHFS_READDIR_PAGE
            && cephfsro_key_to_name(k, name, sizeof(name)) == 0)
        {
            ngx_memcpy(ds->names[ds->npage], name, strlen(name) + 1);
            ds->npage++;
        }
        ngx_memcpy(ds->last_key, k, strlen(k) + 1);   /* cursor = last key seen */
    }
    if (it != NULL) { rados_omap_get_end(it); }
    rados_release_read_op(op);
    ds->more_in_frag = (pmore != 0);
    return 0;
}

ngx_int_t
cephfsro_readdir(brix_sd_dir_t *d, brix_sd_dirent_t *out)
{
    cephfsro_state_t *st = d->inst->state;
    cephfsro_dir_t   *ds = d->state;

    for (;;) {
        if (ds->pi < ds->npage) {
            ngx_memcpy(out->name, ds->names[ds->pi], strlen(ds->names[ds->pi]) + 1);
            ds->pi++;
            return NGX_OK;
        }
        /* current page exhausted: more in this frag? */
        if (ds->more_in_frag) {
            if (cephfsro_dir_fetch_page(st, ds) != 0) { return NGX_ERROR; }
            continue;
        }
        /* advance to the next fragment */
        ds->fi++;
        if (ds->fi >= ds->nfrags) { return NGX_DONE; }   /* end of directory */
        ds->last_key[0] = '\0';
        ds->more_in_frag = 1;                            /* force a first fetch */
        if (cephfsro_dir_fetch_page(st, ds) != 0) { return NGX_ERROR; }
    }
}

ngx_int_t
cephfsro_closedir(brix_sd_dir_t *d)
{
    (void) d;          /* dir + state are on the instance pool */
    return NGX_OK;
}

#endif /* BRIX_HAVE_CEPH */

/* sd_remote_dir.c — S3 ListObjectsV2 directory listing for the remote backend.
 *
 * WHAT: opendir/readdir/closedir over the object catalog as a POSIX-shaped
 *       single directory level: <Contents> under the prefix are files,
 *       <CommonPrefixes> are sub-directories (phase-92 finding #4).
 *
 * WHY:  Split out of sd_remote.c, which crossed the 600-line cap
 *       (coding-standards §1). Paged listing carries its own state machine and
 *       page buffer, independent of the object read/write slots.
 *
 * HOW:  opendir derives the S3 key prefix with no I/O; readdir pages
 *       ListObjectsV2 lazily through the shared sd_s3_list_page, buffering one
 *       decoded page at a time; closedir frees the malloc-owned handle (this
 *       driver runs off the event loop, so there is no pool to hang it on). */


#include "sd_remote.h"
#include "sd_remote_internal.h"
#include "fs/backend/s3/sd_s3.h"

#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>


/* ---- directory listing (S3 ListObjectsV2, delimited + paged) --------------
 *
 * WHAT: opendir/readdir/closedir over the object catalog as a POSIX-shaped
 *       single directory level — <Contents> under the prefix are files,
 *       <CommonPrefixes> are sub-directories (finding #4).
 * WHY:  S3 has no readdir; a WebDAV PROPFIND / xrdfs ls / recursive walk over an
 *       s3:// export previously hit the NULL opendir slot and reported ENOTSUP.
 * HOW:  opendir derives the S3 key prefix from the export-relative path (no I/O)
 *       and readdir pages ListObjectsV2 lazily via the shared sd_s3_list_page,
 *       buffering one page of decoded basenames at a time; closedir frees the
 *       malloc-owned handle (this driver runs off the event loop with no pool).
 *       Object stores expose no per-object owner/mode, so d_type is DT_DIR for a
 *       CommonPrefixes entry and DT_REG otherwise — the VFS stats on anything it
 *       cannot classify, so a coarse d_type is a cheap hint, never authority. */
typedef struct {
    char           name[256];
    unsigned char  d_type;
} sd_remote_dirent;

typedef struct {
    brix_sd_instance_t *inst;
    char                prefix[768];   /* S3 key prefix, "" or "dir/" */
    char                cont[2048];    /* NextContinuationToken for the next page */
    int                 started;       /* fetched at least one page */
    int                 truncated;     /* more pages remain */
    sd_remote_dirent   *ents;          /* current page, grown on demand */
    size_t              n;
    size_t              cap;
    size_t              cursor;
} sd_remote_dir_state;

/* sd_s3_list_page callback: append one decoded entry to the page buffer. A
 * realloc failure stops the page (returns 1) and surfaces as a short page. */
static int
sd_remote_dir_add(void *ud, const char *name, int is_dir)
{
    sd_remote_dir_state *ds = ud;

    if (ds->n == ds->cap) {
        size_t nc = (ds->cap != 0) ? ds->cap * 2 : 64;
        void  *nb = realloc(ds->ents, nc * sizeof(*ds->ents));

        if (nb == NULL) {
            return 1;
        }
        ds->ents = nb;
        ds->cap  = nc;
    }
    snprintf(ds->ents[ds->n].name, sizeof(ds->ents[ds->n].name), "%s", name);
    ds->ents[ds->n].d_type = (unsigned char) (is_dir ? DT_DIR : DT_REG);
    ds->n++;
    return 0;
}

/* Fetch the next ListObjectsV2 page into the (reset) buffer. 0 / -1 (errno). */
static int
sd_remote_dir_fetch(sd_remote_dir_state *ds)
{
    const brix_sd_remote_cfg_t *cfg = ds->inst->state;
    sd_s3_open_params           p;
    char                        root[300];
    char                        cont_out[2048];
    char                        errbuf[256];
    int                         truncated = 0;

    snprintf(root, sizeof(root), "/%s/", cfg->bucket);  /* bucket-root canon URI */
    sd_remote_s3_params(cfg, root, &p);

    ds->n      = 0;
    ds->cursor = 0;
    errno      = 0;
    if (sd_s3_list_page(&p, ds->prefix, ds->started ? ds->cont : "",
            sd_remote_dir_add, ds, &truncated, cont_out, sizeof(cont_out),
            errbuf, sizeof(errbuf)) != 0)
    {
        if (errno == 0) { errno = EIO; }
        return -1;
    }
    ds->truncated = truncated;
    snprintf(ds->cont, sizeof(ds->cont), "%s", cont_out);
    ds->started = 1;
    return 0;
}

brix_sd_dir_t *
sd_remote_opendir(brix_sd_instance_t *inst, const char *path, int *err_out)
{
    sd_remote_dir_state *ds;
    brix_sd_dir_t       *dir;
    const char          *rel = (path != NULL) ? path : "/";
    size_t               n;

    ds  = calloc(1, sizeof(*ds));
    dir = calloc(1, sizeof(*dir));
    if (ds == NULL || dir == NULL) {
        free(ds);
        free(dir);
        if (err_out != NULL) { *err_out = ENOMEM; }
        return NULL;
    }
    ds->inst = inst;

    /* export-relative path -> S3 key prefix: drop the leading '/', ensure a
     * trailing '/' so LIST returns children of THIS level (root -> ""). */
    while (*rel == '/') { rel++; }
    n = strlen(rel);
    if (n + 1 >= sizeof(ds->prefix)) {
        free(ds);
        free(dir);
        if (err_out != NULL) { *err_out = ENAMETOOLONG; }
        return NULL;
    }
    memcpy(ds->prefix, rel, n);
    if (n > 0 && ds->prefix[n - 1] != '/') { ds->prefix[n++] = '/'; }
    ds->prefix[n] = '\0';

    dir->inst  = inst;
    dir->state = ds;
    return dir;
}

ngx_int_t
sd_remote_readdir(brix_sd_dir_t *d, brix_sd_dirent_t *out)
{
    sd_remote_dir_state *ds = d->state;

    for ( ;; ) {
        if (ds->cursor < ds->n) {
            snprintf(out->name, sizeof(out->name), "%s",
                     ds->ents[ds->cursor].name);
            out->d_type = ds->ents[ds->cursor].d_type;
            ds->cursor++;
            return NGX_OK;
        }
        if (ds->started && !ds->truncated) {
            return NGX_DONE;
        }
        if (sd_remote_dir_fetch(ds) != 0) {
            return NGX_ERROR;
        }
    }
}

ngx_int_t
sd_remote_closedir(brix_sd_dir_t *d)
{
    sd_remote_dir_state *ds;

    if (d == NULL || d->state == NULL) {
        return NGX_OK;
    }
    ds = d->state;
    free(ds->ents);
    free(ds);
    d->state = NULL;
    free(d);           /* malloc-owned shell (no pool off the event loop) */
    return NGX_OK;
}

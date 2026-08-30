/*
 * sd_remote_enum.c — the backend-catalog verb (driver->enumerate) for s3://.
 *
 * WHAT: sd_remote_enumerate() reports every object the bucket holds, once each,
 *       with its size and mtime, to the shared brix_sd_catalog_cb.
 * WHY:  inventory, drift detection and the background scrub ask a driver what it
 *       STORES, which is not the same question as what a directory contains. An
 *       object store has no namespace to walk: before this slot, an S3 export
 *       fell back to brix_vfs_walk recursing through opendir/readdir, i.e. one
 *       signed delimited LIST per pseudo-directory, and every entry it found
 *       then cost a HEAD to stat. The flat listing answers with 1000 keys per
 *       request AND carries size/mtime in the same response, so a stat-bearing
 *       enumeration of a bucket costs ceil(n/1000) requests instead of O(n).
 * HOW:  page sd_s3_list_flat_page from the bucket root, translating each key
 *       into a catalog entry: `key` is the S3 key as stored, `path` is the
 *       export-relative logical path (a leading '/' + the key), and the entry is
 *       skipped when it is namespace scaffolding rather than a stored object.
 *       Blocking, transport-injected, malloc-only — safe on the fill thread,
 *       never on the event loop.
 */

#include "sd_remote_internal.h"
#include "fs/backend/s3/sd_s3.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

/* The logical path buffer: one leading '/' plus an S3 key. S3 caps a key at
 * 1024 bytes, so this holds any key the store can legally have returned. */
#define SD_REMOTE_ENUM_PATH_MAX 1100

typedef struct {
    brix_sd_catalog_cb  cb;
    void               *ctx;
    int                 want_stat;
    int                 stopped;    /* the callback asked to stop */
} sd_remote_enum_ctx;

/* sd_s3_list_flat_page callback: translate one listed key into a catalog entry.
 *
 * A key ending in '/' is a DIRECTORY-MARKER object — the zero-byte object this
 * driver's mkdir writes to give S3 a namespace it does not natively have. It is
 * scaffolding, not stored content: reporting it would have an inventory count a
 * directory as a file and a drift check treat every folder as an orphan. This
 * mirrors sd_ceph_enumerate skipping striper data stripes.
 *
 * Returns non-zero to stop the enumeration, which is how the caller's own stop
 * signal propagates back through the pager. */
static int
sd_remote_enum_entry(void *ud, const char *key, uint64_t size, time_t mtime)
{
    sd_remote_enum_ctx    *e = ud;
    brix_sd_catalog_ent_t  ent;
    char                   path[SD_REMOTE_ENUM_PATH_MAX];
    size_t                 klen = strlen(key);

    if (klen == 0 || key[klen - 1] == '/') {
        return 0;                      /* directory marker — not a stored object */
    }

    ngx_memzero(&ent, sizeof(ent));
    ent.key = key;
    /* The bucket root IS the export root here (sd_remote_s3_key composes
     * "/bucket" + the export-relative path), so the logical path is the key with
     * the leading '/' restored. A key too long to represent is reported with
     * path=NULL — an orphan candidate — rather than dropped: it exists, and an
     * inventory that silently omitted it would under-report the store. */
    if (klen + 2 <= sizeof(path)) {
        path[0] = '/';
        memcpy(path + 1, key, klen + 1);
        ent.path = path;
    }
    if (e->want_stat && mtime != 0) {
        ent.have_stat = 1;
        ent.size  = (off_t) size;
        ent.mtime = mtime;
    }
    if (e->cb(e->ctx, &ent) != 0) {
        e->stopped = 1;
        return 1;
    }
    return 0;
}

/* driver->enumerate — see the file header. NGX_OK when the enumeration ran (the
 * callback may have aborted it early, which is not an error), or NGX_ERROR with
 * errno set when a page could not be listed. */
ngx_int_t
sd_remote_enumerate(brix_sd_instance_t *inst, int want_stat,
    brix_sd_catalog_cb cb, void *ctx)
{
    const brix_sd_remote_cfg_t *cfg;
    sd_remote_enum_ctx          e;
    sd_s3_open_params           p;
    char                        root[300];
    char                        cont[2048];
    char                        cont_out[2048];
    char                        errbuf[256];
    int                         started = 0;
    int                         truncated = 0;

    if (inst == NULL || inst->state == NULL || cb == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    cfg = inst->state;

    e.cb        = cb;
    e.ctx       = ctx;
    e.want_stat = want_stat;
    e.stopped   = 0;
    cont[0]     = '\0';

    snprintf(root, sizeof(root), "/%s/", cfg->bucket);  /* bucket-root canon URI */
    sd_remote_s3_params(cfg, root, &p);

    /* Signed as the EXPORT, deliberately: this is not a request path. The
     * catalog verb answers the inventory/scrub engine about what the export
     * holds — there is no requesting user to scope it to, and a per-user view
     * would make an inventory report a subset of the store as the whole of it.
     * The credential-scoped listing a user's request DOES get is opendir_cred. */
    do {
        errno = 0;
        if (sd_s3_list_flat_page(&p, "", started ? cont : "",
                sd_remote_enum_entry, &e, &truncated, cont_out,
                sizeof(cont_out), errbuf, sizeof(errbuf)) != 0)
        {
            if (errno == 0) { errno = EIO; }
            return NGX_ERROR;
        }
        started = 1;
        snprintf(cont, sizeof(cont), "%s", cont_out);
        /* A truncated page with no continuation token would loop forever on the
         * same page: stop instead. S3 never does this, but the token is the only
         * thing advancing the cursor and a proxy that drops it must not wedge a
         * scrub thread. */
        if (truncated && cont[0] == '\0') {
            break;
        }
    } while (truncated && !e.stopped);

    return NGX_OK;
}

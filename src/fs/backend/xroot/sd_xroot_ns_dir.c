/*
 * sd_xroot_ns_dir.c — root:// origin directory listing (kXR_dirlist).
 *
 * The opendir/readdir/closedir vtable slots for the root:// driver, split out of
 * sd_xroot_ns.c so the namespace + metadata path stays focused.  Fetch-all-then-
 * iterate: opendir issues ONE kXR_dirlist against a fresh origin session, buffers
 * every name, and closes the session immediately; readdir yields buffered names;
 * closedir frees the buffer.  Wired into the driver struct in sd_xroot.c via
 * sd_xroot_internal.h; the shared session helper lives in sd_xroot_ns.c.
 */

#include "sd_xroot_internal.h"
#include "auth/crypto/pki_build.h"       /* brix_build_ca_store (GSI origin verify) */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

/* ---- directory listing (kXR_dirlist, fetch-all-then-iterate) --------------
 *
 * WHAT: opendir issues ONE kXR_dirlist against the origin, buffers every
 *       name into a brix_cache_dirlist_t held as the brix_sd_dir_t's driver-
 *       private state, then closes the origin session immediately (mirrors
 *       every other ns op in this file — no op here holds a live origin
 *       connection across separate VFS calls). readdir yields one buffered
 *       name per call; closedir frees the buffer.
 * WHY:  brix_sd_dir_t iteration (opendir/readdir/closedir) is 3 separate VFS
 *       calls with no guarantee they run back-to-back on the same thread, so
 *       a streamed/session-held approach would need to keep an origin TCP
 *       connection open across arbitrary VFS-call gaps — fragile and unlike
 *       every other sd_xroot op. Fetch-all-then-iterate trades a larger
 *       up-front read for a stateless, connection-free readdir/closedir.
 * HOW:  opendir_common does the session + dirlist fetch + dir handle alloc;
 *       opendir/opendir_cred differ only in which credential (NULL vs the
 *       caller's) sd_xroot_session presents at the origin. readdir walks the
 *       buffered brix_cache_dirlist_t by index; closedir frees it.
 */

/* Driver-private dir state: the fetched name buffer plus a read cursor. */
typedef struct {
    brix_cache_dirlist_t dl;      /* heap-owned name array (see cache_internal.h) */
    size_t                 next;    /* index of the next name readdir will yield */
} sd_xroot_dir_state;

/* sd_xroot_opendir_common — shared body for opendir/opendir_cred: open a
 * session under `cred` (NULL ⇒ service credential), fetch the whole listing,
 * close the session, and wrap the result in a brix_sd_dir_t. Returns the dir
 * handle, or NULL with *err_out set. */
static brix_sd_dir_t *
sd_xroot_opendir_common(brix_sd_instance_t *inst, const char *path,
    const brix_sd_cred_t *cred, int *err_out)
{
    sd_xroot_inst_state        *is = inst->state;
    brix_cache_origin_conn_t  oc;
    brix_cache_fill_t        *t;
    sd_xroot_dir_state        *ds;
    brix_sd_dir_t             *dir;
    int                         e = 0;

    if (sd_xroot_session(is->conf, cred, &oc, &t, &e) != 0) {
        if (err_out) { *err_out = e; }
        return NULL;
    }

    ds = calloc(1, sizeof(*ds));
    if (ds == NULL) {
        brix_cache_origin_close(&oc);
        free(t);
        if (err_out) { *err_out = ENOMEM; }
        return NULL;
    }
    brix_cache_dirlist_init(&ds->dl);

    if (brix_cache_origin_dirlist(t, &oc, path, &ds->dl) != 0) {
        e = sd_xroot_errno(t);
        brix_cache_dirlist_free(&ds->dl);
        free(ds);
        brix_cache_origin_close(&oc);
        free(t);
        if (err_out) { *err_out = e; }
        return NULL;
    }

    /* The listing is fully buffered — the origin session is no longer
     * needed for readdir/closedir (fetch-all-then-iterate, see above). */
    brix_cache_origin_close(&oc);
    free(t);

    dir = calloc(1, sizeof(*dir));
    if (dir == NULL) {
        brix_cache_dirlist_free(&ds->dl);
        free(ds);
        if (err_out) { *err_out = ENOMEM; }
        return NULL;
    }
    dir->inst  = inst;
    dir->state = ds;
    return dir;
}

/* opendir — vtable opendir slot: service credential / anonymous. */
brix_sd_dir_t *
sd_xroot_opendir(brix_sd_instance_t *inst, const char *path, int *err_out)
{
    return sd_xroot_opendir_common(inst, path, NULL, err_out);
}

/* opendir_cred — vtable opendir_cred slot: per-user credential, so a remote
 * dirlist authenticates to the origin as the requesting user. */
brix_sd_dir_t *
sd_xroot_opendir_cred(brix_sd_instance_t *inst, const char *path,
    int *err_out, const brix_sd_cred_t *cred)
{
    return sd_xroot_opendir_common(inst, path, cred, err_out);
}

/* readdir — vtable readdir slot: yield the next buffered name, bound-copied
 * into out->name (255 chars + NUL — brix_sd_dirent_t's fixed field). Returns
 * NGX_OK (out filled), NGX_DONE (end of the buffered listing — matches the
 * POSIX driver's readdir contract that brix_vfs_readdir relies on), or
 * NGX_ERROR (malformed state; errno set). */
ngx_int_t
sd_xroot_readdir(brix_sd_dir_t *d, brix_sd_dirent_t *out)
{
    sd_xroot_dir_state *ds = d->state;

    if (ds == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    if (ds->next >= ds->dl.count) {
        return NGX_DONE;
    }
    ngx_cpystrn((u_char *) out->name, (u_char *) ds->dl.names[ds->next],
                sizeof(out->name));
    ds->next++;
    return NGX_OK;
}

/* closedir — vtable closedir slot: free the buffered name array, the dir
 * state, and the brix_sd_dir_t handle itself. No origin session to close
 * (opendir already released it). The VFS (brix_vfs_closedir, vfs_dir.c)
 * calls driver->closedir(dh->sd_dir) but never frees dh->sd_dir itself, so
 * — unlike sd_posix's pool-allocated dir handle, which the pool reclaims —
 * this heap-allocated handle (calloc'd in sd_xroot_opendir_common) MUST be
 * freed here or every dirlist leaks one brix_sd_dir_t. NULL-safe (both on
 * `d` and on `d->state`) so a double-close is harmless. */
ngx_int_t
sd_xroot_closedir(brix_sd_dir_t *d)
{
    sd_xroot_dir_state *ds;

    if (d == NULL) {
        return NGX_OK;
    }
    ds = d->state;
    if (ds != NULL) {
        brix_cache_dirlist_free(&ds->dl);
        free(ds);
        d->state = NULL;
    }
    free(d);
    return NGX_OK;
}

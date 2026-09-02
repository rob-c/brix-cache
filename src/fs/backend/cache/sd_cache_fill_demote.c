/*
 * sd_cache_fill_demote.c — the cold-tier demote copy (phase-85 F7).
 *
 * WHAT: Copies a HOT cached object's bytes into the cold store tier via the
 *       cold driver's staged spine, so the eviction engine can relieve
 *       space-pressure without losing the object outright.
 *
 * WHY:  Split from sd_cache_fill.c for the file-size cap. It reuses the fill
 *       spine's move-granule idiom (SD_CACHE_CHUNK) which is why it lives beside
 *       the fill, not in sd_cache.c — but it shares no per-attempt fill state,
 *       so it isolates cleanly.
 *
 * HOW:  open the hot object -> staged_open on the cold tier -> pread/staged_write
 *       loop -> staged_commit (never a torn cold object). Called by the eviction
 *       engine on space-pressure victims ONLY, just before the hot copy is
 *       removed; write invalidation never demotes.
 */
#include "sd_cache.h"
#include "sd_cache_internal.h"    /* sd_cache_inst_state + SD_CACHE_ST/SRC */
#include "sd_cache_fill_internal.h"     /* SD_CACHE_CHUNK move granule */

#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>


/*
 * WHAT: Copy one hot cache object into an already-open cold staged object.
 * WHY: Separate the streaming state machine from tier/resource acquisition.
 * HOW: Retry interrupted reads, write each chunk at its source offset, and
 *      commit only after a clean EOF; the caller retains cleanup ownership.
 */
static ngx_int_t
sd_cache_demote_copy(brix_sd_obj_t *source, brix_sd_staged_t *staged,
    u_char *buf)
{
    off_t off = 0;

    for ( ;; ) {
        ssize_t n = source->driver->pread(source, buf, SD_CACHE_CHUNK, off);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return NGX_ERROR;
        }
        if (n == 0) {
            return staged->inst->driver->staged_commit(staged, NULL);
        }
        if (staged->inst->driver->staged_write(staged, buf, (size_t) n,
                                                off) < 0)
        {
            return NGX_ERROR;
        }
        off += n;
    }
}


/* Demote the HOT cached object `key` into the cold store tier (phase-85 F7):
 * copy its bytes from the cache store into the cold store via the cold
 * driver's staged spine (write + commit — never a torn cold object). Called by
 * the eviction engine on space-pressure victims ONLY, just before the hot copy
 * is removed; write invalidation never demotes (a written-over object is stale
 * and must not survive in cold). Defined here (not sd_cache.c) to reuse the
 * fill spine's move-granule idiom. NGX_OK / NGX_DECLINED (no cold tier — not
 * an error) / NGX_ERROR with errno set (the caller evicts anyway: space relief
 * wins and the origin refill preserves correctness). */
/* Phase-107 C5: a demotion knows the exact final size up front (the hot copy
 * is complete) - declare it, so a remote cold tier can derive a legal
 * multipart part size instead of hitting the 10,000-part ceiling.  0 when the
 * hot object cannot answer (the cold tier then reserves nothing). */
static off_t
sd_cache_demote_declared_size(brix_sd_obj_t *so)
{
    brix_sd_stat_t  hst;

    if (so->driver->fstat != NULL && so->driver->fstat(so, &hst) == NGX_OK) {
        return hst.size;
    }
    return 0;
}

ngx_int_t
brix_sd_cache_demote(brix_sd_instance_t *inst, const char *key)
{
    sd_cache_inst_state  *st;
    brix_sd_instance_t   *hot, *cold;
    brix_sd_obj_t        *so;
    brix_sd_staged_t     *sg;
    u_char               *buf;
    ngx_int_t             rc;
    int                   err = 0;

    if (!brix_sd_cache_instance_is(inst) || key == NULL) {
        return NGX_DECLINED;
    }
    st   = SD_CACHE_ST(inst);
    cold = st->cold;
    if (cold == NULL) {
        return NGX_DECLINED;
    }
    hot = st->cstore.store;
    if (hot->driver->open == NULL || cold->driver->staged_open == NULL) {
        errno = ENOSYS;
        return NGX_ERROR;
    }
    so = hot->driver->open(hot, key, BRIX_SD_O_READ, 0, &err);
    if (so == NULL) {
        errno = err ? err : EIO;
        return NGX_ERROR;
    }
    if (so->driver->pread == NULL) {
        brix_sd_obj_release(so);
        errno = ENOSYS;
        return NGX_ERROR;
    }
    /* 0600 like the hot store object: the cold tier aggregates many users'
     * bytes under the svc identity too; client-facing perms live in the cinfo
     * the PROMOTE rebuilds, never on the physical cold object. */
    sg = cold->driver->staged_open(cold, key, S_IRUSR | S_IWUSR,
                                   sd_cache_demote_declared_size(so), &err);
    if (sg == NULL) {
        brix_sd_obj_release(so);
        errno = err ? err : EIO;
        return NGX_ERROR;
    }
    buf = malloc(SD_CACHE_CHUNK);
    if (buf == NULL) {
        sg->inst->driver->staged_abort(sg);
        brix_sd_obj_release(so);
        errno = ENOMEM;
        return NGX_ERROR;
    }
    rc = sd_cache_demote_copy(so, sg, buf);
    err = errno;
    free(buf);
    brix_sd_obj_release(so);
    if (rc == NGX_OK) {
        return NGX_OK;
    }
    /* Failed writes/commits keep the staged handle valid for explicit abort. */
    sg->inst->driver->staged_abort(sg);
    errno = err ? err : EIO;
    return NGX_ERROR;
}

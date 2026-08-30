/*
 * meta_advisory_sd.c — brix_sd_setattr_t → brix_meta_advisory_t.
 *
 * See meta_advisory_sd.h for the WHAT/WHY. The sentinel handling below is the
 * whole reason this lives in one place.
 */
#include "fs/backend/meta_advisory_sd.h"

#include <string.h>
#include <time.h>

/*
 * WHAT: Translate the present groups of *attr into *delta.
 * WHY:  See the header — the three sentinels (UTIME_OMIT, UTIME_NOW, and the
 *       (id)-1 "leave unchanged" pair) are the part that must not be re-derived
 *       per backend.
 * HOW:  atime is dropped: no object store tracks it, and the advisory blob has
 *       no field for it, so a request that carries ONLY an atime is reported as
 *       "nothing to persist" (return 0) rather than provoking a write that would
 *       store nothing.
 */
int
brix_meta_advisory_from_setattr(const brix_sd_setattr_t *attr,
    brix_meta_advisory_t *delta)
{
    if (attr == NULL || delta == NULL) {
        return 0;
    }
    memset(delta, 0, sizeof(*delta));

    if (attr->set_mode) {
        delta->have_mode = 1;
        delta->mode = attr->mode;
    }

    /* Owner: the advisory model carries uid AND gid together, so a lone (id)-1
     * ("leave this one unchanged") makes the change unrepresentable — persist
     * neither rather than inventing a value for the omitted half. */
    if (attr->set_owner && attr->uid != (uid_t) -1 && attr->gid != (gid_t) -1) {
        delta->have_owner = 1;
        delta->uid = attr->uid;
        delta->gid = attr->gid;
    }

    if (attr->set_times && attr->mtime.tv_nsec != UTIME_OMIT) {
        delta->have_mtime = 1;
        if (attr->mtime.tv_nsec == UTIME_NOW) {
            delta->mtime = time(NULL);
            delta->mtime_ns = 0;
        } else {
            delta->mtime = attr->mtime.tv_sec;
            delta->mtime_ns = attr->mtime.tv_nsec;
        }
    }

    return (delta->have_mode || delta->have_owner || delta->have_mtime) ? 1 : 0;
}

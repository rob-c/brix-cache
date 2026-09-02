/*
 * sd_ceph_batch.c - bulk namespace delete on raw RADOS (phase-107 C4).
 *
 * WHAT: sd_ceph_unlink_many_io (the ioctx-explicit core) and the plain
 *       sd_ceph_unlink_many slot.
 * WHY:  librados 3.0's C API has no batch remove (checked against the real
 *       header, not the docs), so the batch is N rados_remove calls - the win
 *       is that the ioctx AND ITS IDENTITY are established once per window.
 *       In RADOS the ioctx IS the identity at the OSDs (the T-wave confused
 *       deputy), so the _cred twin (sd_ceph_ns_cred.c) resolving the caller's
 *       ioctx once and running this same core on it is precisely the point:
 *       one acquire/release brackets the whole batch.
 * HOW:  Per-key sd_ceph_unlink_io with is_dir=0 (a batch never carries
 *       directories - contract in sd_batch_types.h), recording each key's
 *       errno and continuing: RADOS removes are independent, so one failed
 *       key never invalidates its neighbours and done is always n. No
 *       BRIX_SD_CAP_BULK_DELETE: this is a loop, not a wire batch, so the
 *       rmtree walker gains nothing by accumulating - only the flat
 *       client-supplied batch (brix_vfs_delete_many) reaches it wide.
 */
#include "sd_ceph.h"

#include <errno.h>

#include "sd_ceph_internal.h"

#if BRIX_HAVE_CEPH

#include <rados/librados.h>

ngx_int_t
sd_ceph_unlink_many_io(sd_ceph_state_t *st, rados_ioctx_t io,
    brix_sd_unlink_batch_t *b)
{
    size_t i;

    if (b->n > BRIX_SD_BULK_DELETE_WINDOW) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    for (i = 0; i < b->n; i++) {
        errno = 0;
        if (sd_ceph_unlink_io(st, io, b->paths[i], 0) == NGX_OK) {
            b->errs[i] = 0;
        } else {
            b->errs[i] = (errno != 0) ? errno : EIO;
        }
    }
    b->done = b->n;
    return NGX_OK;
}

/* The plain slot: the export's own ioctx (service identity), like every
 * non-_cred namespace slot on this driver. */
ngx_int_t
sd_ceph_unlink_many(brix_sd_instance_t *inst, brix_sd_unlink_batch_t *b)
{
    sd_ceph_state_t *st = inst->state;

    return sd_ceph_unlink_many_io(st, st->ioctx, b);
}

#endif /* BRIX_HAVE_CEPH */

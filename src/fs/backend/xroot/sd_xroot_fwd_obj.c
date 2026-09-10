/*
 * sd_xroot_fwd_obj.c — object / dir / staged relays of the forwarding driver.
 *
 * WHAT: The handle-keyed slots.  A handle opened through the forwarding driver
 *       belongs to an sd_xroot CHILD (obj->inst / obj->driver, d->inst,
 *       st->inst are the child's), so these slots are reached only by the
 *       seams that dispatch through the EXPORT's instance rather than the
 *       handle's own driver (vfs_staged.c's ctx->sd->driver->staged_write,
 *       the close/pread fallbacks in vfs_open_handle.c, ...).
 * WHY:  Those seams must work identically whether the export is a fixed
 *       root:// origin or a forwarding one — declaring the slots keeps every
 *       `inst->driver->X != NULL` capability probe true exactly where
 *       sd_xroot's is.
 * HOW:  Forward to the handle's own driver through sd_xroot_fwd_relay_driver,
 *       which refuses (ENOSYS) a NULL or self-referential driver so nothing can
 *       recurse; a child without the slot answers ENOSYS too.
 */
#include "sd_xroot_fwd_internal.h"

#include <errno.h>

static const brix_sd_driver_t *
sd_xroot_fwd_obj_driver(const brix_sd_obj_t *obj)
{
    return (obj != NULL) ? sd_xroot_fwd_relay_driver(obj->driver) : NULL;
}

static const brix_sd_driver_t *
sd_xroot_fwd_inst_driver(const brix_sd_instance_t *inst)
{
    return (inst != NULL) ? sd_xroot_fwd_relay_driver(inst->driver) : NULL;
}

static ngx_int_t
sd_xroot_fwd_nosys(void)
{
    errno = ENOSYS;
    return NGX_ERROR;
}

ngx_int_t
sd_xroot_fwd_close(brix_sd_obj_t *obj)
{
    const brix_sd_driver_t *d = sd_xroot_fwd_obj_driver(obj);

    return (d != NULL && d->close != NULL) ? d->close(obj)
                                           : sd_xroot_fwd_nosys();
}

ssize_t
sd_xroot_fwd_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off)
{
    const brix_sd_driver_t *d = sd_xroot_fwd_obj_driver(obj);

    return (d != NULL && d->pread != NULL) ? d->pread(obj, buf, len, off)
                                           : (ssize_t) sd_xroot_fwd_nosys();
}

ssize_t
sd_xroot_fwd_pwrite(brix_sd_obj_t *obj, const void *buf, size_t len, off_t off)
{
    const brix_sd_driver_t *d = sd_xroot_fwd_obj_driver(obj);

    return (d != NULL && d->pwrite != NULL) ? d->pwrite(obj, buf, len, off)
                                            : (ssize_t) sd_xroot_fwd_nosys();
}

ssize_t
sd_xroot_fwd_preadv(brix_sd_obj_t *obj, const struct iovec *iov, int iovcnt,
    off_t off)
{
    const brix_sd_driver_t *d = sd_xroot_fwd_obj_driver(obj);

    return (d != NULL && d->preadv != NULL) ? d->preadv(obj, iov, iovcnt, off)
                                            : (ssize_t) sd_xroot_fwd_nosys();
}

ngx_int_t
sd_xroot_fwd_ftruncate(brix_sd_obj_t *obj, off_t len)
{
    const brix_sd_driver_t *d = sd_xroot_fwd_obj_driver(obj);

    return (d != NULL && d->ftruncate != NULL) ? d->ftruncate(obj, len)
                                               : sd_xroot_fwd_nosys();
}

ngx_int_t
sd_xroot_fwd_fsync(brix_sd_obj_t *obj)
{
    const brix_sd_driver_t *d = sd_xroot_fwd_obj_driver(obj);

    return (d != NULL && d->fsync != NULL) ? d->fsync(obj)
                                           : sd_xroot_fwd_nosys();
}

ngx_int_t
sd_xroot_fwd_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out)
{
    const brix_sd_driver_t *d = sd_xroot_fwd_obj_driver(obj);

    return (d != NULL && d->fstat != NULL) ? d->fstat(obj, out)
                                           : sd_xroot_fwd_nosys();
}

ngx_int_t
sd_xroot_fwd_query_checksum(brix_sd_obj_t *obj, const char *algo,
    char *hex_out, size_t hex_sz)
{
    const brix_sd_driver_t *d = sd_xroot_fwd_obj_driver(obj);

    return (d != NULL && d->query_checksum != NULL)
           ? d->query_checksum(obj, algo, hex_out, hex_sz)
           : sd_xroot_fwd_nosys();
}

ngx_int_t
sd_xroot_fwd_readdir(brix_sd_dir_t *dir, brix_sd_dirent_t *out)
{
    const brix_sd_driver_t *d = (dir != NULL)
                                ? sd_xroot_fwd_inst_driver(dir->inst) : NULL;

    return (d != NULL && d->readdir != NULL) ? d->readdir(dir, out)
                                             : sd_xroot_fwd_nosys();
}

ngx_int_t
sd_xroot_fwd_closedir(brix_sd_dir_t *dir)
{
    const brix_sd_driver_t *d = (dir != NULL)
                                ? sd_xroot_fwd_inst_driver(dir->inst) : NULL;

    return (d != NULL && d->closedir != NULL) ? d->closedir(dir)
                                              : sd_xroot_fwd_nosys();
}

ssize_t
sd_xroot_fwd_staged_write(brix_sd_staged_t *st, const void *buf, size_t len,
    off_t off)
{
    const brix_sd_driver_t *d = (st != NULL)
                                ? sd_xroot_fwd_inst_driver(st->inst) : NULL;

    return (d != NULL && d->staged_write != NULL)
           ? d->staged_write(st, buf, len, off)
           : (ssize_t) sd_xroot_fwd_nosys();
}

ngx_int_t
sd_xroot_fwd_staged_commit(brix_sd_staged_t *st, brix_sd_precond_t *pre)
{
    const brix_sd_driver_t *d = (st != NULL)
                                ? sd_xroot_fwd_inst_driver(st->inst) : NULL;

    return (d != NULL && d->staged_commit != NULL) ? d->staged_commit(st, pre)
                                                   : sd_xroot_fwd_nosys();
}

void
sd_xroot_fwd_staged_abort(brix_sd_staged_t *st)
{
    const brix_sd_driver_t *d = (st != NULL)
                                ? sd_xroot_fwd_inst_driver(st->inst) : NULL;

    if (d != NULL && d->staged_abort != NULL) {
        d->staged_abort(st);
    }
}

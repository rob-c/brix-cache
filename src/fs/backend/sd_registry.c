/*
 * sd_registry.c — Storage Driver registry + capability-gated accessors.
 *
 * WHAT: Owns the static table of registered drivers (POSIX today; block/object
 *       later), the name->driver lookup, per-export instance construction and
 *       teardown, and the small accessor helpers (caps/fd/supports/name) that
 *       keep callers off the raw vtable.
 *
 * WHY:  The VFS must select a backend by config name and obtain a bound instance
 *       without knowing any driver's internals. Centralizing registration here
 *       means adding a backend is a one-line table edit plus its sd_<name>.c.
 *
 * HOW:  xrootd_sd_instance_create() looks up the driver, pcalloc's an instance,
 *       and runs the driver's init(). The accessors read the driver caps/fd
 *       behind NULL-tolerant guards. Phase 55.A registers only "posix".
 */

#include "sd.h"
#include "core/types/fs_list.h"         /* THE central filesystem census */
#include "fs/backend/rados/sd_ceph.h"   /* xrootd_sd_ceph_driver (only under XROOTD_HAVE_CEPH) */

#include <errno.h>

/* The name-resolvable driver table, GENERATED from the central filesystem
 * declaration (core/types/fs_list.h): every BACKEND-kind row lands here;
 * origins/decorators are created directly by the tier and stay out. Add
 * filesystems THERE (the gated sublists carry the library #if structure). */
#define XROOTD_FS_ROW_BACKEND(ID, sym, name)   &xrootd_sd_##sym##_driver,
#define XROOTD_FS_ROW_ORIGIN(ID, sym, name)
#define XROOTD_FS_ROW_DECORATOR(ID, sym, name)
#define XROOTD_FS_ROW_NEARLINE(ID, sym, name)

static const xrootd_sd_driver_t *const sd_drivers[] = {
    XROOTD_FS_DRIVER_LIST(XROOTD_FS_ROW)
};

#undef XROOTD_FS_ROW_BACKEND
#undef XROOTD_FS_ROW_ORIGIN
#undef XROOTD_FS_ROW_DECORATOR
#undef XROOTD_FS_ROW_NEARLINE

/* Census accessors: iterate every REGISTERED filesystem (tooling/health). */
ngx_uint_t
xrootd_sd_driver_count(void)
{
    return sizeof(sd_drivers) / sizeof(sd_drivers[0]);
}

const xrootd_sd_driver_t *
xrootd_sd_driver_at(ngx_uint_t i)
{
    return (i < sizeof(sd_drivers) / sizeof(sd_drivers[0]))
         ? sd_drivers[i] : NULL;
}

/* xrootd_sd_default_driver — the backend an export defaults to when it names none:
 * the built-in POSIX driver (the full-featured reference backend), so the VFS can
 * resolve "the default backend" without hard-coding the POSIX symbol. */
const xrootd_sd_driver_t *
xrootd_sd_default_driver(void)
{
    return &xrootd_sd_posix_driver;
}

/* xrootd_sd_driver_find — resolve a backend name to its driver (linear scan of the
 * small static table; NULL name → NULL). Used by config parsing and instance
 * creation to map a string to a driver. */
const xrootd_sd_driver_t *
xrootd_sd_driver_find(const char *name)
{
    ngx_uint_t i;

    if (name == NULL) {
        return NULL;
    }
    for (i = 0; i < sizeof(sd_drivers) / sizeof(sd_drivers[0]); i++) {
        if (ngx_strcmp(sd_drivers[i]->name, name) == 0) {
            return sd_drivers[i];
        }
    }
    return NULL;
}

/* xrootd_sd_instance_create — build the per-export instance bound at config/worker
 * init: find the named driver, pcalloc the instance, call init(driver_conf); on an
 * unknown driver or init failure, set *err_out and return NULL. */
xrootd_sd_instance_t *
xrootd_sd_instance_create(ngx_pool_t *pool, ngx_log_t *log, const char *name,
    void *driver_conf, int *err_out)
{
    const xrootd_sd_driver_t *driver;
    xrootd_sd_instance_t     *inst;

    driver = xrootd_sd_driver_find(name);
    if (driver == NULL) {
        if (err_out != NULL) { *err_out = ENOENT; }
        return NULL;
    }

    inst = ngx_pcalloc(pool, sizeof(*inst));
    if (inst == NULL) {
        if (err_out != NULL) { *err_out = ENOMEM; }
        return NULL;
    }

    inst->driver = driver;
    inst->log = log;
    inst->pool = pool;

    if (driver->init != NULL && driver->init(inst, driver_conf) != NGX_OK) {
        if (err_out != NULL) { *err_out = errno != 0 ? errno : EINVAL; }
        return NULL;
    }
    return inst;
}

/* xrootd_sd_instance_destroy — NULL-safe driver->cleanup() (the pool reclaims the
 * struct); drivers may hold kernel/transport resources, e.g. the POSIX rootfd. */
void
xrootd_sd_instance_destroy(xrootd_sd_instance_t *inst)
{
    if (inst != NULL && inst->driver != NULL && inst->driver->cleanup != NULL) {
        inst->driver->cleanup(inst);
    }
}

/* accessors */

uint32_t
xrootd_sd_caps(const xrootd_sd_instance_t *inst)
{
    return (inst != NULL && inst->driver != NULL) ? inst->driver->caps : 0;
}

ngx_fd_t
xrootd_sd_fd(const xrootd_sd_obj_t *obj)
{
    if (obj == NULL || obj->driver == NULL
        || !(obj->driver->caps & XROOTD_SD_CAP_FD))
    {
        return NGX_INVALID_FILE;
    }
    return obj->fd;
}

const char *
xrootd_sd_backend_name(const xrootd_sd_instance_t *inst)
{
    return (inst != NULL && inst->driver != NULL) ? inst->driver->name : "?";
}

ngx_int_t
xrootd_sd_supports(const xrootd_sd_instance_t *inst, uint32_t required_caps)
{
    return (xrootd_sd_caps(inst) & required_caps) == required_caps
               ? NGX_OK : NGX_ERROR;
}

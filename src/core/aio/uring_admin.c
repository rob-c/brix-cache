#include "core/ngx_brix_module.h"
#include "uring.h"
#include <sys/stat.h>


/* File: src/aio/uring_admin.c — io_uring runtime kill switch (Phase 44)
 * WHAT: The no-rebuild, no-reload kill switch for the optional io_uring backend
 *       (§8.1/§14.3): a single cross-worker ngx_atomic_t in shared memory that,
 *       when set, makes every worker's selector skip the io_uring tier on its
 *       next op (in-flight CQEs still drain).  Three ways to flip it — the admin
 *       API (api_admin.c), a watched panic-file (per-worker poll timer here), or
 *       the runtime probe never bringing a ring up in the first place.
 *
 * WHY:  io_uring has been a major kernel attack surface; operators need to
 *       neutralise it fleet-wide in seconds during an incident without a rebuild
 *       or reload.  The flag lives in SHM so one admin call / one dropped file is
 *       observed by every worker on its next op.  Build-independent (no liburing
 *       types) so the HTTP dashboard module can drive it.
 *
 * HOW:  A tiny SHM zone holds one ngx_atomic_t.  The hot path reads it lock-free
 *       (brix_uring_disabled in uring.h).  The panic-file poll mirrors file
 *       existence into the flag.  Everything degrades to a clean no-op when the
 *       zone was never registered (stub build / io_uring off everywhere). */

/* Panic-file poll cadence (coarse: this is an incident switch, not a hot path). */
#define BRIX_URING_PANIC_POLL_MS  2000

/* SHM zone holding the single cross-worker disable flag. */
static ngx_shm_zone_t  *brix_uring_ks_zone;

/* Set at config time iff some block had `brix_io_uring_admin on`. */
static ngx_uint_t       brix_uring_admin_on;

/* Per-worker panic-file poll timer + a NUL-terminated copy of the path. */
static ngx_event_t      brix_uring_panic_timer;
static u_char           brix_uring_panic_path[PATH_MAX];


/*
 * brix_uring_ks_zone_init — SHM zone init callback.  Slab-allocates the single
 * ngx_atomic_t flag and stashes it in sp->data (so a reload re-attaches to the
 * same flag).  Mirrors the minimal single-object SHM pattern used elsewhere in
 * the module.
 */
static ngx_int_t
brix_uring_ks_zone_init(ngx_shm_zone_t *zone, void *data)
{
    ngx_slab_pool_t *sp;
    ngx_atomic_t    *flag;

    if (data) {                       /* reload: inherit the previous flag */
        zone->data = data;
        return NGX_OK;
    }

    sp = (ngx_slab_pool_t *) zone->shm.addr;

    if (zone->shm.exists) {           /* re-attach to an existing segment */
        zone->data = sp->data;
        return NGX_OK;
    }

    flag = ngx_slab_alloc(sp, sizeof(ngx_atomic_t));
    if (flag == NULL) {
        return NGX_ERROR;
    }
    *flag = 0;                        /* enabled by default */
    sp->data    = (void *) flag;
    zone->data  = (void *) flag;
    return NGX_OK;
}

ngx_int_t
brix_uring_killswitch_configure(ngx_conf_t *cf)
{
    ngx_str_t  name = ngx_string("brix_io_uring_killswitch");

    if (brix_uring_ks_zone != NULL) {
        return NGX_OK;                /* already registered */
    }

    brix_uring_ks_zone = ngx_shared_memory_add(cf, &name,
                               (size_t) (2 * ngx_pagesize),
                               &ngx_stream_brix_module);
    if (brix_uring_ks_zone == NULL) {
        return NGX_ERROR;
    }
    brix_uring_ks_zone->init = brix_uring_ks_zone_init;
    return NGX_OK;
}

ngx_atomic_t *
brix_uring_killswitch_ptr(void)
{
    if (brix_uring_ks_zone == NULL || brix_uring_ks_zone->data == NULL) {
        return NULL;
    }
    return (ngx_atomic_t *) brix_uring_ks_zone->data;
}

ngx_int_t
brix_uring_killswitch_set(ngx_uint_t disabled)
{
    ngx_atomic_t *flag = brix_uring_killswitch_ptr();

    if (flag == NULL) {
        return NGX_DECLINED;          /* not configured (stub / io_uring off) */
    }
    *flag = disabled ? 1 : 0;         /* aligned word store: atomic + lock-free */
    return NGX_OK;
}

ngx_int_t
brix_uring_killswitch_get(void)
{
    ngx_atomic_t *flag = brix_uring_killswitch_ptr();

    return flag != NULL ? (ngx_int_t) (*flag) : 0;
}

void
brix_uring_admin_set_enabled(ngx_uint_t on)
{
    brix_uring_admin_on = on;
}

ngx_int_t
brix_uring_admin_enabled(void)
{
    return (ngx_int_t) brix_uring_admin_on;
}

/*
 * brix_uring_panic_handler — poll timer: mirror the panic-file's existence
 * into the SHM disable flag, then re-arm.  A NOTICE is logged only on a state
 * change so the flip is visible without log spam.
 */
static void
brix_uring_panic_handler(ngx_event_t *ev)
{
    struct stat  st;
    ngx_uint_t   exists;
    ngx_int_t    prev;

    exists = (brix_uring_panic_path[0] != '\0'
              && stat((char *) brix_uring_panic_path, &st) == 0) ? 1 : 0;

    prev = brix_uring_killswitch_get();
    if (prev != (ngx_int_t) exists) {
        brix_uring_killswitch_set(exists);
        ngx_log_error(NGX_LOG_NOTICE, ev->log, 0,
            "brix: io_uring %s via panic-file \"%s\"",
            exists ? "DISABLED" : "re-enabled",
            (char *) brix_uring_panic_path);
    }

    ngx_add_timer(ev, BRIX_URING_PANIC_POLL_MS);
}

ngx_int_t
brix_uring_panicfile_arm(ngx_cycle_t *cycle, ngx_str_t *path)
{
    if (path == NULL || path->len == 0) {
        return NGX_OK;
    }
    if (path->len >= sizeof(brix_uring_panic_path)) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
            "brix: io_uring panic-file path too long; ignoring");
        return NGX_OK;
    }

    ngx_memcpy(brix_uring_panic_path, path->data, path->len);
    brix_uring_panic_path[path->len] = '\0';

    brix_uring_panic_timer.handler = brix_uring_panic_handler;
    brix_uring_panic_timer.log     = cycle->log;
    brix_uring_panic_timer.data    = NULL;
    brix_uring_panic_timer.cancelable = 1;   /* don't hold up worker shutdown */

    /* Fire once promptly so a file already present at start disables on boot. */
    ngx_add_timer(&brix_uring_panic_timer, 1);
    return NGX_OK;
}

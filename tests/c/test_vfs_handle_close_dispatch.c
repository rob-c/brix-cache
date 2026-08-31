/*
 * test_vfs_handle_close_dispatch.c — a memory-served handle releases (and
 * syncs) its per-open driver state through the driver's slots.
 *
 * WHAT: drives brix_vfs_close and brix_vfs_sync over handles whose backend
 *       object has NO kernel fd (obj.fd == NGX_INVALID_FILE) but DOES carry
 *       per-open driver state — the shape every memory-served backend
 *       (root://, pblock, RADOS) produces — and proves the driver's close and
 *       fsync slots are dispatched.
 * WHY:  brix_vfs_close used to early-out on obj.fd == NGX_INVALID_FILE, so a
 *       root://-backed write session leaked its origin connection AND its live
 *       remote write handle after a committed GridFTP STOR; the origin then
 *       refused the very next read-open of the object under single-writer
 *       semantics ("already opened by 1 writer"). brix_vfs_sync had the same
 *       early-out, so the writer commit's durability barrier silently became
 *       a no-op for those backends. A live wire test catches the root://
 *       incarnation; this unit pins the dispatch contract for every driver
 *       shape hermetically.
 * HOW:  links the real vfs_open_handle.o + vfs_sync.o on top of the real
 *       policy kernel (vfs_policy.o), with a counting spy driver and a spy
 *       brix_vfs_io_execute; everything else in the two TUs' cross-TU closure
 *       is a no-op stub. Nothing touches a filesystem or a pool.
 *
 * Cases:
 *   success:      close dispatches driver->close for fd-less state-carrying
 *                 handles and for fd-backed ones alike; a stateless fd-less
 *                 metadata shell is still a no-op; sync binds the driver
 *                 object into the SYNC job (driver fsync dispatch) for the
 *                 fd-less shape and leaves it unbound for the fd shape.
 *   error:        a driver close failure propagates NGX_ERROR; a fd-less
 *                 handle whose driver lacks fsync is EINVAL without reaching
 *                 the executor; an executor errno propagates out of sync.
 *   security-neg: a READ_ONLY (and a zeroed, fail-closed) policy refuses
 *                 sync with EROFS before any executor or driver work, and is
 *                 observed by the denial metric — while close, which releases
 *                 resources rather than mutating storage, stays ungated on a
 *                 read-only endpoint (the leak fix cannot be policied away).
 *
 * Build+run: see tests/cmdscripts/c_object_units.py ("vfs_handle_close_dispatch").
 */
#include "fs/vfs/vfs_internal.h"
#include "fs/vfs/vfs_io_core.h"
#include "fs/backend/ucred.h"
#include "fs/vfs/vfs_cred_internal.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

/* ---- spy state ---------------------------------------------------------- */
static int g_close_calls;
static int g_close_rc;              /* what the spy close returns             */
static int g_fsync_calls;
static int g_io_calls;
static int g_io_errno;              /* what the spy executor reports          */
static int g_io_obj_bound;          /* last SYNC job carried the driver obj   */
static int g_denials;
static int g_dummy_state;           /* address = the per-open driver state    */

/* ---- spy driver --------------------------------------------------------- */
static ngx_int_t
spy_close(brix_sd_obj_t *obj)
{
    g_close_calls++;
    if (g_close_rc != NGX_OK) {
        errno = EIO;
        return NGX_ERROR;
    }
    obj->state = NULL;
    obj->fd = NGX_INVALID_FILE;
    return NGX_OK;
}

static ngx_int_t
spy_fsync(brix_sd_obj_t *obj)
{
    (void) obj;
    g_fsync_calls++;
    return NGX_OK;
}

static const brix_sd_driver_t spy_driver = {
    .name  = "spy",
    .close = spy_close,
    .fsync = spy_fsync,
};

static const brix_sd_driver_t spy_driver_no_fsync = {
    .name  = "spy-nofsync",
    .close = spy_close,
};

/* ---- cross-TU closure stubs --------------------------------------------- */
const char *brix_sd_backend_name(const brix_sd_instance_t *inst)
{ (void) inst; return "spy"; }

uint32_t brix_sd_caps(const brix_sd_instance_t *inst)
{ (void) inst; return 0; }

const brix_sd_driver_t *brix_sd_default_driver(void) { return NULL; }

void brix_metric_cache_evicted(brix_proto_t proto, uint64_t bytes)
{ (void) proto; (void) bytes; }

uint64_t brix_sd_cache_evict(brix_sd_instance_t *inst, const char *key)
{ (void) inst; (void) key; return 0; }

void brix_sd_ucred_wipe(brix_sd_ucred_t *cred) { (void) cred; }

int brix_vfs_cred_gate_active(brix_vfs_ctx_t *ctx) { (void) ctx; return 0; }

const char *brix_vfs_export_relative(const brix_vfs_ctx_t *ctx,
    const char *path)
{ (void) ctx; return path; }

brix_sd_instance_t *brix_vfs_ns_leaf(brix_sd_instance_t *top) { return top; }

ngx_int_t brix_vfs_ns_cred(brix_vfs_ctx_t *ctx, brix_sd_ucred_t *store,
    brix_sd_cred_t *cred, int *use_cred, int *err_out)
{
    (void) ctx; (void) err_out;
    memset(store, 0, sizeof(*store));
    memset(cred, 0, sizeof(*cred));
    *use_cred = 0;
    return NGX_OK;
}

brix_vfs_file_t *brix_vfs_open(brix_vfs_ctx_t *ctx, ngx_uint_t flags,
    int *err_out)
{
    (void) ctx; (void) flags;
    if (err_out != NULL) { *err_out = ENOSYS; }
    return NULL;
}

void brix_metric_vfs_mutation_denied(brix_proto_t proto, ngx_uint_t op)
{ (void) proto; (void) op; g_denials++; }

/* The spy executor: record whether vfs_sync bound the handle's driver object
 * into the job (which is what makes the real executor dispatch driver->fsync
 * instead of wrapping the — invalid — kernel fd). */
void brix_vfs_io_execute(brix_vfs_job_t *job)
{
    g_io_calls++;
    assert(job->op == BRIX_VFS_IO_SYNC);
    g_io_obj_bound = (job->obj.driver != NULL);
    if (job->obj.driver == &spy_driver) {
        /* mirror the real executor: driver dispatch reaches the fsync slot */
        (void) job->obj.driver->fsync(&job->obj);
    }
    job->io_errno = g_io_errno;
}

/* ---- helpers ------------------------------------------------------------ */
static void
handle_init(brix_vfs_file_t *fh, const brix_sd_driver_t *drv, ngx_fd_t fd,
    void *state, brix_vfs_mutation_policy_t policy)
{
    memset(fh, 0, sizeof(*fh));
    fh->obj.driver      = drv;
    fh->obj.fd          = fd;
    fh->obj.state       = state;
    fh->memfd           = NGX_INVALID_FILE;
    fh->mutation_policy = policy;
}

static void
reset_spies(void)
{
    g_close_calls = 0;
    g_close_rc    = NGX_OK;
    g_fsync_calls = 0;
    g_io_calls    = 0;
    g_io_errno    = 0;
    g_io_obj_bound = -1;
    g_denials     = 0;
}

/* ---- cases -------------------------------------------------------------- */
static void
test_success_close_dispatches_memory_served(void)
{
    brix_vfs_file_t fh;

    reset_spies();
    handle_init(&fh, &spy_driver, NGX_INVALID_FILE, &g_dummy_state,
                BRIX_VFS_MUTATION_ALLOWED);
    assert(brix_vfs_close(&fh, NULL) == NGX_OK);
    assert(g_close_calls == 1);
    assert(fh.obj.state == NULL);          /* the driver consumed its state   */
}

static void
test_success_close_dispatches_fd_backed(void)
{
    brix_vfs_file_t fh;

    reset_spies();
    handle_init(&fh, &spy_driver, 99, NULL, BRIX_VFS_MUTATION_ALLOWED);
    assert(brix_vfs_close(&fh, NULL) == NGX_OK);
    assert(g_close_calls == 1);            /* fd-backed dispatch unchanged    */
}

static void
test_success_close_skips_stateless_metadata_shell(void)
{
    brix_vfs_file_t fh;

    reset_spies();
    handle_init(&fh, &spy_driver, NGX_INVALID_FILE, NULL,
                BRIX_VFS_MUTATION_ALLOWED);
    assert(brix_vfs_close(&fh, NULL) == NGX_OK);
    assert(g_close_calls == 0);            /* nothing to release              */
}

static void
test_success_sync_binds_driver_obj_when_fdless(void)
{
    brix_vfs_file_t fh;

    reset_spies();
    handle_init(&fh, &spy_driver, NGX_INVALID_FILE, &g_dummy_state,
                BRIX_VFS_MUTATION_ALLOWED);
    assert(brix_vfs_sync(&fh) == NGX_OK);
    assert(g_io_calls == 1);
    assert(g_io_obj_bound == 1);           /* executor got the driver object  */
    assert(g_fsync_calls == 1);            /* ... and dispatched its fsync    */
}

static void
test_success_sync_keeps_fd_path_unbound(void)
{
    brix_vfs_file_t fh;

    reset_spies();
    handle_init(&fh, &spy_driver, 99, &g_dummy_state,
                BRIX_VFS_MUTATION_ALLOWED);
    assert(brix_vfs_sync(&fh) == NGX_OK);
    assert(g_io_calls == 1);
    assert(g_io_obj_bound == 0);           /* raw-fd path byte-for-byte       */
}

static void
test_error_close_failure_propagates(void)
{
    brix_vfs_file_t fh;
    ngx_log_t       quiet;

    reset_spies();
    g_close_rc = NGX_ERROR;
    memset(&quiet, 0, sizeof(quiet));      /* log_level 0: nothing emitted    */
    handle_init(&fh, &spy_driver, NGX_INVALID_FILE, &g_dummy_state,
                BRIX_VFS_MUTATION_ALLOWED);
    assert(brix_vfs_close(&fh, &quiet) == NGX_ERROR);
    assert(g_close_calls == 1);
}

static void
test_error_sync_without_fsync_slot_is_einval(void)
{
    brix_vfs_file_t fh;

    reset_spies();
    handle_init(&fh, &spy_driver_no_fsync, NGX_INVALID_FILE, &g_dummy_state,
                BRIX_VFS_MUTATION_ALLOWED);
    errno = 0;
    assert(brix_vfs_sync(&fh) == NGX_ERROR);
    assert(errno == EINVAL);
    assert(g_io_calls == 0);               /* refused before the executor     */
}

static void
test_error_sync_executor_errno_propagates(void)
{
    brix_vfs_file_t fh;

    reset_spies();
    g_io_errno = EIO;
    handle_init(&fh, &spy_driver, NGX_INVALID_FILE, &g_dummy_state,
                BRIX_VFS_MUTATION_ALLOWED);
    errno = 0;
    assert(brix_vfs_sync(&fh) == NGX_ERROR);
    assert(errno == EIO);
}

static void
test_secneg_read_only_sync_is_erofs_before_any_backend_work(void)
{
    brix_vfs_file_t fh;

    reset_spies();
    handle_init(&fh, &spy_driver, NGX_INVALID_FILE, &g_dummy_state,
                BRIX_VFS_MUTATION_READ_ONLY);
    errno = 0;
    assert(brix_vfs_sync(&fh) == NGX_ERROR);
    assert(errno == EROFS);                /* the posture, never EACCES       */
    assert(g_io_calls == 0);
    assert(g_fsync_calls == 0);
    assert(g_denials == 1);                /* the tripwire counted it         */
}

static void
test_secneg_zeroed_policy_fails_closed(void)
{
    brix_vfs_file_t fh;

    reset_spies();
    handle_init(&fh, &spy_driver, NGX_INVALID_FILE, &g_dummy_state,
                (brix_vfs_mutation_policy_t) 0);
    errno = 0;
    assert(brix_vfs_sync(&fh) == NGX_ERROR);
    assert(errno == EROFS);
    assert(g_io_calls == 0);
}

static void
test_secneg_close_stays_ungated_on_read_only(void)
{
    brix_vfs_file_t fh;

    reset_spies();
    handle_init(&fh, &spy_driver, NGX_INVALID_FILE, &g_dummy_state,
                BRIX_VFS_MUTATION_READ_ONLY);
    assert(brix_vfs_close(&fh, NULL) == NGX_OK);
    assert(g_close_calls == 1);            /* releasing ≠ mutating            */
    assert(g_denials == 0);
}

int
main(void)
{
    test_success_close_dispatches_memory_served();
    test_success_close_dispatches_fd_backed();
    test_success_close_skips_stateless_metadata_shell();
    test_success_sync_binds_driver_obj_when_fdless();
    test_success_sync_keeps_fd_path_unbound();
    test_error_close_failure_propagates();
    test_error_sync_without_fsync_slot_is_einval();
    test_error_sync_executor_errno_propagates();
    test_secneg_read_only_sync_is_erofs_before_any_backend_work();
    test_secneg_zeroed_policy_fails_closed();
    test_secneg_close_stays_ungated_on_read_only();
    printf("vfs_handle_close_dispatch: 11 cases OK\n");
    return 0;
}

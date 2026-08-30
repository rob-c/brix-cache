/*
 * test_sd_block_space.c — the block driver's capacity report, over a real
 * stand-in device and the driver's own init.
 *
 * WHY THIS UNIT EXISTS: with no `space` slot, kXR_Qspace/kXR_statvfs on a block
 * export fell back to statvfs(2) of the local export ROOT — a filesystem that
 * has nothing to do with the raw device the objects live on, and is usually the
 * root fs holding the mount point. An operator sizing a transfer against that
 * answer sized it against the wrong disk, in the wrong direction: the host's
 * spare gigabytes look like room to write into a namespace that cannot grow by
 * a single byte. This pins the two claims the slot makes instead — the figures
 * are the DEVICE's, and free is honestly zero.
 *
 * Everything is real: sd_block_init probes a file standing in for the device
 * exactly as it probes a device (st_size where BLKGETSIZE64 does not apply), and
 * the geometry it derives is the geometry the slot reports from. Only nginx's
 * allocator and logger are borrowed from the real nginx objects.
 *
 * Arms: success (the device capacity, the derived geometry, and free == 0),
 * error (an uninitialised instance and a missing out-pointer are EINVAL, and an
 * empty device never becomes an export at all), and security-negative (the
 * report never describes the filesystem UNDER the device, and never advertises
 * free space on an export where no object can be created).
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include <ngx_config.h>
#include <ngx_core.h>

#include "fs/backend/sd.h"
#include "fs/backend/sd_registry.h"
#include "fs/backend/block/sd_block_internal.h"

static int failures;
#define CHECK(cond, msg) \
    do { if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (errno=%d %s)\n", (msg), errno, strerror(errno)); \
        failures++; \
    } } while (0)

/* The byte plane delegates its opens to the POSIX driver; nothing here opens an
 * extent, so a failing open is enough to link sd_block.o's vtable. */
int
brix_sd_posix_open_unconfined(const char *path, int sd_flags, mode_t mode)
{
    (void) path; (void) sd_flags; (void) mode;
    errno = ENOSYS;
    return -1;
}

const brix_sd_driver_t brix_sd_posix_driver;

/* ---- fixture: a file standing in for the device ---------------------------- */

#define DEV_BYTES   (64 * 1024)
#define EXTENT_SZ   (16 * 1024)

static char g_devpath[256];

static int
dev_create(off_t bytes)
{
    int fd;

    snprintf(g_devpath, sizeof g_devpath, "/tmp/sd_block_space_ut.%d",
             (int) getpid());
    fd = open(g_devpath, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        return -1;
    }
    if (bytes > 0 && ftruncate(fd, bytes) != 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static ngx_pool_t *g_pool;

static int
build_inst(brix_sd_instance_t *inst, off_t extent_size)
{
    brix_sd_block_conf_t conf = { .device = g_devpath,
                                  .extent_size = extent_size };

    memset(inst, 0, sizeof *inst);
    inst->pool = g_pool;
    return sd_block_init(inst, &conf) == NGX_OK;
}

/* ---- arm 1: success — the device's own figures ----------------------------- */

static void
check_success(void)
{
    brix_sd_instance_t inst;
    brix_sd_space_t    sp;

    CHECK(build_inst(&inst, EXTENT_SZ), "init probes the stand-in device");

    memset(&sp, 0xee, sizeof sp);
    CHECK(sd_block_space(&inst, &sp) == NGX_OK, "space ok");
    CHECK(sp.total_bytes == (uint64_t) DEV_BYTES,
          "total is the probed device capacity");
    CHECK(sp.used_bytes == (uint64_t) DEV_BYTES,
          "used is the whole device: the extent set is fixed at init");
    CHECK(sp.free_bytes == 0,
          "free is zero: no operation on this driver creates an object");

    /* The geometry the report comes from is the geometry init derived — the
     * capacity is the DEVICE's, independent of how it was carved up. */
    CHECK(build_inst(&inst, 0), "extent_size 0 makes the whole device one extent");
    memset(&sp, 0, sizeof sp);
    CHECK(sd_block_space(&inst, &sp) == NGX_OK, "space ok with one extent");
    CHECK(sp.total_bytes == (uint64_t) DEV_BYTES,
          "the capacity does not depend on the extent geometry");

    /* A device whose length is not a whole number of extents still reports its
     * real length, not the rounded-up extent span — the tail extent is short. */
    CHECK(dev_create(DEV_BYTES + 1) == 0, "a device with a short tail extent");
    CHECK(build_inst(&inst, EXTENT_SZ), "init accepts it");
    memset(&sp, 0, sizeof sp);
    CHECK(sd_block_space(&inst, &sp) == NGX_OK, "space ok");
    CHECK(sp.total_bytes == (uint64_t) DEV_BYTES + 1,
          "the report is the real capacity, never the rounded extent span");
    CHECK(dev_create(DEV_BYTES) == 0, "restore the aligned device");
}

/* ---- arm 2: error ---------------------------------------------------------- */

static void
check_errors(void)
{
    brix_sd_instance_t inst;
    brix_sd_space_t    sp;

    CHECK(build_inst(&inst, EXTENT_SZ), "init ok");

    errno = 0;
    CHECK(sd_block_space(&inst, NULL) == NGX_ERROR, "NULL out fails");
    CHECK(errno == EINVAL, "NULL out -> EINVAL");

    /* An instance whose init never ran (or failed) has no geometry to report;
     * answering from a NULL state would be a read through it. */
    memset(&inst, 0, sizeof inst);
    errno = 0;
    CHECK(sd_block_space(&inst, &sp) == NGX_ERROR, "uninitialised instance fails");
    CHECK(errno == EINVAL, "uninitialised instance -> EINVAL");

    /* And a zero-length device never becomes an export in the first place, so
     * the slot is never asked to describe one. */
    {
        brix_sd_instance_t empty;

        CHECK(dev_create(0) == 0, "a zero-length stand-in device");
        errno = 0;
        CHECK(!build_inst(&empty, EXTENT_SZ), "init refuses an empty device");
        CHECK(errno == ENODEV, "an empty device -> ENODEV");
        CHECK(dev_create(DEV_BYTES) == 0, "restore the device");
    }
}

/* ---- arm 3: security-negative ---------------------------------------------- */

static void
check_security(void)
{
    brix_sd_instance_t inst;
    brix_sd_space_t    sp;
    struct statvfs     vfs;

    CHECK(build_inst(&inst, EXTENT_SZ), "init ok");
    memset(&sp, 0, sizeof sp);
    CHECK(sd_block_space(&inst, &sp) == NGX_OK, "space ok");

    /* THE regression. The fallback this slot exists to displace describes the
     * filesystem the device file happens to sit on. Those figures are orders of
     * magnitude larger and would tell a client it may write; the device's are
     * the only ones that describe where the bytes actually go. */
    if (statvfs(g_devpath, &vfs) == 0) {
        uint64_t host_total = (uint64_t) vfs.f_blocks * (uint64_t) vfs.f_frsize;
        uint64_t host_free  = (uint64_t) vfs.f_bavail * (uint64_t) vfs.f_frsize;

        CHECK(sp.total_bytes != host_total || host_total == (uint64_t) DEV_BYTES,
              "the report is the device's capacity, not the host filesystem's");
        CHECK(sp.free_bytes != host_free || host_free == 0,
              "and never the host filesystem's free space");
    }

    /* free > 0 on this driver would be an invitation to create an object in a
     * namespace that is fixed at init — every such write lands on ENOENT after
     * the client has already committed to the transfer. */
    CHECK(sp.free_bytes == 0, "a fixed-extent export advertises no free space");
    CHECK(sp.used_bytes == sp.total_bytes,
          "used == total is the same statement, from the other side");

    /* A failed report must leave the caller's struct alone rather than half-fill
     * it: a partially written struct read by a caller that ignored the return
     * code is a fabricated capacity. */
    memset(&inst, 0, sizeof inst);
    memset(&sp, 0xee, sizeof sp);
    CHECK(sd_block_space(&inst, &sp) == NGX_ERROR, "uninitialised instance fails");
    CHECK(sp.total_bytes == 0xeeeeeeeeeeeeeeeeULL
          && sp.used_bytes == 0xeeeeeeeeeeeeeeeeULL
          && sp.free_bytes == 0xeeeeeeeeeeeeeeeeULL,
          "a failed space report writes nothing at all");
}

int
main(void)
{
    g_pool = ngx_create_pool(4096, NULL);
    if (g_pool == NULL || dev_create(DEV_BYTES) != 0) {
        fprintf(stderr, "FAIL: cannot build the fixture\n");
        return 1;
    }

    check_success();
    check_errors();
    check_security();

    ngx_destroy_pool(g_pool);
    unlink(g_devpath);

    if (failures != 0) {
        fprintf(stderr, "sd_block space: %d FAILURE(S)\n", failures);
        return 1;
    }
    printf("sd_block space -> device capacity contract: PASS\n");
    return 0;
}

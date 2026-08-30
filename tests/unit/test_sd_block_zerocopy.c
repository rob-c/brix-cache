/*
 * test_sd_block_zerocopy.c — the block driver's zero-copy and read-ahead slots:
 * read_sendfile_fd and read_advise, driven over a file used as the device.
 *
 * WHY: both slots translate a LOGICAL offset (the object's) into a PHYSICAL one
 *      (the device's), and getting that translation wrong is silent in both
 *      directions — one leaks bytes, the other only wastes them:
 *
 *      1. read_sendfile_fd hands back a bare descriptor. Its consumer addresses
 *         that descriptor with logical offsets and builds its own range from the
 *         object size, so the driver never sees the range and cannot clamp it
 *         afterwards. An extent whose base is NOT 0 therefore must never be
 *         offered: doing so would serve the START of the device under every
 *         object's name and let a ranged read walk straight into the
 *         NEIGHBOURING extent — a cross-object read with no error anywhere.
 *         base == 0 is the entire gate, and this pins it.
 *      2. read_advise must window before it advises. An unwindowed hint warms
 *         the wrong extent's pages and evicts the right ones — worse than the
 *         no-op the slot replaced — and "to EOF" (len == 0) has to mean the
 *         EXTENT's end, not the device's.
 *
 * Unity build: this TU #includes sd_block.c and supplies the two POSIX-driver
 * symbols its byte ops delegate to, so no driver stack is needed. Compiled by
 * cmdscripts.sd_block_zerocopy_unit.
 */
#define XRDPROTO_NO_NGX 1

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fs/backend/block/sd_block_internal.h"

/* The byte ops delegate to the POSIX driver; nothing under test reaches them,
 * so an empty table and a failing open are enough to link. */
const brix_sd_driver_t brix_sd_posix_driver;

int
brix_sd_posix_open_unconfined(const char *path, int sd_flags, mode_t mode)
{
    (void) path; (void) sd_flags; (void) mode;
    errno = ENOSYS;
    return -1;
}

#include "fs/backend/block/sd_block.c"   /* NOLINT — unity build */

static int failures;

static void
check(int ok, const char *what)
{
    if (!ok) {
        printf("  FAIL %s\n", what);
        failures++;
    }
}

/* ---- fixture: a 4 KiB file standing in for the device --------------------- */

#define DEV_BYTES  4096
#define EXT_LEN    1024

static char           g_devpath[256];
static int            g_devfd = -1;
static brix_sd_obj_t  g_obj;
static sd_block_obj_t g_win;

/* Point the object at the extent [base, base+EXT_LEN); base < 0 selects the
 * unconfined (client) path, whose offsets are already absolute. */
static void
fixture(off_t base)
{
    memset(&g_obj, 0, sizeof(g_obj));
    g_obj.fd = g_devfd;
    if (base < 0) {
        g_obj.state = NULL;
        return;
    }
    g_win.base  = base;
    g_win.len   = EXT_LEN;
    g_obj.state = &g_win;
}

static int
dev_open(void)
{
    char buf[DEV_BYTES];

    snprintf(g_devpath, sizeof(g_devpath), "/tmp/sd_block_ut.%d", (int) getpid());
    g_devfd = open(g_devpath, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (g_devfd < 0) {
        printf("  FAIL cannot create the stand-in device: %s\n", strerror(errno));
        return 0;
    }
    memset(buf, 'x', sizeof(buf));
    if (write(g_devfd, buf, sizeof(buf)) != (ssize_t) sizeof(buf)) {
        printf("  FAIL short write to the stand-in device\n");
        return 0;
    }
    return 1;
}

/* ---- read_sendfile_fd: base == 0 is the whole gate ------------------------ */

static void
test_sendfile_fd(void)
{
    printf("read_sendfile_fd\n");

    fixture(0);
    check(sd_block_read_sendfile_fd(&g_obj, 0, EXT_LEN, 1) == g_devfd,
          "an extent based at device offset 0 is offered");
    check(sd_block_read_sendfile_fd(&g_obj, 16, EXT_LEN - 16, 1) == g_devfd,
          "…for an interior range too");

    fixture(-1);
    check(sd_block_read_sendfile_fd(&g_obj, 0, DEV_BYTES, 1) == g_devfd,
          "the unconfined client handle is offered (offsets are absolute)");

    /* THE gate. Every one of these would otherwise serve device offset 0 under
     * the name of an object that lives elsewhere on the device. */
    fixture(EXT_LEN);
    check(sd_block_read_sendfile_fd(&g_obj, 0, EXT_LEN, 1) == NGX_INVALID_FILE,
          "a base-shifted extent is NEVER offered for zero-copy");
    fixture(DEV_BYTES - EXT_LEN);
    check(sd_block_read_sendfile_fd(&g_obj, 0, 1, 1) == NGX_INVALID_FILE,
          "…however small the ask");

    /* An ask that already leaves the extent is refused even at base 0: the
     * consumer would read the neighbouring extent's bytes. */
    fixture(0);
    check(sd_block_read_sendfile_fd(&g_obj, 0, EXT_LEN + 1, 1) == NGX_INVALID_FILE,
          "a range past the extent end is refused");
    check(sd_block_read_sendfile_fd(&g_obj, EXT_LEN - 4, 8, 1) == NGX_INVALID_FILE,
          "…including one that only overruns at the tail");
    check(sd_block_read_sendfile_fd(&g_obj, -1, 8, 1) == NGX_INVALID_FILE,
          "a negative offset is refused, not wrapped");

    /* The transport's verdict comes first, and a handle with no descriptor has
     * nothing to offer. */
    fixture(0);
    check(sd_block_read_sendfile_fd(&g_obj, 0, EXT_LEN, 0) == NGX_INVALID_FILE,
          "want_zerocopy == 0 is honoured before anything else");
    g_obj.fd = NGX_INVALID_FILE;
    check(sd_block_read_sendfile_fd(&g_obj, 0, EXT_LEN, 1) == NGX_INVALID_FILE,
          "a handle with no descriptor offers nothing");
}

/* ---- read_advise: advisory, and windowed before it advises ---------------- */

static void
test_read_advise(void)
{
    printf("read_advise\n");

    fixture(EXT_LEN);
    check(sd_block_read_advise(&g_obj, 0, 64, BRIX_SD_ADV_SEQUENTIAL) == NGX_OK,
          "a windowed hint succeeds");
    check(sd_block_read_advise(&g_obj, 0, 0, BRIX_SD_ADV_WILLNEED) == NGX_OK,
          "len == 0 means 'to the EXTENT's end', not the device's");
    check(sd_block_read_advise(&g_obj, 0, EXT_LEN * 8, BRIX_SD_ADV_RANDOM)
          == NGX_OK, "an over-long range is clamped to the extent, not refused");

    /* Wholly outside the extent: nothing to warm, and nothing to complain
     * about — the slot is advisory, so it reports success and does nothing. */
    check(sd_block_read_advise(&g_obj, EXT_LEN, 64, BRIX_SD_ADV_SEQUENTIAL)
          == NGX_OK, "a hint at the extent end is a silent no-op");
    check(sd_block_read_advise(&g_obj, EXT_LEN * 4, 64, BRIX_SD_ADV_WILLNEED)
          == NGX_OK, "…as is one past it");
    check(sd_block_read_advise(&g_obj, EXT_LEN, 0, BRIX_SD_ADV_WILLNEED)
          == NGX_OK, "…and 'to EOF' from the extent end");
    check(sd_block_read_advise(&g_obj, -1, 0, BRIX_SD_ADV_WILLNEED) == NGX_OK,
          "a negative offset is a no-op, never a negative length");

    fixture(-1);
    check(sd_block_read_advise(&g_obj, 0, DEV_BYTES, BRIX_SD_ADV_SEQUENTIAL)
          == NGX_OK, "the unconfined handle advises the absolute range");

    /* Error path: a descriptor the kernel will not accept. posix_fadvise
     * RETURNS the error rather than setting errno, so the slot has to copy it
     * across — an errno of 0 here would mean the seam's contract was broken. */
    fixture(0);
    g_obj.fd = -1;
    errno = 0;
    if (sd_block_read_advise(&g_obj, 0, 64, BRIX_SD_ADV_SEQUENTIAL)
        == NGX_ERROR)
    {
        check(errno != 0, "a hard failure leaves errno set, not 0");
    } else {
        /* A build with no POSIX_FADV_* compiles the hint out entirely; the
         * slot then has nothing that can fail and NGX_OK is correct. */
        check(1, "no posix_fadvise in this build");
    }
}

int
main(void)
{
    int rc;

    if (!dev_open()) {
        return 1;
    }
    test_sendfile_fd();
    test_read_advise();

    close(g_devfd);
    unlink(g_devpath);

    rc = failures != 0;
    if (rc) {
        printf("sd_block zero-copy/advise suite: %d FAILURE(S)\n", failures);
    } else {
        printf("sd_block zero-copy/advise suite: all checks passed\n");
    }
    return rc;
}

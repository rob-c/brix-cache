/* client/tests/c/vfs_block_unit.c
 *
 * WHAT: Unit tests for the block-device VFS backend (Task A4).
 *       Uses a regular file as a stand-in for a block device.
 * WHY:  Verifies in-place write (no temp/rename), cap flags exclude
 *       ATOMIC_TEMP and TRUNCATE, commit/sync work, and truncate rejects cleanly.
 * HOW:  mkstemp → block:// URL → open/pwrite/commit; check caps, no .tmp sibling,
 *       read-back bytes, error on missing path, clean reject for truncate.
 */

#include "../../lib/vfs.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    /* Test 1: in-place write — bytes appear at the same path; no .tmp sibling;
     *          ATOMIC_TEMP and TRUNCATE caps are absent. */
    {
        xrdc_status st = {0};
        char dev[] = "/tmp/vfs_blk_XXXXXX";
        int fd = mkstemp(dev); assert(fd >= 0);
        assert(ftruncate(fd, 4096) == 0); close(fd);

        xrdc_vfs_open_opts o = { .io_uring = 0, .expected_size = -1, .cred = NULL };
        xrdc_vfs_file *w = NULL;
        char url[64]; snprintf(url, sizeof url, "block://%s", dev);
        assert(xrdc_vfs_open(url, XRDC_VFS_WRITE, &o, &w, &st) == 0);
        assert((xrdc_vfs_get_caps(w) & XRDC_VFS_CAP_ATOMIC_TEMP) == 0);   /* no temp+rename */
        assert((xrdc_vfs_get_caps(w) & XRDC_VFS_CAP_TRUNCATE)    == 0);   /* not truncatable */
        assert((xrdc_vfs_get_caps(w) & XRDC_VFS_CAP_RANDOM_WRITE) != 0);  /* random-write ok */
        assert((xrdc_vfs_get_caps(w) & XRDC_VFS_CAP_FADVISE)      != 0);  /* fadvise ok */
        assert(xrdc_vfs_pwrite(w, 512, "BLK", 3, &st) == 0);
        assert(xrdc_vfs_commit(w, &st) == 0);
        xrdc_vfs_close(w);

        /* verify no sibling .tmp file was created */
        char tmp[256]; snprintf(tmp, sizeof tmp, "%s.tmp", dev);
        assert(access(tmp, F_OK) != 0);

        /* read back bytes directly via POSIX — must see "BLK" at offset 512 */
        int v = open(dev, O_RDONLY); assert(v >= 0);
        char b[3];
        assert(pread(v, b, 3, 512) == 3 && memcmp(b, "BLK", 3) == 0);
        close(v);
        unlink(dev);
        printf("vfs block in-place write OK\n");
    }

    /* Test 2 (error): open of a non-existent device path for WRITE fails cleanly. */
    {
        xrdc_status st = {0};
        xrdc_vfs_file *f = NULL;
        xrdc_vfs_open_opts o = { .io_uring = 0, .expected_size = -1, .cred = NULL };
        int rc = xrdc_vfs_open("block:///tmp/vfs_blk_no_such_device_xrdc",
                               XRDC_VFS_WRITE, &o, &f, &st);
        assert(rc != 0);
        assert(f == NULL);
        assert(st.kxr != 0);   /* status must be populated */
        printf("vfs block missing-path error OK\n");
    }

    /* Test 3 (negative): truncate on a block handle returns a clean XRDC_EUSAGE error;
     *                    sync/commit still work on the same handle. */
    {
        xrdc_status st = {0};
        char dev[] = "/tmp/vfs_blk_trunc_XXXXXX";
        int fd = mkstemp(dev); assert(fd >= 0);
        assert(ftruncate(fd, 4096) == 0); close(fd);

        xrdc_vfs_open_opts o = { .io_uring = 0, .expected_size = -1, .cred = NULL };
        xrdc_vfs_file *w = NULL;
        char url[128]; snprintf(url, sizeof url, "block://%s", dev);
        assert(xrdc_vfs_open(url, XRDC_VFS_WRITE, &o, &w, &st) == 0);

        /* truncate must reject cleanly */
        int rc = xrdc_vfs_truncate(w, 1024, &st);
        assert(rc != 0);
        assert(st.kxr == XRDC_EUSAGE);

        /* commit and sync still work after the rejected truncate */
        st.kxr = 0;
        assert(xrdc_vfs_sync(w, &st) == 0);
        assert(xrdc_vfs_commit(w, &st) == 0);
        xrdc_vfs_close(w);
        unlink(dev);
        printf("vfs block truncate-reject + sync/commit OK\n");
    }

    return 0;
}

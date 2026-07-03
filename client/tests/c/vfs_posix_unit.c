/* client/tests/c/vfs_posix_unit.c
 *
 * WHAT: Unit tests — verifies the VFS façade routes a bare path to the POSIX
 *       backend, that the open handle reports XRDC_VFS_CAP_RANDOM_WRITE,
 *       write→commit yields the bytes at the final path, missing-file reads
 *       fail cleanly, and no-FORCE writes onto an existing file are rejected.
 * WHY:  Confirms end-to-end wiring from brix_vfs_open → POSIX backend → caps,
 *       plus the atomic temp+rename commit path and the two POSIX error guards.
 * HOW:  mkstemp + brix_vfs_open; check caps; write/commit; read back; error cases.
 *
 * NOTE: This test REQUIRES the POSIX backend (Task A3).  At Task A2 stage it
 *       will fail to link with "undefined reference to brix_vfs_posix_backend"
 *       — that is the expected RED state.  Run it after A3 is merged.
 */

#include "../../lib/vfs.h"
#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    /* Test 1: façade routing + caps */
    {
        brix_status st = {0};
        char tmpl[] = "/tmp/vfs_unit_XXXXXX";
        int fd = mkstemp(tmpl); assert(fd >= 0); close(fd);

        brix_vfs_open_opts o = { .io_uring = 0, .expected_size = -1, .cred = NULL };
        brix_vfs_file *f = NULL;
        int rc = brix_vfs_open(tmpl, XRDC_VFS_READ, &o, &f, &st);
        assert(rc == 0 && f != NULL);
        assert((brix_vfs_get_caps(f) & XRDC_VFS_CAP_RANDOM_WRITE) != 0);
        assert((brix_vfs_get_caps(f) & XRDC_VFS_CAP_ATOMIC_TEMP) != 0);
        brix_vfs_close(f);
        unlink(tmpl);
        printf("vfs façade routing OK\n");
    }

    /* Test 2: write → commit round-trip — bytes appear at the final path */
    {
        brix_status s2 = {0};
        char dst[] = "/tmp/vfs_commit_XXXXXX";
        int dfd = mkstemp(dst); assert(dfd >= 0); close(dfd); unlink(dst);

        brix_vfs_open_opts wo = { .io_uring = 0, .expected_size = 5, .cred = NULL };
        brix_vfs_file *w = NULL;
        assert(brix_vfs_open(dst, XRDC_VFS_WRITE | XRDC_VFS_FORCE, &wo, &w, &s2) == 0);
        assert(brix_vfs_pwrite(w, 0, "hello", 5, &s2) == 0);
        assert(brix_vfs_commit(w, &s2) == 0);
        brix_vfs_close(w);

        char buf[8] = {0};
        brix_vfs_file *r = NULL;
        assert(brix_vfs_open(dst, XRDC_VFS_READ, &wo, &r, &s2) == 0);
        assert(brix_vfs_pread(r, 0, buf, 5, &s2) == 5);
        assert(memcmp(buf, "hello", 5) == 0);
        brix_vfs_close(r);
        unlink(dst);
        printf("vfs posix commit OK\n");
    }

    /* Test 3: error — open a non-existent file for READ fails cleanly */
    {
        brix_status s3 = {0};
        brix_vfs_open_opts ro = { .io_uring = 0, .expected_size = -1, .cred = NULL };
        brix_vfs_file *f = NULL;
        int rc = brix_vfs_open("/tmp/vfs_no_such_file_brix_unit", XRDC_VFS_READ,
                               &ro, &f, &s3);
        assert(rc != 0);
        assert(f == NULL);
        assert(s3.kxr != 0);   /* status must be set */
        printf("vfs posix missing-file error OK\n");
    }

    /* Test 4: error — WRITE without FORCE onto an existing final file is rejected */
    {
        brix_status s4 = {0};
        char dst[] = "/tmp/vfs_force_XXXXXX";
        int efd = mkstemp(dst); assert(efd >= 0); close(efd);
        /* dst now exists; open WRITE without FORCE must fail */
        brix_vfs_open_opts wo = { .io_uring = 0, .expected_size = 5, .cred = NULL };
        brix_vfs_file *w = NULL;
        int rc = brix_vfs_open(dst, XRDC_VFS_WRITE, &wo, &w, &s4);
        assert(rc != 0);
        assert(w == NULL);
        assert(s4.kxr != 0);
        unlink(dst);
        printf("vfs posix no-force guard OK\n");
    }

    /* Test 5: abort — temp removed, final never created */
    {
        brix_status s5 = {0};
        char dst[] = "/tmp/vfs_abort_XXXXXX";
        int afd = mkstemp(dst); assert(afd >= 0); close(afd); unlink(dst);

        brix_vfs_open_opts wo = { .io_uring = 0, .expected_size = 4, .cred = NULL };
        brix_vfs_file *w = NULL;
        assert(brix_vfs_open(dst, XRDC_VFS_WRITE | XRDC_VFS_FORCE, &wo, &w, &s5) == 0);
        assert(brix_vfs_pwrite(w, 0, "abcd", 4, &s5) == 0);
        brix_vfs_abort(w);
        brix_vfs_close(w);

        /* final path must not exist */
        assert(access(dst, F_OK) != 0);
        /* no .xrdvfs-tmp.* sibling must remain */
        {
            char tmp_glob[256];
            snprintf(tmp_glob, sizeof(tmp_glob), "%s.xrdvfs-tmp.*", dst);
            /* cheap existence check: build the expected temp name and verify gone */
            char tmp_path[256];
            snprintf(tmp_path, sizeof(tmp_path), "%s.xrdvfs-tmp.%ld",
                     dst, (long) getpid());
            assert(access(tmp_path, F_OK) != 0);
        }
        printf("vfs posix abort OK\n");
    }

    return 0;
}

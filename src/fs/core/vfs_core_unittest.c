/*
 * vfs_core_unittest.c — standalone unit test for the shared VFS I/O verbs.
 *
 * Built and run OUTSIDE the nginx tree (plain gcc), exercising xvfs_* over a
 * real temp fd wrapped in the POSIX storage driver. Verifies pwrite_full /
 * pread_full / pread_once / fstat / ftruncate / fsync / drain round-trip
 * correctly.
 *
 * Usage (-iquote, not -I, so sd.h's <time.h> resolves to the system header and
 * not the project's compat/time.h shadow):
 *   cd src/fs/core
 *   gcc -O2 -Wall -Wextra -Werror -D_GNU_SOURCE -DXRDPROTO_NO_NGX \
 *       -iquote ../../compat -iquote ../../protocol \
 *       -o /tmp/vfs_core_unittest \
 *       vfs_core.c ../backend/posix/sd_posix.c vfs_core_unittest.c
 *   /tmp/vfs_core_unittest
 */
#include "vfs_core.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_fail;

#define CHECK(cond, msg) do {                                  \
    if (cond) { printf("ok: %s\n", msg); }                    \
    else      { printf("FAIL: %s\n", msg); g_fail = 1; }     \
} while (0)

int main(void)
{
    char            tmpl[] = "/tmp/vfs_core_ut.XXXXXX";
    int             fd = mkstemp(tmpl);
    xrootd_sd_obj_t obj;
    unsigned char   src[4096];
    unsigned char   dst[4096];
    size_t          i, n = 0;
    int             sh = 0;
    ssize_t         r;
    xrootd_sd_stat_t st;

    if (fd < 0) { perror("mkstemp"); return 2; }
    for (i = 0; i < sizeof(src); i++) {
        src[i] = (unsigned char) ((i * 37 + 11) & 0xff);
    }
    xrootd_sd_posix_wrap(&obj, fd);

    /* full write */
    CHECK(xvfs_pwrite_full(&obj, src, sizeof(src), 0, &n, &sh) == 0,
          "pwrite_full returns 0");
    CHECK(n == sizeof(src) && sh == 0, "pwrite_full wrote all bytes, no short-io");

    /* full read back */
    memset(dst, 0, sizeof(dst));
    n = 0;
    CHECK(xvfs_pread_full(&obj, dst, sizeof(dst), 0, &n) == 0, "pread_full ok");
    CHECK(n == sizeof(src) && memcmp(src, dst, sizeof(src)) == 0,
          "pread_full round-trip identity");

    /* short read past EOF is success with n < len */
    n = 0;
    CHECK(xvfs_pread_full(&obj, dst, sizeof(dst), 2048, &n) == 0,
          "pread_full past-midpoint ok");
    CHECK(n == 2048, "pread_full short read at EOF reports partial count");

    /* single read */
    memset(dst, 0, sizeof(dst));
    r = xvfs_pread_once(&obj, dst, 512, 100);
    CHECK(r == 512 && memcmp(dst, src + 100, 512) == 0,
          "pread_once returns bytes + correct data");
    CHECK(xvfs_pread_once(&obj, dst, 512, (off_t) sizeof(src)) == 0,
          "pread_once at EOF returns 0");

    /* fstat */
    CHECK(xvfs_fstat(&obj, &st) == 0, "fstat ok");
    CHECK(st.size == (off_t) sizeof(src) && st.is_reg, "fstat size + is_reg");

    /* ftruncate + fstat */
    CHECK(xvfs_ftruncate(&obj, 1000) == 0, "ftruncate ok");
    CHECK(xvfs_fstat(&obj, &st) == 0 && st.size == 1000, "ftruncate shrank file");

    /* fsync */
    CHECK(xvfs_fsync(&obj) == 0, "fsync ok");

    /* drain: copy one object into another through the driver (chunked). Seed and
     * verify via the xvfs_* verbs (no raw POSIX) so the byte path stays on the
     * seam — a small drain buffer forces several pread->pwrite iterations. */
    {
        char            stmpl[] = "/tmp/vfs_core_drain_s.XXXXXX";
        char            dtmpl[] = "/tmp/vfs_core_drain_d.XXXXXX";
        int             sfd = mkstemp(stmpl);
        int             dfd = mkstemp(dtmpl);
        xrootd_sd_obj_t sobj, dobj;
        unsigned char   chk[4096];
        char            buf[1024];          /* small: forces multiple chunks */
        size_t          m = 0;
        int             msh = 0;
        off_t           total = 0;

        if (sfd < 0 || dfd < 0) { perror("mkstemp drain"); return 2; }
        xrootd_sd_posix_wrap(&sobj, sfd);
        xrootd_sd_posix_wrap(&dobj, dfd);

        CHECK(xvfs_pwrite_full(&sobj, src, sizeof(src), 0, &m, &msh) == 0
              && m == sizeof(src) && msh == 0, "drain: seed source");

        CHECK(xvfs_drain(&sobj, &dobj, buf, sizeof(buf), &total) == 0,
              "drain returns 0");
        CHECK(total == (off_t) sizeof(src), "drain reports full byte count");

        memset(chk, 0, sizeof(chk));
        m = 0;
        CHECK(xvfs_pread_full(&dobj, chk, sizeof(chk), 0, &m) == 0
              && m == sizeof(src), "drain: read dst back");
        CHECK(memcmp(src, chk, sizeof(src)) == 0, "drain: dst byte-identical");

        close(sfd); close(dfd); unlink(stmpl); unlink(dtmpl);
    }

    close(fd);
    unlink(tmpl);

    if (g_fail) { printf("\nVFS_CORE UNITTEST FAILED\n"); return 1; }
    printf("\nVFS_CORE UNITTEST PASSED\n");
    return 0;
}

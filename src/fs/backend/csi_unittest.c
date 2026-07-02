/*
 * csi_unittest.c — standalone unit test for the CSI page tagstore (phase-59 W2).
 *
 * Compiles with a thin xrootd_open_beneath() stub (opens under a real temp dir
 * via openat) so the tagstore + verify logic is exercised without nginx:
 *
 *   gcc -Wall -Wextra -Werror -I src -o /tmp/csi_ut \
 *       src/fs/backend/csi_unittest.c src/fs/backend/csi_tagstore.c \
 *       src/fs/backend/csi_verify.c src/compat/crc32c.c && /tmp/csi_ut
 *
 * Exit 0 = all checks pass.
 */

#include "csi_tagstore.h"
#include "compat/crc32c.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

/* stub: open the tag path under a fixed temp root via openat */int
xrootd_open_beneath(int rootfd, const char *reqpath, int flags, mode_t mode)
{
    /* mkdir any leading dirs so "/.xrdt/..." works */
    char tmp[4096];
    snprintf(tmp, sizeof(tmp), "%s", reqpath);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdirat(rootfd, tmp, 0700);
            *p = '/';
        }
    }
    return openat(rootfd, reqpath, flags, mode);
}

/* stub: confined mkdir for the tag prefix tree */int
xrootd_mkdir_beneath(int rootfd, const char *reqpath, mode_t mode)
{
    return mkdirat(rootfd, reqpath, mode);
}

static int g_checks, g_failed;
#define CHECK(c, m)                                                            \
    do {                                                                       \
        g_checks++;                                                            \
        if (!(c)) { g_failed++; fprintf(stderr, "FAIL: %s (line %d)\n", (m),   \
                                        __LINE__); }                           \
    } while (0)

int
main(void)
{
    char        tmpl[] = "/tmp/csi_ut_XXXXXX";
    char       *dir = mkdtemp(tmpl);
    int         rootfd;
    xrootd_csi_t c;
    unsigned char page[XROOTD_CSI_PAGE * 3];
    int         rc;

    if (dir == NULL) { perror("mkdtemp"); return 2; }
    rootfd = open(dir, O_RDONLY | O_DIRECTORY);
    if (rootfd < 0) { perror("open dir"); return 2; }

    /* fresh tag file for /data/a.bin under inline prefix "" */
    memset(&c, 0, sizeof(c));
    c.fill = 1;
    rc = xrootd_csi_open(&c, rootfd, "data/a.bin", "", 1);
    CHECK(rc == XROOTD_CSI_OK, "open creates tag file");

    /* 3 pages of distinct content */
    memset(page + 0 * XROOTD_CSI_PAGE, 'A', XROOTD_CSI_PAGE);
    memset(page + 1 * XROOTD_CSI_PAGE, 'B', XROOTD_CSI_PAGE);
    memset(page + 2 * XROOTD_CSI_PAGE, 'C', XROOTD_CSI_PAGE);

    rc = xrootd_csi_update_aligned(&c, page, 0, sizeof(page));
    CHECK(rc == XROOTD_CSI_OK, "update_aligned writes 3 tags");

    /* verify clean */
    rc = xrootd_csi_verify_read(&c, page, 0, sizeof(page));
    CHECK(rc == XROOTD_CSI_OK, "verify clean data passes");

    /* flip a byte in page 1 → mismatch */
    page[1 * XROOTD_CSI_PAGE + 10] = 'X';
    rc = xrootd_csi_verify_read(&c, page, 0, sizeof(page));
    CHECK(rc == XROOTD_CSI_MISMATCH, "corrupt page detected");

    /* restore and re-verify */
    page[1 * XROOTD_CSI_PAGE + 10] = 'B';
    rc = xrootd_csi_verify_read(&c, page, 0, sizeof(page));
    CHECK(rc == XROOTD_CSI_OK, "restored data verifies");

    /* store_pgcrc fast path: store the CRC for page 0, read it back */
    {
        uint32_t want = xrootd_crc32c_value(page, XROOTD_CSI_PAGE), got = 0;
        rc = xrootd_csi_store_pgcrc(&c, 0, want);
        CHECK(rc == XROOTD_CSI_OK, "store_pgcrc ok");
        CHECK(xrootd_csi_read_tags(&c, &got, 0, 1) == 1 && got == want,
              "stored client CRC round-trips");
    }
    xrootd_csi_sync_header(&c);
    xrootd_csi_close(&c);

    /* reopen (no create) reads the header back */
    memset(&c, 0, sizeof(c));
    rc = xrootd_csi_open(&c, rootfd, "data/a.bin", "", 0);
    CHECK(rc == XROOTD_CSI_OK, "reopen reads existing header");
    CHECK(c.tracked_len == sizeof(page), "tracked_len persisted");
    rc = xrootd_csi_verify_read(&c, page, 0, sizeof(page));
    CHECK(rc == XROOTD_CSI_OK, "verify after reopen passes");
    xrootd_csi_close(&c);

    /* short last page: 2.5 pages */
    memset(&c, 0, sizeof(c));
    c.fill = 1;
    xrootd_csi_open(&c, rootfd, "data/b.bin", "/.xrdt", 1);
    size_t partial = XROOTD_CSI_PAGE * 2 + 100;
    /* aligned update only does full pages; cover the short page via pgcrc */
    xrootd_csi_update_aligned(&c, page, 0, XROOTD_CSI_PAGE * 2);
    xrootd_csi_store_pgcrc(&c, 2, xrootd_crc32c_value(page + 2 * XROOTD_CSI_PAGE,
                                                      100));
    c.tracked_len = partial;
    rc = xrootd_csi_verify_read(&c, page, 0, partial);
    CHECK(rc == XROOTD_CSI_OK, "short last page verifies with exact length");
    xrootd_csi_close(&c);

    close(rootfd);
    printf("csi_unittest: %d checks, %d failed\n", g_checks, g_failed);
    return g_failed == 0 ? 0 : 1;
}

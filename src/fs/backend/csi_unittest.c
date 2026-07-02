/*
 * csi_unittest.c — standalone unit test for the CSI block-checksum engine
 * (xmeta P3: tags live in the file's unified metadata record).
 *
 * Compiles without nginx:
 *
 *   gcc -Wall -Wextra -Werror -I src -o /tmp/csi_ut \
 *       src/fs/backend/csi_unittest.c src/fs/backend/csi_tagstore.c \
 *       src/fs/backend/csi_verify.c src/fs/meta/xmeta.c \
 *       src/fs/meta/xmeta_path.c src/core/compat/crc32c.c && /tmp/csi_ut
 *
 * Exit 0 = all checks pass.
 */

#include "csi_tagstore.h"
#include "fs/meta/xmeta_path.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int g_checks, g_failed;

#define CHECK(cond, name) do { \
    g_checks++; \
    if (cond) { printf("  ok   %s\n", name); } \
    else      { printf("  FAIL %s (line %d)\n", name, __LINE__); g_failed++; } \
} while (0)

#define G 4096u   /* small granule so the test file stays tiny */

static void
write_file(const char *path, const unsigned char *data, size_t len)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);

    if (fd < 0 || write(fd, data, len) != (ssize_t) len) {
        perror("write_file");
        exit(2);
    }
    close(fd);
}

int
main(void)
{
    char dir[] = "/tmp/csi_ut.XXXXXX";
    char path[4400];
    unsigned char data[3 * G];   /* 3 full blocks */
    xrootd_csi_t w, r;
    size_t i;

    if (mkdtemp(dir) == NULL) {
        perror("mkdtemp");
        return 2;
    }
    snprintf(path, sizeof(path), "%s/a.bin", dir);
    for (i = 0; i < sizeof(data); i++) {
        data[i] = (unsigned char) (i * 31u + 7u);
    }
    write_file(path, data, sizeof(data));

    /* ---- write handle: fold + flush creates the record ---- */
    CHECK(xrootd_csi_open(&w, path, G, 1) == XROOTD_CSI_OK, "write open");
    CHECK(xrootd_csi_write_update(&w, data, 0, sizeof(data)) == XROOTD_CSI_OK,
          "fold 3 aligned blocks");
    CHECK(xrootd_csi_flush(&w) == XROOTD_CSI_OK, "flush writes the record");
    xrootd_csi_close(&w);

    /* the record is the file's own xmeta (xattr or sidecar) */
    {
        xrootd_xmeta_t xm;

        CHECK(xrootd_xmeta_path_load(path, &xm) == XROOTD_XMETA_OK
              && xm.have_blockcrc && xm.blockcrc != NULL
              && xm.buffer_size == (int64_t) G && xm.nblocks == 3
              && xm.blockcrc[0] != 0 && xm.blockcrc[1] != 0
              && xm.blockcrc[2] != 0,
              "record holds 3 computed block CRCs");
        CHECK(xm.no_cksum_time == 0, "fully tagged: no_cksum_time clear");
        xrootd_xmeta_free(&xm);
    }

    /* ---- read handle: verify clean / corrupt / restored ---- */
    CHECK(xrootd_csi_open(&r, path, G, 0) == XROOTD_CSI_OK,
          "read open sees a verifiable record");
    CHECK(xrootd_csi_verify_read(&r, data, 0, sizeof(data)) == XROOTD_CSI_OK,
          "verify clean data passes");

    data[G + 10] ^= 0xFF;   /* corrupt block 1 */
    CHECK(xrootd_csi_verify_read(&r, data, 0, sizeof(data))
              == XROOTD_CSI_MISMATCH, "corrupt block detected");
    CHECK(xrootd_csi_verify_read(&r, data, 0, G) == XROOTD_CSI_OK,
          "read not spanning the bad block passes");
    CHECK(xrootd_csi_verify_read(&r, data + G, G, G)
              == XROOTD_CSI_MISMATCH, "exact bad-block read fails");
    /* a read only PARTIALLY covering the bad block skips it (hot-path rule) */
    CHECK(xrootd_csi_verify_read(&r, data + G, G, G / 2) == XROOTD_CSI_OK,
          "partial-edge block is not verified");

    /* trust_fs bypass */
    r.trust_fs = 1;
    CHECK(xrootd_csi_verify_read(&r, data, 0, sizeof(data)) == XROOTD_CSI_OK,
          "trust_fs skips verify on corrupt block");
    r.trust_fs = 0;

    data[G + 10] ^= 0xFF;   /* restore */
    CHECK(xrootd_csi_verify_read(&r, data, 0, sizeof(data)) == XROOTD_CSI_OK,
          "restored data verifies");
    xrootd_csi_close(&r);

    /* ---- unaligned write: edge blocks recomputed at flush ---- */
    memset(data + 100, 0x5A, G);          /* mutate an unaligned window */
    write_file(path, data, sizeof(data));
    CHECK(xrootd_csi_open(&w, path, G, 1) == XROOTD_CSI_OK, "reopen write");
    CHECK(xrootd_csi_write_update(&w, data + 100, 100, G) == XROOTD_CSI_OK,
          "fold unaligned write (no full block covered)");
    CHECK(xrootd_csi_flush(&w) == XROOTD_CSI_OK, "flush recomputes edges");
    xrootd_csi_close(&w);
    CHECK(xrootd_csi_open(&r, path, G, 0) == XROOTD_CSI_OK, "read reopen");
    CHECK(xrootd_csi_verify_read(&r, data, 0, sizeof(data)) == XROOTD_CSI_OK,
          "post-unaligned-write data verifies");
    xrootd_csi_close(&r);

    /* ---- growth: flush re-geometries the record ---- */
    {
        unsigned char *big = malloc(5 * G);

        memcpy(big, data, sizeof(data));
        memset(big + 3 * G, 0xA5, 2 * G);
        write_file(path, big, 5 * G);
        xrootd_csi_open(&w, path, G, 1);
        xrootd_csi_write_update(&w, big + 3 * G, 3 * G, 2 * G);
        CHECK(xrootd_csi_flush(&w) == XROOTD_CSI_OK, "flush after growth");
        xrootd_csi_close(&w);
        {
            xrootd_xmeta_t xm;

            CHECK(xrootd_xmeta_path_load(path, &xm) == XROOTD_XMETA_OK
                  && xm.nblocks == 5 && xm.file_size == 5 * G,
                  "record re-geometried to 5 blocks");
            xrootd_xmeta_free(&xm);
        }
        CHECK(xrootd_csi_open(&r, path, G, 0) == XROOTD_CSI_OK, "read grown");
        CHECK(xrootd_csi_verify_read(&r, big, 0, 5 * G) == XROOTD_CSI_OK,
              "grown file verifies end-to-end");
        xrootd_csi_close(&r);
        free(big);
    }

    /* ---- no record: read open reports NOTAGS ---- */
    {
        char p2[4400];
        xrootd_csi_t n;

        snprintf(p2, sizeof(p2), "%s/naked.bin", dir);
        write_file(p2, data, G);
        CHECK(xrootd_csi_open(&n, p2, G, 0) == XROOTD_CSI_NOTAGS,
              "unrecorded file reads as NOTAGS (csi_require gate)");
    }

    printf("csi_unittest: %d checks, %d failed\n", g_checks, g_failed);
    return g_failed == 0 ? 0 : 1;
}

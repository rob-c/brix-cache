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
    brix_csi_t w, r;
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
    CHECK(brix_csi_open(&w, path, G, 1) == BRIX_CSI_OK, "write open");
    CHECK(brix_csi_write_update(&w, data, 0, sizeof(data)) == BRIX_CSI_OK,
          "fold 3 aligned blocks");
    CHECK(brix_csi_flush(&w) == BRIX_CSI_OK, "flush writes the record");
    brix_csi_close(&w);

    /* the record is the file's own xmeta (xattr or sidecar) */
    {
        brix_xmeta_t xm;

        CHECK(brix_xmeta_path_load(path, &xm) == BRIX_XMETA_OK
              && xm.have_blockcrc && xm.blockcrc != NULL
              && xm.buffer_size == (int64_t) G && xm.nblocks == 3
              && xm.blockcrc[0] != 0 && xm.blockcrc[1] != 0
              && xm.blockcrc[2] != 0,
              "record holds 3 computed block CRCs");
        CHECK(xm.no_cksum_time == 0, "fully tagged: no_cksum_time clear");
        brix_xmeta_free(&xm);
    }

    /* ---- read handle: verify clean / corrupt / restored ---- */
    CHECK(brix_csi_open(&r, path, G, 0) == BRIX_CSI_OK,
          "read open sees a verifiable record");
    CHECK(brix_csi_verify_read(&r, data, 0, sizeof(data)) == BRIX_CSI_OK,
          "verify clean data passes");

    data[G + 10] ^= 0xFF;   /* corrupt block 1 */
    CHECK(brix_csi_verify_read(&r, data, 0, sizeof(data))
              == BRIX_CSI_MISMATCH, "corrupt block detected");
    CHECK(brix_csi_verify_read(&r, data, 0, G) == BRIX_CSI_OK,
          "read not spanning the bad block passes");
    CHECK(brix_csi_verify_read(&r, data + G, G, G)
              == BRIX_CSI_MISMATCH, "exact bad-block read fails");
    /* a read only PARTIALLY covering the bad block skips it (hot-path rule) */
    CHECK(brix_csi_verify_read(&r, data + G, G, G / 2) == BRIX_CSI_OK,
          "partial-edge block is not verified");

    /* trust_fs bypass */
    r.trust_fs = 1;
    CHECK(brix_csi_verify_read(&r, data, 0, sizeof(data)) == BRIX_CSI_OK,
          "trust_fs skips verify on corrupt block");
    r.trust_fs = 0;

    data[G + 10] ^= 0xFF;   /* restore */
    CHECK(brix_csi_verify_read(&r, data, 0, sizeof(data)) == BRIX_CSI_OK,
          "restored data verifies");
    brix_csi_close(&r);

    /* ---- unaligned write: edge blocks recomputed at flush ---- */
    memset(data + 100, 0x5A, G);          /* mutate an unaligned window */
    write_file(path, data, sizeof(data));
    CHECK(brix_csi_open(&w, path, G, 1) == BRIX_CSI_OK, "reopen write");
    CHECK(brix_csi_write_update(&w, data + 100, 100, G) == BRIX_CSI_OK,
          "fold unaligned write (no full block covered)");
    CHECK(brix_csi_flush(&w) == BRIX_CSI_OK, "flush recomputes edges");
    brix_csi_close(&w);
    CHECK(brix_csi_open(&r, path, G, 0) == BRIX_CSI_OK, "read reopen");
    CHECK(brix_csi_verify_read(&r, data, 0, sizeof(data)) == BRIX_CSI_OK,
          "post-unaligned-write data verifies");
    brix_csi_close(&r);

    /* ---- growth: flush re-geometries the record ---- */
    {
        unsigned char *big = malloc(5 * G);

        memcpy(big, data, sizeof(data));
        memset(big + 3 * G, 0xA5, 2 * G);
        write_file(path, big, 5 * G);
        brix_csi_open(&w, path, G, 1);
        brix_csi_write_update(&w, big + 3 * G, 3 * G, 2 * G);
        CHECK(brix_csi_flush(&w) == BRIX_CSI_OK, "flush after growth");
        brix_csi_close(&w);
        {
            brix_xmeta_t xm;

            CHECK(brix_xmeta_path_load(path, &xm) == BRIX_XMETA_OK
                  && xm.nblocks == 5 && xm.file_size == 5 * G,
                  "record re-geometried to 5 blocks");
            brix_xmeta_free(&xm);
        }
        CHECK(brix_csi_open(&r, path, G, 0) == BRIX_CSI_OK, "read grown");
        CHECK(brix_csi_verify_read(&r, big, 0, 5 * G) == BRIX_CSI_OK,
              "grown file verifies end-to-end");
        brix_csi_close(&r);
        free(big);
    }

    /* ---- load-once: a read handle snapshots the record at open and keeps
     * verifying against it even after the on-disk record is removed. A per-read
     * reload implementation would see no record and stop catching corruption —
     * this is the regression guard for the multi-threaded read hot path. ---- */
    {
        char p3[4400];
        brix_csi_t rc;
        unsigned char d3[2 * G];
        size_t k;

        for (k = 0; k < sizeof(d3); k++) {
            d3[k] = (unsigned char) (k * 17u + 3u);
        }
        snprintf(p3, sizeof(p3), "%s/cached.bin", dir);
        write_file(p3, d3, sizeof(d3));

        CHECK(brix_csi_open(&w, p3, G, 1) == BRIX_CSI_OK, "cached: write open");
        CHECK(brix_csi_write_update(&w, d3, 0, sizeof(d3)) == BRIX_CSI_OK,
              "cached: fold blocks");
        CHECK(brix_csi_flush(&w) == BRIX_CSI_OK, "cached: flush writes record");
        brix_csi_close(&w);

        CHECK(brix_csi_open(&rc, p3, G, 0) == BRIX_CSI_OK,
              "cached: read open loads the record once");
        /* Drop both on-disk carriers: a load-once handle keeps its snapshot. */
        brix_xmeta_path_remove(p3);
        CHECK(brix_csi_verify_read(&rc, d3, 0, sizeof(d3)) == BRIX_CSI_OK,
              "cached: clean verify survives record removal (load-once)");
        d3[G + 5] ^= 0xFF;   /* corrupt block 1 */
        CHECK(brix_csi_verify_read(&rc, d3, 0, sizeof(d3)) == BRIX_CSI_MISMATCH,
              "cached: corruption still caught after removal (load-once)");
        brix_csi_close(&rc);
    }

    /* ---- no record: read open reports NOTAGS ---- */
    {
        char p2[4400];
        brix_csi_t n;

        snprintf(p2, sizeof(p2), "%s/naked.bin", dir);
        write_file(p2, data, G);
        CHECK(brix_csi_open(&n, p2, G, 0) == BRIX_CSI_NOTAGS,
              "unrecorded file reads as NOTAGS (csi_require gate)");
    }

    printf("csi_unittest: %d checks, %d failed\n", g_checks, g_failed);
    return g_failed == 0 ? 0 : 1;
}

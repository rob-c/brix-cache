/*
 * test_csi_scrub.c — standalone unit test for the paced CSI scrub engine
 * (phase-59 W2b). Compiles without nginx:
 *
 *   gcc -O -Wall -Wextra -Werror -DXRDPROTO_NO_NGX -I src -o /tmp/csi_scrub_ut \
 *       tests/c/test_csi_scrub.c src/fs/backend/csi_scrub.c \
 *       src/fs/backend/csi_tagstore.c src/fs/backend/csi_verify.c \
 *       src/fs/meta/xmeta.c src/fs/meta/xmeta_path.c \
 *       src/core/compat/crc32c.c src/core/compat/crc32c_hw.c && /tmp/csi_scrub_ut
 *
 * Exit 0 = all checks pass.
 */

#include "fs/backend/csi_scrub.h"
#include "fs/backend/csi_tagstore.h"

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

#define G 4096u   /* small granule so the test files stay tiny */

/* Report sink: record the last corrupt block seen + count. */
struct rep { int n; uint64_t last_block; uint32_t want, got; char path[256]; };

static void
on_mismatch(void *u, const char *path, uint64_t block, uint32_t want,
    uint32_t got)
{
    struct rep *r = u;

    r->n++;
    r->last_block = block;
    r->want = want;
    r->got  = got;
    snprintf(r->path, sizeof(r->path), "%s", path);
}

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

/* Tag a data file by folding it through a write handle and flushing. */
static void
tag_file(const char *path, const unsigned char *data, size_t len)
{
    brix_csi_t w;

    if (brix_csi_open(&w, path, G, 1) != BRIX_CSI_OK
        || brix_csi_write_update(&w, data, 0, len) != BRIX_CSI_OK
        || brix_csi_flush(&w) != BRIX_CSI_OK)
    {
        fprintf(stderr, "tag_file failed for %s\n", path);
        exit(2);
    }
    brix_csi_close(&w);
}

/* Flip one byte at absolute offset in an existing file (on-disk corruption
 * the hot read path would only catch on a fully-spanning read). */
static void
poke(const char *path, off_t off)
{
    unsigned char b;
    int fd = open(path, O_RDWR);

    if (fd < 0 || pread(fd, &b, 1, off) != 1) { perror("poke"); exit(2); }
    b ^= 0xFF;
    if (pwrite(fd, &b, 1, off) != 1) { perror("poke"); exit(2); }
    close(fd);
}

int
main(void)
{
    char dir[] = "/tmp/csi_scrub_ut.XXXXXX";
    char clean[4400], rot[4400], naked[4400], sub[4400], subfile[4500];
    unsigned char data[3 * G];
    brix_csi_scrub_stats_t st;
    struct rep r;
    size_t i;
    long scanned;

    if (mkdtemp(dir) == NULL) { perror("mkdtemp"); return 2; }
    for (i = 0; i < sizeof(data); i++) {
        data[i] = (unsigned char) (i * 31u + 7u);
    }
    snprintf(clean, sizeof(clean), "%s/clean.bin", dir);
    snprintf(rot,   sizeof(rot),   "%s/rot.bin",   dir);
    snprintf(naked, sizeof(naked), "%s/naked.bin", dir);
    snprintf(sub,   sizeof(sub),   "%s/sub",       dir);

    /* ---- scrub_file: a clean tagged file passes ---- */
    write_file(clean, data, sizeof(data));
    tag_file(clean, data, sizeof(data));
    memset(&st, 0, sizeof(st));
    memset(&r, 0, sizeof(r));
    CHECK(brix_csi_scrub_file(clean, &st, on_mismatch, &r) == BRIX_CSI_OK,
          "clean tagged file scrubs OK");
    CHECK(st.files_tagged == 1 && st.blocks_verified == 3
          && st.mismatches == 0 && r.n == 0,
          "clean: 3 blocks verified, 0 mismatch, no report");

    /* ---- scrub_file: on-disk corruption in block 1 is caught ---- */
    write_file(rot, data, sizeof(data));
    tag_file(rot, data, sizeof(data));
    poke(rot, G + 10);                       /* corrupt block 1 on disk */
    memset(&st, 0, sizeof(st));
    memset(&r, 0, sizeof(r));
    CHECK(brix_csi_scrub_file(rot, &st, on_mismatch, &r) == BRIX_CSI_MISMATCH,
          "rotted file scrubs MISMATCH");
    CHECK(st.mismatches == 1 && st.blocks_verified == 2,
          "rot: exactly block 1 corrupt, blocks 0+2 verify");
    CHECK(r.n == 1 && r.last_block == 1 && r.want != r.got
          && strcmp(r.path, rot) == 0,
          "rot: report fired once for block 1 with the offending path");

    /* ---- scrub_file: an untagged file reads as NOTAGS, not an error ---- */
    write_file(naked, data, G);
    memset(&st, 0, sizeof(st));
    CHECK(brix_csi_scrub_file(naked, &st, NULL, NULL) == BRIX_CSI_NOTAGS,
          "untagged file scrubs NOTAGS");
    CHECK(st.files_scanned == 1 && st.files_tagged == 0 && st.errors == 0,
          "notags: scanned but not tagged, no error");

    /* ---- scrub_file: a missing path is a hard error ---- */
    memset(&st, 0, sizeof(st));
    CHECK(brix_csi_scrub_file("/nonexistent/csi/scrub/path", &st, NULL, NULL)
              == BRIX_CSI_NOTAGS,
          "absent file: no record => NOTAGS (never crashes)");

    /* ---- walk: recurses, totals every file, reports the rot ---- */
    if (mkdir(sub, 0755) != 0) { perror("mkdir"); return 2; }
    snprintf(subfile, sizeof(subfile), "%s/deep.bin", sub);
    write_file(subfile, data, sizeof(data));
    tag_file(subfile, data, sizeof(data));
    memset(&st, 0, sizeof(st));
    memset(&r, 0, sizeof(r));
    scanned = brix_csi_scrub_walk(dir, &st, 0, on_mismatch, &r);
    CHECK(scanned == 4, "walk visits all 4 regular files (incl. subdir)");
    CHECK(st.files_tagged == 3 && st.mismatches == 1 && r.n == 1,
          "walk: 3 tagged, the single on-disk rot surfaced once");

    /* ---- walk: budget caps the files scanned this call (pacing knob) ---- */
    memset(&st, 0, sizeof(st));
    scanned = brix_csi_scrub_walk(dir, &st, 2, NULL, NULL);
    CHECK(scanned == 2 && st.files_scanned == 2,
          "walk budget=2 stops after 2 files");

    /* ---- walk: absent root is a clean no-op ---- */
    memset(&st, 0, sizeof(st));
    CHECK(brix_csi_scrub_walk("/no/such/root", &st, 0, NULL, NULL) == 0
          && st.files_scanned == 0,
          "walk on a missing root scans nothing");

    printf("test_csi_scrub: %d checks, %d failed\n", g_checks, g_failed);
    return g_failed == 0 ? 0 : 1;
}

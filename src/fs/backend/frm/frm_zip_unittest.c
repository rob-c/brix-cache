/*
 * frm_zip_unittest.c — standalone checks for the store-only ZIP32 container
 *
 * WHAT: round-trips members through frm_zip.c and probes the reader against
 *       hostile input (path-escaping names, corrupted bytes, non-archives).
 *
 * WHY:  the archiver trusts this container for byte-exact recall from tape;
 *       a wrong offset or an accepted "../" name would silently corrupt or
 *       escape a dataset. Runs without nginx (see tests/test_phase115_tape_arc.py).
 *
 * HOW:  cc -Wall -Wextra -Werror -I src -o t frm_zip_unittest.c frm_zip.c \
 *          core/compat/crc32_ieee.c && ./t  → "all checks passed"
 */

#include "frm_zip.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int g_checks, g_failed;

#define CHECK(cond, name)                                                   \
    do {                                                                    \
        g_checks++;                                                         \
        if (!(cond)) {                                                      \
            g_failed++;                                                     \
            fprintf(stderr, "FAIL %s (%s:%d)\n", name, __FILE__, __LINE__); \
        }                                                                   \
    } while (0)

static int
tmp_fd(void)
{
    const char *dir = getenv("TMPDIR");
    char        path[4096];
    int         fd;

    snprintf(path, sizeof(path), "%s/frm_zip_ut.XXXXXX", dir ? dir : "/tmp");
    fd = mkstemp(path);
    if (fd >= 0) {
        unlink(path);
    }
    return fd;
}

static int
fd_with(const char *data, size_t len)
{
    int fd = tmp_fd();

    if (fd >= 0 && len > 0 && pwrite(fd, data, len, 0) != (ssize_t) len) {
        return -1;
    }
    return fd;
}

static int
add_member(brix_zip_writer_t *w, const char *name, const char *data, size_t len)
{
    int fd = fd_with(data, len);
    int rc;

    if (fd < 0) {
        return -1;
    }
    rc = brix_zip_writer_add(w, name, fd, len, NULL);
    close(fd);
    return rc;
}

typedef struct {
    brix_zip_entry_t e[8];
    unsigned         n;
} index_t;

static int
collect(void *ud, const brix_zip_entry_t *e)
{
    index_t *ix = ud;

    if (ix->n < 8) {
        ix->e[ix->n++] = *e;
    }
    return 0;
}

static int
extract_equals(int zfd, const brix_zip_entry_t *e, const char *want, size_t len)
{
    char buf[256];
    int  dst = tmp_fd();
    int  ok;

    if (dst < 0 || brix_zip_extract(zfd, e, dst) != 0) {
        if (dst >= 0) {
            close(dst);
        }
        return 0;
    }
    ok = (pread(dst, buf, sizeof(buf), 0) == (ssize_t) len && memcmp(buf, want, len) == 0);
    close(dst);
    return ok;
}

static const char A[] = "alpha-alpha-alpha";
static const char B[] = "bravo";
static const char C[] = "";                         /* an empty member is legal */

static int
build_archive(void)
{
    int                fd = tmp_fd();
    brix_zip_writer_t *w = brix_zip_writer_open(fd);

    CHECK(w != NULL, "writer open");
    CHECK(add_member(w, "a.bin", A, sizeof(A) - 1) == 0, "add a.bin");
    CHECK(add_member(w, "sub/b.bin", B, sizeof(B) - 1) == 0, "add sub/b.bin");
    CHECK(add_member(w, "c.txt", C, 0) == 0, "add empty c.txt");
    CHECK(brix_zip_writer_count(w) == 3, "writer count 3");
    CHECK(brix_zip_writer_entry(w, 1)->size == sizeof(B) - 1, "entry 1 size");
    CHECK(brix_zip_writer_finish(w) == 0, "finish");
    brix_zip_writer_close(w);
    return fd;
}

static void
test_round_trip(void)
{
    int      fd = build_archive();
    index_t  ix = { { { { 0 }, 0, 0, 0 } }, 0 };
    unsigned skipped = 99;

    CHECK(brix_zip_index(fd, collect, &ix, &skipped) == 0, "index ok");
    CHECK(skipped == 0, "nothing skipped");
    CHECK(ix.n == 3, "three entries");
    CHECK(strcmp(ix.e[0].name, "a.bin") == 0 && strcmp(ix.e[1].name, "sub/b.bin") == 0
          && strcmp(ix.e[2].name, "c.txt") == 0, "directory order preserved");
    CHECK(ix.e[0].lfh_off == 0 && ix.e[1].lfh_off == 30 + 5 + sizeof(A) - 1, "local header offsets");
    CHECK(extract_equals(fd, &ix.e[0], A, sizeof(A) - 1), "extract a.bin byte-exact");
    CHECK(extract_equals(fd, &ix.e[1], B, sizeof(B) - 1), "extract sub/b.bin byte-exact");
    CHECK(extract_equals(fd, &ix.e[2], C, 0), "extract empty member");
    close(fd);
}

/* A foreign tool rewrites one directory name to "../xy" (same length): the
 * reader must skip it, count it, and still serve the others. */
static void
test_unsafe_name_skipped(void)
{
    int         fd = build_archive();
    struct stat sb;
    uint8_t    *img;
    size_t      i;
    index_t     ix = { { { { 0 }, 0, 0, 0 } }, 0 };
    unsigned    skipped = 0;
    int         patched = 0;

    fstat(fd, &sb);
    img = malloc((size_t) sb.st_size);
    CHECK(pread(fd, img, (size_t) sb.st_size, 0) == sb.st_size, "read image");
    /* the central-directory copy of "a.bin" follows the last local header */
    for (i = (size_t) sb.st_size - 46; i > 0 && !patched; i--) {
        if (memcmp(img + i, "PK\x01\x02", 4) == 0 && memcmp(img + i + 46, "a.bin", 5) == 0) {
            memcpy(img + i + 46, "../xy", 5);
            patched = 1;
        }
    }
    CHECK(patched, "found a.bin in the central directory");
    CHECK(pwrite(fd, img, (size_t) sb.st_size, 0) == sb.st_size, "write patched image");
    free(img);

    CHECK(brix_zip_index(fd, collect, &ix, &skipped) == 0, "index of patched archive ok");
    CHECK(skipped == 1, "one unsafe entry skipped");
    CHECK(ix.n == 2 && strcmp(ix.e[0].name, "sub/b.bin") == 0, "safe entries still served");
    CHECK(extract_equals(fd, &ix.e[0], B, sizeof(B) - 1), "extract after skip still byte-exact");
    close(fd);
}

static void
test_corruption_detected(void)
{
    int      fd = build_archive();
    index_t  ix = { { { { 0 }, 0, 0, 0 } }, 0 };
    uint8_t  byte;
    int      dst;

    CHECK(brix_zip_index(fd, collect, &ix, NULL) == 0, "index before corruption");
    /* flip one payload byte of a.bin (data starts after the 30+5-byte header) */
    CHECK(pread(fd, &byte, 1, 35 + 3) == 1, "read payload byte");
    byte ^= 0x5a;
    CHECK(pwrite(fd, &byte, 1, 35 + 3) == 1, "corrupt payload byte");
    dst = tmp_fd();
    errno = 0;
    CHECK(brix_zip_extract(fd, &ix.e[0], dst) == -1 && errno == EIO, "extract of corrupted member -> EIO");
    CHECK(extract_equals(fd, &ix.e[1], B, sizeof(B) - 1), "other member unaffected");
    close(dst);
    close(fd);
}

static void
test_limits_and_names(void)
{
    int                fd = tmp_fd();
    brix_zip_writer_t *w = brix_zip_writer_open(fd);
    char               longname[BRIX_ZIP_NAME_MAX + 8];

    errno = 0;
    CHECK(brix_zip_writer_add(w, "huge.bin", -1, 0xffffffffull, NULL) == -1 && errno == EFBIG,
          "4 GiB member -> EFBIG before any read");
    errno = 0;
    CHECK(brix_zip_writer_add(w, "../escape", -1, 1, NULL) == -1 && errno == EINVAL, "writer refuses ../");
    brix_zip_writer_close(w);
    close(fd);

    CHECK(brix_zip_name_ok("a/b/c.txt") == 1, "plain nested name ok");
    CHECK(brix_zip_name_ok(".hidden") == 1, "dotfile ok");
    CHECK(brix_zip_name_ok("") == 0, "empty rejected");
    CHECK(brix_zip_name_ok("/abs") == 0, "leading slash rejected");
    CHECK(brix_zip_name_ok("dir/") == 0, "trailing slash rejected");
    CHECK(brix_zip_name_ok("a//b") == 0, "empty segment rejected");
    CHECK(brix_zip_name_ok("a/./b") == 0, "dot segment rejected");
    CHECK(brix_zip_name_ok("a/../b") == 0, "dotdot segment rejected");
    CHECK(brix_zip_name_ok("..") == 0, "bare dotdot rejected");
    CHECK(brix_zip_name_ok("a\\b") == 0, "backslash rejected");
    CHECK(brix_zip_name_ok("a\nb") == 0, "control byte rejected");
    memset(longname, 'x', sizeof(longname) - 1);
    longname[sizeof(longname) - 1] = '\0';
    CHECK(brix_zip_name_ok(longname) == 0, "over-long name rejected");
}

static void
test_not_an_archive(void)
{
    static const char junk[] = "this is not a zip file at all, just some bytes......";
    int               fd = fd_with(junk, sizeof(junk) - 1);
    int               empty = tmp_fd();
    index_t           ix = { { { { 0 }, 0, 0, 0 } }, 0 };

    errno = 0;
    CHECK(brix_zip_index(fd, collect, &ix, NULL) == -1 && errno == EINVAL, "junk -> EINVAL");
    errno = 0;
    CHECK(brix_zip_index(empty, collect, &ix, NULL) == -1 && errno == EINVAL, "empty file -> EINVAL");
    close(fd);
    close(empty);
}

static void
test_empty_archive(void)
{
    int                fd = tmp_fd();
    brix_zip_writer_t *w = brix_zip_writer_open(fd);
    index_t            ix = { { { { 0 }, 0, 0, 0 } }, 0 };
    unsigned           skipped = 7;

    CHECK(brix_zip_writer_finish(w) == 0, "finish empty archive");
    brix_zip_writer_close(w);
    CHECK(brix_zip_index(fd, collect, &ix, &skipped) == 0 && ix.n == 0 && skipped == 0,
          "empty archive indexes to zero entries");
    close(fd);
}

int
main(void)
{
    test_round_trip();
    test_unsafe_name_skipped();
    test_corruption_detected();
    test_limits_and_names();
    test_not_an_archive();
    test_empty_archive();
    if (g_failed) {
        printf("%d of %d checks FAILED\n", g_failed, g_checks);
        return 1;
    }
    printf("all checks passed (%d)\n", g_checks);
    return 0;
}

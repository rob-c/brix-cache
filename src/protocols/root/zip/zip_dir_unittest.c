/*
 * zip_dir_unittest.c — standalone unit test for xrootd_zip_find_member().
 *
 * Built and run OUTSIDE the nginx tree (plain gcc + -lz), so it verifies the
 * pure parser without the module build or any contested hot-path files.
 *
 * Usage: zip_dir_unittest <archive.zip>
 * Expects these members (created by the companion generator):
 *   stored.txt   (method 0)  == "hello stored member\n"
 *   sub/defl.bin (method 8)  == 100000 bytes of 0xAB-ish pattern (see generator)
 *   missing.xyz  (absent)
 * Verifies: resolution, method, sizes, and that the bytes at data_off
 * decompress to the expected content (proving data_off + comp_size are right).
 */
#include "zip_dir.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <zlib.h>

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); failures++; } \
    else { printf("ok: %s\n", msg); } } while (0)

/* Read the member's raw bytes at data_off and decompress (store=copy,
 * deflate=raw inflate); compare to want/want_len. Returns 1 on match. */
static int verify_content(int fd, const xrootd_zip_member_t *m,
                          const unsigned char *want, size_t want_len)
{
    unsigned char *comp = malloc(m->comp_size ? m->comp_size : 1);
    unsigned char *out  = malloc(m->uncomp_size ? m->uncomp_size : 1);
    int ok = 0;

    if (pread(fd, comp, m->comp_size, (off_t) m->data_off)
        != (ssize_t) m->comp_size) {
        goto done;
    }
    if (m->uncomp_size != want_len) {
        goto done;
    }
    if (m->method == XROOTD_ZIP_METHOD_STORE) {
        ok = (memcmp(comp, want, want_len) == 0);
    } else {
        z_stream zs;
        memset(&zs, 0, sizeof(zs));
        /* -15 = raw deflate, no zlib header (ZIP member framing). */
        if (inflateInit2(&zs, -15) != Z_OK) {
            goto done;
        }
        zs.next_in = comp;  zs.avail_in = (uInt) m->comp_size;
        zs.next_out = out;  zs.avail_out = (uInt) m->uncomp_size;
        int zr = inflate(&zs, Z_FINISH);
        inflateEnd(&zs);
        ok = (zr == Z_STREAM_END
              && zs.total_out == want_len
              && memcmp(out, want, want_len) == 0);
    }
done:
    free(comp);
    free(out);
    return ok;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <archive.zip>\n", argv[0]);
        return 2;
    }
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) { perror("open"); return 2; }
    struct stat st;
    if (fstat(fd, &st) != 0) { perror("fstat"); return 2; }

    xrootd_zip_member_t m;
    int rc;

    /* 1. stored member resolves + content matches. */
    rc = xrootd_zip_find_member(fd, st.st_size, "stored.txt", 16u << 20, &m);
    CHECK(rc == XROOTD_ZIP_OK, "stored.txt found");
    if (rc == XROOTD_ZIP_OK) {
        const char *want = "hello stored member\n";
        CHECK(m.method == XROOTD_ZIP_METHOD_STORE, "stored.txt method=store");
        CHECK(m.uncomp_size == strlen(want), "stored.txt uncomp size");
        CHECK(verify_content(fd, &m, (const unsigned char *) want, strlen(want)),
              "stored.txt bytes at data_off match");
    }

    /* 2. deflate member resolves + inflates to expected content. */
    rc = xrootd_zip_find_member(fd, st.st_size, "sub/defl.bin", 16u << 20, &m);
    CHECK(rc == XROOTD_ZIP_OK, "sub/defl.bin found");
    if (rc == XROOTD_ZIP_OK) {
        size_t n = 100000;
        unsigned char *want = malloc(n);
        for (size_t i = 0; i < n; i++) want[i] = (unsigned char) ((i * 31 + 7) & 0xff);
        CHECK(m.method == XROOTD_ZIP_METHOD_DEFLATE, "sub/defl.bin method=deflate");
        CHECK(m.uncomp_size == n, "sub/defl.bin uncomp size");
        CHECK(m.comp_size < n, "sub/defl.bin actually compressed");
        CHECK(verify_content(fd, &m, want, n),
              "sub/defl.bin inflates to expected content");
        free(want);
    }

    /* 2b. ZIP64-forced member: exercises the saturated-size → zip64-extra path. */
    rc = xrootd_zip_find_member(fd, st.st_size, "big64.txt", 16u << 20, &m);
    CHECK(rc == XROOTD_ZIP_OK, "big64.txt (zip64 extra) found");
    if (rc == XROOTD_ZIP_OK) {
        const char *want = "zip64 forced member\n";
        CHECK(m.uncomp_size == strlen(want), "big64.txt zip64 uncomp size");
        CHECK(verify_content(fd, &m, (const unsigned char *) want, strlen(want)),
              "big64.txt bytes at data_off match");
    }

    /* 3. missing member → NOMEMBER. */
    rc = xrootd_zip_find_member(fd, st.st_size, "missing.xyz", 16u << 20, &m);
    CHECK(rc == XROOTD_ZIP_NOMEMBER, "missing.xyz → NOMEMBER");

    /* 4. traversal / bad names rejected. */
    rc = xrootd_zip_find_member(fd, st.st_size, "", 16u << 20, &m);
    CHECK(rc == XROOTD_ZIP_ECORRUPT, "empty name rejected");

    /* 5. tiny cd_max bomb guard trips on a real (larger) central directory. */
    rc = xrootd_zip_find_member(fd, st.st_size, "stored.txt", 4, &m);
    CHECK(rc == XROOTD_ZIP_ECORRUPT, "cd_max bomb guard trips");

    close(fd);
    printf("\n%s\n", failures ? "UNITTEST FAILED" : "UNITTEST PASSED");
    return failures ? 1 : 0;
}

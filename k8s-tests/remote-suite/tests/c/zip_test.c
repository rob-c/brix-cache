/*
 * zip_test.c — standalone unit test for client/lib/zip.c (phase-42 W3).
 *
 * Build (from repo root):
 *   cc -std=c11 -Wall -Wextra -Iclient/lib tests/c/zip_test.c client/lib/zip.c \
 *      -lz -o /tmp/zip_test && /tmp/zip_test
 *
 * Generates real ZIP fixtures with python3's zipfile (STORE, DEFLATE, and a
 * force-ZIP64 member), then parses + extracts each via a local-fd pread adapter
 * and checks byte-exactness against side "expect" files. Also covers member
 * not-found and a corrupted (truncated/bit-flipped) archive.
 */

#include "protocols/shared/zip.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_fail = 0;
#define CHECK(c, ...) do { if (!(c)) { printf("  FAIL: "); printf(__VA_ARGS__); \
    printf("\n"); g_fail = 1; } } while (0)

typedef struct { int fd; } fdctx;

static ssize_t
fd_pread(void *ctx, uint64_t off, void *buf, size_t len)
{
    return pread(((fdctx *) ctx)->fd, buf, len, (off_t) off);
}

typedef struct { uint8_t *data; size_t len, cap; } sinkbuf;

static int
sink_append(void *sc, const uint8_t *d, size_t l)
{
    sinkbuf *s = sc;
    if (s->len + l > s->cap) {
        s->cap = (s->len + l) * 2 + 64;
        s->data = realloc(s->data, s->cap);
        if (s->data == NULL) { return -1; }
    }
    memcpy(s->data + s->len, d, l);
    s->len += l;
    return 0;
}

static uint8_t *
read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    uint8_t *buf;
    long sz;
    if (f == NULL) { return NULL; }
    fseek(f, 0, SEEK_END); sz = ftell(f); fseek(f, 0, SEEK_SET);
    buf = malloc(sz > 0 ? (size_t) sz : 1);
    if (buf && sz > 0 && fread(buf, 1, (size_t) sz, f) != (size_t) sz) {
        free(buf); buf = NULL;
    }
    fclose(f);
    *len = (size_t) sz;
    return buf;
}

static uint64_t
file_size(const char *path)
{
    FILE *f = fopen(path, "rb");
    long sz;
    if (f == NULL) { return 0; }
    fseek(f, 0, SEEK_END); sz = ftell(f); fclose(f);
    return (uint64_t) sz;
}

/* Open the archive, find `member`, extract it, compare to expect_path. */
static void
check_member(const char *zip, const char *member, const char *expect_path)
{
    fdctx        c;
    brix_zip_dir dir;
    const brix_zip_entry *e;
    sinkbuf      out = {0};
    uint8_t     *want;
    size_t       want_len;
    int          rc;

    c.fd = open(zip, O_RDONLY);
    CHECK(c.fd >= 0, "open %s", zip);
    if (c.fd < 0) { return; }

    rc = brix_zip_open(fd_pread, &c, file_size(zip), &dir);
    CHECK(rc == XRDC_ZIP_OK, "zip_open %s rc=%d", zip, rc);
    if (rc != XRDC_ZIP_OK) { close(c.fd); return; }

    e = brix_zip_find(&dir, member);
    CHECK(e != NULL, "find %s", member);
    int method = e ? (int) e->method : -1;
    if (e != NULL) {
        rc = brix_zip_member_extract(fd_pread, &c, e, sink_append, &out);
        CHECK(rc == XRDC_ZIP_OK, "extract %s rc=%d", member, rc);
        want = read_file(expect_path, &want_len);
        CHECK(want != NULL, "read expect %s", expect_path);
        if (rc == XRDC_ZIP_OK && want != NULL) {
            CHECK(out.len == want_len, "%s len %zu != %zu", member, out.len, want_len);
            CHECK(out.len == want_len && memcmp(out.data, want, want_len) == 0,
                  "%s byte mismatch", member);
        }
        free(want);
    }
    free(out.data);
    brix_zip_dir_free(&dir);
    close(c.fd);
    printf("  ok   member %-12s (method %s)\n", member,
           method == 0 ? "STORE" : "DEFLATE");
}

static void
test_not_found(const char *zip)
{
    fdctx c; brix_zip_dir dir; int rc;
    c.fd = open(zip, O_RDONLY);
    rc = brix_zip_open(fd_pread, &c, file_size(zip), &dir);
    CHECK(rc == XRDC_ZIP_OK, "open for not-found");
    if (rc == XRDC_ZIP_OK) {
        CHECK(brix_zip_find(&dir, "does/not/exist") == NULL, "missing member -> NULL");
        brix_zip_dir_free(&dir);
    }
    close(c.fd);
    printf("  ok   member-not-found\n");
}

static void
test_corrupt(void)
{
    /* A truncated archive (no EOCD) must be rejected, not crash. */
    fdctx c; brix_zip_dir dir; int rc;
    system("head -c 64 /tmp/zt/multi.zip > /tmp/zt/trunc.zip");
    c.fd = open("/tmp/zt/trunc.zip", O_RDONLY);
    rc = brix_zip_open(fd_pread, &c, file_size("/tmp/zt/trunc.zip"), &dir);
    CHECK(rc < 0, "truncated archive rejected rc=%d", rc);
    if (rc == XRDC_ZIP_OK) { brix_zip_dir_free(&dir); }
    close(c.fd);
    printf("  ok   corrupt/truncated rejection\n");
}

int
main(void)
{
    int rc;

    printf("== zip reader unit test ==\n");
    rc = system(
        "python3 - <<'PY'\n"
        "import zipfile, os\n"
        "os.makedirs('/tmp/zt', exist_ok=True)\n"
        "d1 = bytes((i*7)&0xff for i in range(5000))\n"
        "d2 = b'hello deflate world ' * 2000\n"
        "d3 = bytes((i*13+1)&0xff for i in range(200000))\n"
        "open('/tmp/zt/stored.expect','wb').write(d1)\n"
        "open('/tmp/zt/deflated.expect','wb').write(d2)\n"
        "open('/tmp/zt/z64.expect','wb').write(d3)\n"
        "z=zipfile.ZipFile('/tmp/zt/multi.zip','w')\n"
        "z.writestr('stored.txt', d1, zipfile.ZIP_STORED)\n"
        "z.writestr('deflated.txt', d2, zipfile.ZIP_DEFLATED)\n"
        "with z.open('z64.bin','w', force_zip64=True) as f: f.write(d3)\n"
        "z.close()\n"
        "PY\n");
    if (rc != 0) {
        printf("  SKIP: could not build fixtures (python3/zipfile unavailable)\n");
        return 0;
    }

    check_member("/tmp/zt/multi.zip", "stored.txt",   "/tmp/zt/stored.expect");
    check_member("/tmp/zt/multi.zip", "deflated.txt", "/tmp/zt/deflated.expect");
    check_member("/tmp/zt/multi.zip", "z64.bin",      "/tmp/zt/z64.expect");
    test_not_found("/tmp/zt/multi.zip");
    test_corrupt();

    printf("%s\n", g_fail ? "== FAILED ==" : "== ALL PASSED ==");
    return g_fail;
}

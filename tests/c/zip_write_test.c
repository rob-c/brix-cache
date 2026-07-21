/*
 * zip_write_test.c — standalone unit test for the ZIP *writer* in
 * client/lib/zip.c (phase-42 W3 write side: brix_zip_writer_*).
 *
 * Build (from repo root):
 *   cc -std=c11 -Wall -Wextra -D_GNU_SOURCE -I client/lib \
 *      tests/c/zip_write_test.c client/lib/zip.c -lz \
 *      -o /tmp/zip_write_test && /tmp/zip_write_test
 *
 * Modelled on tests/c/zip_test.c: self-contained main(), CHECK() asserts that
 * print "  FAIL: ..." and latch g_fail, "  ok ..." progress lines, and a final
 * "== ALL PASSED ==" / nonzero exit on any failure.  Where the reader test
 * generates fixtures via python3 zipfile, this test BUILDS archives with the
 * writer under test and round-trips them through (a) the reader in the same
 * library and (b) the stock `unzip` CLI (subprocess), so both the in-library
 * invariant and external interoperability are proven.
 *
 * Coverage:
 *   (1) write 2 STORE members into an in-memory growable buffer via a write
 *       callback, finish; re-parse the SAME buffer with brix_zip_open +
 *       brix_zip_member_extract and assert both members byte-exact + CRC-OK.
 *   (2) persist that buffer to a temp .zip and assert `unzip -t` is OK and
 *       `unzip -p <file> <member>` reproduces each member byte-exact.
 *   (3) append: build a 1-member archive on disk, read its EOCD via
 *       brix_zip_read_eocd, seed an append-writer (brix_zip_writer_new_append)
 *       writing in-place into a copy, add a 2nd member, finish; re-parse and
 *       assert BOTH members byte-exact, and `unzip -t` OK.
 *   (4) empty-member: a 0-byte source fd stores and reads back as 0 bytes.
 */

#include "protocols/shared/zip.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static int g_fail = 0;
#define CHECK(c, ...) do { if (!(c)) { printf("  FAIL: "); printf(__VA_ARGS__); \
    printf("\n"); g_fail = 1; } } while (0)

/* -------------------------------------------------------------------------- *
 * In-memory growable buffer used both as the writer's sink and as the
 * reader's backing store (via a memory pread callback below).
 * -------------------------------------------------------------------------- */

typedef struct {
    uint8_t *data;
    size_t   len;     /* logical archive length                              */
    size_t   cap;
    size_t   off;     /* current write cursor (append-mode seeks via base)   */
} membuf;

/* Ensure the buffer can hold up to `end` bytes (logical length grows to end). */
static int
membuf_reserve(membuf *m, size_t end)
{
    if (end > m->cap) {
        size_t ncap = m->cap ? m->cap * 2 : 256;
        uint8_t *np;
        while (ncap < end) {
            ncap *= 2;
        }
        np = realloc(m->data, ncap);
        if (np == NULL) {
            return -1;
        }
        m->data = np;
        m->cap  = ncap;
    }
    if (end > m->len) {
        m->len = end;
    }
    return 0;
}

/* brix_zip_write_fn: write exactly `len` bytes at the current cursor. The cursor
 * starts at 0 for a fresh writer and at `base_offset` for an append writer, so a
 * single positional sink serves both — overwriting the old central directory and
 * then growing past it, exactly like the on-disk append path in copy.c. */
static int
membuf_write(void *ctx, const void *data, size_t len)
{
    membuf *m = ctx;
    if (membuf_reserve(m, m->off + len) != 0) {
        return -1;
    }
    memcpy(m->data + m->off, data, len);
    m->off += len;
    return 0;
}

/* brix_zip_pread_fn over the in-memory archive (bounds-checked short read). */
static ssize_t
membuf_pread(void *ctx, uint64_t off, void *buf, size_t len)
{
    membuf *m = ctx;
    if (off > m->len) {
        return 0;
    }
    size_t avail = m->len - (size_t) off;
    size_t n = (len < avail) ? len : avail;
    memcpy(buf, m->data + off, n);
    return (ssize_t) n;
}

/* -------------------------------------------------------------------------- *
 * Extraction sink: collect inflated member bytes into a growable buffer.
 * -------------------------------------------------------------------------- */

typedef struct { uint8_t *data; size_t len, cap; } sinkbuf;

static int
sink_append(void *sc, const uint8_t *d, size_t l)
{
    sinkbuf *s = sc;
    if (s->len + l > s->cap) {
        s->cap = (s->len + l) * 2 + 64;
        s->data = realloc(s->data, s->cap);
        if (s->data == NULL) {
            return -1;
        }
    }
    if (l > 0) {
        memcpy(s->data + s->len, d, l);
    }
    s->len += l;
    return 0;
}

/* -------------------------------------------------------------------------- *
 * Small helpers.
 * -------------------------------------------------------------------------- */

/* Create a temp file holding `data`/`len`, return an O_RDONLY fd; -1 on error.
 * The path is unlinked immediately so the fd is the sole reference. */
static int
tmpfd_with(const uint8_t *data, size_t len)
{
    char tpl[] = "/tmp/zwtsrcXXXXXX";
    int  fd = mkstemp(tpl);
    if (fd < 0) {
        return -1;
    }
    if (unlink(tpl) != 0) {
        close(fd);
        return -1;
    }
    for (size_t pos = 0; pos < len; ) {
        ssize_t n = write(fd, data + pos, len - pos);
        if (n <= 0) {
            close(fd);
            return -1;
        }
        pos += (size_t) n;
    }
    return fd;   /* offset at EOF; writer uses pread(), offset-independent */
}

/* Open the membuf as an archive, find `member`, extract, compare to want/len. */
static void
expect_member(membuf *arc, const char *member, const uint8_t *want, size_t want_len)
{
    brix_zip_dir          dir;
    const brix_zip_entry *e;
    sinkbuf               out = {0};
    int                   rc;

    rc = brix_zip_open(membuf_pread, arc, arc->len, &dir);
    CHECK(rc == XRDC_ZIP_OK, "zip_open(mem) rc=%d", rc);
    if (rc != XRDC_ZIP_OK) {
        return;
    }
    e = brix_zip_find(&dir, member);
    CHECK(e != NULL, "find %s", member);
    if (e != NULL) {
        CHECK(e->method == 0, "%s method=%u (want STORE 0)", member, e->method);
        CHECK(e->uncomp_size == want_len, "%s cd-uncomp %llu != %zu",
              member, (unsigned long long) e->uncomp_size, want_len);
        rc = brix_zip_member_extract(membuf_pread, arc, e, sink_append, &out);
        CHECK(rc == XRDC_ZIP_OK, "extract %s rc=%d", member, rc);
        if (rc == XRDC_ZIP_OK) {
            CHECK(out.len == want_len, "%s len %zu != %zu", member, out.len, want_len);
            CHECK(out.len == want_len
                  && (want_len == 0 || memcmp(out.data, want, want_len) == 0),
                  "%s byte mismatch", member);
        }
    }
    free(out.data);
    brix_zip_dir_free(&dir);
}

/* Per-uid scratch path: a root-run leftover of a fixed /tmp name is not
 * writable (or unlinkable, /tmp is sticky) by a later unprivileged run. */
static const char *
zwt_path(const char *name)
{
    static char buf[256];
    snprintf(buf, sizeof(buf), "/tmp/zwt_%d_%s", (int)getuid(), name);
    return buf;
}

/* Write membuf to `path`. Returns 0 on success. */
static int
membuf_to_file(membuf *m, const char *path)
{
    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        return -1;
    }
    size_t w = (m->len > 0) ? fwrite(m->data, 1, m->len, f) : 0;
    int ok = (w == m->len);
    fclose(f);
    return ok ? 0 : -1;
}

/* `unzip -t <path>` must exit 0 (archive integrity OK). */
static void
expect_unzip_t_ok(const char *path)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "unzip -t %s >/dev/null 2>&1", path);
    int rc = system(cmd);
    CHECK(rc == 0, "unzip -t %s rc=%d", path, rc);
}

/* `unzip -p <path> <member>` output must equal want/len byte-for-byte. */
static void
expect_unzip_p(const char *path, const char *member,
               const uint8_t *want, size_t want_len)
{
    char cmd[512], outp[] = "/tmp/zwtoutXXXXXX";
    int  ofd = mkstemp(outp);
    CHECK(ofd >= 0, "mkstemp for unzip -p");
    if (ofd < 0) {
        return;
    }
    close(ofd);
    snprintf(cmd, sizeof(cmd), "unzip -p %s %s > %s 2>/dev/null",
             path, member, outp);
    int rc = system(cmd);
    CHECK(rc == 0, "unzip -p %s %s rc=%d", path, member, rc);

    FILE *f = fopen(outp, "rb");
    CHECK(f != NULL, "open unzip -p output");
    if (f != NULL) {
        uint8_t *got = malloc(want_len ? want_len + 16 : 16);
        size_t   n = fread(got, 1, want_len ? want_len + 16 : 16, f);
        CHECK(n == want_len, "unzip -p %s got %zu bytes != %zu", member, n, want_len);
        CHECK(n == want_len && (want_len == 0 || memcmp(got, want, want_len) == 0),
              "unzip -p %s byte mismatch", member);
        free(got);
        fclose(f);
    }
    unlink(outp);
}

/* -------------------------------------------------------------------------- *
 * Tests.
 * -------------------------------------------------------------------------- */

/* (1) + (2): two STORE members written to memory, re-read in-library + by unzip. */
static void
test_create_two_members(const uint8_t *a, size_t alen,
                         const uint8_t *b, size_t blen)
{
    membuf           arc = {0};
    brix_zip_writer *w;
    int              fda, fdb, rc;

    fda = tmpfd_with(a, alen);
    fdb = tmpfd_with(b, blen);
    CHECK(fda >= 0 && fdb >= 0, "create source fds");
    if (fda < 0 || fdb < 0) {
        if (fda >= 0) close(fda);
        if (fdb >= 0) close(fdb);
        return;
    }

    w = brix_zip_writer_new(membuf_write, &arc);
    CHECK(w != NULL, "writer_new");
    if (w != NULL) {
        rc = brix_zip_writer_add_fd(w, "alpha.bin", fda);
        CHECK(rc == XRDC_ZIP_OK, "add alpha rc=%d", rc);
        rc = brix_zip_writer_add_fd(w, "nested/beta.txt", fdb);
        CHECK(rc == XRDC_ZIP_OK, "add beta rc=%d", rc);
        rc = brix_zip_writer_finish(w);
        CHECK(rc == XRDC_ZIP_OK, "finish rc=%d", rc);
        brix_zip_writer_free(w);
    }
    close(fda);
    close(fdb);

    /* (1) round-trip through the library reader. */
    expect_member(&arc, "alpha.bin",       a, alen);
    expect_member(&arc, "nested/beta.txt", b, blen);

    /* (2) round-trip through stock unzip. */
    CHECK(membuf_to_file(&arc, zwt_path("two.zip")) == 0, "persist two.zip");
    expect_unzip_t_ok(zwt_path("two.zip"));
    expect_unzip_p(zwt_path("two.zip"), "alpha.bin",       a, alen);
    expect_unzip_p(zwt_path("two.zip"), "nested/beta.txt", b, blen);

    free(arc.data);
    printf("  ok   create 2 STORE members (lib reader + unzip -t/-p)\n");
}

/* (3) append: 1-member archive -> read EOCD/CD -> seed append writer -> add 2nd. */
static void
test_append_member(const uint8_t *a, size_t alen,
                   const uint8_t *b, size_t blen)
{
    membuf           base_arc = {0};
    membuf           app_arc  = {0};
    brix_zip_writer *w;
    int              fda, fdb, rc;
    uint64_t         cd_off = 0, cd_size = 0, n = 0;
    int              z64 = 1;

    /* --- build the original 1-member archive in memory --- */
    fda = tmpfd_with(a, alen);
    CHECK(fda >= 0, "append: create base src fd");
    if (fda < 0) {
        return;
    }
    w = brix_zip_writer_new(membuf_write, &base_arc);
    CHECK(w != NULL, "append: base writer_new");
    if (w != NULL) {
        rc = brix_zip_writer_add_fd(w, "first.dat", fda);
        CHECK(rc == XRDC_ZIP_OK, "append: add first rc=%d", rc);
        rc = brix_zip_writer_finish(w);
        CHECK(rc == XRDC_ZIP_OK, "append: base finish rc=%d", rc);
        brix_zip_writer_free(w);
    }
    close(fda);

    /* --- read its EOCD to locate the central directory --- */
    rc = brix_zip_read_eocd(membuf_pread, &base_arc, base_arc.len,
                            &cd_off, &cd_size, &n, &z64);
    CHECK(rc == XRDC_ZIP_OK, "append: read_eocd rc=%d", rc);
    CHECK(n == 1, "append: base entry count %llu != 1", (unsigned long long) n);
    CHECK(z64 == 0, "append: base unexpectedly ZIP64");
    if (rc != XRDC_ZIP_OK) {
        free(base_arc.data);
        return;
    }

    /* --- read the verbatim CD bytes (the seed) --- */
    uint8_t *seed = malloc(cd_size ? (size_t) cd_size : 1);
    CHECK(seed != NULL, "append: alloc seed");
    ssize_t sr = membuf_pread(&base_arc, cd_off, seed, (size_t) cd_size);
    CHECK(sr == (ssize_t) cd_size, "append: read seed CD %zd != %llu",
          sr, (unsigned long long) cd_size);

    /* --- copy the archive truncated to cd_off; the append writer overwrites the
     *     old CD region (base_offset = cd_off) and grows past it, in-place. --- */
    CHECK(membuf_reserve(&app_arc, (size_t) cd_off) == 0, "append: reserve copy");
    if (cd_off > 0) {
        memcpy(app_arc.data, base_arc.data, (size_t) cd_off);
    }
    app_arc.len = (size_t) cd_off;
    app_arc.off = (size_t) cd_off;        /* sink starts where new data lands */

    fdb = tmpfd_with(b, blen);
    CHECK(fdb >= 0, "append: create 2nd src fd");
    if (fdb >= 0) {
        w = brix_zip_writer_new_append(membuf_write, &app_arc, cd_off,
                                       seed, (size_t) cd_size, (size_t) n);
        CHECK(w != NULL, "append: writer_new_append");
        if (w != NULL) {
            rc = brix_zip_writer_add_fd(w, "second.dat", fdb);
            CHECK(rc == XRDC_ZIP_OK, "append: add second rc=%d", rc);
            rc = brix_zip_writer_finish(w);
            CHECK(rc == XRDC_ZIP_OK, "append: finish rc=%d", rc);
            brix_zip_writer_free(w);
        }
        close(fdb);

        /* both members must survive in the appended archive */
        expect_member(&app_arc, "first.dat",  a, alen);
        expect_member(&app_arc, "second.dat", b, blen);

        CHECK(membuf_to_file(&app_arc, zwt_path("append.zip")) == 0, "persist append.zip");
        expect_unzip_t_ok(zwt_path("append.zip"));
        expect_unzip_p(zwt_path("append.zip"), "first.dat",  a, alen);
        expect_unzip_p(zwt_path("append.zip"), "second.dat", b, blen);
    }

    free(seed);
    free(base_arc.data);
    free(app_arc.data);
    printf("  ok   append 2nd member (both byte-exact + unzip -t)\n");
}

/* (4) empty-member: a 0-byte source stores and reads back as 0 bytes. */
static void
test_empty_member(void)
{
    membuf           arc = {0};
    brix_zip_writer *w;
    int              fd, rc;
    static const uint8_t payload[] = "non-empty companion";

    int fde = tmpfd_with(NULL, 0);          /* 0-byte file */
    int fdc = tmpfd_with(payload, sizeof(payload) - 1);
    CHECK(fde >= 0 && fdc >= 0, "empty: create src fds");
    if (fde < 0 || fdc < 0) {
        if (fde >= 0) close(fde);
        if (fdc >= 0) close(fdc);
        return;
    }
    fd = fde;

    w = brix_zip_writer_new(membuf_write, &arc);
    CHECK(w != NULL, "empty: writer_new");
    if (w != NULL) {
        rc = brix_zip_writer_add_fd(w, "empty.dat", fd);
        CHECK(rc == XRDC_ZIP_OK, "empty: add empty rc=%d", rc);
        rc = brix_zip_writer_add_fd(w, "filled.dat", fdc);
        CHECK(rc == XRDC_ZIP_OK, "empty: add filled rc=%d", rc);
        rc = brix_zip_writer_finish(w);
        CHECK(rc == XRDC_ZIP_OK, "empty: finish rc=%d", rc);
        brix_zip_writer_free(w);
    }
    close(fde);
    close(fdc);

    expect_member(&arc, "empty.dat",  NULL, 0);
    expect_member(&arc, "filled.dat", payload, sizeof(payload) - 1);

    CHECK(membuf_to_file(&arc, zwt_path("empty.zip")) == 0, "persist empty.zip");
    expect_unzip_t_ok(zwt_path("empty.zip"));
    expect_unzip_p(zwt_path("empty.zip"), "empty.dat",  NULL, 0);
    expect_unzip_p(zwt_path("empty.zip"), "filled.dat", payload, sizeof(payload) - 1);

    free(arc.data);
    printf("  ok   empty (0-byte) member stores/reads as 0 bytes\n");
}

int
main(void)
{
    /* Distinct member payloads, sized to span the writer's 64 KiB I/O buffer. */
    size_t   alen = 70000, blen = 12345;
    uint8_t *a = malloc(alen);
    uint8_t *b = malloc(blen);
    if (a == NULL || b == NULL) {
        printf("  FAIL: alloc payloads\n== FAILED ==\n");
        return 1;
    }
    for (size_t i = 0; i < alen; i++) { a[i] = (uint8_t) ((i * 7 + 3) & 0xff); }
    for (size_t i = 0; i < blen; i++) { b[i] = (uint8_t) ((i * 13 + 1) & 0xff); }

    printf("== zip writer unit test ==\n");
    test_create_two_members(a, alen, b, blen);
    test_append_member(a, alen, b, blen);
    test_empty_member();

    free(a);
    free(b);
    printf("%s\n", g_fail ? "== FAILED ==" : "== ALL PASSED ==");
    return g_fail;
}

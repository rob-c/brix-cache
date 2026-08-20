/*
 * tar_unittest.c — unit suite + corpus dumper for the streaming tar reader
 * (phase-104 D6.4). Two personalities:
 *
 *   tar_unittest              — self-contained checks over in-C crafted
 *                               archives: header grammar (octal, base-256,
 *                               signed/unsigned checksum), pax records and
 *                               xattr capture, GNU long names, unknown-flag
 *                               skip, end-of-archive shapes, gzip (and zstd
 *                               when built in), truncation, and the
 *                               body-consumed API contract. Exit 0 = pass.
 *   tar_unittest dump <file>  — parse an archive and print one TAB-separated
 *                               line per entry (type mode size mtime uid gid
 *                               path linkname crc32 xattrs) for the pytest
 *                               corpus lane; "ERROR: <msg>" + exit 3 on a
 *                               malformed archive.
 *
 * Compiles without nginx (catalog_write.c carries the xattr wire helpers and
 * drags catalog.c + hash.c):
 *   gcc -Wall -Wextra -Werror -I shared -o /tmp/tar_ut \
 *       shared/oci/tar_unittest.c shared/oci/tar.c shared/oci/tar_pax.c \
 *       shared/cvmfs/catalog/catalog_write.c shared/cvmfs/catalog/catalog.c \
 *       shared/cvmfs/grammar/hash.c -lsqlite3 -lcrypto -lz && /tmp/tar_ut
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "oci/tar.h"
#include "cvmfs/catalog/catalog_write.h"

#include <zlib.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef BRIX_HAVE_ZSTD
#include <zstd.h>
#endif

static int g_checks, g_failed;
#define CHECK(cond, name) do {                                    \
    g_checks++;                                                   \
    if (cond) { printf("  ok   %s\n", name); }                    \
    else      { printf("  FAIL %s (line %d)\n", name, __LINE__); g_failed++; } \
} while (0)

/* ---- tiny archive writer ------------------------------------------------- */

#define AR_CAP (1u << 20)

typedef struct { unsigned char b[AR_CAP]; size_t len; } ar_t;

static void ar_cksum(unsigned char *h) {
    unsigned sum = 0;
    size_t   i;

    memset(h + 148, ' ', 8);
    for (i = 0; i < 512; i++)
        sum += h[i];
    snprintf((char *) h + 148, 8, "%06o", sum);
    h[155] = ' ';
}

/* Append a ustar header; returns a pointer to it (for field surgery, after
 * which the caller re-runs ar_cksum). */
static unsigned char *ar_hdr(ar_t *a, const char *name, char type,
                             int64_t size, unsigned mode) {
    unsigned char *h = a->b + a->len;

    memset(h, 0, 512);
    snprintf((char *) h, 100, "%s", name);
    snprintf((char *) h + 100, 8, "%07o", mode);
    snprintf((char *) h + 108, 8, "%07o", 0);
    snprintf((char *) h + 116, 8, "%07o", 0);
    snprintf((char *) h + 124, 12, "%011llo", (unsigned long long) size);
    snprintf((char *) h + 136, 12, "%011llo", 1234567ULL);
    h[156] = (unsigned char) type;
    memcpy(h + 257, "ustar", 6);
    memcpy(h + 263, "00", 2);
    ar_cksum(h);
    a->len += 512;
    return h;
}

static void ar_body(ar_t *a, const void *body, size_t n) {
    memcpy(a->b + a->len, body, n);
    a->len += n;
    memset(a->b + a->len, 0, (512 - n % 512) % 512);
    a->len += (512 - n % 512) % 512;
}

static void ar_end(ar_t *a) {
    memset(a->b + a->len, 0, 1024);
    a->len += 1024;
}

/* Write the archive bytes to a fresh temp file, return an fd at offset 0. */
static int ar_fd(const unsigned char *buf, size_t len) {
    char tmpl[] = "tarut.XXXXXX";
    int  fd = mkstemp(tmpl);

    if (fd < 0)
        return -1;
    unlink(tmpl);
    if (write(fd, buf, len) != (ssize_t) len) {
        close(fd);
        return -1;
    }
    lseek(fd, 0, SEEK_SET);
    return fd;
}

/* ---- self-test lanes ----------------------------------------------------- */

static void t_basic(void) {
    ar_t             a = { .len = 0 };
    brix_tar_entry_t e;
    brix_tar_t      *t;
    unsigned char   *h;
    char             err[256], body[64];
    int              fd;

    ar_hdr(&a, "d", '5', 0, 0755);
    ar_hdr(&a, "d/hello.txt", '0', 13, 0644);
    ar_body(&a, "Hello, layer!", 13);
    h = ar_hdr(&a, "d/l", '2', 0, 0777);
    memcpy(h + 157, "hello.txt", 9);              /* linkname field */
    ar_cksum(h);
    ar_end(&a);

    fd = ar_fd(a.b, a.len);
    t  = brix_tar_open_fd(fd, err, sizeof(err));
    CHECK(t != NULL, "basic: open");
    CHECK(brix_tar_next(t, &e) == 1 && e.type == BRIX_TAR_DIR &&
          strcmp(e.path, "d") == 0 && e.mode == 0755, "basic: dir entry");
    CHECK(brix_tar_next(t, &e) == 1 && e.type == BRIX_TAR_REG &&
          strcmp(e.path, "d/hello.txt") == 0 && e.size == 13 &&
          e.mtime == 1234567, "basic: file entry");
    CHECK(brix_tar_read(t, body, sizeof(body)) == 13 &&
          memcmp(body, "Hello, layer!", 13) == 0, "basic: body bytes");
    CHECK(brix_tar_read(t, body, sizeof(body)) == 0, "basic: body EOF");
    CHECK(brix_tar_next(t, &e) == 1 && e.type == BRIX_TAR_SYMLINK &&
          strcmp(e.linkname, "hello.txt") == 0, "basic: symlink entry");
    CHECK(brix_tar_next(t, &e) == 0, "basic: clean EOF");
    brix_tar_close(t);
    close(fd);
}

static void t_api_misuse(void) {
    ar_t             a = { .len = 0 };
    brix_tar_entry_t e;
    brix_tar_t      *t;
    char             err[256];
    int              fd;

    ar_hdr(&a, "f", '0', 5, 0644);
    ar_body(&a, "12345", 5);
    ar_hdr(&a, "g", '0', 0, 0644);
    ar_end(&a);

    fd = ar_fd(a.b, a.len);
    t  = brix_tar_open_fd(fd, err, sizeof(err));
    CHECK(t != NULL && brix_tar_next(t, &e) == 1, "misuse: first entry");
    CHECK(brix_tar_next(t, &e) == -1 &&
          strstr(brix_tar_error(t), "not fully consumed") != NULL,
          "misuse: advance with unread body refused");
    brix_tar_close(t);
    close(fd);

    fd = ar_fd(a.b, a.len);
    t  = brix_tar_open_fd(fd, err, sizeof(err));
    CHECK(t != NULL && brix_tar_next(t, &e) == 1 && brix_tar_skip(t) == 0 &&
          brix_tar_next(t, &e) == 1 && strcmp(e.path, "g") == 0,
          "misuse: skip() then advance is fine");
    brix_tar_close(t);
    close(fd);
}

static void t_numeric_and_cksum(void) {
    ar_t             a = { .len = 0 };
    brix_tar_entry_t e;
    brix_tar_t      *t;
    unsigned char   *h;
    char             err[256], body[8];
    int              fd;
    size_t           i;

    /* base-256 size (=3) on a file with a high-bit byte in the name,
     * checksummed with the historical SIGNED sum. */
    h = ar_hdr(&a, "b256", '0', 0, 0644);
    h[4] = 0xFF;                                  /* name "b256\xff" */
    memset(h + 124, 0, 12);
    h[124] = 0x80;                                /* base-256 marker */
    h[135] = 3;
    {
        long ssum = 0;

        memset(h + 148, ' ', 8);
        for (i = 0; i < 512; i++)
            ssum += (signed char) h[i];
        snprintf((char *) h + 148, 8, "%06lo", (unsigned long) ssum);
        h[155] = ' ';
    }
    ar_body(&a, "abc", 3);
    ar_end(&a);

    fd = ar_fd(a.b, a.len);
    t  = brix_tar_open_fd(fd, err, sizeof(err));
    CHECK(t != NULL && brix_tar_next(t, &e) == 1 && e.size == 3 &&
          brix_tar_read(t, body, sizeof(body)) == 3,
          "num: base-256 size + signed checksum accepted");
    brix_tar_close(t);
    close(fd);

    /* size overflowing int64 (base-256, 9 high bytes) → refused */
    a.len = 0;
    h = ar_hdr(&a, "huge", '0', 0, 0644);
    memset(h + 124, 0xFF, 12);
    h[124] = 0x81;
    ar_cksum(h);
    ar_end(&a);
    fd = ar_fd(a.b, a.len);
    t  = brix_tar_open_fd(fd, err, sizeof(err));
    CHECK(t != NULL && brix_tar_next(t, &e) == -1 &&
          strstr(brix_tar_error(t), "size") != NULL,
          "num: int64-overflow size refused");
    brix_tar_close(t);
    close(fd);

    /* negative base-256 size → refused */
    a.len = 0;
    h = ar_hdr(&a, "neg", '0', 0, 0644);
    memset(h + 124, 0xFF, 12);                    /* 0xFF… = -1 */
    ar_cksum(h);
    ar_end(&a);
    fd = ar_fd(a.b, a.len);
    t  = brix_tar_open_fd(fd, err, sizeof(err));
    CHECK(t != NULL && brix_tar_next(t, &e) == -1 &&
          strstr(brix_tar_error(t), "negative size") != NULL,
          "num: negative size refused");
    brix_tar_close(t);
    close(fd);

    /* corrupted checksum → refused */
    a.len = 0;
    h = ar_hdr(&a, "ok", '0', 0, 0644);
    h[0] ^= 0x01;                                 /* flip after checksum */
    ar_end(&a);
    fd = ar_fd(a.b, a.len);
    t  = brix_tar_open_fd(fd, err, sizeof(err));
    CHECK(t != NULL && brix_tar_next(t, &e) == -1 &&
          strstr(brix_tar_error(t), "checksum") != NULL,
          "num: bad checksum refused");
    brix_tar_close(t);
    close(fd);
}

static void t_pax(void) {
    ar_t             a = { .len = 0 };
    brix_tar_entry_t e;
    brix_tar_t      *t;
    char             err[256];
    int              fd;
    static const char rec[] =
        "31 path=override/long-name.bin\n"
        "30 SCHILY.xattr.user.tag=blue\n"
        "23 mtime=1700000000.25\n";

    ar_hdr(&a, "pax-hdr", 'x', (int64_t) (sizeof(rec) - 1), 0644);
    ar_body(&a, rec, sizeof(rec) - 1);
    ar_hdr(&a, "short-name", '0', 2, 0600);
    ar_body(&a, "zz", 2);
    ar_hdr(&a, "plain", '0', 0, 0644);
    ar_end(&a);

    fd = ar_fd(a.b, a.len);
    t  = brix_tar_open_fd(fd, err, sizeof(err));
    CHECK(t != NULL && brix_tar_next(t, &e) == 1 &&
          strcmp(e.path, "override/long-name.bin") == 0 &&
          e.mtime == 1700000000 && e.size == 2,
          "pax: path + fractional-mtime overrides applied");
    {
        const char          *key = NULL;
        const unsigned char *val = NULL;
        size_t               keylen = 0, vallen = 0;
        int                  n = cvmfs_xattr_count(
                                     (const unsigned char *) e.xattr,
                                     e.xattr_len);

        CHECK(n == 1 &&
              cvmfs_xattr_unpack((const unsigned char *) e.xattr, e.xattr_len,
                                 0, &key, &keylen, &val, &vallen) == 0 &&
              keylen == 8 && memcmp(key, "user.tag", 8) == 0 &&
              vallen == 4 && memcmp(val, "blue", 4) == 0,
              "pax: SCHILY.xattr packed in changeset wire format");
    }
    CHECK(brix_tar_skip(t) == 0 && brix_tar_next(t, &e) == 1 &&
          strcmp(e.path, "plain") == 0 && e.xattr == NULL,
          "pax: overrides reset after the entry");
    brix_tar_close(t);
    close(fd);

    /* malformed record length → refused */
    a.len = 0;
    ar_hdr(&a, "bad-pax", 'x', 9, 0644);
    ar_body(&a, "99 a=b\nxx", 9);
    ar_hdr(&a, "f", '0', 0, 0644);
    ar_end(&a);
    fd = ar_fd(a.b, a.len);
    t  = brix_tar_open_fd(fd, err, sizeof(err));
    CHECK(t != NULL && brix_tar_next(t, &e) == -1 &&
          strstr(brix_tar_error(t), "pax record length") != NULL,
          "pax: lying record length refused");
    brix_tar_close(t);
    close(fd);
}

static void t_gnu_long_and_unknown(void) {
    ar_t             a = { .len = 0 };
    brix_tar_entry_t e;
    brix_tar_t      *t;
    char             err[256], want[130];
    int              fd;
    size_t           i;

    for (i = 0; i < sizeof(want) - 1; i++)
        want[i] = 'a' + (char) (i % 26);
    want[sizeof(want) - 1] = '\0';

    ar_hdr(&a, "././@LongLink", 'L', (int64_t) strlen(want) + 1, 0644);
    ar_body(&a, want, strlen(want) + 1);
    ar_hdr(&a, "truncated-by-ustar", '0', 0, 0644);
    ar_hdr(&a, "vendor-ext", 'Z', 7, 0644);      /* unknown flag: skipped */
    ar_body(&a, "opaque!", 7);
    ar_hdr(&a, "after", '0', 0, 0644);
    ar_end(&a);

    fd = ar_fd(a.b, a.len);
    t  = brix_tar_open_fd(fd, err, sizeof(err));
    CHECK(t != NULL && brix_tar_next(t, &e) == 1 &&
          strcmp(e.path, want) == 0, "gnu: 'L' long name applied");
    CHECK(brix_tar_next(t, &e) == 1 && strcmp(e.path, "after") == 0,
          "gnu: unknown typeflag skipped, stream continues");
    CHECK(brix_tar_next(t, &e) == 0, "gnu: clean EOF");
    brix_tar_close(t);
    close(fd);
}

static void t_ends_and_truncation(void) {
    ar_t             a = { .len = 0 };
    brix_tar_entry_t e;
    brix_tar_t      *t;
    char             err[256];
    int              fd;

    /* single zero block + EOF (sloppy writer) → clean end */
    ar_hdr(&a, "f", '0', 0, 0644);
    memset(a.b + a.len, 0, 512);
    a.len += 512;
    fd = ar_fd(a.b, a.len);
    t  = brix_tar_open_fd(fd, err, sizeof(err));
    CHECK(t != NULL && brix_tar_next(t, &e) == 1 &&
          brix_tar_next(t, &e) == 0, "end: single-zero-block+EOF accepted");
    brix_tar_close(t);
    close(fd);

    /* data after the end marker → refused */
    a.len = 0;
    ar_hdr(&a, "f", '0', 0, 0644);
    memset(a.b + a.len, 0, 512);
    a.len += 512;
    ar_hdr(&a, "smuggled", '0', 0, 0644);
    fd = ar_fd(a.b, a.len);
    t  = brix_tar_open_fd(fd, err, sizeof(err));
    CHECK(t != NULL && brix_tar_next(t, &e) == 1 &&
          brix_tar_next(t, &e) == -1 &&
          strstr(brix_tar_error(t), "end-of-archive") != NULL,
          "end: data after end marker refused");
    brix_tar_close(t);
    close(fd);

    /* truncated body → refused */
    a.len = 0;
    ar_hdr(&a, "f", '0', 100, 0644);
    memcpy(a.b + a.len, "short", 5);
    a.len += 5;
    fd = ar_fd(a.b, a.len);
    t  = brix_tar_open_fd(fd, err, sizeof(err));
    CHECK(t != NULL && brix_tar_next(t, &e) == 1 && brix_tar_skip(t) == -1 &&
          strstr(brix_tar_error(t), "truncated") != NULL,
          "end: truncated body refused");
    brix_tar_close(t);
    close(fd);

    /* truncated header (200 of 512 bytes) → refused */
    a.len = 0;
    ar_hdr(&a, "f", '0', 0, 0644);
    fd = ar_fd(a.b, 200);
    t  = brix_tar_open_fd(fd, err, sizeof(err));
    CHECK(t != NULL && brix_tar_next(t, &e) == -1 &&
          strstr(brix_tar_error(t), "truncated") != NULL,
          "end: truncated header refused");
    brix_tar_close(t);
    close(fd);
}

/* gzip an archive buffer in memory (gzip wrapper via 15+16). */
static size_t gz_pack(const unsigned char *in, size_t inlen,
                      unsigned char *out, size_t outcap) {
    z_stream zs;

    memset(&zs, 0, sizeof(zs));
    if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8,
                     Z_DEFAULT_STRATEGY) != Z_OK)
        return 0;
    zs.next_in   = (unsigned char *) in;
    zs.avail_in  = (uInt) inlen;
    zs.next_out  = out;
    zs.avail_out = (uInt) outcap;
    if (deflate(&zs, Z_FINISH) != Z_STREAM_END) {
        deflateEnd(&zs);
        return 0;
    }
    deflateEnd(&zs);
    return outcap - zs.avail_out;
}

static void t_gzip(void) {
    ar_t                  a = { .len = 0 };
    static unsigned char  gz[AR_CAP];
    size_t                gzlen;
    brix_tar_entry_t      e;
    brix_tar_t           *t;
    char                  err[256], body[16];
    int                   fd;

    ar_hdr(&a, "z/file", '0', 6, 0644);
    ar_body(&a, "gzbody", 6);
    ar_end(&a);
    gzlen = gz_pack(a.b, a.len, gz, sizeof(gz));
    CHECK(gzlen > 0, "gzip: packer sanity");

    fd = ar_fd(gz, gzlen);
    t  = brix_tar_open_fd(fd, err, sizeof(err));
    CHECK(t != NULL && brix_tar_next(t, &e) == 1 &&
          strcmp(e.path, "z/file") == 0 &&
          brix_tar_read(t, body, sizeof(body)) == 6 &&
          memcmp(body, "gzbody", 6) == 0 && brix_tar_next(t, &e) == 0,
          "gzip: sniffed + inflated round-trip");
    brix_tar_close(t);
    close(fd);

    /* truncated gzip stream → refused */
    fd = ar_fd(gz, gzlen / 2);
    t  = brix_tar_open_fd(fd, err, sizeof(err));
    CHECK(t != NULL &&
          (brix_tar_next(t, &e) == -1 ||
           (brix_tar_skip(t) == -1 || brix_tar_next(t, &e) == -1)),
          "gzip: truncated stream refused");
    brix_tar_close(t);
    close(fd);
}

static void t_zstd(void) {
    static const unsigned char magic[] = { 0x28, 0xb5, 0x2f, 0xfd, 0, 0 };
    char                       err[256];

#ifdef BRIX_HAVE_ZSTD
    ar_t                  a = { .len = 0 };
    static unsigned char  zb[AR_CAP];
    size_t                zlen;
    brix_tar_entry_t      e;
    brix_tar_t           *t;
    char                  body[16];
    int                   fd;

    (void) magic;
    ar_hdr(&a, "zs/file", '0', 6, 0644);
    ar_body(&a, "zstdok", 6);
    ar_end(&a);
    zlen = ZSTD_compress(zb, sizeof(zb), a.b, a.len, 3);
    CHECK(!ZSTD_isError(zlen), "zstd: packer sanity");

    fd = ar_fd(zb, zlen);
    t  = brix_tar_open_fd(fd, err, sizeof(err));
    CHECK(t != NULL && brix_tar_next(t, &e) == 1 &&
          strcmp(e.path, "zs/file") == 0 &&
          brix_tar_read(t, body, sizeof(body)) == 6 &&
          memcmp(body, "zstdok", 6) == 0 && brix_tar_next(t, &e) == 0,
          "zstd: sniffed + decompressed round-trip");
    brix_tar_close(t);
    close(fd);
#else
    int fd = ar_fd(magic, sizeof(magic));

    CHECK(brix_tar_open_fd(fd, err, sizeof(err)) == NULL &&
          strstr(err, "zstd") != NULL,
          "zstd: layer refused with a clear message when not built in");
    close(fd);
#endif
}

/* ---- dump mode (corpus driver) ------------------------------------------- */

static const char *type_name(brix_tar_type_t ty) {
    switch (ty) {
    case BRIX_TAR_REG:      return "REG";
    case BRIX_TAR_DIR:      return "DIR";
    case BRIX_TAR_SYMLINK:  return "SYM";
    case BRIX_TAR_HARDLINK: return "HLNK";
    case BRIX_TAR_CHR:      return "CHR";
    case BRIX_TAR_BLK:      return "BLK";
    case BRIX_TAR_FIFO:     return "FIFO";
    }
    return "?";
}

static int dump_archive(const char *file) {
    char             err[256];
    unsigned char    buf[64 * 1024];
    brix_tar_entry_t e;
    brix_tar_t      *t;
    int              fd = open(file, O_RDONLY);
    int              rc;

    if (fd < 0) {
        printf("ERROR: cannot open %s\n", file);
        return 3;
    }
    t = brix_tar_open_fd(fd, err, sizeof(err));
    if (t == NULL) {
        printf("ERROR: %s\n", err);
        close(fd);
        return 3;
    }
    while ((rc = brix_tar_next(t, &e)) == 1) {
        unsigned long crc = crc32(0L, Z_NULL, 0);
        int           got;

        while ((got = brix_tar_read(t, buf, sizeof(buf))) > 0)
            crc = crc32(crc, buf, (uInt) got);
        if (got < 0)
            break;
        printf("%s\t%04o\t%lld\t%lld\t%lld\t%lld\t%s\t%s\t%08lx",
               type_name(e.type), (unsigned) e.mode, (long long) e.size,
               (long long) e.mtime, (long long) e.uid, (long long) e.gid,
               e.path, e.linkname, crc);
        if (e.xattr != NULL) {
            int n = cvmfs_xattr_count((const unsigned char *) e.xattr,
                                      e.xattr_len);
            int i;

            for (i = 0; i < n; i++) {
                const char          *key;
                const unsigned char *val;
                size_t               keylen, vallen, j;

                if (cvmfs_xattr_unpack((const unsigned char *) e.xattr,
                                       e.xattr_len, (size_t) i, &key, &keylen,
                                       &val, &vallen) != 0)
                    break;
                printf("\t%.*s=", (int) keylen, key);
                for (j = 0; j < vallen; j++)
                    printf("%02x", val[j]);
            }
        }
        printf("\n");
    }
    if (rc != 0) {
        printf("ERROR: %s\n", brix_tar_error(t));
        brix_tar_close(t);
        close(fd);
        return 3;
    }
    brix_tar_close(t);
    close(fd);
    printf("EOF\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "dump") == 0)
        return dump_archive(argv[2]);
    if (argc != 1) {
        fprintf(stderr, "usage: %s [dump <archive>]\n", argv[0]);
        return 2;
    }

    printf("tar reader unit suite (D6)\n");
    t_basic();
    t_api_misuse();
    t_numeric_and_cksum();
    t_pax();
    t_gnu_long_and_unknown();
    t_ends_and_truncation();
    t_gzip();
    t_zstd();

    printf("%d checks, %d failed\n", g_checks, g_failed);
    if (g_failed == 0)
        printf("all checks passed\n");
    return g_failed == 0 ? 0 : 1;
}

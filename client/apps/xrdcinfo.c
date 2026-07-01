/*
 * xrdcinfo.c — dump a cache object's .cinfo present-bitmap as JSON.
 *
 * WHAT: Reads a ".cinfo" sidecar (or the user.xrd.cinfo xattr of a cache
 *       object) and prints the block-present bitmap + flags as one JSON object,
 *       for ops/debug and for the partial-fill test suite.
 * WHY:  The nginx-side cinfo.h struct is ngx-coupled (pulls ngx_core.h via
 *       meta.h), so a client tool cannot include it. The on-disk format is
 *       frozen/versioned, so we read fixed little-endian offsets instead —
 *       faithful and decoupled.
 * HOW:  magic u32@0 (XCI1), version u16@4 (3), flags u16@6, block_size u32@8,
 *       size u64@16, nblocks u64@32; the present-bitmap is the trailing
 *       ceil(nblocks/8) bytes (bit b present iff bitmap[b/8] & (1<<(b%8))).
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/xattr.h>

#define XRDCINFO_MAGIC      0x58434931u   /* "XCI1", little-endian */
#define XRDCINFO_VERSION    3
#define XRDCINFO_F_COMPLETE 0x1u
#define XRDCINFO_F_PARTIAL  0x2u
#define XRDCINFO_F_VERIFIED 0x4u
#define XRDCINFO_F_DIRTY    0x8u

/* Little-endian field reads at fixed offsets (buf holds at least off+width). */
static uint16_t
rd_u16(const uint8_t *b, size_t off)
{
    return (uint16_t) (b[off] | (b[off + 1] << 8));
}

static uint32_t
rd_u32(const uint8_t *b, size_t off)
{
    return (uint32_t) b[off] | ((uint32_t) b[off + 1] << 8)
         | ((uint32_t) b[off + 2] << 16) | ((uint32_t) b[off + 3] << 24);
}

static uint64_t
rd_u64(const uint8_t *b, size_t off)
{
    uint64_t v = 0;
    int      i;

    for (i = 0; i < 8; i++) {
        v |= (uint64_t) b[off + i] << (8 * i);
    }
    return v;
}

/* Read the whole record into *buf (malloc'd). Returns byte count, or -1. */
static ssize_t
slurp_file(const char *path, uint8_t **buf)
{
    FILE   *f = fopen(path, "rb");
    long    n;
    uint8_t *p;
    size_t  got;

    if (f == NULL) {
        return -1;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    n = ftell(f);
    if (n < 0) {
        fclose(f);
        return -1;
    }
    rewind(f);
    p = malloc((size_t) n + 1);
    if (p == NULL) {
        fclose(f);
        return -1;
    }
    got = fread(p, 1, (size_t) n, f);
    fclose(f);
    if (got != (size_t) n) {
        free(p);
        return -1;
    }
    *buf = p;
    return n;
}

/* Read the user.xrd.cinfo xattr of an object into *buf (malloc'd). */
static ssize_t
slurp_xattr(const char *path, uint8_t **buf)
{
    ssize_t  n = getxattr(path, "user.xrd.cinfo", NULL, 0);
    uint8_t *p;

    if (n < 0) {
        return -1;
    }
    p = malloc((size_t) n + 1);
    if (p == NULL) {
        return -1;
    }
    if (getxattr(path, "user.xrd.cinfo", p, (size_t) n) != n) {
        free(p);
        return -1;
    }
    *buf = p;
    return n;
}

/* Emit the JSON dump for a slurped record; return the process exit code. */
static int
dump_record(const uint8_t *buf, size_t n)
{
    uint16_t       flags;
    uint32_t       bsize;
    uint64_t       size;
    uint64_t       nblocks;
    size_t         bmlen;
    const uint8_t *bm;
    const char    *sep;
    uint64_t       present;
    uint64_t       b;

    if (n < 40 || rd_u32(buf, 0) != XRDCINFO_MAGIC) {
        printf("{\"error\":\"bad_magic\"}\n");
        return 2;
    }
    if (rd_u16(buf, 4) != XRDCINFO_VERSION) {
        printf("{\"error\":\"bad_version\"}\n");
        return 2;
    }
    flags   = rd_u16(buf, 6);
    bsize   = rd_u32(buf, 8);
    size    = rd_u64(buf, 16);
    nblocks = rd_u64(buf, 32);

    bmlen = (size_t) ((nblocks + 7) / 8);
    if (bmlen > n) {
        printf("{\"error\":\"bad_magic\"}\n");
        return 2;
    }
    bm = buf + (n - bmlen);   /* bitmap is the file tail */

    printf("{\"version\":3,\"flags\":[");
    sep = "";
    if (flags & XRDCINFO_F_COMPLETE) { printf("%s\"COMPLETE\"", sep); sep = ","; }
    if (flags & XRDCINFO_F_PARTIAL)  { printf("%s\"PARTIAL\"",  sep); sep = ","; }
    if (flags & XRDCINFO_F_VERIFIED) { printf("%s\"VERIFIED\"", sep); sep = ","; }
    if (flags & XRDCINFO_F_DIRTY)    { printf("%s\"DIRTY\"",    sep); sep = ","; }
    printf("],\"block_size\":%u,\"size\":%llu,\"nblocks\":%llu,",
           bsize, (unsigned long long) size, (unsigned long long) nblocks);

    present = 0;
    printf("\"present_blocks\":[");
    sep = "";
    for (b = 0; b < nblocks; b++) {
        if (bm[b / 8] & (1u << (b % 8))) {
            printf("%s%llu", sep, (unsigned long long) b);
            sep = ",";
            present++;
        }
    }
    printf("],\"present_count\":%llu,\"complete\":%s}\n",
           (unsigned long long) present,
           (flags & XRDCINFO_F_COMPLETE) ? "true" : "false");
    return 0;
}

int
main(int argc, char **argv)
{
    const char *path = NULL;
    int         use_xattr = 0;
    int         i;
    uint8_t    *buf = NULL;
    ssize_t     n;
    int         rc;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--xattr") == 0) {
            use_xattr = 1;
        } else {
            path = argv[i];
        }
    }
    if (path == NULL) {
        fprintf(stderr, "usage: xrdcinfo [--xattr] <path>\n");
        return 4;
    }

    n = use_xattr ? slurp_xattr(path, &buf) : slurp_file(path, &buf);
    if (n < 0) {
        printf("{\"absent\":true}\n");
        return 3;
    }
    rc = dump_record(buf, (size_t) n);
    free(buf);
    return rc;
}

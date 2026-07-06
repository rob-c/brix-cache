/*
 * xrdcinfo.c — dump a file's unified xmeta metadata record as JSON.
 *
 * WHAT: Reads the "user.xrd.cinfo" xattr (or the "<path>.cinfo" sidecar /
 *       an explicit record file) and prints the record as one JSON object:
 *       geometry, present bitmap, dirty/verify state, block-CRC coverage and
 *       cached digests. WHY: operators/tests inspect exactly what a node
 *       recorded for a file without any nginx dependency. HOW: a minimal
 *       self-contained parser of the xmeta layout — stock XrdPfc cinfo v4
 *       prefix (version i32, 48-byte Store POD, crc, bitmap, AStat[], crc)
 *       followed by "XCX1" TLV sections (STATE/DIGEST/BLOCKCRC/ORIGIN).
 */

#include "core/version.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/xattr.h>

#define XMETA_STOCK_VERSION 4
#define XMETA_EXT_MAGIC     0x31584358u   /* "XCX1" */
#define SEC_STATE    0x0001
#define SEC_DIGEST   0x0002
#define SEC_BLOCKCRC 0x0003
#define SEC_ORIGIN   0x0004
#define F_VERIFIED   0x0001u
#define F_EXPIRES    0x0002u

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
    int64_t  bsize, size, no_cksum;
    int32_t  astatn;
    uint64_t nblocks, present = 0, b;
    size_t   bmlen, off;
    const uint8_t *bm;
    const char *sep;
    uint64_t dirty_lo = 0, dirty_hi = 0;
    uint32_t mode = 0, state_flags = 0;
    int      have_state = 0;

    if (n < 56 || (int32_t) rd_u32(buf, 0) != XMETA_STOCK_VERSION) {
        printf("{\"error\":\"bad_magic\"}\n");
        return 2;
    }
    bsize    = (int64_t) rd_u64(buf, 4);
    size     = (int64_t) rd_u64(buf, 12);
    no_cksum = (int64_t) rd_u64(buf, 28);
    astatn   = (int32_t) rd_u32(buf, 48);
    if (bsize <= 0 || size < 0 || astatn < 0) {
        printf("{\"error\":\"bad_magic\"}\n");
        return 2;
    }
    nblocks = (size > 0) ? ((uint64_t) size + (uint64_t) bsize - 1)
                           / (uint64_t) bsize : 0;
    bmlen = (size_t) ((nblocks + 7) / 8);
    off = 4 + 48 + 4;                        /* version + Store + crc */
    if (off + bmlen + (size_t) astatn * 56 + 4 > n) {
        printf("{\"error\":\"bad_magic\"}\n");
        return 2;
    }
    bm = buf + off;
    off += bmlen + (size_t) astatn * 56 + 4; /* bitmap + AStat[] + crc */

    printf("{\"version\":4,\"block_size\":%lld,\"size\":%lld,"
           "\"nblocks\":%llu,", (long long) bsize, (long long) size,
           (unsigned long long) nblocks);

    printf("\"present_blocks\":[");
    sep = "";
    for (b = 0; b < nblocks; b++) {
        if (bm[b / 8] & (1u << (b % 8))) {
            printf("%s%llu", sep, (unsigned long long) b);
            sep = ",";
            present++;
        }
    }
    printf("],\"present_count\":%llu,\"complete\":%s",
           (unsigned long long) present,
           (nblocks == 0 || present == nblocks) ? "true" : "false");

    /* extension sections */
    if (off + 8 <= n && rd_u32(buf, off) == XMETA_EXT_MAGIC) {
        uint16_t nsec = rd_u16(buf, off + 6);
        uint16_t i;

        off += 8;
        for (i = 0; i < nsec && off + 12 <= n; i++) {
            uint16_t type = rd_u16(buf, off);
            uint32_t plen = rd_u32(buf, off + 4);
            size_t   pay  = off + 8;

            if (pay + plen + 4 > n) {
                break;
            }
            if (type == SEC_STATE && plen >= 80) {
                dirty_lo    = rd_u64(buf, pay + 8);
                dirty_hi    = rd_u64(buf, pay + 16);
                mode        = rd_u32(buf, pay + 72);
                state_flags = rd_u32(buf, pay + 76);
                have_state  = 1;
                printf(",\"origin_mtime\":%llu,\"flush_gen\":%llu",
                       (unsigned long long) rd_u64(buf, pay),
                       (unsigned long long) rd_u64(buf, pay + 24));
            } else if (type == SEC_BLOCKCRC && plen >= 16) {
                uint64_t nb = rd_u64(buf, pay + 8), set = 0, k;

                for (k = 0; k < nb && pay + 16 + k * 4 + 4 <= n; k++) {
                    if (rd_u32(buf, pay + 16 + (size_t) k * 4) != 0) {
                        set++;
                    }
                }
                printf(",\"blockcrc\":{\"granule\":%u,\"nblocks\":%llu,"
                       "\"computed\":%llu}", rd_u32(buf, pay),
                       (unsigned long long) nb, (unsigned long long) set);
            } else if (type == SEC_DIGEST) {
                size_t d = pay, dend = pay + plen;

                printf(",\"digests\":[");
                sep = "";
                while (d + 4 <= dend) {
                    uint16_t alg = rd_u16(buf, d);
                    uint16_t vl  = rd_u16(buf, d + 2);
                    size_t   j;

                    if (d + 4 + vl > dend) {
                        break;
                    }
                    printf("%s{\"alg\":%u,\"value\":\"", sep, alg);
                    for (j = 0; j < vl; j++) {
                        uint8_t ch = buf[d + 4 + j];
                        if (ch >= 0x20 && ch < 0x7f && ch != '"'
                            && ch != '\\')
                        {
                            putchar(ch);
                        } else {
                            printf("\\u%04x", ch);
                        }
                    }
                    printf("\"}");
                    sep = ",";
                    d += 4 + (size_t) vl;
                }
                printf("]");
            }
            off = pay + plen + 4;
        }
    }

    printf(",\"flags\":[");
    sep = "";
    if (nblocks == 0 || present == nblocks) {
        printf("%s\"COMPLETE\"", sep); sep = ",";
    } else if (present > 0) {
        printf("%s\"PARTIAL\"", sep); sep = ",";
    }
    if (have_state && dirty_lo < dirty_hi) {
        printf("%s\"DIRTY\"", sep); sep = ",";
    }
    if (state_flags & F_VERIFIED) {
        printf("%s\"VERIFIED\"", sep); sep = ",";
    }
    if (no_cksum != 0) {
        printf("%s\"UNVERIFIED_BLOCKS\"", sep); sep = ",";
    }
    printf("],\"mode\":%u}\n", mode);
    return 0;
}

/* Real main; dispatched from the xrdcksum multi-call binary (xrdcksum.c). */
int
brix_xrdcinfo_main(int argc, char **argv)
{
    const char *path = NULL;
    int         use_xattr = 0;
    int         i;
    uint8_t    *buf = NULL;
    ssize_t     n;
    int         rc;

    /* xrdcinfo does not include brix.h — bring in version.h directly. */
    if (argc >= 2) {
        if (strcmp(argv[1], "--version") == 0) {
            /* version.h included at file top (see include block below) */
            printf("xrdcinfo (BriX-Cache client) %s\n", brix_client_version());
            return 0;
        }
        if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            printf("usage: xrdcinfo [--xattr] <path>\n"
                   "  dump a proxy-cache .cinfo / xmeta xattr as JSON\n"
                   BRIX_USAGE_FOOTER("xrdcinfo"));
            return 0;
        }
    }

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

    /* carrier chain: the data file's xattr, then its "<path>.cinfo"
     * sidecar, then the path itself as a raw record file. --xattr forces
     * the first form only. */
    n = slurp_xattr(path, &buf);
    if (n < 0 && !use_xattr) {
        char sc[4096];
        int  k = snprintf(sc, sizeof(sc), "%s.cinfo", path);

        if (k > 0 && (size_t) k < sizeof(sc)) {
            n = slurp_file(sc, &buf);
        }
        if (n < 0) {
            n = slurp_file(path, &buf);
        }
    }
    if (n < 0) {
        printf("{\"absent\":true}\n");
        return 3;
    }
    rc = dump_record(buf, (size_t) n);
    free(buf);
    return rc;
}

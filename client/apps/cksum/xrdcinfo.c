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

/*
 * xmeta_hdr_t — the decoded stock-cinfo v4 prefix (geometry + bitmap window).
 * WHAT: geometry fields plus the byte offsets the JSON dump needs. WHY: the
 * header parse and the emitters share exactly this state; passing one struct
 * keeps the data flow explicit and each emitter pure. HOW: filled once by
 * parse_stock_header(), then read by the present/flags emitters.
 */
typedef struct {
    int64_t        bsize;      /* block size */
    int64_t        size;       /* logical file size */
    int64_t        no_cksum;   /* count of blocks lacking a verified checksum */
    uint64_t       nblocks;    /* derived block count */
    const uint8_t *bm;         /* present bitmap (nblocks bits) */
    size_t         ext_off;    /* offset of the first extension section */
} xmeta_hdr_t;

/*
 * xmeta_state_t — the STATE-section fields the flags emitter consumes.
 * WHAT: dirty window, POSIX mode, state flag bits, and a presence marker.
 * WHY: the STATE section is optional; the flags line needs its values (or their
 * zeroed absence) resolved before it runs. HOW: zero-initialised by the caller,
 * populated by emit_ext_state() when a STATE section is present.
 */
typedef struct {
    uint64_t dirty_lo;
    uint64_t dirty_hi;
    uint32_t mode;
    uint32_t flags;
    int      have_state;
} xmeta_state_t;

/*
 * parse_stock_header — validate and decode the stock v4 cinfo prefix.
 * WHAT: checks magic/geometry bounds and fills *h with block geometry, the
 * bitmap pointer and the extension offset. WHY: isolates all bounds checks in
 * one pure step so the dumper orchestrator stays flat. HOW: returns 0 on
 * success, or the process exit code (2) on any malformed field — the caller
 * emits the frozen "bad_magic" object on non-zero.
 */
static int
parse_stock_header(const uint8_t *buf, size_t n, xmeta_hdr_t *h)
{
    int32_t astatn;
    size_t  bmlen, off;

    if (n < 56 || (int32_t) rd_u32(buf, 0) != XMETA_STOCK_VERSION) {
        return 2;
    }
    h->bsize    = (int64_t) rd_u64(buf, 4);
    h->size     = (int64_t) rd_u64(buf, 12);
    h->no_cksum = (int64_t) rd_u64(buf, 28);
    astatn      = (int32_t) rd_u32(buf, 48);
    if (h->bsize <= 0 || h->size < 0 || astatn < 0) {
        return 2;
    }
    h->nblocks = (h->size > 0)
        ? ((uint64_t) h->size + (uint64_t) h->bsize - 1) / (uint64_t) h->bsize
        : 0;
    bmlen = (size_t) ((h->nblocks + 7) / 8);
    off = 4 + 48 + 4;                        /* version + Store + crc */
    if (off + bmlen + (size_t) astatn * 56 + 4 > n) {
        return 2;
    }
    h->bm = buf + off;
    h->ext_off = off + bmlen + (size_t) astatn * 56 + 4; /* + AStat[] + crc */
    return 0;
}

/*
 * emit_geometry — print the leading geometry keys of the JSON object.
 * WHAT: opens the object and emits version/block_size/size/nblocks. WHY: the
 * fixed prefix is a single concern separate from the variable bitmap/sections.
 * HOW: byte-identical to the original leading printf; side effect only.
 */
static void
emit_geometry(const xmeta_hdr_t *h)
{
    printf("{\"version\":4,\"block_size\":%lld,\"size\":%lld,"
           "\"nblocks\":%llu,", (long long) h->bsize, (long long) h->size,
           (unsigned long long) h->nblocks);
}

/*
 * emit_present_bitmap — print the present_blocks array and completeness keys.
 * WHAT: walks the bitmap, emits each present block index, then present_count
 * and complete. WHY: the present-bitmap emit is one self-contained section.
 * HOW: returns the present-block count so the flags emitter can classify
 * complete/partial without rescanning; output bytes are frozen.
 */
static uint64_t
emit_present_bitmap(const xmeta_hdr_t *h)
{
    uint64_t    present = 0, b;
    const char *sep = "";

    printf("\"present_blocks\":[");
    for (b = 0; b < h->nblocks; b++) {
        if (h->bm[b / 8] & (1u << (b % 8))) {
            printf("%s%llu", sep, (unsigned long long) b);
            sep = ",";
            present++;
        }
    }
    printf("],\"present_count\":%llu,\"complete\":%s",
           (unsigned long long) present,
           (h->nblocks == 0 || present == h->nblocks) ? "true" : "false");
    return present;
}

/*
 * emit_ext_state — handle a STATE (SEC_STATE) extension section.
 * WHAT: records dirty/mode/flags into *st and emits origin_mtime/flush_gen.
 * WHY: STATE feeds both the JSON stream (mtime/gen) and the later flags line
 * (dirty/verified/mode). HOW: pure record + one frozen printf; only acts when
 * the payload is long enough, matching the original guard.
 */
static void
emit_ext_state(const uint8_t *buf, size_t pay, uint32_t plen,
    xmeta_state_t *st)
{
    if (plen < 80) {
        return;
    }
    st->dirty_lo   = rd_u64(buf, pay + 8);
    st->dirty_hi   = rd_u64(buf, pay + 16);
    st->mode       = rd_u32(buf, pay + 72);
    st->flags      = rd_u32(buf, pay + 76);
    st->have_state = 1;
    printf(",\"origin_mtime\":%llu,\"flush_gen\":%llu",
           (unsigned long long) rd_u64(buf, pay),
           (unsigned long long) rd_u64(buf, pay + 24));
}

/*
 * emit_ext_blockcrc — handle a BLOCKCRC (SEC_BLOCKCRC) extension section.
 * WHAT: counts the non-zero per-block CRC slots and emits the blockcrc object.
 * WHY: block-CRC coverage is its own JSON key. HOW: bounds-checked scan against
 * n, then one frozen printf; only acts on a payload of the minimum size.
 */
static void
emit_ext_blockcrc(const uint8_t *buf, size_t n, size_t pay, uint32_t plen)
{
    uint64_t nb, set = 0, k;

    if (plen < 16) {
        return;
    }
    nb = rd_u64(buf, pay + 8);
    for (k = 0; k < nb && pay + 16 + k * 4 + 4 <= n; k++) {
        if (rd_u32(buf, pay + 16 + (size_t) k * 4) != 0) {
            set++;
        }
    }
    printf(",\"blockcrc\":{\"granule\":%u,\"nblocks\":%llu,"
           "\"computed\":%llu}", rd_u32(buf, pay),
           (unsigned long long) nb, (unsigned long long) set);
}

/*
 * emit_digest_value — print one digest value as an escaped JSON string body.
 * WHAT: walks vl bytes at buf[base] emitting printable ASCII verbatim and
 * escaping everything else as \uXXXX. WHY: the escape loop is the reusable core
 * of the digest emitter. HOW: putchar/printf side effects only; bytes frozen.
 */
static void
emit_digest_value(const uint8_t *buf, size_t base, uint16_t vl)
{
    size_t j;

    for (j = 0; j < vl; j++) {
        uint8_t ch = buf[base + j];

        if (ch >= 0x20 && ch < 0x7f && ch != '"' && ch != '\\') {
            putchar(ch);
        } else {
            printf("\\u%04x", ch);
        }
    }
}

/*
 * emit_ext_digest — handle a DIGEST (SEC_DIGEST) extension section.
 * WHAT: emits the digests array, one {alg,value} object per TLV entry. WHY:
 * cached digests are their own JSON key with a variable-length entry list.
 * HOW: iterates the alg/len/value triples within the payload window, delegating
 * value escaping to emit_digest_value; output bytes are frozen.
 */
static void
emit_ext_digest(const uint8_t *buf, size_t pay, uint32_t plen)
{
    size_t      d = pay, dend = pay + plen;
    const char *sep = "";

    printf(",\"digests\":[");
    while (d + 4 <= dend) {
        uint16_t alg = rd_u16(buf, d);
        uint16_t vl  = rd_u16(buf, d + 2);

        if (d + 4 + vl > dend) {
            break;
        }
        printf("%s{\"alg\":%u,\"value\":\"", sep, alg);
        emit_digest_value(buf, d + 4, vl);
        printf("\"}");
        sep = ",";
        d += 4 + (size_t) vl;
    }
    printf("]");
}

/*
 * emit_ext_sections — walk the "XCX1" TLV extension block, if present.
 * WHAT: dispatches each section to its type-specific emitter and collects STATE
 * fields into *st. WHY: the section loop is a distinct concern from the header
 * and flags emitters, and its per-type dispatch reads cleanly as a switch.
 * HOW: bounds-checked TLV walk identical to the original; no output when the
 * block is absent.
 */
static void
emit_ext_sections(const uint8_t *buf, size_t n, const xmeta_hdr_t *h,
    xmeta_state_t *st)
{
    size_t   off = h->ext_off;
    uint16_t nsec, i;

    if (off + 8 > n || rd_u32(buf, off) != XMETA_EXT_MAGIC) {
        return;
    }
    nsec = rd_u16(buf, off + 6);
    off += 8;
    for (i = 0; i < nsec && off + 12 <= n; i++) {
        uint16_t type = rd_u16(buf, off);
        uint32_t plen = rd_u32(buf, off + 4);
        size_t   pay  = off + 8;

        if (pay + plen + 4 > n) {
            break;
        }
        switch (type) {
        case SEC_STATE:
            emit_ext_state(buf, pay, plen, st);
            break;
        case SEC_BLOCKCRC:
            emit_ext_blockcrc(buf, n, pay, plen);
            break;
        case SEC_DIGEST:
            emit_ext_digest(buf, pay, plen);
            break;
        default:
            break;
        }
        off = pay + plen + 4;
    }
}

/*
 * emit_flags — print the trailing flags array and mode, closing the object.
 * WHAT: derives COMPLETE/PARTIAL/DIRTY/VERIFIED/UNVERIFIED_BLOCKS from the
 * decoded header + state and emits them with the mode. WHY: the flags line is
 * the final derived summary and belongs in one place. HOW: same guard order and
 * separator handling as the original; output bytes frozen.
 */
static void
emit_flags(const xmeta_hdr_t *h, const xmeta_state_t *st, uint64_t present)
{
    const char *sep = "";

    printf(",\"flags\":[");
    if (h->nblocks == 0 || present == h->nblocks) {
        printf("%s\"COMPLETE\"", sep); sep = ",";
    } else if (present > 0) {
        printf("%s\"PARTIAL\"", sep); sep = ",";
    }
    if (st->have_state && st->dirty_lo < st->dirty_hi) {
        printf("%s\"DIRTY\"", sep); sep = ",";
    }
    if (st->flags & F_VERIFIED) {
        printf("%s\"VERIFIED\"", sep); sep = ",";
    }
    if (h->no_cksum != 0) {
        printf("%s\"UNVERIFIED_BLOCKS\"", sep); sep = ",";
    }
    printf("],\"mode\":%u}\n", st->mode);
}

/*
 * dump_record — emit the JSON dump for a slurped record; return the exit code.
 * WHAT: orchestrates header parse → geometry → present bitmap → extension
 * sections → flags. WHY: keeps the top-level dumper a flat, readable sequence of
 * named steps. HOW: on a malformed header emits the frozen "bad_magic" object
 * and returns 2; otherwise composes the emitters and returns 0.
 */
static int
dump_record(const uint8_t *buf, size_t n)
{
    xmeta_hdr_t   h  = {0};
    xmeta_state_t st = {0};
    uint64_t      present;

    if (parse_stock_header(buf, n, &h) != 0) {
        printf("{\"error\":\"bad_magic\"}\n");
        return 2;
    }
    emit_geometry(&h);
    present = emit_present_bitmap(&h);
    emit_ext_sections(buf, n, &h, &st);
    emit_flags(&h, &st, present);
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

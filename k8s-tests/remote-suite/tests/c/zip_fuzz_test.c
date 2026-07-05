/*
 * zip_fuzz_test.c — adversarial/security fuzz of the ZIP central-directory
 * parser in client/lib/zip.c (brix_zip_open / brix_zip_member_extract).
 *
 * Build (from repo root):
 *   cc -std=c11 -Wall -Wextra -D_GNU_SOURCE -I client/lib \
 *      tests/c/zip_fuzz_test.c client/lib/zip.c -lz -o /tmp/zip_fuzz_test \
 *   && /tmp/zip_fuzz_test
 *
 * Modeled on tests/c/zip_test.c: self-contained main(), CHECK() asserts, prints
 * "ok ..." lines and "== ALL PASSED ==" / nonzero exit on failure.  It builds a
 * valid base archive with python3's zipfile, slurps it into memory, then mutates
 * raw bytes to drive the parser down its bounds-check / reject paths.  Every case
 * must return a NEGATIVE brix_zip_* code (never crash / read OOB / ASAN-trip):
 *
 *   (1) corrupted EOCD signature            -> ENOTZIP
 *   (2) CD offset beyond archive            -> EBADF
 *   (3) CD size field huge (> archive)      -> EBADF
 *   (4) entry-count 0xFFFF, no ZIP64 loc.   -> negative (ENOTZIP or EBADF)
 *   (5) CDFH lfh_off beyond archive         -> negative (open or extract)
 *   (6) member method != 0 && != 8 (=12)    -> EMETHOD
 *   (7) member with a corrupted data byte   -> ECRC
 *   (8) truncated archive (last 50 cut)     -> negative
 *
 * The archive is read through a pread-from-memory callback over the mutated
 * buffer, so no temp .zip files are written for the mutated cases — keeping the
 * fuzz entirely in-process where ASAN can see every out-of-bounds access.
 */

#include "protocols/shared/zip.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail = 0;
#define CHECK(c, ...) do { if (!(c)) { printf("  FAIL: "); printf(__VA_ARGS__); \
    printf("\n"); g_fail = 1; } } while (0)

/* ---- pread-from-memory adapter ----------------------------------------- *
 * Strict bounds-checked pread over a flat buffer.  A short read (off/len that
 * runs past the buffer) returns the partial count, exactly like a real pread on
 * a short file; an out-of-range offset returns 0.  This means the parser must
 * defend itself — the callback never reads OOB on its own. */
typedef struct { const uint8_t *data; size_t len; } membuf;

/* Discard sink: accepts and drops all inflated bytes (returns 0 = continue).
 * brix_zip_member_extract requires a non-NULL sink — it calls it unconditionally
 * for produced bytes — so the fuzz must supply one; we only care about the rc. */
static int
discard_sink(void *sink_ctx, const uint8_t *data, size_t len)
{
    (void) sink_ctx; (void) data; (void) len;
    return 0;
}

static ssize_t
mem_pread(void *ctx, uint64_t off, void *buf, size_t len)
{
    const membuf *m = ctx;

    if (off >= m->len) {
        return 0;
    }
    {
        size_t avail = m->len - (size_t) off;
        size_t n     = (len < avail) ? len : avail;
        memcpy(buf, m->data + (size_t) off, n);
        return (ssize_t) n;
    }
}

/* ---- little-endian helpers for locating + patching archive fields ------- */
static uint16_t le16(const uint8_t *p) { return (uint16_t) (p[0] | (p[1] << 8)); }
static uint32_t le32(const uint8_t *p)
{
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8)
         | ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}
static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t) v; p[1] = (uint8_t) (v >> 8); }
static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t) v;         p[1] = (uint8_t) (v >> 8);
    p[2] = (uint8_t) (v >> 16); p[3] = (uint8_t) (v >> 24);
}

#define SIG_EOCD 0x06054b50u
#define SIG_CDFH 0x02014b50u

/* Locate the EOCD record offset by scanning backward for its signature. */
static long
find_eocd_off(const uint8_t *b, size_t n)
{
    long i;
    if (n < 22) {
        return -1;
    }
    for (i = (long) n - 22; i >= 0; i--) {
        if (le32(b + i) == SIG_EOCD) {
            return i;
        }
    }
    return -1;
}

/* Locate the first central-directory file header by scanning forward. */
static long
find_cdfh_off(const uint8_t *b, size_t n)
{
    size_t i;
    if (n < 4) {
        return -1;
    }
    for (i = 0; i + 4 <= n; i++) {
        if (le32(b + i) == SIG_CDFH) {
            return (long) i;
        }
    }
    return -1;
}

/* Build a fresh in-memory copy of the base archive (caller frees). */
static uint8_t *
dup_base(const uint8_t *base, size_t len)
{
    uint8_t *c = malloc(len);
    if (c != NULL) {
        memcpy(c, base, len);
    }
    return c;
}

/* Run brix_zip_open over a mutated buffer and assert the rc is negative.
 * `accept`, when non-zero, is the exact code we expect (the prompt's primary
 * intent); we still pass on ANY negative code (the contract = "negative + no
 * crash"), but log a note if the exact code differs. */
static int
open_expect_neg(const char *label, const uint8_t *buf, size_t len, int accept)
{
    membuf       m = { buf, len };
    brix_zip_dir dir;
    int          rc = brix_zip_open(mem_pread, &m, len, &dir);

    CHECK(rc < 0, "%s: expected negative rc, got %d", label, rc);
    if (rc == XRDC_ZIP_OK) {
        brix_zip_dir_free(&dir);   /* defensive: shouldn't happen */
        return rc;
    }
    if (accept != 0 && rc != accept) {
        printf("  note %s: rc=%d (expected %d), accepting any negative\n",
               label, rc, accept);
    }
    return rc;
}

/* ---- main fuzz battery -------------------------------------------------- */
int
main(void)
{
    uint8_t *base;
    size_t   base_len = 0;
    long     eocd, cdfh;

    printf("== zip central-directory fuzz test ==\n");

    /* Build a valid base archive (one STORE + one DEFLATE member). */
    if (system(
        "python3 - <<'PY'\n"
        "import zipfile, os\n"
        "os.makedirs('/tmp/ztf', exist_ok=True)\n"
        "d1 = bytes((i*7)&0xff for i in range(4096))\n"
        "d2 = b'deflate fuzz payload ' * 600\n"
        "z = zipfile.ZipFile('/tmp/ztf/base.zip','w')\n"
        "z.writestr('store.bin', d1, zipfile.ZIP_STORED)\n"
        "z.writestr('defl.txt',  d2, zipfile.ZIP_DEFLATED)\n"
        "z.close()\n"
        "zipfile.ZipFile('/tmp/ztf/empty.zip','w').close()\n"   /* 0-entry archive */
        "PY\n") != 0) {
        printf("  SKIP: could not build base fixture (python3/zipfile unavailable)\n");
        return 0;
    }

    {
        FILE *f = fopen("/tmp/ztf/base.zip", "rb");
        long  sz;
        CHECK(f != NULL, "open base.zip");
        if (f == NULL) { printf("== FAILED ==\n"); return 1; }
        fseek(f, 0, SEEK_END); sz = ftell(f); fseek(f, 0, SEEK_SET);
        base_len = (size_t) sz;
        base = malloc(base_len);
        CHECK(base != NULL && fread(base, 1, base_len, f) == base_len, "read base.zip");
        fclose(f);
        if (base == NULL) { printf("== FAILED ==\n"); return 1; }
    }

    /* Sanity: the unmutated base must open + extract cleanly (proves the harness
     * and pread adapter are correct before we start corrupting bytes). */
    {
        membuf       m = { base, base_len };
        brix_zip_dir dir;
        int          rc = brix_zip_open(mem_pread, &m, base_len, &dir);
        CHECK(rc == XRDC_ZIP_OK, "base open rc=%d", rc);
        if (rc == XRDC_ZIP_OK) {
            const brix_zip_entry *e = brix_zip_find(&dir, "store.bin");
            CHECK(e != NULL, "base find store.bin");
            CHECK(dir.n == 2, "base entry count %zu != 2", dir.n);
            brix_zip_dir_free(&dir);
        }
        printf("  ok   base archive opens cleanly (n=2)\n");
    }

    eocd = find_eocd_off(base, base_len);
    cdfh = find_cdfh_off(base, base_len);
    CHECK(eocd >= 0, "locate EOCD in base");
    CHECK(cdfh >= 0, "locate first CDFH in base");
    if (eocd < 0 || cdfh < 0) { printf("== FAILED ==\n"); free(base); return 1; }

    /* (1) Corrupted EOCD signature -> ENOTZIP (no EOCD found at all). */
    {
        uint8_t *b = dup_base(base, base_len);
        CHECK(b != NULL, "dup case1");
        if (b != NULL) {
            b[eocd] ^= 0xFF;                       /* break the 'PK\5\6' sig */
            int rc = open_expect_neg("case1 bad-EOCD-sig", b, base_len, XRDC_ZIP_ENOTZIP);
            CHECK(rc == XRDC_ZIP_ENOTZIP, "case1 expected ENOTZIP, got %d", rc);
            printf("  ok   (1) corrupted EOCD signature -> %d (ENOTZIP)\n", rc);
            free(b);
        }
    }

    /* (2) CD offset pointed beyond the archive -> EBADF. */
    {
        uint8_t *b = dup_base(base, base_len);
        CHECK(b != NULL, "dup case2");
        if (b != NULL) {
            put32(b + eocd + 16, (uint32_t) (base_len + 0x1000));  /* cd_off > asize */
            int rc = open_expect_neg("case2 cd-off-OOB", b, base_len, XRDC_ZIP_EBADF);
            CHECK(rc == XRDC_ZIP_EBADF, "case2 expected EBADF, got %d", rc);
            printf("  ok   (2) CD offset beyond archive -> %d (EBADF)\n", rc);
            free(b);
        }
    }

    /* (3) CD size field huge (> archive, but under MAX_CD_SIZE) -> EBADF. */
    {
        uint8_t *b = dup_base(base, base_len);
        CHECK(b != NULL, "dup case3");
        if (b != NULL) {
            /* base_len ~2-3KB; pick a size well over the archive yet under the
             * 256 MiB MAX_CD_SIZE cap so we exercise the cd_off+cd_size>asize
             * bounds check, not the cap. */
            put32(b + eocd + 12, (uint32_t) (base_len + 0x4000));
            int rc = open_expect_neg("case3 cd-size-huge", b, base_len, XRDC_ZIP_EBADF);
            CHECK(rc == XRDC_ZIP_EBADF, "case3 expected EBADF, got %d", rc);
            printf("  ok   (3) CD size > archive -> %d (EBADF)\n", rc);
            free(b);
        }
    }

    /* (4) Classic EOCD entry-count = 0xFFFF with no valid ZIP64 locator.
     * Saturating the count forces the ZIP64 follow; with no locator present the
     * parser must reject (here: cd_off is also saturated so the post-ZIP64
     * bounds check fires) rather than fabricate entries or crash. */
    {
        uint8_t *b = dup_base(base, base_len);
        CHECK(b != NULL, "dup case4");
        if (b != NULL) {
            put16(b + eocd + 8,  0xFFFF);              /* entries this disk */
            put16(b + eocd + 10, 0xFFFF);              /* entries total     */
            put32(b + eocd + 16, 0xFFFFFFFFu);         /* cd_off saturated  */
            int rc = open_expect_neg("case4 0xFFFF-no-zip64", b, base_len, 0);
            CHECK(rc < 0, "case4 expected negative, got %d", rc);
            printf("  ok   (4) 0xFFFF entries w/o ZIP64 locator -> %d (negative)\n", rc);
            free(b);
        }
    }

    /* (5) A CDFH lfh_off set beyond the archive: brix_zip_open's per-entry extent
     * check (lfh_off >= archive_size) must reject; even if it slipped through,
     * member_data_offset's read_exact would return negative — never an OOB read. */
    {
        uint8_t *b = dup_base(base, base_len);
        CHECK(b != NULL, "dup case5");
        if (b != NULL) {
            /* CDFH local-header-offset is at field +42. */
            put32(b + cdfh + 42, (uint32_t) (base_len + 0x2000));
            membuf       m = { b, base_len };
            brix_zip_dir dir;
            int          rc = brix_zip_open(mem_pread, &m, base_len, &dir);

            if (rc == XRDC_ZIP_OK) {
                /* Open tolerated it — then locate + extract MUST go negative. */
                const brix_zip_entry *e = brix_zip_find(&dir, "store.bin");
                CHECK(e != NULL, "case5 find after lenient open");
                if (e != NULL) {
                    int xrc = brix_zip_member_extract(mem_pread, &m, e,
                                                      discard_sink, NULL);
                    CHECK(xrc < 0, "case5 extract expected negative, got %d", xrc);
                    printf("  ok   (5) lfh_off OOB -> open OK, extract %d (negative)\n", xrc);
                }
                brix_zip_dir_free(&dir);
            } else {
                CHECK(rc < 0, "case5 open expected negative, got %d", rc);
                printf("  ok   (5) lfh_off beyond archive -> open %d (negative)\n", rc);
            }
            free(b);
        }
    }

    /* (6) Member method neither 0 nor 8 (patch CDFH method field to 12) -> EMETHOD.
     * The method field lives at CDFH offset +10; this is parsed into entry.method
     * and member_extract rejects it before touching any data. */
    {
        uint8_t *b = dup_base(base, base_len);
        CHECK(b != NULL, "dup case6");
        if (b != NULL) {
            put16(b + cdfh + 10, 12);                  /* bogus method */
            membuf       m = { b, base_len };
            brix_zip_dir dir;
            int          rc = brix_zip_open(mem_pread, &m, base_len, &dir);
            CHECK(rc == XRDC_ZIP_OK, "case6 open rc=%d", rc);
            if (rc == XRDC_ZIP_OK) {
                const brix_zip_entry *e = brix_zip_find(&dir, "store.bin");
                CHECK(e != NULL, "case6 find store.bin");
                if (e != NULL) {
                    CHECK(e->method == 12, "case6 method parsed as %u", e->method);
                    int xrc = brix_zip_member_extract(mem_pread, &m, e,
                                                      discard_sink, NULL);
                    CHECK(xrc == XRDC_ZIP_EMETHOD,
                          "case6 expected EMETHOD, got %d", xrc);
                    printf("  ok   (6) bogus method 12 -> %d (EMETHOD)\n", xrc);
                }
                brix_zip_dir_free(&dir);
            }
            free(b);
        }
    }

    /* (7) Corrupt a member data byte -> ECRC (STORE member: byte flows verbatim,
     * size matches, but the CRC-32 over the data won't match the CD value). */
    {
        uint8_t *b = dup_base(base, base_len);
        CHECK(b != NULL, "dup case7");
        if (b != NULL) {
            membuf       m = { b, base_len };
            brix_zip_dir dir;
            int          rc = brix_zip_open(mem_pread, &m, base_len, &dir);
            CHECK(rc == XRDC_ZIP_OK, "case7 open rc=%d", rc);
            if (rc == XRDC_ZIP_OK) {
                const brix_zip_entry *e = brix_zip_find(&dir, "store.bin");
                CHECK(e != NULL, "case7 find store.bin");
                if (e != NULL && e->comp_size > 0) {
                    /* Flip a byte inside the STORE member's data region (just past
                     * its local file header: lfh(30) + name + extra). */
                    uint8_t *lfh = b + e->lfh_off;
                    uint64_t doff = e->lfh_off + 30 + le16(lfh + 26) + le16(lfh + 28);
                    CHECK(doff < base_len, "case7 data offset in range");
                    if (doff < base_len) {
                        b[doff] ^= 0xFF;
                        int xrc = brix_zip_member_extract(mem_pread, &m, e,
                                                          discard_sink, NULL);
                        CHECK(xrc == XRDC_ZIP_ECRC,
                              "case7 expected ECRC, got %d", xrc);
                        printf("  ok   (7) corrupted data byte -> %d (ECRC)\n", xrc);
                    }
                }
                brix_zip_dir_free(&dir);
            }
            free(b);
        }
    }

    /* (8) Truncated archive (cut last 50 bytes) -> negative.  Removing the tail
     * destroys the EOCD; the parser must reject (ENOTZIP/EBADF), not crash. */
    {
        size_t tlen = (base_len > 50) ? base_len - 50 : 0;
        uint8_t *b = dup_base(base, tlen ? tlen : 1);
        CHECK(b != NULL, "dup case8");
        if (b != NULL) {
            int rc = open_expect_neg("case8 truncated", b, tlen, 0);
            CHECK(rc < 0, "case8 expected negative, got %d", rc);
            printf("  ok   (8) truncated archive (-50B) -> %d (negative)\n", rc);
            free(b);
        }
    }

    /* (9) Corrupt a byte inside the DEFLATE member's compressed stream -> the
     * inflate must fail with EINFLATE (or, if the bit-flip still inflates to a
     * different length/content, EBADF/ECRC) — never silent success.  The base
     * fixture's only DEFLATE member is defl.txt. */
    {
        uint8_t *b = dup_base(base, base_len);
        CHECK(b != NULL, "dup case9");
        if (b != NULL) {
            membuf       m = { b, base_len };
            brix_zip_dir dir;
            int          rc = brix_zip_open(mem_pread, &m, base_len, &dir);
            CHECK(rc == XRDC_ZIP_OK, "case9 open rc=%d", rc);
            if (rc == XRDC_ZIP_OK) {
                const brix_zip_entry *e = brix_zip_find(&dir, "defl.txt");
                CHECK(e != NULL && e->method == 8, "case9 find defl.txt (DEFLATE)");
                if (e != NULL && e->comp_size > 4) {
                    uint8_t *lfh  = b + e->lfh_off;
                    uint64_t doff = e->lfh_off + 30 + le16(lfh + 26) + le16(lfh + 28);
                    /* flip a byte a few bytes into the deflate stream (past the
                     * block header) so the bit-stream is genuinely corrupt. */
                    uint64_t hit  = doff + 3;
                    CHECK(hit < base_len, "case9 data offset in range");
                    if (hit < base_len) {
                        b[hit] ^= 0x55;
                        int xrc = brix_zip_member_extract(mem_pread, &m, e,
                                                          discard_sink, NULL);
                        CHECK(xrc < 0,
                              "case9 corrupt deflate must go negative, got %d", xrc);
                        if (xrc != XRDC_ZIP_EINFLATE) {
                            printf("  note case9: rc=%d (EINFLATE=%d), accepting any negative\n",
                                   xrc, XRDC_ZIP_EINFLATE);
                        }
                        printf("  ok   (9) corrupt DEFLATE stream -> %d (negative)\n", xrc);
                    }
                }
                brix_zip_dir_free(&dir);
            }
            free(b);
        }
    }

    /* (10) Zip-bomb: declare a tiny uncompressed size for the DEFLATE member so
     * the produced output exceeds it -> the per-byte output guard trips EBOMB
     * (the kernel never trusts the header size for allocation).  Patch defl.txt's
     * CDFH uncomp_size (field +24) down to 8 bytes; its real output is ~12 KiB. */
    {
        long cdfh2 = -1, i;
        for (i = cdfh + 4; i + 4 <= (long) base_len; i++) {
            if (le32(base + i) == SIG_CDFH) { cdfh2 = i; break; }
        }
        CHECK(cdfh2 >= 0, "case10 locate 2nd CDFH (defl.txt)");
        if (cdfh2 >= 0) {
            uint8_t *b = dup_base(base, base_len);
            CHECK(b != NULL, "dup case10");
            if (b != NULL) {
                put32(b + cdfh2 + 24, 8);              /* lie: uncomp_size = 8 */
                membuf       m = { b, base_len };
                brix_zip_dir dir;
                int          rc = brix_zip_open(mem_pread, &m, base_len, &dir);
                CHECK(rc == XRDC_ZIP_OK, "case10 open rc=%d", rc);
                if (rc == XRDC_ZIP_OK) {
                    const brix_zip_entry *e = brix_zip_find(&dir, "defl.txt");
                    CHECK(e != NULL && e->uncomp_size == 8, "case10 uncomp_size lied");
                    if (e != NULL) {
                        int xrc = brix_zip_member_extract(mem_pread, &m, e,
                                                          discard_sink, NULL);
                        CHECK(xrc == XRDC_ZIP_EBOMB,
                              "case10 expected EBOMB, got %d", xrc);
                        printf("  ok   (10) output > declared uncomp_size -> %d (EBOMB)\n", xrc);
                    }
                    brix_zip_dir_free(&dir);
                }
                free(b);
            }
        }
    }

    /* (11) STORE member whose declared uncomp_size disagrees with comp_size:
     * the verbatim copy produces comp_size bytes, which won't equal the inflated
     * uncomp_size -> EBADF (short/over).  Patch store.bin's CDFH uncomp_size
     * (field +24) UP so produced < declared (avoids the EBOMB path) -> EBADF. */
    {
        uint8_t *b = dup_base(base, base_len);
        CHECK(b != NULL, "dup case11");
        if (b != NULL) {
            uint32_t real_un = le32(b + cdfh + 24);
            put32(b + cdfh + 24, real_un + 4096);      /* declare 4 KiB too many */
            membuf       m = { b, base_len };
            brix_zip_dir dir;
            int          rc = brix_zip_open(mem_pread, &m, base_len, &dir);
            CHECK(rc == XRDC_ZIP_OK, "case11 open rc=%d", rc);
            if (rc == XRDC_ZIP_OK) {
                const brix_zip_entry *e = brix_zip_find(&dir, "store.bin");
                CHECK(e != NULL, "case11 find store.bin");
                if (e != NULL) {
                    int xrc = brix_zip_member_extract(mem_pread, &m, e,
                                                      discard_sink, NULL);
                    CHECK(xrc == XRDC_ZIP_EBADF,
                          "case11 STORE size mismatch expected EBADF, got %d", xrc);
                    printf("  ok   (11) STORE size mismatch -> %d (EBADF)\n", xrc);
                }
                brix_zip_dir_free(&dir);
            }
            free(b);
        }
    }

    /* (12) A VALID empty (0-entry) archive must open cleanly with n==0 and no
     * spurious entries (the empty-archive malloc/parse fallback path). */
    {
        FILE *f = fopen("/tmp/ztf/empty.zip", "rb");
        if (f == NULL) {
            printf("  SKIP (12) empty.zip fixture missing\n");
        } else {
            long   sz; uint8_t *eb; size_t elen;
            fseek(f, 0, SEEK_END); sz = ftell(f); fseek(f, 0, SEEK_SET);
            elen = (size_t) sz;
            eb = malloc(elen ? elen : 1);
            CHECK(eb != NULL && fread(eb, 1, elen, f) == elen, "case12 read empty.zip");
            fclose(f);
            if (eb != NULL) {
                membuf       m = { eb, elen };
                brix_zip_dir dir;
                int          rc = brix_zip_open(mem_pread, &m, elen, &dir);
                CHECK(rc == XRDC_ZIP_OK, "case12 empty open rc=%d", rc);
                if (rc == XRDC_ZIP_OK) {
                    CHECK(dir.n == 0, "case12 empty archive n=%zu != 0", dir.n);
                    CHECK(brix_zip_find(&dir, "anything") == NULL,
                          "case12 find in empty must be NULL");
                    printf("  ok   (12) valid empty archive -> open OK, n=0\n");
                    brix_zip_dir_free(&dir);
                }
                free(eb);
            }
        }
    }

    free(base);
    printf("%s\n", g_fail ? "== FAILED ==" : "== ALL PASSED ==");
    return g_fail;
}

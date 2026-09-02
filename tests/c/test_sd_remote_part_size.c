/*
 * test_sd_remote_part_size.c — phase-107 C5: the multipart part-size derivation
 * that lifts sd_remote's silent 160 GB object ceiling.
 *
 * WHAT: sd_remote_part_size (sd_remote_write.o) maps a client-declared final
 *       object size to a LEGAL S3 multipart part size:
 *       max(16 MiB, ceil(declared / 10,000)), rounded UP to a MiB.
 * WHY:  10,000 parts x a fixed 16 MiB part capped every upload at 160 GB; the
 *       declaration (oss.asize / Content-Length / ALLO) is what lifts it. The
 *       doc's W4 gate is explicit: "Prove a declared 5 TB upload picks a legal
 *       part count."
 * HOW:  Pure-function unit over the real object. For every case the legality
 *       invariant is the same three-fold check: the part count fits the 10,000
 *       cap, the size is MiB-aligned, and it never dips below the 16 MiB floor
 *       (a lying small declaration must not fragment the upload — that is the
 *       security-negative arm).
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "fs/backend/remote/sd_remote_internal.h"

#define MiB           ((int64_t) 1 << 20)
#define DEFAULT_PART  (16 * MiB)
#define MAX_PARTS     10000

static int failures;

#define CHECK(cond, msg) do {                                                 \
    if (cond) { printf("  ok: %s\n", msg); }                                  \
    else      { printf("  FAIL: %s\n", msg); failures++; }                    \
} while (0)

/* The three-fold legality invariant for a declared size > 0. */
static void
check_legal(off_t declared, const char *label)
{
    int64_t part  = sd_remote_part_size(declared);
    int64_t parts = ((int64_t) declared + part - 1) / part;
    char    msg[128];

    snprintf(msg, sizeof(msg), "%s: part=%" PRId64 " parts=%" PRId64,
             label, part, parts);
    CHECK(part >= DEFAULT_PART && part % MiB == 0 && parts <= MAX_PARTS, msg);
}

int
main(void)
{
    /* No declaration keeps the historic default (and its ceiling): the part
     * size must not move unless the client declared. */
    CHECK(sd_remote_part_size(0) == DEFAULT_PART, "undeclared (0) -> 16 MiB");
    CHECK(sd_remote_part_size(-1) == DEFAULT_PART, "undeclared (-1) -> 16 MiB");

    /* Security-negative: a small or lying declaration cannot shrink the part
     * below the floor (no part-count explosion, no sub-5-MiB parts). */
    CHECK(sd_remote_part_size(1) == DEFAULT_PART, "1 byte -> floor holds");
    CHECK(sd_remote_part_size(5L * 1024 * 1024) == DEFAULT_PART,
          "5 MiB -> floor holds");

    /* At and below the old ceiling the default is already legal. */
    CHECK(sd_remote_part_size((off_t) MAX_PARTS * DEFAULT_PART) == DEFAULT_PART,
          "exactly 160 GB -> 16 MiB still legal");
    check_legal((off_t) MAX_PARTS * DEFAULT_PART, "160 GB boundary");

    /* One byte past the old ceiling must grow the part (and stay MiB-aligned):
     * this is the first size the fixed part could NOT satisfy. */
    {
        off_t   just_over = (off_t) MAX_PARTS * DEFAULT_PART + 1;
        int64_t part      = sd_remote_part_size(just_over);

        CHECK(part == DEFAULT_PART + MiB, "160 GB + 1 -> 17 MiB");
        check_legal(just_over, "160 GB + 1");
    }

    /* The doc's pytest row 1: a declared 200 GB object selects >= 20 MiB. */
    CHECK(sd_remote_part_size((off_t) 200 * 1000 * 1000 * 1000) >= 20 * MiB,
          "200 GB -> part >= 20 MiB");
    check_legal((off_t) 200 * 1000 * 1000 * 1000, "200 GB");

    /* THE W4 GATE: a declared 5 TB upload picks a legal part count. Both
     * readings of "5 TB" are proven, and both stay under S3's own 5 GiB
     * per-part limit with room to spare. */
    check_legal((off_t) 5 * 1000 * 1000 * 1000 * 1000, "5 TB (decimal)");
    check_legal((off_t) 5 * 1024 * 1024 * 1024 * 1024, "5 TiB (binary)");
    CHECK(sd_remote_part_size((off_t) 5 * 1024 * 1024 * 1024 * 1024)
          <= (int64_t) 5 * 1024 * MiB, "5 TiB part <= S3's 5 GiB cap");

    /* S3's absolute object bound: 5 TiB still derives a legal geometry, so
     * every size this driver can ever be asked to accept is covered. */

    if (failures) {
        printf("%d FAILURE(S)\n", failures);
        return 1;
    }
    printf("all part-size derivations legal\n");
    return 0;
}

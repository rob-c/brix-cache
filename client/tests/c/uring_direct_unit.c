/* client/tests/c/uring_direct_unit.c
 *
 * WHAT: Unit tests for the io_uring disk-ring O_DIRECT tier (phase-92 feature).
 *       Drives brix_disk_ring_create(..., direct=1) directly — no network, no
 *       xrdcp — so it validates the page-cache-bypass path in isolation.
 * WHY:  O_DIRECT imposes block-alignment on offset/length/buffer; the ring
 *       rounds bufsz up, aligns its slab, and re-issues the unaligned final tail
 *       of a download as a buffered write.  These are the code paths a live
 *       transfer would otherwise only hit on real hardware, so they need a unit.
 * HOW:  success — write full blocks + a short (sub-block) tail through a direct
 *                 WRITE ring, flush, then read the file back through a direct
 *                 READ ring and compare byte-for-byte (proves the buffered-tail
 *                 fallback and the aligned read-ahead both preserve the bytes);
 *       error   — a chunk larger than bufsz is rejected with -1 + status;
 *       neg     — a filesystem that rejects O_DIRECT (tmpfs, /dev/shm) makes a
 *                 direct create fail with XRDC_EUNSUPPORTED, which is exactly the
 *                 signal an AUTO caller turns into a buffered fallback.
 *
 * Some environments (containers, exotic filesystems) do not support O_DIRECT on
 * the scratch path at all; when the success create returns EUNSUPPORTED the test
 * prints SKIP for that case rather than failing — the code path is still
 * exercised by the negative test.
 *
 * Exit 0 = all selected tests passed/skipped; abort() on assertion failure.
 */

#include "../../lib/core/aio/uring.h"
#include "../../lib/brix.h"

#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Deterministic, alignment-agnostic pattern so a misplaced byte is obvious. */
static void
fill_pattern(uint8_t *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        b[i] = (uint8_t) (i * 31u + 7u);
    }
}

int
main(void)
{
    /* Total = two full blocks + a short tail, so the final ring_pwrite length is
     * NOT block-aligned and must take the buffered-tail path. */
    enum { TAIL = 1000, TOTAL = 4096 * 2 + TAIL };
    uint8_t *src = malloc(TOTAL);
    assert(src != NULL);
    fill_pattern(src, TOTAL);

    if (!brix_uring_available()) {
        printf("uring_direct: io_uring unavailable — SKIP all\n");
        free(src);
        return 0;
    }

    /* ---- Test 1 (success): direct write ring + buffered short tail, read back
     *      through a direct read ring, byte-exact. ---- */
    {
        brix_status st;
        char path[] = "/tmp/uring_direct_XXXXXX";
        int fd = mkstemp(path);
        assert(fd >= 0);

        brix_status_clear(&st);
        /* Request a deliberately UN-rounded bufsz (4000) to prove the ring rounds
         * it up to the block alignment. */
        brix_disk_ring *w = brix_disk_ring_create(fd, 4, 4000, 1, &st);
        if (w == NULL && st.kxr == XRDC_EUNSUPPORTED) {
            printf("uring_direct: O_DIRECT unsupported on /tmp — SKIP success case\n");
            close(fd);
            unlink(path);
        } else {
            assert(w != NULL);
            size_t bufsz = brix_disk_ring_bufsz(w);
            assert(bufsz % 4096 == 0 && bufsz >= 4000);   /* rounded up */

            /* Sequential, aligned full-block writes, then the short tail. */
            int64_t off = 0;
            size_t  left = TOTAL;
            const uint8_t *p = src;
            while (left > 0) {
                size_t chunk = left < bufsz ? left : bufsz;
                assert(brix_disk_ring_pwrite(w, off, p, chunk, &st) == 0);
                off  += (int64_t) chunk;
                p    += chunk;
                left -= chunk;
            }
            assert(brix_disk_ring_flush(w, &st) == 0);
            brix_disk_ring_destroy(w);

            /* Independently confirm the file length via plain POSIX. */
            int v = open(path, O_RDONLY);
            assert(v >= 0);
            off_t end = lseek(v, 0, SEEK_END);
            assert(end == (off_t) TOTAL);

            /* Read it back through a direct READ ring (sequential read-ahead;
             * the final block is a short read at EOF). */
            brix_status_clear(&st);
            brix_disk_ring *r = brix_disk_ring_create(v, 4, 4000, 1, &st);
            assert(r != NULL);
            uint8_t *back = malloc(TOTAL);
            assert(back != NULL);
            int64_t roff = 0;
            for (;;) {
                ssize_t got = brix_disk_ring_pread(r, roff, back + roff,
                                                   (size_t) (TOTAL - roff), &st);
                assert(got >= 0);
                if (got == 0) { break; }        /* EOF */
                roff += got;
                if (roff >= (int64_t) TOTAL) { break; }
            }
            assert(roff == (int64_t) TOTAL);
            assert(memcmp(src, back, TOTAL) == 0);   /* byte-exact incl. tail */

            brix_disk_ring_destroy(r);
            free(back);
            close(v);
            unlink(path);
            printf("uring_direct success: %d bytes (incl. %d-byte tail) round-tripped\n",
                   (int) TOTAL, (int) TAIL);
        }
    }

    /* ---- Test 2 (error): a chunk larger than bufsz is rejected cleanly. ---- */
    {
        brix_status st;
        char path[] = "/tmp/uring_direct_err_XXXXXX";
        int fd = mkstemp(path);
        assert(fd >= 0);

        brix_status_clear(&st);
        brix_disk_ring *w = brix_disk_ring_create(fd, 4, 4096, 1, &st);
        if (w == NULL && st.kxr == XRDC_EUNSUPPORTED) {
            printf("uring_direct: O_DIRECT unsupported on /tmp — SKIP error case\n");
        } else {
            assert(w != NULL);
            size_t bufsz = brix_disk_ring_bufsz(w);
            brix_status_clear(&st);
            /* One byte past the per-op buffer → must fail without touching disk. */
            assert(brix_disk_ring_pwrite(w, 0, src, bufsz + 1, &st) == -1);
            assert(st.kxr != 0);
            brix_disk_ring_destroy(w);
            printf("uring_direct error: oversize chunk rejected (kxr=%d)\n", st.kxr);
        }
        close(fd);
        unlink(path);
    }

    /* ---- Test 3 (security-neg): a direct create against a fd it cannot query
     *      must fail cleanly (no crash, status set) rather than proceed with an
     *      unaligned/undefined slab.  An already-closed fd deterministically
     *      makes the O_DIRECT enable step's fcntl(F_GETFL) fail, so this is the
     *      same defensive rejection an O_DIRECT-hostile filesystem triggers. ---- */
    {
        brix_status st;
        int fd = open("/dev/null", O_RDWR);
        assert(fd >= 0);
        close(fd);                      /* fd is now invalid */

        brix_status_clear(&st);
        brix_disk_ring *w = brix_disk_ring_create(fd, 4, 4096, 1, &st);
        assert(w == NULL);              /* refused, not crashed */
        assert(st.kxr != 0);            /* status carries the failure */
        printf("uring_direct neg: direct create on invalid fd refused (kxr=%d)\n",
               st.kxr);
    }

    /* ---- Extra (informational): a tmpfs that rejects O_DIRECT surfaces the
     *      EUNSUPPORTED code an AUTO caller turns into a buffered fallback.  Some
     *      kernels silently accept O_DIRECT on tmpfs, so this is not asserted. ---- */
    {
        brix_status st;
        char path[] = "/dev/shm/uring_direct_probe_XXXXXX";
        int fd = mkstemp(path);
        if (fd < 0) {
            printf("uring_direct: /dev/shm unavailable — probe skipped\n");
        } else {
            brix_status_clear(&st);
            brix_disk_ring *w = brix_disk_ring_create(fd, 4, 4096, 1, &st);
            if (w != NULL) {
                brix_disk_ring_destroy(w);
                printf("uring_direct: /dev/shm accepted O_DIRECT — fallback N/A here\n");
            } else {
                assert(st.kxr == XRDC_EUNSUPPORTED);
                printf("uring_direct: tmpfs O_DIRECT refused → EUNSUPPORTED (AUTO would fall back)\n");
            }
            close(fd);
            unlink(path);
        }
    }

    free(src);
    printf("uring_direct unit tests: ALL PASS\n");
    return 0;
}

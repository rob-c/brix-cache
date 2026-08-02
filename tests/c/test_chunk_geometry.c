/*
 * test_chunk_geometry.c — unit for brix_chunk_geometry (src/core/aio/buffers.c),
 * the shared ceil-divide + zero-remainder-remap that both the memory-backed
 * (brix_build_chunked_chain) and zero-copy (brix_build_sendfile_chain) read
 * builders use to split a large contiguous read into wire frames.
 *
 * This is the deterministic anchor for phase-33 P3-B1 (sendfile-span): the
 * change raises BRIX_READ_CHUNK_MAX 16 -> 32 MiB, which is purely the wire-frame
 * geometry — a read's bytes are unchanged, only the number of <=CHUNK_MAX spans
 * (and thus interleaved kXR response headers / sendfile syscalls) coarsens.  The
 * driver-backed fleet endpoints all serve reads through the 2 MiB windowed path,
 * so this geometry is not reachable e2e there; a linked unit over the REAL
 * compiled object is the honest way to pin it.  The function is linked from
 * buffers.o (not reimplemented) so the value baked into the shipped code is what
 * is asserted here.
 *
 * Pins (three-per-change: success / boundary-error / defence):
 *   1. success       — 40 MiB splits into exactly 2 frames (32 MiB + 8 MiB);
 *   2. boundary      — 32 MiB is ONE frame, 32 MiB + 1 spills to TWO (last=1):
 *                      brackets the ceil-divide off-by-one at the new cap and
 *                      proves the cap is exactly 32 MiB (P3-B1's whole point);
 *   3. remap/defence — an exact 2*CHUNK_MAX multiple keeps the last frame a full
 *                      CHUNK_MAX (never a zero-byte trailer), and the maximum
 *                      request (BRIX_READ_REQUEST_MAX) never exceeds the per-slot
 *                      header budget that sizes brix_resp_slot_t.hdr_bytes.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <stddef.h>
#include <stdio.h>

#include "core/types/tunables.h"

/* Pin the P3-B1 value at compile time — the runtime probes below prove the
 * boundary independently, this guards the intended constant explicitly. */
#if BRIX_READ_CHUNK_MAX != (32 * 1024 * 1024)
#error "P3-B1: BRIX_READ_CHUNK_MAX expected to be 32 MiB"
#endif

/* Under test — linked from objs/addon/aio/buffers.o (declared in
 * src/core/aio/buffers_internal.h; redeclared here to keep the TU self-contained
 * without pulling the whole aio include graph). */
void brix_chunk_geometry(size_t data_total, size_t *n_chunks_out,
    size_t *last_size_out);

/* buffers.o references these from its OTHER (uncalled here) builders; stub them
 * so the object links.  brix_chunk_geometry itself calls none of them, so a call
 * into any stub would be a test-harness bug — abort() makes that unmissable. */
void brix_build_resp_hdr(unsigned short a, unsigned short b, uint32_t c, void *d)
{ (void)a;(void)b;(void)c;(void)d; abort(); }
void *brix_get_pool_scratch(void *a, void *b, size_t c)
{ (void)a;(void)b;(void)c; abort(); }
ngx_chain_t *ngx_alloc_chain_link(ngx_pool_t *p) { (void)p; abort(); }
void *ngx_pcalloc(ngx_pool_t *p, size_t s) { (void)p;(void)s; abort(); }

static int failures;

static void
expect(const char *what, size_t data_total,
    size_t want_n, size_t want_last)
{
    size_t n = 0, last = 0;

    brix_chunk_geometry(data_total, &n, &last);
    if (n != want_n || last != want_last) {
        fprintf(stderr,
            "FAIL %s: data_total=%zu -> (n=%zu,last=%zu) want (n=%zu,last=%zu)\n",
            what, data_total, n, last, want_n, want_last);
        failures++;
    }
}

int
main(void)
{
    const size_t CHUNK = (size_t) BRIX_READ_CHUNK_MAX;   /* 32 MiB */
    const size_t MiB   = 1024 * 1024;

    /* 1. success: a 40 MiB read is two frames — 32 MiB + 8 MiB. */
    expect("40MiB two-frame split", 40 * MiB, 2, 8 * MiB);

    /* 2. boundary: exactly one chunk stays a single frame; one byte over spills
     *    to a second frame whose payload is that single trailing byte.  Together
     *    these prove the split boundary is exactly CHUNK (== 32 MiB). */
    expect("exactly one chunk", CHUNK, 1, CHUNK);
    expect("one byte over one chunk", CHUNK + 1, 2, 1);

    /* Also a sub-chunk read is a single frame carrying all its bytes. */
    expect("sub-chunk read", 3 * MiB, 1, 3 * MiB);

    /* 3a. remap defence: an exact 2*CHUNK multiple must NOT produce a zero-byte
     *     final frame — the remainder-0 case remaps the last frame to a full
     *     CHUNK so it carries the real trailing bytes. */
    expect("exact 2x multiple keeps full last frame", 2 * CHUNK, 2, CHUNK);

    /* 3b. header-budget invariant: the largest admissible read
     *     (BRIX_READ_REQUEST_MAX, the clamp in read_validate_req) must fit within
     *     the ceil(REQUEST_MAX/CHUNK) frame count that sizes the per-slot header
     *     buffer, so a multi-chunk response can never overrun slot->hdr_bytes. */
    {
        size_t n = 0, last = 0;
        size_t budget_chunks =
            (((size_t) BRIX_READ_REQUEST_MAX) + CHUNK - 1) / CHUNK;

        brix_chunk_geometry((size_t) BRIX_READ_REQUEST_MAX, &n, &last);
        if (n != budget_chunks || n != 2) {
            fprintf(stderr,
                "FAIL request-max frame count: got n=%zu want %zu (==2)\n",
                n, budget_chunks);
            failures++;
        }
    }

    if (failures == 0) {
        printf("chunk_geometry: all checks passed (CHUNK_MAX=%zu MiB)\n",
               CHUNK / MiB);
    }
    return failures ? 1 : 0;
}

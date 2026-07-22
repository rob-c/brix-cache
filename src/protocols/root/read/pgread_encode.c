/*
 * pgread_encode.c — kXR_pgread page-mode encode engine.
 *
 * The zero-copy paged read + in-place per-page CRC32c core shared by the warm
 * inline path, the AIO worker (via vfs_io_core), and the flat page encoder.
 * Split out of pgread.c for file-size; brix_pgread_read_encode_inplace() and
 * brix_pgread_encode_pages() are declared in read.h and called from the pgread
 * handler (pgread.c) and vfs_io_core.c.  The layout/CRC helpers are used only
 * by brix_pgread_read_encode_inplace and stay static here.
 */

#include "read.h"

#include "fs/backend/sd.h"   /* phase-55: route preadv through the SD seam */
#include "core/compat/pgio.h"     /* shared kXR page-mode encode (libxrdproto) */
#include "core/compat/crc32c.h"   /* brix_crc32c_value — in-place per-page CRC  */

#include <sys/uio.h>            /* preadv / struct iovec                        */

/* CRC32c word size per page unit ([CRC32c(4)][data]); == kXR_pgUnitSZ - page. */
#define BRIX_PG_CKSZ        ((size_t) (kXR_pgUnitSZ - kXR_pgPageSZ))
/* preadv scatter cap per syscall — mirrors kXR_readv (BRIX_READV_PREADV_MAXIOV). */
#define BRIX_PGREAD_MAXIOV  64

/*
 * brix_pgread_batch_t - one preadv scatter batch of gapped wire pages.
 *
 * WHAT: The per-batch page layout for the zero-copy paged read: the iovecs a
 *       single preadv/preadv2 call scatters into, plus each page's data
 *       pointer (just past its 4-byte CRC gap) and length, the page count,
 *       and the total file bytes the batch covers.
 *
 * WHY: Groups the parallel arrays the layout / read / CRC steps of
 *      brix_pgread_read_encode_inplace share, so each step can be a small
 *      single-purpose helper instead of one monolithic loop body.
 *
 * HOW: Filled by brix_pgread_layout_batch, read into by the driver's
 *      preadv/preadv2, checksummed by brix_pgread_crc_batch.
 */
typedef struct {
    struct iovec  iov[BRIX_PGREAD_MAXIOV];   /* scatter targets (page data)  */
    u_char       *data[BRIX_PGREAD_MAXIOV];  /* page data start (after CRC)  */
    size_t        dlen[BRIX_PGREAD_MAXIOV];  /* page data length             */
    int           k;                         /* pages in this batch          */
    size_t        bytes;                     /* total file bytes laid out    */
} brix_pgread_batch_t;

/*
 * brix_pgread_layout_batch - lay out one batch of gapped wire pages.
 *
 * WHAT: Fills `b` with up to BRIX_PGREAD_MAXIOV pages covering the next
 *       `remaining` file bytes of an rlen-byte read starting at `offset`,
 *       placing each page's data just after its 4-byte CRC gap in the wire
 *       buffer at cursor `o`.  Returns the advanced wire-buffer cursor.
 *
 * WHY: Pure gap-layout math, separated from the read syscall and the CRC
 *      pass so each stays independently reviewable (phase-72 decomposition).
 *
 * HOW: Page lengths use the in-page offset so the first fragment shortens on
 *      an unaligned read, exactly as xrdp_pg_encode does; the caller derives
 *      the batch's file offset from (rlen - remaining) the same way.
 */
static u_char *
brix_pgread_layout_batch(off_t offset, size_t rlen, size_t remaining,
    u_char *o, brix_pgread_batch_t *b)
{
    b->k = 0;
    b->bytes = 0;

    while (b->k < BRIX_PGREAD_MAXIOV && remaining > 0) {
        off_t  cur = offset + (off_t) (rlen - remaining);
        size_t in_off = (size_t) (cur & (off_t) (kXR_pgPageSZ - 1));
        size_t len = (size_t) kXR_pgPageSZ - in_off;

        if (len > remaining) {
            len = remaining;
        }
        b->data[b->k] = o + BRIX_PG_CKSZ;
        b->dlen[b->k] = len;
        b->iov[b->k].iov_base = b->data[b->k];
        b->iov[b->k].iov_len  = len;
        o           += BRIX_PG_CKSZ + len;
        b->bytes    += len;
        remaining   -= len;
        b->k++;
    }

    return o;
}

/*
 * brix_pgread_crc_batch - checksum the bytes one batch actually delivered.
 *
 * WHAT: Fuses the per-page CRC32c over exactly `got` bytes of batch `b`,
 *       writing each 4-byte big-endian checksum into the gap preceding its
 *       page data and adding the encoded bytes to *out_size.  Returns 1 when
 *       a short page ends the file (EOF), 0 otherwise.
 *
 * WHY: The CRC pass over delivered bytes is pure computation over the batch
 *      layout; splitting it from the read loop keeps the encode function
 *      under the complexity gate without touching the wire bytes.
 *
 * HOW: Walks the batch pages until the delivered bytes run out; a page that
 *      comes up short means EOF, so stop — no more data follows.
 */
static int
brix_pgread_crc_batch(brix_pgread_batch_t *b, size_t got, size_t *out_size)
{
    int i;

    for (i = 0; i < b->k; i++) {
        size_t   al = (got < b->dlen[i]) ? got : b->dlen[i];
        uint32_t crc_be;

        if (al == 0) {
            break;
        }
        crc_be = htonl(brix_crc32c_value(b->data[i], al));
        memcpy(b->data[i] - BRIX_PG_CKSZ, &crc_be, BRIX_PG_CKSZ);
        *out_size += BRIX_PG_CKSZ + al;
        got       -= al;
        if (al < b->dlen[i]) {
            return 1;   /* short page => short read; no more data follows */
        }
    }

    return 0;
}

/*
 * brix_pgread_read_encode_inplace - zero-copy paged read + in-place CRC.
 *
 * WHAT: Reads up to `rlen` bytes from `fd` at `offset` DIRECTLY into the final
 *       kXR page-mode wire buffer `out` (laid out as [CRC32c(4)][data] per page,
 *       file-offset aligned) and computes each page's CRC32c in place, writing
 *       the 4-byte big-endian checksum into the gap that precedes its data.
 *       Returns the encoded byte count; sets io->nread to bytes read (-1 on I/O
 *       error, with io->io_errno = errno). io->nowait selects the read mode.
 *
 * WHY: The previous path pread() the data into a flat buffer and then ran
 *      xrdp_pg_encode to COPY it into the interleaved wire buffer while
 *      checksumming. Flame-graph profiling showed that copy (a full extra pass
 *      over every byte — the dst-write memory stream) dominating read CPU, and a
 *      copy is memory-bandwidth-bound so the 3-way CRC barely helps it. Reading
 *      straight into the gapped wire buffer removes the copy entirely; the CRC
 *      then runs read-only (brix_crc32c_value, the latency-hiding 3-way path)
 *      over the data already in place. This mirrors the zero-copy preadv-into-
 *      final-buffer pattern kXR_readv already uses. Output is byte-identical to
 *      xrdp_pg_encode (Invariant #1): same page splitting, same CRC, same layout.
 *
 * HOW: Lay out one batch of <= BRIX_PGREAD_MAXIOV pages (data after each 4-byte
 *      CRC gap), preadv the batch's contiguous file region into those gapped
 *      positions, then fuse the per-page CRC over exactly the bytes the batch
 *      delivered — a short page or short batch means EOF, so stop. Page lengths
 *      use the in-page offset so the first fragment shortens on an unaligned
 *      read, exactly as xrdp_pg_encode does.
 */
size_t
brix_pgread_read_encode_inplace(brix_sd_obj_t *obj, off_t offset,
    size_t rlen, u_char *out, brix_pgread_io_t *io)
{
    u_char  *o = out;            /* write cursor in the gapped wire buffer */
    size_t   remaining = rlen;   /* file bytes not yet laid out into a batch */
    size_t          out_size = 0;       /* encoded bytes produced so far */
    ssize_t         total = 0;          /* file bytes actually read */
    int             eof = 0;

    io->nread = 0;
    io->io_errno = 0;

    /* The batched vectored read goes through the handle's storage driver (POSIX
     * or block-striped); the page layout / in-place CRC policy stays here. */

    while (remaining > 0 && !eof) {
        brix_pgread_batch_t batch;
        off_t   batch_off = offset + (off_t) (rlen - remaining);
        ssize_t n;

        /* Lay out a batch of pages: data lands after each 4-byte CRC gap. */
        o = brix_pgread_layout_batch(offset, rlen, remaining, o, &batch);
        remaining -= batch.bytes;

#if defined(RWF_NOWAIT)
        if (io->nowait) {
            /* Warm-cache probe: read only what is already resident. Any short
             * batch or EAGAIN means "not fully in page cache" — abort the whole
             * inline attempt so the caller offloads a blocking read (which also
             * re-detects true EOF correctly). A real error likewise aborts; the
             * blocking re-read surfaces it. Earlier full batches' work is
             * discarded by that re-read. */
            n = obj->driver->preadv2(obj, batch.iov, batch.k, batch_off,
                                               RWF_NOWAIT);
            if (n < 0 || (size_t) n < batch.bytes) {
                io->nread = 0;
                io->io_errno = (n < 0) ? errno : EAGAIN;
                return 0;
            }
        } else
#endif
        {
            /* Compat seam: drivers without a native preadv slot (remote/object
             * backends) fall back to per-iovec pread inside the helper. */
            n = brix_sd_obj_preadv(obj, batch.iov, batch.k, batch_off);
            if (n < 0) {
                io->nread = -1;
                io->io_errno = errno;
                return 0;
            }
        }
        total += n;

        /* Fuse the per-page CRC over exactly the bytes this batch delivered. */
        if (brix_pgread_crc_batch(&batch, (size_t) n, &out_size)) {
            eof = 1;
        }

        if ((size_t) n < batch.bytes) {
            eof = 1;       /* short batch overall => EOF */
        }
    }

    io->nread = total;
    return out_size;
}

/*
 * Encode raw file data into kXR page-mode [CRC32c(4)][data] units, file-offset
 * aligned (short first fragment on an unaligned read). Thin wrapper over the
 * shared page-mode encoder (libxrdproto) so the module and the native client
 * frame pages byte-identically.
 */
size_t
brix_pgread_encode_pages(const u_char *src, size_t len, off_t offset,
                           u_char *dst)
{
    return xrdp_pg_encode((const uint8_t *) src, len, (int64_t) offset,
                          (uint8_t *) dst);
}

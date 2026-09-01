/*
 * io_monitor.h — the per-request I/O monitor accumulator (phase 106 W1, the
 * data-plane variable tail: $brix_bytes_served / $brix_backend_time /
 * $brix_checksum).
 *
 * WHAT: A tiny protocol-neutral record that accumulates, across every brix VFS
 *       operation of ONE request, the bytes moved, the time spent doing that
 *       I/O, and the page-CRC when one was computed. It is the retention layer
 *       the three data-plane log variables read at log time.
 *
 * WHY:  The values already exist at the VFS seam (io_result.length / crc32c and
 *       the observer's op latency), but nothing kept them per-request, so the
 *       three variables could not be implemented as pure handlers (Appendix G
 *       "the three that need data-plane work"). This record is that work, kept
 *       deliberately small: three counters and a flag, no protocol or HTTP
 *       knowledge, so the VFS layer can fold into it through a bare pointer
 *       without depending on the HTTP planes that own its lifetime.
 *
 * HOW:  The owning HTTP plane allocates one on the request pool ON THE EVENT
 *       LOOP (never a worker thread — nginx pools are not thread-safe) and
 *       points the request's brix_vfs_ctx_t->io_monitor at it. The VFS post-op
 *       observer (vfs_internal.h) calls brix_io_monitor_add() for each
 *       observed op. That fold runs on the offload thread for GET/PUT, but it
 *       only writes scalar fields into the already-allocated struct, and the
 *       task done-handler orders those writes before the event-loop log phase
 *       reads them — so there is no race and no thread allocation.
 *
 * THREADING: single-writer. Exactly one op runs at a time for a request, and
 *       the log-phase read happens-after the last op via the done-handler. Do
 *       not add a reader on any other thread.
 */
#ifndef BRIX_OBSERVABILITY_METRICS_IO_MONITOR_H
#define BRIX_OBSERVABILITY_METRICS_IO_MONITOR_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <stdint.h>

/* The tag is what brix_vfs_ctx_t forward-declares; keep it stable. */
typedef struct brix_io_monitor_s {
    uint64_t   bytes;         /* total bytes moved by this request's brix I/O  */
    ngx_msec_t backend_usec;  /* summed VFS op latency, microseconds           */
    uint32_t   crc32c;        /* last computed page-CRC (valid iff have_crc)    */
    unsigned   have_crc:1;    /* a crc32c was actually computed this request    */
    unsigned   any:1;         /* at least one brix I/O op was observed          */
} brix_io_monitor_t;

/*
 * brix_io_monitor_add — fold one observed op into the request's monitor.
 *
 * Scalars only, by design: the VFS observer passes plain counts so this header
 * needs no VFS type and can be included from either side of the seam. NULL
 * monitor (an unmonitored request — e.g. a metadata-only path that never bound
 * one) is the common case and is a silent no-op. `have_crc` is the caller's
 * decision (it is true only when page-CRC was active, so a real crc of 0 is
 * not confused with "no crc"); `crc` is ignored unless have_crc is set.
 */
static ngx_inline void
brix_io_monitor_add(brix_io_monitor_t *m, size_t bytes,
    ngx_msec_t latency_usec, unsigned have_crc, uint32_t crc)
{
    if (m == NULL) {
        return;
    }
    m->any = 1;
    m->bytes += (uint64_t) bytes;
    m->backend_usec += latency_usec;
    if (have_crc) {
        m->crc32c = crc;
        m->have_crc = 1;
    }
}

#endif /* BRIX_OBSERVABILITY_METRICS_IO_MONITOR_H */

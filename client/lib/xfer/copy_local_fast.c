/*
 * copy_local_fast.c - the pipelined half of a local download.
 *
 * WHAT: The brix_rfile -> pump_sink_fn adapter, the eligibility test that picks
 *       the pipelined reader over the serial pump, and the streaming call that
 *       uses it.
 * WHY:  Split out of copy_local.c, which had grown past the size limit.  The
 *       rest of that file is the download session - temp paths, the atomic
 *       rename, the resilient open, the stdout and VFS destinations - and it
 *       enters this one only through download_fast_eligible /
 *       download_stream_fast.  Behaviour-identical to the code it came from.
 * HOW:  Everything the two halves share is already in copy_internal.h.
 */
#include "copy_internal.h"

#include <errno.h>


/* ---- Adapter state for the pipelined download sink ----
 *
 * WHAT: What download_fast_sink needs to turn a brix_rfile chunk callback into
 *       the caller's pump_sink_fn call plus the per-chunk progress tick, the
 *       cancel check and the --xrate-threshold floor.
 * WHY:  The pipelined reader speaks the brix_rfile sink contract while every
 *       download destination (stdout fd, VFS temp file) speaks pump_sink_fn;
 *       one small adapter bridges them without either side learning about the
 *       other, and keeps the bookkeeping transfer_pump does per chunk intact.
 * HOW:  Filled by download_stream_fast, read (and `moved` advanced) by
 *       download_fast_sink.
 */
typedef struct {
    pump_sink_fn          sink;
    void                 *sinkctx;
    const brix_copy_opts *o;
    int64_t               total;    /* progress denominator (source size) */
    int64_t               moved;    /* bytes drained so far */
    uint64_t              t0_ns;    /* pacing epoch */
} dl_fast_sink_t;


/* ---- Drain one pipelined chunk into the download's destination ----
 *
 * WHAT: Writes `len` bytes at absolute offset `off` through the adapter's
 *       pump_sink_fn, ticks progress and applies the rate floor. Returns 0 to
 *       continue or -1 (st set) to abort the transfer.
 *
 * WHY:  transfer_pump does cancel + progress + pacing around every chunk it
 *       drains; the pipelined path must keep doing all three or --xrate-threshold
 *       and SIGINT would silently stop working on fast copies.
 *
 * HOW:  1. An operator cancel aborts with EINTR, exactly as the serial pump does.
 *       2. Hand the bytes to the destination sink.
 *       3. Advance `moved`, emit progress, then apply brix_pump_pace's floor.
 */
static int
download_fast_sink(const uint8_t *data, size_t len, int64_t off, void *arg,
                   brix_status *st)
{
    dl_fast_sink_t *a = (dl_fast_sink_t *) arg;

    if (brix_copy_quit_requested()) {
        brix_status_set(st, XRDC_ESOCK, EINTR, "transfer cancelled (signal)");
        return -1;
    }
    if (a->sink(a->sinkctx, data, off, len, st) != 0) {
        return -1;
    }
    a->moved = off + (int64_t) len;
    pump_emit_progress(a->o, a->moved, a->total);
    if (brix_pump_pace(a->o, a->t0_ns, a->moved, st) != 0) {
        return -1;
    }
    return 0;
}


/* ---- May this download use the pipelined reader? ----
 *
 * WHAT: Returns 1 when the transfer is a plain sized SINGLE-STREAM read that
 *       the pipelined path can carry, 0 when it must use the serial pump.
 *
 * WHY:  Paged I/O (--pgrw) and inline read compression (--compress) have their
 *       own reply framing, and --xrate wants the small, evenly-spaced reads
 *       brix_pump_pace_cap produces — a 4 MiB pipelined chunk would make a capped
 *       transfer lurch.
 *
 *       -S/--streams is the fourth, and the one that is easy to miss: this path
 *       runs BEFORE download_stream_body binds its secondaries and pipelines on
 *       the primary connection alone, so letting it take a fan-out download does
 *       not slow the transfer down — it silently deletes the feature. `-S 4` is
 *       the DEFAULT (xrdcp.c `opts.streams = 4`), so without this clause no
 *       ordinary download has bound a secondary since the pipelined reader
 *       landed, against a documented contract ("the pumps fan full request
 *       frames across the bound connections", native-client-tools.md) and with
 *       nothing to see: the bytes are right and `-S` still parses.
 *
 *       Each of the two is worth having on its own — several reads in flight on
 *       one socket, or one read at a time across four — and the caller chooses
 *       by asking for streams or not asking. (`--parallel` is the third shape:
 *       true concurrent striping, which owns its own path.)
 *
 * HOW:  Require a known size, no pgrw, no compress opaque, no rate cap, and no
 *       bound secondaries requested.
 */
int
download_fast_eligible(const download_body_ctx *j)
{
    const brix_copy_opts *o = j->o;

    return j->si->size >= 0 && !o->pgrw && o->xrate_bps <= 0 && o->streams <= 1
           && (o->compress == NULL || o->compress[0] == '\0');
}


/* ---- Stream the body with several reads in flight ----
 *
 * WHAT: The pipelined half of download_stream_body: opens the source as a
 *       resilient handle, streams si->size bytes through the caller's sink with
 *       brix_rfile_stream, and closes it. 0 / -1 (st set).
 *
 * WHY:  The serial pump idles a full round trip per chunk, which on a fast link
 *       is most of the transfer time. brix_rfile_stream keeps several kXR_reads
 *       outstanding and falls back to the serial pump for anything it cannot
 *       finish, so this is a speed change only — reopen-on-sever, resume at
 *       offset and the adaptive request shrink are all still in force.
 *
 * HOW:  1. Open resiliently (brix_rfile_open_read owns the open retry loop).
 *       2. Wire the cancel predicate so a SIGINT stops the stream.
 *       3. Stream into the adapter; a short stream is the same short-read error
 *          transfer_pump would have reported.
 *       4. Close the handle, preserving a failure status over the close's.
 */
int
download_stream_fast(const download_body_ctx *j, pump_sink_fn sink,
                     void *sinkctx, brix_status *st)
{
    brix_rfile      rf;
    dl_fast_sink_t  adapter;
    int64_t         moved = 0;
    int             rc;

    if (brix_rfile_open_read(j->c, j->su->path, NULL, 0,
                             copy_stall_ms(j->o, 60000), &rf, st) != 0) {
        return -1;
    }
    rf.cancel = brix_copy_quit_requested;

    adapter.sink    = sink;
    adapter.sinkctx = sinkctx;
    adapter.o       = j->o;
    adapter.total   = j->si->size;
    adapter.moved   = 0;
    adapter.t0_ns   = brix_mono_ns();

    rc = brix_rfile_stream(&rf, 0, j->si->size, 0, download_fast_sink,
                           &adapter, &moved, st);
    if (rc == 0 && moved < j->si->size) {
        brix_status_set(st, XRDC_EPROTO, 0,
                        "short read: got %lld of %lld bytes",
                        (long long) moved, (long long) j->si->size);
        rc = -1;
    }
    {
        brix_status throwaway;
        brix_status_clear(&throwaway);
        brix_rfile_close(&rf, rc == 0 ? st : &throwaway);
    }
    return rc;
}

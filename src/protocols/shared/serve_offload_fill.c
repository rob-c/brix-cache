/*
 * serve_offload_fill.c — fetch the window an off-loop serve will send, not the
 * object it lives in.
 *
 * WHAT: given an open remote object and the request's raw Range header, copy
 * into a scratch fd exactly the bytes the response will carry.
 *
 * WHY: the off-loop serve (http_serve_offload.c) materialises a remote object
 * into a scratch temp file and then serves the response out of that file.  It
 * materialised the WHOLE object, always — so a 256-byte Range on a 384 kB
 * object fetched all 384 kB across the network, and the same request against a
 * 10 GB object would have fetched 10 GB.  Nothing looked wrong from outside:
 * the right bytes came back with the right Content-Range.
 *
 * That cost was invisible for as long as the offload was reached only by
 * `xroot`.  Phase-115 §P6 made every blocking-wire driver declare itself, which
 * correctly routed `gsiftp` here too — and gsiftp is the driver whose bounded
 * retrieve (GridFTP `ERET P <off> <len>`) is VISIBLE in the origin's command
 * log.  The origin was then asked for `ERET P 0 384000` to serve a 256-byte
 * window, which is the same defect phase-115 §P4 had already fixed one layer up
 * in brix_vfs_file_sendfile_fd_window(): that layer narrowed the read and this
 * one widened it straight back, silently cancelling every bounded-retrieve
 * extension the drivers negotiate.
 *
 * HOW: the window is derived with the SAME parser the serve itself will use
 * (brix_http_parse_range, via brix_http_serve_file_ranged) against the SAME
 * size, so the window fetched and the window sent cannot disagree — they are
 * one computation run twice.  It is then written into the scratch fd at its
 * TRUE offset over a hole of the full object size, so nothing downstream has to
 * know a narrowing happened: the serve re-derives the window and reads exactly
 * these bytes.  The hole costs no disk and is never read for this request.
 *
 * A header that is absent, unparseable, unsatisfiable, or too large for the
 * caller's buffer yields the whole object.  This may only ever narrow what is
 * FETCHED, never narrow what can be SENT.
 */

#include "serve_offload_fill.h"
#include "core/compat/range.h"
#include "fs/core/vfs_core.h"
#include "fs/backend/sd_registry.h"    /* brix_sd_posix_wrap */

#include <errno.h>
#include <stdlib.h>

/* The chunk the copy reads through; one allocation per materialisation. */
#define BRIX_SERVE_OFFLOAD_FILL_CHUNK  (1024 * 1024)

/* The window [off, off+len) of a `size`-byte object that a response carrying
 * this Range header will send. */
static void
serve_fill_window(const u_char *hdr, size_t hdr_len, off_t size,
    xvfs_window_t *win)
{
    brix_http_range_t  rng;

    win->off = 0;
    win->len = size;
    win->end = 0;

    if (hdr == NULL || hdr_len == 0) {
        return;
    }
    brix_http_parse_range(hdr, hdr_len, size, &rng);
    if (!rng.present || !rng.satisfiable) {
        /* Unsatisfiable is deliberately NOT narrowed to nothing: the serve
         * answers 416 without reading the scratch, but a parser that ever
         * disagreed about satisfiability would then be serving a hole. */
        return;
    }
    win->off = rng.start;
    win->len = rng.end - rng.start + 1;
}

/* The object's size and mtime as the response must report them. */
static void
serve_fill_snap(brix_sd_obj_t *obj, brix_sd_stat_t *snap)
{
    *snap = obj->snap;
    if (obj->driver->fstat != NULL) {
        (void) obj->driver->fstat(obj, snap);
    }
}

/* Size the scratch to the whole object, so a narrowed window lands at its true
 * offset.  Skipped for a whole-object copy, which fills every byte itself and
 * must keep reporting the size it actually managed to read. */
static int
serve_fill_hole(brix_sd_obj_t *dst, const xvfs_window_t *win, off_t size)
{
    if (win->len >= size) {
        return 0;
    }
    return (xvfs_ftruncate(dst, size) == 0) ? 0 : (errno ? errno : EIO);
}

int
brix_serve_offload_fill(brix_sd_obj_t *obj, int tmp_fd,
    const u_char *range_hdr, size_t range_len,
    brix_serve_offload_fill_t *out)
{
    brix_sd_obj_t   dst;            /* worker-owned scratch, driver-routed */
    brix_sd_stat_t  snap;
    xvfs_window_t   win;
    u_char         *buf;
    int             err;

    serve_fill_snap(obj, &snap);
    out->mtime = snap.mtime;
    out->size  = snap.size;

    buf = malloc(BRIX_SERVE_OFFLOAD_FILL_CHUNK);
    if (buf == NULL) {
        return ENOMEM;
    }
    brix_sd_posix_wrap(&dst, tmp_fd);
    serve_fill_window(range_hdr, range_len, snap.size, &win);

    err = serve_fill_hole(&dst, &win, snap.size);
    if (err == 0
        && xvfs_drain_window(obj, &dst, buf, BRIX_SERVE_OFFLOAD_FILL_CHUNK,
                             &win) != 0)
    {
        err = errno ? errno : EIO;
    }
    free(buf);

    /* A whole-object copy reports what it READ, not what the origin claimed:
     * an origin whose size is a lie must not make the response promise bytes
     * that are not in the scratch.  A narrowed copy reports the object size,
     * because that is what its Content-Range denominator has to be — and its
     * window is all-or-nothing, so there is nothing to disagree about. */
    if (err == 0 && win.len >= snap.size) {
        out->size = win.end;
    }
    return err;
}

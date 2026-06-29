/*
 * xfer_mover_pump.c — the in-process byte mover for the transfer engine.
 *
 * WHAT: xrootd_xfer_pump_objects() — a positional read-through/write-through copy
 *       between two SD objects. This is the canonical VFS<->VFS (backend<->backend)
 *       move that the synchronous STAGE path and any same-process SD-to-SD commit
 *       use.
 *
 * WHY:  The loop lived as a private `stage_move_objects` static inside
 *       compat/staged_file.c, reachable only by the staged-commit path. The
 *       transfer engine needs the same mover as a first-class, reusable strategy
 *       (XROOTD_XFER_MOVE_PUMP), so it is lifted here verbatim — behaviour
 *       identical — and staged_file.c now calls it. One mover, one place.
 *
 * HOW:  Read CHUNK bytes from the source driver, write them through the
 *       destination driver at the same offset, until EOF. EINTR is retried on
 *       both sides. No raw pread/pwrite here — the driver slots do the I/O inside
 *       the SD backend, preserving the zero-data-POSIX-outside-the-backend
 *       invariant. Early-return, no goto.
 */

#include "xfer.h"

#include <errno.h>
#include <stdlib.h>

ngx_int_t
xrootd_xfer_pump_objects(xrootd_sd_obj_t *src, xrootd_sd_obj_t *dst)
{
    static const size_t CHUNK = 256 * 1024;
    char               *buf;
    off_t               off = 0;

    if (src == NULL || dst == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    buf = malloc(CHUNK);
    if (buf == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }

    for ( ;; ) {
        ssize_t n = src->driver->pread(src, buf, CHUNK, off);
        ssize_t w_done = 0;

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            free(buf);
            return NGX_ERROR;
        }
        if (n == 0) {
            break;
        }

        while (w_done < n) {
            ssize_t w = dst->driver->pwrite(dst, buf + w_done,
                                            (size_t) (n - w_done), off + w_done);
            if (w < 0) {
                if (errno == EINTR) {
                    continue;
                }
                free(buf);
                return NGX_ERROR;
            }
            w_done += w;
        }
        off += n;
    }

    free(buf);
    return NGX_OK;
}

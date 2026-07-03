#include "query_internal.h"
#include "protocols/root/response/response.h"
#include "core/aio/aio.h"
#include "core/compat/checksum.h"
#include "fs/path/beneath.h"

#include <dirent.h>
#include <sys/stat.h>

/*
 * WHAT: Async kXR_Qckscan — walk a file or directory tree off the event loop, compute checksums
 *       (adler32/crc32c/md5/sha1/sha256) for every regular file encountered, and return one line
 *       per file. Runs in an nginx thread pool worker; results delivered via aio_done callback.
 *
 * WHY:  ckscan walks potentially large directory trees (deep hierarchies with thousands of files).
 *       Doing this on the event loop blocks all other connections. The async path uses ngx_thread_pool_run
 *       to execute the walk in a background worker thread, keeping nginx responsive while scanning completes.
 *       Results are formatted as one checksum line per file matching xrdadler32 output format for client compatibility.
 *
 * HOW:  brix_ckscan_aio_thread() allocates response buffer (grows via append), stat's the scan target — if regular
 *       file, opens confined/canonical fd and computes single checksum; if directory, walks tree with depth/file limits
 *       calling ckscan_append per file. On error sets t->error_code + t->error_msg. Thread completion triggers
 *       brix_ckscan_aio_done() which restores the request streamid via aio_restore_request, sends error response or
 *       ok+checksum data to client, frees buffer, and resumes the client connection event loop.
 */


/* public API: brix_ckscan_aio_thread() — async ckscan thread worker * WHAT: Thread pool worker that computes checksums for a file or directory tree. Stat's the scan target, opens confined fd
 *       for regular files and computes single checksum via brix_checksum_u32_fd; walks directories recursively with depth/file
 *       limits calling ckscan_append per file. Allocates response buffer with dynamic growth. Sets t->error_code on failure. */

void
brix_ckscan_aio_thread(void *data, ngx_log_t *log)
{
    brix_ckscan_aio_t *t    = data;
    /*
     * Growing-buffer triple, passed by reference into brix_ckscan_run:
     *   buf  = heap block (ngx_alloc, NOT pool — this runs on a thread-pool worker
     *          with no access to the request pool); ownership is transferred to
     *          t->resp on success so the done callback frees it, otherwise every
     *          error path below must ngx_free(buf) before returning.
     *   cap  = current allocation size; the run reallocs and updates it in place.
     *   used = bytes written so far (excludes the trailing NUL added at the end).
     */
    size_t               cap  = BRIX_CKSCAN_INIT_CAP;
    size_t               used = 0;
    u_char              *buf;
    uint16_t             err_code = 0;

    buf = ngx_alloc(cap, log);
    if (buf == NULL) {
        t->error_code = kXR_NoMemory;
        snprintf(t->error_msg, sizeof(t->error_msg), "out of memory");
        return;
    }

    /* All stat/open/checksum/walk runs through the confined VFS walk (thread-safe:
     * no pool allocation, no metric), so the worker never touches a confined
     * helper or the request pool directly. */
    if (brix_ckscan_run(log, t->rootfd, t->scan_logical, t->algo,
                          &buf, &cap, &used, t->max_depth, t->max_files,
                          &err_code, t->error_msg, sizeof(t->error_msg))
        != NGX_OK)
    {
        ngx_free(buf);
        t->error_code = err_code;
        return;
    }

    /*
     * NUL-terminate in the slot at [used]: both ngx_alloc(INIT_CAP) above and every
     * ckscan_append/walk grow keep cap strictly greater than used, so [used] is always
     * a valid in-bounds byte and never overwrites response data. resp_len stays = used
     * (the NUL is excluded); the +1 sent to the client in _done covers the terminator.
     * Success handoff: buf ownership now belongs to t->resp — do NOT ngx_free here.
     */
    buf[used] = '\0';
    t->resp     = buf;
    t->resp_len = used;
    t->error_code = 0;
}

/* public API: brix_ckscan_aio_done() — async ckscan completion callback * WHAT: Event handler invoked when the thread pool worker completes. Restores the request streamid via aio_restore_request,
 *       sends error response (t->error_code + t->error_msg) or ok+checksum data to client, frees the response buffer, and
 *       resumes the client connection event loop via brix_aio_resume(). */

void
brix_ckscan_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t   *task = ev->data;
    brix_ckscan_aio_t *t    = task->ctx;
    brix_ctx_t        *ctx  = t->ctx;
    ngx_connection_t    *c    = t->c;

    /*
     * Cross-thread race guard. The worker ran detached from the event loop, so the
     * client connection may have closed (or the session been re-keyed) meanwhile.
     * aio_restore_request re-binds this op to its original streamid; if it fails the
     * connection/session is gone — we must NOT touch c or send anything, but we still
     * own t->resp (transferred from the worker) and must free it here to avoid a leak.
     */
    if (!brix_aio_restore_request(ctx, t->streamid)) {
        if (t->resp) {
            ngx_free(t->resp);
        }
        return;
    }

    if (t->error_code != 0) {
        BRIX_OP_ERR(ctx, BRIX_OP_QUERY_CKSCAN);
        brix_send_error(ctx, c, (uint16_t) t->error_code, t->error_msg);
    } else {
        BRIX_OP_OK(ctx, BRIX_OP_QUERY_CKSCAN);
        brix_log_access(ctx, c, "QUERY", t->scan_logical, "ckscan",
                          1, 0, NULL, 0);
        /* resp_len + 1: include the worker's trailing NUL in the kXR_ok payload,
         * matching xrdadler32 client expectations for a C-string body. */
        brix_send_ok(ctx, c, t->resp, (uint32_t) (t->resp_len + 1));
    }

    if (t->resp) {
        ngx_free(t->resp);
    }

    brix_aio_resume(c);
}


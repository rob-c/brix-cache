/*
 * Async kXR_dirlist via nginx thread pool.
 *
 * WHAT: Offloads the entire directory iteration + stat + checksum work to a
 *       thread-pool worker, freeing the nginx event loop to serve other
 *       connections while a large or slow-media directory is being scanned.
 *
 * WHY: directory iteration + fstatat(2) + fgetxattr(2)/hash-on-miss can block for tens
 *      to hundreds of milliseconds on spinning disk or network-backed storage.
 *      Running these on the event loop stalls all connections sharing that
 *      worker process.  Posting to the nginx thread pool lets I/O block on a
 *      dedicated OS thread instead.
 *
 * HOW:
 *   Main thread (brix_handle_dirlist, handler.c):
 *     1. Auth, path resolution and algorithm validation run synchronously.
 *     2. A response buffer is allocated from c->pool (large block → ngx_pfree
 *        can release it after drain).
 *     3. Fields are copied into brix_dirlist_aio_t; the task is posted.
 *     4. Returns NGX_OK immediately; ctx->state = XRD_ST_AIO.
 *
 *   Worker thread (brix_dirlist_aio_thread):
 *     - Opens the directory independently (no nginx state touched).
 *     - Iterates entries: skip "." / ".." / unsafe names.
 *     - Calls fstatat, brix_dirlist_checksum_token (xattr fast path or
 *       full hash), and builds the complete XRootD wire response directly into
 *       t->response.  Wire format: one or more kXR_oksofar frames followed by
 *       a single kXR_ok frame.
 *     - No pool allocation in this function — only POSIX syscalls and pure
 *       computation.
 *
 *   Done callback (brix_dirlist_aio_done, main thread):
 *     - Checks ctx->destroyed; on error sends kXR_IOError.
 *     - On success: wraps t->response in a memory ngx_buf_t + ngx_chain_t and
 *       calls brix_queue_response_chain(ctx, c, chain, t->response) so the
 *       buffer is freed via brix_release_read_buffer (ngx_pfree) once the
 *       chain has been fully drained.
 *     - Calls brix_aio_resume to re-arm the read event.
 *
 * Fallback: if the thread pool is not configured (conf->common.thread_pool == NULL)
 * or the queue is full, brix_handle_dirlist falls back to the synchronous
 * loop already present in handler.c — behaviour is identical to pre-AIO.
 *
 * Truncation: if the directory listing would exceed BRIX_DIRLIST_AIO_RESPONSE_MAX
 * (4 MiB), the thread sets io_errno = E2BIG and the done callback returns
 * kXR_IOError.  The operator can increase the limit or rely on the sync path.
 */

#include "core/ngx_brix_module.h"
#include "protocols/root/dirlist/dcksm.h"
#include "fs/path/path.h"
#include "protocols/root/response/response.h"
#include "aio.h"
#include "core/compat/error_mapping.h"

#include <dirent.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <openssl/evp.h>


/* Maximum wire-response payload per kXR_oksofar / kXR_ok chunk. */
#define DIRLIST_CHUNK_CAP  65536UL

/*
 * brix_dirlist_aio_thread — worker: execute confined dirlist VFS job.
 *
 * THREAD SAFETY RULES (enforced here):
 *   - NO pool allocation (ngx_palloc / ngx_pcalloc / ngx_palloc_large).
 *   - NO nginx connection state access (c->log is stale once on a thread).
 *   - Use only the VFS worker-safe execution core and task-owned fields.
 */
void
brix_dirlist_aio_thread(void *data, ngx_log_t *log)
{
    ngx_thread_task_t    *task = data;
    brix_dirlist_aio_t *t    = task->ctx;
    brix_vfs_job_t      job;

    t->response_len = 0;
    t->io_errno     = 0;
    t->err_msg[0]   = '\0';

    brix_vfs_job_opendir_init(&job, t->dirfd, t->response, t->response_cap,
                                t->streamid, t->want_stat, t->want_cksum,
                                t->resolved, t->cksum_algo, log,
                                t->err_msg, sizeof(t->err_msg));
    brix_vfs_io_execute(&job);

    t->response_len = job.out_size;
    t->io_errno = job.io_errno;

    if (t->dirfd >= 0) {
        close(t->dirfd);
        t->dirfd = -1;
    }
}

/*
 * brix_dirlist_aio_done — main-thread completion callback.
 *
 * Fires on the nginx event loop after the thread pool posts the result.
 * Responsibilities:
 *   1. Guard against stale connection (ctx->destroyed check).
 *   2. On I/O error: send kXR_error frame, release response buffer, resume.
 *   3. On success: wrap t->response in a memory chain and queue it.
 *      The buffer is released via brix_release_read_buffer (ngx_pfree)
 *      after the chain has been fully drained.
 *   4. Call brix_aio_resume() to re-arm the appropriate event.
 */
void
brix_dirlist_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t    *task = ev->data;
    brix_dirlist_aio_t *t    = task->ctx;
    brix_ctx_t         *ctx  = t->ctx;
    ngx_connection_t     *c    = t->c;

    /* Restore connection state; abort silently if connection was destroyed. */
    if (!brix_aio_restore_request(ctx, t->streamid)) {
        return;
    }

    if (t->io_errno) {
        uint16_t  xrd_err;
        char      msg[128];

        xrd_err = brix_kxr_from_errno(t->io_errno);

        snprintf(msg, sizeof(msg), "dirlist: %s",
                 t->err_msg[0] ? t->err_msg : strerror(t->io_errno));
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "xrootd: dirlist AIO failed: %s", msg);
        brix_log_access(ctx, c, "DIRLIST", t->resolved, "-",
                          0, xrd_err, msg, 0);
        BRIX_OP_ERR(ctx, BRIX_OP_DIRLIST);

        brix_release_read_buffer(ctx, c, t->response);
        t->response = NULL;
        brix_send_error(ctx, c, xrd_err, msg);
        brix_aio_resume(c);
        return;
    }

    brix_log_access(ctx, c, "DIRLIST", t->resolved,
                      t->want_cksum ? "dcksm"
                                    : (t->want_stat ? "stat" : "-"),
                      1, 0, NULL, 0);
    BRIX_OP_OK(ctx, BRIX_OP_DIRLIST);

    /*
     * The worker already built a contiguous wire response containing every
     * kXR_oksofar frame plus the final kXR_ok frame.  Queue it as a plain
     * buffer so an empty final body still sends its 8-byte header and so the
     * owned backing allocation is retained across partial writes.
     */
    brix_queue_response_base(ctx, c, t->response, t->response_len,
                               t->response);
    if (ctx->state != XRD_ST_SENDING) {
        brix_release_read_buffer(ctx, c, t->response);
    }

    brix_aio_resume(c);
}

/*
 * Async kXR_dirlist via nginx thread pool.
 *
 * WHAT: Offloads the entire directory iteration + stat + checksum work to a
 *       thread-pool worker, freeing the nginx event loop to serve other
 *       connections while a large or slow-media directory is being scanned.
 *
 * WHY: readdir(3) + fstatat(2) + fgetxattr(2)/hash-on-miss can block for tens
 *      to hundreds of milliseconds on spinning disk or network-backed storage.
 *      Running these on the event loop stalls all connections sharing that
 *      worker process.  Posting to the nginx thread pool lets I/O block on a
 *      dedicated OS thread instead.
 *
 * HOW:
 *   Main thread (xrootd_handle_dirlist, handler.c):
 *     1. Auth, path resolution and algorithm validation run synchronously.
 *     2. A response buffer is allocated from c->pool (large block → ngx_pfree
 *        can release it after drain).
 *     3. Fields are copied into xrootd_dirlist_aio_t; the task is posted.
 *     4. Returns NGX_OK immediately; ctx->state = XRD_ST_AIO.
 *
 *   Worker thread (xrootd_dirlist_aio_thread):
 *     - Opens the directory independently (no nginx state touched).
 *     - Iterates entries: skip "." / ".." / unsafe names.
 *     - Calls fstatat, xrootd_dirlist_checksum_token (xattr fast path or
 *       full hash), and builds the complete XRootD wire response directly into
 *       t->response.  Wire format: one or more kXR_oksofar frames followed by
 *       a single kXR_ok frame.
 *     - No pool allocation in this function — only POSIX syscalls and pure
 *       computation.
 *
 *   Done callback (xrootd_dirlist_aio_done, main thread):
 *     - Checks ctx->destroyed; on error sends kXR_IOError.
 *     - On success: wraps t->response in a memory ngx_buf_t + ngx_chain_t and
 *       calls xrootd_queue_response_chain(ctx, c, chain, t->response) so the
 *       buffer is freed via xrootd_release_read_buffer (ngx_pfree) once the
 *       chain has been fully drained.
 *     - Calls xrootd_aio_resume to re-arm the read event.
 *
 * Fallback: if the thread pool is not configured (conf->common.thread_pool == NULL)
 * or the queue is full, xrootd_handle_dirlist falls back to the synchronous
 * loop already present in handler.c — behaviour is identical to pre-AIO.
 *
 * Truncation: if the directory listing would exceed XROOTD_DIRLIST_AIO_RESPONSE_MAX
 * (4 MiB), the thread sets io_errno = E2BIG and the done callback returns
 * kXR_IOError.  The operator can increase the limit or rely on the sync path.
 */

#include "ngx_xrootd_module.h"
#include "../dirlist/dcksm.h"
#include "../path/path.h"
#include "../response/response.h"
#include "../aio/aio.h"
#include "../compat/error_mapping.h"

#include <dirent.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <openssl/evp.h>


/* Maximum wire-response payload per kXR_oksofar / kXR_ok chunk. */
#define DIRLIST_CHUNK_CAP  65536UL

/*
 * xrootd_dirlist_aio_thread — worker: open dir, iterate, build wire response.
 *
 * THREAD SAFETY RULES (enforced here):
 *   - NO pool allocation (ngx_palloc / ngx_pcalloc / ngx_palloc_large).
 *   - NO nginx connection state access (c->log is stale once on a thread).
 *   - Use only POSIX calls, memcpy, snprintf, and the pure-computation helpers
 *     (xrootd_dirlist_checksum_token, xrootd_dirlist_make_dcksm_stat_body,
 *      xrootd_make_stat_body, xrootd_build_resp_hdr).
 *   - Use the `log` parameter provided by the thread pool for any logging.
 */
void
xrootd_dirlist_aio_thread(void *data, ngx_log_t *log)
{
    ngx_thread_task_t    *task = data;
    xrootd_dirlist_aio_t *t    = task->ctx;
    DIR                  *dp;
    struct dirent        *de;
    int                   dfd;
    u_char               *out  = t->response;
    size_t                cap  = t->response_cap;

    /*
     * Response wire layout:
     *
     *   base       = start of the current chunk's ServerResponseHdr
     *   cdata      = out + base + XRD_RESPONSE_HDR_LEN  (data area)
     *   cdpos      = bytes written so far into cdata
     *
     * When a chunk fills up we write its kXR_oksofar header at `out + base`,
     * advance base to the next chunk, and start fresh.
     */
    size_t   base  = 0;       /* position of current chunk header in out[]  */
    u_char  *cdata;           /* data area of current chunk                 */
    size_t   cdpos = 0;       /* bytes written in current chunk data area   */

    t->response_len = 0;
    t->io_errno     = 0;
    t->err_msg[0]   = '\0';

    /* Verify the buffer is large enough for at least one chunk. */
    if (cap < (size_t)(XRD_RESPONSE_HDR_LEN + DIRLIST_CHUNK_CAP)) {
        t->io_errno = ENOMEM;
        ngx_snprintf((u_char *) t->err_msg, sizeof(t->err_msg) - 1,
                     "response buffer too small");
        return;
    }

    /* Open the directory directly; no xrootd_open_confined() here because
     * the path was already validated and confined on the main thread. */
    dfd = open(t->resolved, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0) {
        t->io_errno = errno;
        ngx_snprintf((u_char *) t->err_msg, sizeof(t->err_msg) - 1,
                     "%s", strerror(errno));
        return;
    }

    dp = fdopendir(dfd);
    if (dp == NULL) {
        t->io_errno = errno;
        ngx_snprintf((u_char *) t->err_msg, sizeof(t->err_msg) - 1,
                     "%s", strerror(errno));
        close(dfd);
        return;
    }

    /* Initialise first chunk data pointer. */
    cdata = out + XRD_RESPONSE_HDR_LEN;

    /*
     * kXR_dstat leadin: the "." pseudo-entry with an empty stat body.
     * Format: ".\n<stat_body>\n"  where stat_body is "0 0 0 0".
     */
    if (t->want_stat) {
        static const char dstat_leadin[] = ".\n0 0 0 0\n";
        memcpy(cdata, dstat_leadin, sizeof(dstat_leadin) - 1);
        cdpos = sizeof(dstat_leadin) - 1;
    }

    while ((de = readdir(dp)) != NULL) {
        const char *name = de->d_name;
        size_t      nlen;
        struct stat entry_st;
        char        statbuf[256];
        char        cksum_token[EVP_MAX_MD_SIZE * 2 + 64];
        char        entry_path[PATH_MAX];
        size_t      need;
        int         n;

        /* Skip self and parent. */
        if (name[0] == '.' && (name[1] == '\0'
                                || (name[1] == '.' && name[2] == '\0')))
        {
            continue;
        }

        /* Skip this gateway's internal control artifacts (e.g. the checkpoint
         * recovery lock ".nginx-xrootd-ckp-recovery.lock") so they never appear
         * in the user-visible namespace — a stock XRootD export has no such
         * files, and a conformance dirlist must match. */
        if (ngx_strncmp(name, ".nginx-xrootd", sizeof(".nginx-xrootd") - 1) == 0) {
            continue;
        }

        /* Skip entries whose names contain control characters or DEL —
         * they would corrupt the newline-delimited wire format. */
        {
            const u_char *p;
            int           unsafe = 0;

            for (p = (const u_char *) name; *p != '\0'; p++) {
                if (*p < 0x20 || *p == 0x7f) {
                    unsafe = 1;
                    break;
                }
            }
            if (unsafe) {
                ngx_log_error(NGX_LOG_WARN, log, 0,
                    "xrootd: dirlist (aio) skipping entry with control bytes");
                continue;
            }
        }

        nlen = strlen(name);
        need = nlen + 1;     /* name + '\n' */
        statbuf[0]    = '\0';
        cksum_token[0] = '\0';

        if (t->want_stat) {
            if (fstatat(dirfd(dp), name, &entry_st,
                        AT_SYMLINK_NOFOLLOW) != 0)
            {
                if (errno != ENOENT) {
                    ngx_log_error(NGX_LOG_WARN, log, errno,
                        "xrootd: dirlist (aio) fstatat failed");
                }
                continue;
            }

            if (t->want_cksum) {
                xrootd_dirlist_make_dcksm_stat_body(&entry_st, statbuf,
                                                    sizeof(statbuf));
            } else {
                xrootd_make_stat_body(&entry_st, 0, 0, statbuf,
                                      sizeof(statbuf));
            }
            need += strlen(statbuf) + 1;   /* stat body + '\n' */
        }

        if (t->want_cksum && t->want_stat) {
            n = snprintf(entry_path, sizeof(entry_path), "%s/%s",
                         t->resolved, name);
            if (n < 0 || (size_t) n >= sizeof(entry_path)) {
                snprintf(cksum_token, sizeof(cksum_token),
                         "%s:none", t->cksum_algo);
            } else {
                xrootd_dirlist_checksum_token(log, dirfd(dp), name,
                                              entry_path, &entry_st,
                                              t->cksum_algo,
                                              cksum_token,
                                              sizeof(cksum_token));
            }
            /* " [ algo:hex ]" */
            need += strlen(cksum_token) + sizeof(" [  ]") - 1;
        }

        /* If this entry would overflow the current chunk, flush it first. */
        if (cdpos + need > DIRLIST_CHUNK_CAP) {
            xrootd_build_resp_hdr(t->streamid, kXR_oksofar,
                                  (uint32_t) cdpos,
                                  (ServerResponseHdr *)(out + base));
            base  += XRD_RESPONSE_HDR_LEN + cdpos;

            /* Check whether there's room for at least one more chunk. */
            if (base + XRD_RESPONSE_HDR_LEN + DIRLIST_CHUNK_CAP > cap) {
                ngx_log_error(NGX_LOG_WARN, log, 0,
                    "xrootd: dirlist (aio) response buffer full "
                    "(%uz bytes), listing truncated",
                    cap);
                t->io_errno = E2BIG;
                snprintf(t->err_msg, sizeof(t->err_msg),
                         "listing too large for AIO buffer (%zu bytes)", cap);
                closedir(dp);
                return;
            }

            cdata = out + base + XRD_RESPONSE_HDR_LEN;
            cdpos = 0;
        }

        /* Write the entry name. */
        memcpy(cdata + cdpos, name, nlen);
        cdpos += nlen;
        cdata[cdpos++] = '\n';

        /* Write stat body and optional checksum token. */
        if (t->want_stat) {
            size_t slen = strlen(statbuf);

            memcpy(cdata + cdpos, statbuf, slen);
            cdpos += slen;

            if (t->want_cksum) {
                n = snprintf((char *)(cdata + cdpos),
                             DIRLIST_CHUNK_CAP - cdpos,
                             " [ %s ]", cksum_token);
                if (n > 0) {
                    cdpos += (size_t) n;
                }
            }

            cdata[cdpos++] = '\n';
        }
    }

    closedir(dp);

    /*
     * Write the final kXR_ok frame.
     * The last '\n' becomes '\0' per the XRootD wire convention.
     */
    if (cdpos > 0) {
        cdata[cdpos - 1] = '\0';
    }
    xrootd_build_resp_hdr(t->streamid, kXR_ok, (uint32_t) cdpos,
                          (ServerResponseHdr *)(out + base));
    t->response_len = base + XRD_RESPONSE_HDR_LEN + cdpos;
}

/*
 * xrootd_dirlist_aio_done — main-thread completion callback.
 *
 * Fires on the nginx event loop after the thread pool posts the result.
 * Responsibilities:
 *   1. Guard against stale connection (ctx->destroyed check).
 *   2. On I/O error: send kXR_error frame, release response buffer, resume.
 *   3. On success: wrap t->response in a memory chain and queue it.
 *      The buffer is released via xrootd_release_read_buffer (ngx_pfree)
 *      after the chain has been fully drained.
 *   4. Call xrootd_aio_resume() to re-arm the appropriate event.
 */
void
xrootd_dirlist_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t    *task = ev->data;
    xrootd_dirlist_aio_t *t    = task->ctx;
    xrootd_ctx_t         *ctx  = t->ctx;
    ngx_connection_t     *c    = t->c;

    /* Restore connection state; abort silently if connection was destroyed. */
    if (!xrootd_aio_restore_request(ctx, t->streamid)) {
        return;
    }

    if (t->io_errno) {
        uint16_t  xrd_err;
        char      msg[128];

        xrd_err = xrootd_kxr_from_errno(t->io_errno);

        snprintf(msg, sizeof(msg), "dirlist: %s",
                 t->err_msg[0] ? t->err_msg : strerror(t->io_errno));
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "xrootd: dirlist AIO failed: %s", msg);
        xrootd_log_access(ctx, c, "DIRLIST", t->resolved, "-",
                          0, xrd_err, msg, 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_DIRLIST);

        xrootd_release_read_buffer(ctx, c, t->response);
        t->response = NULL;
        xrootd_send_error(ctx, c, xrd_err, msg);
        xrootd_aio_resume(c);
        return;
    }

    xrootd_log_access(ctx, c, "DIRLIST", t->resolved,
                      t->want_cksum ? "dcksm"
                                    : (t->want_stat ? "stat" : "-"),
                      1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_DIRLIST);

    /*
     * The worker already built a contiguous wire response containing every
     * kXR_oksofar frame plus the final kXR_ok frame.  Queue it as a plain
     * buffer so an empty final body still sends its 8-byte header and so the
     * owned backing allocation is retained across partial writes.
     */
    xrootd_queue_response_base(ctx, c, t->response, t->response_len,
                               t->response);
    if (ctx->state != XRD_ST_SENDING) {
        xrootd_release_read_buffer(ctx, c, t->response);
    }

    xrootd_aio_resume(c);
}


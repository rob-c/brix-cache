#include "query_internal.h"
#include "../response/response.h"
#include "../aio/aio.h"
#include "../compat/checksum.h"

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
 * HOW:  xrootd_ckscan_aio_thread() allocates response buffer (grows via append), stat's the scan target — if regular
 *       file, opens confined/canonical fd and computes single checksum; if directory, walks tree with depth/file limits
 *       calling ckscan_append per file. On error sets t->error_code + t->error_msg. Thread completion triggers
 *       xrootd_ckscan_aio_done() which restores the request streamid via aio_restore_request, sends error response or
 *       ok+checksum data to client, frees buffer, and resumes the client connection event loop.
 */


/* ---- public API: xrootd_ckscan_aio_thread() — async ckscan thread worker ----
 * WHAT: Thread pool worker that computes checksums for a file or directory tree. Stat's the scan target, opens confined fd
 *       for regular files and computes single checksum via xrootd_checksum_u32_fd; walks directories recursively with depth/file
 *       limits calling ckscan_append per file. Allocates response buffer with dynamic growth. Sets t->error_code on failure. */

void
xrootd_ckscan_aio_thread(void *data, ngx_log_t *log)
{
    xrootd_ckscan_aio_t *t    = data;
    struct stat          st;
    size_t               cap  = XROOTD_CKSCAN_INIT_CAP;
    size_t               used = 0;
    u_char              *buf;
    ngx_uint_t           nfiles = 0;

    buf = ngx_alloc(cap, log);
    if (buf == NULL) {
        t->error_code = kXR_NoMemory;
        snprintf(t->error_msg, sizeof(t->error_msg), "out of memory");
        return;
    }

    if (stat(t->scan_resolved, &st) != 0) {
        ngx_free(buf);
        t->error_code = kXR_NotFound;
        snprintf(t->error_msg, sizeof(t->error_msg), "stat failed: %s",
                 strerror(errno));
        return;
    }

    if (S_ISREG(st.st_mode)) {
        int      fd;
        uint32_t cksum;
        xrootd_checksum_alg_t alg;

        fd = xrootd_open_confined_canon(log, t->root_resolved,
                                        t->scan_resolved, O_RDONLY, 0);
        if (fd < 0) {
            ngx_free(buf);
            t->error_code = kXR_IOError;
            snprintf(t->error_msg, sizeof(t->error_msg), "open failed: %s",
                     strerror(errno));
            return;
        }

        if (xrootd_checksum_parse(t->algo, strlen(t->algo), &alg, NULL, 0)
                != NGX_OK
            || xrootd_checksum_u32_fd(alg, fd, t->scan_resolved, log,
                                      &cksum) != NGX_OK)
        {
            cksum = (uint32_t) -1;
        }
        close(fd);

        if (cksum == (uint32_t) -1) {
            ngx_free(buf);
            t->error_code = kXR_IOError;
            snprintf(t->error_msg, sizeof(t->error_msg), "checksum failed");
            return;
        }

        {
            int append_rc;

            append_rc = xrootd_ckscan_append(&buf, &cap, &used,
                                             t->algo, cksum,
                                             t->scan_logical);
            if (append_rc <= 0) {
                ngx_free(buf);
                t->error_code = (append_rc == 0) ? kXR_ArgTooLong
                                                 : kXR_NoMemory;
                snprintf(t->error_msg, sizeof(t->error_msg), "%s",
                         append_rc == 0 ? "path too long" : "out of memory");
                return;
            }
        }

    } else if (S_ISDIR(st.st_mode)) {
        char errmsg[128] = "";

        if (xrootd_ckscan_walk(log, t->root_resolved, t->scan_resolved,
                               t->scan_logical, t->algo, &buf, &cap, &used,
                               0, t->max_depth, t->max_files, &nfiles,
                               errmsg, sizeof(errmsg)) < 0)
        {
            ngx_free(buf);
            t->error_code = kXR_IOError;
            snprintf(t->error_msg, sizeof(t->error_msg), "%s", errmsg);
            return;
        }
    } else {
        ngx_free(buf);
        t->error_code = kXR_ArgInvalid;
        snprintf(t->error_msg, sizeof(t->error_msg), "not a file or directory");
        return;
    }

    buf[used] = '\0';
    t->resp     = buf;
    t->resp_len = used;
    t->error_code = 0;
}

/* ---- public API: xrootd_ckscan_aio_done() — async ckscan completion callback ----
 * WHAT: Event handler invoked when the thread pool worker completes. Restores the request streamid via aio_restore_request,
 *       sends error response (t->error_code + t->error_msg) or ok+checksum data to client, frees the response buffer, and
 *       resumes the client connection event loop via xrootd_aio_resume(). */

void
xrootd_ckscan_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t   *task = ev->data;
    xrootd_ckscan_aio_t *t    = task->ctx;
    xrootd_ctx_t        *ctx  = t->ctx;
    ngx_connection_t    *c    = t->c;

    if (!xrootd_aio_restore_request(ctx, t->streamid)) {
        if (t->resp) {
            ngx_free(t->resp);
        }
        return;
    }

    if (t->error_code != 0) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSCAN);
        xrootd_send_error(ctx, c, (uint16_t) t->error_code, t->error_msg);
    } else {
        XROOTD_OP_OK(ctx, XROOTD_OP_QUERY_CKSCAN);
        xrootd_log_access(ctx, c, "QUERY", t->scan_logical, "ckscan",
                          1, 0, NULL, 0);
        xrootd_send_ok(ctx, c, t->resp, (uint32_t) (t->resp_len + 1));
    }

    if (t->resp) {
        ngx_free(t->resp);
    }

    xrootd_aio_resume(c);
}


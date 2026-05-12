#include "ngx_xrootd_module.h"
#include "chkpoint_xeq.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

/*
 * kXR_chkpoint — checkpoint/transaction write semantics.
 *
 * Opcodes:
 *   kXR_ckpBegin    (0) — snapshot the file into a temp copy
 *   kXR_ckpCommit   (1) — discard the snapshot (writes are permanent)
 *   kXR_ckpRollback (3) — restore the file from the snapshot
 *   kXR_ckpQuery    (2) — report checkpoint capacity and usage
 *   kXR_ckpXeq      (4) — execute a write sub-operation (write/pgwrite/
 *                           truncate/writev) under checkpoint protection
 *
 * The checkpoint is stored as a sibling file: <open-path>.ckp.
 * A non-NULL ckp_path in the xrootd_file_t slot indicates an active checkpoint.
 */

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

/*
 * Copy len bytes from src_fd at src_off → dst_fd at dst_off.
 * Tries copy_file_range(2); falls back to pread/pwrite on ENOSYS/EOPNOTSUPP.
 */
static int
ckp_copy_range(int src_fd, off_t src_off, int dst_fd, off_t dst_off,
    size_t len, ngx_log_t *log)
{
    size_t    remaining = len;
    u_char    buf[65536];
    ssize_t   nr, nw;

    while (remaining > 0) {
#ifdef __NR_copy_file_range
        loff_t  s_off = (loff_t) src_off;
        loff_t  d_off = (loff_t) dst_off;
        ssize_t cfr;

        cfr = (ssize_t) syscall(__NR_copy_file_range,
                                src_fd, &s_off,
                                dst_fd, &d_off,
                                remaining, 0);
        if (cfr > 0) {
            src_off   += (off_t) cfr;
            dst_off   += (off_t) cfr;
            remaining -= (size_t) cfr;
            continue;
        }
        if (cfr < 0 && errno != ENOSYS && errno != EOPNOTSUPP && errno != EXDEV) {
            ngx_log_error(NGX_LOG_ERR, log, errno,
                          "xrootd: chkpoint copy_file_range failed");
            return -1;
        }
        /* Fall through to pread/pwrite for ENOSYS / EOPNOTSUPP / EXDEV */
#endif

        nr = pread(src_fd, buf, remaining < sizeof(buf) ? remaining : sizeof(buf),
                   src_off);
        if (nr <= 0) {
            ngx_log_error(NGX_LOG_ERR, log, errno,
                          "xrootd: chkpoint pread failed");
            return -1;
        }
        nw = pwrite(dst_fd, buf, (size_t) nr, dst_off);
        if (nw != nr) {
            ngx_log_error(NGX_LOG_ERR, log, errno,
                          "xrootd: chkpoint pwrite failed");
            return -1;
        }
        src_off   += (off_t) nr;
        dst_off   += (off_t) nr;
        remaining -= (size_t) nr;
    }

    return 0;
}


static void
ckp_clear_path(xrootd_file_t *f)
{
    if (f->ckp_path != NULL) {
        ngx_free(f->ckp_path);
        f->ckp_path = NULL;
    }
    f->ckp_size = 0;
}


/* ------------------------------------------------------------------ */
/* kXR_ckpBegin — snapshot current file state                          */
/* ------------------------------------------------------------------ */

static ngx_int_t
ckp_begin(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx)
{
    xrootd_file_t *f = &ctx->files[idx];
    struct stat    st;
    size_t         plen;
    int            ckp_fd;

    if (f->ckp_path != NULL) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CHKPOINT, "CHKPOINT", f->path, "begin",
                          kXR_inProgress, "checkpoint already active");
    }

    if (fstat(f->fd, &st) != 0) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CHKPOINT, "CHKPOINT", f->path, "begin",
                          kXR_IOError, strerror(errno));
    }

    if ((int64_t) st.st_size > kXR_ckpMinMax) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CHKPOINT, "CHKPOINT", f->path, "begin",
                          kXR_overQuota, "file too large to checkpoint");
    }

    plen = strlen(f->path);
    if (plen + 4 >= PATH_MAX) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_CHKPOINT);
        return xrootd_send_error(ctx, c, kXR_ArgTooLong,
                                 "path too long for checkpoint");
    }

    f->ckp_path = ngx_alloc(plen + 5, c->log);
    if (f->ckp_path == NULL) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_CHKPOINT);
        return xrootd_send_error(ctx, c, kXR_NoMemory,
                                 "checkpoint path allocation failed");
    }

    ngx_memcpy(f->ckp_path, f->path, plen);
    ngx_memcpy(f->ckp_path + plen, ".ckp", 5); /* includes NUL */

    ckp_fd = open(f->ckp_path, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0600);
    if (ckp_fd < 0) {
        ckp_clear_path(f);
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CHKPOINT, "CHKPOINT", f->path, "begin",
                          kXR_IOError, strerror(errno));
    }

    f->ckp_size = (int64_t) st.st_size;

    if (f->ckp_size > 0) {
        if (ckp_copy_range(f->fd, 0, ckp_fd, 0, (size_t) f->ckp_size,
                           c->log) != 0) {
            close(ckp_fd);
            unlink(f->ckp_path);
            ckp_clear_path(f);
            XROOTD_OP_ERR(ctx, XROOTD_OP_CHKPOINT);
            return xrootd_send_error(ctx, c, kXR_IOError,
                                     "checkpoint copy failed");
        }
    }

    close(ckp_fd);

    XROOTD_RETURN_OK(ctx, c, XROOTD_OP_CHKPOINT, "CHKPOINT", f->path, "begin", 0);
}


/* ------------------------------------------------------------------ */
/* kXR_ckpCommit — discard checkpoint, writes are permanent            */
/* ------------------------------------------------------------------ */

static ngx_int_t
ckp_commit(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx)
{
    xrootd_file_t *f = &ctx->files[idx];

    if (f->ckp_path == NULL) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CHKPOINT, "CHKPOINT", f->path, "commit",
                          kXR_InvalidRequest, "no active checkpoint");
    }

    (void) unlink(f->ckp_path);
    ckp_clear_path(f);

    XROOTD_RETURN_OK(ctx, c, XROOTD_OP_CHKPOINT, "CHKPOINT", f->path, "commit", 0);
}


/* ------------------------------------------------------------------ */
/* kXR_ckpRollback — restore file from checkpoint                      */
/* ------------------------------------------------------------------ */

static ngx_int_t
ckp_rollback(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx)
{
    xrootd_file_t *f = &ctx->files[idx];
    int            ckp_fd;

    if (f->ckp_path == NULL) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CHKPOINT, "CHKPOINT", f->path, "rollback",
                          kXR_InvalidRequest, "no active checkpoint");
    }

    /* Truncate original to its checkpointed length first. */
    if (ftruncate(f->fd, (off_t) f->ckp_size) != 0) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CHKPOINT, "CHKPOINT", f->path, "rollback",
                          kXR_IOError, strerror(errno));
    }

    /* Restore file content from checkpoint if there was any. */
    if (f->ckp_size > 0) {
        ckp_fd = open(f->ckp_path, O_RDONLY | O_CLOEXEC);
        if (ckp_fd < 0) {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CHKPOINT, "CHKPOINT", f->path, "rollback",
                              kXR_IOError, strerror(errno));
        }

        if (ckp_copy_range(ckp_fd, 0, f->fd, 0, (size_t) f->ckp_size,
                           c->log) != 0) {
            close(ckp_fd);
            XROOTD_OP_ERR(ctx, XROOTD_OP_CHKPOINT);
            return xrootd_send_error(ctx, c, kXR_IOError,
                                     "checkpoint restore copy failed");
        }
        close(ckp_fd);
    }

    (void) unlink(f->ckp_path);
    ckp_clear_path(f);

    XROOTD_RETURN_OK(ctx, c, XROOTD_OP_CHKPOINT, "CHKPOINT", f->path, "rollback", 0);
}


/* ------------------------------------------------------------------ */
/* kXR_ckpQuery — report checkpoint capacity / current usage           */
/* ------------------------------------------------------------------ */

static ngx_int_t
ckp_query(xrootd_ctx_t *ctx, ngx_connection_t *c, int idx)
{
    xrootd_file_t              *f = &ctx->files[idx];
    uint32_t                    use_sz = 0;
    ServerResponseBody_ChkPoint body;

    if (f->ckp_path != NULL) {
        struct stat st;
        if (stat(f->ckp_path, &st) == 0) {
            use_sz = (uint32_t) st.st_size;
        }
    }

    body.maxCkpSize = htonl((uint32_t) kXR_ckpMinMax);
    body.useCkpSize = htonl(use_sz);

    xrootd_log_access(ctx, c, "CHKPOINT", f->path, "query",
                      1, kXR_ok, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_CHKPOINT);
    return xrootd_send_ok(ctx, c, &body, (uint32_t) sizeof(body));
}


/* ------------------------------------------------------------------ */
/* Top-level kXR_chkpoint dispatcher                                   */
/* ------------------------------------------------------------------ */

ngx_int_t
xrootd_handle_chkpoint(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientChkPointRequest *req = (ClientChkPointRequest *) ctx->hdr_buf;
    int                    idx;
    ngx_int_t              validate_rc;

    (void) conf;

    idx = (int)(unsigned char) req->fhandle[0];

    if (!xrootd_validate_write_handle(ctx, c, idx, "CHKPOINT",
                                      XROOTD_OP_CHKPOINT, &validate_rc)) {
        return validate_rc;
    }

    switch ((unsigned char) req->opcode) {

    case kXR_ckpBegin:
        return ckp_begin(ctx, c, idx);

    case kXR_ckpCommit:
        return ckp_commit(ctx, c, idx);

    case kXR_ckpQuery:
        return ckp_query(ctx, c, idx);

    case kXR_ckpRollback:
        return ckp_rollback(ctx, c, idx);

    case kXR_ckpXeq:
        return ckp_xeq(ctx, c, idx);

    default:
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "xrootd: kXR_chkpoint unknown opcode=%d",
                       (int)(unsigned char) req->opcode);
        XROOTD_OP_ERR(ctx, XROOTD_OP_CHKPOINT);
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "unknown chkpoint opcode");
    }
}

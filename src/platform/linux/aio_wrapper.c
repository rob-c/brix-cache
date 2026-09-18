/*
 * src/platform/linux/aio_wrapper.c - Linux io_uring async I/O
 * 
 * Phase 4: Full io_uring implementation for async read/write operations.
 * This integrates with the existing Phase 44 io_uring backend.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "../platform.h"
#include "../platform_api.h"

#if BRIX_PLATFORM_LINUX && BRIX_HAS_IO_URING

#include <liburing.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

struct brix_aio_ctx {
    struct io_uring ring;
    size_t max_entries;
    ngx_uint_t pending_ops;
};

typedef struct brix_aio_ctx brix_aio_ctx_t;

/* Callback wrapper structure */
typedef struct {
    void (*callback)(int, ssize_t, void *);
    void *user_data;
    int fd;
} brix_aio_callback_t;

brix_aio_ctx_t *
brix_aio_create(size_t max_entries)
{
    brix_aio_ctx_t *ctx;
    int ret;
    
    ctx = calloc(1, sizeof(brix_aio_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }
    
    ret = io_uring_queue_init(max_entries, &ctx->ring, 0);
    if (ret < 0) {
        errno = -ret;
        free(ctx);
        return NULL;
    }
    
    ctx->max_entries = max_entries;
    ctx->pending_ops = 0;
    
    return ctx;
}

void
brix_aio_destroy(brix_aio_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    
    io_uring_queue_exit(&ctx->ring);
    free(ctx);
}

static void
brix_aio_io_uring_callback(struct io_uring_cqe *cqe)
{
    brix_aio_callback_t *cb = (brix_aio_callback_t *)cqe->user_data;
    
    if (cb != NULL) {
        if (cqe->res >= 0) {
            cb->callback(cb->fd, (ssize_t)cqe->res, cb->user_data);
        } else {
            errno = -cqe->res;
            cb->callback(cb->fd, -1, cb->user_data);
        }
        free(cb);
    }
}

/* ---- Prepare a typed read or write submission ----
 * WHAT: Queue the request with its callback, or report validation/capacity errors.
 * WHY: Read/write preparation has identical ownership and pending accounting.
 * HOW: 1. Validate inputs and acquire a submission slot. 2. Attach the callback.
 *      3. Prepare the chosen opcode and increment pending operations.
 */
static int
brix_aio_prepare(brix_aio_ctx_t *ctx, int fd, const void *buf, size_t count,
              off_t offset, void (*callback)(int, ssize_t, void *), void *user_data, unsigned int opcode)
{
    struct io_uring_sqe *sqe;
    brix_aio_callback_t *cb;
    
    if (ctx == NULL || buf == NULL || callback == NULL) {
        errno = EINVAL;
        return -1;
    }
    
    sqe = io_uring_get_sqe(&ctx->ring);
    if (sqe == NULL) {
        errno = EAGAIN;
        return -1;
    }
    
    cb = calloc(1, sizeof(brix_aio_callback_t));
    if (cb == NULL) {
        errno = ENOMEM;
        return -1;
    }
    
    cb->callback = callback;
    cb->user_data = user_data;
    cb->fd = fd;
    
    io_uring_prep_rw(opcode, sqe, fd, buf, count, offset);
    io_uring_sqe_set_data(sqe, cb);
    
    ngx_atomic_fetch_add(&ctx->pending_ops, 1);
    
    return 0;
}

int
brix_aio_read(brix_aio_ctx_t *ctx, int fd, void *buf, size_t count,
              off_t offset, void (*callback)(int, ssize_t, void *), void *user_data)
{
    return brix_aio_prepare(ctx, fd, buf, count, offset, callback,
                            user_data, IORING_OP_READ);
}

int
brix_aio_write(brix_aio_ctx_t *ctx, int fd, const void *buf, size_t count, 
               off_t offset, void (*callback)(int, ssize_t, void *), void *user_data)
{
    return brix_aio_prepare(ctx, fd, buf, count, offset, callback,
                            user_data, IORING_OP_WRITE);
}

/* ---- Submit queued Linux AIO requests and wait for their completions ----
 *
 * WHAT: Return the number completed, or -1 on a submission/wait error.
 * WHY: liburing requires an actual timespec pointer for finite timeouts.
 * HOW: 1. Submit prepared requests and check the submission result.
 *      2. Wait with a converted timeout, or without a deadline when negative.
 *      3. Dispatch and consume each completed request.
 */
int
brix_aio_wait(brix_aio_ctx_t *ctx, int timeout_ms)
{
    struct io_uring_cqe *cqe;
    struct __kernel_timespec timeout;
    int ret;
    int completed = 0;
    
    if (ctx == NULL) {
        errno = EINVAL;
        return -1;
    }

    ret = io_uring_submit(&ctx->ring);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }

    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_nsec = (timeout_ms % 1000) * 1000000L;
    
    while (ctx->pending_ops > 0) {
        if (timeout_ms < 0) {
            ret = io_uring_wait_cqe(&ctx->ring, &cqe);
        } else {
            ret = io_uring_wait_cqe_timeout(&ctx->ring, &cqe, &timeout);
        }
        
        if (ret < 0) {
            if (ret == -ETIME) {
                return completed;  /* Timeout */
            }
            if (ret == -EINTR) {
                continue;  /* Interrupted, retry */
            }
            errno = -ret;
            return -1;
        }
        
        /* Process completion */
        brix_aio_io_uring_callback(cqe);
        io_uring_cqe_seen(&ctx->ring, cqe);
        ctx->pending_ops--;
        completed++;
    }
    
    return completed;
}

#else /* !BRIX_PLATFORM_LINUX || !BRIX_HAS_IO_URING */

/* Stub implementation when io_uring is not available */

typedef struct brix_aio_ctx brix_aio_ctx_t;

brix_aio_ctx_t *
brix_aio_create(size_t max_entries)
{
    (void)max_entries;
    errno = ENOSYS;
    return NULL;
}

void
brix_aio_destroy(brix_aio_ctx_t *ctx)
{
    (void)ctx;
}

int
brix_aio_write(brix_aio_ctx_t *ctx, int fd, const void *buf, size_t count,
               off_t offset, void (*callback)(int, ssize_t, void *), void *user_data)
{
    (void)ctx;
    (void)fd;
    (void)buf;
    (void)count;
    (void)offset;
    (void)callback;
    (void)user_data;
    errno = ENOSYS;
    return -1;
}

int
brix_aio_read(brix_aio_ctx_t *ctx, int fd, void *buf, size_t count,
              off_t offset, void (*callback)(int, ssize_t, void *), void *user_data)
{
    return brix_aio_write(ctx, fd, buf, count, offset, callback, user_data);
}

int
brix_aio_wait(brix_aio_ctx_t *ctx, int timeout_ms)
{
    (void)ctx;
    (void)timeout_ms;
    errno = ENOSYS;
    return -1;
}

#endif /* BRIX_PLATFORM_LINUX && BRIX_HAS_IO_URING */

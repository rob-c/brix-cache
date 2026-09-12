/*
 * src/platform/linux/aio_wrapper.c - Linux io_uring async I/O
 * 
 * Phase 4: Full io_uring implementation for async read/write operations.
 * This integrates with the existing Phase 44 io_uring backend.
 */

#include "../platform.h"
#include "../platform_api.h"

#if BRIX_HAS_IO_URING

#include <liburing.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

/*
 * Async I/O context for Linux (io_uring-based)
 */
struct brix_aio_ctx {
    struct io_uring ring;
    size_t max_entries;
    ngx_uint_t pending_ops;
};

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
    if (ctx != NULL) {
        io_uring_queue_exit(&ctx->ring);
        free(ctx);
    }
}

/* Completion handler callback */
static void
brix_aio_io_uring_callback(struct io_uring_cqe *cqe)
{
    brix_aio_callback_t *cb = (brix_aio_callback_t *)cqe->user_data;
    
    if (cb && cb->callback) {
        if (cqe->res >= 0) {
            cb->callback(cb->fd, (ssize_t)cqe->res, cb->user_data);
        } else {
            errno = -cqe->res;
            cb->callback(cb->fd, -1, cb->user_data);
        }
    }
    
    if (cb) {
        free(cb);
    }
}

int
brix_aio_read(brix_aio_ctx_t *ctx, int fd, void *buf, size_t count, 
              off_t offset, void (*callback)(int, ssize_t, void *), void *user_data)
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
    
    /* Allocate callback structure */
    cb = malloc(sizeof(brix_aio_callback_t));
    if (cb == NULL) {
        errno = ENOMEM;
        return -1;
    }
    
    cb->callback = callback;
    cb->user_data = user_data;
    cb->fd = fd;
    
    /* Prepare read operation */
    io_uring_prep_read(sqe, fd, buf, count, offset);
    io_uring_sqe_set_data(sqe, cb);
    
    ctx->pending_ops++;
    
    return 0;
}

int
brix_aio_write(brix_aio_ctx_t *ctx, int fd, const void *buf, size_t count, 
               off_t offset, void (*callback)(int, ssize_t, void *), void *user_data)
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
    
    /* Allocate callback structure */
    cb = malloc(sizeof(brix_aio_callback_t));
    if (cb == NULL) {
        errno = ENOMEM;
        return -1;
    }
    
    cb->callback = callback;
    cb->user_data = user_data;
    cb->fd = fd;
    
    /* Prepare write operation */
    io_uring_prep_write(sqe, fd, buf, count, offset);
    io_uring_sqe_set_data(sqe, cb);
    
    ctx->pending_ops++;
    
    return 0;
}

int
brix_aio_wait(brix_aio_ctx_t *ctx, int timeout_ms)
{
    struct io_uring_cqe *cqe;
    int ret;
    int completed = 0;
    
    if (ctx == NULL) {
        errno = EINVAL;
        return -1;
    }
    
    /* Submit pending operations */
    ret = io_uring_submit(&ctx->ring);
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    
    /* Wait for completions */
    while (ctx->pending_ops > 0) {
        ret = io_uring_wait_cqe_timeout(&ctx->ring, &cqe, 
                                        timeout_ms < 0 ? NULL : 
                                        &(struct __kernel_timespec){
                                            .tv_sec = timeout_ms / 1000,
                                            .tv_nsec = (timeout_ms % 1000) * 1000000
                                        });
        
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

#else /* !BRIX_HAS_IO_URING */

/* Stub implementation when io_uring is not available */

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
brix_aio_read(brix_aio_ctx_t *ctx, int fd, void *buf, size_t count, 
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
brix_aio_wait(brix_aio_ctx_t *ctx, int timeout_ms)
{
    (void)ctx;
    (void)timeout_ms;
    errno = ENOSYS;
    return -1;
}

#endif /* BRIX_HAS_IO_URING */

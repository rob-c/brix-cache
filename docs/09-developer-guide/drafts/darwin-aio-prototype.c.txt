/*
 * src/platform/darwin/aio_wrapper.c - macOS async I/O via thread pool
 * 
 * Phase 4: Uses nginx thread pool for async operations.
 * macOS lacks io_uring, so we use nginx's thread_pool directive.
 * 
 * This wrapper provides the same API as the Linux io_uring wrapper,
 * but uses nginx thread pool infrastructure for actual async operations.
 */

#include "../platform.h"
#include "../platform_api.h"
#include <ngx_thread_pool.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

/*
 * Async I/O context for macOS (thread pool-based)
 */
struct brix_aio_ctx {
    ngx_thread_pool_t *pool;
    size_t max_entries;
    ngx_atomic_t pending_ops;
    ngx_log_t *log;
};

/* Task structure for thread pool operations */
typedef struct {
    ngx_thread_task_t task;
    int fd;
    void *buf;
    size_t count;
    off_t offset;
    void (*callback)(int, ssize_t, void *);
    void *user_data;
    int is_read;  /* 1=read, 0=write */
    brix_aio_ctx_t *ctx;
} brix_aio_task_t;

/* Thread pool task handler */
static ngx_int_t
brix_aio_thread_handler(ngx_thread_pool_t *tp, ngx_log_t *log, brix_aio_task_t *aio_task)
{
    ssize_t result;
    
    if (aio_task->is_read) {
        result = pread(aio_task->fd, aio_task->buf, aio_task->count, aio_task->offset);
    } else {
        result = pwrite(aio_task->fd, aio_task->buf, aio_task->count, aio_task->offset);
    }
    
    /* Call callback with result */
    if (aio_task->callback) {
        aio_task->callback(aio_task->fd, result, aio_task->user_data);
    }
    
    /* Decrement pending ops */
    ngx_atomic_fetch_add(&aio_task->ctx->pending_ops, -1);
    
    /* Free task structure */
    free(aio_task);
    
    return NGX_OK;
}

brix_aio_ctx_t *
brix_aio_create(size_t max_entries)
{
    brix_aio_ctx_t *ctx;
    ngx_str_t name = ngx_string("brix_aio");
    
    ctx = calloc(1, sizeof(brix_aio_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }
    
    /* Get nginx thread pool - must be configured in nginx.conf */
    ctx->pool = ngx_thread_pool_get(ngx_cycle, &name);
    if (ctx->pool == NULL) {
        /* Thread pool not configured - this is an error */
        /* Caller should add 'thread_pool brix_aio threads=4' to nginx.conf */
        free(ctx);
        errno = ENOENT;
        return NULL;
    }
    
    ctx->max_entries = max_entries;
    ctx->pending_ops = 0;
    ctx->log = ngx_cycle->log;
    
    return ctx;
}

void
brix_aio_destroy(brix_aio_ctx_t *ctx)
{
    if (ctx != NULL) {
        /* Wait for pending operations to complete */
        while (ctx->pending_ops > 0) {
            usleep(1000);  /* 1ms */
        }
        free(ctx);
    }
}

int
brix_aio_read(brix_aio_ctx_t *ctx, int fd, void *buf, size_t count, 
              off_t offset, void (*callback)(int, ssize_t, void *), void *user_data)
{
    brix_aio_task_t *aio_task;
    ngx_int_t rc;
    
    if (ctx == NULL || buf == NULL || callback == NULL) {
        errno = EINVAL;
        return -1;
    }
    
    /* Allocate task structure */
    aio_task = calloc(1, sizeof(brix_aio_task_t));
    if (aio_task == NULL) {
        errno = ENOMEM;
        return -1;
    }
    
    aio_task->fd = fd;
    aio_task->buf = buf;
    aio_task->count = count;
    aio_task->offset = offset;
    aio_task->callback = callback;
    aio_task->user_data = user_data;
    aio_task->is_read = 1;
    aio_task->ctx = ctx;
    
    /* Set up thread task */
    aio_task->task.handler = (ngx_thread_handler_pt)brix_aio_thread_handler;
    aio_task->task.ctx = aio_task;
    
    /* Increment pending ops before posting */
    ngx_atomic_fetch_add(&ctx->pending_ops, 1);
    
    /* Post to thread pool */
    rc = ngx_thread_post(ctx->pool, &aio_task->task, ctx->log);
    if (rc != NGX_OK) {
        ngx_atomic_fetch_add(&ctx->pending_ops, -1);
        free(aio_task);
        errno = EAGAIN;
        return -1;
    }
    
    return 0;
}

int
brix_aio_write(brix_aio_ctx_t *ctx, int fd, const void *buf, size_t count, 
               off_t offset, void (*callback)(int, ssize_t, void *), void *user_data)
{
    brix_aio_task_t *aio_task;
    ngx_int_t rc;
    
    if (ctx == NULL || buf == NULL || callback == NULL) {
        errno = EINVAL;
        return -1;
    }
    
    /* Allocate task structure */
    aio_task = calloc(1, sizeof(brix_aio_task_t));
    if (aio_task == NULL) {
        errno = ENOMEM;
        return -1;
    }
    
    aio_task->fd = fd;
    aio_task->buf = (void *)buf;  /* Cast away const for thread task */
    aio_task->count = count;
    aio_task->offset = offset;
    aio_task->callback = callback;
    aio_task->user_data = user_data;
    aio_task->is_read = 0;
    aio_task->ctx = ctx;
    
    /* Set up thread task */
    aio_task->task.handler = (ngx_thread_handler_pt)brix_aio_thread_handler;
    aio_task->task.ctx = aio_task;
    
    /* Increment pending ops before posting */
    ngx_atomic_fetch_add(&ctx->pending_ops, 1);
    
    /* Post to thread pool */
    rc = ngx_thread_post(ctx->pool, &aio_task->task, ctx->log);
    if (rc != NGX_OK) {
        ngx_atomic_fetch_add(&ctx->pending_ops, -1);
        free(aio_task);
        errno = EAGAIN;
        return -1;
    }
    
    return 0;
}

int
brix_aio_wait(brix_aio_ctx_t *ctx, int timeout_ms)
{
    int elapsed = 0;
    int completed = 0;
    
    if (ctx == NULL) {
        errno = EINVAL;
        return -1;
    }
    
    /* Wait for pending operations with timeout */
    while (ctx->pending_ops > 0) {
        if (timeout_ms >= 0 && elapsed >= timeout_ms) {
            return completed;  /* Timeout */
        }
        
        usleep(1000);  /* 1ms */
        elapsed += 1;
        completed++;
    }
    
    return completed;
}

/*
 * src/platform/darwin/aio_wrapper_stub.c - macOS AIO stub
 * 
 * macOS lacks io_uring and the nginx thread pool API used in the full
 * implementation. This stub allows compilation but reports AIO as unavailable.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "../platform.h"
#include "../platform_api.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Stub AIO context */
struct brix_aio_ctx {
    int dummy;
};
typedef struct brix_aio_ctx brix_aio_ctx_t;

int
brix_aio_init(size_t max_entries, ngx_log_t *log)
{
    (void)max_entries; (void)log;
    /* AIO not available on macOS without io_uring */
    return -1;
}

void
brix_aio_destroy(brix_aio_ctx_t *ctx)
{
    (void)ctx;
}

int
brix_aio_submit_read(brix_aio_ctx_t *ctx, int fd, void *buf, size_t count,
                     off_t offset, void (*callback)(int, ssize_t, void *),
                     void *user_data)
{
    (void)ctx; (void)fd; (void)buf; (void)count; (void)offset;
    (void)callback; (void)user_data;
    return -ENOSYS;  /* Not implemented */
}

int
brix_aio_submit_write(brix_aio_ctx_t *ctx, int fd, const void *buf, size_t count,
                      off_t offset, void (*callback)(int, ssize_t, void *),
                      void *user_data)
{
    (void)ctx; (void)fd; (void)buf; (void)count; (void)offset;
    (void)callback; (void)user_data;
    return -ENOSYS;  /* Not implemented */
}

int
brix_aio_wait(brix_aio_ctx_t *ctx, int timeout_ms)
{
    (void)ctx; (void)timeout_ms;
    return -ENOSYS;  /* Not implemented */
}

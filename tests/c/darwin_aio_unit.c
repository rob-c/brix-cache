/* Native success, error, and positional-integrity checks for Darwin AIO. */
#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct brix_aio_ctx brix_aio_ctx_t;
brix_aio_ctx_t *brix_aio_create(size_t max_entries);
void brix_aio_destroy(brix_aio_ctx_t *ctx);
int brix_aio_read(brix_aio_ctx_t *, int, void *, size_t, off_t,
    void (*)(int, ssize_t, void *), void *);
int brix_aio_write(brix_aio_ctx_t *, int, const void *, size_t, off_t,
    void (*)(int, ssize_t, void *), void *);
int brix_aio_wait(brix_aio_ctx_t *ctx, int timeout_ms);

static void
record_result(int fd, ssize_t result, void *data)
{
    ssize_t *slot = data;

    (void) fd;
    *slot = result;
}

int
main(void)
{
    char            name[] = "/tmp/brix-aio.XXXXXX";
    char            actual[9] = { 0 };
    const char      initial[] = "--------";
    const char      payload[] = "DATA";
    ssize_t         result = -2;
    brix_aio_ctx_t *ctx = brix_aio_create(2);
    int             fd = mkstemp(name);

    assert(ctx != NULL && fd >= 0);
    unlink(name);
    assert(write(fd, initial, 8) == 8);
    assert(brix_aio_write(ctx, fd, payload, 4, 2, record_result, &result) == 0);
    while (result == -2) assert(brix_aio_wait(ctx, 1000) >= 0);
    assert(result == 4);
    assert(pread(fd, actual, 8, 0) == 8);
    assert(memcmp(actual, "--DATA--", 8) == 0);
    result = -2;
    memset(actual, 0, sizeof(actual));
    assert(brix_aio_read(ctx, fd, actual, 4, 2, record_result, &result) == 0);
    while (result == -2) assert(brix_aio_wait(ctx, 1000) >= 0);
    assert(result == 4 && memcmp(actual, "DATA", 4) == 0);
    assert(brix_aio_read(ctx, fd, actual, 1, 0, NULL, NULL) == -1);
    assert(pread(fd, actual, 8, 0) == 8);
    assert(memcmp(actual, "--DATA--", 8) == 0);
    brix_aio_destroy(ctx);
    close(fd);
    return 0;
}

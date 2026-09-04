/* Public bounded stream, fd-drain and whole-file helpers for brix_rfile. */
#include "brix.h"
#include "brix_ops.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BRIX_RFILE_CHUNK_DEFAULT (1u << 20)

typedef struct {
    int fd;
} rfile_fd_sink_t;

typedef struct {
    uint8_t *data;
    size_t   used;
    size_t   capacity;
} rfile_memory_sink_t;

static int
rfile_arguments_valid(brix_rfile *rf, int64_t offset, int64_t limit,
                      brix_rfile_sink_fn sink, brix_status *st)
{
    if (rf != NULL && sink != NULL && offset >= 0 && limit >= -1) {
        return 1;
    }
    brix_status_set(st, XRDC_EUSAGE, EINVAL, "invalid resilient-file stream arguments");
    return 0;
}

int
brix_rfile_pump(brix_rfile *rf, int64_t offset, int64_t limit,
                size_t chunk_size, brix_rfile_sink_fn sink, void *arg,
                int64_t *moved, brix_status *st)
{
    uint8_t *buffer;
    int64_t  total = 0;
    int      rc = 0;

    if (moved != NULL) {
        *moved = 0;
    }
    if (!rfile_arguments_valid(rf, offset, limit, sink, st)) {
        return -1;
    }
    if (chunk_size == 0) {
        chunk_size = BRIX_RFILE_CHUNK_DEFAULT;
    }
    buffer = malloc(chunk_size);
    if (buffer == NULL) {
        brix_status_set(st, XRDC_EIO, ENOMEM, "resilient-file stream: out of memory");
        return -1;
    }
    while (limit < 0 || total < limit) {
        size_t  want = chunk_size;
        ssize_t got;
        int      sink_rc;

        if (limit >= 0 && (int64_t) want > limit - total) {
            want = (size_t) (limit - total);
        }
        if (want == 0) {
            break;
        }
        got = brix_rfile_pread(rf, offset + total, buffer, want, st);
        if (got < 0) {
            rc = -1;
            break;
        }
        if (got == 0) {
            break;
        }
        sink_rc = sink(buffer, (size_t) got, offset + total, arg, st);
        total += got;
        if (sink_rc != 0) {
            rc = sink_rc < 0 ? -1 : 0;
            break;
        }
    }
    free(buffer);
    if (moved != NULL) {
        *moved = total;
    }
    return rc;
}

static int
rfile_fd_sink(const uint8_t *data, size_t len, int64_t offset, void *arg,
              brix_status *st)
{
    rfile_fd_sink_t *sink = arg;
    size_t           written = 0;

    (void) offset;
    while (written < len) {
        ssize_t n = write(sink->fd, data + written, len - written);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            int cause = n < 0 ? errno : EIO;
            brix_status_set(st, XRDC_EIO, cause,
                            "local write: %s", strerror(cause));
            return -1;
        }
        written += (size_t) n;
    }
    return 0;
}

int
brix_rfile_drain_to_fd(brix_rfile *rf, int64_t offset, int64_t limit,
                       size_t chunk_size, int fd, int64_t *moved,
                       brix_status *st)
{
    rfile_fd_sink_t sink = {fd};

    if (fd < 0) {
        brix_status_set(st, XRDC_EUSAGE, EBADF, "invalid output descriptor");
        return -1;
    }
    return brix_rfile_pump(rf, offset, limit, chunk_size, rfile_fd_sink,
                           &sink, moved, st);
}

static int
rfile_memory_sink(const uint8_t *data, size_t len, int64_t offset, void *arg,
                  brix_status *st)
{
    rfile_memory_sink_t *sink = arg;

    (void) offset;
    if (len > sink->capacity - sink->used) {
        brix_status_set(st, XRDC_EPROTO, EOVERFLOW,
                        "remote file exceeded its declared size");
        return -1;
    }
    memcpy(sink->data + sink->used, data, len);
    sink->used += len;
    return 0;
}

static int
rfile_slurp_size(brix_conn *c, const char *path, int64_t max_bytes,
                 size_t *size, brix_status *st)
{
    brix_statinfo info;

    if (c == NULL || path == NULL || max_bytes < -1 || size == NULL) {
        brix_status_set(st, XRDC_EUSAGE, EINVAL, "invalid resilient-file slurp arguments");
        return -1;
    }
    if (brix_stat(c, path, &info, st) != 0) {
        return -1;
    }
    if (info.size < 0 || (uint64_t) info.size > SIZE_MAX
        || (max_bytes >= 0 && info.size > max_bytes)) {
        brix_status_set(st, XRDC_EIO, EFBIG, "remote file is too large to slurp");
        return -1;
    }
    *size = (size_t) info.size;
    return 0;
}

int
brix_rfile_slurp(brix_conn *c, const char *path, const char *opaque,
                 int64_t max_bytes, uint8_t **out, int64_t *len,
                 brix_status *st)
{
    brix_rfile         file;
    rfile_memory_sink_t sink;
    size_t              size;
    int                 rc;

    if (out == NULL || len == NULL) {
        brix_status_set(st, XRDC_EUSAGE, EINVAL, "missing resilient-file slurp output");
        return -1;
    }
    *out = NULL;
    *len = 0;
    if (rfile_slurp_size(c, path, max_bytes, &size, st) != 0) {
        return -1;
    }
    sink.data = malloc(size == 0 ? 1 : size);
    if (sink.data == NULL) {
        brix_status_set(st, XRDC_EIO, ENOMEM, "resilient-file slurp: out of memory");
        return -1;
    }
    sink.used = 0;
    sink.capacity = size;
    if (brix_rfile_open_read(c, path, opaque, 0, -1, &file, st) != 0) {
        free(sink.data);
        return -1;
    }
    rc = brix_rfile_pump(&file, 0, (int64_t) size, 0,
                         rfile_memory_sink, &sink, NULL, st);
    {
        brix_status ignored;
        brix_status_clear(&ignored);
        if (brix_rfile_close(&file, rc == 0 ? st : &ignored) != 0 && rc == 0) {
            rc = -1;
        }
    }
    if (rc != 0) {
        free(sink.data);
        return -1;
    }
    *out = sink.data;
    *len = (int64_t) sink.used;
    return 0;
}

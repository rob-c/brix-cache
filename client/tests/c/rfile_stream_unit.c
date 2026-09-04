/* Public resilient-file stream helpers: success, failure and bounded-input tests. */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "brix.h"
#include "brix_ops.h"

static const uint8_t sample[] = "0123456789abcdef";
static int fail_at = -1;
static int64_t advertised_size = (int64_t) sizeof(sample) - 1;

ssize_t
brix_rfile_pread(brix_rfile *rf, int64_t off, void *buf, size_t len,
                 brix_status *st)
{
    size_t available;

    (void) rf;
    if (fail_at >= 0 && off >= fail_at) {
        brix_status_set(st, XRDC_ESOCK, ECONNRESET, "injected read failure");
        return -1;
    }
    if (off >= advertised_size) {
        return 0;
    }
    available = (size_t) (advertised_size - off);
    if (len > available) {
        len = available;
    }
    memcpy(buf, sample + off, len);
    return (ssize_t) len;
}

int
brix_stat(brix_conn *c, const char *path, brix_statinfo *info, brix_status *st)
{
    (void) c;
    (void) path;
    (void) st;
    memset(info, 0, sizeof(*info));
    info->size = advertised_size;
    return 0;
}

int
brix_rfile_open_read(brix_conn *c, const char *path, const char *opaque,
                     int pgrw, int max_stall_ms, brix_rfile *rf,
                     brix_status *st)
{
    (void) c;
    (void) path;
    (void) opaque;
    (void) pgrw;
    (void) max_stall_ms;
    (void) rf;
    (void) st;
    return 0;
}

int
brix_rfile_close(brix_rfile *rf, brix_status *st)
{
    (void) rf;
    (void) st;
    return 0;
}

typedef struct {
    uint8_t data[64];
    size_t  used;
    int     stop_after_first;
} capture_t;

static int
capture(const uint8_t *data, size_t len, int64_t offset, void *arg,
        brix_status *st)
{
    capture_t *out = arg;

    (void) offset;
    (void) st;
    memcpy(out->data + out->used, data, len);
    out->used += len;
    return out->stop_after_first ? 1 : 0;
}

static void
test_pump_success_limit_and_stop(void)
{
    brix_rfile file = {0};
    brix_status st = {0};
    capture_t out = {0};
    int64_t moved = -1;

    assert(brix_rfile_pump(&file, 2, 7, 3, capture, &out, &moved, &st) == 0);
    assert(moved == 7 && out.used == 7);
    assert(memcmp(out.data, "2345678", 7) == 0);

    memset(&out, 0, sizeof(out));
    out.stop_after_first = 1;
    assert(brix_rfile_pump(&file, 0, -1, 4, capture, &out, &moved, &st) == 0);
    assert(moved == 4 && out.used == 4);
}

static void
test_pump_failure_and_invalid_input(void)
{
    brix_rfile file = {0};
    brix_status st = {0};
    capture_t out = {0};
    int64_t moved = -1;

    fail_at = 4;
    assert(brix_rfile_pump(&file, 0, -1, 4, capture, &out, &moved, &st) == -1);
    assert(moved == 4 && st.sys_errno == ECONNRESET);
    fail_at = -1;
    brix_status_clear(&st);
    assert(brix_rfile_pump(NULL, 0, -1, 4, capture, &out, &moved, &st) == -1);
    assert(st.kxr == XRDC_EUSAGE);
}

static void
test_fd_drain(void)
{
    brix_rfile file = {0};
    brix_status st = {0};
    uint8_t data[16] = {0};
    int fds[2];
    int64_t moved = 0;

    assert(pipe(fds) == 0);
    assert(brix_rfile_drain_to_fd(&file, 1, 5, 2, fds[1], &moved, &st) == 0);
    close(fds[1]);
    assert(read(fds[0], data, sizeof(data)) == 5);
    close(fds[0]);
    assert(moved == 5 && memcmp(data, "12345", 5) == 0);
    assert(brix_rfile_drain_to_fd(&file, 0, 1, 1, -1, NULL, &st) == -1);
}

static void
test_slurp_and_size_cap(void)
{
    brix_conn conn = {0};
    brix_status st = {0};
    uint8_t *data = NULL;
    int64_t len = -1;

    assert(brix_rfile_slurp(&conn, "/sample", NULL, 16, &data, &len, &st) == 0);
    assert(len == 16 && memcmp(data, sample, 16) == 0);
    free(data);
    data = NULL;
    assert(brix_rfile_slurp(&conn, "/sample", NULL, 15, &data, &len, &st) == -1);
    assert(data == NULL && len == 0 && st.sys_errno == EFBIG);
}

int
main(void)
{
    test_pump_success_limit_and_stop();
    test_pump_failure_and_invalid_input();
    test_fd_drain();
    test_slurp_and_size_cap();
    puts("rfile_stream_unit: ALL PASS");
    return 0;
}

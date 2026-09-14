"""Real C queue preparation and pure Windows argument serialization."""

import subprocess

import pytest

from test_platform_linux_native import native_compile  # noqa: F401


@pytest.fixture(scope="module")
def queue_binary(native_compile):
    """Use real liburing SQE preparation with memory-owned queue storage."""
    return native_compile("queue-prepare", r'''
#include <assert.h>
#include "platform/linux/aio_wrapper.c"
static void completed(int fd, ssize_t result, void *state) {
    assert(fd == 17);
    assert(result == 4);
    *(int *)state += 1;
}
static void check_request(struct io_uring_sqe *sqe, int opcode, char *buffer) {
    assert(sqe->opcode == opcode);
    assert(sqe->fd == 17 && sqe->len == 4 && sqe->off == 12);
    assert(sqe->addr == (uintptr_t)buffer);
    struct io_uring_cqe completion = {0};
    completion.user_data = sqe->user_data;
    completion.res = 4;
    brix_aio_io_uring_callback(&completion);
}
int main(int argc, char **argv) {
    assert(argc == 2);
    struct brix_aio_ctx ctx = {0};
    struct io_uring_sqe entries[2] = {0};
    unsigned int head = 0;
    char buffer[4] = "abc";
    int callbacks = 0;
    ctx.ring.sq.khead = &head;
    ctx.ring.sq.sqes = entries;
    ctx.ring.sq.ring_entries = 2;
    ctx.ring.sq.ring_mask = 1;
    if (strcmp(argv[1], "success") == 0) {
        assert(brix_aio_read(&ctx, 17, buffer, 4, 12, completed, &callbacks) == 0);
        assert(brix_aio_write(&ctx, 17, buffer, 4, 12, completed, &callbacks) == 0);
        assert(ctx.pending_ops == 2 && ctx.ring.sq.sqe_tail == 2);
        check_request(&entries[0], IORING_OP_READ, buffer);
        check_request(&entries[1], IORING_OP_WRITE, buffer);
        assert(callbacks == 2);
    } else if (strcmp(argv[1], "full") == 0) {
        ctx.ring.sq.sqe_tail = 2;
        assert(brix_aio_read(&ctx, 17, buffer, 4, 12, completed, &callbacks) == -1);
        assert(errno == EAGAIN && ctx.pending_ops == 0);
        assert(brix_aio_write(&ctx, 17, buffer, 4, 12, completed, &callbacks) == -1);
        assert(errno == EAGAIN && ctx.ring.sq.sqe_tail == 2);
    } else {
        assert(brix_aio_read(NULL, 17, buffer, 4, 12, completed, &callbacks) == -1);
        assert(errno == EINVAL);
        assert(brix_aio_write(&ctx, 17, NULL, 4, 12, completed, &callbacks) == -1);
        assert(errno == EINVAL);
        assert(brix_aio_read(&ctx, 17, buffer, 4, 12, NULL, &callbacks) == -1);
        assert(errno == EINVAL && ctx.ring.sq.sqe_tail == 0 && ctx.pending_ops == 0);
    }
    return 0;
}
''', extra=["-luring"])


@pytest.mark.parametrize("case", ["success", "full", "invalid"])
def test_native_queue_preparation(queue_binary, case):
    subprocess.run([str(queue_binary), case], check=True, timeout=10)


@pytest.fixture(scope="module")
def arguments_binary(native_compile):
    """Compile the actual pure serializer without any Windows API emulation."""
    return native_compile("windows-arguments", r'''
#include <assert.h>
#include <errno.h>
#include <string.h>
#include "platform/windows/process_internal.h"
int main(int argc, char **argv) {
    assert(argc == 2);
    char output[128];
    if (strcmp(argv[1], "success") == 0) {
        assert(brix_win32_escape_argument("plain", output, sizeof(output)) == 0);
        assert(strcmp(output, "plain") == 0);
        assert(brix_win32_escape_argument("two words", output, sizeof(output)) == 0);
        assert(strcmp(output, "\"two words\"") == 0);
        char *args[] = {"app", "two words", NULL};
        assert(brix_win32_build_command_line(args, output, sizeof(output)) == 0);
        assert(strcmp(output, "app \"two words\"") == 0);
    } else if (strcmp(argv[1], "invalid") == 0) {
        assert(brix_win32_escape_argument(NULL, output, sizeof(output)) == -1);
        assert(errno == EINVAL);
        assert(brix_win32_escape_argument("x", NULL, sizeof(output)) == -1);
        assert(errno == EINVAL);
        assert(brix_win32_build_command_line(NULL, output, sizeof(output)) == -1);
        assert(errno == EINVAL);
    } else {
        char storage[8];
        memset(storage, 'X', sizeof(storage));
        assert(brix_win32_escape_argument("\"", storage, 3) == -1);
        assert(errno == ENOSPC && storage[3] == 'X');
        assert(brix_win32_escape_argument("a\\\"b", output, sizeof(output)) == 0);
        assert(strcmp(output, "\"a\\\\\\\"b\"") == 0);
        assert(brix_win32_escape_argument("path\\", output, sizeof(output)) == 0);
        assert(strcmp(output, "\"path\\\\\"") == 0);
    }
    return 0;
}
''', sources=["src/platform/windows/process_args.c"])


@pytest.mark.parametrize("case", ["success", "invalid", "bounds-and-quotes"])
def test_native_windows_argument_serialization(arguments_binary, case):
    subprocess.run([str(arguments_binary), case], check=True, timeout=10)

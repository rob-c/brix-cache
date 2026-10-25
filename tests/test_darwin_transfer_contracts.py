"""Run actual Darwin PAL bodies against controlled sendfile syscall outcomes."""

from pathlib import Path
import re
import subprocess

import pytest


@pytest.fixture(scope="module")
def transfer_pal(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    source = (root / "src/platform/darwin/posix_wrapper.c").read_text()
    bodies = []
    for result, name in (("ssize_t", "sendfile"), ("int", "eventfd")):
        match = re.search(result + r'\nbrix_plat_' + name + r'\([^{}]+\n\{.*?\n\}', source, re.S)
        assert match
        bodies.append(match[0])
    directory = tmp_path_factory.mktemp("darwin-transfer-pal")
    program = directory / "transfer.c"
    program.write_text(_SYSCALLS + "\n".join(bodies) + _CHECKS)
    binary = directory / "transfer"
    compiled = subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                               str(program), "-o", str(binary)],
                              capture_output=True, text=True, timeout=30)
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    return binary


@pytest.mark.parametrize("case", ["bounded", "zero", "partial", "error", "huge",
                                  "invalid", "eventfd", "eventfd-initial", "eventfd-flags"])
def test_darwin_transfer_and_notification_refusals(transfer_pal, case):
    subprocess.run([str(transfer_pal), case], check=True, timeout=5)


_SYSCALLS = r'''
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#ifndef SSIZE_MAX
#define SSIZE_MAX ((ssize_t)(SIZE_MAX >> 1))
#endif
static off_t requested, completed;
static int failure, calls;
static int sendfile(int input, int output, off_t offset, off_t *length,
                    void *headers, int flags) {
    assert(input == 1 && output == 2 && offset == 7);
    assert(headers == NULL && flags == 0);
    requested = *length;
    *length = completed;
    calls++;
    if (failure) { errno = failure; return -1; }
    return 0;
}
'''

_CHECKS = r'''
int main(int argc, char **argv) {
    off_t offset = 7;
    size_t count = 4;
    assert(argc == 2);
    if (strncmp(argv[1], "eventfd", 7) == 0) {
        unsigned initial = strcmp(argv[1], "eventfd-initial") == 0 ? 5 : 0;
        int flags = strcmp(argv[1], "eventfd-flags") == 0 ? 06000 : 0;
        assert(brix_plat_eventfd(initial, flags) == -1 && errno == ENOTSUP);
        assert(calls == 0);
        return 0;
    }
    completed = 4;
    if (strcmp(argv[1], "partial") == 0) { completed = 2; failure = EAGAIN; }
    if (strcmp(argv[1], "error") == 0) { completed = 0; failure = EBADF; }
    if (strcmp(argv[1], "zero") == 0) { count = 0; completed = 0; }
    if (strcmp(argv[1], "huge") == 0) { count = SIZE_MAX; completed = 1; }
    if (strcmp(argv[1], "invalid") == 0) {
        assert(brix_plat_sendfile(2, 1, NULL, count) == -1 && errno == EINVAL);
        offset = -1;
        assert(brix_plat_sendfile(2, 1, &offset, count) == -1 && errno == EINVAL);
        assert(calls == 0);
        return 0;
    }
    ssize_t result = brix_plat_sendfile(2, 1, &offset, count);
    if (failure == EBADF) {
        assert(result == -1 && errno == EBADF && offset == 7);
        return 0;
    }
    assert(result == completed && offset == 7 + completed);
    assert(calls == (count != 0));
    if (count) assert(requested == (count > (size_t)SSIZE_MAX ? SSIZE_MAX : (off_t)count));
    return 0;
}
'''

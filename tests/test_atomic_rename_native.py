"""Exercise current rename primitives on owned files, without a broker/fleet.

Production function bodies are extracted unchanged. The Apple preprocessor arm
is compiled against a Linux test adapter; this is not native Darwin validation.
"""

from pathlib import Path
import subprocess

import pytest

from csource_scan import function_body
from test_platform_linux_native import native_compile


def _functions():
    root = Path(__file__).resolve().parents[1] / "src"
    broker = (root / "auth/impersonate/broker_ops.c").read_text()
    beneath = (root / "fs/path/beneath.c").read_text()
    pieces = [
        "int imp_do_exchange(int sfd, const char *sbase, int dfd, const char *dbase)"
        + function_body(broker, "imp_do_exchange"),
        "int imp_do_rename(int sfd, const char *sbase, int dfd, const char *dbase, int noreplace)"
        + function_body(broker, "imp_do_rename"),
        "int brix_renameat_noreplace_fallback(ngx_log_t *log, int sfd, const char *sbase, int dfd, const char *dbase)"
        + function_body(beneath, "brix_renameat_noreplace_fallback"),
    ]
    start = beneath.index("typedef enum {", beneath.index("brix_renameat_noreplace_fallback("))
    end = beneath.index("} beneath_two_path_op_t;", start) + len("} beneath_two_path_op_t;")
    pieces.append(beneath[start:end])
    pieces.append("static int beneath_imp_two_path(beneath_two_path_op_t op, const char *src, const char *dst) { (void)op; (void)src; (void)dst; abort(); }")
    pieces.append("static int beneath_two_path(beneath_two_path_op_t op, int rootfd, const char *src, const char *dst)"
                  + function_body(beneath, "beneath_two_path"))
    return "\n".join(pieces)


_ADAPTER = r'''
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
typedef int ngx_log_t;
struct test_cycle { ngx_log_t *log; };
static struct test_cycle cycle = { NULL };
#define ngx_cycle (&cycle)
#define NGX_LOG_WARN 1
#define ngx_log_error(level, log, err, ...) ((void)(log))
static int noreplace_degraded, noreplace_warned;
static int forced_errno, rename_calls, syscall_calls;
long __real_syscall(long number, ...);
int __real_renameat(int sfd, const char *src, int dfd, const char *dst);
long __wrap_syscall(long number, ...) {
    va_list ap;
    va_start(ap, number);
    int sfd = va_arg(ap, int);
    const char *src = va_arg(ap, const char *);
    int dfd = va_arg(ap, int);
    const char *dst = va_arg(ap, const char *);
    unsigned int flags = va_arg(ap, unsigned int);
    va_end(ap);
    assert(number == SYS_renameat2);
    syscall_calls++;
    if (forced_errno) { errno = forced_errno; return -1; }
    return __real_syscall(number, sfd, src, dfd, dst, flags);
}
int __wrap_renameat(int sfd, const char *src, int dfd, const char *dst) {
    rename_calls++;
    return __real_renameat(sfd, src, dfd, dst);
}
static int brix_imp_client_active(void) { return 0; }
static int beneath_open_parent(int rootfd, const char *path, char *buffer,
    size_t size, const char **base) {
    (void)buffer; (void)size;
    assert(strcmp(path, "source") == 0 || strcmp(path, "destination") == 0);
    *base = path;
    return dup(rootfd);
}
static void beneath_close_parent(int fd, int rootfd) {
    (void)rootfd;
    int saved = errno;
    assert(close(fd) == 0);
    errno = saved;
}
'''


_MAIN = r'''
int main(int argc, char **argv) {
    assert(argc == 4);
    int rootfd = open(argv[3], O_RDONLY | O_DIRECTORY);
    assert(rootfd >= 0);
    int exchange = strstr(argv[1], "exchange") != NULL;
    int success = strcmp(argv[2], "success") == 0;
    int fallback = strcmp(argv[2], "fallback") == 0;
    if (strcmp(argv[2], "unsupported") == 0 || fallback) { forced_errno = ENOSYS; }
    if (strcmp(argv[2], "denied") == 0) { forced_errno = EACCES; }
    if (success && !exchange) { assert(unlinkat(rootfd, "destination", 0) == 0); }
    int rc;
    if (strcmp(argv[1], "broker-exchange") == 0) {
        rc = imp_do_exchange(rootfd, "source", rootfd, "destination");
    } else if (strcmp(argv[1], "broker-noreplace") == 0) {
        rc = imp_do_rename(rootfd, "source", rootfd, "destination", 1);
    } else {
        rc = beneath_two_path(exchange ? BENEATH_2P_EXCHANGE : BENEATH_2P_RENAME_EXCL,
                              rootfd, "source", "destination");
    }
#if TEST_APPLE
    assert(rc == -1 && errno == ENOTSUP);
    assert(rename_calls == 0 && syscall_calls == 0);
#else
    assert(syscall_calls == 1);
    if (success || fallback) {
        assert(rc == 0);
        assert(rename_calls == fallback);
    } else {
        int expected = forced_errno == ENOSYS ? ENOTSUP : forced_errno;
        if (expected == 0) { expected = EEXIST; }
        assert(rc == -1 && errno == expected && rename_calls == 0);
    }
#endif
    assert(close(rootfd) == 0);
    return 0;
}
'''


@pytest.fixture(scope="module")
def rename_binaries(native_compile):
    functions = _functions()
    binaries = {}
    for arm in ("linux", "apple"):
        defines = "\n#define TEST_APPLE 0\n"
        if arm == "apple":
            defines = "\n#define TEST_APPLE 1\n#define __APPLE__ 1\n#define __MACH__ 1\n"
        binaries[arm] = native_compile(
            "atomic-rename-" + arm, _ADAPTER + defines + functions + _MAIN,
            extra=("-Wl,--wrap=syscall", "-Wl,--wrap=renameat", "-Wno-unused-variable"))
    return binaries


@pytest.mark.parametrize("arm,api,mode", [
    *(('linux', api, mode) for api in ('broker-exchange', 'beneath-exchange')
      for mode in ('success', 'unsupported', 'denied')),
    *(('linux', api, mode) for api in ('broker-noreplace', 'beneath-noreplace')
      for mode in ('success', 'exists', 'fallback')),
    *(('apple', api, 'unsupported') for api in ('broker-exchange', 'beneath-exchange',
                                             'broker-noreplace', 'beneath-noreplace')),
])
def test_atomic_rename_contract(rename_binaries, tmp_path, arm, api, mode):
    source, destination = tmp_path / "source", tmp_path / "destination"
    source.write_text("alpha")
    destination.write_text("beta")
    result = subprocess.run([str(rename_binaries[arm]), api, mode, str(tmp_path)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    if arm == "linux" and mode == "success" and api.endswith("exchange"):
        assert source.read_text() == "beta" and destination.read_text() == "alpha"
    elif arm == "linux" and mode in ("success", "fallback"):
        assert not source.exists() and destination.read_text() == "alpha"
    else:
        assert source.read_text() == "alpha" and destination.read_text() == "beta"

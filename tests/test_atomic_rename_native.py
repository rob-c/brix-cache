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



# The PAL seam the pasted bodies now call (INVARIANT 14).  They used to issue
# syscall(SYS_renameat2, ...) inline; brix_plat_renameat2() took that over, so
# this harness — which stubs the whole environment (ngx_log_t, __wrap_syscall,
# beneath_open_parent, ...) rather than linking production objects — has to
# provide it too.  Linking the real src/platform/linux/path_wrapper.c is not an
# option here: the SAME bodies are compiled a second time with __APPLE__ set, to
# check the Darwin arm in one run.  Mirrors the contract in platform_api_posix.h:
# one BRIX_RENAME_* flag, ENOSYS/EINVAL reported as ENOTSUP so the caller can
# pick its degraded path.  Routing through syscall() keeps __wrap_syscall's
# forced_errno / syscall_calls bookkeeping intact.
_PAL_STUB = r'''
#define BRIX_RENAME_NOREPLACE  1
#define BRIX_RENAME_EXCHANGE   2
#if TEST_APPLE
/* Darwin uses renameatx_np, which this Linux harness cannot issue; the arm
   exists to prove the CALLER handles a platform that refuses the flag. */
static int brix_plat_renameat2(int sfd, const char *sbase, int dfd,
    const char *dbase, unsigned int flags) {
    (void)sfd; (void)sbase; (void)dfd; (void)dbase; (void)flags;
    errno = ENOTSUP;
    return -1;
}
#else
static int brix_plat_renameat2(int sfd, const char *sbase, int dfd,
    const char *dbase, unsigned int flags) {
    unsigned int kflags = 0;
    if (flags & BRIX_RENAME_NOREPLACE) { kflags |= 1u; }   /* RENAME_NOREPLACE */
    if (flags & BRIX_RENAME_EXCHANGE)  { kflags |= 2u; }   /* RENAME_EXCHANGE  */
    if (syscall(SYS_renameat2, sfd, sbase, dfd, dbase, kflags) == 0) {
        return 0;
    }
    if (errno == ENOSYS || errno == EINVAL) {
        errno = ENOTSUP;
    }
    return -1;
}
#endif
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
    /* Darwin refuses the flag (ENOTSUP) and never reaches the linux syscall.
       From there the two APIs diverge, and asserting one contract for both was
       wrong: imp_do_exchange has NO degraded path and must surface ENOTSUP,
       while the noreplace pair deliberately falls back to plain renameat() --
       the same behaviour the linux "fallback" mode below pins. */
    assert(syscall_calls == 0);
    if (exchange) {
        assert(rc == -1 && errno == ENOTSUP);
        assert(rename_calls == 0);
    } else {
        assert(rc == 0);
        assert(rename_calls == 1);
    }
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
            "atomic-rename-" + arm, _ADAPTER + defines + _PAL_STUB + functions + _MAIN,
            extra=("-Wl,--wrap=syscall", "-Wl,--wrap=renameat", "-Wno-unused-variable"))
    return binaries


def _expected_outcome(arm, api, mode):
    """Which post-state this (arm, api, mode) cell must leave behind.

    "swapped"   both names traded contents (a successful exchange)
    "moved"     the rename happened: a plain success, or the documented
                degrade of the noreplace pair to bare renameat() when the
                platform refuses the flag — the linux "fallback" mode, and
                EVERY apple noreplace cell, since Darwin always refuses here
    "unchanged" the call failed and left both names alone
    """
    if arm == "linux" and mode == "success":
        return "swapped" if api.endswith("exchange") else "moved"
    if mode == "fallback" or (arm == "apple" and api.endswith("noreplace")):
        return "moved"
    return "unchanged"


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
    if _expected_outcome(arm, api, mode) == "swapped":
        assert source.read_text() == "beta" and destination.read_text() == "alpha"
    elif _expected_outcome(arm, api, mode) == "moved":
        assert not source.exists() and destination.read_text() == "alpha"
    else:
        assert source.read_text() == "alpha" and destination.read_text() == "beta"

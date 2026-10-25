"""Actual FRM exchange/path bodies on owned files; no HSM, broker or fleet.

The unsupported branches are compiled against a Linux test adapter. This does
not establish native Darwin compatibility.
"""

from pathlib import Path
import errno
import subprocess
import sys

import pytest

from csource_scan import function_body
from test_platform_linux_native import native_compile

pytestmark = pytest.mark.skipif(sys.platform != "linux",
                                reason="Linux renameat2 syscall-interposition adapter")


# The PAL seam sd_frm_exec.c now calls (INVARIANT 14).  It used to carry its own
# "#ifndef RENAME_EXCHANGE" compat block, which this fixture spliced in; that
# block moved into brix_plat_renameat2(), so there is nothing left to splice and
# the harness must supply the seam itself.  Mirrors platform_api_posix.h: the
# flag is translated to the kernel bit, and a platform that cannot issue the
# call answers ENOTSUP WITHOUT a syscall -- which is exactly what the 'darwin'
# and 'no-syscall' arms assert.
_PAL_STUB = r'''
#define BRIX_RENAME_NOREPLACE  1
#define BRIX_RENAME_EXCHANGE   2
static int brix_plat_renameat2(int sfd, const char *sbase, int dfd,
    const char *dbase, unsigned int flags) {
#if defined(__APPLE__) || !defined(SYS_renameat2)
    (void)sfd; (void)sbase; (void)dfd; (void)dbase; (void)flags;
    errno = ENOTSUP;
    return -1;
#else
    unsigned int kflags = 0;
    if (flags & BRIX_RENAME_NOREPLACE) { kflags |= 1u; }
    if (flags & BRIX_RENAME_EXCHANGE)  { kflags |= 2u; }
    if (syscall(SYS_renameat2, sfd, sbase, dfd, dbase, kflags) == 0) {
        return 0;
    }
    if (errno == ENOSYS || errno == EINVAL) {
        errno = ENOTSUP;
    }
    return -1;
#endif
}
'''


_ADAPTER = r'''
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "fs/backend/frm/sd_frm_mss.h"
static int injected_errno;
static int syscall_count;
long __real_syscall(long number, ...);
long __wrap_syscall(long number, ...) {
    va_list args;
    va_start(args, number);
    int source_dir = va_arg(args, int);
    const char *source = va_arg(args, const char *);
    int destination_dir = va_arg(args, int);
    const char *destination = va_arg(args, const char *);
    unsigned int flags = va_arg(args, unsigned int);
    va_end(args);
    assert(number == SYS_renameat2 && flags == (1u << 1));
    syscall_count++;
    if (injected_errno != 0) {
        errno = injected_errno;
        return -1;
    }
    return __real_syscall(number, source_dir, source, destination_dir, destination, flags);
}
int __wrap_rename(const char *source, const char *destination) {
    (void)source; (void)destination;
    assert(!"an atomic exchange must never invoke plain rename");
    return -1;
}
'''

_MAIN = r'''
int main(int argc, char **argv) {
    assert(argc == 4);
    frm_mss_head_t head = { 0 };
    assert(strlen(argv[1]) < sizeof(head.base));
    strcpy(head.base, argv[1]);
    injected_errno = atoi(argv[2]);
    int expected = atoi(argv[3]);
    char long_key[PATH_MAX + 1];
    memset(long_key, 'x', sizeof(long_key) - 1);
    long_key[sizeof(long_key) - 1] = '\0';
    const char *destination = expected == ENAMETOOLONG ? long_key : "destination";
    errno = 0;
    int result = frm_mss_exchange(&head, "source", destination);
    if (expected == 0) {
        assert(result == 0 && syscall_count == 1);
    } else {
        assert(result == -1 && errno == expected);
        assert(syscall_count == (injected_errno != 0));
    }
    return 0;
}
'''


@pytest.fixture(scope='module')
def frm_exchange_binaries(native_compile):
    root = Path(__file__).resolve().parents[1] / 'src/fs/backend/frm'
    source = (root / 'sd_frm_exec.c').read_text()
    paths = (root / 'sd_frm_mss_ops.c').read_text()
    bodies = ('int frm_online_path(const char *base, const char *key, char *out, size_t cap)'
              + function_body(paths, 'frm_online_path') + '\n'
              + _PAL_STUB + '\n'
              + 'int frm_mss_exchange(void *mss, const char *a, const char *b)'
              + function_body(source, 'frm_mss_exchange'))
    switches = {'linux': '', 'darwin': '#undef __linux__\n#define __APPLE__ 1\n#define __MACH__ 1\n',
                'no-syscall': '#undef SYS_renameat2\n'}
    return {arm: native_compile('frm-exchange-' + arm, _ADAPTER + switch + bodies + _MAIN,
                                extra=('-Wl,--wrap=syscall', '-Wl,--wrap=rename'))
            for arm, switch in switches.items()}


@pytest.mark.parametrize('arm,error,expected', [
    ('linux', 0, 0),
    ('linux', errno.EACCES, errno.EACCES),
    ('linux', errno.ENOSYS, errno.ENOTSUP),
    ('linux', errno.EINVAL, errno.ENOTSUP),
    ('linux', 0, errno.ENAMETOOLONG),
    ('darwin', 0, errno.ENOTSUP),
    ('no-syscall', 0, errno.ENOTSUP),
])
def test_frm_exchange_contract(frm_exchange_binaries, tmp_path, arm, error, expected):
    online = tmp_path / '.online'
    online.mkdir()
    source, destination = online / 'source', online / 'destination'
    source.write_bytes(b'alpha')
    destination.write_bytes(b'beta')
    result = subprocess.run([str(frm_exchange_binaries[arm]), str(tmp_path), str(error), str(expected)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    actual = (source.read_bytes(), destination.read_bytes())
    assert actual == ((b'beta', b'alpha') if expected == 0 else (b'alpha', b'beta'))

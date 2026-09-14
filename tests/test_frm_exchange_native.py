"""Actual FRM exchange/path bodies on owned files; no HSM, broker or fleet.

The unsupported branches are compiled against a Linux test adapter. This does
not establish native Darwin compatibility.
"""

from pathlib import Path
import errno
import subprocess

import pytest

from csource_scan import function_body
from test_platform_linux_native import native_compile


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
    macro_start = source.index('#ifndef RENAME_EXCHANGE')
    macro_end = source.index('#endif', macro_start) + len('#endif')
    bodies = ('int frm_online_path(const char *base, const char *key, char *out, size_t cap)'
              + function_body(paths, 'frm_online_path') + '\n'
              + source[macro_start:macro_end] + '\n'
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

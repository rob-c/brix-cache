"""Process PAL fallbacks close descriptors and preserve exact identity bounds."""

import errno
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def pal_process(server_native_compile):
    names = ('syscall', 'opendir', 'sysconf', 'readlink', 'open64', 'read')
    return server_native_compile('pal-process', 'tests/c/pal_process_native_test.c',
                                 ['-Wl,--wrap=' + name for name in names])


def invoke(binary, operation, mode='normal', capacity=4096, expected=0):
    result = subprocess.run([str(binary), operation, mode, str(capacity), str(expected)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('mode', ['native', 'procfs', 'loop', 'loop-default'])
def test_closefrom_preserves_low_fds_and_closes_every_high_fd(pal_process, mode):
    invoke(pal_process, 'closefrom', mode)


@pytest.mark.parametrize('mode', ['normal', 'invalid'])
def test_peer_identity_requires_a_valid_local_socket(pal_process, mode):
    invoke(pal_process, 'peer', mode)


@pytest.mark.parametrize('operation,capacity,error', [
    ('boot', 0, errno.ENAMETOOLONG), ('boot', 1, errno.ENAMETOOLONG),
    ('boot', 8, errno.ENAMETOOLONG), ('boot', 4096, 0),
    ('exe', 0, errno.ENAMETOOLONG), ('exe', 1, errno.EINVAL),
    ('exe', 8, errno.ENAMETOOLONG), ('exe', 4096, 0)])
def test_process_identity_rejects_truncated_values(pal_process, operation, capacity, error):
    # readlink rejects a zero-byte destination before a truncation can occur.
    invoke(pal_process, operation, capacity=capacity, expected=error)


@pytest.mark.parametrize('operation,mode,error', [('exe', 'readlink-error', errno.EACCES),
    ('boot', 'open-error', errno.EACCES), ('boot', 'read-error', errno.EIO),
    ('boot', 'empty', errno.ENODATA)])
def test_procfs_failure_cannot_return_a_partial_identity(pal_process, operation, mode, error):
    invoke(pal_process, operation, mode, expected=error)

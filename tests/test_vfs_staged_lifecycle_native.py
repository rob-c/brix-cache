"""Staged storage retains data, errno and handle ownership across failures."""

import errno
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def staged(server_native_compile):
    return server_native_compile('vfs-staged-lifecycle',
        'tests/c/vfs_staged_lifecycle_native_test.c',
        ['-Wl,--wrap=' + name for name in ('ngx_pcalloc', 'ngx_palloc',
            'brix_vfs_fd_reserve', 'brix_vfs_backend_durable')])


def invoke(binary, root, backend, mode, error=0, expected=0):
    result = subprocess.run([str(binary), str(root), backend, mode, str(error),
        str(expected)], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


@pytest.mark.parametrize('backend', ['posix', 'driver'])
def test_success_publishes_once_and_abort_is_idempotent(staged, tmp_path, backend):
    output = invoke(staged, tmp_path, backend, 'normal')
    if backend == 'driver':
        assert output == 'opens=1 writes=2 commits=1 aborts=0 barriers=1\n'
    else:
        assert (tmp_path / 'object').read_bytes() == b'abcdef'
        assert (tmp_path / 'object').stat().st_mode & 0o777 == 0o600
        assert len(list(tmp_path.iterdir())) == 1


@pytest.mark.parametrize('backend', ['posix', 'driver'])
@pytest.mark.parametrize('mode,expected', [('readonly', errno.EROFS),
    ('null-root', errno.EINVAL), ('unconfined', errno.EINVAL),
    ('allocation', errno.ENOMEM), ('clone', errno.ENOMEM)])
def test_refused_open_never_creates_storage(staged, tmp_path, backend, mode, expected):
    invoke(staged, tmp_path, backend, mode, expected=expected)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('error', [errno.ENOSPC, errno.EDQUOT, errno.EIO])
def test_reserve_failure_closes_and_removes_real_temporary_file(staged, tmp_path, error):
    invoke(staged, tmp_path, 'posix', 'reserve', error, error)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('mode,error,expected', [('long-key', 0, errno.ENAMETOOLONG),
    ('driver-open', errno.EACCES, errno.EACCES), ('short', 0, errno.EIO),
    ('driver-write', errno.ENOSPC, errno.ENOSPC),
    ('driver-commit', errno.EIO, errno.EIO), ('barrier', 0, errno.EIO),
    ('barrier', errno.EDQUOT, errno.EDQUOT)])
def test_backend_failures_preserve_errno_and_handle_ownership(staged, tmp_path,
                                                            mode, error, expected):
    invoke(staged, tmp_path, 'driver', mode, error, expected)


@pytest.mark.parametrize('backend', ['posix', 'driver'])
@pytest.mark.parametrize('mode,expected', [('readonly-write', errno.EROFS),
    ('readonly-commit', errno.EROFS), ('missing-path', errno.EINVAL)])
def test_refused_delayed_mutation_never_publishes(staged, tmp_path, backend, mode, expected):
    invoke(staged, tmp_path, backend, mode, expected=expected)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('mode', ['match-missing', 'match-mismatch'])
def test_failed_precondition_preserves_original_namespace(staged, tmp_path, mode):
    target = tmp_path / 'object'
    if mode == 'match-mismatch':
        target.write_bytes(b'old')
    invoke(staged, tmp_path, 'posix', mode, expected=errno.ECANCELED)
    if mode == 'match-mismatch':
        assert target.read_bytes() == b'old'
        assert list(tmp_path.iterdir()) == [target]
    else:
        assert list(tmp_path.iterdir()) == []

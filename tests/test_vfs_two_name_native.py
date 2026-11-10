"""Two-name mutations preserve policy, exact dispatch and durability outcomes."""

import errno
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def two_name(server_native_compile):
    return server_native_compile('vfs-two-name', 'tests/c/vfs_two_name_native_test.c',
        ['-Wl,--wrap=' + name for name in ('brix_vfs_backend_durable',
                                          'brix_publish_dirsync', 'brix_vfs_ns_cred')])


def invoke(binary, tmp_path, operation='rename', backend='driver', mode='normal',
           error=0, barrier=0, expected=0, overwrite=1):
    result = subprocess.run([str(binary), str(tmp_path), operation, backend, mode,
        str(error), str(barrier), str(expected), str(overwrite)],
        capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


@pytest.mark.parametrize('operation', ['rename', 'exchange'])
@pytest.mark.parametrize('backend', ['posix', 'driver'])
def test_two_name_success_preserves_content_and_dispatch(two_name, tmp_path, operation, backend):
    output = invoke(two_name, tmp_path, operation, backend)
    assert f'syncs={1 if operation == "rename" else 2}' in output
    if backend == 'posix':
        assert (tmp_path / 'destination').read_bytes() == b'source-bytes'
        if operation == 'exchange':
            assert (tmp_path / 'source').read_bytes() == b'destination-bytes'
        else:
            assert not (tmp_path / 'source').exists()


@pytest.mark.parametrize('operation', ['rename', 'exchange'])
@pytest.mark.parametrize('mode,expected', [('readonly', errno.EROFS),
    ('null-target', errno.EINVAL), ('null-root', errno.EINVAL),
    ('unconfined', errno.EINVAL), ('empty-target', errno.EINVAL),
    ('outside', errno.EINVAL), ('no-capability', errno.EPERM), ('no-operation', errno.ENOTSUP)])
def test_refused_entry_never_dispatches_mutation(two_name, tmp_path, operation, mode, expected):
    assert invoke(two_name, tmp_path, operation, mode=mode, expected=expected) == 'calls=0 syncs=0\n'


@pytest.mark.parametrize('operation', ['rename', 'exchange'])
def test_request_credentials_reach_both_name_driver(two_name, tmp_path, operation):
    invoke(two_name, tmp_path, operation, mode='credential')


@pytest.mark.parametrize('operation', ['rename', 'exchange'])
@pytest.mark.parametrize('error', [0, errno.EKEYEXPIRED])
def test_credential_refusal_never_uses_service_identity(two_name, tmp_path, operation, error):
    invoke(two_name, tmp_path, operation, mode='credential-error', error=error,
           expected=error or errno.EACCES)


@pytest.mark.parametrize('operation,barrier', [('rename', 1), ('exchange', 1), ('exchange', 2)])
@pytest.mark.parametrize('backend', ['posix', 'driver'])
@pytest.mark.parametrize('error', [0, errno.ENOSPC])
def test_failed_barrier_reports_failure_after_namespace_change(two_name, tmp_path,
                                                             operation, barrier, backend, error):
    invoke(two_name, tmp_path, operation, backend, error=error, barrier=barrier,
           expected=error or errno.EIO)
    if backend == 'posix':
        assert (tmp_path / 'destination').read_bytes() == b'source-bytes'


@pytest.mark.parametrize('operation', ['rename', 'exchange'])
def test_driver_error_preserves_errno_without_sync(two_name, tmp_path, operation):
    assert invoke(two_name, tmp_path, operation, mode='driver-error', error=errno.EXDEV,
                  expected=errno.EXDEV) == 'calls=1 syncs=0\n'


@pytest.mark.parametrize('overwrite', [0, 1])
@pytest.mark.parametrize('mode', ['normal', 'directory', 'stat-error', 'no-stat'])
def test_worker_adapter_retains_replace_and_directory_contract(two_name, tmp_path, overwrite, mode):
    invoke(two_name, tmp_path, 'worker', mode=mode, overwrite=overwrite)


@pytest.mark.parametrize('mode', ['bad-source', 'bad-target'])
def test_worker_invalid_names_stop_before_driver(two_name, tmp_path, mode):
    assert invoke(two_name, tmp_path, 'worker', mode=mode, expected=errno.EINVAL) == 'calls=0 syncs=0\n'

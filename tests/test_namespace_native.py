"""Real confined namespace operations preserve data and publish preconditions."""

import errno
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def namespace_binary(server_native_compile):
    return server_native_compile('namespace', 'tests/c/namespace_native_test.c',
        ['-Wl,--wrap=brix_unlink_beneath', '-Wl,--wrap=brix_copy_range'])


def execute(binary, tmp_path, family, mode, flag):
    root = tmp_path / 'root'
    root.mkdir()
    result = subprocess.run([str(binary), family, mode, str(flag), str(root)],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('recursive', [0, 1])
@pytest.mark.parametrize('mode', ['file', 'empty-dir', 'full-dir', 'missing',
                                'idempotent', 'require-dir', 'require-empty',
                                'symlink', 'outside'])
def test_delete_classification_and_confinement(namespace_binary, tmp_path, recursive, mode):
    execute(namespace_binary, tmp_path, 'delete', mode, recursive)


@pytest.mark.parametrize('staged', [0, 1])
@pytest.mark.parametrize('mode', ['copy', 'overwrite', 'no-overwrite', 'source-dir',
    'source-missing', 'destination-dir', 'parent-missing', 'outside',
    'absent', 'absent-existing', 'meta-match', 'meta-mismatch', 'meta-missing',
    'etag', 'bad-kind', 'io-error'])
def test_copy_publish_preconditions(namespace_binary, tmp_path, staged, mode):
    execute(namespace_binary, tmp_path, 'copy', mode, staged)


@pytest.mark.parametrize('error', [errno.EACCES, errno.EPERM, errno.EEXIST,
    errno.ENOTEMPTY, errno.ENAMETOOLONG, errno.ENOSPC, errno.EDQUOT,
    errno.EBUSY, errno.EINVAL, errno.EIO, errno.ELOOP, errno.EXDEV])
def test_delete_errno_disposition(namespace_binary, tmp_path, error):
    execute(namespace_binary, tmp_path, 'errno', 'unlink', error)

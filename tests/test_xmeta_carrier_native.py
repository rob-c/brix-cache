"""Metadata persistence preserves codec bytes and staged-object ownership."""

import errno
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def xmeta_carrier(server_native_compile):
    return server_native_compile('xmeta-carrier', 'tests/c/xmeta_carrier_native_test.c',
                                 ['-Wl,--wrap=malloc', '-Wl,--wrap=realloc'])


def invoke(binary, operation='save', carrier='sidecar', mode='normal', error=0, rc=0, expected=0):
    result = subprocess.run([str(binary), operation, carrier, mode, str(error), str(rc), str(expected)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('operation', ['save', 'load'])
@pytest.mark.parametrize('carrier', ['sidecar', 'xattr'])
def test_each_carrier_preserves_complete_metadata(xmeta_carrier, operation, carrier):
    invoke(xmeta_carrier, operation, carrier)


@pytest.mark.parametrize('error', [errno.ENOTSUP, errno.E2BIG, errno.ERANGE, errno.ENOSPC])
@pytest.mark.parametrize('operation', ['save', 'load'])
def test_only_representation_errors_select_sidecar_fallback(xmeta_carrier, error, operation):
    invoke(xmeta_carrier, operation, 'xattr', error=error)


@pytest.mark.parametrize('error', [errno.EINVAL, errno.EACCES, errno.EIO])
@pytest.mark.parametrize('operation', ['save', 'load'])
def test_hard_xattr_errors_cannot_be_hidden_by_fallback(xmeta_carrier, error, operation):
    invoke(xmeta_carrier, operation, 'xattr', error=error, rc=-1, expected=error)


@pytest.mark.parametrize('mode', ['open', 'write', 'commit'])
@pytest.mark.parametrize('error', [0, errno.ENOSPC])
def test_failed_sidecar_publication_aborts_and_preserves_errno(xmeta_carrier, mode, error):
    invoke(xmeta_carrier, mode=mode, error=error, rc=-1, expected=error or errno.EIO)


@pytest.mark.parametrize('operation,mode', [('save', 'no-open'), ('save', 'no-write'),
    ('save', 'no-commit'), ('load', 'no-open'), ('load', 'no-read')])
def test_missing_required_driver_slot_is_explicit(xmeta_carrier, operation, mode):
    invoke(xmeta_carrier, operation, mode=mode, rc=-1, expected=errno.ENOTSUP)


@pytest.mark.parametrize('operation', ['save', 'load'])
@pytest.mark.parametrize('mode,error', [('long-key', errno.ENAMETOOLONG), ('null-store', errno.EINVAL)])
def test_invalid_context_or_oversized_key_never_reaches_storage(xmeta_carrier, operation, mode, error):
    invoke(xmeta_carrier, operation, mode=mode, rc=-1, expected=error)


@pytest.mark.parametrize('mode,error,rc,expected', [('partial', 0, 0, 0),
    ('empty', 0, -5, 0), ('read', 0, -1, errno.EIO), ('read', errno.EACCES, -1, errno.EACCES),
    ('open', errno.ENOENT, -5, 0), ('open', errno.EACCES, -1, errno.EACCES),
    ('realloc', 0, -1, errno.ENOMEM)])
def test_sidecar_read_owns_and_closes_its_buffer(xmeta_carrier, mode, error, rc, expected):
    invoke(xmeta_carrier, 'load', mode=mode, error=error, rc=rc, expected=expected)


def test_xattr_buffer_allocation_failure_returns_no_metadata(xmeta_carrier):
    invoke(xmeta_carrier, 'load', 'xattr', 'malloc', rc=-1, expected=errno.ENOMEM)

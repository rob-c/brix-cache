"""Metadata writes preserve credential scope, recursive mkdir and policy precedence."""

import errno
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def metadata(server_native_compile):
    return server_native_compile('vfs-metadata', 'tests/c/vfs_metadata_native_test.c',
        ['-Wl,--wrap=brix_vfs_ns_cred', '-Wl,--wrap=brix_vfs_backend_resolve'])


def invoke(binary, tmp_path, operation, mode='normal', error=0, parents=0,
           expected=0, credential=0):
    result = subprocess.run([str(binary), str(tmp_path), operation, mode, str(error),
        str(parents), str(expected), str(credential)], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


def report_fields(output):
    """Decode the native fixture's independent dispatch counters."""
    return dict(item.split('=') for item in output.split())


@pytest.mark.parametrize('operation', ['mkdir', 'chmod', 'setattr'])
@pytest.mark.parametrize('credential', [0, 1])
def test_metadata_mutation_dispatches_exact_key_and_attributes(metadata, tmp_path, operation, credential):
    fields = report_fields(invoke(metadata, tmp_path, operation, credential=credential))
    assert fields['calls'] == '1' and fields['stats'] == '0'
    assert (int(fields['credentials']) > 0) == bool(credential)


@pytest.mark.parametrize('operation', ['mkdir', 'chmod', 'setattr'])
@pytest.mark.parametrize('mode,expected', [('readonly', errno.EROFS),
    ('null-root', errno.EINVAL), ('unconfined', errno.EINVAL),
    ('empty-path', errno.EINVAL), ('null-context', errno.EINVAL),
    ('long-path', errno.ENAMETOOLONG)])
def test_invalid_or_readonly_metadata_never_reaches_driver(metadata, tmp_path, operation, mode, expected):
    output = invoke(metadata, tmp_path, operation, mode, expected=expected, credential=1)
    assert output.startswith('calls=0 ')


@pytest.mark.parametrize('operation', ['mkdir', 'chmod', 'setattr'])
@pytest.mark.parametrize('error', [0, errno.EKEYEXPIRED])
def test_credential_refusal_prevents_service_identity_fallback(metadata, tmp_path, operation, error):
    invoke(metadata, tmp_path, operation, 'credential-error', error=error,
           expected=error or errno.EACCES, credential=1)


@pytest.mark.parametrize('operation', ['mkdir', 'chmod', 'setattr'])
@pytest.mark.parametrize('credential', [0, 1])
def test_backend_errno_is_preserved(metadata, tmp_path, operation, credential):
    invoke(metadata, tmp_path, operation, 'driver-error', error=errno.ENOSPC,
           expected=errno.ENOSPC, credential=credential)


@pytest.mark.parametrize('credential', [0, 1])
@pytest.mark.parametrize('mode,expected,error,calls,stats', [
    ('normal', 0, 0, 2, 0), ('exists-dir', 0, errno.EEXIST, 2, 1),
    ('exists-file', errno.EEXIST, errno.EEXIST, 2, 1),
    ('exists-stat-error', errno.EEXIST, errno.EEXIST, 2, 1),
    ('driver-error', errno.EIO, errno.EIO, 1, 0)])
def test_recursive_mkdir_checks_existing_leaf_type(metadata, tmp_path, credential,
                                                 mode, expected, error, calls, stats):
    output = invoke(metadata, tmp_path, 'mkdir', mode, error=error, parents=1,
                    expected=expected, credential=credential)
    fields = report_fields(output)
    assert fields['calls'] == str(calls)
    assert fields['stats'] == str(stats)
    assert (int(fields['credentials']) > 0) == bool(credential)


@pytest.mark.parametrize('operation,mode,expected', [
    ('mkdir', 'no-capability', errno.EPERM), ('mkdir', 'no-operation', errno.ENOTSUP),
    ('chmod', 'no-operation', 0), ('setattr', 'no-operation', 0),
    ('setattr', 'null-attributes', errno.EINVAL)])
def test_unsupported_metadata_operation_preserves_contract(metadata, tmp_path, operation, mode, expected):
    assert invoke(metadata, tmp_path, operation, mode, expected=expected) == (
        'calls=0 credentials=0 stats=0\n')

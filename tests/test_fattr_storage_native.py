"""Private fattr envelopes preserve exact values and reject corrupt storage."""

import errno
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def fattr_storage(server_native_compile):
    return server_native_compile('fattr-storage', 'tests/c/fattr_storage_native_test.c',
        ['-Wl,--wrap=' + name for name in ('ngx_palloc', 'brix_vfs_fsetxattr', 'brix_sha256')])


def invoke(binary, tmp_path, operation, mode, name='$brix$logical', size=17, expected=0, readonly=0):
    result = subprocess.run([str(binary), str(tmp_path / 'value'), operation, mode,
        name, str(size), str(expected), str(readonly)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('name', ['ordinary', '$brix$logical'])
@pytest.mark.parametrize('size', [0, 17, 2048, 2049, 4097])
def test_roundtrip_replace_and_remove_preserve_logical_bytes(fattr_storage, tmp_path, name, size):
    invoke(fattr_storage, tmp_path, 'write', 'normal', name, size)


@pytest.mark.parametrize('mode', ['magic', 'name', 'nul-name', 'name-size', 'truncated'])
@pytest.mark.parametrize('size', [17, 2049])
def test_corrupt_private_envelope_is_never_exposed(fattr_storage, tmp_path, mode, size):
    invoke(fattr_storage, tmp_path, 'corrupt', mode, size=size)


@pytest.mark.parametrize('mode', ['value-size', 'digest-byte'])
def test_chunk_manifest_integrity_is_required(fattr_storage, tmp_path, mode):
    invoke(fattr_storage, tmp_path, 'corrupt', mode, size=2049)


@pytest.mark.parametrize('mode,size,error', [('alloc-first', 17, errno.ENOMEM),
    ('alloc-first', 2049, errno.ENOMEM), ('chunk-io', 2049, errno.EIO),
    ('manifest-io', 2049, errno.EIO), ('digest', 2049, errno.EIO)])
def test_failed_wrapped_publication_leaves_no_physical_keys(fattr_storage, tmp_path, mode, size, error):
    invoke(fattr_storage, tmp_path, 'write', mode, size=size, expected=error)


@pytest.mark.parametrize('mode,size', [('alloc-first', 17), ('alloc-first', 2049), ('alloc-second', 2049)])
def test_failed_read_returns_no_partial_value(fattr_storage, tmp_path, mode, size):
    invoke(fattr_storage, tmp_path, 'read', mode, size=size, expected=errno.ENOMEM)


def test_direct_name_can_fall_back_when_chunk_namespace_is_full(fattr_storage, tmp_path):
    invoke(fattr_storage, tmp_path, 'write', 'chunk-space', name='ordinary', size=2049)


@pytest.mark.parametrize('name,size', [('ordinary', 17), ('$brix$logical', 17), ('$brix$logical', 2049)])
def test_readonly_policy_precedes_physical_xattr_mutation(fattr_storage, tmp_path, name, size):
    invoke(fattr_storage, tmp_path, 'write', 'normal', name, size, errno.EROFS, readonly=1)

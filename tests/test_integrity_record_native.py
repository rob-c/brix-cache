"""Persisted digest records preserve data, metadata ownership and freshness checks."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def integrity_binary(server_native_compile):
    wrappers = ('getxattr', 'setxattr', 'brix_xmeta_path_load', 'brix_xmeta_path_save',
                'brix_xmeta_path_lock', 'brix_xmeta_path_unlock', 'brix_xmeta_init',
                'brix_xmeta_digest_set')
    return server_native_compile('integrity-record', 'tests/c/integrity_record_native_test.c',
                                tuple('-Wl,--wrap=' + name for name in wrappers))


@pytest.mark.parametrize('sidecar', [0, 1])
@pytest.mark.parametrize('family,mode', [
    *[('roundtrip', name) for name in ('adler32', 'crc32', 'crc32c', 'md5', 'sha1',
                                      'sha256', 'crc64', 'crc64nvme', 'zcrc32')],
    *[('failure', mode) for mode in ('lock', 'load', 'init', 'digest', 'save')],
    *[('refusal', mode) for mode in ('size', 'mtime', 'malformed', 'empty', 'oversize')],
    ('inputs', 'invalid'),
])
def test_integrity_record_storage_contract(integrity_binary, tmp_path, family, mode, sidecar):
    path = tmp_path / 'data'; payload = bytes(range(256)) * 16 + b'x'; path.write_bytes(payload)
    result = subprocess.run([str(integrity_binary), family, str(path), mode,
                             'a1b2c3d4', str(sidecar)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    expected = payload[:4096] if mode == 'size' else payload
    assert path.read_bytes() == expected
    assert result.stdout.strip() == 'integrity record verified'


@pytest.mark.parametrize('mode', ['valid', 'full', 'invalid-hex', 'zero-length',
    'negative-length', 'oversize-length', 'truncated', 'stale', 'ignore-time'])
def test_binary_checksum_record_refuses_invalid_metadata(integrity_binary, mode):
    result = subprocess.run([str(integrity_binary), 'binary', 'unused', mode, 'unused', '0'],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == 'integrity record verified'

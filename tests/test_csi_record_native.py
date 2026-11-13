"""Checksum publication preserves geometry metadata and marks unverifiable blocks."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def record_binary(server_native_compile):
    wrappers = ('brix_xmeta_path_load', 'brix_xmeta_path_save', 'brix_xmeta_path_lock',
                'brix_xmeta_path_unlock', 'brix_xmeta_init', 'realloc', 'calloc',
                'malloc', 'pread64')
    return server_native_compile('csi-record', 'tests/c/csi_record_native_test.c',
                                tuple('-Wl,--wrap=' + name for name in wrappers))


@pytest.mark.parametrize('mode,blocks,original', [
    ('fold', 80, 0), ('fold', 4, 2), ('fold', 1, 4),
    ('recompute', 4, 2), ('recompute', 1, 4), ('recompute', 80, 0),
    ('fold-alloc', 80, 0), ('no-crcs', 4, 4), ('eintr', 4, 4),
    ('short', 4, 4), ('scratch-alloc', 4, 4),
    ('load', 4, 4), ('save', 4, 4), ('lock', 4, 4), ('init', 4, 0),
    ('init', 4, 2), ('crc-alloc', 4, 4), ('invalid', 0, 0), ('cap', 0, 0),
])
def test_checksum_record_ownership(record_binary, tmp_path, mode, blocks, original):
    result = subprocess.run([str(record_binary), mode, str(tmp_path / 'data'),
                             str(blocks), str(original)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == 'checksum record contract verified'

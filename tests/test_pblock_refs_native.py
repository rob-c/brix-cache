"""Real dedup/COW catalogs preserve bytes and ownership through storage failures."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def refs_binary(server_native_compile):
    wrappers = ('sqlite3_step', 'pblock_copy_one_block', 'brix_wverify_begin',
                'pblock_pack_or_block_read')
    return server_native_compile('pblock-refs', 'tests/c/pblock_refs_native_test.c',
                                tuple('-Wl,--wrap=' + name for name in wrappers))


@pytest.mark.parametrize('mode', ['fold-equal', 'fold-collision', 'fold-repoint',
    'break-success', 'break-copy', 'break-repoint', 'break-count',
    'hash-verify', 'hash-read', 'hash-short', 'hash-hash'])
@pytest.mark.parametrize('length', [7, 4097, 70001])
def test_refs_keep_catalog_and_block_ownership(refs_binary, tmp_path, mode, length):
    (tmp_path / 'pblock.opts').write_text('csi=1\n')
    result = subprocess.run([str(refs_binary), str(tmp_path), mode, str(length)],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == 'dedup ownership verified'

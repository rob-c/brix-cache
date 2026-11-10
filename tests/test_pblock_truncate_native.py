"""Physical-block truncation preserves exact prefixes for plain and encoded storage."""

import errno
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def truncate_binary(server_native_compile):
    return server_native_compile('pblock-truncate', 'tests/c/pblock_truncate_native_test.c',
        ['-Wl,--wrap=' + name for name in ('malloc', 'pblock_block_path', 'ftruncate64', 'open64')])


def invoke(binary, tmp_path, codec, length, mode='', error=0):
    (tmp_path / 'pblock.opts').write_text('xform=zstd\n' if codec == 'zstd' else '')
    result = subprocess.run([str(binary), str(tmp_path), mode, str(length), str(error)],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('codec', ['plain', 'zstd'])
@pytest.mark.parametrize('length', [0, 1, 4096, 5000, 8192])
def test_truncation_reopens_exact_prefix_across_block_boundaries(truncate_binary, tmp_path, codec, length):
    invoke(truncate_binary, tmp_path, codec, length)


@pytest.mark.parametrize('codec,mode,error', [('zstd', 'allocation', errno.ENOMEM),
    ('zstd', 'path', errno.ENAMETOOLONG), ('zstd', 'open', errno.EACCES),
    ('plain', 'path', errno.ENAMETOOLONG), ('plain', 'open', errno.EACCES),
    ('plain', 'truncate', errno.ENOSPC)])
def test_failed_boundary_update_keeps_original_size_and_bytes(truncate_binary, tmp_path, codec, mode, error):
    invoke(truncate_binary, tmp_path, codec, 5000, mode, error)

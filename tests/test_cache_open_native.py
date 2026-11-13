"""Cache hit admission and metadata persistence against actual temporary files."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def cache_open_binary(server_native_compile):
    return server_native_compile('cache-open', 'tests/c/cache_open_native_test.c',
                                ['-Wl,--wrap=brix_vfs_adopt_obj'])


@pytest.mark.parametrize('case', ['hit', 'stale-size', 'stale-mtime', 'no-meta',
    'missing', 'directory', 'symlink', 'wrong-root', 'export-root', 'no-storage',
    'disabled', 'no-cache-root', 'empty-cache-root', 'null-context', 'null-output',
    'nocache', 'write', 'create', 'truncate', 'append', 'stat-error',
    'open-error', 'open-missing', 'adopt-error', 'adopt-heap-error',
    'metadata', 'metadata-zero', 'metadata-limits', 'legacy', 'legacy-short',
    'legacy-corrupt', 'legacy-symlink', 'metadata-errors', 'access', 'path-map',
    'first-access'])
def test_cache_entry_contracts(cache_open_binary, tmp_path, case):
    result = subprocess.run([str(cache_open_binary), case, str(tmp_path)],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr

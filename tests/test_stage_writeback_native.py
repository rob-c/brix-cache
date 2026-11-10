"""Real staging preserves partial writes, pending data, retries and caller identity."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def writeback_binary(server_native_compile):
    return server_native_compile('stage-writeback', 'tests/c/stage_writeback_native_test.c',
        ('-Wl,--wrap=brix_stage_run_inline_cred', '-Wl,--wrap=brix_stage_submit',
         '-Wl,--wrap=calloc'))


@pytest.mark.parametrize('mode', ['update', 'new', 'pending', 'identity', 'trunc-open',
    'hydrate-fail', 'probe-error', 'retry', 'async', 'truncate', 'no-source-stat',
    'no-store-open', 'no-store-write', 'no-store-read', 'no-store-stat',
    'no-store-truncate', 'no-store-reserve', 'no-store-setattr', 'no-store-fsync',
    'reserve', 'shell-alloc', 'state-alloc', 'store-open-error',
    'evict-clean', 'evict-busy', 'evict-relay', 'evict-credential',
    'namespace-rename', 'namespace-copy', 'namespace-metadata', 'namespace-directory',
    'namespace-batch', 'namespace-boundary', 'namespace-read'])
def test_writeback_ownership(writeback_binary, tmp_path, mode):
    source, store = tmp_path / 'source', tmp_path / 'store'
    source.mkdir()
    store.mkdir()
    result = subprocess.run([str(writeback_binary), mode, str(source), str(store)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == 'write-back ownership verified'
    if mode.startswith('namespace-'):
        assert list(store.iterdir()) == []
        assert not (tmp_path / 'escape').exists()

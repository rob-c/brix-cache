"""SYNC publishes integrity metadata while preserving descriptor identity."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def csi_sync(server_native_compile):
    return server_native_compile('csi-sync', 'tests/c/csi_sync_native_test.c')


@pytest.mark.parametrize('mode', ['publish', 'partial', 'corrupt', 'readonly',
                                  'bad-fd', 'replaced', 'unlinked'])
def test_sync_integrity_and_descriptor_contract(csi_sync, tmp_path, mode):
    result = subprocess.run([str(csi_sync), mode, str(tmp_path / 'data')],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == 'sync contract preserved'

"""Forwarding-driver contracts with a real confined POSIX child backend."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def forwarding_binary(server_native_compile):
    return server_native_compile('xroot-forward', 'tests/c/xroot_forward_native_test.c',
        ['-Wl,--wrap=brix_sd_xroot_create_origin', '-Wl,--wrap=brix_sd_xroot_destroy'])


@pytest.mark.parametrize('case', ['io', 'namespace', 'xattrs', 'stage-commit',
    'stage-abort', 'null-handles', 'null-driver', 'empty-driver', 'self-driver',
    'admission', 'origin-cache', 'origin-cap', 'factory-failure', 'invalid-config',
    'bad-open', 'bad-namespace', 'cross-origin', 'missing-slots'])
def test_forwarding_backend_contracts(forwarding_binary, tmp_path, case):
    result = subprocess.run([str(forwarding_binary), case, str(tmp_path)],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr

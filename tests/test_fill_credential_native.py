"""Cache-fill credentials retain ownership, exact bounds and authorization scope."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def fill_credential(server_native_compile):
    return server_native_compile('fill-credential', 'tests/c/fill_credential_native_test.c',
        ['-Wl,--wrap=brix_vfs_backend_cred', '-Wl,--wrap=brix_sd_ucred_wipe'])


def invoke(binary, mode, index=0, overflow=0):
    result = subprocess.run([str(binary), mode, str(index), str(overflow)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('index', range(15))
@pytest.mark.parametrize('mode', ['normal', 'empty'])
def test_every_credential_field_survives_source_reuse(fill_credential, index, mode):
    invoke(fill_credential, mode, index)


@pytest.mark.parametrize('index', range(15))
def test_each_oversized_credential_field_fails_closed(fill_credential, index):
    invoke(fill_credential, 'normal', index, overflow=1)


@pytest.mark.parametrize('mode', ['denied', 'gate-error', 'service', 'null-context'])
def test_absent_or_denied_user_credential_cannot_enable_forwarding(fill_credential, mode):
    invoke(fill_credential, mode)

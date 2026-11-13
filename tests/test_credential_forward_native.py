"""Credential adapters preserve selected identity, missing slots and refusal outputs."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def credential_forward(server_native_compile):
    return server_native_compile('credential-forward', 'tests/c/credential_forward_native_test.c')


@pytest.mark.parametrize('operation', ['open', 'hinted', 'staged', 'opendir'])
@pytest.mark.parametrize('mode', ['plain', 'scoped', 'scoped-only', 'allow', 'deny', 'missing'])
@pytest.mark.parametrize('error_output', [False, True])
def test_pointer_operation_never_loses_credential_contract(credential_forward,
                                                          operation, mode, error_output):
    result = subprocess.run([str(credential_forward), operation, mode, str(int(error_output))],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('mode', ['plain', 'deny'])
def test_absent_namespace_slots_are_explicit(credential_forward, mode):
    result = subprocess.run([str(credential_forward), 'namespace', mode, '1'],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr

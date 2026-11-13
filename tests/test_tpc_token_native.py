"""Delegation helper bytes, subprocess errors and controlled environment boundary."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def token_binary(server_native_compile):
    if Path('/usr/local/sbin/nginx-xrootd-tpc-token').exists():
        pytest.skip('A configured operator token helper must not be invoked by this fixture')
    return server_native_compile('tpc-token', 'tests/c/tpc_token_native_test.c',
        ['-Wl,--wrap=pipe', '-Wl,--wrap=fork'])


def invoke(binary, mode='oidc-agent', token='', environment=None):
    result = subprocess.run([str(binary), mode, token], env=environment,
        capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    status, body = result.stdout.split('\n', 1)
    return tuple(map(int, status.split())), body


def helper_environment(tmp_path, payload, status=0, executable=True):
    helper = tmp_path / 'oidc-fixture'
    record = tmp_path / 'environment.json'
    helper.write_text(f'#!{sys.executable}\n'
        'import json, os, sys\n'
        f'with open({str(record)!r}, "w") as out:\n'
        '    json.dump({"argv": sys.argv[1:], "environment": dict(os.environ)}, out)\n'
        f'os.write(1, {payload!r})\n'
        f'sys.exit({status})\n')
    helper.chmod(0o700 if executable else 0o600)
    environment = {**os.environ, 'BRIX_OIDC_TOKEN_BIN': str(helper),
        'BRIX_TPC_TEST_SECRET': 'must-not-be-inherited',
        'OIDC_SOCK': str(tmp_path / 'agent.sock'),
        'XDG_RUNTIME_DIR': str(tmp_path / 'runtime')}
    return environment, record


@pytest.mark.parametrize('payload,token', [
    (b'opaque.token\r\n\t ', 'opaque.token'),
    (b'{"access_token":"json.token","token_type":"Bearer"}', 'json.token'),
    (b'{"access_token":"escaped\\u002etoken"}\n', 'escaped.token'),
    (b'x' * 65535, 'x' * 65535),
])
def test_helper_output_and_curated_environment(token_binary, tmp_path, payload, token):
    environment, record = helper_environment(tmp_path, payload)
    assert invoke(token_binary, environment=environment) == ((0, 0), token)
    observed = json.loads(record.read_text())
    assert observed['argv'] == ['-c', 'default']
    child = observed['environment']
    assert 'BRIX_TPC_TEST_SECRET' not in child and 'BRIX_OIDC_TOKEN_BIN' not in child
    assert child['PATH'] == '/usr/bin:/bin'
    assert child['OIDC_SOCK'] == environment['OIDC_SOCK']
    assert child['XDG_RUNTIME_DIR'] == environment['XDG_RUNTIME_DIR']


@pytest.mark.parametrize('payload,status', [(b'{', 0), (b'{}', 0), (b'', 0),
    (b' \r\n\t', 0),
    (b'{"access_token":27}', 0), (b'{"access_token":""}', 0),
    (b'x' * 65536, 0), (b'usable.token', 7), (b'', 9)])
def test_failed_or_invalid_helper_cannot_publish_credential(token_binary, tmp_path,
                                                          payload, status):
    environment, _record = helper_environment(tmp_path, payload, status)
    assert invoke(token_binary, environment=environment) == ((-1, 3030), '')


@pytest.mark.parametrize('fault', ['pipe', 'fork'])
def test_subprocess_admission_failure_does_not_execute_helper(token_binary, tmp_path, fault):
    environment, record = helper_environment(tmp_path, b'token')
    environment['BRIX_TPC_TEST_FAIL'] = fault
    assert invoke(token_binary, environment=environment) == ((-1, 3012), '')
    assert not record.exists()


@pytest.mark.parametrize('mode,token,status', [('', '', (0, 0)),
    ('none', 'unchanged', (0, 0)), ('passthrough', '', (-1, 3030)),
    ('passthrough', 'opaque.token', (0, 0)), ('passthrough-opt', '', (0, 0)),
    ('passthrough-opt', 'opaque.token', (0, 0)), ('unknown', '', (-1, 3000)),
    ('token-exchange', '', (-1, 3000))])
def test_delegation_mode_boundaries(token_binary, mode, token, status):
    assert invoke(token_binary, mode, token) == (status, token if status[0] == 0 else '')

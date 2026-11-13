"""HTTP delegation executes an explicit OIDC helper and validates its result."""

import json
from pathlib import Path
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401
from test_tpc_token_native import helper_environment


@pytest.fixture(scope='module')
def oidc_binary(server_native_compile):
    if Path('/usr/local/sbin/nginx-xrootd-tpc-cred').exists():
        pytest.skip('An installed operator credential helper is outside this fixture')
    wrapped = ['pipe', 'fork', 'ngx_pnalloc', 'execv', 'execvp', 'execve', '_exit']
    flags = ['-Wl,--wrap=' + name for name in wrapped]
    flags += ['-Wl,-u,__gcov_dump', '-Wl,-u,__gcov_reset',
              str(Path(__file__).resolve().parent / 'c/coverage_exec_finite.c')]
    return server_native_compile('tpc-oidc', 'tests/c/tpc_oidc_native_test.c', flags)


def fetch(binary, environment, url='https://origin.example/path', mask='normal'):
    result = subprocess.run([str(binary), url, mask], env=environment,
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    status, token = result.stdout.split('\n', 1)
    return int(status), token


@pytest.mark.parametrize('payload,token', [
    (b'opaque-token\r\n ', 'opaque-token'),
    (b'{"access_token":"json.token"}', 'json.token'),
    (b'{"access_token":"escaped\\u002etoken"}\n', 'escaped.token'),
])
@pytest.mark.parametrize('mask', ['normal', 'blocked'])
def test_http_oidc_token_and_controlled_environment(oidc_binary, tmp_path,
                                                  payload, token, mask):
    env, record = helper_environment(tmp_path, payload)
    assert fetch(oidc_binary, env, mask=mask) == (0, token)
    observed = json.loads(record.read_text())
    assert observed['argv'] == ['-c', 'origin.example']
    child = observed['environment']
    assert child['PATH'] == '/usr/bin:/bin'
    assert child['OIDC_SOCK'] == env['OIDC_SOCK']
    assert child['XDG_RUNTIME_DIR'] == env['XDG_RUNTIME_DIR']
    assert 'BRIX_TPC_TEST_SECRET' not in child
    assert 'BRIX_OIDC_TOKEN_BIN' not in child


@pytest.mark.parametrize('url,client', [
    ('no-scheme', 'default'), ('https:///path', 'default'),
    ('https://--inject/path', 'default'), ('https://host.example', 'host.example'),
    ('https://' + 'h' * 100 + '/data', 'h' * 63),
])
def test_http_oidc_client_name_cannot_inject_options(oidc_binary, tmp_path, url, client):
    env, record = helper_environment(tmp_path, b'token')
    assert fetch(oidc_binary, env, url) == (0, 'token')
    assert json.loads(record.read_text())['argv'] == ['-c', client]


@pytest.mark.parametrize('payload,status', [(b'{', 0), (b'{}', 0), (b'', 0),
    (b' \r\n', 0), (b'{"access_token":7}', 0), (b'{"access_token":""}', 0),
    (b'token', 17), (b'', 9)])
def test_http_oidc_invalid_or_failed_output_is_not_published(oidc_binary, tmp_path,
                                                          payload, status):
    env, _record = helper_environment(tmp_path, payload, status)
    result, token = fetch(oidc_binary, env)
    assert result != 0 and token == ''


@pytest.mark.parametrize('fault', ['pipe', 'fork', 'allocation'])
def test_http_oidc_admission_and_allocation_failures(oidc_binary, tmp_path, fault):
    env, record = helper_environment(tmp_path, b'token')
    env['BRIX_TPC_TEST_FAIL'] = fault
    assert fetch(oidc_binary, env, mask='blocked') == (-1, '')
    assert record.exists() == (fault == 'allocation')


def test_http_oidc_optional_runtime_environment_can_be_absent(oidc_binary, tmp_path):
    env, record = helper_environment(tmp_path, b'token')
    env.pop('OIDC_SOCK', None)
    env.pop('XDG_RUNTIME_DIR', None)
    assert fetch(oidc_binary, env) == (0, 'token')
    child = json.loads(record.read_text())['environment']
    assert 'OIDC_SOCK' not in child and 'XDG_RUNTIME_DIR' not in child

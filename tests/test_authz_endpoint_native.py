"""Gate-only handlers preserve subrequest policy, subject privacy and OOM errors."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def endpoint(server_native_compile):
    wrappers = ('ngx_http_brix_webdav_access_handler', 'ngx_http_send_header',
                'ngx_http_internal_redirect', 'ngx_pnalloc', 'ngx_list_push')
    binary = server_native_compile('authz-endpoint', 'tests/c/authz_endpoint_native_test.c',
                                    ['-Wl,--wrap=' + name for name in wrappers])
    def run(mode='normal', accel=0, sub=1, status=0, header=-1, expected=None):
        if expected is None:
            expected = -4 if accel else 0
        result = subprocess.run([str(binary), mode, str(accel), str(sub), str(status),
                                 str(header), str(expected)], capture_output=True,
                                text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout
    return run


@pytest.mark.parametrize('accel', [0, 1])
@pytest.mark.parametrize('sub', [0, 1])
@pytest.mark.parametrize('mode', ['normal', 'anonymous', 'no-context', 'empty'])
def test_subject_only_handoff_and_anonymous_omission(endpoint, accel, sub, mode):
    output = endpoint(mode=mode, accel=accel, sub=sub)
    assert 'secret' not in output and 'credential' not in output
    if mode == 'normal':
        assert output.count('HEADER X-Brix-') == 4


@pytest.mark.parametrize('accel', [0, 1])
@pytest.mark.parametrize('status', [-5, 401, 403, 500, -1])
def test_subrequest_cannot_bypass_denied_or_missing_policy(endpoint, accel, status):
    expected = 403 if accel or status == -5 else status
    assert 'sent=0 redirects=0' in endpoint(accel=accel, status=status, expected=expected)


@pytest.mark.parametrize('accel', [0, 1])
@pytest.mark.parametrize('header', range(4))
def test_each_header_allocation_failure_prevents_publication(endpoint, accel, header):
    assert 'sent=0 redirects=0' in endpoint(accel=accel, header=header, expected=500)


def test_redirect_target_allocation_failure_prevents_handoff(endpoint):
    assert 'access=0' in endpoint(mode='allocation', accel=1, expected=500)


def test_send_failure_is_not_reported_as_success(endpoint):
    endpoint(mode='send-error', expected=-1)


def test_unconfigured_gate_does_not_publish_identity(endpoint):
    assert 'HEADER' not in endpoint(mode='neither', expected=-5)

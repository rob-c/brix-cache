"""Upstream connection failures preserve DNS, socket and bootstrap ownership."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def proxy_connect(server_native_compile):
    names = ('brix_proxy_select_endpoint', 'brix_proxy_gsi_connect_async',
             'brix_dns_resolve', 'ngx_nonblocking', 'ngx_get_connection',
             'ngx_free_connection', 'ngx_create_pool', 'ngx_palloc', 'connect',
             'ngx_handle_write_event', 'brix_proxy_cleanup', 'brix_proxy_abort',
             'brix_proxy_flush', 'ngx_ssl_create_connection', 'ngx_ssl_handshake',
             'brix_proxy_tls_handshake_done')
    binary = server_native_compile('proxy-connect', 'tests/c/proxy_connect_native_test.c',
                                  ['-Wl,--wrap=' + name for name in names])
    def run(mode='normal', deferred=0, policy=0, expected=0, username='xrd'):
        result = subprocess.run([str(binary), mode, str(deferred), str(policy),
                                 str(expected), username], capture_output=True,
                                text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout
    return run


@pytest.mark.parametrize('deferred', [0, 1])
@pytest.mark.parametrize('mode', ['normal', 'second-family', 'connecting', 'no-timeout'])
def test_resolved_socket_preserves_address_and_scheduling(proxy_connect, deferred, mode):
    output = proxy_connect(mode=mode, deferred=deferred)
    assert 'dns=1 aborts=0 cleanups=0 freed=0' in output
    assert f'flushes={int(mode in ("normal", "second-family"))}' in output


@pytest.mark.parametrize('deferred', [0, 1])
@pytest.mark.parametrize('mode', ['dns-start', 'dns-error', 'dns-empty', 'no-family',
    'nonblocking', 'connection', 'pool', 'bootstrap', 'connect-error', 'event-error', 'flush-error'])
def test_failed_connect_releases_resources_and_routes_error_once(proxy_connect, deferred, mode):
    output = proxy_connect(mode=mode, deferred=deferred, expected=-1)
    assert f'dns=1 aborts={int(deferred and mode != "dns-start")}' in output
    assert f'freed={int(mode in ("pool", "bootstrap"))}' in output


@pytest.mark.parametrize('mode,expected', [('pooled', 0), ('select-error', -1),
                                         ('gsi-ok', 0), ('gsi-error', -1)])
def test_completed_endpoint_or_gsi_route_never_opens_another_socket(proxy_connect, mode, expected):
    assert 'dns=0 aborts=0 cleanups=0 freed=0 flushes=0 tls=0' in proxy_connect(
        mode=mode, expected=expected)


@pytest.mark.parametrize('mode,policy,username', [('normal', 0, 'xrd'),
    ('normal', 1, 'client'), ('normal', 2, 'fixed-us'), ('normal', 999, 'xrd'),
    ('empty-user', 1, 'xrd'), ('no-client', 1, 'xrd')])
def test_login_identity_policy_reaches_exact_bootstrap(proxy_connect, mode, policy, username):
    assert 'flushes=1 tls=0' in proxy_connect(mode=mode, policy=policy, username=username)


@pytest.mark.parametrize('deferred', [0, 1])
@pytest.mark.parametrize('mode', ['tls-normal', 'tls-name', 'tls-again', 'tls-create'])
def test_tls_uses_sni_and_completion_callback_without_cleartext_bootstrap(proxy_connect, deferred, mode):
    output = proxy_connect(mode=mode, deferred=deferred, expected=-1 if mode == 'tls-create' else 0)
    assert f'flushes=0 tls={int(mode in ("tls-normal", "tls-name"))}' in output

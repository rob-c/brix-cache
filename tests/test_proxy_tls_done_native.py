"""The upstream TLS callback must establish trust before sending bootstrap bytes."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def tls_done(server_native_compile):
    wrappers = ('brix_proxy_cleanup', 'brix_proxy_abort', 'brix_proxy_flush',
                'ngx_handle_read_event', 'ngx_handle_write_event')
    binary = server_native_compile('proxy-tls-done', 'tests/c/proxy_tls_done_native_test.c',
                                  ['-Wl,--wrap=' + name for name in wrappers])

    def run(mode):
        result = subprocess.run([str(binary), mode], capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
    return run


@pytest.mark.parametrize('mode', ['normal', 'partial'])
def test_verified_upstream_arms_the_next_required_event(tls_done, mode):
    tls_done(mode)


@pytest.mark.parametrize('mode', ['handshake', 'untrusted'])
def test_failed_tls_trust_prevents_bootstrap_and_events(tls_done, mode):
    tls_done(mode)


@pytest.mark.parametrize('mode', ['destroyed', 'no-client'])
def test_disconnected_client_releases_upstream_without_bootstrap(tls_done, mode):
    tls_done(mode)


@pytest.mark.parametrize('mode', ['flush-error', 'read-error', 'write-error'])
def test_post_tls_io_failure_aborts_once(tls_done, mode):
    tls_done(mode)

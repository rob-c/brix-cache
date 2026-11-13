"""HTTP PTR preaccess waits resume once, cancel on abort and fail closed on refusal."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def peer_name_binary(server_native_compile):
    wrappers = ('ngx_pcalloc', 'ngx_pool_cleanup_add', 'ngx_array_push',
                'brix_http_monitor_get', 'brix_dns_reverse_cached', 'brix_dns_reverse',
                'brix_dns_reverse_cancel', 'ngx_http_core_run_phases')
    return server_native_compile('http-peer-name', 'tests/c/http_peer_name_native_test.c',
                                tuple('-Wl,--wrap=' + name for name in wrappers))


@pytest.mark.parametrize('mode', ['deferred', 'answer-refusal', 'inline', 'cancel',
    'dispatch-refusal', 'wait-allocation', 'cleanup-allocation', 'phase-allocation',
    'no-monitor', 'already-waited', 'cached', 'negative', 'unneeded', 'no-config',
    'no-address', 'oversize-address'])
def test_http_peer_lookup_owns_its_wait(peer_name_binary, mode):
    result = subprocess.run([str(peer_name_binary), mode],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == 'HTTP peer-name ownership verified'

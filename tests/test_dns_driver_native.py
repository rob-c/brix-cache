"""DNS requests must finish once, honor family policy and release cancelled work."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def dns_driver_binary(server_native_compile):
    wrappers = ('ngx_resolve_start', 'ngx_resolve_name', 'ngx_resolve_name_done',
                'brix_dns_cache_lookup', 'brix_dns_cache_store',
                'ngx_thread_pool_get', 'ngx_thread_task_alloc', 'ngx_thread_task_post',
                'ngx_create_pool', 'ngx_destroy_pool', 'getaddrinfo', 'freeaddrinfo')
    return server_native_compile('dns-driver', 'tests/c/dns_driver_native_test.c',
                                 ['-Wl,--wrap=' + name for name in wrappers])


@pytest.mark.parametrize('family,mode', [
    *[('literal', mode) for mode in ('bracket', 'excluded', 'empty', 'long')],
    *[('nginx', mode) for mode in ('success', 'family', 'oversize', 'min-ttl',
        'max-ttl', 'default-ttl', 'trailing-dot', 'search', 'absolute-search',
        'retry', 'no-resolver', 'start-fail', 'dispatch-fail', 'policy-removed',
        'cancel', 'cancel-posted')],
    *[('thread', mode) for mode in ('success', 'max-ttl', 'negative', 'system',
        'oversize', 'no-pool', 'pool-fail', 'task-fail', 'post-fail', 'cancel')],
    *[('sync', mode) for mode in ('success', 'system', 'oversize', 'empty', 'bounded')],
    *[('diagnostic', mode) for mode in ('complete', 'empty', 'one', 'zero', 'missing', 'bounded')],
])
def test_dns_request_result_and_ownership(dns_driver_binary, family, mode):
    """Keep completion, cancellation, policy and diagnostic boundaries observable."""
    result = subprocess.run([str(dns_driver_binary), family, mode],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == 'DNS driver lifecycle verified'

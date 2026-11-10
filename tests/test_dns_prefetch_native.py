"""DNS prefetch deduplicates fills and preserves bounded cache identity and ownership."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def prefetch_binary(server_native_compile):
    return server_native_compile('dns-prefetch', 'tests/c/dns_prefetch_native_test.c',
        ('-Wl,--wrap=ngx_calloc', '-Wl,--wrap=ngx_alloc', '-Wl,--wrap=brix_dns_resolve'))


@pytest.mark.parametrize('family,mode', [
    *[('prefetch', mode) for mode in ('success', 'negative', 'error', 'unknown-error',
        'deferred', 'long-budget', 'dispatch-failure', 'request-alloc')],
    *[('marker', mode) for mode in ('lifecycle', 'entry-alloc', 'name-alloc')],
    *[('family', str(index)) for index in range(6)],
    ('collision', 'names'), ('invalid', 'refusals'),
    *[('reverse', mode) for mode in ('success', 'pending', 'replace')],
])
def test_dns_cache_retains_identity_and_fill_ownership(prefetch_binary, family, mode):
    result = subprocess.run([str(prefetch_binary), family, mode],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == 'DNS cache ownership verified'

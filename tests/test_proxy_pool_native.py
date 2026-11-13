"""Dynamic proxy state contracts; this does not activate the dormant feature."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def pool_binary(server_native_compile):
    return server_native_compile('proxy-pool', 'tests/c/proxy_pool_native_test.c',
        ['-Wl,--wrap=brix_dns_backend_prepare', '-Wl,--wrap=brix_dns_resolve'])


def run_pool(binary, *arguments):
    result = subprocess.run([str(binary), *arguments], capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('case', ['weighted', 'drain', 'capacity', 'prepare-error',
    'start-error', 'resolve-error', 'oversized-address', 'drain-during-dns',
    'remove-during-dns'])
def test_proxy_pool_state_transitions(pool_binary, case):
    """Keep weighted picks, live references and pending/failed DNS consistent."""
    run_pool(pool_binary, case)


@pytest.mark.parametrize('url', ['', 'file:///etc/passwd', 'ftp://127.0.0.1',  # net-literal-allow: invalid URL parser input
    'http://', 'http://:80', 'http://host:65536', 'http://[::1', 'http://host:bad'])  # net-literal-allow: incomplete IPv6 URL parser input
def test_proxy_pool_rejects_invalid_backend_authorities(pool_binary, url):
    run_pool(pool_binary, 'invalid-url', url)

"""Token cache identity, expiry and configuration remain fail-closed at boundaries."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def token_cache_boundary(server_native_compile):
    wrappers = ('time', 'brix_sha256', 'brix_kv_get', 'brix_kv_set', 'brix_kv_find')
    binary = server_native_compile('token-cache-boundary', 'tests/c/token_cache_boundary_native_test.c',
                                  ['-Wl,--wrap=' + name for name in wrappers])

    def run(family, mode, expiry=1):
        result = subprocess.run([str(binary), family, mode, str(expiry)],
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
    return run


@pytest.mark.parametrize('expiry', [-999, -1, 0, 1, 299, 300, 301, 3600])
def test_claim_expiry_never_outlives_five_minute_cap(token_cache_boundary, expiry):
    token_cache_boundary('cache', 'normal', expiry)


@pytest.mark.parametrize('mode', ['null-zone', 'null-token', 'empty', 'digest-error',
                                'miss', 'short', 'full'])
def test_unavailable_or_malformed_cache_record_cannot_extend_authority(token_cache_boundary, mode):
    token_cache_boundary('cache', mode)


@pytest.mark.parametrize('mode', ['normal', 'missing', 'empty', 'bad-option',
                                'unknown', 'small-key', 'small-value'])
def test_only_a_sufficient_named_zone_can_bind(token_cache_boundary, mode):
    token_cache_boundary('directive', mode)

"""Eviction prioritizes oversized objects, stops on capacity and retains partial fills."""

import os
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def eviction(server_native_compile):
    names = ('brix_cache_usage_measure', 'brix_cstore_evict', 'brix_srv_unregister_path',
        'brix_cache_storage_decorator', 'brix_sd_cache_demote', 'brix_cache_state_root',
        'brix_cache_collect_dir')
    return server_native_compile('cache-eviction', 'tests/c/cache_eviction_native_test.c',
                                 ['-Wl,--wrap=' + name for name in names])


def seed_files(tmp_path):
    """Give the real collector deterministic sizes and access ordering."""
    for name, size, stamp in [('old', 10, 100), ('large', 20, 200), ('new', 5, 300),
                               ('busy.ngx-xrootd-part', 100, 1)]:
        path = tmp_path / name; path.write_bytes(b'x' * size); os.utime(path, (stamp, stamp))


def parse_result(output):
    rows = output.splitlines()
    removed = [line.removeprefix('removed=') for line in rows if line.startswith('removed=')]
    counts = tuple(map(int, next(line for line in rows if line.startswith('result=')).split('=')[1].split()))
    return removed, counts


def invoke(binary, tmp_path, mode, operation='purge'):
    seed_files(tmp_path)
    result = subprocess.run([str(binary), str(tmp_path), mode, operation],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (tmp_path / 'busy.ngx-xrootd-part').read_bytes() == b'x' * 100
    assert (tmp_path / 'new').read_bytes() == b'x' * 5
    return parse_result(result.stdout)


@pytest.mark.parametrize('mode', ['normal', 'lru', 'ipv6', 'demote', 'partial-scan'])
def test_priority_capacity_and_manager_unregistration(eviction, tmp_path, mode):
    removed, counts = invoke(eviction, tmp_path, mode)
    assert removed == (['/old', '/large'] if mode == 'lru' else ['/large', '/old'])
    assert counts[:3] == (0, 2, 30) and counts[4:6] == (2, 2)
    assert counts[6] == (2 if mode == 'demote' else 0)
    assert counts[7] == int(mode == 'partial-scan')


@pytest.mark.parametrize('mode,rc,errors', [('no-root', -1, 1), ('usage-error', -1, 1), ('below', 0, 0)])
def test_missing_capacity_or_satisfied_target_removes_nothing(eviction, tmp_path, mode, rc, errors):
    removed, counts = invoke(eviction, tmp_path, mode)
    assert not removed and counts[:3] == (rc, 0, 0) and counts[7] == errors
    assert (tmp_path / 'old').exists() and (tmp_path / 'large').exists()


def test_failed_remeasurement_stops_after_one_completed_eviction(eviction, tmp_path):
    removed, counts = invoke(eviction, tmp_path, 'remeasure-error')
    assert removed == ['/large'] and counts[:3] == (-1, 1, 20)
    assert counts[7] == 1 and (tmp_path / 'old').exists()


@pytest.mark.parametrize('mode', ['normal', 'usage-error', 'below', 'remeasure-error'])
def test_on_fill_releases_its_sentinel_after_success_or_failure(eviction, tmp_path, mode):
    removed, _counts = invoke(eviction, tmp_path, mode, 'on-fill')
    expected = {'normal': ['/large', '/old'], 'usage-error': [], 'below': [],
                'remeasure-error': ['/large']}
    assert removed == expected[mode]
    assert not list(tmp_path.glob('*evict*'))

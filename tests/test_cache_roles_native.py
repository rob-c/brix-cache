"""Cache keys and role instances preserve namespace boundaries and borrowed descriptors."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def roles_binary(server_native_compile):
    return server_native_compile('cache-roles', 'tests/c/cache_roles_native_test.c',
        ['-Wl,--wrap=brix_sd_posix_borrow_instance', '-Wl,--wrap=brix_cstore_init'])


def invoke(binary, operation, mode, root, cache, path):
    result = subprocess.run([str(binary), operation, mode, str(root), str(cache), str(path)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.strip()


@pytest.mark.parametrize('path,expected', [('/export/file', '0|/file|-'), ('/export', '0|/|-'),
    ('/export-other/file', '-1|-|-'), ('/cache/file', '-1|-|/file'),
    ('/cache-other/file', '-1|-|-'), ('/cache', '-1|-|-')])
def test_keys_keep_export_and_cache_namespaces_distinct(roles_binary, path, expected):
    assert invoke(roles_binary, 'key', 'normal', '/export', '/cache', path) == expected


@pytest.mark.parametrize('mode', ['disabled', 'small'])
def test_absent_cache_or_small_destination_refuses_a_key(roles_binary, mode):
    assert invoke(roles_binary, 'key', mode, '/export', '/cache', '/export/file') == '-1|-|-'


@pytest.mark.parametrize('mode,expected', [('normal', '1'), ('borrow-error', '0'), ('null', '0'), ('empty', '0')])
def test_lazy_cache_lookup_is_stable_or_closes_a_failed_borrow(roles_binary, tmp_path, mode, expected):
    assert invoke(roles_binary, 'lazy', mode, tmp_path, tmp_path, '-') == expected


def test_lazy_cache_does_not_create_missing_storage(roles_binary, tmp_path):
    absent = tmp_path / 'missing'
    assert invoke(roles_binary, 'lazy', 'normal', tmp_path, absent, '-') == '0'
    assert not absent.exists()


@pytest.mark.parametrize('mode,expected', [('normal', '0 1 1 1'), ('borrow-error', '0 0 0 0'),
    ('cstore-error', '-1 1 0 0')])
def test_distinct_role_roots_close_all_owned_descriptors_even_after_failure(roles_binary, tmp_path, mode, expected):
    cache = tmp_path / 'cache'; stage = tmp_path / 'stage'; cache.mkdir(); stage.mkdir()
    assert invoke(roles_binary, 'roles', mode, tmp_path, cache, stage) == expected


def test_missing_role_directories_are_not_created_by_worker_setup(roles_binary, tmp_path):
    cache = tmp_path / 'cache'; stage = tmp_path / 'stage'
    assert invoke(roles_binary, 'roles', 'normal', tmp_path, cache, stage) == '0 0 0 0'
    assert not cache.exists() and not stage.exists()

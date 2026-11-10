"""Cache-store adapters preserve sparse bytes, driver errors and descriptor ownership."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def cache_store(server_native_compile):
    return server_native_compile('cache-store', 'tests/c/cache_store_native_test.c',
        ['-Wl,--wrap=brix_cinfo_l1_create', '-Wl,--wrap=ftruncate64'])


def invoke(binary, operation, mode, path):
    result = subprocess.run([str(binary), operation, mode, str(path)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('mode', ['sidecar', 'xattr', 'allocation'])
def test_adapter_mode_selection_and_allocation_failure(cache_store, tmp_path, mode):
    invoke(cache_store, 'init', mode, tmp_path)


def test_missing_driver_capabilities_refuse_mutation(cache_store, tmp_path):
    invoke(cache_store, 'missing', '', tmp_path)


@pytest.mark.parametrize('mode', ['normal', 'long-key', 'truncate', 'fill-refused'])
def test_partial_file_bytes_bounds_and_failed_resize_cleanup(cache_store, tmp_path, mode):
    invoke(cache_store, 'partial', mode, tmp_path)


@pytest.mark.parametrize('mode', ['normal', 'stage-refused'])
def test_nested_fill_preserves_driver_error_and_exact_dispatch(cache_store, tmp_path, mode):
    invoke(cache_store, 'fill', mode, tmp_path)


@pytest.mark.parametrize('mode', ['normal', 'open-refused'])
def test_checksum_seeding_releases_heap_shell_and_owned_descriptor(cache_store, tmp_path, mode):
    path = tmp_path / 'object'
    path.write_bytes(b'abcdefghijkl')
    invoke(cache_store, 'seed', mode, path)

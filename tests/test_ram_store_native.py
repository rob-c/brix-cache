"""Real RAM store contracts include atomic publication, bounds and failed allocations."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def ram_binary(server_native_compile):
    wrapped = ['malloc', 'calloc', 'realloc', 'strdup', 'strndup', 'ngx_calloc']
    return server_native_compile('ram-store', 'tests/c/ram_store_native_test.c',
                                 ['-Wl,--wrap=' + name for name in wrapped])


def run_ram(binary, *arguments):
    result = subprocess.run([str(binary), *map(str, arguments)], capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('case', ['data', 'holes', 'xattrs', 'missing',
                                 'reservations', 'invalid-init'])
def test_ram_lifecycle_and_bounds(ram_binary, case):
    run_ram(ram_binary, case)


@pytest.mark.parametrize('path', ['/folder', '/folder/', '/folder///'])
def test_ram_listing_snapshot_survives_unlink(ram_binary, path):
    run_ram(ram_binary, 'listing', path)


@pytest.mark.parametrize('path', ['', 'relative', '../relative', '/../outside',
                                 '/a/../b', '/a/..'])
def test_every_ram_namespace_operation_refuses_parent_components(ram_binary, path):
    run_ram(ram_binary, 'bad-path', path)


@pytest.mark.parametrize('condition', ['absent', 'exists', 'missing', 'matching',
                                      'mismatch', 'unknown'])
def test_ram_atomic_publish_preconditions(ram_binary, condition):
    run_ram(ram_binary, 'precondition', condition)


@pytest.mark.parametrize('skip', [0, 1])
def test_failed_instance_allocation_leaves_no_state(ram_binary, skip):
    run_ram(ram_binary, 'init-failure', skip)


@pytest.mark.parametrize('operation,allocator,skip', [
    ('open', 'ngx_calloc', 0), ('open', 'ngx_calloc', 1),
    ('staged', 'calloc', 0), ('staged', 'calloc', 1), ('staged', 'strdup', 0),
    ('mkdir', 'calloc', 0), ('mkdir', 'strdup', 0),
    ('directory', 'ngx_calloc', 0), ('directory', 'calloc', 0),
    ('directory', 'calloc', 1), ('directory', 'calloc', 2),
    ('directory', 'strndup', 0), ('directory', 'strndup', 1),
    ('xattr', 'malloc', 0), ('xattr', 'calloc', 0), ('xattr', 'strdup', 0),
    ('write', 'realloc', 0),
])
def test_allocation_failure_preserves_existing_objects(ram_binary, operation,
                                                       allocator, skip):
    run_ram(ram_binary, 'failure', operation, allocator, skip)

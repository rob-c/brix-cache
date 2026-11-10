"""Cache forwarding retains credentials and invalidates only the affected keys."""

import errno
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def forward_binary(server_native_compile):
    return server_native_compile('cache-forward', 'tests/c/cache_forward_native_test.c',
                                 ['-Wl,--wrap=brix_cstore_evict'])


def invoke(binary, operation, mode, credential):
    result = subprocess.run([str(binary), operation, mode, str(int(credential))],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    values = result.stdout.split()
    return tuple(map(int, values[:5])), values[5]


@pytest.mark.parametrize('operation,evictions,keys', [('batch', 3, '/a/b/c'), ('staged', 1, '/a')])
@pytest.mark.parametrize('credential', [False, True])
def test_success_forwards_the_same_identity_and_invalidates_exact_keys(forward_binary, operation, evictions, keys, credential):
    assert invoke(forward_binary, operation, 'normal', credential) == ((0, 0, 1, int(credential), evictions), keys)


@pytest.mark.parametrize('operation', ['batch', 'staged'])
@pytest.mark.parametrize('credential', [False, True])
def test_partial_batch_only_evicts_successful_attempted_keys(forward_binary, operation, credential):
    assert invoke(forward_binary, operation, 'partial', credential) == ((-1, errno.EIO, 1, int(credential), 1), '/a')


@pytest.mark.parametrize('operation,error', [('batch', errno.ENOTSUP), ('staged', errno.ENOSYS)])
@pytest.mark.parametrize('credential', [False, True])
def test_absent_source_capability_cannot_invent_a_mutation(forward_binary, operation, error, credential):
    assert invoke(forward_binary, operation, 'absent', credential) == ((-1, error, 0, 0, 0), '-')


@pytest.mark.parametrize('operation,evictions,keys', [('batch', 3, '/a/b/c'), ('staged', 1, '/a')])
def test_explicitly_allowed_service_fallback_preserves_source_outcome(forward_binary, operation, evictions, keys):
    assert invoke(forward_binary, operation, 'fallback', True) == ((0, 0, 1, 0, evictions), keys)


@pytest.mark.parametrize('operation,evictions,keys', [('batch', 0, '-'), ('staged', 1, '/a')])
def test_denied_credential_fallback_never_calls_the_service_slot(forward_binary, operation, evictions, keys):
    assert invoke(forward_binary, operation, 'denied', True) == ((-1, errno.EACCES, 0, 0, evictions), keys)


@pytest.mark.parametrize('operation,evictions,keys', [('unlink', 1, '/a'), ('rename', 2, '/a/b'),
                                                   ('opendir', 0, '-'), ('sync', 0, '-')])
def test_plain_namespace_and_publish_forward_without_owning_source_handles(forward_binary, operation, evictions, keys):
    assert invoke(forward_binary, operation, 'normal', False) == ((0, 0, 1, 0, evictions), keys)
    assert invoke(forward_binary, operation, 'partial', False) == ((-1, errno.EIO, 1, 0, 0), '-')


def test_optional_publish_barrier_and_unsupported_reservation_are_distinct(forward_binary):
    assert invoke(forward_binary, 'sync', 'absent', False) == ((0, 0, 0, 0, 0), '-')
    assert invoke(forward_binary, 'reserve', 'normal', False) == ((-1, errno.EOPNOTSUPP, 0, 0, 0), '-')

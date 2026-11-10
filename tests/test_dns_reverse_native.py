"""Reverse DNS preserves callback ownership and finite positive/negative caching."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def reverse_binary(server_native_compile):
    names = ('brix_dns_policy_resolver', 'ngx_resolve_start', 'ngx_resolve_addr',
        'ngx_resolve_addr_done', 'getnameinfo', 'brix_dns_bridge_reverse',
        'brix_dns_thread_task_new', 'brix_dns_thread_task_post')
    return server_native_compile('dns-reverse', 'tests/c/dns_reverse_native_test.c',
                                ['-Wl,--wrap=' + name for name in names])


def invoke(binary, backend, mode='normal', family=4):
    result = subprocess.run([str(binary), backend, mode, str(family)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return tuple(map(int, result.stdout.split()))


@pytest.mark.parametrize('family', [4, 6])
@pytest.mark.parametrize('backend', ['resolver', 'thread', 'sync', 'prefetch'])
def test_reverse_answer_is_cached_without_duplicate_lookup(reverse_binary, family, backend):
    counts = invoke(reverse_binary, backend, family=family)
    assert counts[:3] == (0, 0, 0)
    assert counts[4] == int(backend != 'resolver')
    assert counts[5] == (2 if backend in ('resolver', 'thread') else 0)


@pytest.mark.parametrize('backend', ['resolver', 'thread', 'sync'])
@pytest.mark.parametrize('mode,result', [('no-name', -5), ('libc-error', -1)])
def test_failed_lookup_caches_no_attacker_controlled_name(reverse_binary, backend, mode, result):
    counts = invoke(reverse_binary, backend, mode)
    assert counts[1:3] == (result, -5) and counts[8] == 0
    assert counts[5] == int(backend != 'sync')


@pytest.mark.parametrize('mode,expected_ttl', [('normal', 8), ('ttl-low', 3), ('no-policy', 100)])
def test_resolver_ttl_is_clamped_to_the_declared_policy(reverse_binary, mode, expected_ttl):
    counts = invoke(reverse_binary, 'resolver', mode)
    assert counts[:3] == (0, 0, 0) and counts[7] == expected_ttl


def test_untrusted_long_ptr_is_terminated_at_the_public_capacity(reverse_binary):
    counts = invoke(reverse_binary, 'resolver', 'long-name')
    assert counts[:3] == (0, 0, 0) and counts[8] == 255


@pytest.mark.parametrize('backend', ['resolver', 'thread'])
def test_cancellation_prevents_completion_and_cache_publication(reverse_binary, backend):
    counts = invoke(reverse_binary, backend, 'cancel')
    assert counts[0] == 0 and counts[2] == -2 and counts[5] == 0
    assert counts[6] == int(backend == 'resolver')


@pytest.mark.parametrize('backend,mode,rc,callbacks', [
    ('resolver', 'start-null', 0, 1), ('resolver', 'no-resolver', 0, 1),
    ('resolver', 'resolve-error', 0, 1), ('resolver', 'empty-name', 0, 1),
    ('thread', 'no-pool', 0, 1), ('thread', 'task-alloc', -1, 0),
    ('thread', 'post-error', -1, 0)])
def test_backend_start_failures_never_leave_pending_ownership(reverse_binary, backend, mode, rc, callbacks):
    counts = invoke(reverse_binary, backend, mode)
    assert counts[0] == rc and counts[5] == callbacks and counts[8] == 0


@pytest.mark.parametrize('backend', ['resolver', 'thread', 'sync'])
@pytest.mark.parametrize('mode', ['unsupported', 'short-address'])
def test_unsupported_peer_addresses_never_reach_a_resolver(reverse_binary, backend, mode):
    counts = invoke(reverse_binary, backend, mode)
    assert counts[1] == -5 and counts[3:5] == (0, 0) and counts[8] == 0


@pytest.mark.parametrize('mode,result', [('null-address', -5), ('null-buffer', -1), ('empty-buffer', -1)])
def test_invalid_sync_buffers_cannot_start_work(reverse_binary, mode, result):
    counts = invoke(reverse_binary, 'sync', mode)
    assert counts[0] == result and counts[3:5] == (0, 0)


def test_sync_bridge_answer_does_not_fall_through_to_libc(reverse_binary):
    counts = invoke(reverse_binary, 'sync', 'bridge')
    assert counts[:2] == (0, 0) and counts[4] == 0 and counts[8] == len('bridge.test')


@pytest.mark.parametrize('mode', ['no-name', 'libc-error', 'post-error'])
def test_prefetch_failure_releases_its_request_without_duplicate_dispatch(reverse_binary, mode):
    counts = invoke(reverse_binary, 'prefetch', mode)
    assert counts[0] == 0 and counts[3] == 1 and counts[5] == 0

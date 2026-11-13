"""Real thread/eventfd resolver bridge lifecycle and failure contracts."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def bridge_binary(server_native_compile):
    wrappers = ('malloc', 'calloc', 'realloc', 'strdup', 'strndup', 'ngx_calloc',
                'ngx_get_connection', 'ngx_free_connection', 'brix_dns_resolve',
                'brix_dns_reverse')
    return server_native_compile('dns-bridge', 'tests/c/dns_bridge_native_test.c',
                                 ['-Wl,--wrap=' + name for name in wrappers])


def run_bridge(binary, mode, reverse=0, maximum=2):
    result = subprocess.run([str(binary), mode, str(reverse), str(maximum)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


@pytest.mark.parametrize('reverse', [0, 1])
@pytest.mark.parametrize('mode', ['normal', 'large-deadline', 'dispatch-error', 'answer-error',
    'alloc-fail', 'pending-exit', 'inflight-exit', 'not-ready', 'no-policy', 'off',
    'empty-resolver', 'main', 'connection-fail', 'event-fail'])
def test_lookup_preserves_result_and_shutdown_ownership(bridge_binary, mode, reverse):
    run_bridge(bridge_binary, mode, reverse, 0 if reverse else 2)


@pytest.mark.parametrize('maximum', [0, 1, 2])
def test_forward_answers_respect_caller_capacity(bridge_binary, maximum):
    assert f'count={maximum}' in run_bridge(bridge_binary, 'normal', maximum=maximum)


@pytest.mark.parametrize('mode', ['empty', 'no-error-buffer'])
def test_forward_optional_answers_and_diagnostics(bridge_binary, mode):
    run_bridge(bridge_binary, mode)


@pytest.mark.parametrize('maximum', [1, 8, 64])
def test_reverse_name_is_bounded_and_terminated(bridge_binary, maximum):
    output = run_bridge(bridge_binary, 'normal', reverse=1, maximum=maximum)
    assert 'text=' + 'verified.example'[:maximum - 1] + '\n' in output


def test_oversize_sockaddr_cannot_enter_bridge(bridge_binary):
    assert 'dispatched=0' in run_bridge(bridge_binary, 'oversize', reverse=1)

"""Bound proxy requests retain their session identity and opaque wire handles."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def lazy_proxy_binary(server_native_compile):
    return server_native_compile('proxy-lazy', 'tests/c/proxy_lazy_native_test.c',
        ['-Wl,--wrap=brix_send_error', '-Wl,--wrap=brix_proxy_abort',
         '-Wl,--wrap=brix_proxy_cleanup', '-Wl,--wrap=ngx_handle_read_event'])


@pytest.mark.parametrize('case', ['read', 'pgread', 'readv', 'chain', 'no-saved',
    'not-lazy', 'upstream-denied', 'foreign-session', 'missing-handle',
    'invalid-handle', 'send-error', 'send-again', 'arm-error',
    'deferred-send-error', 'deferred-send-again', 'deferred-arm-error',
    'wait', 'wait-payload', 'wait-send-error', 'wait-send-again',
    'wait-arm-error', 'wait-no-context', 'wait-destroyed', 'wait-no-request',
    'wait-no-upstream', 'wait-null', 'slots'])
def test_bound_proxy_transitions(lazy_proxy_binary, case):
    result = subprocess.run([str(lazy_proxy_binary), case], capture_output=True,
                            text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr

"""Kernel splice framing, real backpressure, and bounded buffered fallback."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def splice_binary(server_native_compile):
    wrapped = ['brix_proxy_abort', 'brix_schedule_read_resume',
               'ngx_stream_brix_send', 'brix_queue_response_base',
               'ngx_handle_read_event', 'ngx_handle_write_event', 'ngx_alloc']
    return server_native_compile('proxy-splice', 'tests/c/proxy_splice_native_test.c',
                                  ['-Wl,--wrap=' + name for name in wrapped])


@pytest.mark.parametrize('case', [
    'fill', 'fill-alloc-error', 'fill-arm-error', 'fill-relay-error',
    'drain', 'drain-alloc-error', 'drain-arm-error', 'drain-relay-error',
    'deferred', 'deferred-arm-error', 'destroyed', 'missing-context',
    'missing-proxy', 'inactive', 'no-upstream', 'no-client', 'closed',
    'bad-upstream', 'bad-client', 'stream', 'stream-arm-error',
    'header0', 'header1', 'header2', 'header3', 'header4',
])
def test_proxy_splice_transitions(splice_binary, case):
    result = subprocess.run([str(splice_binary), case], capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr

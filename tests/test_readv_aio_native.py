"""Readv workers and completions preserve data, request identity and buffer ownership."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def readv_aio_binary(server_native_compile):
    wrappers = ['brix_queue_response_chain', 'brix_aio_resume', 'brix_send_error',
                'brix_read_io_error', 'brix_build_chunked_chain']
    return server_native_compile('readv-aio', 'tests/c/readv_aio_native_test.c',
                                 ['-Wl,--wrap=' + name for name in wrappers])


@pytest.mark.parametrize('mode', ['contiguous', 'scattered', 'empty-segment',
                                 'queued', 'destroyed', 'chain-failure',
                                 'bad-fd', 'past-eof', 'negative-offset',
                                 'overflow', 'empty-plan', 'wait'])
def test_worker_result_and_completion_ownership(readv_aio_binary, tmp_path, mode):
    source = tmp_path / 'data'
    source.write_bytes(b'abcdefghijklmnop')
    result = subprocess.run([str(readv_aio_binary), mode, str(source)],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr

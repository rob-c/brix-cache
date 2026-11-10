"""Native TPC completion owns replies, destination cleanup and source preservation."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def tpc_done_binary(server_native_compile):
    return server_native_compile('tpc-done', 'tests/c/tpc_done_native_test.c',
        ['-Wl,--wrap=brix_send_ok', '-Wl,--wrap=brix_send_error',
         '-Wl,--wrap=brix_queue_response', '-Wl,--wrap=brix_aio_resume',
         '-Wl,--wrap=close'])


@pytest.mark.parametrize('reply', ['open', 'sync'])
@pytest.mark.parametrize('owner', ['plain', 'driver'])
@pytest.mark.parametrize('mode', ['success', 'fail', 'push-fail', 'read-only-fail',
    'destroyed', 'orphan-context', 'orphan-connection', 'invalid-slot',
    'stat-key', 'stat', 'key', 'no-stat'])
def test_completion_lifetime_and_data_ownership(tpc_done_binary, tmp_path, reply, mode, owner):
    result = subprocess.run([str(tpc_done_binary), reply, mode, str(tmp_path), owner],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr

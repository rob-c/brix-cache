"""Reconnect replay must complete every request even if its first write fails."""

from pathlib import Path
import subprocess
import sys

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def replay_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    return compile_client_contract(root, tmp_path_factory.mktemp('aio-replay'),
        'tests/c/aio_reconnect_native_test.c',
        ('io_engine_arm', 'io_engine_del', 'aconn_do_write', 'pthread_create'))


@pytest.mark.parametrize('mode', ['success', 'arm-failure', 'replay-drop',
                                 'worker-failure', 'repark', 'unsafe'])
@pytest.mark.parametrize('requests', [1, 2, 5])
def test_replay_retains_all_parked_requests(replay_binary, mode, requests):
    result = subprocess.run([str(replay_binary), mode, str(requests)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert f'completed={requests} expected={requests}' in result.stdout

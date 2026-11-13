"""Real reconnect workers preserve endpoints, deadlines and one completion wakeup."""

from pathlib import Path
import subprocess
import sys

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def worker_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    return compile_client_contract(root, tmp_path_factory.mktemp('aio-worker'),
        'tests/c/aio_worker_native_test.c', ('brix_mono_ns', 'brix_reconnect', 'nanosleep'))


@pytest.mark.parametrize('attempt', [1, 2, 3, 4, 6])
@pytest.mark.parametrize('connect_ms', [0, 25, 100])
def test_reconnect_success_publishes_once(worker_binary, attempt, connect_ms):
    result = subprocess.run([str(worker_binary), str(attempt), '10000', str(connect_ms)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert f'attempts={attempt} sleeps={attempt - 1} result=0' in result.stdout


@pytest.mark.parametrize('budget_ms,connect_ms', [(0, 0), (1, 0), (50, 0), (210, 0),
    (5000, 0), (1, 10), (200, 500), (450, 100)])
def test_reconnect_deadline_preserves_last_failure(worker_binary, budget_ms, connect_ms):
    result = subprocess.run([str(worker_binary), '0', str(budget_ms), str(connect_ms)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'result=-1' in result.stdout

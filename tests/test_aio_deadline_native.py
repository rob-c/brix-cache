"""Deadline expiry preserves survivors and never wraps a far-future timer."""

from pathlib import Path
import subprocess
import sys

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def deadline_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    return compile_client_contract(root, tmp_path_factory.mktemp('aio-deadline'),
        'tests/c/aio_deadline_native_test.c', ('brix_mono_ns', 'io_engine_del'))


@pytest.mark.parametrize('delta_ns,expected', [(1, 1), (999999, 1), (1000000, 2),
    (1999999, 2), (2000000, 3), (1000000000, 1000), (2147483647000000, 1000),
    (4294967296000000, 1000)])
def test_wait_stays_bounded_for_far_future_deadlines(deadline_binary, delta_ns, expected):
    result = subprocess.run([str(deadline_binary), 'wait', str(delta_ns), str(expected)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('mode', ['alive', 'parked', 'dead', 'heartbeat'])
def test_expiry_retains_survivors_and_completes_once(deadline_binary, mode):
    result = subprocess.run([str(deadline_binary), mode, '0', '0'],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'deadline ownership verified' in result.stdout

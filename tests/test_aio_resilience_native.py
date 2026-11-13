"""A concurrently disabled heartbeat must not become an immediately due ping."""

from pathlib import Path
import subprocess
import sys

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def aio_policy_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    return compile_client_contract(root, tmp_path_factory.mktemp('aio-policy'),
        'tests/c/aio_resilience_native_test.c',
        ('brix_mono_ns', 'aconn_do_write', 'io_engine_arm', 'calloc'))


@pytest.mark.parametrize('mode,expected', [('due', 1), ('recent', 0), ('disabled', 0),
    ('reconnecting', 0), ('pending', 0), ('alloc-failure', 0), ('disable-during-check', 0)])
def test_heartbeat_uses_one_policy_snapshot(aio_policy_binary, mode, expected):
    result = subprocess.run([str(aio_policy_binary), mode, str(expected)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert f'writes={expected}' in result.stdout

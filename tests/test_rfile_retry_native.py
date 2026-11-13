"""The synchronous handle runner retains cancellation, deadline and replay contracts."""
from pathlib import Path
import subprocess
import sys
import pytest
from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def retry_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp('rfile-retry-native')
    wrappers = ['brix_file_' + name for name in
                ('read', 'pgread', 'write', 'pgwrite', 'stat', 'open_read', 'open_update')]
    wrappers += ['brix_reconnect', 'brix_backoff_sleep_fast']
    return compile_client_contract(root, output, 'tests/c/rfile_retry_native_test.c', wrappers)


@pytest.mark.parametrize('operation', ['read', 'pgread', 'write', 'pgwrite', 'stat'])
@pytest.mark.parametrize('mode', ['success', 'retry', 'auth-error', 'cancel', 'disabled', 'deadline'])
def test_handle_operation_recovery(retry_binary, operation, mode):
    run_retry(retry_binary, operation, mode)


@pytest.mark.parametrize('operation', ['read', 'pgread'])
def test_adaptive_read_never_shrinks_below_floor(retry_binary, operation):
    run_retry(retry_binary, operation, 'floor')


def run_retry(binary, operation, mode):
    result = subprocess.run([str(binary), operation, mode],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


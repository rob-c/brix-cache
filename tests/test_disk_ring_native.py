"""Real kernel disk rings preserve bounded buffers, seek order and error disposition."""

from pathlib import Path
import subprocess
import sys

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux io_uring')


@pytest.fixture(scope='module')
def disk_ring_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp('disk-ring-native')
    wrappers = ['calloc', 'malloc', 'posix_memalign', 'io_uring_queue_init',
                'io_uring_submit']
    return compile_client_contract(root, output, 'tests/c/disk_ring_native_test.c', wrappers)


@pytest.mark.parametrize('mode', ['roundtrip', 'short-read', 'read-error', 'write-error',
                                 'calloc', 'slots', 'malloc', 'aligned', 'queue',
                                 'submit', 'direct', 'depth-low', 'depth-high'])
def test_disk_ring_data_and_failure_contracts(disk_ring_binary, tmp_path, mode):
    result = subprocess.run([str(disk_ring_binary), mode, str(tmp_path / 'data')],
                            capture_output=True, text=True, timeout=15)
    if result.returncode == 77:
        pytest.skip('Kernel io_uring disk operations are unavailable')
    assert result.returncode == 0, result.stdout + result.stderr

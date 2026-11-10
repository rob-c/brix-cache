"""Real local-storage contracts: publication, device semantics and failed resources."""

from pathlib import Path
import subprocess
import sys

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def client_vfs_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp('client-vfs-native')
    return compile_client_contract(root, output, 'tests/c/client_vfs_native_test.c',
        ('malloc', 'calloc', 'strdup', 'pread', 'pwrite', 'fstat', 'stat',
         'fsync', 'ftruncate', 'rename', 'brix_uring_available',
         'brix_disk_ring_create', 'brix_disk_ring_pwrite', 'brix_disk_ring_flush'))


def run_contract(binary, tmp_path, backend, mode, ring):
    result = subprocess.run([str(binary), backend, mode, ring, str(tmp_path)],
                            capture_output=True, text=True, timeout=15)
    if result.returncode == 77:
        pytest.skip('This build or kernel cannot run real io_uring operations')
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('backend', ['file', 'block'])
@pytest.mark.parametrize('ring', ['off', 'on', 'auto'])
@pytest.mark.parametrize('mode', ['roundtrip', 'abort', 'read-only', 'stat'])
def test_real_storage_contracts(client_vfs_binary, tmp_path, backend, ring, mode):
    run_contract(client_vfs_binary, tmp_path, backend, mode, ring)


@pytest.mark.parametrize('backend', ['file', 'block'])
@pytest.mark.parametrize('mode', ['read-strdup', 'read-calloc', 'write-strdup',
    'write-calloc', 'read-missing', 'write-missing', 'symlink', 'read-pread',
    'read-fstat', 'write-pwrite', 'write-fsync', 'commit-fsync', 'stat-fail',
    'ring-unavailable', 'ring-create', 'ring-write', 'ring-flush', 'commit-flush'])
def test_storage_failure_contracts(client_vfs_binary, tmp_path, backend, mode):
    run_contract(client_vfs_binary, tmp_path, backend, mode, 'off')


@pytest.mark.parametrize('mode', ['write-malloc', 'write-ftruncate', 'commit-rename',
                                 'existing', 'read-symlink'])
def test_atomic_file_failures(client_vfs_binary, tmp_path, mode):
    run_contract(client_vfs_binary, tmp_path, 'file', mode, 'off')


@pytest.mark.parametrize('backend', ['file', 'block'])
@pytest.mark.parametrize('mode', ['auto-unavailable', 'auto-create'])
def test_optional_ring_falls_back(client_vfs_binary, tmp_path, backend, mode):
    run_contract(client_vfs_binary, tmp_path, backend, mode, 'auto')

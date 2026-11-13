"""Shipped socket I/O keeps cancellation, deadlines and syscall failures bounded."""

from pathlib import Path
import subprocess
import sys

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def socket_boundary_binary(tmp_path_factory):
    """Link the finite driver to the configured client archive and dependencies."""
    root = Path(__file__).resolve().parents[1]
    return compile_client_contract(root, tmp_path_factory.mktemp('socket-boundary'),
        'tests/c/client_socket_boundary_test.c',
        ('poll', 'read', 'send', 'brix_mono_ns', 'socket', 'connect', 'getsockopt'))


@pytest.mark.parametrize('case', [
    'read-partial', 'write-partial', 'read-again', 'write-interrupt',
    'poll-interrupt', 'read-poll-error', 'write-poll-error', 'read-timeout',
    'write-timeout', 'read-error', 'write-error', 'read-cancel', 'write-cancel',
    'read-eof', 'read-expired', 'read-submillisecond', 'read-drip',
    'connect-success', 'connect-socket-error', 'connect-direct-error',
    'connect-poll-error', 'connect-timeout', 'connect-inspect-error', 'connect-refused',
])
def test_socket_boundaries_preserve_bytes_and_native_status(socket_boundary_binary, case):
    """Real bytes, closed descriptors and untouched buffers remain observable."""
    result = subprocess.run([str(socket_boundary_binary), case],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == 'Socket boundary contract verified'

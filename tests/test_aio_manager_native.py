"""Connection managers retain streams and release every partial construction owner."""

from pathlib import Path
import subprocess
import sys

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def manager_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    return compile_client_contract(root, tmp_path_factory.mktemp('aio-manager'),
        'tests/c/aio_manager_native_test.c', ('calloc', 'pthread_create',
            'brix_loop_create', 'brix_loop_destroy', 'brix_connect', 'brix_close',
            'brix_aconn_attach', 'brix_aconn_close', 'brix_aconn_set_resilience',
            'brix_aio_call_ex'))


@pytest.mark.parametrize('options', [0, 1])
@pytest.mark.parametrize('mode', ['defaults', 'eager', 'clamp-eager', 'lazy',
    'lazy-connect', 'lazy-attach', 'connect-failure', 'attach-failure',
    'loop-failure', 'thread-failure', 'alloc-1', 'alloc-2', 'alloc-3', 'alloc-4', 'alloc-5'])
def test_manager_owns_every_created_stream(manager_binary, mode, options):
    result = subprocess.run([str(manager_binary), mode, str(options)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == 'manager ownership verified'

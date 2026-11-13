"""Resource failures preserve async loop, connection and request ownership."""

from pathlib import Path
import subprocess
import sys

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def lifecycle_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    return compile_client_contract(root, tmp_path_factory.mktemp('aio-lifecycle'),
        'tests/c/aio_lifecycle_native_test.c', ('calloc', 'malloc', 'pthread_create',
            'io_engine_setup', 'io_engine_teardown', 'io_engine_arm'))


@pytest.mark.parametrize('family,mode', [
    *[('create', value) for value in ('loop-alloc', 'engine', 'thread')],
    *[('attach', value) for value in ('null-loop', 'null-session', 'signing', 'bad-fd',
                                    'attach-alloc', 'arm')],
    *[('submit', value) for value in ('command-alloc', 'payload-alloc', 'request-alloc',
                                    'dead', 'park')],
    *[('null', value) for value in ('null-connection', 'null-header', 'null-callback')],
    *[('shutdown', value) for value in ('explicit', 'implicit', 'stop-alloc')],
])
def test_async_ownership_on_refusal(lifecycle_binary, family, mode):
    result = subprocess.run([str(lifecycle_binary), family, mode],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'lifecycle ownership verified' in result.stdout

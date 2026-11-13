"""Async byte queues retain ownership across fragments, retry and TLS boundaries."""

from pathlib import Path
import subprocess
import sys

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def transport_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    return compile_client_contract(root, tmp_path_factory.mktemp('aio-transport'),
        'tests/c/aio_transport_native_test.c', ('send', 'read', 'realloc',
            'SSL_write', 'SSL_read', 'SSL_get_error', 'aconn_on_transport_error',
            'io_engine_arm', 'brix_mono_ns'))


def run_case(binary, family, mode, tls=0):
    result = subprocess.run([str(binary), family, str(mode), str(tls)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == 'async transport verified'


@pytest.mark.parametrize('mode,tls', [('success', 0), ('interrupt', 0),
    ('blocked', 0), ('fatal', 0), ('success', 1), ('want-read', 1),
    ('want-write', 1), ('fatal', 1)])
def test_write_keeps_exact_unsent_suffix(transport_binary, mode, tls):
    run_case(transport_binary, 'write', mode, tls)


@pytest.mark.parametrize('mode,tls', [('success', 0), ('interrupt', 0),
    ('fatal', 0), ('eof', 0), ('allocation', 0), ('oversize', 0),
    ('success', 1), ('want-read', 1), ('want-write', 1), ('fatal', 1), ('tls-eof', 1)])
def test_read_orders_completion_and_transport_failure(transport_binary, mode, tls):
    run_case(transport_binary, 'read', mode, tls)


@pytest.mark.parametrize('direct', [0, 1])
@pytest.mark.parametrize('split', [1, 7, 8, 9, 127, 263])
def test_fragment_boundaries_preserve_bytes(transport_binary, split, direct):
    run_case(transport_binary, 'fragment', split, direct)


@pytest.mark.parametrize('family', ['overflow', 'rtt'])
def test_capacity_and_timer_bounds(transport_binary, family):
    run_case(transport_binary, family, 'unused')


@pytest.mark.parametrize('mode', ['terminal', 'continuation', 'growth', 'landing-overflow'])
def test_accumulation_failure_cannot_report_success(transport_binary, mode):
    run_case(transport_binary, 'accumulation', mode)

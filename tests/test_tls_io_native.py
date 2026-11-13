"""TLS framing retries must preserve progress, cancellation and read deadlines."""

import errno
from pathlib import Path
import subprocess
import sys

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def tls_io(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    binary = compile_client_contract(root, tmp_path_factory.mktemp('tls-io'),
        'tests/c/tls_io_native_test.c', ('SSL_read_ex', 'SSL_write_ex', 'SSL_get_error',
        'brix_copy_quit_requested', 'brix_mono_ns', 'poll'))
    def invoke(operation, mode='', error=0, syscall_errno=0, expected=0, deadline=0, timeout=20):
        result = subprocess.run([str(binary), operation, mode, str(error), str(syscall_errno),
            str(expected), str(deadline), str(timeout)], capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
        lines = result.stdout.splitlines()
        return {key: int(value) for key, value in (part.split('=') for part in lines[0].split())}, lines[1]
    return invoke


@pytest.mark.parametrize('operation,copied', [('read', 8), ('write', 8), ('some', 3)])
def test_partial_tls_records_preserve_exact_progress(tls_io, operation, copied):
    observed, message = tls_io(operation)
    assert observed['copied'] == copied and observed['polls'] == 0 and message == ''


@pytest.mark.parametrize('operation', ['read', 'write', 'some'])
@pytest.mark.parametrize('error', [2, 3])  # OpenSSL WANT_READ / WANT_WRITE
@pytest.mark.parametrize('mode,polls', [('', 1), ('poll-intr', 2)])
def test_retryable_record_errors_wait_for_requested_direction(tls_io, operation, error, mode, polls):
    observed, _message = tls_io(operation, mode, error)
    assert observed['polls'] == polls and observed['copied'] > 0


@pytest.mark.parametrize('operation', ['read', 'write', 'some'])
@pytest.mark.parametrize('syscall_errno', [errno.EINTR, errno.EAGAIN])
def test_retryable_syscall_errors_preserve_progress(tls_io, operation, syscall_errno):
    observed, _message = tls_io(operation, error=5, syscall_errno=syscall_errno)
    assert observed['polls'] == 0 and observed['copied'] > 0


@pytest.mark.parametrize('operation', ['read', 'write', 'some'])
@pytest.mark.parametrize('mode,expected_errno', [('timeout', errno.ETIMEDOUT), ('poll-error', errno.EBADF)])
def test_readiness_failure_is_terminal(tls_io, operation, mode, expected_errno):
    observed, message = tls_io(operation, mode, error=2, expected=-1)
    assert observed['errno'] == expected_errno and observed['copied'] == 0
    assert message


@pytest.mark.parametrize('operation', ['read', 'write'])
def test_cancel_stops_before_next_tls_call(tls_io, operation):
    observed, message = tls_io(operation, 'cancel', expected=-1)
    assert observed['calls'] == observed['polls'] == 0
    assert observed['errno'] == errno.EINTR and 'cancelled' in message


@pytest.mark.parametrize('operation', ['read', 'write', 'some'])
def test_tls_protocol_errors_do_not_return_data(tls_io, operation):
    observed, message = tls_io(operation, error=1, expected=-1)
    assert observed['copied'] == 0 and 'TLS' in message


@pytest.mark.parametrize('operation', ['read', 'write'])
@pytest.mark.parametrize('syscall_errno,hint', [(0, 'unexpected EOF'), (errno.EIO, 'Input/output error')])
def test_terminal_syscall_failure_preserves_error_detail(tls_io, operation, syscall_errno, hint):
    observed, message = tls_io(operation, error=5, syscall_errno=syscall_errno, expected=-1)
    assert observed['errno'] == syscall_errno and hint in message


@pytest.mark.parametrize('error', [5, 6])  # syscall EOF / TLS close_notify
def test_stream_read_exposes_eof_as_zero_bytes(tls_io, error):
    observed, _message = tls_io('some', error=error)
    assert observed['got'] == observed['copied'] == 0


def test_framed_read_rejects_close_before_requested_length(tls_io):
    _observed, message = tls_io('read', error=6, expected=-1)
    assert 'closed by peer' in message


@pytest.mark.parametrize('mode,polls', [('deadline', 0), ('submillisecond', 0), ('deadline-after-poll', 1)])
def test_whole_read_deadline_cannot_be_extended_by_retry(tls_io, mode, polls):
    observed, message = tls_io('read', mode, error=2, expected=-1, deadline=1)
    assert observed['polls'] == polls and observed['errno'] == errno.ETIMEDOUT
    assert 'slow-drip deadline' in message


@pytest.mark.parametrize('timeout,mode', [(20, ''), (500, 'clamp'), (0, 'clamp')])
def test_poll_uses_smaller_idle_or_remaining_whole_read_budget(tls_io, timeout, mode):
    observed, _message = tls_io('read', mode, error=2, deadline=1, timeout=timeout)
    assert observed['polls'] == 1 and observed['copied'] == 8

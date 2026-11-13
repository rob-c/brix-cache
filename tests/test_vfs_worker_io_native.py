"""VFS worker progress, framing and stale-output contracts at the storage seam."""

import errno
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def worker_io(server_native_compile):
    binary = server_native_compile('vfs-worker-io', 'tests/c/vfs_worker_io_native_test.c')
    def invoke(operation, mode='', count=8, error=0, size=8):
        result = subprocess.run([str(binary), str(operation), mode, str(count), str(error), str(size)],
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stderr
    return invoke


@pytest.mark.parametrize('operation,size', [(0, 8), (1, 8), (2, 12), (4, 8)])
@pytest.mark.parametrize('mode', ['', 'intr', 'reuse'])
def test_full_io_resets_outputs_and_preserves_bytes(worker_io, operation, size, mode):
    worker_io(operation, mode, size=size)


@pytest.mark.parametrize('operation', [0, 1])
def test_short_progress_is_accumulated(worker_io, operation):
    assert 'calls=3' in worker_io(operation, 'partial')


@pytest.mark.parametrize('operation', [0, 1, 2])
@pytest.mark.parametrize('mode', ['bad-fd', 'negative', 'null-buffer'])
def test_invalid_jobs_never_reach_storage(worker_io, operation, mode):
    assert 'calls=0' in worker_io(operation, mode, -1, errno.EINVAL, 0)


@pytest.mark.parametrize('operation', [0, 2])
def test_read_capacity_is_checked_before_io(worker_io, operation):
    assert 'calls=0' in worker_io(operation, 'capacity', -1, errno.EINVAL, 0)


@pytest.mark.parametrize('operation', [0, 1, 2])
def test_empty_request_is_success_without_storage_access(worker_io, operation):
    assert 'calls=0' in worker_io(operation, 'empty', 0, 0, 0)


@pytest.mark.parametrize('operation', [0, 1, 2, 4])
def test_backend_errors_do_not_report_success(worker_io, operation):
    worker_io(operation, 'error', -1, errno.ENOSPC, 0)


@pytest.mark.parametrize('mode', ['partial-error', 'partial-zero'])
def test_partial_write_reports_progress_and_failure(worker_io, mode):
    error = errno.ENOSPC if mode == 'partial-error' else errno.EIO
    assert 'short=1' in worker_io(1, mode, 3, error, 3)


def test_partial_read_error_keeps_count_without_exposing_success(worker_io):
    worker_io(0, 'partial-error', -1, errno.ENOSPC, 3)


def test_read_eof_returns_available_bytes(worker_io):
    worker_io(0, 'partial-zero', 3, 0, 3)


@pytest.mark.parametrize('operation', [0, 1, 2, 4])
def test_zero_byte_backend_result_is_read_eof_or_failed_write(worker_io, operation):
    error = errno.EIO if operation in (1, 4) else 0
    worker_io(operation, 'zero', 0, error, 0)


@pytest.mark.parametrize('mode', ['partial-error', 'partial-zero'])
def test_vector_write_failure_identifies_segment(worker_io, mode):
    error = errno.ENOSPC if mode == 'partial-error' else errno.EIO
    assert 'seg 0' in worker_io(4, mode, 3, error, 0)


@pytest.mark.parametrize('operation,mode', [(3, 'no-segments'), (3, 'zero-segments'),
    (3, 'null-error'), (3, 'zero-error'), (4, 'no-segments'), (4, 'zero-segments')])
def test_invalid_vectors_support_absent_error_buffers(worker_io, operation, mode):
    worker_io(operation, mode, -1, errno.EINVAL, 0)


@pytest.mark.parametrize('operation', [5, 6])
@pytest.mark.parametrize('mode,error', [('', 0), ('bad-fd', errno.EINVAL), ('error', errno.EIO)])
def test_sync_and_truncate_propagate_backend_result(worker_io, operation, mode, error):
    worker_io(operation, mode, -1 if error else 0, error, 0)


def test_unknown_operation_is_rejected(worker_io):
    worker_io(99, count=-1, error=errno.EINVAL, size=0)

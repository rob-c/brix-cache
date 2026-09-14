"""Small OS workflow checks used by the platform integration harness."""

import errno
import os

import pytest


def read_published_files(file_path, iterations, errors):
    """Read complete publications and retain worker failures for pytest."""
    try:
        for _ in range(iterations):
            data = file_path.read_bytes()
            assert data == b'initial' or data.startswith(b'iteration ')
    except Exception as error:
        errors.append(f'Reader error: {error}')


def publish_files(file_path, iterations, errors):
    """Complete each write before atomically replacing the visible file."""
    try:
        for index in range(iterations):
            pending = file_path.with_suffix('.pending')
            pending.write_bytes(f'iteration {index}'.encode())
            pending.replace(file_path)
    except Exception as error:
        errors.append(f'Writer error: {error}')


def assert_disk_full_error(platform_context):
    """Exercise Linux ENOSPC without filling a filesystem or host memory."""
    if not platform_context['is_linux']:
        return
    descriptor = os.open('/dev/full', os.O_WRONLY)
    try:
        with pytest.raises(OSError) as failure:
            os.write(descriptor, b'test')
        assert failure.value.errno == errno.ENOSPC
    finally:
        os.close(descriptor)

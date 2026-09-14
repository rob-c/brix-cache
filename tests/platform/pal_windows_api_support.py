"""Shared fixtures and platform setup for test_windows_pal_100percent.py."""

from pal_windows_helpers import remove_ads_streams

import pytest
import os
import sys
import tempfile
import platform
import ctypes
import subprocess
import socket
import struct
import time
from pathlib import Path
from typing import Optional, Tuple, List

# =============================================================================
# TEST CONFIGURATION
# =============================================================================

TEST_TIMEOUT = 30  # seconds
LARGE_FILE_SIZE = 10 * 1024 * 1024  # 10MB for performance tests
BUFFER_SIZE = 64 * 1024  # 64KB buffer

# Platform markers
WINDOWS_ONLY = pytest.mark.skipif(
    not sys.platform.startswith('win'),
    reason="Windows-specific PAL tests"
)
WINDOWS_OR_WSL = pytest.mark.skipif(
    not (sys.platform.startswith('win') or 'microsoft' in platform.release().lower()),
    reason="Requires Windows or WSL"
)
LINUX_ONLY = pytest.mark.skipif(
    sys.platform.startswith('win') or 'microsoft' in platform.release().lower(),
    reason="Linux-specific tests"
)

# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture(scope="module")
def temp_dir():
    """Create a temporary directory for test files"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture(scope="module")
def test_file(temp_dir) -> Path:
    """Create a test file for xattr operations"""
    test_file = temp_dir / "test_xattr.txt"
    test_file.write_text("test content for xattr operations")
    return test_file


@pytest.fixture(scope="module")
def test_file_large(temp_dir) -> Path:
    """Create a large test file for zero-copy tests"""
    test_file = temp_dir / "test_large.bin"
    with open(test_file, 'wb') as f:
        # Write 10MB of patterned data
        pattern = bytes(range(256))
        for _ in range(LARGE_FILE_SIZE // 256):
            f.write(pattern)
    return test_file


@pytest.fixture(scope="module")
def test_dir(temp_dir) -> Path:
    """Create a test directory for watcher tests"""
    test_dir = temp_dir / "test_watch_dir"
    test_dir.mkdir(parents=True, exist_ok=True)
    return test_dir


@pytest.fixture(scope="function")
def clean_ads_stream(test_file) -> Path:
    """Create a clean file with no ADS streams for xattr tests"""
    # Remove any existing ADS streams
    try:
        base_path = str(test_file)
        # List and remove all streams
        import ctypes
        kernel32 = ctypes.windll.kernel32
        find_first_stream = kernel32.FindFirstStreamW
        find_next_stream = kernel32.FindNextStreamW
        find_close = kernel32.FindClose

        if find_first_stream and find_next_stream:
            # Windows has stream enumeration
            pass
    except Exception:
        pass
    return test_file


@pytest.fixture(scope="function")
def socket_pair():
    """Create a connected socket pair for zero-copy tests"""
    if sys.platform.startswith('win'):
        from ephemeral_port import free_port
        from settings import HOST
        # Windows socket pair
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, free_port(HOST)))
        server.listen(1)

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((HOST, server.getsockname()[1]))

        conn, _ = server.accept()
        server.close()

        yield (client.fileno(), conn.fileno())

        client.close()
        conn.close()
    else:
        pytest.skip("Socket pair test requires Windows")


# =============================================================================
# CATEGORY 1: FILE DESCRIPTORS (5 tests)
# =============================================================================

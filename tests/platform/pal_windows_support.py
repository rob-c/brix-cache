"""Shared fixtures and platform setup for test_windows.py."""

from pal_windows_helpers import assert_copyfile2_error, assert_unique_buffers, count_bytes

import pytest
import os
import sys
import tempfile
import ctypes
import socket
import time
from pathlib import Path

# Platform detection
IS_WINDOWS = sys.platform == 'win32'
IS_WSL2 = False

if IS_WINDOWS:
    try:
        # Check if running under WSL2
        with open('/proc/version', 'r') as f:
            proc_version = f.read().lower()
            IS_WSL2 = 'microsoft' in proc_version or 'wsl' in proc_version
    except:
        pass

# Windows-specific imports
if IS_WINDOWS:
    from ctypes import wintypes
    import ctypes.wintypes

    # Load Windows DLLs
    kernel32 = ctypes.windll.kernel32
    ntdll = ctypes.windll.ntdll
    bcrypt = ctypes.windll.bcrypt
    ws2_32 = ctypes.windll.ws2_32

    # Win32 constants
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    OPEN_EXISTING = 3
    FILE_FLAG_DELETE_ON_CLOSE = 0x04000000
    FILE_FLAG_RANDOM_ACCESS = 0x10000000

    # BCrypt constants
    BCRYPT_RNG_ALGORITHM = "RNG"
    BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x00000020

    # IOCP constants
    INFINITE = 0xFFFFFFFF

    # Pipe constants
    PIPE_ACCESS_DUPLEX = 0x00000003
    PIPE_TYPE_BYTE = 0x00000000
    PIPE_WAIT = 0x00000000
    PIPE_NOWAIT = 0x00000001

    # Event constants
    EVENT_MODIFY_STATE = 0x0002
    SYNCHRONIZE = 0x00100000


pytestmark = pytest.mark.skipif(not (IS_WINDOWS), reason="Requires native Windows APIs")


# =============================================================================
# PLATFORM DETECTION TESTS
# =============================================================================

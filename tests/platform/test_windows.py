"""
test_windows.py - Windows Platform Abstraction Layer Tests

Tests for the BriX-Cache PAL Windows implementation.
Covers: HANDLE/fd abstraction, eventfd emulation, file system watching,
        zero-copy transfers, cryptographic RNG, and privilege detection.

Platform Markers:
    @pytest.mark.windows - All Windows tests
    @pytest.mark.native_windows - Native Windows (not WSL2)
    @pytest.mark.wsl2 - Windows Subsystem for Linux
    @pytest.mark.server - Windows Server 2019/2022
    @pytest.mark.win10 - Windows 10/11
    @pytest.mark.admin - Requires Administrator privileges

Usage:
    # Run all Windows tests
    pytest tests/platform/test_windows.py -v

    # Run only native Windows tests
    pytest tests/platform/test_windows.py -m "native_windows" -v

    # Run only WSL2 tests
    pytest tests/platform/test_windows.py -m "wsl2" -v

    # Run server-specific tests
    pytest tests/platform/test_windows.py -m "server" -v
"""


import pytest
import sys

pytest.register_assert_rewrite(
    "pal_cases_windows_io",
    "pal_cases_windows_system",
)

from pal_windows_support import (
    pytestmark,
)

from pal_cases_windows_io import (
    TestPlatformDetection,
    TestHandleFdAbstraction,
    TestEventfdEmulation,
    TestFileSystemWatcher,
)

from pal_cases_windows_system import (
    TestZeroCopyTransfers,
    TestCryptographicRNG,
    TestWSL2vsNative,
    TestAdministratorPrivileges,
)

if __name__ == '__main__':
    # Run tests with pytest
    pytest.main([__file__, '-v', '--tb=short'])

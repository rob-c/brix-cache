"""Shared fixtures and platform setup for test_phase3_integration.py."""

from pal_integration_helpers import (normalize_platform, normalize_architecture,
    check_and_remove_user_xattrs, print_coverage_summary)

import os
import sys
import platform
import tempfile
import shutil
import time
import ctypes
import subprocess
import json
import hashlib
import threading
import multiprocessing
from pathlib import Path
from typing import Optional, Tuple, Dict, List, Any
from dataclasses import dataclass
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest

from pal_workflow_helpers import (assert_disk_full_error, publish_files,
                                  read_published_files)

# =============================================================================
# Test Configuration
# =============================================================================

TEST_TIMEOUT = 60  # seconds for integration tests
PERFORMANCE_THRESHOLD = 0.1  # 10% regression tolerance
LARGE_FILE_SIZE = 10 * 1024 * 1024  # 10MB for performance tests
SMALL_FILE_SIZE = 1024  # 1KB for functional tests
BUFFER_SIZE = 64 * 1024  # 64KB for copy operations

# Platform markers
WINDOWS_ONLY = pytest.mark.skipif(
    not (sys.platform.startswith('win') or sys.platform == 'win32'),
    reason="Windows-specific test"
)
LINUX_ONLY = pytest.mark.skipif(
    platform.system() != "Linux",
    reason="Linux-specific test"
)
MACOS_ONLY = pytest.mark.skipif(
    platform.system() != "Darwin",
    reason="macOS-specific test"
)
ARM64_ONLY = pytest.mark.skipif(
    platform.machine() not in ("aarch64", "arm64", "ARM64"),
    reason="ARM64-specific test"
)
X86_64_ONLY = pytest.mark.skipif(
    platform.machine() not in ("x86_64", "AMD64"),
    reason="x86_64-specific test"
)
PERFORMANCE_TEST = pytest.mark.slow
REQUIRES_ROOT = pytest.mark.requires_root


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class PALFunctionStatus:
    """Track PAL function test status"""
    name: str
    category: str
    tested: bool = False
    passed: bool = False
    skipped: bool = False
    error: Optional[str] = None
    duration_ms: float = 0.0
    platform: str = ""


@dataclass
class PerformanceMetrics:
    """Performance test metrics"""
    operation: str
    throughput_mbps: float
    latency_ms: float
    iops: int
    cpu_usage_percent: float
    memory_usage_mb: float
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat()


@dataclass
class IntegrationTestResult:
    """Complete integration test result"""
    test_name: str
    platform: str
    architecture: str
    passed: bool
    duration_ms: float
    pal_functions_tested: List[str]
    performance_metrics: Optional[PerformanceMetrics] = None
    errors: List[str] = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture(scope="session")
def platform_context():
    """Provide comprehensive platform context"""
    system = platform.system().lower()
    machine = platform.machine().lower()

    plat_name = normalize_platform(system)

    arch = normalize_architecture(machine)

    return {
        "system": system,
        "release": platform.release(),
        "version": platform.version(),
        "machine": machine,
        "processor": platform.processor(),
        "python_version": platform.python_version(),
        "platform": plat_name,
        "architecture": arch,
        "is_linux": plat_name == "linux",
        "is_darwin": plat_name == "darwin",
        "is_windows": plat_name == "windows",
        "is_x86_64": arch == "x86_64",
        "is_arm64": arch == "arm64",
        "is_arm64_linux": (plat_name, arch) == ("linux", "arm64"),
        "is_arm64_macos": (plat_name, arch) == ("darwin", "arm64"),
        "is_windows_x86_64": (plat_name, arch) == ("windows", "x86_64"),
    }


@pytest.fixture
def temp_workspace(platform_context):
    """Create a temporary workspace for integration tests"""
    workspace = tempfile.mkdtemp(prefix=f"brix_phase3_{platform_context['platform']}_")
    yield Path(workspace)
    shutil.rmtree(workspace, ignore_errors=True)


@pytest.fixture
def test_files(temp_workspace):
    """Create test files of various sizes"""
    files = {}

    # Small file (1KB)
    small_file = temp_workspace / "small_test.bin"
    small_file.write_bytes(os.urandom(SMALL_FILE_SIZE))
    files['small'] = small_file

    # Large file (10MB) for performance tests
    large_file = temp_workspace / "large_test.bin"
    with open(large_file, 'wb') as f:
        # Write in chunks to avoid memory issues
        for _ in range(LARGE_FILE_SIZE // BUFFER_SIZE):
            f.write(os.urandom(BUFFER_SIZE))
    files['large'] = large_file

    # Text file for xattr tests
    text_file = temp_workspace / "text_test.txt"
    text_file.write_text("Integration test content for xattr operations")
    files['text'] = text_file

    # Directory for file operations
    test_dir = temp_workspace / "test_directory"
    test_dir.mkdir()
    files['dir'] = test_dir

    return files


@pytest.fixture
def pal_functions_list():
    """Return complete list of all 42 PAL functions by category"""
    return {
        'file_descriptor': [
            'brix_plat_open',
            'brix_plat_close',
            'brix_plat_read',
            'brix_plat_write',
            'brix_plat_lseek',
        ],
        'event_notification': [
            'brix_plat_eventfd',
            'brix_plat_epoll',
        ],
        'filesystem_watcher': [
            'brix_plat_fs_watch_init',
            'brix_plat_fs_watch_add',
            'brix_plat_fs_watch_remove',
            'brix_plat_fs_watch_poll',
            'brix_plat_fs_watch_cleanup',
        ],
        'random': [
            'brix_plat_random',
        ],
        'xattr': [
            'brix_plat_getxattr',
            'brix_plat_fgetxattr',
            'brix_plat_setxattr',
            'brix_plat_fsetxattr',
            'brix_plat_removexattr',
            'brix_plat_fremovexattr',
            'brix_plat_listxattr',
            'brix_plat_flistxattr',
        ],
        'process_execution': [
            'brix_plat_execvpe',
        ],
        'byte_order': [
            'brix_plat_htobe64',
            'brix_plat_be64toh',
            'brix_plat_htobe32',
            'brix_plat_be32toh',
            'brix_plat_htobe16',
            'brix_plat_be16toh',
        ],
        'zero_copy': [
            'brix_plat_sendfile',
            'brix_plat_splice',
            'brix_plat_copy_range',
        ],
        'platform_detection': [
            'brix_plat_name',
            'brix_plat_version',
            'brix_plat_arch',
            'brix_plat_is_root',
            'brix_plat_cpu_count',
            'brix_plat_total_memory',
            'brix_plat_available_memory',
        ],
        'security': [
            'brix_plat_security_init',
            'brix_plat_security_enter',
            'brix_plat_setfsuid',
            'brix_plat_setfsgid',
        ],
        'initialization': [
            'brix_plat_init',
            'brix_plat_cleanup',
        ],
    }


# =============================================================================
# PAL Function Tests - All 42 Functions
# =============================================================================

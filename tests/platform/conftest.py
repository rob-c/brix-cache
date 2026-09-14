"""
tests/platform/conftest.py - Pytest configuration and fixtures for PAL testing

Provides:
- Platform detection fixtures
- Temporary file/directory fixtures
- PAL API loading and initialization
- Coverage reporting hooks
- Platform-specific markers
"""

import os
import sys
import platform
import tempfile
import shutil
import pytest
from pathlib import Path

# Add tests directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from test_platform_linux_native import native_compile  # configured C SDK fixture
from pal_native import anon_fd, pal_native  # production C bindings

# =============================================================================
# Platform Detection
# =============================================================================

@pytest.fixture(scope="session")
def platform_info():
    """Return detailed platform information"""
    return {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
        "is_linux": platform.system() == "Linux",
        "is_darwin": platform.system() == "Darwin",
        "is_windows": platform.system() == "Windows",
        "is_x86_64": platform.machine() in ("x86_64", "AMD64"),
        "is_arm64": platform.machine() in ("aarch64", "ARM64", "arm64"),
    }


@pytest.fixture(scope="session")
def platform_name(platform_info):
    """Return platform name string"""
    if platform_info["is_linux"]:
        return "linux"
    elif platform_info["is_darwin"]:
        return "darwin"
    elif platform_info["is_windows"]:
        return "windows"
    else:
        return "unknown"


@pytest.fixture(scope="session")
def arch_name(platform_info):
    """Return architecture name string"""
    if platform_info["is_x86_64"]:
        return "x86_64"
    elif platform_info["is_arm64"]:
        return "arm64"
    else:
        return platform_info["machine"]


# =============================================================================
# Temporary File/Directory Fixtures
# =============================================================================

@pytest.fixture
def temp_dir():
    """Create a temporary directory, clean up after test"""
    dirpath = tempfile.mkdtemp(prefix="brix_pal_test_")
    yield Path(dirpath)
    shutil.rmtree(dirpath, ignore_errors=True)


@pytest.fixture
def temp_file(temp_dir):
    """Create a temporary file, clean up after test"""
    filepath = temp_dir / "test_file.txt"
    filepath.write_text("test content for PAL testing")
    yield filepath


@pytest.fixture
def temp_binary_file(temp_dir):
    """Create a temporary binary file, clean up after test"""
    filepath = temp_dir / "test_file.bin"
    filepath.write_bytes(bytes(range(256)))
    yield filepath


# =============================================================================
# PAL API Loading
# =============================================================================

@pytest.fixture(scope="session")
def pal_lib(platform_name):
    """
    Load the PAL library for testing.
    
    This fixture attempts to load the compiled PAL library.
    For now, we test the Python implementation.
    In the future, this can load the C library via ctypes/cffi.
    """
    # For Python-based testing, import the test helpers
    try:
        from pal_test_helpers import PALTestHelpers
        helpers = PALTestHelpers()
        yield helpers
    except ImportError:
        # Fallback: use subprocess to call test binaries
        yield None


@pytest.fixture(scope="session")
def pal_initialized(pal_lib):
    """Ensure PAL is initialized before running tests"""
    if pal_lib:
        result = pal_lib.init()
        assert result == 0, "PAL initialization failed"
    yield
    if pal_lib:
        pal_lib.cleanup()


# =============================================================================
# Test Data
# =============================================================================

@pytest.fixture
def test_data():
    """Provide test data for various PAL functions"""
    return {
        "byte_order_values": [
            0x0000000000000001,
            0x000000000000FFFF,
            0x00000000FFFFFFFF,
            0x000000FFFFFFFFFFFF,
            0x0000FFFFFFFFFFFFFF,
            0x00FFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0x123456789ABCDEF0,
        ],
        "random_size": 1024,
        "xattr_name": "user.brix_test",
        "xattr_value": b"test attribute value",
        "anon_fd_name": "brix_test_anon",
    }


# =============================================================================
# Pytest Markers Configuration
# =============================================================================

def pytest_configure(config):
    """Register platform markers for both nested and repository collection."""
    platform_markers = {
        "arm64_linux": "ARM64 Linux platform",
        "arm64_macos": "ARM64 macOS platform",
        "apple_silicon": "Apple Silicon platform",
        "m1": "Apple M1 hardware", "m2": "Apple M2 hardware",
        "m3": "Apple M3 hardware", "accelerate": "Apple Accelerate framework",
        "clonefile": "APFS clonefile support", "crc32": "hardware CRC32",
        "neon": "ARM NEON support", "sve": "ARM SVE support",
        "graviton": "AWS Graviton hardware", "ampere": "Ampere hardware",
        "native_windows": "native Windows platform", "wsl2": "WSL2 platform",
        "server": "Windows Server platform", "win10": "Windows 10 or later",
        "admin": "Windows administrator privileges",
    }
    for marker, description in platform_markers.items():
        config.addinivalue_line("markers", f"{marker}: {description}")
    config.addinivalue_line(
        "markers",
        "linux: mark test to run only on Linux"
    )
    config.addinivalue_line(
        "markers",
        "darwin: mark test to run only on macOS"
    )
    config.addinivalue_line(
        "markers",
        "windows: mark test to run only on Windows"
    )
    config.addinivalue_line(
        "markers",
        "x86_64: mark test to run only on x86_64"
    )
    config.addinivalue_line(
        "markers",
        "arm64: mark test to run only on ARM64"
    )
    config.addinivalue_line(
        "markers",
        "slow: mark test as slow (for CI exclusion)"
    )
    config.addinivalue_line(
        "markers",
        "requires_root: mark test as requiring root privileges"
    )
    config.addinivalue_line(
        "markers",
        "pal_function(name): mark test with PAL function name for coverage"
    )


# =============================================================================
# Coverage Reporting
# =============================================================================

class PALCoverageReporter:
    """Track PAL function coverage"""
    
    def __init__(self):
        self.covered_functions = set()
        self.total_functions = set()
        self.test_results = {}
    
    def record_function(self, func_name):
        """Record that a function was tested"""
        self.covered_functions.add(func_name)
    
    def record_result(self, func_name, test_name, passed, details=None):
        """Record test result for a function"""
        if func_name not in self.test_results:
            self.test_results[func_name] = []
        self.test_results[func_name].append({
            "test": test_name,
            "passed": passed,
            "details": details
        })
    
    def get_coverage_report(self):
        """Generate coverage report"""
        total = len(self.total_functions)
        covered = len(self.covered_functions)
        percentage = (covered / total * 100) if total > 0 else 0
        
        return {
            "total_functions": total,
            "covered_functions": covered,
            "percentage": percentage,
            "uncovered": list(self.total_functions - self.covered_functions),
            "results": self.test_results
        }


@pytest.fixture(scope="session")
def coverage_reporter():
    """Provide coverage reporter instance"""
    reporter = PALCoverageReporter()
    yield reporter
    # Print coverage summary at end
    print("\n" + "="*70)
    print("PAL FUNCTION COVERAGE SUMMARY")
    print("="*70)
    report = reporter.get_coverage_report()
    print(f"Total Functions: {report['total_functions']}")
    print(f"Covered: {report['covered_functions']}")
    print(f"Coverage: {report['percentage']:.1f}%")
    if report['uncovered']:
        print(f"\nUncovered Functions:")
        for func in sorted(report['uncovered']):
            print(f"  - {func}")
    print("="*70)


# =============================================================================
# Helper Functions
# =============================================================================

def skip_if_not_platform(request, platform_name):
    """Skip test if not running on specified platform"""
    current = platform.system().lower()
    if current != platform_name.lower():
        pytest.skip(f"Test requires {platform_name}, running on {current}")


def skip_if_not_arch(request, arch):
    """Skip test if not running on specified architecture"""
    current = platform.machine().lower()
    if current != arch.lower():
        pytest.skip(f"Test requires {arch}, running on {current}")


# Export helpers
__all__ = [
    'skip_if_not_platform',
    'skip_if_not_arch',
    'PALCoverageReporter',
]

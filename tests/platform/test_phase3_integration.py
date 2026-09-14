#!/usr/bin/env python3
"""
tests/platform/test_phase3_integration.py - Phase 3 Master Integration Test Suite

Comprehensive integration tests for complete PAL workflow across all 5 platforms:
- Linux x86_64
- Linux ARM64
- macOS x86_64
- macOS ARM64
- Windows x86_64

Tests all 42 Windows PAL functions in integration scenarios with:
- Cross-platform compatibility verification
- Complete PAL workflow testing
- Performance regression checks
- Error handling validation
- Security boundary testing

Run with:
    python3 -m pytest tests/platform/test_phase3_integration.py -v --tb=short

For specific platforms:
    python3 -m pytest tests/platform/test_phase3_integration.py -v -m "windows"
    python3 -m pytest tests/platform/test_phase3_integration.py -v -m "linux"
    python3 -m pytest tests/platform/test_phase3_integration.py -v -m "darwin"
    python3 -m pytest tests/platform/test_phase3_integration.py -v -m "arm64"

Performance tests (slow):
    python3 -m pytest tests/platform/test_phase3_integration.py -v -m "performance"

Coverage report:
    python3 -m pytest tests/platform/test_phase3_integration.py -v --cov=src/platform

Platform: All (Linux x86_64/ARM64, macOS x86_64/ARM64, Windows x86_64)
Minimum: pytest 7.0+, Python 3.8+
Author: BriX-Cache Development Team
Phase: 3 - Final Integration & Validation
"""


import pytest
import sys

pytest.register_assert_rewrite(
    "pal_cases_integration_io",
    "pal_cases_integration_system",
    "pal_cases_integration_workflows",
)

from pal_integration_support import (
    IntegrationTestResult,
    PALFunctionStatus,
    PerformanceMetrics,
    pal_functions_list,
    platform_context,
    temp_workspace,
    test_files,
)

from pal_cases_integration_io import (
    TestPALFileDescriptor,
    TestPALEventNotification,
    TestPALFilesystemWatcher,
    TestPALRandom,
    TestPALXattr,
    TestPALProcessExecution,
)

from pal_cases_integration_system import (
    TestPALByteOrder,
    TestPALZeroCopy,
    TestPALPlatformDetection,
    TestPALSecurity,
    TestPALInitialization,
)

from pal_cases_integration_workflows import (
    TestCrossPlatformCompatibility,
    TestPerformanceRegression,
    TestCompletePALWorkflow,
    TestPALSummary,
)

if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "-ra",
        "--color=yes",
    ])

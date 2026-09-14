#!/usr/bin/env python3
"""
Test suite for detect_platform_features.py

Run with: python3 -m pytest tools/ci/test_detect_platform.py -v
Or: python3 tools/ci/test_detect_platform.py
"""

import json
import os
import subprocess
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from detect_platform_features import (
    detect_platform,
    detect_architecture,
    detect_compiler_support,
    detect_optimization_flags,
    detect_runtime_info,
)


def test_detect_platform():
    """Test platform detection."""
    result = detect_platform()
    
    # Required fields
    assert "name" in result
    assert result["name"] in ["linux", "darwin", "windows"]
    assert "system" in result
    assert "release" in result
    assert "machine" in result
    
    # Platform-specific fields
    if result["name"] == "linux":
        assert "linux_distro" in result
    elif result["name"] == "darwin":
        assert "macos" in result
        if result["macos"]:
            assert "version" in result["macos"]
    
    print(f"✓ Platform: {result['name']} ({result['release']})")
    return True


def test_detect_architecture():
    """Test architecture detection."""
    result = detect_architecture()
    
    # Required fields
    assert "raw" in result
    assert "normalized" in result
    assert "family" in result
    assert "features" in result
    
    # Valid architecture families
    assert result["family"] in ["x86_64", "arm64", "arm", "riscv", "unknown"]
    
    # Features should be a dict
    assert isinstance(result["features"], dict)
    
    # Architecture-specific feature checks
    if result["family"] == "x86_64":
        assert "has_sse" in result["features"]
        assert "has_avx2" in result["features"]
    elif result["family"] == "arm64":
        assert "has_neon" in result["features"]
        assert "is_apple_silicon" in result["features"]
    
    print(f"✓ Architecture: {result['normalized']} ({result['family']})")
    return True


def _assert_compiler_capabilities(result):
    """A capability must belong to a recognized compiler."""
    if result["name"]:
        assert result["name"] in ["gcc", "clang", "apple-clang"]
    if result["supports_lto"]:
        assert result["name"] is not None


def test_detect_compiler_support():
    """Test compiler detection."""
    result = detect_compiler_support()
    
    # Required fields
    assert "name" in result
    assert "version" in result or result["name"] is None
    assert "supports_lto" in result
    assert "supports_pgo" in result
    _assert_compiler_capabilities(result)
    
    print(f"✓ Compiler: {result['name']} {result['version'] or 'unknown'}")
    return True


def test_detect_optimization_flags():
    """Test optimization flag detection."""
    result = detect_optimization_flags()
    
    # Required fields
    assert "march" in result
    assert "mtune" in result
    assert "cpu_features" in result
    assert "frameworks" in result
    assert "ldflags" in result
    
    # All should be lists
    assert isinstance(result["march"], list)
    assert isinstance(result["mtune"], list)
    assert isinstance(result["cpu_features"], list)
    assert isinstance(result["frameworks"], list)
    assert isinstance(result["ldflags"], list)
    
    # Empty lists are valid; every supplied flag must have the correct prefix.
    assert all(flag.startswith("-march=") for flag in result["march"])
    assert all(flag.startswith("-mtune=") for flag in result["mtune"])
    
    print(f"✓ Optimization flags: {' '.join(result['march'])}")
    return True


def test_detect_runtime_info():
    """Test runtime information detection."""
    result = detect_runtime_info()
    
    # Required fields
    assert "python_version" in result
    assert "is_ci" in result
    assert "ci_provider" in result
    assert "cpu_count" in result
    assert "total_memory_mb" in result or result["total_memory_mb"] is None
    
    # Type checks
    assert isinstance(result["python_version"], str)
    assert isinstance(result["is_ci"], bool)
    assert isinstance(result["cpu_count"], int)
    assert result["cpu_count"] > 0
    
    # CI provider should be None or a known value
    if result["ci_provider"]:
        assert result["ci_provider"] in [
            "github-actions",
            "gitlab-ci",
            "travis",
            "circleci",
            "jenkins",
        ]
    
    print(f"✓ Runtime: Python {result['python_version']}, {result['cpu_count']} CPUs")
    return True


def test_script_execution():
    """Test that the script runs and produces valid JSON."""
    script_path = Path(__file__).parent / "detect_platform_features.py"
    
    result = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    
    assert result.returncode == 0, f"Script failed: {result.stderr}"
    
    # Parse JSON output
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise AssertionError(f"Invalid JSON output: {e}")
    
    # Check required top-level keys
    required_keys = [
        "platform",
        "architecture",
        "compiler",
        "optimization_flags",
        "runtime",
        "recommendations",
        "metadata",
    ]
    
    for key in required_keys:
        assert key in data, f"Missing required key: {key}"
    
    print("✓ Script execution and JSON output valid")
    return True


def test_ci_format_output():
    """Test CI format output."""
    script_path = Path(__file__).parent / "detect_platform_features.py"
    
    result = subprocess.run(
        [sys.executable, str(script_path), "--ci-format"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    
    assert result.returncode == 0, f"Script failed: {result.stderr}"
    
    # Check output format (key=value pairs)
    lines = result.stdout.strip().split("\n")
    assert len(lines) >= 5, "CI format should have multiple key=value lines"
    
    for line in lines:
        assert "=" in line, f"Invalid CI format line: {line}"
        key, value = line.split("=", 1)
        assert key.strip(), f"Empty key in line: {line}"
        
        # Value should be valid JSON
        try:
            json.loads(value)
        except json.JSONDecodeError as e:
            raise AssertionError(f"Invalid JSON in CI format value for {key}: {e}")
    
    print("✓ CI format output valid")
    return True


def test_recommendations_structure():
    """Test that recommendations have correct structure."""
    result = subprocess.run(
        [sys.executable, str(Path(__file__).parent / "detect_platform_features.py")],
        capture_output=True,
        text=True,
        timeout=30,
    )
    
    data = json.loads(result.stdout)
    recommendations = data["recommendations"]
    
    # Required fields
    assert "platform_flags" in recommendations
    assert "optimization_level" in recommendations
    assert "enable_lto" in recommendations
    
    # platform_flags should be a dict
    assert isinstance(recommendations["platform_flags"], dict)
    
    # optimization_level should be a valid gcc/clang flag
    assert recommendations["optimization_level"].startswith("-O")
    
    # enable_lto should be False, "thin", or "full"
    assert recommendations["enable_lto"] in [True, False, "thin", "full"]
    
    print("✓ Recommendations structure valid")
    return True


def test_metadata():
    """Test metadata field."""
    result = subprocess.run(
        [sys.executable, str(Path(__file__).parent / "detect_platform_features.py")],
        capture_output=True,
        text=True,
        timeout=30,
    )
    
    data = json.loads(result.stdout)
    metadata = data["metadata"]
    
    # Required fields
    assert "script" in metadata
    assert "version" in metadata
    
    # Script name should be correct
    assert metadata["script"] == "detect_platform_features.py"
    
    print(f"✓ Metadata: {metadata['script']} v{metadata['version']}")
    return True


def run_all_tests():
    """Run all tests and report results."""
    tests = [
        test_detect_platform,
        test_detect_architecture,
        test_detect_compiler_support,
        test_detect_optimization_flags,
        test_detect_runtime_info,
        test_script_execution,
        test_ci_format_output,
        test_recommendations_structure,
        test_metadata,
    ]
    
    passed = 0
    failed = 0
    
    print("=" * 60)
    print("Running detect_platform_features.py test suite")
    print("=" * 60)
    print()
    
    for test_func in tests:
        try:
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"✗ {test_func.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"✗ {test_func.__name__}: Unexpected error: {e}")
            failed += 1
    
    print()
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)

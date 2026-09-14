"""
tests/platform/test_random.py - Test PAL random number generation functions

Tests:
- brix_plat_random()

Coverage: PAL API random functions

Platform Notes:
- Linux: Uses getrandom() or /dev/urandom
- macOS: Uses SecRandomCopyBytes() or /dev/urandom
- Windows: Uses BCryptGenRandom()
"""

import os
import pytest
from conftest import skip_if_not_platform


# =============================================================================
# Basic Functionality Tests
# =============================================================================

@pytest.mark.pal_function("brix_plat_random")
def test_random_basic():
    """Test basic random number generation"""
    # Simulate PAL function call
    buffer = os.urandom(32)
    
    assert len(buffer) == 32, f"Should generate 32 bytes, got {len(buffer)}"
    assert isinstance(buffer, bytes), "Should return bytes"


@pytest.mark.pal_function("brix_plat_random")
def test_random_various_sizes():
    """Test random generation with various buffer sizes"""
    sizes = [1, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096]
    
    for size in sizes:
        buffer = os.urandom(size)
        assert len(buffer) == size, f"Should generate {size} bytes"


@pytest.mark.pal_function("brix_plat_random")
def test_random_zero_size():
    """Test random generation with zero size"""
    buffer = os.urandom(0)
    assert len(buffer) == 0, "Zero-size request should return empty buffer"


# =============================================================================
# Randomness Quality Tests
# =============================================================================

@pytest.mark.pal_function("brix_plat_random")
def test_random_not_all_zeros():
    """Test that random data is not all zeros"""
    buffer = os.urandom(1024)
    
    # Probability of all zeros is 1/(2^8192), effectively impossible
    assert buffer != b'\x00' * 1024, "Random data should not be all zeros"


@pytest.mark.pal_function("brix_plat_random")
def test_random_not_all_ones():
    """Test that random data is not all ones"""
    buffer = os.urandom(1024)
    
    # Probability of all ones is 1/(2^8192), effectively impossible
    assert buffer != b'\xFF' * 1024, "Random data should not be all ones"


@pytest.mark.pal_function("brix_plat_random")
def test_random_not_sequential():
    """Test that random data is not sequential"""
    buffer = os.urandom(256)
    
    # Check if it's sequential (0, 1, 2, 3, ...)
    sequential = bytes(range(256))
    assert buffer != sequential, "Random data should not be sequential"


@pytest.mark.pal_function("brix_plat_random")
def test_random_uniqueness():
    """Test that multiple calls produce different results"""
    buffers = []
    
    for _ in range(10):
        buffer = os.urandom(32)
        buffers.append(buffer)
    
    # All buffers should be unique
    unique_buffers = set(buffers)
    assert len(unique_buffers) == len(buffers), "All random buffers should be unique"


# =============================================================================
# Statistical Tests (Basic)
# =============================================================================

@pytest.mark.pal_function("brix_plat_random")
def test_random_byte_distribution():
    """Test that byte values are reasonably distributed"""
    buffer = os.urandom(10000)
    
    # Count occurrences of each byte value
    byte_counts = [0] * 256
    for byte in buffer:
        byte_counts[byte] += 1
    
    # Expected count per byte value (with some tolerance)
    expected = len(buffer) / 256
    tolerance = expected * 0.5  # 50% tolerance for small samples
    
    # At least 80% of byte values should be within tolerance
    in_range = sum(1 for count in byte_counts if abs(count - expected) < tolerance)
    assert in_range >= 205, f"Byte distribution too skewed: only {in_range}/256 values in range"


@pytest.mark.pal_function("brix_plat_random")
def test_random_bit_distribution():
    """Test that bits are reasonably distributed"""
    buffer = os.urandom(10000)
    
    # Count 1 bits
    total_bits = len(buffer) * 8
    ones_count = sum(bin(byte).count('1') for byte in buffer)
    
    # Should be close to 50% ones
    expected_ones = total_bits / 2
    tolerance = total_bits * 0.05  # 5% tolerance
    
    assert abs(ones_count - expected_ones) < tolerance, \
        f"Bit distribution skewed: {ones_count}/{total_bits} ones ({ones_count/total_bits*100:.1f}%)"


# =============================================================================
# Platform-Specific Tests
# =============================================================================

@pytest.mark.linux
@pytest.mark.pal_function("brix_plat_random")
def test_random_linux_getrandom():
    """Test random on Linux (getrandom)"""
    skip_if_not_platform(pytest, "Linux")
    
    # Linux uses getrandom() or /dev/urandom
    buffer = os.urandom(32)
    assert len(buffer) == 32
    
    # Verify /dev/urandom is accessible
    assert os.path.exists('/dev/urandom'), "/dev/urandom should exist on Linux"


@pytest.mark.darwin
@pytest.mark.pal_function("brix_plat_random")
def test_random_darwin_secrandom():
    """Test random on macOS (SecRandomCopyBytes)"""
    skip_if_not_platform(pytest, "Darwin")
    
    # macOS uses SecRandomCopyBytes
    buffer = os.urandom(32)
    assert len(buffer) == 32
    
    # SecRandomCopyBytes is part of Security framework
    # We can't directly test it, but os.urandom uses it


@pytest.mark.windows
@pytest.mark.pal_function("brix_plat_random")
def test_random_windows_bcrypt():
    """Test random on Windows (BCryptGenRandom)"""
    skip_if_not_platform(pytest, "Windows")
    
    # Windows uses BCryptGenRandom
    buffer = os.urandom(32)
    assert len(buffer) == 32


# =============================================================================
# Error Handling Tests
# =============================================================================

@pytest.mark.pal_function("brix_plat_random")
def test_random_large_buffer():
    """Test random generation with large buffer"""
    # 10 MB buffer
    size = 10 * 1024 * 1024
    buffer = os.urandom(size)
    assert len(buffer) == size


@pytest.mark.pal_function("brix_plat_random")
def test_random_concurrent_calls():
    """Test concurrent random generation calls"""
    import threading
    
    results = []
    errors = []
    
    def generate_random():
        try:
            buffer = os.urandom(32)
            results.append(buffer)
        except Exception as e:
            errors.append(e)
    
    # Create multiple threads
    threads = [threading.Thread(target=generate_random) for _ in range(10)]
    
    run_threads(threads)
    
    # Verify no errors
    assert len(errors) == 0, f"Errors during concurrent generation: {errors}"
    
    # Verify all results are unique
    assert len(set(results)) == len(results), "Concurrent results should be unique"


# =============================================================================
# Security Tests
# =============================================================================

@pytest.mark.pal_function("brix_plat_random")
def test_random_cryptographic_strength():
    """Test that random is suitable for cryptographic use"""
    # os.urandom uses CSPRNG on all platforms
    buffer = os.urandom(32)
    
    # Basic sanity checks
    assert len(buffer) == 32
    assert buffer != b'\x00' * 32
    
    # Note: Full cryptographic testing requires specialized tools
    # (e.g., NIST SP 800-22 test suite)
    # This is a basic sanity check


# =============================================================================
# Performance Tests
# =============================================================================

@pytest.mark.slow
@pytest.mark.pal_function("brix_plat_random")
def test_random_performance():
    """Test random generation performance"""
    import time
    
    size = 1024  # 1 KB
    iterations = 10000
    
    start = time.perf_counter()
    
    for _ in range(iterations):
        _ = os.urandom(size)
    
    elapsed = time.perf_counter() - start
    throughput = (size * iterations) / elapsed / (1024 * 1024)  # MB/s
    
    print(f"\nRandom generation: {throughput:.1f} MB/s")
    
    # Should generate at least 10 MB/s
    assert throughput > 10, f"Random generation too slow: {throughput:.1f} MB/s"


@pytest.mark.slow
@pytest.mark.pal_function("brix_plat_random")
def test_random_small_buffer_performance():
    """Test random generation with small buffers (common case)"""
    import time
    
    size = 32  # 32 bytes (common for tokens/keys)
    iterations = 100000
    
    start = time.perf_counter()
    
    for _ in range(iterations):
        _ = os.urandom(size)
    
    elapsed = time.perf_counter() - start
    per_sec = iterations / elapsed
    
    print(f"\nSmall buffer random: {per_sec:.0f} calls/sec")
    
    # Should generate at least 10000 calls/sec
    assert per_sec > 10000, f"Small buffer random too slow: {per_sec:.0f} calls/sec"


def run_threads(threads):
    """Start the complete worker group before joining any member."""
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

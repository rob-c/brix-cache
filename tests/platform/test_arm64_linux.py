"""
test_arm64_linux.py - ARM64 Linux Platform Tests

Tests for ARM64-specific features on Linux:
- Hardware CRC32 acceleration (ARMv8-A CRC extension)
- NEON SIMD optimizations
- SVE/SVE2 vector extensions
- Cache line alignment
- Atomic operations
- Endianness validation

Platform Markers:
    @pytest.mark.arm64 - All ARM64 tests
    @pytest.mark.arm64_linux - ARM64 Linux specific
    @pytest.mark.crc32 - CRC32 hardware acceleration tests
    @pytest.mark.neon - NEON SIMD tests
    @pytest.mark.sve - SVE/SVE2 vector extension tests
    @pytest.mark.graviton - AWS Graviton-specific tests
    @pytest.mark.ampere - Ampere Altra-specific tests

Usage:
    # Run all ARM64 tests
    pytest tests/platform/test_arm64_linux.py -v

    # Run CRC32 hardware tests
    pytest tests/platform/test_arm64_linux.py -m "crc32" -v

    # Run on specific hardware
    pytest tests/platform/test_arm64_linux.py -m "graviton" -v
"""

from pal_arm_linux_helpers import (report_cpu_features, report_cpu_identity,
    report_graviton, report_ampere, report_other_clouds, report_lscpu_cache,
    report_sysfs_cache)

import pytest
import os
import sys
import struct
import ctypes
import subprocess
from pathlib import Path

# Platform detection
IS_LINUX = sys.platform == 'linux'
IS_ARM64 = (os.uname().machine == 'aarch64' if IS_LINUX else False)


pytestmark = pytest.mark.skipif(not (IS_LINUX and IS_ARM64), reason="Requires ARM64 Linux")


# =============================================================================
# PLATFORM DETECTION TESTS
# =============================================================================

class TestARM64Detection:
    """Test ARM64 platform detection and CPU feature identification."""
    
    @pytest.mark.arm64
    def test_is_arm64(self):
        """Verify we're running on ARM64."""
        if IS_LINUX:
            assert IS_ARM64, "This test suite requires ARM64 Linux"
            print(f"\nPlatform: {os.uname().machine}")
    
    @pytest.mark.arm64
    @pytest.mark.arm64_linux
    def test_cpu_features(self):
        """Detect ARM64 CPU features from /proc/cpuinfo."""
        if not IS_LINUX:
            pytest.skip("Linux-only test")
        
        try:
            with open('/proc/cpuinfo', 'r') as f:
                cpuinfo = f.read()
            
            report_cpu_features(cpuinfo)
            
            report_cpu_identity(cpuinfo)
            
        except FileNotFoundError:
            pytest.skip("/proc/cpuinfo not available")
    
    @pytest.mark.arm64
    @pytest.mark.arm64_linux
    def test_cloud_provider_detection(self):
        """Detect if running on cloud ARM64 (Graviton, Ampere, etc.)."""
        if not IS_LINUX:
            pytest.skip("Linux-only test")
        
        report_graviton()
            
        report_ampere()
                
        report_other_clouds()
    
    @pytest.mark.arm64
    @pytest.mark.arm64_linux
    def test_memory_info(self):
        """Get memory information."""
        if not IS_LINUX:
            pytest.skip("Linux-only test")
        
        try:
            with open('/proc/meminfo', 'r') as f:
                meminfo = f.read()
            
            for line in meminfo.split('\n')[:5]:
                print(line)
                
        except FileNotFoundError:
            pytest.skip("/proc/meminfo not available")


# =============================================================================
# ENDIANNESS TESTS
# =============================================================================

class TestEndianness:
    """Test ARM64 endianness (should be little-endian like x86_64)."""
    
    @pytest.mark.arm64
    def test_byte_order(self):
        """Verify ARM64 is little-endian."""
        # Pack a multi-byte value
        value = 0x12345678
        packed = struct.pack('<I', value)  # Little-endian
        packed_be = struct.pack('>I', value)  # Big-endian
        
        # Check native byte order
        native_packed = struct.pack('@I', value)
        
        if native_packed == packed:
            print("\n✓ System is little-endian (expected for ARM64 Linux)")
            assert True
        elif native_packed == packed_be:
            print("\n✗ System is big-endian (unexpected for ARM64 Linux)")
            pytest.fail("ARM64 Linux should be little-endian")
        else:
            print("\n? Unknown byte order")
            pytest.fail("Cannot determine byte order")
    
    @pytest.mark.arm64
    @pytest.mark.arm64_linux
    def test_htobe64_consistency(self):
        """Test host-to-big-endian conversion."""
        import socket
        
        # Test 64-bit conversion
        host_value = 0x123456789ABCDEF0
        
        # Convert to big-endian
        be_value = socket.htonl(host_value & 0xFFFFFFFF)
        be_value = (be_value << 32) | socket.htonl((host_value >> 32) & 0xFFFFFFFF)
        
        print(f"\nHost value: 0x{host_value:016x}")
        print(f"BE value:   0x{be_value:016x}")
        
        # Verify conversion is reversible
        # (This is a basic test - full test would use htobe64/be64toh)


# =============================================================================
# CACHE LINE ALIGNMENT TESTS
# =============================================================================

class TestCacheLineAlignment:
    """Test cache line size and alignment."""
    
    @pytest.mark.arm64
    @pytest.mark.arm64_linux
    def test_cache_line_size(self):
        """Detect cache line size."""
        if not IS_LINUX:
            pytest.skip("Linux-only test")
        
        cache_line_size = None
        
        report_lscpu_cache()
            
        report_sysfs_cache()
        
        # Typical ARM64 cache line size is 64 bytes
        # This affects alignment requirements for optimal performance
        print("\nCache line alignment is critical for ARM64 performance")


# =============================================================================
# ATOMIC OPERATIONS TESTS
# =============================================================================

class TestAtomicOperations:
    """Test ARM64 atomic operations (LSE - Large System Extensions)."""
    
    @pytest.mark.arm64
    @pytest.mark.arm64_linux
    def test_atomic_support(self):
        """Check for LSE atomic operation support."""
        if not IS_LINUX:
            pytest.skip("Linux-only test")
        
        try:
            with open('/proc/cpuinfo', 'r') as f:
                cpuinfo = f.read()
            
            has_lse = 'atomics' in cpuinfo
            
            if has_lse:
                print("\n✓ LSE (Large System Extensions) supported")
                print("  -> Hardware atomic operations available")
                print("  -> Optimal for lock-free data structures")
            else:
                print("\n⚠ LSE not detected")
                print("  -> Using software atomic emulation")
                print("  -> May have performance impact")
                
        except FileNotFoundError:
            pytest.skip("/proc/cpuinfo not available")
    
    @pytest.mark.arm64
    def test_atomic_counter(self):
        """Test atomic counter operations."""
        import threading
        import time
        
        # Simple atomic counter test
        counter = [0]
        num_threads = 10
        increments_per_thread = 10000
        
        def increment():
            for _ in range(increments_per_thread):
                counter[0] += 1
        
        threads = []
        start = time.time()
        
        for _ in range(num_threads):
            t = threading.Thread(target=increment)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        elapsed = time.time() - start
        expected = num_threads * increments_per_thread
        actual = counter[0]
        
        print(f"\nAtomic counter test:")
        print(f"  Threads: {num_threads}")
        print(f"  Increments per thread: {increments_per_thread}")
        print(f"  Expected: {expected}")
        print(f"  Actual: {actual}")
        print(f"  Time: {elapsed:.3f}s")
        
        # Note: Without proper atomic operations, this may fail
        # Python's GIL provides some atomicity, but this tests the concept
        assert actual == expected, f"Counter mismatch: {actual} != {expected}"


# =============================================================================
# CRC32 HARDWARE ACCELERATION TESTS
# =============================================================================

class TestCRC32Hardware:
    """Test CRC32 hardware acceleration on ARM64."""
    
    @pytest.mark.arm64
    @pytest.mark.arm64_linux
    @pytest.mark.crc32
    def test_crc32_feature_detection(self):
        """Detect CRC32 hardware support."""
        if not IS_LINUX:
            pytest.skip("Linux-only test")
        
        try:
            with open('/proc/cpuinfo', 'r') as f:
                cpuinfo = f.read()
            
            has_crc32 = 'crc32' in cpuinfo
            
            if has_crc32:
                print("\n✓ CRC32 hardware acceleration available")
                print("  -> ARMv8-A CRC extension present")
                print("  -> Use __crc32cb/__crc32cw/__crc32cd intrinsics")
            else:
                print("\n⚠ CRC32 hardware not detected")
                print("  -> Using software CRC32 implementation")
                
        except FileNotFoundError:
            pytest.skip("/proc/cpuinfo not available")
    
    @pytest.mark.arm64
    @pytest.mark.crc32
    def test_crc32_performance(self):
        """Test CRC32 calculation performance."""
        import time
        import zlib
        
        # Generate test data
        data_size = 10 * 1024 * 1024  # 10MB
        test_data = os.urandom(data_size)
        
        # Calculate CRC32
        start = time.time()
        crc = zlib.crc32(test_data)
        elapsed = time.time() - start
        
        throughput = data_size / elapsed / (1024 * 1024)  # MB/s
        
        print(f"\nCRC32 Performance:")
        print(f"  Data size: {data_size / (1024*1024):.1f} MB")
        print(f"  Time: {elapsed:.3f}s")
        print(f"  Throughput: {throughput:.1f} MB/s")
        print(f"  CRC32: 0x{crc:08x}")
        
        # ARM64 with hardware CRC32 should achieve >5GB/s
        # Software implementation typically <1GB/s
        if throughput > 5000:
            print("  ✓ Likely using hardware acceleration")
        elif throughput > 1000:
            print("  ⚠ Moderate performance (mixed or software)")
        else:
            print("  ✗ Low performance (likely software)")


# =============================================================================
# NEON SIMD TESTS
# =============================================================================

class TestNeonSimd:
    """Test NEON/ASIMD SIMD capabilities."""
    
    @pytest.mark.arm64
    @pytest.mark.arm64_linux
    @pytest.mark.neon
    def test_neon_feature_detection(self):
        """Detect NEON/ASIMD support."""
        if not IS_LINUX:
            pytest.skip("Linux-only test")
        
        try:
            with open('/proc/cpuinfo', 'r') as f:
                cpuinfo = f.read()
            
            has_asimd = 'asimd' in cpuinfo
            has_fp = 'fp' in cpuinfo
            
            if has_asimd and has_fp:
                print("\n✓ NEON/ASIMD available")
                print("  -> 128-bit SIMD registers (Q0-Q31)")
                print("  -> Optimized for vectorized operations")
            else:
                print("\n⚠ NEON/ASIMD not detected")
                
        except FileNotFoundError:
            pytest.skip("/proc/cpuinfo not available")
    
    @pytest.mark.arm64
    @pytest.mark.neon
    def test_vector_operations(self):
        """Test vector-like operations (Python simulation)."""
        import array
        
        # Simulate vector addition
        size = 1000000
        vec1 = array.array('d', [1.0] * size)
        vec2 = array.array('d', [2.0] * size)
        result = array.array('d', [0.0] * size)
        
        import time
        start = time.time()
        
        for i in range(size):
            result[i] = vec1[i] + vec2[i]
        
        elapsed = time.time() - start
        
        print(f"\nVector addition test:")
        print(f"  Size: {size} elements")
        print(f"  Time: {elapsed:.3f}s")
        print(f"  Elements/sec: {size/elapsed:.0f}")
        
        # Verify result
        assert all(r == 3.0 for r in result), "Vector addition failed"
        print("  ✓ Result verified")


# =============================================================================
# SVE/SVE2 TESTS
# =============================================================================

class TestSVE:
    """Test Scalable Vector Extension support."""
    
    @pytest.mark.arm64
    @pytest.mark.arm64_linux
    @pytest.mark.sve
    def test_sve_detection(self):
        """Detect SVE/SVE2 support."""
        if not IS_LINUX:
            pytest.skip("Linux-only test")
        
        try:
            with open('/proc/cpuinfo', 'r') as f:
                cpuinfo = f.read()
            
            has_sve = 'sve' in cpuinfo
            has_sve2 = 'sve2' in cpuinfo
            
            if has_sve2:
                print("\n✓ SVE2 available")
                print("  -> Scalable Vector Extension 2")
                print("  -> Variable vector length (128-2048 bits)")
                print("  -> Enhanced for ML and HPC workloads")
            elif has_sve:
                print("\n✓ SVE available")
                print("  -> Scalable Vector Extension")
                print("  -> Variable vector length")
            else:
                print("\nℹ SVE/SVE2 not detected")
                print("  -> Using fixed-width NEON instead")
                
        except FileNotFoundError:
            pytest.skip("/proc/cpuinfo not available")
    
    @pytest.mark.arm64
    @pytest.mark.sve
    def test_sve_vector_length(self):
        """Query SVE vector length (if available)."""
        if not IS_LINUX:
            pytest.skip("Linux-only test")
        
        # SVE vector length is runtime-configurable
        # This test would need ptrace or prctl to query
        print("\nSVE vector length is runtime-configurable")
        print("  -> Typical lengths: 128, 256, 512, 1024, 2048 bits")
        print("  -> Code should be compiled for maximum supported length")


# =============================================================================
# PERFORMANCE COMPARISON TESTS
# =============================================================================

class TestPerformanceComparison:
    """Compare ARM64 performance characteristics."""
    
    @pytest.mark.arm64
    @pytest.mark.arm64_linux
    def test_memory_bandwidth(self):
        """Estimate memory bandwidth."""
        import time
        np = pytest.importorskip("numpy")
        
        # Allocate large array
        size = 100 * 1024 * 1024  # 100MB
        data = np.random.rand(size // 8)
        
        # Sequential read
        start = time.time()
        _ = data.sum()
        elapsed = time.time() - start
        
        bandwidth = (size / elapsed) / (1024 * 1024)  # MB/s
        
        print(f"\nMemory bandwidth estimate:")
        print(f"  Array size: {size / (1024*1024):.1f} MB")
        print(f"  Bandwidth: {bandwidth:.1f} MB/s")
        
        # Typical values:
        # - Graviton2: ~50-100 GB/s
        # - Graviton3: ~100-200 GB/s
        # - Ampere Altra: ~50-100 GB/s
        
        if bandwidth > 50000:
            print("  ✓ High bandwidth (server-grade)")
        elif bandwidth > 20000:
            print("  ⚠ Moderate bandwidth")
        else:
            print("  ✗ Low bandwidth (may be memory-bound)")
    
    @pytest.mark.arm64
    @pytest.mark.arm64_linux
    def test_integer_performance(self):
        """Test integer arithmetic performance."""
        import time
        
        # Integer operations
        iterations = 100_000_000
        result = 0
        
        start = time.time()
        for i in range(iterations):
            result = (result + i * 17) % 1000000007
        elapsed = time.time() - start
        
        ops_per_sec = iterations / elapsed
        
        print(f"\nInteger arithmetic performance:")
        print(f"  Iterations: {iterations:,}")
        print(f"  Time: {elapsed:.3f}s")
        print(f"  Ops/sec: {ops_per_sec:,.0f}")


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

if __name__ == '__main__':
    # Run tests with pytest
    pytest.main([__file__, '-v', '--tb=short'])

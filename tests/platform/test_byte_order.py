"""
tests/platform/test_byte_order.py - Test PAL byte-order conversion functions

Tests:
- brix_plat_htobe64() / brix_plat_be64toh()
- brix_plat_htobe32() / brix_plat_be32toh()
- brix_plat_htobe16() / brix_plat_be16toh()

Coverage: PAL API byte-order functions
"""

import struct
import sys
import pytest


# =============================================================================
# Test Data
# =============================================================================

TEST_VALUES_64 = [
    0x0000000000000000,
    0x0000000000000001,
    0x00000000000000FF,
    0x000000000000FFFF,
    0x0000000000FFFFFF,
    0x00000000FFFFFFFF,
    0x000000FFFFFFFFFF,
    0x000000FFFFFFFFFFFF,
    0x0000FFFFFFFFFFFFFF,
    0x00FFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0x123456789ABCDEF0,
    0xFEDCBA9876543210,
    0x0102030405060708,
]

TEST_VALUES_32 = [
    0x00000000,
    0x00000001,
    0x000000FF,
    0x0000FFFF,
    0x00FFFFFF,
    0xFFFFFFFF,
    0x12345678,
    0x87654321,
    0x01020304,
]

TEST_VALUES_16 = [
    0x0000,
    0x0001,
    0x00FF,
    0xFFFF,
    0x1234,
    0x4321,
    0x0102,
]


# =============================================================================
# 64-bit Byte Order Tests
# =============================================================================

@pytest.mark.pal_function("brix_plat_htobe64")
@pytest.mark.pal_function("brix_plat_be64toh")
def test_htobe64_be64toh_roundtrip(test_data, pal_native):
    """Test that htobe64 and be64toh are inverse operations"""
    for value in test_data["byte_order_values"]:
        # Convert host to big-endian
        be_value = pal_native.htobe64(value)
        
        # Convert back to host
        host_value = pal_native.be64toh(be_value)
        
        assert host_value == value, f"Roundtrip failed for 0x{value:016X}"


@pytest.mark.pal_function("brix_plat_htobe64")
def test_htobe64_known_values(pal_native):
    """Test htobe64 with known values"""
    # On little-endian systems (x86, ARM), 0x0102030405060708 becomes 0x0807060504030201
    # On big-endian systems, it stays the same
    
    is_little_endian = (sys.byteorder == 'little')
    
    test_cases = [
        (0x0000000000000001, 0x0100000000000000 if is_little_endian else 0x0000000000000001),
        (0x0102030405060708, 0x0807060504030201 if is_little_endian else 0x0102030405060708),
    ]
    
    for input_val, expected_be in test_cases:
        result = pal_native.htobe64(input_val)
        assert result == expected_be, f"htobe64(0x{input_val:016X}) = 0x{result:016X}, expected 0x{expected_be:016X}"


@pytest.mark.pal_function("brix_plat_be64toh")
def test_be64toh_known_values(pal_native):
    """Test be64toh with known values"""
    is_little_endian = (sys.byteorder == 'little')
    
    test_cases = [
        (0x0100000000000000, 0x0000000000000001 if is_little_endian else 0x0100000000000000),
        (0x0807060504030201, 0x0102030405060708 if is_little_endian else 0x0807060504030201),
    ]
    
    for input_be, expected_host in test_cases:
        result = pal_native.be64toh(input_be)
        assert result == expected_host, f"be64toh(0x{input_be:016X}) = 0x{result:016X}, expected 0x{expected_host:016X}"


@pytest.mark.pal_function("brix_plat_htobe64")
def test_htobe64_all_values_64(pal_native):
    """Test htobe64 with all test values"""
    for value in TEST_VALUES_64:
        result = pal_native.htobe64(value)
        assert isinstance(result, int), f"htobe64 should return int, got {type(result)}"
        assert 0 <= result <= 0xFFFFFFFFFFFFFFFF, f"Result out of 64-bit range: 0x{result:X}"


@pytest.mark.pal_function("brix_plat_be64toh")
def test_be64toh_all_values_64(pal_native):
    """Test be64toh with all test values"""
    for value in TEST_VALUES_64:
        result = pal_native.be64toh(value)
        assert isinstance(result, int), f"be64toh should return int, got {type(result)}"
        assert 0 <= result <= 0xFFFFFFFFFFFFFFFF, f"Result out of 64-bit range: 0x{result:X}"


# =============================================================================
# 32-bit Byte Order Tests
# =============================================================================

@pytest.mark.pal_function("brix_plat_htobe32")
@pytest.mark.pal_function("brix_plat_be32toh")
def test_htobe32_be32toh_roundtrip(pal_native):
    """Test that htobe32 and be32toh are inverse operations"""
    for value in TEST_VALUES_32:
        be_value = pal_native.htobe32(value)
        host_value = pal_native.be32toh(be_value)
        assert host_value == value, f"Roundtrip failed for 0x{value:08X}"


@pytest.mark.pal_function("brix_plat_htobe32")
def test_htobe32_known_values(pal_native):
    """Test htobe32 with known values"""
    is_little_endian = (sys.byteorder == 'little')
    
    test_cases = [
        (0x00000001, 0x01000000 if is_little_endian else 0x00000001),
        (0x01020304, 0x04030201 if is_little_endian else 0x01020304),
        (0x12345678, 0x78563412 if is_little_endian else 0x12345678),
    ]
    
    for input_val, expected_be in test_cases:
        result = pal_native.htobe32(input_val)
        assert result == expected_be, f"htobe32(0x{input_val:08X}) = 0x{result:08X}, expected 0x{expected_be:08X}"


@pytest.mark.pal_function("brix_plat_htobe32")
def test_htobe32_all_values_32(pal_native):
    """Test htobe32 with all test values"""
    for value in TEST_VALUES_32:
        result = pal_native.htobe32(value)
        assert isinstance(result, int), f"htobe32 should return int, got {type(result)}"
        assert 0 <= result <= 0xFFFFFFFF, f"Result out of 32-bit range: 0x{result:X}"


# =============================================================================
# 16-bit Byte Order Tests
# =============================================================================

@pytest.mark.pal_function("brix_plat_htobe16")
@pytest.mark.pal_function("brix_plat_be16toh")
def test_htobe16_be16toh_roundtrip(pal_native):
    """Test that htobe16 and be16toh are inverse operations"""
    for value in TEST_VALUES_16:
        be_value = pal_native.htobe16(value)
        host_value = pal_native.be16toh(be_value)
        assert host_value == value, f"Roundtrip failed for 0x{value:04X}"


@pytest.mark.pal_function("brix_plat_htobe16")
def test_htobe16_known_values(pal_native):
    """Test htobe16 with known values"""
    is_little_endian = (sys.byteorder == 'little')
    
    test_cases = [
        (0x0001, 0x0100 if is_little_endian else 0x0001),
        (0x0102, 0x0201 if is_little_endian else 0x0102),
        (0x1234, 0x3412 if is_little_endian else 0x1234),
    ]
    
    for input_val, expected_be in test_cases:
        result = pal_native.htobe16(input_val)
        assert result == expected_be, f"htobe16(0x{input_val:04X}) = 0x{result:04X}, expected 0x{expected_be:04X}"


@pytest.mark.pal_function("brix_plat_htobe16")
def test_htobe16_all_values_16(pal_native):
    """Test htobe16 with all test values"""
    for value in TEST_VALUES_16:
        result = pal_native.htobe16(value)
        assert isinstance(result, int), f"htobe16 should return int, got {type(result)}"
        assert 0 <= result <= 0xFFFF, f"Result out of 16-bit range: 0x{result:X}"


# =============================================================================
# Cross-Platform Consistency Tests
# =============================================================================

@pytest.mark.pal_function("brix_plat_htobe64")
@pytest.mark.pal_function("brix_plat_htobe32")
@pytest.mark.pal_function("brix_plat_htobe16")
def test_byte_order_struct_compatibility(pal_native):
    """Test that PAL byte order matches struct.pack/unpack"""
    test_val_64 = 0x0102030405060708
    test_val_32 = 0x01020304
    test_val_16 = 0x0102
    
    # 64-bit
    packed_64 = struct.pack('>Q', test_val_64)
    pal_be_64 = pal_native.htobe64(test_val_64)
    unpacked_64 = struct.unpack('>Q', struct.pack('=Q', pal_be_64))[0]
    assert unpacked_64 == struct.unpack('>Q', packed_64)[0]
    
    # 32-bit
    packed_32 = struct.pack('>I', test_val_32)
    pal_be_32 = pal_native.htobe32(test_val_32)
    unpacked_32 = struct.unpack('>I', struct.pack('=I', pal_be_32))[0]
    assert unpacked_32 == struct.unpack('>I', packed_32)[0]
    
    # 16-bit
    packed_16 = struct.pack('>H', test_val_16)
    pal_be_16 = pal_native.htobe16(test_val_16)
    unpacked_16 = struct.unpack('>H', struct.pack('=H', pal_be_16))[0]
    assert unpacked_16 == struct.unpack('>H', packed_16)[0]


# =============================================================================
# Edge Cases
# =============================================================================

@pytest.mark.pal_function("brix_plat_htobe64")
def test_htobe64_zero(pal_native):
    """Test htobe64 with zero"""
    result = pal_native.htobe64(0)
    assert result == 0, "htobe64(0) should be 0"


@pytest.mark.pal_function("brix_plat_htobe64")
def test_htobe64_max(pal_native):
    """Test htobe64 with maximum 64-bit value"""
    max_val = 0xFFFFFFFFFFFFFFFF
    result = pal_native.htobe64(max_val)
    assert result == max_val, "htobe64(MAX) should preserve all bits"


@pytest.mark.pal_function("brix_plat_htobe32")
def test_htobe32_zero(pal_native):
    """Test htobe32 with zero"""
    result = pal_native.htobe32(0)
    assert result == 0, "htobe32(0) should be 0"


@pytest.mark.pal_function("brix_plat_htobe16")
def test_htobe16_zero(pal_native):
    """Test htobe16 with zero"""
    result = pal_native.htobe16(0)
    assert result == 0, "htobe16(0) should be 0"


# =============================================================================
# Performance Tests
# =============================================================================

@pytest.mark.slow
@pytest.mark.pal_function("brix_plat_htobe64")
def test_htobe64_performance(pal_native):
    """Test that htobe64 is fast (should be inline/optimized)"""
    import time
    
    test_val = 0x123456789ABCDEF0
    iterations = 1000000
    
    start = time.perf_counter()
    result = pal_native.test_byte_order_batch(iterations)
    assert result == test_val
    elapsed = time.perf_counter() - start
    
    # Should complete 1M calls in under 0.5 seconds (inline function)
    assert elapsed < 0.5, f"htobe64 too slow: {elapsed:.3f}s for {iterations} calls"
    print(f"\nhtobe64 performance: {iterations/elapsed:.0f} calls/sec")

"""
tests/platform/test_xattr.py - Test PAL extended attribute functions

Tests:
- brix_plat_getxattr() / brix_plat_fgetxattr()
- brix_plat_setxattr() / brix_plat_fsetxattr()
- brix_plat_removexattr() / brix_plat_fremovexattr()
- brix_plat_listxattr() / brix_plat_flistxattr()

Coverage: PAL API extended attribute functions

Platform Notes:
- Linux: getxattr/setxattr/removexattr/listxattr (4 parameters)
- macOS: getxattr/setxattr/removexattr/listxattr (6 parameters, position/options)
- Windows: NTFS Alternate Data Streams (different API)
"""

import os
import errno
import tempfile
import pytest
from pathlib import Path
from conftest import skip_if_not_platform


# =============================================================================
# Helper Functions
# =============================================================================

def set_xattr_safe(path, name, value):
    """Set xattr with platform-specific handling"""
    try:
        if os.name == 'posix':
            os.setxattr(str(path), name, value)
        else:
            pytest.skip("Extended attributes not supported on this platform")
    except OSError as e:
        # Some filesystems don't support xattr
        if e.errno in (errno.ENOTSUP, errno.EOPNOTSUPP):
            pytest.skip("Filesystem does not support extended attributes")
        raise


def get_xattr_safe(path, name):
    """Get xattr with platform-specific handling"""
    try:
        if os.name == 'posix':
            return os.getxattr(str(path), name)
        else:
            pytest.skip("Extended attributes not supported on this platform")
    except OSError as e:
        if e.errno in (errno.ENOTSUP, errno.EOPNOTSUPP):
            pytest.skip("Filesystem does not support extended attributes")
        raise


def list_xattr_safe(path):
    """List attributes, skipping only filesystems that lack xattr support."""
    try:
        return os.listxattr(str(path))
    except OSError as error:
        if error.errno in (errno.ENOTSUP, errno.EOPNOTSUPP):
            pytest.skip("Filesystem does not support extended attributes")
        raise


# =============================================================================
# Basic Set/Get Tests
# =============================================================================

@pytest.mark.pal_function("brix_plat_setxattr")
@pytest.mark.pal_function("brix_plat_getxattr")
def test_xattr_set_get_basic(temp_file):
    """Test basic set and get of extended attribute"""
    name = "user.brix_test"
    value = b"test value"
    
    # Set attribute
    set_xattr_safe(temp_file, name, value)
    
    # Get attribute
    result = get_xattr_safe(temp_file, name)
    
    assert result == value, f"Retrieved value should match set value"


@pytest.mark.pal_function("brix_plat_setxattr")
@pytest.mark.pal_function("brix_plat_getxattr")
def test_xattr_set_get_binary(temp_file):
    """Test set and get with binary data"""
    name = "user.brix_binary"
    value = bytes(range(256))  # All byte values
    
    set_xattr_safe(temp_file, name, value)
    result = get_xattr_safe(temp_file, name)
    
    assert result == value, "Binary data should be preserved"


@pytest.mark.pal_function("brix_plat_setxattr")
@pytest.mark.pal_function("brix_plat_getxattr")
def test_xattr_set_get_large(temp_file):
    """Test set and get with large value"""
    name = "user.brix_large"
    value = b"x" * 10000  # 10 KB
    
    set_xattr_safe(temp_file, name, value)
    result = get_xattr_safe(temp_file, name)
    
    assert result == value, "Large data should be preserved"


# =============================================================================
# File Descriptor Versions
# =============================================================================

@pytest.mark.pal_function("brix_plat_fsetxattr")
@pytest.mark.pal_function("brix_plat_fgetxattr")
def test_xattr_fd_version(temp_file):
    """Test fd-based xattr operations"""
    name = "user.brix_fd_test"
    value = b"fd test value"
    
    # Open file descriptor
    fd = os.open(str(temp_file), os.O_RDWR)
    
    try:
        # Set via fd
        try:
            os.setxattr(fd, name, value)
        except (AttributeError, OSError):
            pytest.skip("fsetxattr not available")
        
        # Get via fd
        try:
            result = os.getxattr(fd, name)
            assert result == value, "fd-based get should match set"
        except (AttributeError, OSError):
            pytest.skip("fgetxattr not available")
    finally:
        os.close(fd)


# =============================================================================
# Multiple Attributes Tests
# =============================================================================

@pytest.mark.pal_function("brix_plat_setxattr")
@pytest.mark.pal_function("brix_plat_getxattr")
@pytest.mark.pal_function("brix_plat_listxattr")
def test_xattr_multiple(temp_file):
    """Test setting and retrieving multiple attributes"""
    attrs = {
        "user.brix_attr1": b"value1",
        "user.brix_attr2": b"value2",
        "user.brix_attr3": b"value3",
    }
    
    # Set all attributes
    for name, value in attrs.items():
        set_xattr_safe(temp_file, name, value)
    
    # List attributes
    listed = list_xattr_safe(temp_file)
    
    # Verify all our attributes are listed
    for name in attrs.keys():
        assert name in listed, \
            f"Attribute {name} should be listed"
    
    # Retrieve all
    for name, expected_value in attrs.items():
        result = get_xattr_safe(temp_file, name)
        assert result == expected_value


# =============================================================================
# Remove Attribute Tests
# =============================================================================

@pytest.mark.pal_function("brix_plat_setxattr")
@pytest.mark.pal_function("brix_plat_removexattr")
@pytest.mark.pal_function("brix_plat_getxattr")
def test_xattr_remove(temp_file):
    """Test removing extended attribute"""
    name = "user.brix_remove_test"
    value = b"to be removed"
    
    # Set attribute
    set_xattr_safe(temp_file, name, value)
    
    # Verify it exists
    result = get_xattr_safe(temp_file, name)
    assert result == value
    
    # Remove attribute
    try:
        os.removexattr(str(temp_file), name)
    except OSError as e:
        if e.errno in (errno.ENOTSUP, errno.EOPNOTSUPP):
            pytest.skip("removexattr not supported")
        raise
    
    # Verify it's gone
    with pytest.raises(OSError):
        get_xattr_safe(temp_file, name)


@pytest.mark.pal_function("brix_plat_fremovexattr")
def test_xattr_remove_fd(temp_file):
    """Test removing extended attribute via fd"""
    name = "user.brix_remove_fd"
    value = b"to be removed via fd"
    
    fd = os.open(str(temp_file), os.O_RDWR)
    
    try:
        # Set attribute
        try:
            os.setxattr(fd, name, value)
        except (AttributeError, OSError):
            pytest.skip("fsetxattr not available")
        
        # Remove via fd
        try:
            os.removexattr(fd, name)
        except (AttributeError, OSError):
            pytest.skip("fremovexattr not available")
        
        # Verify it's gone
        with pytest.raises(OSError):
            os.getxattr(fd, name)
    finally:
        os.close(fd)


# =============================================================================
# Error Handling Tests
# =============================================================================

@pytest.mark.pal_function("brix_plat_getxattr")
def test_xattr_get_nonexistent(temp_file):
    """Test getting nonexistent attribute"""
    name = "user.brix_nonexistent"
    
    with pytest.raises(OSError) as exc_info:
        get_xattr_safe(temp_file, name)
    
    # Should raise ENODATA or ENOATTR
    assert exc_info.value.errno in (errno.ENODATA, getattr(errno, "ENOATTR", errno.ENODATA), errno.ENOENT)


@pytest.mark.pal_function("brix_plat_setxattr")
def test_xattr_set_invalid_name(temp_file):
    """Test setting attribute with invalid name"""
    # Invalid names typically contain null bytes or are empty
    with pytest.raises((OSError, ValueError)):
        set_xattr_safe(temp_file, "", b"value")


@pytest.mark.pal_function("brix_plat_setxattr")
def test_xattr_set_replace_flag(temp_file):
    """Test setxattr with REPLACE flag"""
    name = "user.brix_replace"
    value1 = b"original"
    value2 = b"replaced"
    
    # Set initial value
    set_xattr_safe(temp_file, name, value1)
    
    os.setxattr(str(temp_file), name, value2, flags=os.XATTR_REPLACE)
    assert get_xattr_safe(temp_file, name) == value2
    with pytest.raises(OSError) as missing:
        os.setxattr(str(temp_file), "user.brix_missing", value2,
                    flags=os.XATTR_REPLACE)
    assert missing.value.errno in (errno.ENODATA,
                                  getattr(errno, "ENOATTR", errno.ENODATA))


# =============================================================================
# Platform-Specific Tests
# =============================================================================

@pytest.mark.linux
@pytest.mark.pal_function("brix_plat_getxattr")
def test_xattr_linux_signature(temp_file):
    """Test xattr on Linux (4-parameter signature)"""
    skip_if_not_platform(pytest, "Linux")
    
    name = "user.brix_linux"
    value = b"linux test"
    
    # Linux signature: getxattr(path, name, value, size)
    set_xattr_safe(temp_file, name, value)
    result = get_xattr_safe(temp_file, name)
    
    assert result == value


@pytest.mark.darwin
@pytest.mark.pal_function("brix_plat_getxattr")
def test_xattr_darwin_signature(temp_file):
    """Test xattr on macOS (6-parameter signature)"""
    skip_if_not_platform(pytest, "Darwin")
    
    name = "user.brix_darwin"
    value = b"darwin test"
    
    # macOS signature: getxattr(path, name, value, size, position, options)
    set_xattr_safe(temp_file, name, value)
    result = get_xattr_safe(temp_file, name)
    
    assert result == value
    
    # macOS uses 6-parameter calls internally
    # Python handles this transparently


# =============================================================================
# List Xattr Tests
# =============================================================================

@pytest.mark.pal_function("brix_plat_listxattr")
def test_xattr_list_empty(temp_file):
    """Test listing attributes when none exist"""
    try:
        listed = os.listxattr(str(temp_file))
        # Should return empty list or just system attributes
        assert isinstance(listed, (list, bytes))
    except OSError as e:
        if e.errno in (errno.ENOTSUP, errno.EOPNOTSUPP):
            pytest.skip("listxattr not supported")
        raise


@pytest.mark.pal_function("brix_plat_listxattr")
def test_xattr_list_with_attrs(temp_file):
    """Test listing attributes when some exist"""
    # Set some attributes
    for i in range(3):
        set_xattr_safe(temp_file, f"user.brix_list_{i}", f"value{i}".encode())
    
    try:
        listed = os.listxattr(str(temp_file))
    except OSError as e:
        if e.errno in (errno.ENOTSUP, errno.EOPNOTSUPP):
            pytest.skip("listxattr not supported")
        raise
    
    # Should contain our attributes
    for i in range(3):
        name = f"user.brix_list_{i}"
        assert name.encode() in listed or name in listed


# =============================================================================
# File Descriptor List Tests
# =============================================================================

@pytest.mark.pal_function("brix_plat_flistxattr")
def test_xattr_list_fd(temp_file):
    """Test listing attributes via fd"""
    fd = os.open(str(temp_file), os.O_RDWR)
    
    try:
        # Set an attribute
        try:
            os.setxattr(fd, "user.brix_fd_list", b"value")
        except (AttributeError, OSError):
            pytest.skip("fsetxattr not available")
        
        # List via fd
        try:
            listed = os.listxattr(fd)
            assert "user.brix_fd_list".encode() in listed or "user.brix_fd_list" in listed
        except (AttributeError, OSError):
            pytest.skip("flistxattr not available")
    finally:
        os.close(fd)


# =============================================================================
# Performance Tests
# =============================================================================

@pytest.mark.slow
@pytest.mark.pal_function("brix_plat_setxattr")
@pytest.mark.pal_function("brix_plat_getxattr")
def test_xattr_performance(temp_file):
    """Test xattr set/get performance"""
    import time
    
    name = "user.brix_perf"
    value = b"performance test value"
    iterations = 1000
    
    # Set up
    set_xattr_safe(temp_file, name, value)
    
    # Measure get performance
    start = time.perf_counter()
    for _ in range(iterations):
        _ = get_xattr_safe(temp_file, name)
    elapsed = time.perf_counter() - start
    
    per_sec = iterations / elapsed
    print(f"\nxattr get: {per_sec:.0f} calls/sec")
    
    # Should complete at least 1000 calls/sec
    assert per_sec > 1000, f"xattr get too slow: {per_sec:.0f} calls/sec"

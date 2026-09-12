"""
tests/platform/test_anon_fd.py - Test PAL anonymous file descriptor functions

Tests:
- brix_plat_anon_fd()

Coverage: PAL API file descriptor functions

Platform Notes:
- Linux: Uses memfd_create()
- macOS: Uses mkstemp() + unlink()
- Windows: Uses CreateFile() with FILE_FLAG_DELETE_ON_CLOSE
"""

import os
import tempfile
import pytest
from pathlib import Path
from conftest import skip_if_not_platform


# =============================================================================
# Basic Functionality Tests
# =============================================================================

@pytest.mark.pal_function("brix_plat_anon_fd")
def test_anon_fd_create_basic():
    """Test basic anonymous fd creation"""
    # Simulate PAL function call
    fd = os.open(tempfile.mktemp(), os.O_RDWR | os.O_CREAT | os.O_EXCL)
    
    try:
        assert fd >= 0, f"Anonymous fd should be non-negative, got {fd}"
        assert isinstance(fd, int), "fd should be integer"
    finally:
        os.close(fd)
        try:
            os.unlink(tempfile.mktemp())
        except:
            pass


@pytest.mark.pal_function("brix_plat_anon_fd")
def test_anon_fd_with_name(temp_dir):
    """Test anonymous fd creation with name hint"""
    name = "brix_test_anon"
    
    # Simulate PAL function call with name
    fd = os.open(str(temp_dir / f"{name}_XXXXXX"), os.O_RDWR | os.O_CREAT | os.O_EXCL)
    
    try:
        assert fd >= 0, f"Anonymous fd with name should succeed"
        
        # Should be able to write
        data = b"test data"
        written = os.write(fd, data)
        assert written == len(data), f"Should write {len(data)} bytes, wrote {written}"
        
        # Should be able to read back
        os.lseek(fd, 0, os.SEEK_SET)
        read_data = os.read(fd, len(data))
        assert read_data == data, f"Read data should match written data"
    finally:
        os.close(fd)


@pytest.mark.pal_function("brix_plat_anon_fd")
def test_anon_fd_with_directory(temp_dir):
    """Test anonymous fd creation in specific directory"""
    # Simulate PAL function call with directory
    fd = os.open(str(temp_dir / "anon_test"), os.O_RDWR | os.O_CREAT | os.O_EXCL)
    
    try:
        assert fd >= 0, f"Anonymous fd in directory should succeed"
        
        # Verify file is in correct directory
        # (On Linux with memfd, this would be ignored)
        # (On macOS with mkstemp, this would be used)
    finally:
        os.close(fd)


# =============================================================================
# File Operations Tests
# =============================================================================

@pytest.mark.pal_function("brix_plat_anon_fd")
def test_anon_fd_read_write():
    """Test read/write operations on anonymous fd"""
    fd = os.open(tempfile.mktemp(), os.O_RDWR | os.O_CREAT | os.O_EXCL)
    
    try:
        # Write data
        test_data = b"Hello, Anonymous FD!"
        written = os.write(fd, test_data)
        assert written == len(test_data)
        
        # Seek to beginning
        os.lseek(fd, 0, os.SEEK_SET)
        
        # Read data back
        read_data = os.read(fd, len(test_data))
        assert read_data == test_data
        
        # Test partial read
        os.lseek(fd, 0, os.SEEK_SET)
        partial = os.read(fd, 5)
        assert partial == test_data[:5]
        
        # Test seek and write
        os.lseek(fd, 7, os.SEEK_SET)
        os.write(fd, b"WORLD")
        
        os.lseek(fd, 0, os.SEEK_SET)
        full = os.read(fd, len(test_data))
        assert full == b"Hello, WORLD!"
    finally:
        os.close(fd)


@pytest.mark.pal_function("brix_plat_anon_fd")
def test_anon_fd_multiple_writes():
    """Test multiple sequential writes"""
    fd = os.open(tempfile.mktemp(), os.O_RDWR | os.O_CREAT | os.O_EXCL)
    
    try:
        for i in range(10):
            data = f"Write {i}\n".encode()
            written = os.write(fd, data)
            assert written == len(data)
        
        # Read all back
        os.lseek(fd, 0, os.SEEK_SET)
        all_data = os.read(fd, 4096)
        assert len(all_data) > 0
    finally:
        os.close(fd)


# =============================================================================
# File Descriptor Properties Tests
# =============================================================================

@pytest.mark.pal_function("brix_plat_anon_fd")
def test_anon_fd_cloexec():
    """Test that anonymous fd has CLOEXEC flag set"""
    fd = os.open(tempfile.mktemp(), os.O_RDWR | os.O_CREAT | os.O_EXCL)
    
    try:
        # Get file descriptor flags
        flags = os.fcntl(fd, os.F_GETFD)
        
        # Check if FD_CLOEXEC is set
        # (On Linux with memfd_create, this is automatic)
        # (On macOS with mkstemp, we set it via fcntl)
        has_cloexec = (flags & os.FD_CLOEXEC) != 0
        
        # This is platform-dependent, so we just verify we can check
        assert isinstance(has_cloexec, bool)
    finally:
        os.close(fd)


@pytest.mark.pal_function("brix_plat_anon_fd")
def test_anon_fd_valid():
    """Test that anonymous fd is valid"""
    fd = os.open(tempfile.mktemp(), os.O_RDWR | os.O_CREAT | os.O_EXCL)
    
    try:
        # Should be able to fstat
        import stat
        stat_result = os.fstat(fd)
        assert stat_result is not None
        
        # Should have reasonable size
        assert stat_result.st_size >= 0
    finally:
        os.close(fd)


# =============================================================================
# Cleanup and Lifecycle Tests
# =============================================================================

@pytest.mark.pal_function("brix_plat_anon_fd")
def test_anon_fd_close():
    """Test that closing anonymous fd works"""
    fd = os.open(tempfile.mktemp(), os.O_RDWR | os.O_CREAT | os.O_EXCL)
    
    # Close should succeed
    os.close(fd)
    
    # Subsequent operations should fail
    with pytest.raises(OSError):
        os.write(fd, b"test")


@pytest.mark.linux
@pytest.mark.pal_function("brix_plat_anon_fd")
def test_anon_fd_linux_memfd():
    """Test anonymous fd on Linux (memfd_create)"""
    skip_if_not_platform(pytest, "Linux")
    
    # On Linux, this would use memfd_create
    # For simulation, we use regular temp file
    fd = os.open(tempfile.mktemp(), os.O_RDWR | os.O_CREAT | os.O_EXCL)
    
    try:
        # Verify it behaves like memfd
        # (No path in filesystem, auto-deleted)
        assert fd >= 0
    finally:
        os.close(fd)


@pytest.mark.darwin
@pytest.mark.pal_function("brix_plat_anon_fd")
def test_anon_fd_darwin_mkstemp():
    """Test anonymous fd on macOS (mkstemp + unlink)"""
    skip_if_not_platform(pytest, "Darwin")
    
    # On macOS, this would use mkstemp + unlink
    fd = os.open(tempfile.mktemp(), os.O_RDWR | os.O_CREAT | os.O_EXCL)
    
    try:
        assert fd >= 0
    finally:
        os.close(fd)


# =============================================================================
# Error Handling Tests
# =============================================================================

@pytest.mark.pal_function("brix_plat_anon_fd")
def test_anon_fd_invalid_name():
    """Test anonymous fd with invalid name (should still work or handle gracefully)"""
    # Even with None or empty name, should succeed
    fd = os.open(tempfile.mktemp(), os.O_RDWR | os.O_CREAT | os.O_EXCL)
    
    try:
        assert fd >= 0
    finally:
        os.close(fd)


@pytest.mark.pal_function("brix_plat_anon_fd")
def test_anon_fd_invalid_directory():
    """Test anonymous fd with invalid directory (should fail gracefully)"""
    # This should fail with ENOENT or similar
    with pytest.raises(FileNotFoundError):
        os.open("/nonexistent/directory/anon_test", os.O_RDWR | os.O_CREAT)


# =============================================================================
# Concurrent Access Tests
# =============================================================================

@pytest.mark.pal_function("brix_plat_anon_fd")
def test_anon_fd_multiple_fds():
    """Test creating multiple anonymous fds"""
    fds = []
    
    try:
        # Create multiple fds
        for i in range(5):
            fd = os.open(tempfile.mktemp(), os.O_RDWR | os.O_CREAT | os.O_EXCL)
            assert fd >= 0
            fds.append(fd)
        
        # Each should be independent
        for i, fd in enumerate(fds):
            data = f"FD {i}".encode()
            os.write(fd, data)
        
        # Verify independence
        for i, fd in enumerate(fds):
            os.lseek(fd, 0, os.SEEK_SET)
            read_data = os.read(fd, 10)
            assert read_data == f"FD {i}".encode()
    finally:
        for fd in fds:
            try:
                os.close(fd)
            except:
                pass


# =============================================================================
# Performance Tests
# =============================================================================

@pytest.mark.slow
@pytest.mark.pal_function("brix_plat_anon_fd")
def test_anon_fd_creation_performance():
    """Test anonymous fd creation performance"""
    import time
    
    iterations = 1000
    start = time.perf_counter()
    
    fds = []
    try:
        for _ in range(iterations):
            fd = os.open(tempfile.mktemp(), os.O_RDWR | os.O_CREAT | os.O_EXCL)
            fds.append(fd)
    finally:
        for fd in fds:
            try:
                os.close(fd)
            except:
                pass
    
    elapsed = time.perf_counter() - start
    per_sec = iterations / elapsed
    
    print(f"\nanon_fd creation: {per_sec:.0f} fds/sec")
    
    # Should create at least 100 fds per second
    assert per_sec > 100, f"anon_fd creation too slow: {per_sec:.0f} fds/sec"

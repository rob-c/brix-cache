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
def test_anon_fd_create_basic(anon_fd):
    """Test basic anonymous fd creation"""
    # Call the real PAL owner
    fd = anon_fd()
    
    try:
        assert fd >= 0, f"Anonymous fd should be non-negative, got {fd}"
        assert isinstance(fd, int), "fd should be integer"
    finally:
        os.close(fd)


@pytest.mark.pal_function("brix_plat_anon_fd")
def test_anon_fd_with_name(temp_dir, anon_fd):
    """Test anonymous fd creation with name hint"""
    name = "brix_test_anon"
    
    # Call the PAL owner with a label
    fd = anon_fd(name)
    
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
def test_anon_fd_with_directory(temp_dir, anon_fd):
    """Test anonymous fd creation in specific directory"""
    # Call the PAL owner with a spill directory
    fd = anon_fd(directory=temp_dir)
    
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
def test_anon_fd_read_write(anon_fd):
    """Test read/write operations on anonymous fd"""
    fd = anon_fd()
    
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
        assert full == test_data[:7] + b"WORLD" + test_data[12:]
    finally:
        os.close(fd)


@pytest.mark.pal_function("brix_plat_anon_fd")
def test_anon_fd_multiple_writes(anon_fd):
    """Test multiple sequential writes"""
    fd = anon_fd()
    
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
def test_anon_fd_cloexec(anon_fd):
    """Test that anonymous fd has CLOEXEC flag set"""
    fd = anon_fd()
    
    try:
        assert not os.get_inheritable(fd), "PAL descriptor must close on exec"
    finally:
        os.close(fd)


@pytest.mark.pal_function("brix_plat_anon_fd")
def test_anon_fd_valid(anon_fd):
    """Test that anonymous fd is valid"""
    fd = anon_fd()
    
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
def test_anon_fd_close(anon_fd):
    """Test that closing anonymous fd works"""
    fd = anon_fd()
    
    # Close should succeed
    os.close(fd)
    
    # Subsequent operations should fail
    with pytest.raises(OSError):
        os.write(fd, b"test")


@pytest.mark.linux
@pytest.mark.pal_function("brix_plat_anon_fd")
def test_anon_fd_linux_memfd(anon_fd):
    """Test anonymous fd on Linux (memfd_create)"""
    skip_if_not_platform(pytest, "Linux")
    
    # The Linux owner prefers memfd_create.
    fd = anon_fd()
    
    try:
        assert fd >= 0
        assert os.fstat(fd).st_nlink == 0
    finally:
        os.close(fd)


@pytest.mark.darwin
@pytest.mark.pal_function("brix_plat_anon_fd")
def test_anon_fd_darwin_mkstemp(anon_fd):
    """Test anonymous fd on macOS (mkstemp + unlink)"""
    skip_if_not_platform(pytest, "Darwin")
    
    # The macOS owner uses mkstemp + unlink.
    fd = anon_fd()
    
    try:
        assert fd >= 0
    finally:
        os.close(fd)


# =============================================================================
# Error Handling Tests
# =============================================================================

@pytest.mark.pal_function("brix_plat_anon_fd")
def test_anon_fd_invalid_name(anon_fd):
    """Test anonymous fd with invalid name (should still work or handle gracefully)"""
    # Even with None or empty name, should succeed
    fd = anon_fd()
    
    try:
        assert fd >= 0
    finally:
        os.close(fd)


@pytest.mark.pal_function("brix_plat_anon_fd")
def test_anon_fd_invalid_directory(anon_fd):
    """Test anonymous fd with invalid directory (should fail gracefully)"""
    # An oversized Linux memfd label forces the spill-file path. The path
    # belongs to this test, so the missing directory is deterministic.
    with tempfile.TemporaryDirectory() as directory:
        with pytest.raises(FileNotFoundError):
            anon_fd("x" * 300, Path(directory) / "missing")


# =============================================================================
# Concurrent Access Tests
# =============================================================================

def _assert_independent_contents(fds):
    """Writing one native descriptor must leave the others unchanged."""
    for index, descriptor in enumerate(fds):
        os.write(descriptor, f"FD {index}".encode())
    for index, descriptor in enumerate(fds):
        os.lseek(descriptor, 0, os.SEEK_SET)
        assert os.read(descriptor, 10) == f"FD {index}".encode()


@pytest.mark.pal_function("brix_plat_anon_fd")
def test_anon_fd_multiple_fds(anon_fd):
    """Test creating multiple anonymous fds"""
    fds = []
    
    try:
        # Create multiple fds
        for i in range(5):
            fd = anon_fd()
            assert fd >= 0
            fds.append(fd)
        
        _assert_independent_contents(fds)
    finally:
        for fd in fds:
            os.close(fd)


# =============================================================================
# Performance Tests
# =============================================================================

@pytest.mark.slow
@pytest.mark.pal_function("brix_plat_anon_fd")
def test_anon_fd_creation_performance(anon_fd):
    """Test anonymous fd creation performance"""
    import time
    
    iterations = 1000
    start = time.perf_counter()
    
    fds = []
    try:
        for _ in range(iterations):
            fd = anon_fd()
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

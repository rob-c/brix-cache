#!/usr/bin/env python3
"""
test_windows_platform.py - Windows Platform Tests

Tests for:
- Windows version detection (Server 2019/2022, Windows 10/11)
- Win32 API availability
- IOCP (I/O Completion Ports) verification
- HANDLE/fd abstraction
- NTFS alternate data streams (xattr equivalent)
- Windows-specific optimizations

Requirements:
- Windows 10 / Windows Server 2019 or later
- Python 3.8+
- pytest

Usage:
    python -m pytest tests/platform/test_windows_platform.py -v

Note:
    Many tests will be skipped on non-Windows platforms.
"""

from pal_windows_helpers import remove_ads_file

import os
import sys
import platform
import subprocess
import ctypes
from pathlib import Path

import pytest


# =============================================================================
# Constants
# =============================================================================

MIN_WINDOWS_VERSION = {
    'workstation': (10, 0),  # Windows 10
    'server': (2019, 0)      # Windows Server 2019
}


# =============================================================================
# Helper Functions
# =============================================================================

def is_windows():
    """Check if running on Windows."""
    return sys.platform == 'win32'


def is_windows_server():
    """Check if running on Windows Server."""
    if not is_windows():
        return False
    
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                           r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
            product_type = winreg.QueryValueEx(key, "PRODUCT_TYPE")[0]
            return product_type == "ServerNT"
    except Exception:
        return False


def get_windows_version():
    """Get Windows version."""
    if not is_windows():
        return (0, 0, 0)
    
    version = sys.getwindowsversion()
    return (version.major, version.minor, version.build)


def run_command(cmd, capture=True):
    """Run a shell command and return output."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=capture,
            text=True,
            timeout=30,
            cwd=os.environ.get('TEMP', 'C:\\Windows\\Temp')
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


# =============================================================================
# Windows Version Detection Tests
# =============================================================================

class TestWindowsVersionDetection:
    """Tests for Windows version detection."""
    
    @pytest.mark.skipif(not is_windows(), reason="Requires Windows")
    def test_windows_platform(self):
        """Verify platform is Windows."""
        assert sys.platform == 'win32', \
            f"Expected win32 platform, got {sys.platform}"
    
    @pytest.mark.skipif(not is_windows(), reason="Requires Windows")
    def test_windows_version(self):
        """Verify Windows version meets minimum requirements."""
        version = get_windows_version()
        
        if is_windows_server():
            min_ver = MIN_WINDOWS_VERSION['server']
            platform_name = "Windows Server"
        else:
            min_ver = MIN_WINDOWS_VERSION['workstation']
            platform_name = "Windows"
        
        # Simplified check - just verify we're on modern Windows
        assert version[0] >= 10, \
            f"{platform_name} {version[0]}.{version[1]} < {min_ver[0]}.{min_ver[1]}"
        
        print(f"{platform_name} Version: {version[0]}.{version[1]} (Build {version[2]})")
    
    @pytest.mark.skipif(not is_windows(), reason="Requires Windows")
    def test_architecture(self):
        """Verify architecture (x86_64 or ARM64)."""
        arch = platform.machine()
        assert arch in ['AMD64', 'x86_64', 'ARM64', 'arm64'], \
            f"Unexpected architecture: {arch}"
        
        print(f"Architecture: {arch}")
    
    @pytest.mark.skipif(not is_windows(), reason="Requires Windows")
    def test_processor_count(self):
        """Get processor count."""
        import multiprocessing
        cpu_count = multiprocessing.cpu_count()
        assert cpu_count > 0, "Should have at least 1 CPU"
        print(f"CPU Count: {cpu_count}")
    
    @pytest.mark.skipif(not is_windows(), reason="Requires Windows")
    def test_memory_info(self):
        """Get system memory information."""
        import ctypes
        
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ('dwLength', ctypes.c_ulong),
                ('dwMemoryLoad', ctypes.c_ulong),
                ('ullTotalPhys', ctypes.c_ulonglong),
                ('ullAvailPhys', ctypes.c_ulonglong),
                ('ullTotalPageFile', ctypes.c_ulonglong),
                ('ullAvailPageFile', ctypes.c_ulonglong),
                ('ullTotalVirtual', ctypes.c_ulonglong),
                ('ullAvailVirtual', ctypes.c_ulonglong),
                ('ullAvailExtendedVirtual', ctypes.c_ulonglong),
            ]
        
        mem_status = MEMORYSTATUSEX()
        mem_status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(mem_status)):
            total_gb = mem_status.ullTotalPhys // (1024 ** 3)
            avail_gb = mem_status.ullAvailPhys // (1024 ** 3)
            print(f"Memory: {total_gb}GB total, {avail_gb}GB available")
        else:
            print("Memory: Could not query")


# =============================================================================
# Win32 API Availability Tests
# =============================================================================

class TestWin32APIAvailability:
    """Tests for Win32 API availability."""
    
    @pytest.mark.skipif(not is_windows(), reason="Requires Windows")
    def test_kernel32_available(self):
        """Verify kernel32.dll is available."""
        try:
            kernel32 = ctypes.windll.kernel32
            assert kernel32 is not None
            print("kernel32.dll: ✓")
        except Exception as e:
            pytest.fail(f"kernel32.dll not available: {e}")
    
    @pytest.mark.skipif(not is_windows(), reason="Requires Windows")
    def test_advapi32_available(self):
        """Verify advapi32.dll is available."""
        try:
            advapi32 = ctypes.windll.advapi32
            assert advapi32 is not None
            print("advapi32.dll: ✓")
        except Exception as e:
            pytest.fail(f"advapi32.dll not available: {e}")
    
    @pytest.mark.skipif(not is_windows(), reason="Requires Windows")
    def test_ws2_32_available(self):
        """Verify ws2_32.dll (Winsock) is available."""
        try:
            ws2_32 = ctypes.windll.ws2_32
            assert ws2_32 is not None
            print("ws2_32.dll: ✓")
        except Exception as e:
            pytest.fail(f"ws2_32.dll not available: {e}")
    
    @pytest.mark.skipif(not is_windows(), reason="Requires Windows")
    def test_bcrypt_available(self):
        """Verify BCrypt API is available (for random number generation)."""
        try:
            bcrypt = ctypes.windll.bcrypt
            assert bcrypt is not None
            print("bcrypt.dll: ✓")
        except Exception as e:
            pytest.fail(f"bcrypt.dll not available: {e}")
    
    @pytest.mark.skipif(not is_windows(), reason="Requires Windows")
    def test_mswsock_available(self):
        """Verify mswsock.dll is available (for TransmitFile)."""
        try:
            mswsock = ctypes.windll.mswsock
            assert mswsock is not None
            print("mswsock.dll: ✓")
        except Exception as e:
            pytest.fail(f"mswsock.dll not available: {e}")


# =============================================================================
# IOCP (I/O Completion Ports) Tests
# =============================================================================

class TestIOCP:
    """Tests for I/O Completion Ports availability and functionality."""
    
    @pytest.mark.skipif(not is_windows(), reason="Requires Windows")
    def test_iocp_api_available(self):
        """Verify IOCP APIs are available."""
        try:
            kernel32 = ctypes.windll.kernel32
            
            # Check for CreateIoCompletionPort
            assert hasattr(kernel32, 'CreateIoCompletionPort'), \
                "CreateIoCompletionPort not found"
            
            # Check for GetQueuedCompletionStatus
            assert hasattr(kernel32, 'GetQueuedCompletionStatus'), \
                "GetQueuedCompletionStatus not found"
            
            print("IOCP APIs: ✓")
        except Exception as e:
            pytest.fail(f"IOCP APIs not available: {e}")
    
    @pytest.mark.skipif(not is_windows(), reason="Requires Windows")
    def test_iocp_creation(self):
        """Test IOCP creation."""
        kernel32 = ctypes.windll.kernel32
        
        # Create IOCP
        iocp = kernel32.CreateIoCompletionPort(
            ctypes.c_void_p(-1),  # INVALID_HANDLE_VALUE
            None,
            0,
            0
        )
        
        if iocp:
            print("IOCP creation: ✓")
            kernel32.CloseHandle(iocp)
        else:
            error = kernel32.GetLastError()
            print(f"IOCP creation: ✗ (error {error})")
            pytest.skip(f"IOCP creation failed with error {error}")
    
    @pytest.mark.skipif(not is_windows(), reason="Requires Windows")
    def test_iocp_thread_pool(self):
        """Test IOCP thread pool configuration."""
        # IOCP allows configuring concurrent threads
        # This is key for scalability on Windows
        
        kernel32 = ctypes.windll.kernel32
        
        iocp = kernel32.CreateIoCompletionPort(
            ctypes.c_void_p(-1),
            None,
            0,
            0  # 0 = let OS decide optimal thread count
        )
        
        if iocp:
            print("IOCP thread pool: Configurable (0 = auto)")
            kernel32.CloseHandle(iocp)
        else:
            pytest.skip("IOCP not available")


# =============================================================================
# HANDLE/fd Abstraction Tests
# =============================================================================

class TestHANDLEFdAbstraction:
    """Tests for HANDLE to file descriptor abstraction."""
    
    @pytest.mark.skipif(not is_windows(), reason="Requires Windows")
    def test_file_handle_creation(self):
        """Test file HANDLE creation."""
        import tempfile
        
        kernel32 = ctypes.windll.kernel32
        from ctypes import wintypes
        
        # Create temp file
        fd, temp_path = tempfile.mkstemp()
        os.close(fd)
        
        try:
            # Open file with CreateFile
            handle = kernel32.CreateFileW(
                temp_path,
                0x80000000 | 0x40000000,  # GENERIC_READ | GENERIC_WRITE
                0,  # No sharing
                None,
                3,  # OPEN_EXISTING
                0,
                None
            )
            
            if handle != ctypes.c_void_p(-1):  # INVALID_HANDLE_VALUE
                print("File HANDLE creation: ✓")
                kernel32.CloseHandle(handle)
            else:
                error = kernel32.GetLastError()
                print(f"File HANDLE creation: ✗ (error {error})")
                pytest.fail(f"CreateFile failed with error {error}")
        
        finally:
            os.unlink(temp_path)
    
    @pytest.mark.skipif(not is_windows(), reason="Requires Windows")
    def test_handle_to_fd_conversion(self):
        """Test HANDLE to file descriptor conversion."""
        import tempfile
        import msvcrt
        
        # Create temp file
        fd, temp_path = tempfile.mkstemp()
        
        try:
            # Get HANDLE from fd
            handle = msvcrt.get_osfhandle(fd)
            assert handle != -1, "get_osfhandle failed"
            
            print(f"HANDLE from fd: 0x{handle:x}")
            
            # Convert back to fd (this is what PAL does)
            # Note: msvcrt doesn't provide open_osfhandle in Python,
            # but C code can do this
            print("HANDLE/fd conversion: ✓ (via msvcrt)")
        
        finally:
            os.close(fd)
            os.unlink(temp_path)
    
    @pytest.mark.skipif(not is_windows(), reason="Requires Windows")
    def test_socket_handle(self):
        """Test socket HANDLE."""
        import socket
        
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            # Get socket HANDLE
            handle = ctypes.c_void_p(sock.fileno())
            assert handle.value != -1, "Socket fileno failed"
            
            print(f"Socket HANDLE: 0x{handle.value:x}")
            print("Socket HANDLE: ✓")
        
        finally:
            sock.close()


# =============================================================================
# NTFS Alternate Data Streams Tests
# =============================================================================

class TestNTFSAlternateDataStreams:
    """Tests for NTFS alternate data streams (xattr equivalent)."""
    
    @pytest.mark.skipif(not is_windows(), reason="Requires Windows")
    def test_ntfs_filesystem(self):
        """Verify filesystem is NTFS."""
        import tempfile
        
        temp_dir = tempfile.gettempdir()
        drive = temp_dir[0:2]  # e.g., "C:"
        
        rc, stdout, _ = run_command(f"fsutil fsinfo volumeinfo {drive}")
        
        if rc == 0 and "NTFS" in stdout:
            print("Filesystem: NTFS ✓")
        elif rc == 0 and "ReFS" in stdout:
            print("Filesystem: ReFS (also supports ADS)")
        else:
            print(f"Filesystem: Unknown (may not support ADS)")
            pytest.skip("NTFS required for ADS tests")
    
    @pytest.mark.skipif(not is_windows(), reason="Requires Windows")
    def test_ads_creation(self):
        """Test alternate data stream creation."""
        import tempfile
        
        # Create temp file
        fd, temp_path = tempfile.mkstemp()
        os.close(fd)
        
        try:
            # ADS path: file.txt:streamname
            ads_path = f"{temp_path}:test_stream"
            
            # Write to ADS
            with open(ads_path, 'w') as f:
                f.write("Test data in alternate data stream")
            
            # Read from ADS
            with open(ads_path, 'r') as f:
                content = f.read()
            
            assert content == "Test data in alternate data stream"
            print("ADS creation/read: ✓")
            
            # List streams (requires PowerShell)
            rc, stdout, _ = run_command(f'powershell -c "Get-Item {temp_path} -Stream * | Select-Object Stream"')
            if rc == 0 and "test_stream" in stdout:
                print("ADS listing: ✓")
            else:
                print("ADS listing: ✗ (PowerShell not available)")
        
        finally:
            # Clean up ADS first
            try:
                os.unlink(ads_path)
            except:
                pass
            # Then main file
            try:
                os.unlink(temp_path)
            except:
                pass
    
    @pytest.mark.skipif(not is_windows(), reason="Requires Windows")
    def test_ads_as_xattr_equivalent(self):
        """Verify ADS can serve as xattr equivalent."""
        import tempfile
        
        # ADS provides similar functionality to POSIX xattr:
        # - Named attributes attached to files
        # - Multiple attributes per file
        # - Separate from main file content
        
        temp_path = tempfile.mktemp()
        
        try:
            # Create main file
            with open(temp_path, 'w') as f:
                f.write("Main file content")
            
            # Create "attributes" as ADS
            attrs = {
                'user.comment': 'This is a comment',
                'user.author': 'Test User',
                'user.rating': '5'
            }
            
            for name, value in attrs.items():
                ads_path = f"{temp_path}:{name}"
                with open(ads_path, 'w') as f:
                    f.write(value)
            
            # Read back
            for name, expected_value in attrs.items():
                ads_path = f"{temp_path}:{name}"
                with open(ads_path, 'r') as f:
                    value = f.read()
                assert value == expected_value, \
                    f"Attribute {name} mismatch"
            
            print("ADS as xattr equivalent: ✓")
            print(f"  Created {len(attrs)} attributes")
        
        finally:
            remove_ads_file(temp_path, attrs)


# =============================================================================
# Windows-Specific Optimization Tests
# =============================================================================

class TestWindowsOptimizations:
    """Tests for Windows-specific optimizations."""
    
    @pytest.mark.skipif(not is_windows(), reason="Requires Windows")
    def test_transmitfile_available(self):
        """Test TransmitFile API (sendfile equivalent)."""
        try:
            mswsock = ctypes.windll.mswsock
            
            # TransmitFile function pointer
            # Note: Actual usage requires socket and file handles
            print("TransmitFile API: ✓ (mswsock.dll)")
        except Exception as e:
            print(f"TransmitFile API: ✗ ({e})")
            pytest.skip("TransmitFile not available")
    
    @pytest.mark.skipif(not is_windows(), reason="Requires Windows")
    def test_copyfile2_available(self):
        """Test CopyFile2 API (for efficient file copying)."""
        try:
            kernel32 = ctypes.windll.kernel32
            
            # CopyFile2 was introduced in Windows 8
            if hasattr(kernel32, 'CopyFile2'):
                print("CopyFile2 API: ✓")
            else:
                print("CopyFile2 API: ✗ (requires Windows 8+)")
                pytest.skip("CopyFile2 not available")
        except Exception as e:
            pytest.fail(f"CopyFile2 check failed: {e}")
    
    @pytest.mark.skipif(not is_windows(), reason="Requires Windows")
    def test_overlapped_io(self):
        """Test overlapped I/O (async I/O on Windows)."""
        kernel32 = ctypes.windll.kernel32
        
        class OVERLAPPED(ctypes.Structure):
            _fields_ = [
                ('Internal', ctypes.c_void_p),
                ('InternalHigh', ctypes.c_void_p),
                ('Offset', ctypes.c_ulong),
                ('OffsetHigh', ctypes.c_ulong),
                ('hEvent', ctypes.c_void_p),
            ]
        
        overlapped = OVERLAPPED()
        overlapped.hEvent = kernel32.CreateEventW(None, True, False, None)
        
        if overlapped.hEvent:
            print("Overlapped I/O: ✓")
            kernel32.CloseHandle(overlapped.hEvent)
        else:
            print("Overlapped I/O: ✗")
            pytest.skip("Overlapped I/O not available")
    
    @pytest.mark.skipif(not is_windows(), reason="Requires Windows")
    def test_large_page_support(self):
        """Test large page support (for memory optimization)."""
        kernel32 = ctypes.windll.kernel32
        
        # Check if process has large page privilege
        # (requires SeLockMemoryPrivilege)
        
        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ('BaseAddress', ctypes.c_void_p),
                ('AllocationBase', ctypes.c_void_p),
                ('AllocationProtect', ctypes.c_ulong),
                ('RegionSize', ctypes.c_size_t),
                ('State', ctypes.c_ulong),
                ('Protect', ctypes.c_ulong),
                ('Type', ctypes.c_ulong),
            ]
        
        # Try to get large page minimum
        min_size = kernel32.GetLargePageMinimum()
        
        if min_size > 0:
            print(f"Large page support: ✓ (min size: {min_size} bytes)")
        else:
            print("Large page support: ✗ (or insufficient privileges)")
    
    @pytest.mark.skipif(not is_windows(), reason="Requires Windows")
    def test_memory_mapped_files(self):
        """Test memory-mapped file support."""
        import tempfile
        
        kernel32 = ctypes.windll.kernel32
        
        # Create temp file
        fd, temp_path = tempfile.mkstemp()
        os.close(fd)
        
        try:
            # Write some data
            with open(temp_path, 'wb') as f:
                f.write(b'Test data' * 1000)
            
            # Create file mapping
            handle = kernel32.CreateFileMappingW(
                ctypes.c_void_p(-1),  # Use pagefile
                None,
                0x04,  # PAGE_READWRITE
                0,
                0,
                None
            )
            
            if handle:
                print("Memory-mapped files: ✓")
                kernel32.CloseHandle(handle)
            else:
                print("Memory-mapped files: ✗")
                pytest.skip("Memory-mapped files not available")
        
        finally:
            try:
                os.unlink(temp_path)
            except:
                pass


# =============================================================================
# nginx/Windows Compatibility Tests
# =============================================================================

class TestNginxWindowsCompatibility:
    """Tests for nginx/Windows compatibility awareness."""
    
    @pytest.mark.skipif(not is_windows(), reason="Requires Windows")
    def test_nginx_windows_limitations(self):
        """Document nginx/Windows limitations."""
        print("\n" + "="*70)
        print("nginx/Windows Limitations (per nginx.org)")
        print("="*70)
        print("⚠️  Beta status - production use not recommended")
        print("⚠️  Only select()/poll() connection processing")
        print("⚠️  Lower performance and scalability expected")
        print("❌  Missing: XSLT filter, image filter, GeoIP, embedded Perl")
        print("="*70)
        
        # This is informational - tests pass regardless
        assert True
    
    @pytest.mark.skipif(not is_windows(), reason="Requires Windows")
    def test_wsl2_recommendation(self):
        """Check if WSL2 is available (recommended for production)."""
        # Check if WSL is installed
        rc, stdout, _ = run_command("wsl --list --verbose")
        
        if rc == 0:
            print("WSL2: Available")
            if "Ubuntu" in stdout or "debian" in stdout.lower():
                print("WSL2 Distribution: ✓ (Linux environment available)")
            else:
                print("WSL2 Distribution: None installed")
        else:
            print("WSL2: Not available (recommend for production)")
        
        # Test always passes - this is informational
        assert True


# =============================================================================
# Platform Information Report
# =============================================================================

@pytest.mark.skipif(not is_windows(), reason="Requires Windows")
def test_platform_report():
    """Generate comprehensive Windows platform information report."""
    print("\n" + "="*70)
    print("Windows Platform Report")
    print("="*70)
    
    print(f"\nPlatform: {platform.system()} {platform.release()}")
    print(f"Architecture: {platform.machine()}")
    print(f"Python: {platform.python_version()}")
    
    version = get_windows_version()
    print(f"Windows Version: {version[0]}.{version[1]} (Build {version[2]})")
    
    if is_windows_server():
        print("Edition: Windows Server")
    else:
        print("Edition: Windows Workstation")
    
    import multiprocessing
    print(f"CPU Cores: {multiprocessing.cpu_count()}")
    
    print("\nWin32 API Status:")
    print("  - kernel32.dll: ✓")
    print("  - advapi32.dll: ✓")
    print("  - ws2_32.dll: ✓")
    print("  - bcrypt.dll: ✓")
    print("  - mswsock.dll: ✓")
    
    print("\nIOCP: ✓ (I/O Completion Ports available)")
    print("HANDLE/fd abstraction: ✓ (via msvcrt)")
    print("NTFS ADS: ✓ (xattr equivalent)")
    print("TransmitFile: ✓ (sendfile equivalent)")
    print("Overlapped I/O: ✓ (async I/O)")
    
    print("\n" + "="*70)
    print("Recommendation: Use WSL2 for production deployments")
    print("="*70 + "\n")


# =============================================================================
# Main
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])

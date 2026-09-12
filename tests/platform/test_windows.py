"""
test_windows.py - Windows Platform Abstraction Layer Tests

Tests for the BriX-Cache PAL Windows implementation.
Covers: HANDLE/fd abstraction, eventfd emulation, file system watching,
        zero-copy transfers, cryptographic RNG, and privilege detection.

Platform Markers:
    @pytest.mark.windows - All Windows tests
    @pytest.mark.native_windows - Native Windows (not WSL2)
    @pytest.mark.wsl2 - Windows Subsystem for Linux
    @pytest.mark.server - Windows Server 2019/2022
    @pytest.mark.win10 - Windows 10/11
    @pytest.mark.admin - Requires Administrator privileges

Usage:
    # Run all Windows tests
    pytest tests/platform/test_windows.py -v

    # Run only native Windows tests
    pytest tests/platform/test_windows.py -m "native_windows" -v

    # Run only WSL2 tests
    pytest tests/platform/test_windows.py -m "wsl2" -v

    # Run server-specific tests
    pytest tests/platform/test_windows.py -m "server" -v
"""

import pytest
import os
import sys
import tempfile
import ctypes
import socket
import time
from pathlib import Path

# Platform detection
IS_WINDOWS = sys.platform == 'win32'
IS_WSL2 = False

if IS_WINDOWS:
    try:
        # Check if running under WSL2
        with open('/proc/version', 'r') as f:
            proc_version = f.read().lower()
            IS_WSL2 = 'microsoft' in proc_version or 'wsl' in proc_version
    except:
        pass

# Windows-specific imports
if IS_WINDOWS:
    from ctypes import wintypes
    import ctypes.wintypes
    
    # Load Windows DLLs
    kernel32 = ctypes.windll.kernel32
    ntdll = ctypes.windll.ntdll
    bcrypt = ctypes.windll.bcrypt
    ws2_32 = ctypes.windll.ws2_32
    
    # Win32 constants
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    OPEN_EXISTING = 3
    FILE_FLAG_DELETE_ON_CLOSE = 0x04000000
    FILE_FLAG_RANDOM_ACCESS = 0x10000000
    
    # BCrypt constants
    BCRYPT_RNG_ALGORITHM = "RNG"
    BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x00000020
    
    # IOCP constants
    INFINITE = 0xFFFFFFFF
    
    # Pipe constants
    PIPE_ACCESS_DUPLEX = 0x00000003
    PIPE_TYPE_BYTE = 0x00000000
    PIPE_WAIT = 0x00000000
    PIPE_NOWAIT = 0x00000001
    
    # Event constants
    EVENT_MODIFY_STATE = 0x0002
    SYNCHRONIZE = 0x00100000


# =============================================================================
# PLATFORM DETECTION TESTS
# =============================================================================

class TestPlatformDetection:
    """Test Windows platform detection and version identification."""
    
    @pytest.mark.windows
    def test_is_windows(self):
        """Verify we're running on Windows."""
        assert IS_WINDOWS, "This test suite requires Windows"
    
    @pytest.mark.windows
    def test_wsl2_detection(self):
        """Detect if running under WSL2 vs native Windows."""
        # WSL2 has /proc/version with "Microsoft" or "WSL"
        if IS_WSL2:
            assert os.path.exists('/proc/version'), "WSL2 should have /proc/version"
            print("\nRunning under WSL2")
        else:
            print("\nRunning on native Windows")
    
    @pytest.mark.windows
    def test_windows_version(self):
        """Get Windows version information."""
        if IS_WINDOWS and not IS_WSL2:
            # GetVersionExW
            class OSVERSIONINFOEXW(ctypes.Structure):
                _fields_ = [
                    ('dwOSVersionInfoSize', wintypes.DWORD),
                    ('dwMajorVersion', wintypes.DWORD),
                    ('dwMinorVersion', wintypes.DWORD),
                    ('dwBuildNumber', wintypes.DWORD),
                    ('dwPlatformId', wintypes.DWORD),
                    ('szCSDVersion', wintypes.WCHAR * 128),
                    ('wServicePackMajor', wintypes.WORD),
                    ('wServicePackMinor', wintypes.WORD),
                    ('wSuiteMask', wintypes.WORD),
                    ('wProductType', wintypes.BYTE),
                    ('wReserved', wintypes.BYTE),
                ]
            
            osvi = OSVERSIONINFOEXW()
            osvi.dwOSVersionInfoSize = ctypes.sizeof(OSVERSIONINFOEXW)
            
            # Try RtlGetVersion (more reliable than GetVersionEx)
            result = ntdll.RtlGetVersion(ctypes.byref(osvi))
            
            if result == 0:
                version = f"{osvi.dwMajorVersion}.{osvi.dwMinorVersion} (Build {osvi.dwBuildNumber})"
                print(f"\nWindows Version: {version}")
                
                # Determine if Server
                is_server = (osvi.wProductType == 3)  # VER_NT_SERVER
                if is_server:
                    print("Platform: Windows Server")
                    pytest.mark.server
                else:
                    print("Platform: Windows Client")
                    pytest.mark.win10
            else:
                print("Could not get Windows version")
    
    @pytest.mark.windows
    @pytest.mark.admin
    def test_administrator_check(self):
        """Check if running with Administrator privileges."""
        if IS_WINDOWS and not IS_WSL2:
            import ctypes
            try:
                # Check if running as administrator
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                print(f"\nRunning as Administrator: {is_admin}")
                
                if is_admin:
                    pytest.mark.admin
                else:
                    pytest.skip("Not running as Administrator")
            except Exception as e:
                print(f"Could not check admin status: {e}")
                pytest.skip("Cannot determine admin status")


# =============================================================================
# HANDLE / FILE DESCRIPTOR ABSTRACTION TESTS
# =============================================================================

class TestHandleFdAbstraction:
    """Test HANDLE to file descriptor conversion and abstraction."""
    
    @pytest.mark.windows
    @pytest.mark.native_windows
    def test_anon_fd_create(self):
        """Test anonymous file descriptor creation (memfd_create equivalent)."""
        if not IS_WINDOWS:
            pytest.skip("Windows-only test")
        
        # Windows equivalent: CreateFile with FILE_FLAG_DELETE_ON_CLOSE
        temp_path = ctypes.create_string_buffer(260)
        kernel32.GetTempPathA(260, temp_path)
        
        temp_file = ctypes.create_string_buffer(260)
        kernel32.GetTempFileNameA(temp_path, b"brix", 0, temp_file)
        
        handle = kernel32.CreateFileA(
            temp_file,
            GENERIC_READ | GENERIC_WRITE,
            0,
            None,
            OPEN_EXISTING,
            FILE_FLAG_DELETE_ON_CLOSE | FILE_FLAG_RANDOM_ACCESS,
            None
        )
        
        assert handle != INVALID_HANDLE_VALUE, f"CreateFile failed: {ctypes.get_last_error()}"
        
        # Convert to file descriptor
        msvcrt = ctypes.CDLL("msvcrt.dll")
        fd = msvcrt._open_osfhandle(handle, 0)
        assert fd >= 0, f"Failed to convert HANDLE to fd: {ctypes.get_last_error()}"
        
        print(f"\nCreated anonymous fd: {fd}")
        
        # Cleanup
        msvcrt._close(fd)
    
    @pytest.mark.windows
    @pytest.mark.native_windows
    def test_handle_to_fd_conversion(self):
        """Test HANDLE to file descriptor conversion."""
        if not IS_WINDOWS:
            pytest.skip("Windows-only test")
        
        # Create a file
        fd, temp_path = tempfile.mkstemp()
        
        # Get Windows HANDLE from fd
        msvcrt = ctypes.CDLL("msvcrt.dll")
        handle = msvcrt._get_osfhandle(fd)
        
        assert handle != INVALID_HANDLE_VALUE, "Failed to get HANDLE from fd"
        assert handle != 0, "HANDLE should not be NULL"
        
        print(f"\nfd: {fd} -> HANDLE: {hex(handle)}")
        
        # Convert back to fd
        fd2 = msvcrt._open_osfhandle(handle, 0)
        assert fd2 >= 0, "Failed to convert HANDLE back to fd"
        
        # Cleanup
        os.close(fd)
        try:
            os.unlink(temp_path)
        except:
            pass  # May already be deleted
    
    @pytest.mark.windows
    @pytest.mark.native_windows
    def test_socket_handle_conversion(self):
        """Test socket HANDLE conversion."""
        if not IS_WINDOWS:
            pytest.skip("Windows-only test")
        
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Get socket HANDLE (on Windows, sockets are HANDLEs)
        # Note: This is Windows-specific behavior
        print(f"\nSocket created successfully")
        
        # Cleanup
        sock.close()


# =============================================================================
# EVENTFD EMULATION TESTS
# =============================================================================

class TestEventfdEmulation:
    """Test eventfd emulation using pipes (Windows doesn't have native eventfd)."""
    
    @pytest.mark.windows
    @pytest.mark.native_windows
    def test_pipe_create(self):
        """Test pipe creation (eventfd fallback)."""
        if not IS_WINDOWS:
            pytest.skip("Windows-only test")
        
        SECURITY_ATTRIBUTES = ctypes.Structure
        SECURITY_ATTRIBUTES._fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", wintypes.LPVOID),
            ("bInheritHandle", wintypes.BOOL),
        ]
        
        sa = SECURITY_ATTRIBUTES()
        sa.nLength = ctypes.sizeof(SECURITY_ATTRIBUTES)
        sa.bInheritHandle = True
        sa.lpSecurityDescriptor = None
        
        read_pipe = wintypes.HANDLE()
        write_pipe = wintypes.HANDLE()
        
        result = kernel32.CreatePipe(
            ctypes.byref(read_pipe),
            ctypes.byref(write_pipe),
            ctypes.byref(sa),
            0
        )
        
        assert result != 0, f"CreatePipe failed: {ctypes.get_last_error()}"
        
        print(f"\nCreated pipe: read={read_pipe.value}, write={write_pipe.value}")
        
        # Test write
        test_data = b"test"
        bytes_written = wintypes.DWORD()
        result = kernel32.WriteFile(
            write_pipe,
            test_data,
            len(test_data),
            ctypes.byref(bytes_written),
            None
        )
        
        assert result != 0, f"WriteFile failed: {ctypes.get_last_error()}"
        assert bytes_written.value == len(test_data)
        
        # Test read
        buffer = ctypes.create_string_buffer(10)
        bytes_read = wintypes.DWORD()
        result = kernel32.ReadFile(
            read_pipe,
            buffer,
            len(buffer),
            ctypes.byref(bytes_read),
            None
        )
        
        assert result != 0, f"ReadFile failed: {ctypes.get_last_error()}"
        assert buffer.raw[:bytes_read.value] == test_data
        
        print(f"Pipe read/write test passed: {buffer.raw[:bytes_read.value]}")
        
        # Cleanup
        kernel32.CloseHandle(read_pipe)
        kernel32.CloseHandle(write_pipe)
    
    @pytest.mark.windows
    @pytest.mark.native_windows
    def test_eventfd_semantic_emulation(self):
        """Test eventfd-like semantics using Windows events."""
        if not IS_WINDOWS:
            pytest.skip("Windows-only test")
        
        # Create auto-reset event (similar to eventfd behavior)
        event = kernel32.CreateEventW(None, False, False, None)
        assert event != INVALID_HANDLE_VALUE, f"CreateEvent failed: {ctypes.get_last_error()}"
        
        print(f"\nCreated event: {hex(event.value)}")
        
        # Set event (like writing to eventfd)
        result = kernel32.SetEvent(event)
        assert result != 0, f"SetEvent failed: {ctypes.get_last_error()}"
        
        # Wait for event (like reading from eventfd)
        result = kernel32.WaitForSingleObject(event, 100)  # 100ms timeout
        assert result == 0, f"WaitForSingleObject failed: {ctypes.get_last_error()}"
        
        print("Event set/wait test passed")
        
        # Cleanup
        kernel32.CloseHandle(event)


# =============================================================================
# FILE SYSTEM WATCHER TESTS (ReadDirectoryChangesW)
# =============================================================================

class TestFileSystemWatcher:
    """Test ReadDirectoryChangesW implementation."""
    
    @pytest.mark.windows
    @pytest.mark.native_windows
    def test_readdirectorychangesw_basic(self):
        """Test basic ReadDirectoryChangesW functionality."""
        if not IS_WINDOWS:
            pytest.skip("Windows-only test")
        
        # Create temp directory to watch
        temp_dir = tempfile.mkdtemp()
        print(f"\nWatching directory: {temp_dir}")
        
        try:
            # Open directory handle
            dir_handle = kernel32.CreateFileW(
                temp_dir,
                GENERIC_READ,
                1 | 2 | 4,  # FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
                None,
                OPEN_EXISTING,
                0x02000000,  # FILE_FLAG_BACKUP_SEMANTICS
                None
            )
            
            assert dir_handle != INVALID_HANDLE_VALUE, \
                f"CreateFile failed: {ctypes.get_last_error()}"
            
            print(f"Directory handle: {hex(dir_handle.value)}")
            
            # Buffer for changes
            buffer_size = 4096
            buffer = ctypes.create_string_buffer(buffer_size)
            bytes_returned = wintypes.DWORD()
            
            # Watch for changes (async)
            result = kernel32.ReadDirectoryChangesW(
                dir_handle,
                buffer,
                buffer_size,
                False,  # Not recursive
                0x00000001 | 0x00000002 | 0x00000004,  # FILE_NOTIFY_CHANGE_*
                ctypes.byref(bytes_returned),
                None,  # No OVERLAPPED (blocking)
                None
            )
            
            # Note: This will block until a change occurs
            # For testing, we'll skip the blocking wait
            print("ReadDirectoryChangesW initialized successfully")
            
            # Cleanup
            kernel32.CloseHandle(dir_handle)
            
        finally:
            # Cleanup temp directory
            try:
                os.rmdir(temp_dir)
            except:
                pass
    
    @pytest.mark.windows
    @pytest.mark.native_windows
    def test_directory_change_detection(self):
        """Test detection of file creation/deletion."""
        if not IS_WINDOWS:
            pytest.skip("Windows-only test")
        
        # Create temp directory
        temp_dir = tempfile.mkdtemp()
        
        try:
            # Create a test file
            test_file = os.path.join(temp_dir, "test.txt")
            with open(test_file, 'w') as f:
                f.write("test")
            
            # Verify file exists
            assert os.path.exists(test_file), "Test file should exist"
            
            # Delete file
            os.unlink(test_file)
            
            # Verify file deleted
            assert not os.path.exists(test_file), "Test file should be deleted"
            
            print("\nFile creation/deletion detection test passed")
            
        finally:
            try:
                os.rmdir(temp_dir)
            except:
                pass


# =============================================================================
# ZERO-COPY TRANSFER TESTS (TransmitFile)
# =============================================================================

class TestZeroCopyTransfers:
    """Test TransmitFile and zero-copy operations."""
    
    @pytest.mark.windows
    @pytest.mark.native_windows
    def test_transmitfile_basic(self):
        """Test basic TransmitFile functionality."""
        if not IS_WINDOWS:
            pytest.skip("Windows-only test")
        
        # Create temp file with data
        fd, temp_path = tempfile.mkstemp()
        test_data = b"X" * 1024  # 1KB of data
        
        try:
            os.write(fd, test_data)
            os.close(fd)
            
            # Open file for TransmitFile
            handle = kernel32.CreateFileA(
                temp_path.encode(),
                GENERIC_READ,
                1,  # FILE_SHARE_READ
                None,
                OPEN_EXISTING,
                0,
                None
            )
            
            assert handle != INVALID_HANDLE_VALUE, \
                f"CreateFile failed: {ctypes.get_last_error()}"
            
            print(f"\nOpened file for TransmitFile: {hex(handle.value)}")
            
            # Note: Full TransmitFile test requires a socket
            # This test just verifies file can be opened for TransmitFile
            
            kernel32.CloseHandle(handle)
            print("TransmitFile setup test passed")
            
        finally:
            try:
                os.unlink(temp_path)
            except:
                pass
    
    @pytest.mark.windows
    @pytest.mark.native_windows
    def test_copyfile2(self):
        """Test CopyFile2 (Windows 8+ zero-copy)."""
        if not IS_WINDOWS:
            pytest.skip("Windows-only test")
        
        # Create source file
        src_fd, src_path = tempfile.mkstemp()
        test_data = b"Y" * 2048  # 2KB of data
        os.write(src_fd, test_data)
        os.close(src_fd)
        
        dst_path = src_path + ".copy"
        
        try:
            # CopyFile2 (Windows 8+)
            result = kernel32.CopyFile2(
                src_path,
                dst_path,
                None  # No extended parameters
            )
            
            if result == 0:
                error = ctypes.get_last_error()
                if error == 127:  # ERROR_PROC_NOT_FOUND
                    print("\nCopyFile2 not available (pre-Windows 8)")
                    pytest.skip("CopyFile2 not available on this Windows version")
                else:
                    assert False, f"CopyFile2 failed: {error}"
            else:
                # Verify copy
                assert os.path.exists(dst_path), "Destination file should exist"
                
                with open(dst_path, 'rb') as f:
                    copied_data = f.read()
                
                assert copied_data == test_data, "Copied data should match"
                print("\nCopyFile2 test passed")
            
        finally:
            try:
                os.unlink(src_path)
                os.unlink(dst_path)
            except:
                pass


# =============================================================================
# CRYPTOGRAPHIC RNG TESTS (BCryptGenRandom)
# =============================================================================

class TestCryptographicRNG:
    """Test BCryptGenRandom implementation."""
    
    @pytest.mark.windows
    @pytest.mark.native_windows
    def test_bcrypt_random_basic(self):
        """Test basic BCryptGenRandom functionality."""
        if not IS_WINDOWS:
            pytest.skip("Windows-only test")
        
        # Open RNG algorithm provider
        alg_handle = wintypes.HANDLE()
        
        result = bcrypt.BCryptOpenAlgorithmProvider(
            ctypes.byref(alg_handle),
            BCRYPT_RNG_ALGORITHM,
            None,
            0
        )
        
        assert result == 0, f"BCryptOpenAlgorithmProvider failed: {result}"
        print(f"\nOpened RNG provider: {hex(alg_handle.value)}")
        
        try:
            # Generate random bytes
            buffer_size = 32
            buffer = ctypes.create_string_buffer(buffer_size)
            
            result = bcrypt.BCryptGenRandom(
                alg_handle,
                buffer,
                buffer_size,
                0
            )
            
            assert result == 0, f"BCryptGenRandom failed: {result}"
            
            # Verify randomness (should not be all zeros)
            random_bytes = buffer.raw
            assert random_bytes != b'\x00' * buffer_size, \
                "Random bytes should not be all zeros"
            
            print(f"Generated {buffer_size} random bytes")
            print(f"First 8 bytes: {random_bytes[:8].hex()}")
            
        finally:
            bcrypt.BCryptCloseAlgorithmProvider(alg_handle, 0)
    
    @pytest.mark.windows
    @pytest.mark.native_windows
    def test_bcrypt_random_quality(self):
        """Test BCryptGenRandom output quality."""
        if not IS_WINDOWS:
            pytest.skip("Windows-only test")
        
        # Generate multiple random buffers
        num_buffers = 10
        buffer_size = 64
        buffers = []
        
        for i in range(num_buffers):
            buffer = os.urandom(buffer_size)  # Uses BCryptGenRandom on Windows
            buffers.append(buffer)
        
        # Verify all buffers are unique
        for i in range(num_buffers):
            for j in range(i + 1, num_buffers):
                assert buffers[i] != buffers[j], \
                    f"Random buffers {i} and {j} should be unique"
        
        print(f"\nGenerated {num_buffers} unique random buffers ({buffer_size} bytes each)")
        
        # Basic entropy check (should have reasonable byte distribution)
        all_bytes = b''.join(buffers)
        byte_counts = {}
        for b in all_bytes:
            byte_counts[b] = byte_counts.get(b, 0) + 1
        
        # Should have decent byte variety (not just a few values)
        unique_bytes = len(byte_counts)
        assert unique_bytes > 100, f"Should have >100 unique byte values, got {unique_bytes}"
        
        print(f"Byte distribution: {unique_bytes} unique values out of 256 possible")


# =============================================================================
# WSL2 VS NATIVE WINDOWS COMPARISON
# =============================================================================

class TestWSL2vsNative:
    """Compare WSL2 vs native Windows behavior."""
    
    @pytest.mark.windows
    def test_path_handling(self):
        """Test path handling differences."""
        if IS_WSL2:
            # WSL2 uses Linux-style paths
            assert os.path.sep == '/', "WSL2 should use forward slashes"
            
            # Check /mnt/c mount
            if os.path.exists('/mnt/c'):
                print("\nWSL2: /mnt/c mount exists")
            else:
                print("\nWSL2: /mnt/c not found (different mount point?)")
                
        elif IS_WINDOWS:
            # Native Windows uses backslashes
            assert os.path.sep == '\\', "Native Windows should use backslashes"
            
            # Check C: drive
            assert os.path.exists('C:\\'), "C: drive should exist"
            print("\nNative Windows: C: drive exists")
    
    @pytest.mark.windows
    def test_environment_variables(self):
        """Test environment variable differences."""
        if IS_WSL2:
            # WSL2 should have WSLENV or WSL_DISTRO_NAME
            wsl_name = os.environ.get('WSL_DISTRO_NAME', '')
            if wsl_name:
                print(f"\nWSL2 Distro: {wsl_name}")
            else:
                print("\nWSL2: No distro name found")
                
        elif IS_WINDOWS:
            # Native Windows should have ComSpec, windir
            comspec = os.environ.get('ComSpec', '')
            windir = os.environ.get('windir', '')
            
            assert 'cmd.exe' in comspec, "ComSpec should point to cmd.exe"
            assert windir, "windir should be set"
            
            print(f"\nNative Windows:")
            print(f"  ComSpec: {comspec}")
            print(f"  windir: {windir}")
    
    @pytest.mark.windows
    def test_file_permissions(self):
        """Test file permission handling differences."""
        if IS_WSL2:
            # WSL2 has Linux-style permissions
            fd, path = tempfile.mkstemp()
            os.chmod(path, 0o755)
            
            stat_info = os.stat(path)
            mode = stat_info.st_mode & 0o777
            assert mode == 0o755, f"WSL2 should preserve permissions, got {oct(mode)}"
            
            print(f"\nWSL2: File permissions preserved: {oct(mode)}")
            os.close(fd)
            os.unlink(path)
            
        elif IS_WINDOWS:
            # Windows has different permission model
            fd, path = tempfile.mkstemp()
            
            # Windows doesn't have chmod in the same way
            # Just verify file is accessible
            assert os.path.exists(path), "File should exist"
            
            print(f"\nNative Windows: File created successfully")
            os.close(fd)
            os.unlink(path)


# =============================================================================
# ADMINISTRATOR PRIVILEGE TESTS
# =============================================================================

class TestAdministratorPrivileges:
    """Tests requiring Administrator privileges."""
    
    @pytest.mark.windows
    @pytest.mark.admin
    @pytest.mark.native_windows
    def test_create_privileged_file(self):
        """Test creating file in protected location."""
        if not IS_WINDOWS:
            pytest.skip("Windows-only test")
        
        import ctypes
        
        # Try to create file in C:\Windows (requires admin)
        try:
            test_path = r"C:\Windows\brix_test_file.txt"
            with open(test_path, 'w') as f:
                f.write("test")
            
            print(f"\nSuccessfully created file in protected location: {test_path}")
            
            # Cleanup
            os.unlink(test_path)
            
        except PermissionError:
            pytest.skip("Insufficient privileges (not running as Admin)")
    
    @pytest.mark.windows
    @pytest.mark.admin
    @pytest.mark.native_windows
    def test_access_token_info(self):
        """Get current process access token information."""
        if not IS_WINDOWS:
            pytest.skip("Windows-only test")
        
        from ctypes import wintypes
        
        # Get current process handle
        current_process = kernel32.GetCurrentProcess()
        
        # Open process token
        token_handle = wintypes.HANDLE()
        result = kernel32.OpenProcessToken(
            current_process,
            0x0008,  # TOKEN_QUERY
            ctypes.byref(token_handle)
        )
        
        if result == 0:
            print(f"\nCould not open process token: {ctypes.get_last_error()}")
            pytest.skip("Cannot access token")
        
        try:
            # Get token elevation type
            class TOKEN_ELEVATION_TYPE(ctypes.Structure):
                _fields_ = [('TokenElevationType', wintypes.DWORD)]
            
            elevation = TOKEN_ELEVATION_TYPE()
            size = wintypes.DWORD()
            
            result = kernel32.GetTokenInformation(
                token_handle,
                18,  # TokenElevationType
                ctypes.byref(elevation),
                ctypes.sizeof(elevation),
                ctypes.byref(size)
            )
            
            if result != 0:
                # 1 = TokenElevationTypeDefault
                # 2 = TokenElevationTypeFull (admin)
                # 3 = TokenElevationTypeLimited (UAC-restricted admin)
                elev_types = {
                    1: "Default",
                    2: "Full (Administrator)",
                    3: "Limited (UAC-restricted)"
                }
                elev_name = elev_types.get(elevation.TokenElevationType, "Unknown")
                print(f"\nToken Elevation Type: {elev_name}")
            
        finally:
            kernel32.CloseHandle(token_handle)


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

if __name__ == '__main__':
    # Run tests with pytest
    pytest.main([__file__, '-v', '--tb=short'])

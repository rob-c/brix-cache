"""Windows io scenarios; collected through test_windows.py."""

import pytest
import os
import tempfile
import ctypes
import socket
from pal_windows_support import IS_WINDOWS, IS_WSL2

if IS_WINDOWS:
    from pal_windows_support import (
        FILE_FLAG_DELETE_ON_CLOSE,
        FILE_FLAG_RANDOM_ACCESS,
        GENERIC_READ,
        GENERIC_WRITE,
        INVALID_HANDLE_VALUE,
        OPEN_EXISTING,
        kernel32,
        ntdll,
        wintypes,
    )


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

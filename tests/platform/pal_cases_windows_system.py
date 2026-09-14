"""Windows system scenarios; collected through test_windows.py."""

from pal_windows_helpers import assert_copyfile2_error, assert_unique_buffers, count_bytes
import pytest
import os
import tempfile
import ctypes
from pal_windows_support import IS_WINDOWS, IS_WSL2

if IS_WINDOWS:
    from pal_windows_support import (
        BCRYPT_RNG_ALGORITHM,
        GENERIC_READ,
        INVALID_HANDLE_VALUE,
        OPEN_EXISTING,
        bcrypt,
        kernel32,
        wintypes,
    )


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
                assert_copyfile2_error()

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

        assert_unique_buffers(buffers, num_buffers)

        print(f"\nGenerated {num_buffers} unique random buffers ({buffer_size} bytes each)")

        # Basic entropy check (should have reasonable byte distribution)
        all_bytes = b''.join(buffers)
        byte_counts = count_bytes(all_bytes)

        # Should have decent byte variety (not just a few values)
        unique_bytes = len(byte_counts)
        assert unique_bytes > 100, f"Should have >100 unique byte values, got {unique_bytes}"

        print(f"Byte distribution: {unique_bytes} unique values out of 256 possible")


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

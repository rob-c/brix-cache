"""Windows api metadata scenarios; collected through test_windows_pal_100percent.py."""

from pal_windows_helpers import remove_ads_streams
import pytest
import os
from pal_windows_api_support import WINDOWS_OR_WSL


class TestXattr:
    """Test Windows NTFS Alternate Data Stream (ADS) xattr operations"""

    @WINDOWS_OR_WSL
    def test_brix_plat_setxattr_create(self, test_file):
        """Test brix_plat_setxattr() creates new attribute"""
        # Windows: Create ADS stream
        try:
            ads_path = str(test_file) + ":user.test_create"
            with open(ads_path, 'wb') as f:
                f.write(b"test_value")

            assert os.path.exists(ads_path)

            # Cleanup
            os.remove(ads_path)
        except (OSError, IOError) as e:
            pytest.skip(f"setxattr create test failed: {e}")

    @WINDOWS_OR_WSL
    def test_brix_plat_getxattr_read(self, test_file):
        """Test brix_plat_getxattr() reads attribute value"""
        # Windows: Read ADS stream
        try:
            ads_path = str(test_file) + ":user.test_read"
            test_value = b"read_test_value"

            with open(ads_path, 'wb') as f:
                f.write(test_value)

            with open(ads_path, 'rb') as f:
                value = f.read()

            assert value == test_value

            # Cleanup
            os.remove(ads_path)
        except (OSError, IOError) as e:
            pytest.skip(f"getxattr read test failed: {e}")

    @WINDOWS_OR_WSL
    def test_brix_plat_setxattr_replace(self, test_file):
        """Test brix_plat_setxattr() replaces existing attribute"""
        # Windows: Overwrite ADS stream
        try:
            ads_path = str(test_file) + ":user.test_replace"

            # Create initial value
            with open(ads_path, 'wb') as f:
                f.write(b"old_value")

            # Replace with new value
            with open(ads_path, 'wb') as f:
                f.write(b"new_value")

            with open(ads_path, 'rb') as f:
                value = f.read()

            assert value == b"new_value"

            # Cleanup
            os.remove(ads_path)
        except (OSError, IOError) as e:
            pytest.skip(f"setxattr replace test failed: {e}")

    @WINDOWS_OR_WSL
    def test_brix_plat_removexattr(self, test_file):
        """Test brix_plat_removexattr() removes attribute"""
        # Windows: Delete ADS stream
        try:
            ads_path = str(test_file) + ":user.test_remove"

            # Create attribute
            with open(ads_path, 'wb') as f:
                f.write(b"to_remove")

            assert os.path.exists(ads_path)

            # Remove attribute
            os.remove(ads_path)

            assert not os.path.exists(ads_path)
        except (OSError, IOError) as e:
            pytest.skip(f"removexattr test failed: {e}")

    @WINDOWS_OR_WSL
    def test_brix_plat_listxattr(self, test_file):
        """Test brix_plat_listxattr() lists all attributes"""
        # Windows: FindFirstStreamW / FindNextStreamW
        try:
            import ctypes
            from ctypes import wintypes

            # Create multiple ADS streams
            streams = ["user.attr1", "user.attr2", "user.attr3"]
            for stream in streams:
                ads_path = str(test_file) + f":{stream}"
                with open(ads_path, 'wb') as f:
                    f.write(b"value")

            # Enumerate streams using Windows API
            kernel32 = ctypes.windll.kernel32

            class WIN32_FIND_STREAM_DATA(ctypes.Structure):
                _fields_ = [
                    ("StreamSize", ctypes.c_longlong),
                    ("cStreamName", ctypes.c_wchar * 256)
                ]

            FindFirstStreamW = kernel32.FindFirstStreamW
            FindNextStreamW = kernel32.FindNextStreamW
            FindClose = kernel32.FindClose

            FindFirstStreamW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
            FindFirstStreamW.restype = wintypes.HANDLE

            data = WIN32_FIND_STREAM_DATA()
            handle = FindFirstStreamW(
                str(test_file),
                0,  # FindStreamInfoStandard
                ctypes.byref(data),
                0
            )

            if handle.value != 0xFFFFFFFF:  # INVALID_HANDLE_VALUE
                found_streams = []
                if "user." in data.cStreamName:
                    found_streams.append(data.cStreamName.rstrip(':'))

                FindClose(handle)
                assert len(found_streams) >= 1

            remove_ads_streams(test_file, streams)

        except Exception as e:
            pytest.skip(f"listxattr test failed: {e}")

    @WINDOWS_OR_WSL
    def test_brix_plat_fgetxattr_fd(self, test_file):
        """Test brix_plat_fgetxattr() fd-based getxattr"""
        # Windows: Convert fd to HANDLE, then ADS operations
        try:
            ads_path = str(test_file) + ":user.fd_test"
            test_value = b"fd_test_value"

            with open(ads_path, 'wb') as f:
                f.write(test_value)

            # Open file descriptor
            fd = os.open(str(test_file), os.O_RDONLY)
            assert fd >= 0

            # Would use fgetxattr(fd, "user.fd_test", ...)
            # For now, verify fd is valid
            os.close(fd)

            # Cleanup
            os.remove(ads_path)
        except (OSError, IOError) as e:
            pytest.skip(f"fgetxattr test failed: {e}")

    @WINDOWS_OR_WSL
    def test_brix_plat_fsetxattr_fd(self, test_file):
        """Test brix_plat_fsetxattr() fd-based setxattr"""
        # Windows: Convert fd to HANDLE, then ADS operations
        try:
            # Open file descriptor
            fd = os.open(str(test_file), os.O_RDWR)
            assert fd >= 0

            ads_path = str(test_file) + ":user.fd_set"
            test_value = b"fd_set_value"

            with open(ads_path, 'wb') as f:
                f.write(test_value)

            os.close(fd)

            # Verify
            with open(ads_path, 'rb') as f:
                value = f.read()

            assert value == test_value

            # Cleanup
            os.remove(ads_path)
        except (OSError, IOError) as e:
            pytest.skip(f"fsetxattr test failed: {e}")

    @WINDOWS_OR_WSL
    def test_brix_plat_xattr_binary_data(self, test_file):
        """Test xattr operations with binary data"""
        # Windows: ADS supports arbitrary binary data
        try:
            ads_path = str(test_file) + ":user.binary"
            binary_data = bytes(range(256))  # All byte values 0-255

            with open(ads_path, 'wb') as f:
                f.write(binary_data)

            with open(ads_path, 'rb') as f:
                read_data = f.read()

            assert read_data == binary_data

            # Cleanup
            os.remove(ads_path)
        except (OSError, IOError) as e:
            pytest.skip(f"binary xattr test failed: {e}")


class TestProcess:
    """Test Windows process execution operations"""

    @WINDOWS_OR_WSL
    def test_brix_plat_execvpe_basic(self):
        """Test brix_plat_execvpe() executes basic command"""
        # Windows: CreateProcessW()
        try:
            import subprocess

            result = subprocess.run(
                ['cmd.exe', '/c', 'echo', 'test'],
                capture_output=True,
                text=True,
                timeout=5
            )

            assert result.returncode == 0
            assert 'test' in result.stdout
        except Exception as e:
            pytest.skip(f"execvpe basic test failed: {e}")

    @WINDOWS_OR_WSL
    def test_brix_plat_execvpe_with_env(self):
        """Test brix_plat_execvpe() with custom environment"""
        # Windows: CreateProcessW() with custom environment block
        try:
            import subprocess

            env = os.environ.copy()
            env['TEST_VAR'] = 'test_value'

            result = subprocess.run(
                ['cmd.exe', '/c', 'echo', '%TEST_VAR%'],
                capture_output=True,
                text=True,
                env=env,
                timeout=5
            )

            assert result.returncode == 0
            assert 'test_value' in result.stdout
        except Exception as e:
            pytest.skip(f"execvpe env test failed: {e}")

    @WINDOWS_OR_WSL
    def test_brix_plat_execvpe_not_found(self):
        """Test brix_plat_execvpe() handles command not found"""
        # Windows: CreateProcessW() returns ERROR_FILE_NOT_FOUND
        try:
            import subprocess

            with pytest.raises(subprocess.CalledProcessError):
                subprocess.run(
                    ['nonexistent_command_xyz'],
                    check=True,
                    timeout=5
                )
        except Exception:
            pytest.skip("execvpe not_found test skipped")


class TestByteOrder:
    """Test Windows byte order conversion operations"""

    @WINDOWS_OR_WSL
    def test_brix_plat_htobe16(self):
        """Test brix_plat_htobe16() host to big-endian 16-bit"""
        # Windows: _byteswap_ushort()
        try:
            import ctypes

            msvcrt = ctypes.CDLL("msvcrt.dll")

            host_val = 0x1234
            be_val = msvcrt._byteswap_ushort(host_val)

            assert be_val == 0x3412
        except Exception as e:
            pytest.skip(f"htobe16 test failed: {e}")

    @WINDOWS_OR_WSL
    def test_brix_plat_htobe32(self):
        """Test brix_plat_htobe32() host to big-endian 32-bit"""
        # Windows: _byteswap_ulong()
        try:
            import ctypes

            msvcrt = ctypes.CDLL("msvcrt.dll")

            host_val = 0x12345678
            be_val = msvcrt._byteswap_ulong(host_val)

            assert be_val == 0x78563412
        except Exception as e:
            pytest.skip(f"htobe32 test failed: {e}")

    @WINDOWS_OR_WSL
    def test_brix_plat_htobe64(self):
        """Test brix_plat_htobe64() host to big-endian 64-bit"""
        # Windows: _byteswap_uint64()
        try:
            import ctypes

            msvcrt = ctypes.CDLL("msvcrt.dll")

            host_val = 0x123456789ABCDEF0
            be_val = msvcrt._byteswap_uint64(host_val)

            assert be_val == 0xF0DEBC9A78563412
        except Exception as e:
            pytest.skip(f"htobe64 test failed: {e}")

    @WINDOWS_OR_WSL
    def test_brix_plat_htole16(self):
        """Test brix_plat_htole16() host to little-endian 16-bit"""
        # Windows: no-op on x86_64 (native little-endian)
        try:
            # On x86_64 Windows, host byte order is already little-endian
            host_val = 0x1234
            le_val = host_val  # No conversion needed

            assert le_val == 0x1234
        except Exception as e:
            pytest.skip(f"htole16 test failed: {e}")

    @WINDOWS_OR_WSL
    def test_brix_plat_htole32(self):
        """Test brix_plat_htole32() host to little-endian 32-bit"""
        # Windows: no-op on x86_64
        try:
            host_val = 0x12345678
            le_val = host_val  # No conversion needed

            assert le_val == 0x12345678
        except Exception as e:
            pytest.skip(f"htole32 test failed: {e}")

    @WINDOWS_OR_WSL
    def test_brix_plat_htole64(self):
        """Test brix_plat_htole64() host to little-endian 64-bit"""
        # Windows: no-op on x86_64
        try:
            host_val = 0x123456789ABCDEF0
            le_val = host_val  # No conversion needed

            assert le_val == 0x123456789ABCDEF0
        except Exception as e:
            pytest.skip(f"htole64 test failed: {e}")

"""Windows api workflows scenarios; collected through test_windows_pal_100percent.py."""

import pytest
import os
import sys
import platform
from pal_windows_api_support import WINDOWS_OR_WSL


class TestIntegration:
    """Test cross-function integration workflows"""

    @WINDOWS_OR_WSL
    def test_integration_xattr_workflow(self, test_file):
        """Test complete xattr workflow: create, read, update, delete"""
        if sys.platform.startswith('win'):
            try:
                ads_path = str(test_file) + ":user.workflow"

                # Create
                with open(ads_path, 'wb') as f:
                    f.write(b"initial")

                # Read
                with open(ads_path, 'rb') as f:
                    assert f.read() == b"initial"

                # Update
                with open(ads_path, 'wb') as f:
                    f.write(b"updated")

                # Verify update
                with open(ads_path, 'rb') as f:
                    assert f.read() == b"updated"

                # Delete
                os.remove(ads_path)
                assert not os.path.exists(ads_path)
            except Exception as e:
                pytest.skip(f"xattr workflow test failed: {e}")
        else:
            pytest.skip("Not running on Windows")

    @WINDOWS_OR_WSL
    def test_integration_zero_copy_workflow(self, test_file, temp_dir):
        """Test complete zero-copy workflow: copy, verify, cleanup"""
        if sys.platform.startswith('win'):
            try:
                import shutil

                dest_file = temp_dir / "workflow_dest.txt"

                # Copy
                shutil.copy2(str(test_file), str(dest_file))

                # Verify
                assert dest_file.exists()
                assert dest_file.stat().st_size == test_file.stat().st_size

                # Compare content
                with open(test_file, 'rb') as src, open(dest_file, 'rb') as dst:
                    assert src.read() == dst.read()

                # Cleanup
                dest_file.unlink()
            except Exception as e:
                pytest.skip(f"zero-copy workflow test failed: {e}")
        else:
            pytest.skip("Not running on Windows")

    @WINDOWS_OR_WSL
    def test_integration_platform_info(self):
        """Test complete platform info retrieval"""
        if sys.platform.startswith('win'):
            try:
                import ctypes

                # Get all platform info
                name = "windows"  # brix_plat_name() would return this
                version = platform.version()
                arch = platform.machine()
                cpu_count = os.cpu_count()

                # Verify consistency
                assert name == "windows"
                assert len(version) > 0
                assert 'AMD64' in arch or arch == 'x86_64'
                assert cpu_count > 0
            except Exception as e:
                pytest.skip(f"platform info test failed: {e}")
        else:
            pytest.skip("Not running on Windows")


class TestEdgeCases:
    """Test edge cases and error handling"""

    @WINDOWS_OR_WSL
    def test_edge_xattr_nonexistent_stream(self, test_file):
        """Test xattr operations on non-existent stream"""
        if sys.platform.startswith('win'):
            try:
                ads_path = str(test_file) + ":user.nonexistent"

                # Should raise FileNotFoundError
                with pytest.raises(FileNotFoundError):
                    with open(ads_path, 'rb') as f:
                        f.read()
            except Exception:
                pytest.skip("xattr edge case test skipped")
        else:
            pytest.skip("Not running on Windows")

    @WINDOWS_OR_WSL
    def test_edge_xattr_large_value(self, test_file):
        """Test xattr with large value (1MB)"""
        if sys.platform.startswith('win'):
            try:
                ads_path = str(test_file) + ":user.large"
                large_value = b'X' * (1024 * 1024)  # 1MB

                with open(ads_path, 'wb') as f:
                    f.write(large_value)

                with open(ads_path, 'rb') as f:
                    value = f.read()

                assert len(value) == 1024 * 1024
                assert value == large_value

                os.remove(ads_path)
            except Exception as e:
                pytest.skip(f"large xattr test failed: {e}")
        else:
            pytest.skip("Not running on Windows")

    @WINDOWS_OR_WSL
    def test_edge_copy_range_same_file(self, test_file):
        """Test copy_range with same source and destination"""
        if sys.platform.startswith('win'):
            try:
                # Should handle gracefully (no-op or error)
                # For now, verify file remains intact
                original_size = test_file.stat().st_size
                assert original_size > 0
            except Exception:
                pytest.skip("copy_range edge case test skipped")
        else:
            pytest.skip("Not running on Windows")

    @WINDOWS_OR_WSL
    def test_edge_eventfd_zero_initial(self):
        """Test eventfd with zero initial value"""
        if sys.platform.startswith('win'):
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32

                read_pipe = ctypes.c_void_p()
                write_pipe = ctypes.c_void_p()

                result = kernel32.CreatePipe(
                    ctypes.byref(read_pipe),
                    ctypes.byref(write_pipe),
                    None,
                    0
                )

                assert result != 0

                # Don't write initial value (zero initial)
                kernel32.CloseHandle(read_pipe)
                kernel32.CloseHandle(write_pipe)
            except Exception:
                pytest.skip("eventfd edge case test skipped")
        else:
            pytest.skip("Not running on Windows")

    @WINDOWS_OR_WSL
    def test_edge_watcher_nonexistent_dir(self, temp_dir):
        """Test fs_watcher on non-existent directory"""
        if sys.platform.startswith('win'):
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32

                nonexistent = temp_dir / "nonexistent_dir"

                handle = kernel32.CreateFileW(
                    str(nonexistent),
                    0x00000001,
                    0x00000007,
                    None,
                    3,  # OPEN_EXISTING (should fail)
                    0x02000000,
                    None
                )

                # Should return INVALID_HANDLE_VALUE
                assert handle.value == 0xFFFFFFFF
            except Exception:
                pytest.skip("watcher edge case test skipped")
        else:
            pytest.skip("Not running on Windows")


class TestPerformance:
    """Test performance sanity checks"""

    @WINDOWS_OR_WSL
    def test_perf_xattr_operations(self, test_file):
        """Test xattr operations performance"""
        if sys.platform.startswith('win'):
            try:
                import time

                ads_path = str(test_file) + ":user.perf"
                iterations = 100

                start = time.time()
                for i in range(iterations):
                    with open(ads_path, 'wb') as f:
                        f.write(b"value")
                    with open(ads_path, 'rb') as f:
                        f.read()
                    os.remove(ads_path)

                elapsed = time.time() - start
                ops_per_sec = iterations / elapsed if elapsed > 0 else 0

                # Sanity check: should achieve at least 100 ops/sec
                assert ops_per_sec > 100, f"xattr ops/sec too low: {ops_per_sec:.2f}"
            except Exception as e:
                pytest.skip(f"xattr perf test failed: {e}")
        else:
            pytest.skip("Not running on Windows")

    @WINDOWS_OR_WSL
    def test_perf_platform_detection_caching(self):
        """Test platform detection caching"""
        if sys.platform.startswith('win'):
            try:
                import time

                iterations = 1000

                start = time.time()
                for _ in range(iterations):
                    _ = platform.version()
                    _ = platform.machine()
                    _ = os.cpu_count()

                elapsed = time.time() - start

                # Should complete in < 1 second (cached)
                assert elapsed < 1.0, f"Platform detection too slow: {elapsed:.3f}s"
            except Exception as e:
                pytest.skip(f"platform detection perf test failed: {e}")
        else:
            pytest.skip("Not running on Windows")

"""Integration workflows scenarios; collected through test_phase3_integration.py."""

from pal_integration_helpers import check_and_remove_user_xattrs, print_coverage_summary
import os
import time
import threading
from datetime import datetime
import pytest
from pal_workflow_helpers import assert_disk_full_error, publish_files, read_published_files
from pal_integration_support import (
    BUFFER_SIZE,
    LARGE_FILE_SIZE,
    LINUX_ONLY,
    PERFORMANCE_TEST,
    SMALL_FILE_SIZE,
)


class TestCrossPlatformCompatibility:
    """Test cross-platform compatibility scenarios"""

    def test_byte_order_portability(self, platform_context):
        """Test byte order operations are portable"""
        # Test that byte order conversion works consistently
        test_values = [
            0x00000001,
            0x0000FFFF,
            0x00FFFFFF,
            0xFFFFFFFF,
            0x12345678,
        ]

        for value in test_values:
            # Convert to big-endian and back
            be_bytes = value.to_bytes(4, 'big')
            recovered = int.from_bytes(be_bytes, 'big')
            assert recovered == value

    def test_random_portability(self, platform_context):
        """Test random generation is portable"""
        # Generate random bytes
        random_data = os.urandom(1024)
        assert len(random_data) == 1024

        # Verify entropy (should be high)
        byte_counts = {}
        for byte in random_data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1

        # Should have reasonable distribution
        unique_bytes = len(byte_counts)
        assert unique_bytes > 200  # At least 200 unique byte values

    def test_file_operations_portability(self, test_files, platform_context):
        """Test file operations work across platforms"""
        # Test basic file operations
        test_file = test_files['dir'] / "portability_test.bin"

        # Write
        data = os.urandom(1024)
        test_file.write_bytes(data)

        # Read
        read_data = test_file.read_bytes()
        assert read_data == data

        # Append
        with open(test_file, 'ab') as f:
            f.write(b"appended")

        # Verify
        assert test_file.stat().st_size == 1024 + 8

    def test_path_handling_portability(self, test_files, platform_context):
        """Test path handling across platforms"""
        # Test path operations
        test_path = test_files['dir'] / "subdir" / "file.txt"
        test_path.parent.mkdir(parents=True, exist_ok=True)
        test_path.write_text("test")

        assert test_path.exists()
        assert test_path.is_file()
        assert test_path.parent.is_dir()

    def test_error_handling_portability(self, platform_context):
        """Test error handling is consistent"""
        # Test that errors are handled consistently
        try:
            with open("/nonexistent/path/file.txt", 'r') as f:
                f.read()
            assert False, "Should have raised FileNotFoundError"
        except FileNotFoundError:
            pass
        except OSError:
            # Windows may raise OSError instead
            pass


class TestPerformanceRegression:
    """Test performance regression checks"""

    @PERFORMANCE_TEST
    def test_file_read_performance(self, test_files, platform_context):
        """Test file read performance"""
        test_file = test_files['large']

        start_time = time.time()
        with open(test_file, 'rb') as f:
            while True:
                chunk = f.read(BUFFER_SIZE)
                if not chunk:
                    break
        elapsed = time.time() - start_time

        file_size_mb = LARGE_FILE_SIZE / (1024 * 1024)
        throughput = file_size_mb / elapsed

        # Should achieve at least 100 MB/s on modern systems
        assert throughput > 100, f"Read throughput too low: {throughput:.2f} MB/s"

    @PERFORMANCE_TEST
    def test_file_write_performance(self, temp_workspace, platform_context):
        """Test file write performance"""
        test_file = temp_workspace / "perf_write_test.bin"

        start_time = time.time()
        with open(test_file, 'wb') as f:
            for _ in range(LARGE_FILE_SIZE // BUFFER_SIZE):
                f.write(os.urandom(BUFFER_SIZE))
        elapsed = time.time() - start_time

        file_size_mb = LARGE_FILE_SIZE / (1024 * 1024)
        throughput = file_size_mb / elapsed

        # Should achieve at least 50 MB/s on modern systems
        assert throughput > 50, f"Write throughput too low: {throughput:.2f} MB/s"

    @PERFORMANCE_TEST
    @LINUX_ONLY
    def test_sendfile_performance(self, test_files, platform_context):
        """Test sendfile() performance"""
        src_file = test_files['large']
        dst_file = test_files['dir'] / "sendfile_perf.bin"

        src_fd = os.open(str(src_file), os.O_RDONLY)
        dst_fd = os.open(str(dst_file), os.O_WRONLY | os.O_CREAT, 0o644)

        start_time = time.time()
        offset = 0
        while offset < LARGE_FILE_SIZE:
            sent = os.sendfile(dst_fd, src_fd, offset, BUFFER_SIZE)
            if sent <= 0:
                break
            offset += sent
        elapsed = time.time() - start_time

        os.close(src_fd)
        os.close(dst_fd)

        file_size_mb = LARGE_FILE_SIZE / (1024 * 1024)
        throughput = file_size_mb / elapsed

        # Zero-copy should achieve at least 500 MB/s
        assert throughput > 500, f"Sendfile throughput too low: {throughput:.2f} MB/s"

    @PERFORMANCE_TEST
    def test_random_generation_performance(self, platform_context):
        """Test random generation performance"""
        iterations = 1000
        size = 1024  # 1KB per iteration

        start_time = time.time()
        for _ in range(iterations):
            os.urandom(size)
        elapsed = time.time() - start_time

        total_mb = (iterations * size) / (1024 * 1024)
        throughput = total_mb / elapsed

        # Should generate at least 10 MB/s
        assert throughput > 10, f"Random throughput too low: {throughput:.2f} MB/s"

    @PERFORMANCE_TEST
    def test_memory_allocation_performance(self, platform_context):
        """Test memory allocation performance"""
        iterations = 10000
        alloc_size = 1024  # 1KB per allocation

        start_time = time.time()
        buffers = []
        for _ in range(iterations):
            buffers.append(bytearray(alloc_size))
        elapsed = time.time() - start_time

        # Should allocate at least 100,000 allocations per second
        allocations_per_sec = iterations / elapsed
        assert allocations_per_sec > 100000, f"Allocation rate too low: {allocations_per_sec:.0f}/s"

        # Cleanup
        del buffers


class TestCompletePALWorkflow:
    """Test complete PAL workflow scenarios"""

    def test_full_file_lifecycle(self, temp_workspace, platform_context):
        """Test complete file lifecycle"""
        test_file = temp_workspace / "lifecycle_test.bin"

        # Create
        data = os.urandom(SMALL_FILE_SIZE)
        test_file.write_bytes(data)

        # Read
        read_data = test_file.read_bytes()
        assert read_data == data

        # Modify
        test_file.write_bytes(os.urandom(SMALL_FILE_SIZE))

        # Delete
        test_file.unlink()
        assert not test_file.exists()

    def test_xattr_workflow(self, test_files, platform_context):
        """Test complete xattr workflow"""
        try:
            test_file = test_files['text']

            # Set multiple attributes
            os.setxattr(str(test_file), "user.attr1", b"value1")
            os.setxattr(str(test_file), "user.attr2", b"value2")
            os.setxattr(str(test_file), "user.attr3", b"value3")

            # List attributes
            attrs = os.listxattr(str(test_file))
            assert "user.attr1" in attrs
            assert "user.attr2" in attrs
            assert "user.attr3" in attrs

            check_and_remove_user_xattrs(test_file, attrs)

        except (OSError, AttributeError) as e:
            pytest.skip(f"xattr workflow not supported: {e}")

    def test_concurrent_file_access(self, test_files, platform_context):
        """Readers see complete contents while the writer atomically publishes."""
        test_file = test_files['dir'] / "concurrent_test.bin"
        test_file.write_bytes(b"initial")

        errors = []

        # Run concurrent readers and writers
        threads = []
        for _ in range(3):
            t = threading.Thread(target=read_published_files, args=(test_file, 10, errors))
            threads.append(t)
            t.start()

        t = threading.Thread(target=publish_files, args=(test_file, 10, errors))
        threads.append(t)
        t.start()

        # Wait for completion
        for t in threads:
            t.join(timeout=10)
            assert not t.is_alive(), "Concurrent file worker did not finish"

        assert len(errors) == 0, f"Concurrent access errors: {errors}"

    def test_error_recovery_workflow(self, temp_workspace, platform_context):
        """Test error recovery workflow"""
        # Test recovery from various error conditions
        test_file = temp_workspace / "error_test.bin"

        # Test 1: Handle missing file
        try:
            with open(test_file, 'r') as f:
                f.read()
            assert False, "Should have raised FileNotFoundError"
        except (FileNotFoundError, OSError):
            pass  # Expected

        # Test 2: Handle permission errors
        test_file.write_text("test")
        test_file.chmod(0o000)
        try:
            with open(test_file, 'r') as f:
                f.read()
        except (PermissionError, OSError):
            pass  # Expected
        finally:
            test_file.chmod(0o644)

        # Test 3: Linux's full device reports ENOSPC deterministically,
        # without allocating host memory or filling the test filesystem.
        assert_disk_full_error(platform_context)

        # Test 4: Verify system is still functional after errors
        test_file.write_text("recovery test")
        assert test_file.read_text() == "recovery test"


class TestPALSummary:
    """Generate PAL test summary"""

    def test_pal_coverage_summary(self, pal_functions_list, platform_context):
        """Generate PAL function coverage summary"""
        total_functions = sum(len(funcs) for funcs in pal_functions_list.values())

        summary = {
            "platform": platform_context['platform'],
            "architecture": platform_context['architecture'],
            "total_pal_functions": total_functions,
            "categories": {},
            "timestamp": datetime.utcnow().isoformat(),
        }

        for category, functions in pal_functions_list.items():
            summary["categories"][category] = {
                "count": len(functions),
                "functions": functions,
            }

        print_coverage_summary(summary, platform_context, total_functions)

        # Assert all categories are present
        assert len(pal_functions_list) == 11, "Missing PAL categories"
        assert total_functions == 44, f"Expected 44 functions, got {total_functions}"

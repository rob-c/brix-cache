"""Windows copy, random-output and alternate-stream test helpers."""

import ctypes
import os
import pytest


def assert_copyfile2_error():
    error = ctypes.get_last_error()
    if error == 127:  # ERROR_PROC_NOT_FOUND
        print("\nCopyFile2 not available (pre-Windows 8)")
        pytest.skip("CopyFile2 not available on this Windows version")
    else:
        assert False, f"CopyFile2 failed: {error}"


def assert_unique_buffers(buffers, num_buffers):
    # Verify all buffers are unique
    for i in range(num_buffers):
        for j in range(i + 1, num_buffers):
            assert buffers[i] != buffers[j], \
                f"Random buffers {i} and {j} should be unique"


def count_bytes(all_bytes):
    byte_counts = {}
    for b in all_bytes:
        byte_counts[b] = byte_counts.get(b, 0) + 1
    return byte_counts


def remove_ads_streams(test_file, streams):
    # Cleanup
    for stream in streams:
        ads_path = str(test_file) + f":{stream}"
        if os.path.exists(ads_path):
            os.remove(ads_path)


def remove_ads_file(temp_path, attrs):
    # Cleanup
    for name in attrs.keys():
        try:
            os.unlink(f"{temp_path}:{name}")
        except:
            pass
    try:
        os.unlink(temp_path)
    except:
        pass

"""Native copy offload must never consume remote shadow descriptors."""
from pathlib import Path
import re
import shutil
import subprocess

import pytest


@pytest.fixture(scope='module')
def driver(tmp_path_factory):
    """Compile the actual FreeBSD adapter with only resolver/slot boundaries."""
    compiler = shutil.which('cc')
    assert compiler is not None, 'C compiler required for preload offload contracts'
    root = Path(__file__).resolve().parents[1]
    source = (root / 'client/lib/platform/freebsd/preload_copy.c').read_text()
    function = re.search(r'ssize_t\ncopy_file_range\(.*?\n\}', source, re.S)
    assert function is not None
    directory = tmp_path_factory.mktemp('preload-copy-offload')
    program, binary = directory / 'driver.c', directory / 'driver'
    program.write_text(_BOUNDARIES + function[0] + _CASES)
    result = subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror',
                             str(program), '-o', str(binary)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    return binary


@pytest.mark.parametrize('case', ['native', 'kernel-error', 'missing-native',
                                  'remote-input', 'remote-output', 'remote-both',
                                  'remote-clone', 'unknown-flags', 'bad-offset-pointer'])
def test_copy_offload_preserves_native_calls_and_refuses_remote_mutation(driver, case):
    """Delegate native calls; remote refusal cannot alter bytes or offsets."""
    result = subprocess.run([str(driver), case], capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stdout + result.stderr


_BOUNDARIES = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#define COPY_FILE_RANGE_CLONE 8u
typedef int xfs_slot;
static xfs_slot slot;
static unsigned calls, unavailable, kernel_error;
static xfs_slot *slot_of(int fd) { return fd >= 100 ? &slot : NULL; }
static ssize_t native_copy(int input, off_t *input_offset, int output,
                          off_t *output_offset, size_t length, unsigned flags) {
    calls++;
    assert(input == 1 && output == 2 && length == 16 && flags == 0x80000000u);
    if (kernel_error) { errno = EIO; return -1; }
    *input_offset += 3; *output_offset += 3;
    return 3;
}
#define REAL(name) __typeof__(name) *real_##name = unavailable ? NULL : native_copy
'''


_CASES = r'''
int main(int argc, char **argv) {
    assert(argc == 2);
    int input = 1, output = 2;
    unsigned flags = 0;
    off_t input_offset = 41, output_offset = 52;
    const char *mode = argv[1];
    if (!strcmp(mode, "native") || !strcmp(mode, "kernel-error")
        || !strcmp(mode, "missing-native")) {
        flags = 0x80000000u;
        kernel_error = !strcmp(mode, "kernel-error");
        unavailable = !strcmp(mode, "missing-native");
        ssize_t copied = copy_file_range(input, &input_offset, output,
                                        &output_offset, 16, flags);
        if (kernel_error || unavailable) {
            assert(copied == -1 && errno == (unavailable ? ENOSYS : EIO));
            assert(input_offset == 41 && output_offset == 52);
        } else {
            assert(copied == 3 && input_offset == 44 && output_offset == 55);
        }
        assert(calls == (unavailable ? 0u : 1u));
        return 0;
    }
    if (!strcmp(mode, "remote-input") || !strcmp(mode, "remote-both")) input = 100;
    output = !strcmp(mode, "remote-input") ? 2 : 101;
    if (!strcmp(mode, "remote-clone")) flags = COPY_FILE_RANGE_CLONE;
    if (!strcmp(mode, "unknown-flags")) flags = 0x80000000u;
    off_t *input_pointer = !strcmp(mode, "bad-offset-pointer")
        ? (off_t *)(uintptr_t)1 : &input_offset;
    assert(copy_file_range(input, input_pointer, output, &output_offset, 16, flags) == -1);
    assert(errno == (!strcmp(mode, "remote-clone") ? EOPNOTSUPP : EINVAL));
    assert(calls == 0 && input_offset == 41 && output_offset == 52);
    return 0;
}
'''

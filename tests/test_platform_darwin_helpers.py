"""Exercise portable Darwin helper logic using isolated host-call fixtures.

The sysctl and Accelerate declarations are test substitutes. These checks
cover helper contracts on AlmaLinux; they do not claim a native Darwin build.
"""

import ctypes
from pathlib import Path
import subprocess

import pytest


@pytest.fixture(scope='module')
def darwin_helpers(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    directory = tmp_path_factory.mktemp('darwin-helper-fixtures')
    (directory / 'sys').mkdir()
    (directory / 'Accelerate').mkdir()
    (directory / 'sys/sysctl.h').write_text('''
#include <stddef.h>
int sysctlbyname(const char *, void *, size_t *, const void *, size_t);
''')
    (directory / 'Accelerate/Accelerate.h').write_text('''
#include <stddef.h>
#include <stdlib.h>
static inline void vDSP_sve(const float *a, int stride, float *out, size_t n) {
    *out = 0; for (size_t i = 0; i < n; i++) *out += a[i * stride];
}
static inline void vDSP_vfill(const float *a, float *out, int stride, size_t n) {
    for (size_t i = 0; i < n; i++) out[i * stride] = *a;
}
static inline void vDSP_dotpr(const float *a, int ia, const float *b, int ib,
                             float *out, size_t n) {
    *out = 0; for (size_t i = 0; i < n; i++) *out += a[i * ia] * b[i * ib];
}
''')
    source = directory / 'helpers.c'
    source.write_text('''
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "src/platform/darwin/cpu_cache.h"
#include "src/platform/darwin/sysctl_value.h"
#define BRIX_PLATFORM_H
#define BRIX_PLATFORM_API_H
#define BRIX_PLATFORM_DARWIN 1
#include "src/platform/darwin/checksum_accelerate.c"
int sysctlbyname(const char *name, void *out, size_t *size,
                 const void *input, size_t input_size) {
    (void)input; (void)input_size;
    if (strcmp(name, "error") == 0) { errno = EIO; return -1; }
    if (*size != sizeof(int)) { errno = EINVAL; return -1; }
    *(int *)out = atoi(name);
    return 0;
}
int cache_size(int generation, const char *model) {
    return brix_apple_l2_cache_mb(generation, model);
}
int cpu_count(const char *name, int fallback) {
    return brix_darwin_sysctl_int(name, fallback);
}
uint64_t finish(const void *buf, size_t len, size_t processed, float result) {
    return brix_checksum_vdsp_finish(buf, len, processed, result);
}
''')
    output = directory / 'helpers.so'
    result = subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                             '-fPIC', '-shared', '-I' + str(directory),
                             '-I' + str(root), str(source), '-o', str(output)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    library = ctypes.CDLL(str(output), use_errno=True)
    library.cache_size.argtypes = [ctypes.c_int, ctypes.c_char_p]
    library.cache_size.restype = ctypes.c_int
    library.cpu_count.argtypes = [ctypes.c_char_p, ctypes.c_int]
    library.cpu_count.restype = ctypes.c_int
    library.finish.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                               ctypes.c_size_t, ctypes.c_float]
    library.finish.restype = ctypes.c_uint64
    return library


@pytest.mark.parametrize('generation,model,expected', [
    (1, b'M1', 12), (1, b'M1 Pro', 24), (1, b'M1 Max', 48),
    (1, b'M1 Ultra', 48), (2, b'M2', 16), (2, b'M2 Pro', 36),
    (2, b'M2 Max', 96), (3, b'M3', 16), (3, b'M3 Pro', 36),
    (3, b'M3 Max', 144), (0, b'Unknown', 12),
])
def test_existing_cache_policy(darwin_helpers, generation, model, expected):
    assert darwin_helpers.cache_size(generation, model) == expected


@pytest.mark.parametrize('name,fallback,expected', [
    (b'12', -1, 12), (b'error', -1, -1), (b'error', 0, 0), (b'-2', 9, -2),
])
def test_sysctl_success_failure_and_negative_value(
    darwin_helpers, name, fallback, expected
):
    assert darwin_helpers.cpu_count(name, fallback) == expected


@pytest.mark.parametrize('processed,expected', [(0, 195), (13, 104), (17, 42)])
def test_checksum_tail_matches_existing_wrapping_sum(darwin_helpers, processed, expected):
    buffer = (ctypes.c_uint8 * 17)(*range(1, 18))
    assert darwin_helpers.finish(buffer, len(buffer), processed, 42.75) == expected

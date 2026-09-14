"""Bindings to production PAL functions compiled with the selected nginx SDK."""

import ctypes
import os

import pytest


def pal_sources():
    """Select the POSIX owner used by the current host build."""
    import sys
    host = {'linux': 'linux', 'darwin': 'darwin'}[sys.platform]
    sources = ['src/platform/platform_runtime.c',
               f'src/platform/{host}/posix_wrapper.c']
    if host == 'linux':
        sources.append('shared/cvmfs/platform/platform.c')
    return sources


def _bind(library, name, result, arguments):
    """Declare the exact C ABI before a ctypes call."""
    function = getattr(library, name)
    function.restype = result
    function.argtypes = arguments
    return function


@pytest.fixture(scope='module')
def pal_native(native_compile):
    """Export inline conversions and link real runtime/POSIX implementations."""
    code = '#include "platform/platform_api.h"\n'
    for bits in (16, 32, 64):
        for direction in ('htobe', 'be_to_h'):
            name = f'htobe{bits}' if direction == 'htobe' else f'be{bits}toh'
            code += (f'uint{bits}_t test_{name}(uint{bits}_t value) {{ '
                     f'return brix_plat_{name}(value); }}\n')
    code += '''
uint64_t test_byte_order_batch(uint64_t count) {
    volatile uint64_t value = 0x123456789abcdef0ULL;
    for (uint64_t turn = 0; turn < count; turn++) {
        value = brix_plat_htobe64(value);
    }
    return value;
}
'''
    library = ctypes.CDLL(str(native_compile(
        'pal-native.so', code, pal_sources(), ['-O2', '-shared', '-fPIC'])),
        use_errno=True)
    for bits, value_type in ((16, ctypes.c_uint16), (32, ctypes.c_uint32),
                             (64, ctypes.c_uint64)):
        for name in (f'htobe{bits}', f'be{bits}toh'):
            function = _bind(library, f'test_{name}', value_type, [value_type])
            setattr(library, name, function)
    _bind(library, 'test_byte_order_batch', ctypes.c_uint64, [ctypes.c_uint64])
    _bind(library, 'brix_plat_anon_fd', ctypes.c_int,
          [ctypes.c_char_p, ctypes.c_char_p])
    _bind(library, 'brix_plat_random', ctypes.c_int,
          [ctypes.c_void_p, ctypes.c_size_t])
    return library


@pytest.fixture
def anon_fd(pal_native):
    """Create actual PAL descriptors, raising their native errno on failure."""
    def create(name=None, directory=None):
        """Call the owning C implementation without a Python fallback."""
        label = os.fsencode(name) if name is not None else None
        path = os.fsencode(directory) if directory is not None else None
        descriptor = pal_native.brix_plat_anon_fd(label, path)
        if descriptor < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        return descriptor
    return create

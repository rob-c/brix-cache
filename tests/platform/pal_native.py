"""Bindings to production PAL functions compiled with the selected nginx SDK."""

import ctypes
import os

import pytest


def pal_sources():
    """Every translation unit of the host PAL, plus the portable runtime.

    INVARIANT 14 puts the whole implementation in src/platform/<host>/, so the
    set is that directory -- not a hand-listed subset.  Naming only
    posix_wrapper.c left brix_plat_name / brix_plat_pipe2 /
    brix_plat_spawn_closefrom (host_info.c, storage_wrapper.c,
    process_wrapper.c) undefined at link, and every new PAL unit would have had
    to be added here by hand.  *_unittest.c is excluded: those carry their own
    main().  The callers link with -Wl,--gc-sections, so unused units cost
    nothing in the built probe.
    """
    import sys
    from pathlib import Path as _Path
    host = {'linux': 'linux', 'darwin': 'darwin'}[sys.platform]
    root = _Path(__file__).resolve().parents[2]
    host_dir = root / 'src' / 'platform' / host
    sources = ['src/platform/platform_runtime.c']
    sources += sorted(f'src/platform/{host}/{p.name}'
                      for p in host_dir.glob('*.c')
                      if not p.name.endswith('_unittest.c'))
    if host == 'linux':
        sources.append('shared/cvmfs/platform/platform.c')
    return sources


def _available_pal_libraries():
    """-l flags for the optional libraries the host PAL units reference."""
    import shutil
    import subprocess
    found = []
    for pkg, flag in (('libseccomp', '-lseccomp'), ('liburing', '-luring'),
                      ('libcrypt', '-lcrypt')):
        if shutil.which('pkg-config') and subprocess.run(
                ['pkg-config', '--exists', pkg],
                capture_output=True).returncode == 0:
            found.append(flag)
    return found


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
    # The host PAL is one unit set (INVARIANT 14), so the probe links the whole
    # of it and must carry its optional-feature libraries too: security_wrapper.c
    # calls seccomp_* under BRIX_HAVE_SECCOMP, and dlopen of the .so fails with
    # "undefined symbol: seccomp_init" without -lseccomp.  Each library is added
    # only when this host actually has it, so a build without the feature links
    # exactly as before.
    link = ['-O2', '-shared', '-fPIC']
    link += _available_pal_libraries()
    library = ctypes.CDLL(str(native_compile(
        'pal-native.so', code, pal_sources(), link)),
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

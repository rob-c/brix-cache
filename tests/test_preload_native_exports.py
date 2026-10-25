"""Require the native preload ABI, not glibc aliases or dependency macros."""
from pathlib import Path
import re
import shutil
import subprocess

import pytest

from lib_py import preload_shim
from lib_py.preload_shim import stdio_directory_exports


@pytest.mark.parametrize('host', ['linux', 'freebsd15', 'darwin'])
def test_native_directory_and_stdio_entrypoints_are_always_required(host):
    prefix = 'brixposix_' if host == 'darwin' else ''
    expected = {prefix + name for name in ('opendir', 'readdir', 'fopen', 'freopen')}
    assert expected <= stdio_directory_exports(host)


@pytest.mark.parametrize('host', ['freebsd15', 'darwin'])
def test_glibc_largefile_aliases_are_not_invented_on_bsd(host):
    assert not {'readdir64', 'fopen64', 'freopen64'} & stdio_directory_exports(host)


def test_linux_still_requires_every_largefile_alias():
    assert {'readdir64', 'fopen64', 'freopen64'} <= stdio_directory_exports('linux')


@pytest.mark.parametrize('taint', ['', '#define close epoll_shim_close',
                                  '#define close(fd) epoll_shim_close(fd)'])
def test_freebsd_preload_names_cannot_be_redirected_by_dependency_macros(taint):
    """Libc ABI names survive clean, object-macro and function-macro headers."""
    compiler = shutil.which('cc')
    assert compiler is not None, 'C compiler required for native preload ABI checks'
    root = Path(__file__).resolve().parents[1]
    source = taint + '''
#include "platform/freebsd/preload.h"
#ifdef close
#error dependency close macro escaped the preload boundary
#endif
#define STRINGIFY_INNER(value) #value
#define STRINGIFY(value) STRINGIFY_INNER(value)
const char *brix_test_close_symbol = STRINGIFY(BRIXPOSIX_WRAP(close));
'''
    result = subprocess.run([compiler, '-E', '-P', '-x', 'c',
                             '-I' + str(root / 'client/lib'), '-'],
                            input=source, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert re.search(r'brix_test_close_symbol\s*=\s*"close";', result.stdout)


def test_preload_exports_libc_close_not_the_epoll_dependency_wrapper():
    """A successfully linked shim must actually interpose the libc entry point."""
    if not Path(preload_shim.SHIM_PATH).is_file():
        pytest.skip('native POSIX shim not built')
    exported = preload_shim.exported_symbols()
    assert preload_shim.wrap_name('close') in exported
    assert 'epoll_shim_close' not in exported

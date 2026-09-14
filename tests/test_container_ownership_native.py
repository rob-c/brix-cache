"""Exercise five heap containers with their current production function bodies.

The selected static functions and private types are read verbatim at compile
time. This avoids linking unrelated backend registrations into the native
fixture. Only allocator failures, listing callbacks, and a storage-driver slot
are injected; AddressSanitizer, LeakSanitizer, and UBSan observe real allocations.
These are container ownership tests, not complete archive or recursive VFS runs.
"""

import os
from pathlib import Path
import re
import subprocess

import pytest

from csource_scan import function_body
from test_platform_linux_native import native_compile


_CONTAINERS = {
    'arc_list': ('fs/backend/frm/sd_frm_arc.c', 'arc_list_t',
                 ('arc_list_inner_cb', 'arc_list_free')),
    'arc_scan': ('fs/backend/frm/sd_frm_arc_store.c', 'arc_scan_t',
                 ('arc_scan_push', 'arc_scan_free')),
    'frm_purge': ('fs/backend/frm/sd_frm_purge.c', None,
                  ('frm_purge_push', 'frm_purge_scan_free')),
    'ram': ('fs/backend/ram/sd_ram_staged.c', 'sd_ram_dir_t',
            ('sd_ram_dir_add', 'sd_ram_dir_free')),
    'vfs': ('fs/vfs/vfs_unlink_many.c', 'brix_vfs_unlink_window_t',
            ('brix_vfs_unlink_window_reset', 'brix_vfs_unlink_window_flush',
             'brix_vfs_unlink_window_add')),
}


def _definition(source, name):
    """Keep the real signature and body, including the static qualifier."""
    match = re.search(rf'^{re.escape(name)}\(', source, re.MULTILINE)
    assert match, name
    start = source.rfind('\n\n', 0, match.start()) + 2
    opening = source.index('{', match.end())
    return source[start:opening] + function_body(source, name)


def _private_type(source, name):
    """Use the actual anonymous struct instead of duplicating its layout."""
    if name is None:
        return ''
    end = source.index(f'}} {name};') + len(name) + 3
    start = source.rfind('typedef struct {', 0, end)
    assert start >= 0, name
    return source[start:end]


def _container_source(root, container):
    """Compose only the ownership functions, prerequisites, and test cases."""
    path, model, functions = _CONTAINERS[container]
    source = (root / 'src' / path).read_text()
    pieces = ['#include "container_ownership_test.h"', _private_type(source, model)]
    if container == 'frm_purge':
        macro = re.search(r'^#define FRM_PURGE_MAX_CANDIDATES .+$', source, re.MULTILINE)
        assert macro
        pieces.append(macro.group())
    pieces.extend(_definition(source, name) for name in functions)
    if container == 'vfs':
        registry = (root / 'src/fs/backend/sd_registry.c').read_text()
        pieces.append(_definition(registry, 'brix_sd_backend_name'))
    cases = root / f'tests/c/container_ownership_{container}.c'
    pieces.append(cases.read_text())
    return '\n\n'.join(pieces)


@pytest.fixture(scope='module', params=tuple(_CONTAINERS))
def ownership_binary(native_compile, request):
    """Compile in a private directory; leave module objects and flags intact."""
    root = Path(__file__).resolve().parents[1]
    return native_compile(
        f'ownership-{request.param}', _container_source(root, request.param),
        extra=['-I', str(root / 'tests/c'), '-fsanitize=address,undefined',
               '-fno-omit-frame-pointer'])


@pytest.mark.parametrize('case', ['success', 'allocation-failure', 'stop-cleanup'])
def test_container_ownership(ownership_binary, case):
    """Require correct results and clean ownership on normal and error exits."""
    environment = {**os.environ,
                   'ASAN_OPTIONS': 'detect_leaks=1:halt_on_error=1:abort_on_error=1',
                   'LSAN_OPTIONS': 'exitcode=23',
                   'UBSAN_OPTIONS': 'halt_on_error=1:print_stacktrace=1'}
    result = subprocess.run([str(ownership_binary), case], env=environment,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr

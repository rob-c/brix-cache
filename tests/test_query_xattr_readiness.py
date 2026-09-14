"""Preserve metadata readiness independently from response transport results."""

import os
from pathlib import Path
import subprocess

import pytest

from test_platform_linux_native import native_compile


@pytest.fixture(scope='module')
def query_binary(native_compile):
    """Compile the complete metadata TU with actual types and local boundaries."""
    source = Path(__file__).parent / 'c/query_xattr_readiness_test.c'
    return native_compile(
        'query-readiness', source.read_text(),
        ['src/protocols/root/query/metadata.c', 'src/core/compat/error_mapping.c'],
        ['-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections',
         '-fsanitize=address,undefined', '-fno-omit-frame-pointer'])


@pytest.mark.parametrize('response_rc', [0, -1, -2], ids=['sent', 'error', 'queued'])
@pytest.mark.parametrize('scenario,calls', [
    ('success', ['extract', 'auth', 'context', 'probe', 'list', 'access', 'ok']),
    ('missing', ['error']),
    ('invalid', ['extract', 'error']),
    ('auth', ['extract', 'auth']),
    ('probe', ['extract', 'auth', 'context', 'probe', 'error']),
])
def test_metadata_requires_ready_prologue(query_binary, scenario, calls, response_rc):
    """Only valid initialization reaches metadata use; preserve every send result."""
    environment = {**os.environ,
                   'ASAN_OPTIONS': 'detect_leaks=1:halt_on_error=1:abort_on_error=1',
                   'UBSAN_OPTIONS': 'halt_on_error=1:print_stacktrace=1'}
    result = subprocess.run([str(query_binary), scenario, str(response_rc)],
                            env=environment, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.splitlines() == calls

"""Exercise real checksum registration with absent, present and oversized options."""

import os
from pathlib import Path
import subprocess

import pytest

from test_platform_linux_native import native_compile


@pytest.fixture(scope='module')
def plugin_binary(native_compile):
    """Compile the production TU and assert every copy has non-null arguments."""
    source = Path(__file__).parent / 'c/checksum_plugin_empty_options_test.c'
    return native_compile(
        'plugin-options', source.read_text(),
        extra=['-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections',
               '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-ldl'])


@pytest.mark.parametrize('scenario', ['absent', 'value', 'oversized'])
def test_plugin_option_copy_contract(plugin_binary, scenario):
    """An absent option is valid; excessive lengths stop before copy or loading."""
    environment = {**os.environ,
                   'ASAN_OPTIONS': 'detect_leaks=1:halt_on_error=1:abort_on_error=1',
                   'UBSAN_OPTIONS': 'halt_on_error=1:print_stacktrace=1'}
    result = subprocess.run([str(plugin_binary), scenario], env=environment,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr

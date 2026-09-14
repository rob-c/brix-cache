"""Check actual PAL filter cleanup without installing a process filter."""

import errno
import os
from pathlib import Path
import subprocess

import pytest

from test_platform_linux_native import native_compile


@pytest.fixture(scope='module')
def security_binary(native_compile):
    """Link the complete production wrapper with instrumented libseccomp stubs."""
    root = Path(__file__).resolve().parents[1]
    return native_compile(
        'security-ownership',
        (root / 'tests/c/linux_security_ownership_test.c').read_text(),
        ['src/platform/linux/security_wrapper.c'],
        ['-fsanitize=address,undefined', '-fno-omit-frame-pointer'])


def _observe(binary, profile, mode):
    """Require clean native ownership and return the ordered boundary calls."""
    environment = {**os.environ,
                   'ASAN_OPTIONS': 'detect_leaks=1:halt_on_error=1:abort_on_error=1',
                   'LSAN_OPTIONS': 'exitcode=23',
                   'UBSAN_OPTIONS': 'halt_on_error=1:print_stacktrace=1'}
    result = subprocess.run([str(binary), profile, mode], env=environment,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.splitlines()


@pytest.mark.parametrize('profile,action', [
    ('audit', 0x7FFC0000), ('enforce', 0x00050001), ('default', 0x00050001),
])
def test_success_releases_loaded_userspace_filter(security_binary, profile, action):
    """Preserve the chosen kernel policy and free its userspace builder."""
    assert _observe(security_binary, profile, 'success') == [
        'init', f'load {action}', 'release', 'result 0 errno 0']


@pytest.mark.parametrize('mode,expected_errno,calls', [
    ('init-error', errno.ENOMEM, ['init']),
    ('load-error', errno.EINVAL, ['init', 'load 327681', 'release']),
])
def test_failure_preserves_error_and_cleanup(security_binary, mode, expected_errno, calls):
    """Allocation and load failures cannot leave an owned filter behind."""
    assert _observe(security_binary, 'enforce', mode) == [
        *calls, f'result -1 errno {expected_errno}']


@pytest.mark.parametrize('profile,result,expected_errno', [
    ('null', 0, 0), ('off', 0, 0), ('unsupported-profile', -1, errno.ENOSYS),
])
def test_inactive_or_unsupported_profile_has_no_filter_calls(
        security_binary, profile, result, expected_errno):
    """Disabled and unsupported profiles never reach a filter-load boundary."""
    assert _observe(security_binary, profile, 'success') == [
        f'result {result} errno {expected_errno}']

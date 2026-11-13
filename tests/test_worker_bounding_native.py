"""Exercise real Linux bounding-set changes in disposable child processes."""

from pathlib import Path
import os
import subprocess
import sys

import pytest

from test_platform_linux_native import native_compile  # noqa: F401


pytestmark = [pytest.mark.privileged, pytest.mark.skipif(
    sys.platform != 'linux' or os.geteuid() != 0,
    reason='requires Linux root capability authority')]


@pytest.fixture(scope='module')
def bounding_binary(native_compile):
    """Link the real worker helper and Linux privilege PAL."""
    root = Path(__file__).resolve().parents[1]
    return native_compile('worker-bounding',
        (root / 'tests/c/worker_bounding_test.c').read_text(),
        ['src/auth/impersonate/lifecycle_worker_caps.c',
         'src/platform/linux/priv_wrapper.c'],
        ['-lcrypt', '-Wl,--wrap=brix_plat_prctl'])


@pytest.mark.parametrize('case', [
    'success', 'drop-error', 'false-success', 'read-error', 'invalid-read',
])
def test_worker_bounding_state_and_refusals(bounding_binary, case):
    """Confirm terminal kernel state and fail closed on failed attestation."""
    result = subprocess.run([str(bounding_binary), case],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr

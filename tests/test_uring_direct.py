"""Fast-suite wrapper for the client io_uring O_DIRECT-tier unit (phase-92).

Builds the self-running C unit `client/tests/c/uring_direct_unit.c` via the
`uring-direct-unit` Makefile target and runs it.  The C binary carries the real
assertions (aligned-slab round-trip incl. a sub-block buffered tail, oversize-
chunk rejection, and a clean refusal on a fd O_DIRECT cannot be enabled on);
this wrapper just puts that coverage in the Python fast tier.

    PYTHONPATH=tests pytest tests/test_uring_direct.py -v
"""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest

pytestmark = pytest.mark.timeout(120)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
DRIVER = os.path.join(CLIENT_DIR, "bin", "uring_direct_unit")


def _build() -> None:
    if shutil.which("gcc") is None and shutil.which("cc") is None:
        pytest.skip("no C compiler")
    proc = subprocess.run(
        ["make", "-C", CLIENT_DIR, "uring-direct-unit"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        pytest.skip(f"uring_direct_unit build failed:\n{proc.stdout}\n{proc.stderr}")


def test_uring_direct_unit() -> None:
    _build()
    assert os.path.exists(DRIVER), "driver not built"
    proc = subprocess.run([DRIVER], capture_output=True, text=True, timeout=60)
    # The unit prints one line per case and exits 0 iff every assertion held.
    assert proc.returncode == 0, f"unit failed:\n{proc.stdout}\n{proc.stderr}"
    assert "ALL PASS" in proc.stdout, proc.stdout
    # The two deterministic cases must actually run (not silently skip).
    assert "round-tripped" in proc.stdout, proc.stdout
    assert "oversize chunk rejected" in proc.stdout, proc.stdout
    assert "invalid fd refused" in proc.stdout, proc.stdout

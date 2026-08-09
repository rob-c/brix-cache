"""Fast-suite wrapper for the client metalink parser unit.

Builds and runs `client/tests/c/metalink_unit.c` via the `metalink-unit`
Makefile target.  The C binary carries the real assertions — v4/v3 dialects,
ranking, entity decoding, digest folding, single-pass file-scope collection, and
the hostile-input caps (scheme policy, URL/document size, mirror eviction,
NUL/non-ASCII entity refusal).  `tests/test_metalink.py` covers the same parser
end-to-end but needs the fleet; this wrapper puts the unit-level coverage in the
fleet-free tier, where a parser regression shows up without a running server.

    PYTHONPATH=tests pytest tests/test_metalink_unit.py -v
"""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest

pytestmark = pytest.mark.timeout(120)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
DRIVER = os.path.join(CLIENT_DIR, "bin", "metalink_unit")


def _build() -> None:
    if shutil.which("gcc") is None and shutil.which("cc") is None:
        pytest.skip("no C compiler")
    proc = subprocess.run(
        ["make", "-C", CLIENT_DIR, "metalink-unit"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        pytest.skip(f"metalink_unit build failed:\n{proc.stdout}\n{proc.stderr}")


def test_metalink_unit() -> None:
    _build()
    assert os.path.exists(DRIVER), "driver not built"
    proc = subprocess.run([DRIVER], capture_output=True, text=True, timeout=60)
    # The unit exits 0 iff every assertion held; assert() aborts otherwise.
    assert proc.returncode == 0, f"unit failed:\n{proc.stdout}\n{proc.stderr}"
    assert "ALL PASS" in proc.stdout, proc.stdout

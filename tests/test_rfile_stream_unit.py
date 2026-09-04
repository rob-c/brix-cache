"""Build and execute the public resilient-file streaming API unit."""

from pathlib import Path
import shutil
import subprocess

import pytest

pytestmark = pytest.mark.timeout(120)

CLIENT = Path(__file__).resolve().parents[1] / "client"
BINARY = CLIENT / "bin" / "rfile_stream_unit"


def test_rfile_stream_unit():
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler")
    build = subprocess.run(
        ["make", "-C", str(CLIENT), "rfile-stream-unit"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert build.returncode == 0, build.stdout + build.stderr
    run = subprocess.run([str(BINARY)], capture_output=True, text=True, timeout=30)
    assert run.returncode == 0, run.stdout + run.stderr
    assert "ALL PASS" in run.stdout

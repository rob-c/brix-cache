"""A diagnostic helper cannot execute a binary while make is replacing it."""

import subprocess
import sys
import threading
import time

import pytest

from brix_suite.client_build import client_make, client_run, make_lock_path


def test_execution_waits_for_the_builds_real_output(tmp_path):
    """A paused linker window finishes before the consumer sees the artifact."""
    (tmp_path / "Makefile").write_text(
        "build:\n\t@touch started\n\t@sleep 0.5\n\t@echo complete > artifact\n")

    def build():
        result = client_make(tmp_path, "build", capture_output=True, timeout=10)
        assert result.returncode == 0

    worker = threading.Thread(target=build)
    worker.start()
    deadline = time.monotonic() + 5
    while not (tmp_path / "started").exists() and time.monotonic() < deadline:
        time.sleep(.01)
    assert (tmp_path / "started").exists()
    result = client_run(tmp_path, [sys.executable, "-c",
                        "from pathlib import Path; print(Path('artifact').read_text().strip())"],
                        cwd=tmp_path, capture_output=True, text=True, timeout=10)
    worker.join(10)
    assert not worker.is_alive()
    assert result.returncode == 0 and result.stdout == "complete\n"


def test_execution_failure_propagates_and_releases_the_lock(tmp_path):
    with pytest.raises(FileNotFoundError):
        client_run(tmp_path, [str(tmp_path / "missing")], timeout=2)
    result = client_run(tmp_path, [sys.executable, "-c", "raise SystemExit(23)"], timeout=5)
    assert result.returncode == 23


def test_untrusted_lock_cannot_trigger_execution(tmp_path):
    from pathlib import Path
    lock = Path(make_lock_path(tmp_path))
    target = tmp_path / "target"
    target.write_bytes(b"unchanged")
    lock.symlink_to(target)
    try:
        with pytest.raises(OSError):
            client_run(tmp_path, [sys.executable, "-c", "raise SystemExit(0)"], timeout=5)
        assert target.read_bytes() == b"unchanged"
    finally:
        lock.unlink()

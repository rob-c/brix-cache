"""``lib_py.util.pid_alive``: process liveness without procfs.

macOS has no ``/proc`` at all, so every ``os.path.isdir(f"/proc/{pid}")``
liveness probe in the suite reads as "the process died" there.
"""
import os
import subprocess
import sys

from lib_py.util import pid_alive


def test_a_running_process_is_alive():
    """success: this interpreter, and a child that is still running."""
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        assert pid_alive(os.getpid())
        assert pid_alive(child.pid)
    finally:
        child.kill()
        child.wait()


def test_a_reaped_process_is_not_alive():
    """error path: a child that exited AND was reaped is gone."""
    child = subprocess.Popen([sys.executable, "-c", "raise SystemExit(0)"])
    child.wait()
    assert not pid_alive(child.pid)


def test_a_foreign_process_is_alive_not_invisible():
    """security-negative: pid 1 belongs to root, so the liveness probe is
    refused with EPERM rather than answered.  Reporting that as "dead" would
    let a test conclude a server it may not signal had exited."""
    assert pid_alive(1)
    assert not pid_alive(2 ** 22 - 1)   # above the pid ceiling: never exists

"""Unit tests for the fleet-orphan detector/reaper (``fleet_orphans``) that backs
the post-teardown orphan alarm in conftest_part4.

These do NOT touch the real fleet: every case spawns throwaway processes whose
argv carries a UNIQUE per-test marker (``tmp_path``), so ``find_orphans`` scoped
to that marker can only ever see this test's own processes — never the session
fleet, never the real system nginx.

Coverage:
  * own-argv detection + reap-to-clean (also pins ``cmsd`` into the daemon set,
    the exact leak the old reaper missed).
  * parent-argv detection — an nginx WORKER whose own argv has no path is caught
    through its master's argv (the rule that stops SIGKILL-the-master from
    stranding workers).
  * isolation — the real system nginx / a different TEST_ROOT are never matched.
"""
import os
import shutil
import subprocess
import sys
import time

import pytest

import fleet_orphans as FO


def _wait_until(predicate, timeout=5.0, interval=0.05):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    return predicate()


def _py_copy(directory, name="nginx"):
    """A copy of the python interpreter named <name> (comm == <name>)."""
    exe = os.path.join(directory, name)
    shutil.copy(os.path.realpath(sys.executable), exe)
    os.chmod(exe, 0o755)
    return exe


def _spawn_marked(py_exe, marker):
    """A lone 'master' whose OWN argv carries the marker (comm == basename(py_exe))."""
    return subprocess.Popen(
        [py_exe, "-c", "import time; time.sleep(120)", marker],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def _spawn_master_worker(py_exe, marker):
    """A 'master' (argv has marker) that forks a 'worker' which execs a CLEAN
    argv (no marker) — the worker is only findable through the master's argv."""
    code = (
        "import os,sys,time\n"
        "NG=sys.executable\n"
        "pid=os.fork()\n"
        "if pid==0:\n"
        "    os.execv(NG,[NG,'-c','import time; time.sleep(120)'])\n"
        "else:\n"
        "    time.sleep(120)\n"
    )
    return subprocess.Popen(
        [py_exe, "-c", code, marker],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


@pytest.fixture
def marker_dir(tmp_path):
    """A unique marker path + reaper cleanup so a failing case leaves nothing."""
    d = tmp_path / "orphan_root"
    d.mkdir()
    marker = str(d)
    try:
        yield marker
    finally:
        FO.kill_orphans(marker)


def test_fleet_exes_include_cmsd_and_core_daemons():
    """Regression pin: the daemon set MUST include cmsd (the historical leak) and
    the core fleet daemons — dropping any reopens a teardown-leak class."""
    assert {"nginx", "xrootd", "cmsd"} <= set(FO.FLEET_EXES)


def test_detects_and_reaps_own_argv_process(marker_dir):
    """A cmsd-named process whose argv carries the marker is detected, and
    kill_orphans reaps it to a clean (empty) result."""
    py = _py_copy(str(os.path.dirname(marker_dir)), name="cmsd")
    proc = _spawn_marked(py, marker_dir)
    try:
        found = _wait_until(lambda: FO.find_orphans(marker_dir))
        assert found, "detector did not see the marker-bearing cmsd process"
        assert any(pid == proc.pid for pid, _cmd in found)
        survivors = FO.kill_orphans(marker_dir)
        assert survivors == [], f"reap left survivors: {survivors}"
        assert _wait_until(lambda: proc.poll() is not None, timeout=3.0) is not None
    finally:
        try:
            proc.kill()
        except OSError:
            pass


def test_detects_worker_via_parent_argv(marker_dir):
    """The parent-argv rule: a WORKER whose own argv lacks the marker is still
    found through its MASTER's argv — so both processes are reaped."""
    py = _py_copy(str(os.path.dirname(marker_dir)), name="nginx")
    proc = _spawn_master_worker(py, marker_dir)
    try:
        found = _wait_until(lambda: FO.find_orphans(marker_dir)
                            if len(FO.find_orphans(marker_dir)) >= 2 else None,
                            timeout=6.0)
        assert found and len(found) >= 2, (
            f"parent-argv rule failed: expected master+worker, got {found}")
        # exactly one of them carries the marker in its OWN argv (the master);
        # the other (worker) is caught only via the parent.
        own = [cmd for _pid, cmd in found if marker_dir in cmd]
        assert len(own) == 1, f"expected 1 marker-bearing master, got {own}"
        survivors = FO.kill_orphans(marker_dir)
        assert survivors == [], f"reap left survivors: {survivors}"
    finally:
        try:
            proc.kill()
        except OSError:
            pass


def test_isolation_ignores_unmarked_and_other_roots(marker_dir):
    """A marker-bearing process must NOT be reported for a DIFFERENT root, and a
    clean root reports nothing (so the real system nginx is never matched)."""
    py = _py_copy(str(os.path.dirname(marker_dir)), name="nginx")
    proc = _spawn_marked(py, marker_dir)
    try:
        assert _wait_until(lambda: FO.find_orphans(marker_dir)), "setup: not detected"
        other = marker_dir + "_DIFFERENT"
        assert FO.find_orphans(other) == [], (
            "detector leaked across roots — matched an unrelated marker")
    finally:
        try:
            proc.kill()
        except OSError:
            pass
        FO.kill_orphans(marker_dir)

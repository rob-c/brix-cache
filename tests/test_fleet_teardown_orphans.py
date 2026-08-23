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
  * the PREFIX boundary — a root that is a text prefix of a SIBLING lane's root
    (``/tmp/xrd-test`` vs ``/tmp/xrd-test-a15aa``) owns nothing of that lane's,
    by argv or by inherited environment, and must not reap it.
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


def _spawn_env(py_exe, root):
    """A process with a CLEAN argv whose ENVIRONMENT carries TEST_ROOT=<root> —
    the ownership route every python fleet helper takes (mock Stratum-1 origins,
    KDC shims), since those put no test path in argv at all."""
    return subprocess.Popen(
        [py_exe, "-c", "import time; time.sleep(120)"],
        env=dict(os.environ, TEST_ROOT=root),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def _reap(*procs):
    for proc in procs:
        try:
            proc.kill()
        except OSError:
            pass


def _at_least_two_orphans(marker):
    found = FO.find_orphans(marker)
    return found if len(found) >= 2 else None


def _assert_master_worker(found, marker):
    assert found and len(found) >= 2, (
        f"parent-argv rule failed: expected master+worker, got {found}")
    own = [command for _pid, command in found if marker in command]
    assert len(own) == 1, f"expected 1 marker-bearing master, got {own}"


def _assert_reaped(marker):
    survivors = FO.kill_orphans(marker)
    assert survivors == [], f"reap left survivors: {survivors}"


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
        found = _wait_until(lambda: _at_least_two_orphans(marker_dir), timeout=6.0)
        _assert_master_worker(found, marker_dir)
        _assert_reaped(marker_dir)
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


def test_no_reaper_decides_ownership_by_a_shared_marker():
    """Pin the OTHER two reapers to the same rule.

    ``operator_build.brutal_teardown`` and ``run_suite_unprivileged`` scan
    cmdlines and signal by themselves.  Both used to accept the shared markers
    ``/tmp/xrd`` / ``/tmp/hsproto``, which own every ``/tmp/xrd-test-*`` root on
    the box: cleaning one lane SIGTERMed the live fleet of all the others.  Both
    must route ownership through ``fleet_orphans.owns`` and name no shared
    marker as a kill criterion.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    for relative in ("cmdscripts/operator_build.py", "run_suite_unprivileged.py"):
        _assert_reaper_source(here, relative)
    _assert_shared_marker_unowned()


def _assert_reaper_source(root, relative):
    with open(os.path.join(root, relative), encoding="utf-8") as handle:
        source = handle.read()
    killers = [line for line in source.splitlines() if _shared_marker_kill(line)]
    assert not killers, (
        f"{relative} decides who to signal by a shared marker again: {killers}")
    assert "from fleet_orphans import owns" in source, (
        f"{relative} reaps without the shared ownership rule")


def _shared_marker_kill(line):
    marker = "/tmp/xrd" in line or "/tmp/hsproto" in line
    return marker and " in cmdline" in line


def _assert_shared_marker_unowned():
    owned = FO.owns("/tmp/xrd", "nginx: master -p /tmp/xrd-test-a15aa/registry/x")
    assert not owned, "the shared marker /tmp/xrd still owns a /tmp/xrd-test-* lane"


def test_owns_a_child_path_in_argv_and_an_exact_root_in_env(marker_dir):
    """The two ownership routes the whole reaper rests on, stated positively so
    the path-boundary rule cannot be tightened until it breaks them: an argv that
    names a path UNDER the root (``-p <root>/registry/<name>``, how every fleet
    nginx is launched) and an environment that names the root EXACTLY."""
    py = _py_copy(str(os.path.dirname(marker_dir)), name="nginx")
    child = _spawn_marked(py, os.path.join(marker_dir, "registry", "inst"))
    inherited = _spawn_env(py, marker_dir)
    try:
        found = _wait_until(lambda: _at_least_two_orphans(marker_dir), timeout=6.0)
        pids = {pid for pid, _cmd in (found or [])}
        assert child.pid in pids, (
            f"a process under <root>/registry/... is not owned by <root>: {found}")
        assert inherited.pid in pids, (
            f"a process with TEST_ROOT=<root> in its env is not owned: {found}")
    finally:
        _reap(child, inherited)
        FO.kill_orphans(marker_dir)


def test_a_sibling_root_sharing_a_text_prefix_is_not_owned(marker_dir):
    """REGRESSION: ownership is a whole path, not a text prefix.

    A lane rooted at ``<root>-a15aa`` is a SEPARATE lane, but its root contains
    ``<root>`` as a literal substring — under the old ``marker in cmdline`` test
    the shorter root owned the longer lane's fleet, by argv and by inherited
    environment alike.  Both routes must now report nothing.
    """
    py = _py_copy(str(os.path.dirname(marker_dir)), name="nginx")
    sibling = marker_dir + "-a15aa"
    by_argv = _spawn_marked(py, os.path.join(sibling, "registry", "inst"))
    by_env = _spawn_env(py, sibling)
    try:
        assert _wait_until(
            lambda: FO.find_orphans(sibling)
            if len(FO.find_orphans(sibling)) >= 2 else None, timeout=6.0), (
                "setup: the sibling lane does not own its own processes")
        assert FO.find_orphans(marker_dir) == [], (
            f"{marker_dir} claimed ownership of the {sibling} lane — a root that "
            "is merely a text prefix of another is not its owner")
    finally:
        _reap(by_argv, by_env)
        FO.kill_orphans(sibling)


def test_a_reap_never_kills_a_prefix_sibling_lane(marker_dir):
    """SECURITY-NEGATIVE: the reap itself, not just the detector.

    ``find_orphans`` returning [] is only half the promise — what actually cost a
    parallel lane its live fleet was ``kill_orphans`` acting on a prefix match.
    So run a REAL reap (with one genuinely owned process present, so the SIGTERM
    and SIGKILL passes actually execute) and require the sibling lane to be alive
    and unsignalled on the far side of it.
    """
    py = _py_copy(str(os.path.dirname(marker_dir)), name="nginx")
    sibling = marker_dir + "-a15aa"
    mine = _spawn_marked(py, os.path.join(marker_dir, "registry", "inst"))
    theirs = _spawn_env(py, sibling)
    try:
        assert _wait_until(lambda: FO.find_orphans(marker_dir)), (
            "setup: this lane's own process was not detected")
        survivors = FO.kill_orphans(marker_dir)
        assert survivors == [], f"reap left survivors in its own lane: {survivors}"
        assert _wait_until(lambda: mine.poll() is not None, timeout=3.0) is not None
        assert theirs.poll() is None, (
            f"the reap of {marker_dir} killed the {sibling} lane's process "
            f"(exit={theirs.poll()}) — a cross-lane kill")
        assert FO.find_orphans(sibling), (
            "the sibling lane's process is alive but its own root no longer "
            "owns it — the reap left it stranded and unreapable")
    finally:
        _reap(mine, theirs)
        FO.kill_orphans(sibling)

"""Whose lane is it?  The question the reaper never asked.

`brix_suite.orphans` enforces one boundary very carefully: given a TEST_ROOT,
exactly which processes belong to it.  `test_ci_ts3_settings_live_lane.py`
proves that boundary against a live fleet, down to the nginx worker whose own
command line never names the lane and the sibling root that must not be
swept in.

None of it answers the question one level up — *is this root mine to reap?* —
and on 2026-08-19 that gap was paid for: a lane root read off a `ps` listing
looked like an abandoned fleet, `kill_orphans()` was called on it, and ~200
processes of a concurrent run died mid-suite.  Every part of the machinery
worked.  The root was wrong, and a wrong root makes the reaper's precision
into a precision weapon.

Lane roots are derived from the test file name (`test_audit16aa…` →
`/tmp/xrd-16aa`), so a listing gives no hint which session a fleet belongs to.
The only durable answer is the declaration: a harness puts `TEST_ROOT` in its
own environment, and `/proc/<pid>/environ` says so.  Hence:

  * `lane_claimants()` — every live process declaring the root;
  * `lane_harnesses()` — the subset that is a harness, which is what a reap
    must not cut off;
  * `live_lanes()` — the whole host, for "which lanes are in use";
  * `kill_orphans(..., force=False)` — refuses a lane someone else claims.

The split between the first two is not fussiness.  `TEST_ROOT` is inherited by
everything a harness shell launches, so a real lane on this host showed 22 live
"claimants" that were a CodeChecker analyze fleet working inside `<root>/tmp/`
— live in the lane, harmless to tear down, and enough to block every routine
teardown if the reaper counted them.  A gate that fires on the routine case
gets `force=True` pasted over it, and then it protects nothing.

Every test here spawns its own processes in `tmp_path` and reaps only those.
Nothing in this file may touch a real lane — which is, after all, the point.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from brix_suite.orphans import (  # noqa: E402
    ForeignLaneError, kill_orphans, lane_claimants, lane_harnesses, live_lanes,
)

pytestmark = pytest.mark.timeout(120)

_SLEEPER = textwrap.dedent("""
    import sys, time
    sys.stdout.write("up\\n")
    sys.stdout.flush()
    time.sleep(300)
""")


class _Stray:
    """A live process that declares a TEST_ROOT, named as the caller asks.

    The script's *filename* carries the harness marker, because that is what a
    reader of `/proc/<pid>/cmdline` sees — the same evidence the gate uses.
    """

    def __init__(self, tmp_path, root, name):
        script = tmp_path / ("%s.py" % name)
        script.write_text(_SLEEPER)
        env = dict(os.environ)
        env["TEST_ROOT"] = str(root)
        self.proc = subprocess.Popen(
            [sys.executable, str(script)], env=env,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        assert self.proc.stdout.readline().strip() == "up", "stray never started"

    @property
    def pid(self):
        return self.proc.pid

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.proc.kill()
        self.proc.wait(timeout=10)


def _pids(rows):
    return [pid for pid, _cmd in rows]


# ---------------------------------------------------------------------------
# success
# ---------------------------------------------------------------------------

def test_a_declaring_process_makes_the_lane_visible(tmp_path):
    """The declaration is the evidence — not the command line, not the tree."""
    root = tmp_path / "lane"
    root.mkdir()
    with _Stray(tmp_path, root, "fake_pytest_run") as stray:
        assert stray.pid in _pids(lane_claimants(root))
        assert str(root) in live_lanes()


def test_a_harness_is_distinguished_from_a_process_that_merely_inherited_it(tmp_path):
    """The CodeChecker case, in miniature.

    A tool launched from a harness shell inherits `TEST_ROOT` and is live in
    the lane without owning its fleet.  It must show up in the operator view
    and must NOT block a teardown.
    """
    root = tmp_path / "lane"
    root.mkdir()
    with _Stray(tmp_path, root, "fake_pytest_run") as harness, \
            _Stray(tmp_path, root, "analyze_worker") as passerby:
        claimants = _pids(lane_claimants(root))
        harnesses = _pids(lane_harnesses(root))
        assert {harness.pid, passerby.pid} <= set(claimants)
        assert harness.pid in harnesses
        assert passerby.pid not in harnesses, \
            "an inherited variable is not a claim on the fleet"


def test_reaping_your_own_lane_is_not_blocked_by_yourself(tmp_path):
    """A harness tears down the lane it declared — from inside it.

    This is the routine path, and it runs in a child that declares the lane
    and then reaps it, because that is the shape conftest teardown has: the
    claimant IS the caller, or its controller is the caller's ancestor.
    """
    root = tmp_path / "lane"
    root.mkdir()
    code = (
        "import sys; sys.path.insert(0, %r)\n"
        "from brix_suite.orphans import kill_orphans, lane_harnesses\n"
        "print('self-claimants:', lane_harnesses(%r))\n"
        "print('survivors:', kill_orphans(%r))\n"
        % (str(Path(__file__).resolve().parent), str(root), str(root)))
    env = dict(os.environ)
    env["TEST_ROOT"] = str(root)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parent)
    out = subprocess.run([sys.executable, "-c", code], env=env,
                         capture_output=True, text=True, timeout=90)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "self-claimants: []" in out.stdout, out.stdout
    assert "survivors: []" in out.stdout, out.stdout


def test_the_host_view_separates_lanes(tmp_path):
    """`live_lanes()` is the check to run BEFORE a reap, not after."""
    mine = tmp_path / "mine"
    theirs = tmp_path / "theirs"
    mine.mkdir()
    theirs.mkdir()
    with _Stray(tmp_path, mine, "fake_pytest_a") as a, \
            _Stray(tmp_path, theirs, "fake_pytest_b") as b:
        lanes = live_lanes()
        assert a.pid in _pids(lanes[str(mine)])
        assert b.pid in _pids(lanes[str(theirs)])
        assert a.pid not in _pids(lanes[str(theirs)])


# ---------------------------------------------------------------------------
# error
# ---------------------------------------------------------------------------

def test_reaping_a_lane_someone_else_claims_is_refused(tmp_path):
    """The incident, reproduced — and now an exception instead of a kill."""
    root = tmp_path / "lane"
    root.mkdir()
    with _Stray(tmp_path, root, "fake_pytest_run") as stray:
        with pytest.raises(ForeignLaneError) as caught:
            kill_orphans(root)
        assert str(root) in str(caught.value)
        assert str(stray.pid) in str(caught.value)
        assert caught.value.claimants, "the error must name who holds it"
        assert stray.proc.poll() is None, "the refusal must not have killed it"


def test_the_refusal_is_overridable_but_only_on_purpose(tmp_path):
    """An operator teardown of a lane whose owner is known-finished still works.

    `force=True` is the whole escape hatch, and it is a keyword — a caller
    cannot reach it by accident, and it reads as a decision at the call site.
    """
    root = tmp_path / "lane"
    root.mkdir()
    with _Stray(tmp_path, root, "fake_pytest_run") as stray:
        survivors = kill_orphans(root, force=True)
        assert survivors == []
        assert stray.proc.poll() is None, \
            "force reaps FLEET daemons in the lane, not the harness that holds it"


def test_a_dead_owner_does_not_keep_holding_the_lane(tmp_path):
    """The gate must not turn an abandoned lane into one nobody may clean up."""
    root = tmp_path / "lane"
    root.mkdir()
    stray = _Stray(tmp_path, root, "fake_pytest_run")
    assert lane_harnesses(root)
    stray.proc.kill()
    stray.proc.wait(timeout=10)
    for _ in range(50):
        if not lane_harnesses(root):
            break
        time.sleep(0.1)
    assert lane_harnesses(root) == []
    assert kill_orphans(root) == []


# ---------------------------------------------------------------------------
# security-negative
# ---------------------------------------------------------------------------

def test_a_prefix_sibling_lane_is_not_claimed(tmp_path):
    """`/tmp/xrd-test` must not be held by `/tmp/xrd-test-a15aa`'s owner.

    The reaper already refuses to KILL across a prefix boundary; the claim
    check has to refuse to READ across the same one, or the gate blocks a lane
    whose only crime is being spelled like the start of another.
    """
    root = tmp_path / "lane"
    sibling = tmp_path / "lane-sibling"
    root.mkdir()
    sibling.mkdir()
    with _Stray(tmp_path, sibling, "fake_pytest_run") as stray:
        assert stray.pid in _pids(lane_claimants(sibling))
        assert lane_claimants(root) == [], "prefix sibling leaked into the lane"
        assert kill_orphans(root) == [], "and must not be blocked by it"


def test_an_empty_test_root_declaration_claims_nothing(tmp_path):
    """`TEST_ROOT=` unset-but-present must not resolve to the process's cwd.

    `os.path.realpath("")` is the current directory, so an empty declaration
    would silently claim whatever lane the process happened to be sitting in —
    a claim nobody wrote and nobody can see.
    """
    root = tmp_path / "lane"
    root.mkdir()
    script = tmp_path / "fake_pytest_empty.py"
    script.write_text(_SLEEPER)
    env = dict(os.environ)
    env["TEST_ROOT"] = ""
    proc = subprocess.Popen([sys.executable, str(script)], env=env, cwd=str(root),
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            text=True)
    try:
        assert proc.stdout.readline().strip() == "up"
        assert proc.pid not in _pids(lane_claimants(root))
        assert str(root) not in live_lanes()
    finally:
        proc.kill()
        proc.wait(timeout=10)


def test_the_gate_cannot_be_satisfied_by_a_lookalike_command_line(tmp_path):
    """Claiming is by DECLARATION; naming yourself pytest claims nothing.

    Otherwise any process with a suggestive argv could hold a lane hostage —
    or, read the other way, a harness could be spoofed into believing its own
    lane belongs to someone else and refusing to clean up after itself.
    """
    root = tmp_path / "lane"
    other = tmp_path / "elsewhere"
    root.mkdir()
    other.mkdir()
    with _Stray(tmp_path, other, "fake_pytest_run") as stray:
        assert stray.pid not in _pids(lane_claimants(root))
        assert lane_harnesses(root) == []
        assert kill_orphans(root) == []


def test_a_directory_named_like_a_harness_does_not_make_one(tmp_path):
    """Where a process WORKS is not what it RUNS.

    This one caught itself.  The first cut matched the markers against the raw
    command line, and every path this file hands a child lives under
    `/tmp/pytest-of-<user>/…` — so the passer-by in the test above was read as
    a running pytest and the distinction collapsed.  On a real host the same
    rule promotes any linter, fixture helper or worker handed a temp path into
    the owner of a lane it only borrowed, the gate fires on the routine case,
    and `force=True` gets pasted over it.

    Both spellings are pinned here because the cheap one is the one that will
    still be true when this file's own temp paths stop containing the word.
    """
    from brix_suite.orphans import _is_harness_cmd

    assert _is_harness_cmd("python3 -m pytest test_x.py -q")
    assert _is_harness_cmd("python3 -m cmdscripts.manage_test_servers start-all")
    assert not _is_harness_cmd(
        "CodeChecker analyze --output /tmp/pytest-of-rcurrie/p0/reports")
    assert not _is_harness_cmd(
        "/usr/bin/python3 /tmp/pytest-of-rcurrie/p0/analyze_worker.py")

    workdir = tmp_path / "pytest-of-nobody" / "p0"
    workdir.mkdir(parents=True)
    root = tmp_path / "lane"
    root.mkdir()
    with _Stray(workdir, root, "linter") as passerby:
        assert passerby.pid in _pids(lane_claimants(root))
        assert lane_harnesses(root) == [], \
            "a temp directory is not a harness"
        assert kill_orphans(root) == []


def test_the_operator_teardown_refuses_a_claimed_lane_too(tmp_path):
    """The wider door, gated by the same rule.

    `operator_build.brutal_teardown` does not stop at signalling: it deletes
    the lane's `data`, `pki`, `tokens`, `logs` and `tmp`.  Run on someone
    else's root it destroys their artefacts, not just their processes — so
    closing only `kill_orphans` would have been half a fix.

    It refuses by RETURNING a failing check rather than raising, because it is
    a checks runner and a red line naming the claimant is what an operator can
    act on; the assertions below pin both halves — that it says no, and that
    it did not touch the tree while saying so.
    """
    import cmdscripts.operator_build as operator_build

    root = tmp_path / "lane"
    (root / "data").mkdir(parents=True)
    (root / "data" / "artifact").write_text("someone else's run")

    with _Stray(tmp_path, root, "fake_pytest_run") as stray:
        results = operator_build.brutal_teardown(root)
        assert results and results[0][0] is False, results
        assert str(stray.pid) in results[0][1], results[0][1]
        assert (root / "data" / "artifact").read_text() == "someone else's run"
        assert stray.proc.poll() is None

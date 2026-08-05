"""Pytest lane for `brixcvmfs repo gc` (phase-96 S10–S11).

Pure-local (no servers): builds the standalone repotool, publishes revision
history, and verifies reflog-anchored mark & sweep independently in Python —
exact-sweep reachability, refusals (active transaction, missing/tampered
reflog), the mark-skip mutation guard, and tag pinning.
"""

from cmdscripts.cvmfs_admin_checks import run_gc_checks


def test_cvmfs_gc(tmp_path):
    results = run_gc_checks(tmp_path)
    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results)

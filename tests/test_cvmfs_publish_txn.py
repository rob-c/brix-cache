"""Pytest lane for `brixcvmfs repo transaction/abort/publish` (phase-96 S4–S7).

Pure-local (no servers): builds the standalone repotool, runs full publish
transactions, and verifies manifests/catalogs/CAS objects independently in
Python. Covers crash-safety, lock contention, dirtab nesting, chunking, and
the fail-closed tamper/symlink security negatives.
"""

import pytest
from cmdscripts.cvmfs_publish_txn import run_checks


# The repotool publishes are quick alone (<10 s) but stall past the 30 s default
# on a loaded host (8 xdist workers building tools): widen the per-test timeout.
pytestmark = pytest.mark.timeout(300)

def test_cvmfs_publish_transaction(tmp_path):
    results = run_checks(tmp_path)
    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results)

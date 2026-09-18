"""Pytest lane for `brixcvmfs repo tag add|list|rollback` (phase-96 S12).

Pure-local (no servers): tags a revision, publishes past it, rolls back and
verifies the republished tree matches the tagged catalog row-for-row at a NEW
revision number; unknown-tag and history-object-tamper refusals fail closed.
"""

import pytest
from cmdscripts.cvmfs_admin_checks import run_tag_checks


# The repotool publishes are quick alone (<10 s) but stall past the 30 s default
# on a loaded host (8 xdist workers building tools): widen the per-test timeout.
pytestmark = pytest.mark.timeout(300)

def test_cvmfs_tags(tmp_path):
    results = run_tag_checks(tmp_path)
    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results)

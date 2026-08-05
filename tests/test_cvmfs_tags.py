"""Pytest lane for `brixcvmfs repo tag add|list|rollback` (phase-96 S12).

Pure-local (no servers): tags a revision, publishes past it, rolls back and
verifies the republished tree matches the tagged catalog row-for-row at a NEW
revision number; unknown-tag and history-object-tamper refusals fail closed.
"""

from cmdscripts.cvmfs_admin_checks import run_tag_checks


def test_cvmfs_tags(tmp_path):
    results = run_tag_checks(tmp_path)
    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results)

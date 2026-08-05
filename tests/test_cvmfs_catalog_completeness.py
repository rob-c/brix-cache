"""Pytest lane for phase-96 S8 catalog completeness + `brixcvmfs repo fsck`.

Pure-local (no servers): hardlink group encoding, user.* xattr BLOB fidelity,
per-catalog schema/revision properties, subtree_* counter aggregation,
.cvmfscatalog marker birth/dissolve, and the fsck drift/malformed-BLOB
security negatives.
"""

from cmdscripts.cvmfs_catalog_completeness import run_checks


def test_cvmfs_catalog_completeness(tmp_path):
    results = run_checks(tmp_path)
    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results)

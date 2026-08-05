"""Pytest lanes for the `brixcvmfs repo` CLI (phase-96 S3).

The unit lane is pure-local (no servers). The check-oracle lane serves the
minted repo over HTTP on the module's fixed cmdscript port and judges the
write plane with the real read client (`brixcvmfs --check`).
"""

import pytest

from cmdscripts.cvmfs_repo_cli import run_check_oracle, run_checks


def _assert_all(results):
    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results)


def test_cvmfs_repo_cli_lifecycle(tmp_path):
    _assert_all(run_checks(tmp_path))


@pytest.mark.xdist_group("cmd-cvmfs_repo_cli")
def test_cvmfs_repo_check_oracle(tmp_path):
    from cmdscripts.brixcvmfs_live import LiveSkip

    try:
        results = run_check_oracle(tmp_path)
    except LiveSkip as exc:
        pytest.skip(str(exc))
    _assert_all(results)

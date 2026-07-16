from pathlib import Path

from cmdscripts.ceph_operator import run_checks


def test_ceph_operator_ports_are_importable(tmp_path: Path):
    results = run_checks(tmp_path)
    failed = [message for ok, message in results if not ok]
    assert not failed, "\n".join(failed)

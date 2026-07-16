from pathlib import Path

import pytest

from cmdscripts.cvmfs_driver_units import run_checks


@pytest.mark.parametrize("name", ["core", "client", "build"])
def test_cvmfs_driver_unit_ports(tmp_path: Path, name: str):
    results = run_checks(tmp_path, [name])
    failed = [message for ok, message in results if not ok]
    assert not failed, "\n".join(failed)


def test_brixcvmfs_check_port(tmp_path: Path):
    results = run_checks(tmp_path, ["check"])
    failed = [message for ok, message in results if not ok]
    assert not failed, "\n".join(failed)

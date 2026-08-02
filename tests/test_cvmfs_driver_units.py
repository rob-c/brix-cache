from pathlib import Path

import pytest

from cmdscripts.cvmfs_driver_units import run_checks

pytestmark = pytest.mark.xdist_group("cmd-cvmfs_driver_units")


@pytest.mark.parametrize("name", ["core", "client", "walk", "xorf", "bundle", "dict", "pack", "pathidx", "build"])
def test_cvmfs_driver_unit_ports(tmp_path: Path, name: str):
    results = run_checks(tmp_path, [name])
    failed = [message for ok, message in results if not ok]
    assert not failed, "\n".join(failed)


@pytest.mark.timeout(120)   # compiles brixcvmfs + mkrepo, forges a repo, live-mounts
def test_brixcvmfs_check_port(tmp_path: Path):
    results = run_checks(tmp_path, ["check"])
    failed = [message for ok, message in results if not ok]
    assert not failed, "\n".join(failed)

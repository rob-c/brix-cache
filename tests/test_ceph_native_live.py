"""Run the existing real Ceph data/credential contracts in the active C build.

Set TEST_CEPH=1 with CEPH_CONF, CEPH_POOL and the credential keyring variables
from the isolated Ceph lab. The native process preserves its coverage counters;
the existing Docker operator remains available for an independent build lab.
"""

import os
from pathlib import Path
import subprocess
import sys

import pytest

from cmdscripts.ceph_sources import driver_arguments
from cmdscripts.compile_run import REPO_ROOT

pytestmark = [pytest.mark.serial, pytest.mark.timeout(300),
              pytest.mark.skipif(sys.platform != 'linux' or
                                 os.environ.get('TEST_CEPH') != '1',
                                 reason='requires an explicitly selected Linux Ceph lab')]


def run_contract(driver, tmp_path, cephfs=False):
    """Build the existing production closure and retain every native assertion."""
    config = Path(os.environ['CEPH_CONF'])
    assert config.is_file(), f'configured Ceph lab is missing {config}'
    binary = tmp_path / driver
    source = f'tests/ceph/{driver}.c'
    built = subprocess.run(driver_arguments(source, str(binary), cephfs), cwd=REPO_ROOT,
                           capture_output=True, text=True, timeout=120)
    assert built.returncode == 0, built.stdout + built.stderr
    result = subprocess.run([str(binary)], cwd=REPO_ROOT, capture_output=True,
                            text=True, timeout=180)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'FAIL' not in result.stdout + result.stderr
    return result.stdout


@pytest.mark.parametrize('driver', ['sd_ceph_live_test', 'sd_ceph_cred_live_test'])
def test_native_ceph_contracts(driver, tmp_path):
    """Real CephX enforces permissions while production C verifies data/metadata."""
    assert 'ok:' in run_contract(driver, tmp_path)


@pytest.mark.skipif(os.environ.get('TEST_CEPHFS') != '1',
                    reason='requires the seeded, flushed CephFS fixture')
def test_native_cephfs_readonly_contract(tmp_path):
    """Read real CephFS metadata/data, reject missing paths and refuse mutations."""
    assert 'ALL PASS' in run_contract('sd_cephfs_ro_live_test', tmp_path, cephfs=True)

"""Live migration must pin the source object's version despite other workers."""

import os
from pathlib import Path
import subprocess
import sys

import pytest

from brix_suite.client_build import client_make, client_run
from test_ceph_migration_native import (
    migration_tools, migration_lab, check_source, check_destination)
from test_xrd_dispatch_native import private_link_command

pytestmark = [pytest.mark.serial, pytest.mark.timeout(240),
    pytest.mark.skipif(sys.platform != 'linux' or os.environ.get('TEST_CEPHFS') != '1',
                      reason='requires an explicitly selected disposable CephFS lab')]


@pytest.fixture(scope='module')
def interleaved_migrator(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp('ceph-version')
    binary = output / 'xrdceph_striper_migrate'
    plan = client_make(root / 'client', '-n', 'xrdceph_striper_migrate', f'BINDIR={output}',
                       capture_output=True, text=True, timeout=120)
    assert plan.returncode == 0, plan.stdout + plan.stderr
    command = private_link_command(plan.stdout.replace('\\\n', ' '), binary)
    command += [str(root / 'tests/c/ceph_migrate_version_interleave.cpp'), '-Iapps/ceph',
                '-Wl,--wrap=_ZN8librados7v14_2_05IoCtx16get_last_versionEv']
    result = client_run(root / 'client', command, cwd=root / 'client',
                        capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    return binary


def migrate_with_fault(binary, lab, mode, fault):
    return subprocess.run([str(binary), lab['pool'], os.environ.get('CEPHFS_DATA', 'cephfs_data'),
        lab['prefix'], '--threads', '1', '--mode', mode, '--verify'],
        env=dict(os.environ, BRIX_MIGRATE_VERSION_FAULT=fault),
        capture_output=True, timeout=120)


@pytest.mark.parametrize('mode', ['copy', 'redirect'])
def test_another_worker_read_cannot_replace_source_version(interleaved_migrator, migration_lab, mode):
    result = migrate_with_fault(interleaved_migrator, migration_lab, mode, 'interleave')
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.count(b'OK   ') == 3
    assert result.stderr.count(b"injected another object's read") >= 3
    check_source(migration_lab)
    check_destination(migration_lab)


def test_changed_source_version_is_still_rejected(interleaved_migrator, migration_lab):
    result = migrate_with_fault(interleaved_migrator, migration_lab, 'copy', 'stale')
    assert result.returncode == 1, result.stdout + result.stderr
    assert b'copy_from ' in result.stdout and b'OK   ' not in result.stdout
    check_source(migration_lab)

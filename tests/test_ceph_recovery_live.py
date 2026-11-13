"""Recovery CLIs must extract real RADOS/CephFS bytes and report failures."""

import os
from pathlib import Path
import subprocess
import sys

import pytest

from brix_suite.client_build import client_make
from cmdscripts.compile_run import REPO_ROOT

pytestmark = [pytest.mark.serial, pytest.mark.timeout(180),
    pytest.mark.skipif(sys.platform != 'linux' or os.environ.get('TEST_CEPH') != '1',
                      reason='requires an explicitly selected Linux Ceph lab')]


def invoke(binary, *args, expected=0):
    result = subprocess.run([str(binary), *map(str, args)], capture_output=True,
                            timeout=60)
    assert result.returncode == expected, result.stdout + result.stderr
    return result.stdout


@pytest.fixture(scope='module')
def recovery_tools(tmp_path_factory):
    output = tmp_path_factory.mktemp('ceph-recovery-tools')
    targets = ['xrdrados_rescue', 'xrdcephfs_rescue', 'xrdceph_migrate']
    build = client_make(REPO_ROOT / 'client', *targets, f'BINDIR={output}',
                         capture_output=True, text=True, timeout=180)
    assert build.returncode == 0, build.stdout + build.stderr
    return {name: output / name for name in targets}


@pytest.fixture(scope='module')
def recovery_pool(recovery_tools, tmp_path_factory):
    pool = os.environ.get('CEPH_RECOVERY_POOL')
    if not pool:
        pytest.skip('requires CEPH_RECOVERY_POOL naming an empty disposable pool')
    assert invoke(recovery_tools['xrdrados_rescue'], pool, 'ls') == b''
    seed = tmp_path_factory.mktemp('ceph-recovery-seed') / 'seed'
    invoke('gcc', str(REPO_ROOT / 'tests/c/ceph_recovery_seed.c'), '-lrados', '-o', seed)
    invoke(seed, pool, 'seed')
    try:
        yield pool
    finally:
        invoke(seed, pool, 'clean')
        assert invoke(recovery_tools['xrdrados_rescue'], pool, 'ls') == b''


def content(size):
    pattern = b'ABCDEFGHIJKLMNOPQRSTUVW'
    return (pattern * (size // len(pattern) + 1))[:size]


@pytest.mark.parametrize('key,size', [('folder/small', 19),
    ('folder/big', 2 * 1024 * 1024 + 7), ('empty', 0)])
def test_rados_stat_and_get_preserve_every_byte(recovery_tools, recovery_pool,
                                               tmp_path, key, size):
    binary = recovery_tools['xrdrados_rescue']
    output = invoke(binary, recovery_pool, 'stat', key)
    assert f'size:  {size}\n'.encode() in output
    target = tmp_path / 'recovered'
    invoke(binary, recovery_pool, 'get', key, target)
    assert target.read_bytes() == content(size)


def test_rados_prefix_copy_flattens_object_paths(recovery_tools, recovery_pool, tmp_path):
    binary = recovery_tools['xrdrados_rescue']
    assert set(invoke(binary, recovery_pool, 'ls', 'folder/').splitlines()) == {
        b'folder/small', b'folder/big'}
    invoke(binary, recovery_pool, 'cp', 'folder/', tmp_path)
    assert sorted(path.name for path in tmp_path.iterdir()) == ['folder_big', 'folder_small']
    assert (tmp_path / 'folder_small').read_bytes() == content(19)
    assert (tmp_path / 'folder_big').read_bytes() == content(2 * 1024 * 1024 + 7)


def test_rados_migration_preserves_tree_and_xattrs(recovery_tools, recovery_pool, tmp_path):
    output = invoke(recovery_tools['xrdceph_migrate'], recovery_pool, tmp_path)
    assert b'migrated 3 file(s)' in output and b'(0 failure(s))' in output
    for key, size in [('folder/small', 19), ('folder/big', 2 * 1024 * 1024 + 7), ('empty', 0)]:
        path = tmp_path / key
        assert path.read_bytes() == content(size)
        assert os.getxattr(path, 'user.recovery') == b'fixture'


@pytest.mark.parametrize('arguments', [('stat',), ('get',), ('cp',), ('unknown',)])
def test_rados_invalid_commands_report_usage(recovery_tools, recovery_pool, arguments):
    invoke(recovery_tools['xrdrados_rescue'], recovery_pool, *arguments, expected=2)


def test_rados_failed_reads_and_destinations_report_failure(recovery_tools,
                                                          recovery_pool, tmp_path):
    binary = recovery_tools['xrdrados_rescue']
    invoke(binary, recovery_pool, 'stat', 'absent', expected=1)
    invoke(binary, recovery_pool, 'get', 'absent', tmp_path / 'absent', expected=1)
    invoke(binary, recovery_pool, 'get', 'folder/small', tmp_path, expected=1)
    target = tmp_path / 'blocked'
    target.write_bytes(b'protected')
    invoke(binary, recovery_pool, 'cp', 'folder/', target, expected=1)
    invoke(recovery_tools['xrdceph_migrate'], recovery_pool, target, expected=1)
    assert target.read_bytes() == b'protected'


@pytest.fixture
def cephfs_pools():
    if os.environ.get('TEST_CEPHFS') != '1':
        pytest.skip('requires the seeded, flushed CephFS fixture')
    return (os.environ.get('CEPHFS_META', 'cephfs_metadata'),
            os.environ.get('CEPHFS_DATA', 'cephfs_data'))


def test_cephfs_recovery_reads_directory_metadata_and_payload(recovery_tools,
                                                            cephfs_pools, tmp_path):
    binary = recovery_tools['xrdcephfs_rescue']
    listing = invoke(binary, *cephfs_pools, 'ls', '/dir1')
    assert b'hello.txt' in listing and b'sub' in listing
    assert b'27' in invoke(binary, *cephfs_pools, 'stat', '/dir1/hello.txt')
    small = invoke(binary, *cephfs_pools, 'cat', '/dir1/hello.txt')
    assert len(small) == 27
    target = tmp_path / 'big'
    invoke(binary, *cephfs_pools, 'get', '/dir1/sub/big.bin', target)
    data = target.read_bytes()
    assert len(data) == 5 * 1024 * 1024
    assert data[:8] == b'BIGSTART' and data[-8:] == b'BIGENDED'
    invoke(binary, *cephfs_pools, 'cp', '-r', '/dir1/sub', tmp_path / 'tree')
    assert (tmp_path / 'tree/big.bin').read_bytes() == data


@pytest.mark.parametrize('command,arguments,expected', [
    ('stat', ['/missing'], 1), ('ls', ['/missing'], 1),
    ('cat', ['/missing'], 1), ('get', ['/missing'], 2),
    ('cp', ['/missing'], 2), ('unknown', ['/'], 2)])
def test_cephfs_recovery_failures_are_explicit(recovery_tools, cephfs_pools,
                                              command, arguments, expected):
    invoke(recovery_tools['xrdcephfs_rescue'], *cephfs_pools, command, *arguments,
           expected=expected)

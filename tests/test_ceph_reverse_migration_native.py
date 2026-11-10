"""Reverse migration is tested only with an explicitly quiesced disposable FS."""

import os

import pytest

from test_ceph_migration_native import migration_tools  # noqa: F401
from test_ceph_recovery_live import invoke

pytestmark = [pytest.mark.serial, pytest.mark.timeout(240),
    pytest.mark.skipif(os.environ.get('TEST_CEPHFS_QUIESCED') != '1',
                      reason='requires a disposable CephFS with its journal flushed and MDS stopped')]


def reverse(tools, pool, strip, *options):
    return invoke(tools['xrdceph_cephfs_to_striper'],
                  os.environ.get('CEPHFS_META', 'cephfs_metadata'),
                  os.environ.get('CEPHFS_DATA', 'cephfs_data'), pool,
                  '--assume-quiesced', '--threads', '2', '--strip', strip, *options)


def source_bytes(tools):
    pools = [os.environ.get('CEPHFS_META', 'cephfs_metadata'),
             os.environ.get('CEPHFS_DATA', 'cephfs_data')]
    return {key: invoke(tools['xrdcephfs_rescue'], *pools, 'cat', '/' + key)
            for key in ['top.txt', 'dir1/hello.txt', 'dir1/sub/big.bin']}


def check_striper_bytes(tools, pool, strip, expected):
    for key, data in expected.items():
        actual = invoke(tools['probe'], pool, key.removeprefix(strip), 'read')
        assert actual == data


@pytest.fixture
def reverse_pool(migration_tools):
    pool = os.environ.get('CEPH_REVERSE_POOL')
    if not pool:
        pytest.skip('requires CEPH_REVERSE_POOL naming an empty disposable pool')
    assert invoke(migration_tools['xrdrados_rescue'], pool, 'ls') == b''
    return pool


def check_reverse_lifecycle(tools, pool, strip, expected):
    report = reverse(tools, pool, strip, '--report-only')
    assert b'SYMLINK' in report
    assert invoke(tools['xrdrados_rescue'], pool, 'ls') == b''
    assert reverse(tools, pool, strip, '--dry-run').count(b'DRY  ') == 3
    assert invoke(tools['xrdrados_rescue'], pool, 'ls') == b''
    assert reverse(tools, pool, strip, '--verify').count(b'OK   ') == 3
    check_striper_bytes(tools, pool, strip, expected)
    assert reverse(tools, pool, strip, '--verify').count(b'SKIP ') == 3
    assert reverse(tools, pool, strip, '--rollback', '--dry-run').count(b'DRY  ') == 3
    assert reverse(tools, pool, strip, '--finalize', '--dry-run').count(b'DRY  ') == 3
    check_striper_bytes(tools, pool, strip, expected)
    assert reverse(tools, pool, strip, '--finalize', '--verify').count(b'OK   ') == 3
    check_striper_bytes(tools, pool, strip, expected)
    assert source_bytes(tools) == expected


@pytest.mark.parametrize('strip', ['', 'dir1/'])
def test_reverse_redirect_finalize_and_rollback_preserve_source(migration_tools,
                                                               reverse_pool, strip):
    tools, pool = migration_tools, reverse_pool
    expected = source_bytes(tools)
    assert len(expected['dir1/hello.txt']) == 27
    assert len(expected['dir1/sub/big.bin']) == 5 * 1024 * 1024
    try:
        check_reverse_lifecycle(tools, pool, strip, expected)
    finally:
        reverse(tools, pool, strip, '--rollback')
        assert invoke(tools['xrdrados_rescue'], pool, 'ls') == b''
        assert source_bytes(tools) == expected

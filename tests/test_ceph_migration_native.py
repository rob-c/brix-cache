"""Exercise shipped C++ migration tools against a disposable striper pool."""

import os
import re
import struct
import sys
import uuid

import pytest

from brix_suite.client_build import client_make
from cmdscripts.compile_run import REPO_ROOT
from test_ceph_recovery_live import invoke

pytestmark = [pytest.mark.serial, pytest.mark.timeout(240),
    pytest.mark.skipif(sys.platform != 'linux' or os.environ.get('TEST_CEPHFS') != '1',
                      reason='requires an explicitly selected disposable CephFS lab')]


@pytest.fixture(scope='module')
def migration_tools(tmp_path_factory):
    output = tmp_path_factory.mktemp('ceph-migration-tools')
    names = ['xrdceph_striper_migrate', 'xrdceph_cephfs_to_striper',
             'xrdrados_rescue', 'xrdcephfs_rescue']
    build = client_make(REPO_ROOT / 'client', *names, f'BINDIR={output}',
                        capture_output=True, text=True, timeout=180)
    assert build.returncode == 0, build.stdout + build.stderr
    invoke('gcc', REPO_ROOT / 'tests/ceph/striper_seed.c', '-lradosstriper',
           '-lrados', '-o', output / 'seed')
    invoke('gcc', '-D_FILE_OFFSET_BITS=64', REPO_ROOT / 'tests/c/ceph_migration_probe.c', '-lradosstriper',
           '-lrados', '-lcephfs', '-o', output / 'probe')
    return {name: output / name for name in [*names, 'seed', 'probe']}


def pattern(size):
    words = b''.join(struct.pack('<Q', offset) for offset in range(0, size - 7, 8))
    return words + bytes(offset & 255 for offset in range(len(words), size))


def migrate(lab, *options, expected=0):
    return invoke(lab['tools']['xrdceph_striper_migrate'], lab['pool'],
                  os.environ.get('CEPHFS_DATA', 'cephfs_data'), lab['prefix'],
                  '--threads', '2', *options, expected=expected)


def check_source(lab, operation='read'):
    for key, size in lab['objects']:
        actual = invoke(lab['tools']['probe'], lab['pool'], key, operation)
        if operation == 'read':
            assert actual == pattern(size)


def check_destination(lab, operation='read'):
    for key, size in lab['objects']:
        actual = invoke(lab['tools']['probe'], 'cephfs',
                        f"{lab['prefix']}/{key}", operation)
        if operation == 'read':
            assert actual == pattern(size)


def remove_source(lab):
    objects = invoke(lab['tools']['xrdrados_rescue'], lab['pool'], 'ls').decode().splitlines()
    owned = {key for key, _size in lab['objects']}
    for key in objects:
        stem, suffix = key.rsplit('.', 1)
        assert stem in owned and re.fullmatch('[0-9a-f]{16}', suffix)
        invoke(lab['tools']['probe'], lab['pool'], key, 'remove-object')
    assert invoke(lab['tools']['xrdrados_rescue'], lab['pool'], 'ls') == b''


def cleanup_lab(lab):
    # The shipped rollback detaches redirect stubs before any source is removed.
    migrate(lab, '--rollback', '--list', lab['list'])
    check_destination(lab, 'missing')
    remove_source(lab)
    invoke(lab['tools']['probe'], 'cephfs', lab['prefix'] + '/dataset', 'rmdir')
    invoke(lab['tools']['probe'], 'cephfs', lab['prefix'], 'rmdir')


@pytest.fixture
def migration_lab(migration_tools, tmp_path):
    pool = os.environ.get('CEPH_STRIPER_POOL')
    root = os.environ.get('CEPH_MIGRATION_ROOT')
    if not pool or not root:
        pytest.skip('requires an empty CEPH_STRIPER_POOL and writable CEPH_MIGRATION_ROOT')
    assert invoke(migration_tools['xrdrados_rescue'], pool, 'ls') == b''
    lab = {'tools': migration_tools, 'pool': pool,
           'list': tmp_path / 'objects.list',
           'prefix': root.rstrip('/') + '/migration-' + uuid.uuid4().hex,
           'objects': [('dataset/empty', 0), ('dataset/small', 19),
                       ('dataset/large', 2 * 1024 * 1024 + 7)]}
    lab['list'].write_text(''.join(key + '\n' for key, _size in lab['objects']))
    for key, size in lab['objects']:
        invoke(migration_tools['seed'], pool, key, size, 1048576, 65536, 2)
    try:
        yield lab
    finally:
        cleanup_lab(lab)


@pytest.mark.parametrize('mode,threads', [('copy', 1), ('copy', 2), ('redirect', 2)])
def test_migrate_verify_idempotency_and_safe_rollback(migration_lab, mode, threads):
    lab = migration_lab
    output = migrate(lab, '--mode', mode, '--threads', threads, '--verify', '--progress')
    assert output.count(b'OK   ') == 3
    check_source(lab)
    check_destination(lab)
    assert migrate(lab, '--mode', mode).count(b'SKIP ') == 3
    assert migrate(lab, '--mode', mode, '--force', '--verify').count(b'OK   ') == 3
    check_destination(lab)
    migrate(lab, '--rollback', '--dry-run')
    check_destination(lab)
    migrate(lab, '--rollback')
    check_destination(lab, 'missing')
    check_source(lab)


def test_estimator_rolls_back_sample_and_preserves_source(migration_lab):
    lab = migration_lab
    output = migrate(lab, '--dry-run', '--sample-mb', '0', '--verify')
    assert output.count(b'DRY  ') == 3
    check_source(lab)
    check_destination(lab, 'missing')


def test_finalization_materializes_source_independent_files(migration_lab):
    lab = migration_lab
    migrate(lab, '--verify')
    assert migrate(lab, '--finalize', '--dry-run').count(b'DRY  finalize ') == 3
    check_source(lab)
    assert migrate(lab, '--finalize').count(b'FINALIZE ') == 3
    remove_source(lab)
    check_destination(lab)


def test_rejected_layout_cannot_publish_wrong_geometry(migration_lab):
    lab = migration_lab
    key = 'dataset/small.0000000000000000'
    invoke(lab['tools']['probe'], lab['pool'], key, 'invalid-layout')
    output = migrate(lab, '--mode', 'copy', '--verify', expected=1)
    assert b'FAIL dataset/small: layout ' in output
    invoke(lab['tools']['probe'], 'cephfs', lab['prefix'] + '/dataset/small', 'missing')


def test_redirect_cannot_delete_the_source_it_still_references(migration_lab):
    lab = migration_lab
    migrate(lab, '--delete-source', expected=2)
    check_source(lab)
    check_destination(lab, 'missing')


def test_profile_and_work_list_preserve_byte_exact_migration(migration_lab,
                                                            tmp_path, monkeypatch):
    lab = migration_lab
    profile = tmp_path / 'site.conf'
    profile.write_text('\n'.join(['# explicit private fixture', 'strip = ',
        f"striper_pool = {lab['pool']}", 'data_pool = cephfs_data',
        f"dest_prefix = {lab['prefix']}", 'client = admin', 'fs_name = cephfs',
        f"conf = {os.environ['CEPH_CONF']}", '']))
    monkeypatch.setenv('XRDCEPH_MIGRATE_CONF', str(profile))
    lab['list'].write_bytes(b'dataset/small \r\ndataset/empty\r\ndataset/large\n')
    output = invoke(lab['tools']['xrdceph_striper_migrate'], '--mode', 'copy',
                    '--threads', '0', '--list', lab['list'], '--verify')
    assert output.count(b'OK   ') == 3
    check_source(lab)
    check_destination(lab)


@pytest.mark.parametrize('name', ['xrdceph_striper_migrate', 'xrdceph_cephfs_to_striper'])
@pytest.mark.parametrize('args', [[], ['one'], ['one', 'two'], ['one', 'two', 'three', 'four'],
    ['--unknown'], ['--threads'], ['--config'], ['--conf'], ['--strip']])
def test_incomplete_cli_never_connects(migration_tools, name, args):
    invoke(migration_tools[name], *args, expected=2)


@pytest.mark.parametrize('contents', ['unknown=pool', 'missing equals',
                                      'striper_pool=\n# unset only\n'])
@pytest.mark.parametrize('name', ['xrdceph_striper_migrate', 'xrdceph_cephfs_to_striper'])
def test_invalid_profile_is_rejected(migration_tools, tmp_path, name, contents):
    profile = tmp_path / 'profile'
    profile.write_text(contents)
    invoke(migration_tools[name], '--config', profile, expected=2)


@pytest.mark.parametrize('args', [('--mode',), ('--mode', 'invalid'),
    ('--delete-source',), ('--mode', 'copy', '--rollback', '--delete-source')])
def test_forward_destructive_option_conflicts_are_refused(migration_tools, args):
    invoke(migration_tools['xrdceph_striper_migrate'], 'source', 'data', '/target',
           *args, expected=2)


@pytest.mark.parametrize('args', [(), ('--assume-quiesced', '--delete-source')])
def test_reverse_migration_requires_quiescence_and_finalization(migration_tools, args):
    invoke(migration_tools['xrdceph_cephfs_to_striper'], 'meta', 'data', 'target',
           *args, expected=2)

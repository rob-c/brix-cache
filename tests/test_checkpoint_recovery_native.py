"""Checkpoint rollback either restores exact durable bytes or retains a replayable journal."""

import errno
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def recovery_binary(server_native_compile):
    names = ['brix_vfs_open_fd', 'fstat64', 'fstatat64', 'fdopendir', 'dirfd', 'flock',
        'brix_staged_open', 'brix_copy_range', 'brix_rename_beneath', 'brix_vfs_unlink_path']
    return server_native_compile('checkpoint-recovery', 'tests/c/checkpoint_recovery_native_test.c',
                                ['-Wl,--wrap=' + name for name in names])


def invoke(binary, mode, root):
    result = subprocess.run([str(binary), mode, str(root)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return int(result.stdout)


@pytest.mark.parametrize('content', [b'', b'snapshot bytes\x00\xff'])
def test_recovery_replaces_uncommitted_bytes_and_removes_only_the_snapshot(recovery_binary, tmp_path, content):
    target = tmp_path / 'file'; target.write_bytes(b'uncommitted')
    journal = tmp_path / 'file.ckp'; journal.write_bytes(content)
    assert invoke(recovery_binary, 'normal', tmp_path) == 0
    assert target.read_bytes() == content and not journal.exists()
    assert target.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize('mode', ['snapshot-open', 'snapshot-stat', 'snapshot-type', 'stage',
    'copy', 'commit', 'root-open', 'fdopendir', 'dirfd', 'lock'])
def test_storage_or_lock_failure_keeps_the_old_file_and_recovery_journal(recovery_binary, tmp_path, mode):
    target = tmp_path / 'file'; target.write_bytes(b'uncommitted')
    journal = tmp_path / 'file.ckp'; journal.write_bytes(b'snapshot')
    assert invoke(recovery_binary, mode, tmp_path) == -1
    assert target.read_bytes() == b'uncommitted' and journal.read_bytes() == b'snapshot'
    assert sorted(path.name for path in tmp_path.iterdir()) == ['.nginx-xrootd-ckp-recovery.lock', 'file', 'file.ckp']


def test_unlink_failure_keeps_a_replayable_journal_after_successful_commit(recovery_binary, tmp_path):
    target = tmp_path / 'file'; target.write_bytes(b'uncommitted')
    journal = tmp_path / 'file.ckp'; journal.write_bytes(b'snapshot')
    assert invoke(recovery_binary, 'unlink', tmp_path) == -1
    assert target.read_bytes() == journal.read_bytes() == b'snapshot'


@pytest.mark.parametrize('error,rc', [(errno.EACCES, 0), (errno.ENOENT, 0),
    (errno.ENOTDIR, 0), (errno.ELOOP, 0), (errno.EIO, -1)])
def test_private_or_racing_subdirectory_is_skipped_but_unexpected_io_failure_is_fatal(recovery_binary, tmp_path, error, rc):
    child = tmp_path / 'child'; child.mkdir(); (child / 'file.ckp').write_bytes(b'snapshot')
    assert invoke(recovery_binary, 'child-' + str(error), tmp_path) == rc
    assert (child / 'file.ckp').read_bytes() == b'snapshot'


def test_racing_entry_metadata_is_skipped_without_replacing_the_file(recovery_binary, tmp_path):
    (tmp_path / 'file.ckp').write_bytes(b'snapshot')
    assert invoke(recovery_binary, 'entry-stat', tmp_path) == 0
    assert not (tmp_path / 'file').exists() and (tmp_path / 'file.ckp').read_bytes() == b'snapshot'


def test_symlink_snapshot_never_reads_or_replaces_an_external_object(recovery_binary, tmp_path):
    outside = tmp_path / 'outside'; outside.write_bytes(b'private')
    export = tmp_path / 'export'; export.mkdir(); (export / 'file.ckp').symlink_to(outside)
    assert invoke(recovery_binary, 'normal', export) == 0
    assert outside.read_bytes() == b'private' and not (export / 'file').exists()

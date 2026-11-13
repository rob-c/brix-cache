"""The supported synchronous fallback must satisfy real kernel FUSE contracts."""

from contextlib import contextmanager
import errno
import os
from pathlib import Path
import shutil
import uuid

import pytest

from lib_py import fuse_host
from settings import DATA_ROOT
import test_xrootdfs as contracts
from test_xrootdfs import built, remote_file  # noqa: F401

pytestmark = [pytest.mark.timeout(120),
              pytest.mark.skipif(not fuse_host.FUSE_READY, reason=fuse_host.SKIP_REASON)]


@pytest.fixture
def legacy_mount(monkeypatch, built):
    """Reuse the canonical mount owner, requiring a normal daemon exit."""
    mount = contracts._mount

    @contextmanager
    def legacy(*arguments):
        with mount('--legacy', '--attr-timeout', '0', '--entry-timeout', '0',
                   '--max-conns', '2', *arguments) as volume:
            yield volume
        assert volume.proc.returncode == 0, 'legacy mount did not exit cleanly'

    monkeypatch.setattr(contracts, '_mount', legacy)
    return legacy


@pytest.mark.parametrize('exercise', [contracts.test_fuse_cat_and_stat,
    contracts.test_fuse_ls_and_enoent, contracts.test_fuse_concurrent_reads,
    contracts.test_fuse_xattr, contracts.test_fuse_xattr_off_by_default],
    ids=lambda exercise: exercise.__name__)
def test_legacy_existing_file_contracts(legacy_mount, built, remote_file, exercise):
    exercise(built, remote_file)


@pytest.mark.parametrize('exercise', [contracts.test_fuse_write_roundtrip,
    contracts.test_fuse_random_write_inplace, contracts.test_fuse_statfs,
    contracts.test_fuse_large_io_buffered, contracts.test_fuse_buffering_disabled],
    ids=lambda exercise: exercise.__name__)
def test_legacy_new_file_contracts(legacy_mount, built, exercise):
    exercise(built)


def test_legacy_namespace_mutations_and_sync(legacy_mount):
    name = '_legacy_' + uuid.uuid4().hex
    backing = Path(DATA_ROOT) / name
    try:
        with legacy_mount() as volume:
            directory = Path(volume.mnt) / name
            directory.mkdir(mode=0o700)
            source, target = directory / 'source', directory / 'target'
            source.write_bytes(b'original')
            with source.open('r+b', buffering=0) as handle:
                handle.write(b'new')
                os.fsync(handle.fileno())
                handle.truncate(5)
            assert source.read_bytes() == b'newgi'
            source.chmod(0o640)
            assert source.stat().st_mode & 0o777 == 0o640
            source.rename(target)
            assert not source.exists() and target.read_bytes() == b'newgi'
            assert os.access(target, os.R_OK)
            assert not os.access(source, os.F_OK)
            target.unlink()
            directory.rmdir()
        assert not backing.exists()
    finally:
        shutil.rmtree(backing, ignore_errors=True)


@pytest.mark.parametrize('name', ['security.label', 'trusted.secret', 'user.XrdCks.adler32'])
def test_legacy_xattr_namespace_refusal_preserves_bytes(legacy_mount, remote_file, name):
    filename, payload = remote_file
    with legacy_mount('--xattr') as volume:
        path = Path(volume.mnt) / filename
        with pytest.raises(OSError) as caught:
            os.setxattr(path, name, b'untrusted')
        assert caught.value.errno in (errno.EACCES, errno.EPERM, errno.ENOTSUP)
        assert path.read_bytes() == payload


def test_legacy_handle_stat_survives_unlink_and_name_replacement(legacy_mount, remote_file):
    filename, payload = remote_file
    backing = Path(DATA_ROOT) / filename
    with legacy_mount() as volume:
        path = Path(volume.mnt) / filename
        with path.open('rb', buffering=0) as handle:
            inode = os.fstat(handle.fileno()).st_ino
            path.unlink()
            backing.write_bytes(b'replacement')
            info = os.fstat(handle.fileno())
            assert info.st_ino == inode and info.st_size == len(payload)
            assert handle.read() == payload
        assert backing.read_bytes() == b'replacement'

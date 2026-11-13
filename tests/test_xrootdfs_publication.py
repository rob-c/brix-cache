"""FUSE create/truncate publish before replying, even on resumable origins."""

from contextlib import contextmanager
import errno
import os
from pathlib import Path
import uuid

import pytest

from lib_py import fuse_host
from settings import DATA_ROOT
from test_xrootdfs import _mount, built  # noqa: F401

pytestmark = [pytest.mark.timeout(120),
              pytest.mark.skipif(not fuse_host.FUSE_READY, reason=fuse_host.SKIP_REASON)]


@pytest.fixture
def published_mount(built):
    """Use a unique backing file and always unmount before removing it."""
    @contextmanager
    def mount():
        name = '_fuse_publish_' + uuid.uuid4().hex
        backing = Path(DATA_ROOT) / name
        try:
            with _mount() as volume:
                yield Path(volume.mnt) / name, backing
        finally:
            backing.unlink(missing_ok=True)
    return mount


def test_create_is_visible_before_writer_closes(published_mount):
    with published_mount() as (path, backing):
        with path.open('wb', buffering=0) as writer:
            assert backing.exists() and backing.stat().st_size == 0
            writer.write(b'published bytes')
            os.fsync(writer.fileno())
            assert backing.read_bytes() == b'published bytes'


def test_truncate_is_visible_before_any_write(published_mount):
    with published_mount() as (path, backing):
        backing.write_bytes(b'old contents')
        with path.open('wb', buffering=0):
            assert backing.read_bytes() == b''


def test_immediate_close_and_reopen_never_observes_missing_name(published_mount):
    with published_mount() as (path, backing):
        for index in range(100):
            payload = f'payload-{index:04d}'.encode()
            path.write_bytes(payload)
            with path.open('r+b', buffering=0) as update:
                update.seek(0)
                update.write(b'changed')
            assert path.read_bytes() == b'changed' + payload[7:]
            assert backing.read_bytes() == b'changed' + payload[7:]


def test_exclusive_create_refusal_preserves_existing_bytes(published_mount):
    with published_mount() as (path, backing):
        backing.write_bytes(b'protected')
        with pytest.raises(FileExistsError) as caught:
            path.open('xb').close()
        assert caught.value.errno == errno.EEXIST
        assert backing.read_bytes() == b'protected'


def test_new_write_handle_survives_unlink_without_reopening_name(published_mount):
    with published_mount() as (path, backing):
        with path.open('w+b', buffering=0) as handle:
            handle.write(b'original')
            os.fsync(handle.fileno())
            inode = os.fstat(handle.fileno()).st_ino
            path.unlink()
            backing.write_bytes(b'replacement')
            handle.seek(0)
            handle.write(b'changed!')
            os.fsync(handle.fileno())
            handle.seek(0)
            assert handle.read() == b'changed!'
            assert os.fstat(handle.fileno()).st_ino == inode
        assert backing.read_bytes() == b'replacement'

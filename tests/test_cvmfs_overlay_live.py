"""Writable CVMFS union contracts through actual FUSE syscalls and signed catalogs."""

import errno
from functools import partial
from http.server import ThreadingHTTPServer
import os
from pathlib import Path
import stat
import threading

import pytest

from settings import BIND_HOST, HOST

from test_cvmfs_mount_opts import _QuietHandler, BRIXMOUNT, FUSE_READY
from test_cvmfs_conformance_smoke import Dir, File, RepoForge, Symlink, fuse_mount

pytestmark = [pytest.mark.serial, pytest.mark.timeout(60),
    pytest.mark.skipif(not FUSE_READY or not Path(BRIXMOUNT).is_file(),
                      reason='requires the native FUSE client and mount device')]


@pytest.fixture(scope='module')
def overlay_origin(tmp_path_factory):
    root = tmp_path_factory.mktemp('overlay-origin')
    name = 'overlay.native.brix'
    public = root / 'repo.pub'
    tree = {'lower': File(b'original lower bytes'), 'lower-link': Symlink('lower'),
            'folder': Dir({'child': File(b'child')}), 'empty': Dir({})}
    forge = RepoForge(name, root / 'web').build(tree, public)
    server = ThreadingHTTPServer((BIND_HOST, 0),
                                partial(_QuietHandler, directory=str(root / 'web')))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield name, f'http://{HOST}:{server.server_port}/cvmfs/{name}', public
    finally:
        server.shutdown()
        server.server_close()
        thread.join(3)
        forge.close()


@pytest.fixture
def overlay_mount(overlay_origin):
    with fuse_mount(*overlay_origin, mount_type='cvmfs-rw',
                    opts='auto_unmount,attr_timeout=0,entry_timeout=0') as (mount, process):
        assert os.path.ismount(mount) and process.poll() is None
        yield mount
    assert process.wait(timeout=5) == 0


def assert_errno(expected, action, *arguments, **kwargs):
    with pytest.raises(OSError) as caught:
        action(*arguments, **kwargs)
    assert caught.value.errno == expected


@pytest.mark.parametrize('relative', ['lower', 'folder', 'created', '.brixwrites/direct'])
def test_metadata_copyup_and_passthrough(overlay_mount, relative):
    path = overlay_mount / relative
    if not path.exists():
        path.write_bytes(b'new')
    os.chmod(path, 0o700)
    assert stat.S_IMODE(path.stat().st_mode) == 0o700
    os.utime(path, ns=(1600000000000000000, 1600000000123456789))
    assert path.stat().st_mtime_ns == 1600000000123456789
    os.chown(path, -1, -1)
    if relative == 'lower':
        assert path.read_bytes() == b'original lower bytes'
        assert os.getxattr(path, 'user.overlay') == b'modified'


def test_directory_whiteout_recreation_is_opaque(overlay_mount):
    folder = overlay_mount / 'folder'
    assert_errno(errno.ENOTEMPTY, folder.rmdir)
    (folder / 'child').unlink()
    folder.rmdir()
    assert not folder.exists()
    folder.mkdir()
    assert list(folder.iterdir()) == []
    (folder / 'new').write_bytes(b'new child')
    folder.rename(overlay_mount / 'moved')
    assert (overlay_mount / 'moved/new').read_bytes() == b'new child'
    assert not folder.exists()


def test_merged_directory_rename_requires_copy_fallback(overlay_mount):
    assert_errno(errno.EXDEV, (overlay_mount / 'folder').rename, overlay_mount / 'target')
    assert (overlay_mount / 'folder/child').read_bytes() == b'child'
    assert not (overlay_mount / 'target').exists()


@pytest.mark.parametrize('relative', ['new-link', '.brixwrites/direct-link'])
def test_upper_and_passthrough_symlinks_preserve_target(overlay_mount, relative):
    link = overlay_mount / relative
    link.symlink_to('../lower' if relative.startswith('.') else 'lower')
    assert os.readlink(link) == ('../lower' if relative.startswith('.') else 'lower')
    link.unlink()
    assert not link.is_symlink()
    assert os.readlink(overlay_mount / 'lower-link') == 'lower'


@pytest.mark.parametrize('relative', ['newdir', '.brixwrites/direct-dir'])
def test_upper_and_passthrough_directory_lifecycle(overlay_mount, relative):
    directory = overlay_mount / relative
    directory.mkdir()
    file = directory / 'data'
    file.write_bytes(b'payload')
    with file.open('r+b') as stream:
        stream.truncate(3)
        os.fsync(stream.fileno())
        os.utime(stream.fileno(), ns=(1600000000000000000, 1600000000000000000))
    assert file.read_bytes() == b'pay'
    assert_errno(errno.ENOTEMPTY, directory.rmdir)
    file.unlink()
    directory.rmdir()
    assert not directory.exists()


@pytest.mark.parametrize('name', ['.brix.wh.hidden', '.brix.opq', '.brixcache'])
def test_overlay_control_names_cannot_be_created(overlay_mount, name):
    path = overlay_mount / name
    assert_errno(errno.EPERM, path.mkdir)
    assert_errno(errno.EPERM, path.symlink_to, 'lower')
    assert (overlay_mount / 'lower').read_bytes() == b'original lower bytes'


def test_masked_names_refuse_metadata_and_removal(overlay_mount):
    path = overlay_mount / 'lower'
    path.unlink()
    assert_errno(errno.ENOENT, path.unlink)
    assert_errno(errno.ENOENT, os.chmod, path, 0o600)
    assert_errno(errno.ENOENT, os.utime, path)
    assert 'lower' not in os.listdir(overlay_mount)


def test_overlay_attributes_and_space_account_for_local_writes(overlay_mount):
    path = overlay_mount / 'lower'
    assert os.getxattr(path, 'user.overlay') == b'lower'
    assert 'user.overlay' in os.listxattr(path)
    (overlay_mount / 'new').write_bytes(b'new')
    assert os.getxattr(overlay_mount / 'new', 'user.overlay') == b'new'
    assert_errno(errno.ENODATA, os.getxattr, overlay_mount / 'new', 'user.hash')
    stats = os.statvfs(overlay_mount)
    assert stats.f_namemax == 255 and stats.f_bsize > 0 and stats.f_blocks > 0

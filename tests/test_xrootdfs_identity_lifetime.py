"""Real low-level FUSE hard-link identity, namespace and open-handle regressions."""
import errno
import os
from pathlib import Path
import shutil

import pytest

from settings import DATA_ROOT
from test_xrootdfs_ext import built, mount, seed
from test_xrootdfs import _mount

pytestmark = pytest.mark.timeout(120)


@pytest.fixture
def uncached_mount(built):
    """Metadata freshness is measured without the explicitly allowed TTL cache."""
    with _mount("--attr-timeout", "0", "--entry-timeout", "0") as volume:
        yield Path(volume.mnt)


def test_hardlink_same_kernel_inode_and_shared_updates(mount, seed):
    """A LINK reply must share inode identity and in-place write visibility."""
    directory, _ = mount
    source, target = Path(directory) / seed, Path(directory) / (seed + ".hard")
    original = source.stat().st_ino
    os.link(source, target)
    assert source.stat().st_ino == target.stat().st_ino == original
    with target.open("r+b", buffering=0) as handle:
        handle.write(b"LINK")
    assert source.read_bytes() == target.read_bytes() == b"LINKor-ext-payload\n"
    assert os.stat(Path(DATA_ROOT) / seed).st_ino == os.stat(
        Path(DATA_ROOT) / (seed + ".hard")).st_ino


def test_open_survives_both_aliases_unlinked(mount, seed):
    """Unlink/forget must not free a live handle or redirect it to another path."""
    directory, _ = mount
    source, target = Path(directory) / seed, Path(directory) / (seed + ".hard")
    os.link(source, target)
    with target.open("rb", buffering=0) as handle:
        original = os.fstat(handle.fileno()).st_ino
        source.unlink()
        assert target.stat().st_ino == original
        target.unlink()
        assert os.fstat(handle.fileno()).st_ino == original
        assert handle.read() == b"vendor-ext-payload\n"
    assert not source.exists() and not target.exists()


def test_fstat_observes_open_inode_not_recreated_name(uncached_mount, seed):
    """An open handle sees external size changes and never stats a replacement."""
    source = uncached_mount / seed
    backing = Path(DATA_ROOT) / seed
    with source.open("rb", buffering=0) as handle:
        inode = os.fstat(handle.fileno()).st_ino
        with backing.open("ab") as changed:
            changed.write(b"extended")
        assert os.fstat(handle.fileno()).st_size == len(b"vendor-ext-payload\nextended")
        source.unlink()
        backing.write_bytes(b"replacement")
        info = os.fstat(handle.fileno())
        assert info.st_ino == inode and info.st_size != len(b"replacement")
        assert handle.read() == b"vendor-ext-payload\nextended"


def test_existing_link_refuses_without_rebinding_target(mount, seed):
    """EEXIST must not attach an unrelated destination to the source inode."""
    directory, _ = mount
    source, target = Path(directory) / seed, Path(directory) / (seed + ".hard")
    backing = Path(DATA_ROOT) / (seed + ".hard")
    backing.write_bytes(b"independent target")
    original = target.stat().st_ino
    with pytest.raises(OSError) as caught:
        os.link(source, target)
    assert caught.value.errno == errno.EEXIST
    assert target.stat().st_ino == original != source.stat().st_ino
    assert target.read_bytes() == b"independent target"


def test_rename_between_hardlink_aliases_is_noop(mount, seed):
    """Renaming one alias over another of the same inode must preserve both."""
    directory, _ = mount
    source, target = Path(directory) / seed, Path(directory) / (seed + ".hard")
    os.link(source, target)
    inode = source.stat().st_ino
    source.rename(target)
    assert source.stat().st_ino == target.stat().st_ino == inode
    assert source.read_bytes() == target.read_bytes() == b"vendor-ext-payload\n"


def test_parent_rename_preserves_descendant_inode(mount, seed):
    """A cached child remains the same node after its parent is renamed."""
    directory, _ = mount
    before = Path(DATA_ROOT) / (seed + ".dir")
    after = Path(DATA_ROOT) / (seed + ".renamed")
    before.mkdir()
    (before / "child").write_bytes(b"renamed child")
    try:
        old = Path(directory) / before.name
        new = Path(directory) / after.name
        inode = (old / "child").stat().st_ino
        old.rename(new)
        assert (new / "child").stat().st_ino == inode
        assert (new / "child").read_bytes() == b"renamed child"
        assert not old.exists()
    finally:
        shutil.rmtree(before, ignore_errors=True)
        shutil.rmtree(after, ignore_errors=True)


def test_directory_pagination_lists_every_entry_once(mount, seed):
    """A multi-buffer directory is complete and repeatable, without inode zero."""
    directory, _ = mount
    backing = Path(DATA_ROOT) / (seed + ".dir")
    backing.mkdir()
    expected = {f"entry-{number:04d}" for number in range(1500)}
    try:
        for name in expected:
            (backing / name).write_bytes(b"")
        path = Path(directory) / backing.name
        _check_complete_listing(path, expected)
    finally:
        shutil.rmtree(backing)


def _check_complete_listing(path, expected):
    """Check cardinality as well as membership, and repeat a complete traversal."""
    listing = os.listdir(path)
    assert len(listing) == len(expected) and set(listing) == expected
    assert set(os.listdir(path)) == expected
    with os.scandir(path) as entries:
        selected = [entry for number, entry in enumerate(entries) if number < 8]
    for entry in selected:
        assert entry.inode() == entry.stat(follow_symlinks=False).st_ino


@pytest.mark.parametrize('behavior', ['exact', 'eof', 'premature'])
def test_kernel_read_never_pads_a_premature_remote_eof(built, monkeypatch, behavior):
    """A controlled peer proves exact bytes/EOF and EIO for contradictory EOF."""
    from _test_phase115_pgread_verify_helpers import PgOrigin
    import test_xrootdfs as driver

    class ReadOrigin(PgOrigin):
        def _read_data(self, offset, length, arguments, sequence):
            if self.behaviour == 'premature' and offset > 0:
                return b''
            return super()._read_data(offset, length, arguments, sequence)

    payload = bytes(range(256)) * 1024
    with ReadOrigin(payload, behaviour=behavior, advertise=False) as origin:
        monkeypatch.setattr(driver, 'ANON_URL', f'root://{driver.SERVER_HOST}:{origin.port}/')
        with _mount('--readahead', '0') as mounted:
            with (Path(mounted.mnt) / 'data.bin').open('rb', buffering=0) as handle:
                offset = len(payload) - 3 if behavior == 'eof' else 65536
                _assert_kernel_read_result(handle.fileno(), payload, offset, behavior)
        assert origin.reads > 0


def _assert_kernel_read_result(descriptor, payload, offset, behavior):
    """Keep the original corrupt-peer refusal separate from legitimate short EOF."""
    if behavior == 'premature':
        with pytest.raises(OSError) as error:
            os.pread(descriptor, 4096, offset)
        assert error.value.errno == errno.EIO
        return
    assert os.pread(descriptor, 4096, offset) == payload[offset:offset + 4096]

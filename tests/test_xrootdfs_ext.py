"""
test_xrootdfs_ext.py — M5: vendor POSIX-extension ops through the FUSE mount.

WHAT: Exercises the capability-negotiated kXR_setattr / kXR_symlink / kXR_readlink
      / kXR_link extensions end-to-end through xrootdfs against a module build
      that advertises "xrdfs.ext":
        - the mount banner reports the negotiated capabilities;
        - setattr: os.utime() through the mount changes the backing file's mtime;
        - symlink + readlink (to an existing target AND a dangling one);
        - hard link shares the backing inode;
        - ls -l shows a symlink as a symlink (getattr lstat → S_IFLNK).
WHY:  Proves the wire + module + client + driver extension path works and is
      correctly capability-gated.

Run (against a module rebuilt with the extensions, e.g. a private server):
  TEST_ROOT=/tmp/xrd-aio TEST_NGINX_ANON_PORT=11199 TEST_SKIP_SERVER_SETUP=1 \
    PYTHONPATH=tests python3 -m pytest tests/test_xrootdfs_ext.py -v -p no:xdist
"""
import os
import shutil
import socket
import stat as statmod
import subprocess
import time

import pytest

from settings import DATA_ROOT, NGINX_ANON_PORT, SERVER_HOST

pytestmark = pytest.mark.timeout(120)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XROOTDFS = os.path.join(CLIENT_DIR, "bin", "xrootdfs")
ANON_URL = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}/"

_FUSE_OK = os.path.exists("/dev/fuse") and shutil.which("fusermount3") is not None


def _port_up(host, port):
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


@pytest.fixture(scope="module")
def built():
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler")
    if not _FUSE_OK:
        pytest.skip("FUSE unavailable")
    proc = subprocess.run(["make", "-C", CLIENT_DIR, "xrootdfs"],
                          capture_output=True, text=True, timeout=240)
    if proc.returncode != 0 or not os.path.exists(XROOTDFS):
        pytest.skip(f"xrootdfs build failed:\n{proc.stdout}\n{proc.stderr}")
    if not _port_up(SERVER_HOST, NGINX_ANON_PORT):
        pytest.skip("anon server not running")
    return True


@pytest.fixture()
def mount(built):
    """Mount xrootdfs; yields (mountpoint, banner_text)."""
    mnt = subprocess.check_output(["mktemp", "-d", os.path.join(os.environ["TMPDIR"], "xrdext.XXXXXX")]).decode().strip()
    banner_path = mnt + ".banner"
    fh = open(banner_path, "w")
    p = subprocess.Popen([XROOTDFS, ANON_URL, mnt, "-f"], stdout=fh, stderr=fh)
    for _ in range(60):
        if os.path.ismount(mnt):
            break
        time.sleep(0.1)
    else:
        p.kill(); fh.close()
        subprocess.run(["fusermount3", "-u", mnt], capture_output=True)
        os.rmdir(mnt)
        pytest.skip("xrootdfs failed to mount")
    time.sleep(0.2)
    fh.flush()
    with open(banner_path) as bf:
        banner = bf.read()
    yield mnt, banner
    subprocess.run(["fusermount3", "-u", mnt], capture_output=True)
    p.wait(timeout=10)
    fh.close()
    for pth in (mnt, banner_path):
        try:
            os.rmdir(pth) if pth == mnt else os.unlink(pth)
        except OSError:
            pass


@pytest.fixture()
def seed():
    """A regular file in the served data root; cleans up ext artifacts."""
    name = f"_ext_{os.getpid()}_{int(time.time()*1000)}.bin"
    path = os.path.join(DATA_ROOT, name)
    with open(path, "wb") as fh:
        fh.write(b"vendor-ext-payload\n")
    artifacts = [path, path + ".lnk", path + ".hard", path + ".dangling"]
    yield name
    for a in artifacts:
        try:
            os.unlink(a)
        except OSError:
            pass


def test_capability_advertised(mount):
    """The mount banner reports all four extensions as supported."""
    _mnt, banner = mount
    assert "setattr=1" in banner, banner
    assert "symlink=1" in banner, banner
    assert "readlink=1" in banner, banner
    assert "link=1" in banner, banner


def test_setattr_mtime(mount, seed):
    """os.utime() through the mount persists to the backing file's mtime."""
    mnt, _banner = mount
    target = 1560600000  # 2019-06-15ish
    os.utime(os.path.join(mnt, seed), (target, target))
    backing = int(os.stat(os.path.join(DATA_ROOT, seed)).st_mtime)
    assert backing == target
    # and the mount reports it back
    assert int(os.stat(os.path.join(mnt, seed)).st_mtime) == target


def test_symlink_to_existing(mount, seed):
    """symlink + readlink round-trip; ls sees it as a symlink (getattr lstat)."""
    mnt, _banner = mount
    link = seed + ".lnk"
    os.symlink(seed, os.path.join(mnt, link))
    assert os.readlink(os.path.join(mnt, link)) == seed
    st = os.lstat(os.path.join(mnt, link))
    assert statmod.S_ISLNK(st.st_mode), "mount must present it as a symlink"
    # reading through the link yields the target's content
    with open(os.path.join(mnt, link), "rb") as fh:
        assert fh.read() == b"vendor-ext-payload\n"
    # backing is a real symlink
    assert os.readlink(os.path.join(DATA_ROOT, link)) == seed


def test_symlink_dangling(mount, seed):
    """A dangling symlink can be created and its target read back."""
    mnt, _banner = mount
    link = seed + ".dangling"
    os.symlink("/no/such/target", os.path.join(mnt, link))
    assert os.readlink(os.path.join(mnt, link)) == "/no/such/target"


def test_hard_link(mount, seed):
    """A hard link shares the backing inode."""
    mnt, _banner = mount
    hard = seed + ".hard"
    os.link(os.path.join(mnt, seed), os.path.join(mnt, hard))
    a = os.stat(os.path.join(DATA_ROOT, seed)).st_ino
    b = os.stat(os.path.join(DATA_ROOT, hard)).st_ino
    assert a == b
    with open(os.path.join(mnt, hard), "rb") as fh:
        assert fh.read() == b"vendor-ext-payload\n"


def test_readdir_reports_symlink(mount, seed):
    """readdir-plus (a directory listing, not a per-path getattr) reports a
    symlink entry as a symlink — the server lstat's each entry
    (AT_SYMLINK_NOFOLLOW) so `ls -l <dir>` shows it as a link."""
    mnt, _banner = mount
    link = seed + ".lnk"
    os.symlink(seed, os.path.join(mnt, link))
    # scandir(follow_symlinks=False) uses the readdir-plus per-entry attrs,
    # not a separate getattr, so this exercises the dirlist path specifically.
    found = None
    for e in os.scandir(mnt):
        if e.name == link:
            found = e
            break
    assert found is not None, "symlink entry missing from the directory listing"
    assert found.is_symlink(), "readdir-plus must report the entry as a symlink"

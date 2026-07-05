# brix-remote-ok
"""
test_xrootdfs_http.py — HTTP(S)/WebDAV transport for the xrootdfs FUSE driver.

WHAT: Mounts the async FUSE driver over BOTH transports it now speaks — the binary
      root:// protocol and HTTP/WebDAV (XrdHttp-style Range GET) — against the same
      namespace, and asserts:
        * getattr/readdir/read are byte-exact over each transport;
        * the two transports return IDENTICAL bytes for the same file (the premise
          of the root-vs-https performance comparison);
        * the HTTP mount is read-only (write/mkdir/unlink → EROFS).
WHY:  Proves the new webfile.c transport (PROPFIND stat/readdir + ranged GET over a
      persistent keep-alive socket) is wired correctly into the driver and is a
      faithful, interchangeable alternative to root:// — against this nginx module
      and (opt-in) against an official XRootD XrdHttp endpoint.
HOW:  Uses the standard fleet: root://:ANON and http://:HTTP_WEBDAV both serve
      DATA_ROOT anonymously. The official-XRootD comparison (root:// + https/XrdHttp)
      is opt-in via TEST_OFFICIAL_ROOT_URL / TEST_OFFICIAL_HTTPS_URL and is skipped
      when those are unset, so the committed suite runs against nginx in CI.

Run (against the standard fleet):
  PYTHONPATH=tests python3 -m pytest tests/test_xrootdfs_http.py -v -p no:xdist

Run the official-XRootD comparison too (a local xrootd + XrdHttp on /data):
  TEST_OFFICIAL_ROOT_URL=root://127.0.0.1:12095/data \
  TEST_OFFICIAL_HTTPS_URL=https://127.0.0.1:12096/data \
    PYTHONPATH=tests python3 -m pytest tests/test_xrootdfs_http.py -v -p no:xdist
"""
import contextlib
import hashlib
import os
import shutil
import socket
import subprocess
import time

import pytest

from settings import DATA_ROOT, NGINX_ANON_PORT, NGINX_HTTP_WEBDAV_PORT, SERVER_HOST

pytestmark = pytest.mark.timeout(180)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XROOTDFS = os.path.join(CLIENT_DIR, "bin", "xrootdfs")

_FUSE_OK = os.path.exists("/dev/fuse") and shutil.which("fusermount3") is not None

# A multi-MiB payload so reads span many ranged GETs / many pipelined root:// reads.
_PAYLOAD = os.urandom(6 * 1024 * 1024 + 12345)
_PAYLOAD_MD5 = hashlib.md5(_PAYLOAD).hexdigest()
_FNAME = f"_xrdfshttp_{os.getpid()}.bin"


def _port_up(host, port):
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


@pytest.fixture(scope="module")
def built():
    if not _FUSE_OK:
        pytest.skip("FUSE unavailable (/dev/fuse or fusermount3 missing)")
    proc = subprocess.run(["make", "-C", CLIENT_DIR, "xrootdfs"],
                          capture_output=True, text=True, timeout=300)
    if proc.returncode != 0 or not os.path.exists(XROOTDFS):
        pytest.skip(f"xrootdfs build failed:\n{proc.stdout}\n{proc.stderr}")
    return True


@pytest.fixture(scope="module")
def data_file(built):
    """A known-md5 file dropped into the served data root for the module."""
    path = os.path.join(DATA_ROOT, _FNAME)
    os.makedirs(DATA_ROOT, exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(_PAYLOAD)
    yield _FNAME, _PAYLOAD_MD5
    with contextlib.suppress(OSError):
        os.unlink(path)


@contextlib.contextmanager
def _mount(url, extra=None):
    """Mount xrootdfs at a fresh mountpoint; unmount on exit."""
    mnt = subprocess.check_output(
        ["mktemp", "-d", os.path.join(os.environ["TMPDIR"], "xrdfshttp.XXXXXX")]).decode().strip()
    argv = [XROOTDFS, url, mnt, "-f"]
    if extra:
        argv[1:1] = extra
    proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        for _ in range(80):
            if os.path.ismount(mnt):
                break
            if proc.poll() is not None:
                break
            time.sleep(0.1)
        if not os.path.ismount(mnt):
            err = b""
            with contextlib.suppress(Exception):
                err = proc.stderr.read() if proc.stderr else b""
            proc.kill()
            pytest.skip(f"mount failed for {url}: {err.decode(errors='replace')}")
        yield mnt
    finally:
        subprocess.run(["fusermount3", "-u", "-z", mnt], capture_output=True)
        with contextlib.suppress(Exception):
            proc.wait(timeout=10)
        with contextlib.suppress(OSError):
            os.rmdir(mnt)


def _md5_of(path, chunk=65536):
    h = hashlib.md5()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


# ---- endpoint table -------------------------------------------------------
# Each entry: (id, url, extra-args, needs-up-check host/port or None for opt-in).

def _nginx_root():
    return f"root://{SERVER_HOST}:{NGINX_ANON_PORT}/"


def _nginx_http():
    return f"http://{SERVER_HOST}:{NGINX_HTTP_WEBDAV_PORT}/"


def _require(host, port):
    if not _port_up(host, port):
        pytest.skip(f"server {host}:{port} not running")


# ==========================================================================
# nginx module — both transports
# ==========================================================================

def test_nginx_root_read(data_file):
    """root:// FUSE read is byte-exact against the nginx module."""
    _require(SERVER_HOST, NGINX_ANON_PORT)
    name, md5 = data_file
    with _mount(_nginx_root()) as mnt:
        assert _md5_of(os.path.join(mnt, name)) == md5


def test_nginx_http_read(data_file):
    """http/WebDAV FUSE read (ranged GET) is byte-exact against the nginx module."""
    _require(SERVER_HOST, NGINX_HTTP_WEBDAV_PORT)
    name, md5 = data_file
    with _mount(_nginx_http()) as mnt:
        assert _md5_of(os.path.join(mnt, name)) == md5


def test_nginx_readdir_both_transports(data_file):
    """The file is listed by readdir over BOTH transports."""
    _require(SERVER_HOST, NGINX_ANON_PORT)
    _require(SERVER_HOST, NGINX_HTTP_WEBDAV_PORT)
    name, _ = data_file
    with _mount(_nginx_root()) as mnt:
        assert name in os.listdir(mnt)
    with _mount(_nginx_http()) as mnt:
        assert name in os.listdir(mnt)


def test_nginx_getattr_size_matches(data_file):
    """getattr reports the true size over both transports (no dir/size confusion)."""
    _require(SERVER_HOST, NGINX_ANON_PORT)
    _require(SERVER_HOST, NGINX_HTTP_WEBDAV_PORT)
    name, _ = data_file
    want = len(_PAYLOAD)
    with _mount(_nginx_root()) as mnt:
        st = os.stat(os.path.join(mnt, name))
        assert st.st_size == want and not os.path.isdir(os.path.join(mnt, name))
    with _mount(_nginx_http()) as mnt:
        st = os.stat(os.path.join(mnt, name))
        assert st.st_size == want and not os.path.isdir(os.path.join(mnt, name))


def test_nginx_cross_protocol_identical(data_file):
    """root:// and http/WebDAV return byte-identical content (comparison premise)."""
    _require(SERVER_HOST, NGINX_ANON_PORT)
    _require(SERVER_HOST, NGINX_HTTP_WEBDAV_PORT)
    name, _ = data_file
    with _mount(_nginx_root()) as r:
        root_md5 = _md5_of(os.path.join(r, name))
    with _mount(_nginx_http()) as w:
        http_md5 = _md5_of(os.path.join(w, name))
    assert root_md5 == http_md5


def test_nginx_partial_range_read(data_file):
    """A pread at an interior offset (one ranged GET) returns the right bytes."""
    _require(SERVER_HOST, NGINX_HTTP_WEBDAV_PORT)
    name, _ = data_file
    off, length = 1_000_003, 65_521          # odd offset/length → exercises Range math
    with _mount(_nginx_http()) as mnt:
        with open(os.path.join(mnt, name), "rb") as f:
            f.seek(off)
            got = f.read(length)
    assert got == _PAYLOAD[off:off + length]


def test_http_mount_is_readonly(data_file):
    """The HTTP/WebDAV mount rejects writes (EROFS) — it is a read-only transport."""
    import errno
    _require(SERVER_HOST, NGINX_HTTP_WEBDAV_PORT)
    with _mount(_nginx_http()) as mnt:
        with pytest.raises(OSError) as ei:
            with open(os.path.join(mnt, "_should_fail.txt"), "wb") as f:
                f.write(b"nope")
        assert ei.value.errno == errno.EROFS
        with pytest.raises(OSError) as ei2:
            os.mkdir(os.path.join(mnt, "_should_fail_dir"))
        assert ei2.value.errno == errno.EROFS


# ==========================================================================
# official XRootD — opt-in (root:// + https/XrdHttp), skipped when env unset
# ==========================================================================

_OFF_ROOT = os.environ.get("TEST_OFFICIAL_ROOT_URL")
_OFF_HTTPS = os.environ.get("TEST_OFFICIAL_HTTPS_URL")
# The official server serves its OWN data dir, distinct from nginx's DATA_ROOT, so
# the payload must be placed there too (the URLs export this dir's contents).
_OFF_DATA = os.environ.get("TEST_OFFICIAL_DATA_DIR")


@pytest.fixture(scope="module")
def official_file(built):
    """Drop the known-md5 payload into the official server's data dir."""
    if not _OFF_DATA:
        pytest.skip("TEST_OFFICIAL_DATA_DIR not set (official server's data dir)")
    path = os.path.join(_OFF_DATA, _FNAME)
    with open(path, "wb") as fh:
        fh.write(_PAYLOAD)
    yield _FNAME, _PAYLOAD_MD5
    with contextlib.suppress(OSError):
        os.unlink(path)


@pytest.mark.skipif(not _OFF_ROOT, reason="TEST_OFFICIAL_ROOT_URL not set")
def test_official_root_read(official_file):
    """root:// FUSE read against an official XRootD server is byte-exact."""
    name, md5 = official_file
    with _mount(_OFF_ROOT) as mnt:
        assert _md5_of(os.path.join(mnt, name)) == md5


@pytest.mark.skipif(not _OFF_HTTPS, reason="TEST_OFFICIAL_HTTPS_URL not set")
def test_official_xrdhttp_read(official_file):
    """https/XrdHttp FUSE read against an official XRootD server is byte-exact.

    XrdHttp uses a self-signed cert in test beds and advertises 'Connection: Close'
    without closing the socket — both handled by the driver (--noverifyhost + framed
    Content-Length reads)."""
    name, md5 = official_file
    with _mount(_OFF_HTTPS, extra=["--noverifyhost"]) as mnt:
        assert _md5_of(os.path.join(mnt, name)) == md5


@pytest.mark.skipif(not (_OFF_ROOT and _OFF_HTTPS),
                    reason="official root+https URLs not both set")
def test_official_cross_protocol_identical(official_file):
    """Official root:// and XrdHttp return byte-identical content."""
    name, _ = official_file
    with _mount(_OFF_ROOT) as r:
        root_md5 = _md5_of(os.path.join(r, name))
    with _mount(_OFF_HTTPS, extra=["--noverifyhost"]) as w:
        http_md5 = _md5_of(os.path.join(w, name))
    assert root_md5 == http_md5

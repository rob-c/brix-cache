# brix-remote-skip
"""
test_client_xrdfs_web.py — native `xrdfs` over an http(s)/WebDAV endpoint.

WHAT: The native `xrdfs` accepts an http/https/dav/davs URL endpoint (not just
      root://) and serves the read-only metadata commands `ls` and `stat` over
      WebDAV PROPFIND — mirroring the official xrdfs, which also takes an https://
      WebDAV URL. Mutating/file commands report a clear "use a root:// endpoint"
      message rather than the old "scheme not supported by native client".
WHY:  Before this, `./client/bin/xrdfs https://host/path ls` errored on the scheme;
      the official client accepted it. This closes that parity gap.
HOW:  Uses the standard fleet's anonymous http WebDAV endpoint (:HTTP_WEBDAV,
      serving DATA_ROOT). Drops a known file and lists/stats it through `xrdfs`.

Run (against the running fleet):
  TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_client_xrdfs_web.py -v -p no:xdist
"""
import contextlib
import os
import socket
import subprocess

import pytest

from settings import DATA_ROOT, NGINX_HTTP_WEBDAV_PORT, SERVER_HOST

pytestmark = pytest.mark.timeout(120)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRDFS = os.path.join(CLIENT_DIR, "bin", "xrdfs")

_FNAME = f"_xrdfsweb_{os.getpid()}.bin"
_PAYLOAD = os.urandom(4096)
_WEB = f"http://{SERVER_HOST}:{NGINX_HTTP_WEBDAV_PORT}/"


def _port_up(host, port):
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


@pytest.fixture(scope="module")
def xrdfs(): # noqa: D401
    proc = subprocess.run(["make", "-C", CLIENT_DIR, "xrdfs"],
                          capture_output=True, text=True, timeout=240)
    if proc.returncode != 0 or not os.path.exists(XRDFS):
        pytest.skip(f"xrdfs build failed:\n{proc.stdout}\n{proc.stderr}")
    if not _port_up(SERVER_HOST, NGINX_HTTP_WEBDAV_PORT):
        pytest.skip(f"http WebDAV {SERVER_HOST}:{NGINX_HTTP_WEBDAV_PORT} not running")
    return XRDFS


@pytest.fixture(scope="module")
def data_file(xrdfs):
    os.makedirs(DATA_ROOT, exist_ok=True)
    path = os.path.join(DATA_ROOT, _FNAME)
    with open(path, "wb") as fh:
        fh.write(_PAYLOAD)
    yield _FNAME
    with contextlib.suppress(OSError):
        os.unlink(path)


def _run(*args):
    return subprocess.run([XRDFS, *args], capture_output=True, text=True, timeout=30)


def test_web_scheme_is_accepted(data_file):
    """An https/http WebDAV URL no longer errors with 'scheme not supported'."""
    r = _run(_WEB, "ls")
    assert "scheme not supported" not in (r.stdout + r.stderr)
    assert r.returncode == 0, r.stderr


def test_web_ls_lists_file(data_file):
    """`xrdfs <webdav> ls` lists a known file in the export."""
    r = _run(_WEB, "ls")
    assert r.returncode == 0, r.stderr
    assert _FNAME in r.stdout


def test_web_ls_long(data_file):
    """`ls -l` prints the size and a dir/file flag column."""
    r = _run(_WEB, "ls", "-l")
    assert r.returncode == 0, r.stderr
    line = next((ln for ln in r.stdout.splitlines() if _FNAME in ln), "")
    assert str(len(_PAYLOAD)) in line          # size present
    assert line[:1] in ("-", "d")              # type column


def test_web_stat(data_file):
    """`stat` reports the size of a file over WebDAV."""
    r = _run(_WEB, "stat", _FNAME)
    assert r.returncode == 0, r.stderr
    assert f"Size:   {len(_PAYLOAD)}" in r.stdout
    assert "Path:   " in r.stdout


def test_web_unsupported_command_is_clear(data_file):
    """A mutating command over WebDAV fails with a clear, non-cryptic message."""
    r = _run(_WEB, "mkdir", "newdir")
    assert r.returncode != 0
    assert "not supported over an http(s)/WebDAV endpoint" in r.stderr
    assert "scheme not supported" not in r.stderr

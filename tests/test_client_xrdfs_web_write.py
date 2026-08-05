"""
test_client_xrdfs_web_write.py — native `xrdfs`/`xrd` WRITE-metadata over WebDAV.

WHAT: The native client now serves the write-metadata verbs `mkdir`, `rm`,
      `rmdir` and `mv` over an http/https/dav/davs WebDAV endpoint (MKCOL /
      DELETE / MOVE), not only read-only `ls`/`stat`. The unified `xrd` wrapper
      forwards those verbs to `xrdfs` for a WebDAV endpoint exactly as it does
      for root://, so `xrd mkdir davs://h/d` and `xrd mv davs://h/a davs://h/b`
      work too.
WHY:  before this, every mutating verb over WebDAV printed "use a root:// endpoint";
      the write surface was root:// only. This closes that gap and matches the
      official client, which drives MKCOL/DELETE/MOVE over its WebDAV URL.
HOW:  self-provisions two single-worker nginx WebDAV endpoints via the lifecycle
      harness — one writable (allow_write on) for the success/error paths and one
      read-only (allow_write off) for the security-negative — so the behaviour is
      observable without touching the shared fleet.

The three required cases per the coding standard:
  * success:  mkdir -> (xrdcp put) -> mv -> stat -> rm -> rmdir round-trips and
              the moved/removed objects are reflected on the backend filesystem;
  * error:    `rm` of a path that does not exist FAILS (maps 404 -> not-found),
              it is NOT silently reported as success;
  * security: on a read-only endpoint every write verb is rejected (the server's
              allow_write gate → non-zero exit), never a faked success.

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_client_xrdfs_web_write.py -v -p no:xdist
"""
import os
import subprocess
import uuid

import pytest

from settings import BIND_HOST, HOST as _HOST, NGINX_BIN
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.serial, pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-xrdfs-web-write"),
              pytest.mark.timeout(180)]

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRDFS = os.path.join(CLIENT_DIR, "bin", "xrdfs")
XRDCP = os.path.join(CLIENT_DIR, "bin", "xrdcp")
XRD = os.path.join(CLIENT_DIR, "bin", "xrd")


def _build():
    proc = subprocess.run(["make", "-C", CLIENT_DIR, "xrdfs", "xrdcp", "xrd"],
                          capture_output=True, text=True, timeout=300)
    if proc.returncode != 0 or not all(os.path.exists(b) for b in (XRDFS, XRDCP, XRD)):
        pytest.skip(f"client build failed:\n{proc.stdout}\n{proc.stderr}")


def _endpoint(harness, name, template, data):
    ep = harness.start(NginxInstanceSpec(
        name=name,
        template=template,
        protocol="webdav",
        template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": str(data)},
        reason="xrdfs webdav write-metadata"))
    return f"http://{_HOST}:{ep.port}"


@pytest.fixture(scope="module")
def rw(tmp_path_factory):
    """A writable anonymous WebDAV endpoint + its backing DATA_DIR."""
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    _build()
    data = tmp_path_factory.mktemp("xrdfs-web-write-data")
    os.chmod(str(data), 0o777)  # the (nobody) worker must be able to MKCOL here
    harness = LifecycleHarness()
    try:
        base = _endpoint(harness, "lc-xrdfs-web-write-rw",
                         "nginx_lc_webdav_verify_write.conf", data)
        yield base, str(data)
    finally:
        harness.close()


@pytest.fixture(scope="module")
def ro(tmp_path_factory):
    """A read-only anonymous WebDAV endpoint (allow_write off)."""
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    _build()
    data = tmp_path_factory.mktemp("xrdfs-web-ro-data")
    os.chmod(str(data), 0o777)  # writable on disk: the denial must come from the
    harness = LifecycleHarness()  # allow_write gate, not a filesystem-permission accident
    try:
        base = _endpoint(harness, "lc-xrdfs-web-write-ro",
                         "nginx_lc_webdav_metadata_ro.conf", data)
        yield base, str(data)
    finally:
        harness.close()


def _xrdfs(base, *args):
    return subprocess.run([XRDFS, base, *args],
                          capture_output=True, text=True, timeout=30)


def _xrd(*args):
    return subprocess.run([XRD, *args], capture_output=True, text=True, timeout=30)


# ---------------------------------------------------------------- success ----
def test_web_write_metadata_roundtrip(rw):
    """mkdir → put → mv → stat → rm → rmdir all succeed and land on the backend."""
    base, data = rw
    d = f"/wm_{uuid.uuid4().hex}"
    src = os.path.join(CLIENT_DIR, "bin", "xrdfs")  # any real local file to upload

    assert _xrdfs(base, "mkdir", d).returncode == 0
    assert os.path.isdir(data + d), "MKCOL did not create the collection on disk"

    put = subprocess.run([XRDCP, "-f", src, f"{base}{d}/f.dat"],
                         capture_output=True, text=True, timeout=60)
    assert put.returncode == 0, put.stderr
    assert os.path.exists(f"{data}{d}/f.dat")

    assert _xrdfs(base, "mv", f"{d}/f.dat", f"{d}/g.dat").returncode == 0
    assert os.path.exists(f"{data}{d}/g.dat") and not os.path.exists(f"{data}{d}/f.dat"), \
        "MOVE did not rename on disk"

    stat = _xrdfs(base, "stat", f"{d}/g.dat")
    assert stat.returncode == 0 and "Path:   " in stat.stdout

    assert _xrdfs(base, "rm", f"{d}/g.dat").returncode == 0
    assert not os.path.exists(f"{data}{d}/g.dat"), "DELETE did not remove the file"

    assert _xrdfs(base, "rmdir", d).returncode == 0
    assert not os.path.isdir(data + d), "DELETE did not remove the collection"


def test_wrapper_web_write_metadata(rw):
    """`xrd <verb> davs://…` forwards mkdir/mv/rm/rmdir to xrdfs over WebDAV."""
    base, data = rw
    d = f"/ww_{uuid.uuid4().hex}"

    assert _xrd("mkdir", f"{base}{d}").returncode == 0
    assert os.path.isdir(data + d)

    put = subprocess.run([XRDCP, "-f", XRDFS, f"{base}{d}/a.dat"],
                         capture_output=True, text=True, timeout=60)
    assert put.returncode == 0, put.stderr

    # two full-URL operands must both map to same-endpoint paths
    assert _xrd("mv", f"{base}{d}/a.dat", f"{base}{d}/b.dat").returncode == 0
    assert os.path.exists(f"{data}{d}/b.dat")

    assert _xrd("rm", f"{base}{d}/b.dat").returncode == 0
    assert _xrd("rmdir", f"{base}{d}").returncode == 0
    assert not os.path.isdir(data + d)


# ------------------------------------------------------------------ error ----
def test_rm_missing_path_is_reported_error(rw):
    """`rm` of a non-existent WebDAV path FAILS (404→not-found), not a fake success."""
    base, _ = rw
    r = _xrdfs(base, "rm", f"/no_such_{uuid.uuid4().hex}")
    assert r.returncode != 0, "rm of a missing path must not succeed"
    combined = (r.stdout + r.stderr).lower()
    assert "not" in combined and "found" in combined or "404" in combined, combined


def test_rmdir_missing_path_is_reported_error(rw):
    """`rmdir` of a non-existent collection also fails cleanly."""
    base, _ = rw
    r = _xrdfs(base, "rmdir", f"/no_dir_{uuid.uuid4().hex}")
    assert r.returncode != 0


# --------------------------------------------------------------- security ----
def test_readonly_endpoint_rejects_writes(ro):
    """On allow_write=off, every write verb is denied — never a faked success."""
    base, data = ro
    d = f"/sec_{uuid.uuid4().hex}"

    mk = _xrdfs(base, "mkdir", d)
    assert mk.returncode != 0, "mkdir must be rejected on a read-only endpoint"
    assert not os.path.isdir(data + d), "read-only endpoint must not have created the dir"

    rm = _xrdfs(base, "rm", "/anything")
    assert rm.returncode != 0, "rm must be rejected on a read-only endpoint"

    mv = _xrdfs(base, "mv", "/a", "/b")
    assert mv.returncode != 0, "mv must be rejected on a read-only endpoint"

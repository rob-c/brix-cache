"""
tests/test_checksum_on_write.py — §8.3 checksum-on-ingest (WebDAV PUT).

With xrootd_webdav_checksum_on_write naming algorithms, a successful PUT proactively
persists each digest on the committed file (xattr, or .cks sidecar on no-xattr fs).
Verified by reading the user.XrdCks.<alg> xattr off the committed file and checking
the stored hex equals the algorithm over the content. A control server WITHOUT the
directive leaves no checksum xattr.

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_checksum_on_write.py -v
"""

import os
import socket
import subprocess
import sys
import time
import uuid
import zlib

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "."))

try:
    import requests
    _HAVE_REQUESTS = True
except Exception:  # pragma: no cover
    _HAVE_REQUESTS = False

from settings import NGINX_BIN, free_port, HOST, BIND_HOST  # noqa: E402



def _wait_port(port, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _start(tmp_path_factory, on_write, xattr_format=None):
    d = tmp_path_factory.mktemp("cow")
    (d / "logs").mkdir()
    (d / "t").mkdir()
    (d / "cadir").mkdir()
    data = d / "data"
    data.mkdir()
    port = free_port()
    extra = (f"xrootd_webdav_checksum_on_write {on_write};" if on_write else "")
    if xattr_format:
        extra += f"\n            xrootd_webdav_checksum_xattr_format {xattr_format};"
    conf = f"""
error_log {d}/logs/error.log info;
pid {d}/logs/nginx.pid;
events {{ worker_connections 64; }}
http {{
    client_body_temp_path {d}/t; proxy_temp_path {d}/t; fastcgi_temp_path {d}/t;
    uwsgi_temp_path {d}/t; scgi_temp_path {d}/t; access_log off;
    server {{
        listen {BIND_HOST}:{port};
        location / {{
            xrootd_webdav on;
            xrootd_webdav_root {data};
            xrootd_webdav_auth none;
            xrootd_webdav_allow_write on;
            {extra}
        }}
    }}
}}
daemon off;
master_process off;
"""
    cp = d / "nginx.conf"
    cp.write_text(conf)
    proc = subprocess.Popen([NGINX_BIN, "-p", str(d), "-c", str(cp)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if not _wait_port(port):
        err = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
        proc.terminate()
        pytest.skip(f"server did not start: {err}")
    return proc, port, str(data), f"http://{HOST}:{port}"


@pytest.fixture(scope="module")
def cow_server(tmp_path_factory):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")
    if not _HAVE_REQUESTS:
        pytest.skip("requests not available")
    proc, port, data, base = _start(tmp_path_factory, "adler32,crc32c")
    yield port, data, base
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture(scope="module")
def xrdcks_server(tmp_path_factory):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")
    if not _HAVE_REQUESTS:
        pytest.skip("requests not available")
    proc, port, data, base = _start(tmp_path_factory, "adler32",
                                    xattr_format="xrdcks")
    yield port, data, base
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture(scope="module")
def plain_server(tmp_path_factory):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")
    proc, port, data, base = _start(tmp_path_factory, None)
    yield port, data, base
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def _xattr_text(path, alg):
    try:
        v = os.getxattr(path, f"user.XrdCks.{alg}")
    except OSError:
        return None
    return v.decode(errors="replace")


def test_on_write_persists_xattr(cow_server):
    _port, data, base = cow_server
    name = f"cow_{uuid.uuid4().hex[:10]}.bin"
    body = os.urandom(5000)
    r = requests.put(f"{base}/{name}", data=body, timeout=10)
    assert r.status_code in (200, 201, 204), r.status_code

    fpath = os.path.join(data, name)
    assert os.path.exists(fpath)

    adler = _xattr_text(fpath, "adler32")
    crc = _xattr_text(fpath, "crc32c")
    assert adler is not None, "adler32 xattr missing after on-write"
    assert crc is not None, "crc32c xattr missing after on-write"
    # stored format is "<hex> <mtime_sec> <mtime_nsec> <size>"; verify the adler32 hex
    want = format(zlib.adler32(body) & 0xffffffff, "08x")
    assert adler.split()[0] == want, f"adler32 {adler.split()[0]} != {want}"


def test_no_directive_no_xattr(plain_server):
    _port, data, base = plain_server
    name = f"plain_{uuid.uuid4().hex[:10]}.bin"
    r = requests.put(f"{base}/{name}", data=b"hello-plain", timeout=10)
    assert r.status_code in (200, 201, 204), r.status_code
    fpath = os.path.join(data, name)
    assert os.path.exists(fpath)
    assert _xattr_text(fpath, "adler32") is None, "no checksum xattr expected"


def test_xrdcks_binary_format(xrdcks_server):
    """With xattr_format=xrdcks, the persisted user.XrdCks.adler32 must be the
    stock binary XrdCksData record (Name[16] + fmTime + ... + Value[64]), not our
    text format — so a stock xrdfs/OSS reads it. Validate the on-disk bytes."""
    import struct as _struct
    _port, data, base = xrdcks_server
    name = f"cowb_{uuid.uuid4().hex[:10]}.bin"
    body = os.urandom(4096)
    r = requests.put(f"{base}/{name}", data=body, timeout=10)
    assert r.status_code in (200, 201, 204), r.status_code
    raw = os.getxattr(os.path.join(data, name), "user.XrdCks.adler32")

    # XrdCksData is a fixed struct (96 bytes on x86-64): not our text "<hex> ...".
    assert len(raw) >= 88, len(raw)
    assert b" " not in raw[:16], "looks like text, not binary XrdCksData"
    name_field = raw[:16].split(b"\x00", 1)[0]
    assert name_field == b"adler32", name_field
    # Length byte (offset 31 on x86-64 layout) = 4 for adler32; Value follows.
    length = raw[31]
    assert length == 4, length
    digest = raw[32:36]
    assert digest == _struct.pack(">I", zlib.adler32(body) & 0xffffffff), digest.hex()

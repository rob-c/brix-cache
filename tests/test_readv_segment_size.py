"""
tests/test_readv_segment_size.py

Verifies the xrootd_readv_segment_size directive (the per-kXR_readv-element cap,
the official "maxReadv_ior") end-to-end against the OFFICIAL XRootD client:

  1. the server advertises the configured value via kXR_Qconfig "readv_ior_max"
     (and "readv_iov_max"), so official clients size their VectorReads to it; and
  2. an official VectorRead of an element up to that size returns the full,
     byte-exact data.

A dedicated anonymous nginx is started on a free port with the directive set to
16m, so a single 8 MiB readv element — larger than the stock 2 MiB default —
succeeds in one element. Single server per test so XrdCl's per-process connection
state stays simple (multiple servers in one process can wedge XrdCl).

Run:
    pytest tests/test_readv_segment_size.py -v
"""

import os
import socket
import subprocess
import tempfile
import time
import shutil

import pytest
from XRootD import client
from XRootD.client.flags import QueryCode

NGINX_BIN = os.environ.get("RESIL_NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")

_CONF = """\
worker_processes 1;
daemon off;
error_log {logs}/error.log error;
pid {logs}/nginx.pid;
events {{ worker_connections 1024; }}
stream {{
    server {{
        listen 127.0.0.1:{port};
        xrootd on;
        xrootd_storage_backend posix:{data};
        xrootd_readv_segment_size 16m;
        xrootd_access_log {logs}/access.log;
    }}
}}
"""

FILE_BYTES = 20 * 1024 * 1024
SEG_CAP = 16 * 1024 * 1024          # the configured xrootd_readv_segment_size
MAXSEGS = 1024                       # XROOTD_READV_MAXSEGS


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture(scope="module")
def server16m():
    """A dedicated anon nginx with xrootd_readv_segment_size 16m + a 20 MiB file."""
    if not os.path.isfile(NGINX_BIN):
        pytest.skip(f"nginx binary not found: {NGINX_BIN}")
    prefix = tempfile.mkdtemp(prefix="readv_seg_")
    data = os.path.join(prefix, "data")
    logs = os.path.join(prefix, "logs")
    confd = os.path.join(prefix, "conf")
    for d in (data, logs, confd):
        os.makedirs(d, exist_ok=True)
    payload = os.urandom(FILE_BYTES)
    with open(os.path.join(data, "big.bin"), "wb") as fh:
        fh.write(payload)
    port = _free_port()
    with open(os.path.join(confd, "nginx.conf"), "w") as fh:
        fh.write(_CONF.format(port=port, data=data, logs=logs))
    env = dict(os.environ)
    env.pop("LD_LIBRARY_PATH", None)   # conda prefix breaks system XRootD libs
    proc = subprocess.Popen([NGINX_BIN, "-p", prefix, "-c", "conf/nginx.conf"], env=env)
    up = False
    for _ in range(60):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            up = True
            break
        except OSError:
            time.sleep(0.1)
    if not up:
        proc.terminate()
        shutil.rmtree(prefix, ignore_errors=True)
        pytest.fail(f"nginx never came up on :{port}")
    try:
        yield {"url": f"root://127.0.0.1:{port}", "payload": payload}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        shutil.rmtree(prefix, ignore_errors=True)


def test_qconfig_advertises_configured_segment_size(server16m):
    """kXR_Qconfig readv_ior_max reports the configured cap; readv_iov_max the
    segment-count limit — so official clients size their VectorReads to match."""
    fs = client.FileSystem(server16m["url"])
    st, rsp = fs.query(QueryCode.CONFIG, "readv_ior_max")
    assert st.ok, f"Qconfig readv_ior_max failed: {st.message}"
    assert int(bytes(rsp).split()[0]) == SEG_CAP

    st, rsp = fs.query(QueryCode.CONFIG, "readv_iov_max")
    assert st.ok, f"Qconfig readv_iov_max failed: {st.message}"
    assert int(bytes(rsp).split()[0]) == MAXSEGS


def test_official_vectorread_large_element(server16m):
    """An official VectorRead of a single 8 MiB element (larger than the stock
    2 MiB default) returns the full element, byte-exact, because the cap is 16m."""
    req = 8 * 1024 * 1024
    f = client.File()
    st, _ = f.open(server16m["url"] + "//big.bin", 0)
    assert st.ok, f"open failed: {st.message}"
    try:
        st, vri = f.vector_read([(0, req)])
        assert st.ok, f"vector_read failed: {st.message}"
        got = b"".join(bytes(ch.buffer) for ch in vri.chunks)
        assert len(got) == req, f"expected {req} bytes, got {len(got)}"
        assert got == server16m["payload"][:req], "VectorRead bytes are not byte-exact"
    finally:
        f.close()

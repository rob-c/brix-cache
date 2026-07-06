"""
tests/test_cns.py — §6 Composite Cluster Name Space (2-node, real instances).

Stands up a manager (brix_manager_mode + brix_cns collect + a CMS server port)
and a data server (brix_cns emit, CMS-linked to the manager). A client writes a
file to the data server; on close the data server reports it to the manager over
the CMS link; a stat of that path AT THE MANAGER is then answered from the cluster
name-space inventory (size/mtime) instead of redirecting.

  * after a DS write, the manager stats the file from its CNS inventory (right size)
  * a path never written is NOT in the inventory (manager doesn't fabricate it)

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_cns.py -v
"""

import os
import socket
import struct
import subprocess
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "."))
from settings import NGINX_BIN, free_port, BIND_HOST  # noqa: E402

kXR_login, kXR_open, kXR_write, kXR_close, kXR_stat = 3007, 3010, 3019, 3003, 3017
kXR_ok, kXR_error = 0, 4003


def _recv_exact(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise EOFError("closed")
        b += c
    return b


def _resp(s):
    h = _recv_exact(s, 8)
    dl = struct.unpack("!I", h[4:8])[0]
    return struct.unpack("!H", h[2:4])[0], (_recv_exact(s, dl) if dl else b"")


def _session(port):
    s = socket.create_connection((BIND_HOST, port), timeout=10)
    s.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    assert _resp(s)[0] == kXR_ok
    s.sendall(struct.pack("!2sHI8sBBBBI", b"\x00\x01", kXR_login,
                          os.getpid() & 0x7fffffff, b"cns\x00\x00\x00\x00\x00",
                          0, 0, 0, 0, 0))
    assert _resp(s)[0] == kXR_ok
    return s


def _write_file(ds_port, path, data):
    s = _session(ds_port)
    p = path.encode()
    # open write|new|mkpath (0x0008 new | 0x0002? ) — use write + create
    opts = 0x0008 | 0x4000 | 0x0100   # kXR_new | kXR_open_wrto(write) | kXR_mkpath
    s.sendall(struct.pack("!2sHHHH6s4sI", b"\x00\x03", kXR_open, 0o644, opts, 0,
                          b"\x00" * 6, b"\x00" * 4, len(p)) + p)
    st, body = _resp(s)
    assert st == kXR_ok, ("open-write", st, body)
    fh = body[0:4]
    s.sendall(struct.pack("!2sH4sqiI", b"\x00\x07", kXR_write, fh, 0, 0,
                          len(data)) + data)
    assert _resp(s)[0] == kXR_ok, "write"
    s.sendall(struct.pack("!2sH4s12sI", b"\x00\x0e", kXR_close, fh, b"\x00" * 12, 0))
    _resp(s)
    s.close()


def _stat(port, path):
    s = _session(port)
    p = path.encode()
    s.sendall(struct.pack("!2sH16sI", b"\x00\x25", kXR_stat, b"\x00" * 16,
                          len(p)) + p)
    st, body = _resp(s)
    s.close()
    return st, body


def _render(tmpl, **kw):
    out = tmpl
    for k, v in kw.items():
        out = out.replace("{" + k + "}", str(v))
    return out


@pytest.fixture(scope="module")
def cluster(tmp_path_factory):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")
    base = tmp_path_factory.mktemp("cns")
    mgr_log = base / "mgr"; mgr_log.mkdir()
    ds_log = base / "ds"; ds_log.mkdir()
    data = base / "data"; data.mkdir()
    mgr_port = free_port()
    cms_port = free_port()
    ds_port = free_port()

    mgr_conf = f"""
worker_processes 1; daemon off; master_process off;
error_log {mgr_log}/error.log info; pid {mgr_log}/nginx.pid;
events {{ worker_connections 64; }}
stream {{
  server {{ listen {BIND_HOST}:{mgr_port}; brix_root on; brix_auth none;
           brix_manager_mode on; brix_cns collect; }}
  server {{ listen {BIND_HOST}:{cms_port}; brix_cms_server on; }}
}}
"""
    ds_conf = f"""
worker_processes 1; daemon off; master_process off;
error_log {ds_log}/error.log info; pid {ds_log}/nginx.pid;
events {{ worker_connections 64; }}
stream {{
  server {{ listen {BIND_HOST}:{ds_port}; brix_root on; brix_storage_backend posix:{data};
           brix_auth none; brix_allow_write on; brix_cns emit;
           brix_cms_manager {BIND_HOST}:{cms_port}; brix_cms_paths /;
           brix_cms_interval 1; brix_listen_port {ds_port}; }}
}}
"""
    (base / "mgr.conf").write_text(mgr_conf)
    (base / "ds.conf").write_text(ds_conf)

    procs = []
    for name in ("mgr", "ds"):
        p = subprocess.Popen([NGINX_BIN, "-c", str(base / f"{name}.conf"),
                              "-p", str(base / name)],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        procs.append(p)

    def up(port):
        for _ in range(100):
            try:
                socket.create_connection((BIND_HOST, port), timeout=0.5).close()
                return True
            except OSError:
                time.sleep(0.1)
        return False

    if not (up(mgr_port) and up(cms_port) and up(ds_port)):
        for p in procs:
            p.terminate()
        pytest.skip("cluster did not start")

    # Let the data server's CMS link to the manager come up + log in.
    time.sleep(6)
    yield mgr_port, ds_port
    for p in procs:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()


def test_manager_stats_written_file_from_cns(cluster):
    mgr_port, ds_port = cluster
    payload = b"composite-name-space-payload-12345"
    _write_file(ds_port, "/cnsfile.dat", payload)

    # Give the CNS event a moment to reach + apply at the manager.
    size = None
    for _ in range(40):
        st, body = _stat(mgr_port, "/cnsfile.dat")
        if st == kXR_ok:
            # "<id> <size> <flags> <modtime>"
            size = int(body.decode(errors="replace").split()[1])
            break
        time.sleep(0.25)
    assert size == len(payload), (size, len(payload))


def test_manager_unknown_path_not_in_inventory(cluster):
    mgr_port, _ = cluster
    st, _ = _stat(mgr_port, "/never-written-xyz.dat")
    # Not in CNS → the manager must NOT fabricate a successful stat. It falls
    # through to normal manager_mode handling (locate/redirect), which for a path
    # held by no data server answers wait/redirect/error — anything but kXR_ok.
    assert st != kXR_ok, st

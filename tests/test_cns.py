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
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "."))
from server_registry import NginxInstanceSpec  # noqa: E402
from settings import BIND_HOST  # noqa: E402

pytestmark = pytest.mark.uses_lifecycle_harness

kXR_login, kXR_open, kXR_write, kXR_close, kXR_stat = 3007, 3010, 3019, 3003, 3017
kXR_mkdir, kXR_rm, kXR_rmdir = 3008, 3014, 3015
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


def _mkdir(ds_port, path, mode=0o755):
    """kXR_mkdir: options(1) reserved(13) mode(2) dlen(4) + path (non-recursive)."""
    s = _session(ds_port)
    p = path.encode()
    s.sendall(struct.pack("!2sHB13sHI", b"\x00\x11", kXR_mkdir, 0,
                          b"\x00" * 13, mode, len(p)) + p)
    st, body = _resp(s)
    s.close()
    return st, body


def _ns_remove(ds_port, opcode, path):
    """kXR_rm / kXR_rmdir: reserved(16) dlen(4) + path."""
    s = _session(ds_port)
    p = path.encode()
    s.sendall(struct.pack("!2sH16sI", b"\x00\x13", opcode, b"\x00" * 16,
                          len(p)) + p)
    st, body = _resp(s)
    s.close()
    return st, body


def _poll_manager(mgr_port, path, want_ok, tries=40):
    """Poll the manager's CNS-backed stat until it (dis)appears; returns final st."""
    st = None
    for _ in range(tries):
        st, _ = _stat(mgr_port, path)
        if (st == kXR_ok) == want_ok:
            return st
        time.sleep(0.25)
    return st


@pytest.fixture
def cluster(lifecycle, tmp_path_factory):
    base = tmp_path_factory.mktemp("cns")
    data = base / "data"; data.mkdir()

    mgr = lifecycle.start(NginxInstanceSpec(
        name="lc-cns-manager",
        template="nginx_cns_manager.conf",
        protocol="root",
        readiness="tcp",
        reason="CNS manager (brix_cns collect) + CMS server port.",
    ))
    ds = lifecycle.start(NginxInstanceSpec(
        name="lc-cns-data",
        template="nginx_cns_data.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(data),
        template_values={"CMS_PORT": mgr.extra_ports["CMS_PORT"]},
        reason="CNS data server (brix_cns emit) CMS-linked to the manager.",
    ))

    # Let the data server's CMS link to the manager come up + log in.
    time.sleep(6)
    yield mgr.port, ds.port


@pytest.fixture
def cluster_async(lifecycle, tmp_path_factory):
    """Same 2-node cluster as ``cluster`` but the data server runs with
    ``brix_backend_async on`` — a kXR_rm/kXR_rmdir is enqueued on the durable
    queue and its reply + §6 CNS emit are delivered late by the queue waker.
    Serial with the sync cluster tests (reuses the manager's fixed port; the
    lifecycle harness stops each server at teardown)."""
    base = tmp_path_factory.mktemp("cns-async")
    data = base / "data"; data.mkdir()

    mgr = lifecycle.start(NginxInstanceSpec(
        name="lc-cns-manager",
        template="nginx_cns_manager.conf",
        protocol="root",
        readiness="tcp",
        reason="CNS manager for the backend-async data server.",
    ))
    ds = lifecycle.start(NginxInstanceSpec(
        name="lc-cns-data-async",
        template="nginx_cns_data_async.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(data),
        template_values={"CMS_PORT": mgr.extra_ports["CMS_PORT"]},
        reason="CNS data server with brix_backend_async on.",
    ))
    time.sleep(6)
    yield mgr.port, ds.port


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


def test_manager_reflects_rm_delete(cluster):
    """§6 DEL wire wrapper: a DS unlink removes the path from the manager CNS."""
    mgr_port, ds_port = cluster
    _write_file(ds_port, "/cns-del.dat", b"delete-me-payload")
    assert _poll_manager(mgr_port, "/cns-del.dat", want_ok=True) == kXR_ok

    st, body = _ns_remove(ds_port, kXR_rm, "/cns-del.dat")
    assert st == kXR_ok, ("rm", st, body)
    # DEL event must propagate: the manager stops answering the stat from CNS.
    assert _poll_manager(mgr_port, "/cns-del.dat", want_ok=False) != kXR_ok


def test_manager_reflects_mkdir_and_rmdir(cluster):
    """§6 MKDIR/RMDIR wire wrappers: a DS mkdir then rmdir round-trips the CNS."""
    mgr_port, ds_port = cluster
    st, body = _mkdir(ds_port, "/cns-dir")
    assert st == kXR_ok, ("mkdir", st, body)
    # MKDIR event must reach the manager inventory (dir becomes stat-able).
    assert _poll_manager(mgr_port, "/cns-dir", want_ok=True) == kXR_ok

    st, body = _ns_remove(ds_port, kXR_rmdir, "/cns-dir")
    assert st == kXR_ok, ("rmdir", st, body)
    # RMDIR event must drop it back out of the inventory.
    assert _poll_manager(mgr_port, "/cns-dir", want_ok=False) != kXR_ok


def test_manager_reflects_async_backend_rm_delete(cluster_async):
    """phase-58: with brix_backend_async ON, a DS unlink is enqueued on the
    durable queue and only runs at flush time — the §6 DEL event is emitted by
    the queue waker (baq_root_done), NOT the inline op_table path (which returned
    early). The manager must still stop answering the stat from CNS, proving the
    async removal path converges into the inventory."""
    mgr_port, ds_port = cluster_async
    _write_file(ds_port, "/cns-async-del.dat", b"async-delete-me-payload")
    assert _poll_manager(mgr_port, "/cns-async-del.dat", want_ok=True) == kXR_ok

    st, body = _ns_remove(ds_port, kXR_rm, "/cns-async-del.dat")
    assert st == kXR_ok, ("async rm", st, body)
    assert _poll_manager(mgr_port, "/cns-async-del.dat", want_ok=False) != kXR_ok


def test_manager_reflects_async_backend_rmdir(cluster_async):
    """phase-58: the durable-queue RMDIR path likewise emits its §6 RMDIR event
    from the queue waker on flush — a DS mkdir (inline) then an async rmdir
    round-trips the manager CNS inventory."""
    mgr_port, ds_port = cluster_async
    st, body = _mkdir(ds_port, "/cns-async-dir")
    assert st == kXR_ok, ("mkdir", st, body)
    assert _poll_manager(mgr_port, "/cns-async-dir", want_ok=True) == kXR_ok

    st, body = _ns_remove(ds_port, kXR_rmdir, "/cns-async-dir")
    assert st == kXR_ok, ("async rmdir", st, body)
    assert _poll_manager(mgr_port, "/cns-async-dir", want_ok=False) != kXR_ok

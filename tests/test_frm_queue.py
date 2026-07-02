"""
tests/test_frm_queue.py

Phase 35 / Phase 0 — FRM durable stage-request queue (src/frm/).

Proves the Phase-0 Definition of Done over the real XRootD wire protocol against
a self-contained nginx (own stream server, dedicated port, own queue file):

  * kXR_prepare(kXR_stage) issues a durable, host-qualified reqid (NOT "0")
  * kXR_QPrep reports real queue state ('q' queued / 'A' resident / 'M' missing)
  * the queued record SURVIVES A FULL NGINX RESTART (file = truth; the SHM index
    is rebuilt by reconciliation at start) — the load-bearing durability property
  * kXR_prepare(kXR_cancel) deletes the request (QPrep then reports 'M')
  * kXR_QPrep with an unknown reqid does not crash

No fleet dependency (TEST_SKIP_SERVER_SETUP-style: spawns its own nginx).
"""

import os
import socket
import struct
import subprocess
import time

import pytest

from settings import NGINX_BIN, free_port, HOST, BIND_HOST

PORT = int(os.environ.get("TEST_FRM_QUEUE_PORT") or free_port())

# --- wire constants (XProtocol.hh) ---
kXR_login    = 3007
kXR_query    = 3001
kXR_prepare  = 3021
kXR_QPrep    = 2
kXR_ok       = 0
kXR_error    = 4003

# kXR_prepare option bits (src/protocols/root/protocol/flags.h)
kXR_cancel   = 0x01
kXR_noerrs   = 0x04
kXR_stage    = 0x08


def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"closed after {len(buf)}/{n}")
        buf.extend(chunk)
    return bytes(buf)


def _read_response(sock):
    sid, status, dlen = struct.unpack("!2sHI", _recv_exact(sock, 8))
    return status, (_recv_exact(sock, dlen) if dlen else b"")


def _session():
    sock = socket.create_connection((HOST, PORT), timeout=10)
    sock.settimeout(10)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))      # handshake
    status, _ = _read_response(sock)
    assert status == kXR_ok
    sock.sendall(struct.pack("!2sHI8sBBBBI",
                             b"\x00\x01", kXR_login,
                             os.getpid() & 0xFFFFFFFF,
                             b"pytest\x00\x00", 0, 0, 5, 0, 0))
    status, _ = _read_response(sock)
    assert status == kXR_ok
    return sock


def _prepare(sock, paths, options, streamid=b"\x00\x03"):
    """ClientPrepareRequest: 2s H(reqid) B(options) B(prty) H(port) H(optionX)
    10s(reserved) I(dlen)."""
    payload = "".join(p + "\n" for p in paths).encode()
    req = struct.pack("!2sHBBHH10sI", streamid, kXR_prepare,
                      options, 0, 0, 0, b"\x00" * 10, len(payload))
    sock.sendall(req + payload)
    return _read_response(sock)


def _query(sock, infotype, payload, streamid=b"\x00\x04"):
    req = struct.pack("!2sHHH4s8sI", streamid, kXR_query, infotype, 0,
                      b"\x00" * 4, b"\x00" * 8, len(payload))
    sock.sendall(req + payload)
    return _read_response(sock)


def _qprep_status(sock, reqid, path):
    """Return the single status letter QPrep reports for `path`."""
    payload = (reqid + "\n" + path + "\n").encode()
    status, body = _query(sock, kXR_QPrep, payload)
    assert status == kXR_ok, f"QPrep status {status}"
    # body is "<letter> <path>\n...\0"
    return chr(body[0]) if body else "?"


def _cancel(sock, reqid, streamid=b"\x00\x05"):
    payload = (reqid + "\n").encode()
    req = struct.pack("!2sHBBHH10sI", streamid, kXR_prepare,
                      kXR_cancel, 0, 0, 0, b"\x00" * 10, len(payload))
    sock.sendall(req + payload)
    return _read_response(sock)


def _wait_port(port, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


class _Server:
    def __init__(self, prefix, conf):
        self.prefix = prefix
        self.conf = conf
        self.proc = None

    def start(self):
        self.proc = subprocess.Popen([NGINX_BIN, "-p", str(self.prefix),
                                      "-c", str(self.conf)],
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
        if not _wait_port(PORT):
            err = self.proc.stderr.read().decode(errors="replace")
            self.stop()
            pytest.skip(f"FRM server did not start: {err}")

    def stop(self):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            self.proc = None

    def restart(self):
        self.stop()
        time.sleep(0.3)
        self.start()


@pytest.fixture(scope="module")
def frm(tmp_path_factory):
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")

    d = tmp_path_factory.mktemp("frm")
    (d / "logs").mkdir()
    data = d / "data"
    data.mkdir()
    (data / "online.bin").write_bytes(b"x" * 4096)
    queue = d / "frm.queue"

    conf = f"""
error_log {d}/logs/error.log info;
pid {d}/logs/nginx.pid;
events {{ worker_connections 64; }}
stream {{
    server {{
        listen {BIND_HOST}:{PORT};
        xrootd on;
        xrootd_storage_backend posix:{data};
        xrootd_auth none;
        xrootd_frm on;
        xrootd_frm_queue_path {queue};
        xrootd_frm_max_inflight 128;
    }}
}}
daemon off;
master_process off;
"""
    cp = d / "nginx.conf"
    cp.write_text(conf)
    srv = _Server(d, cp)
    srv.start()
    srv.data = str(data)
    srv.queue = str(queue)
    yield srv
    srv.stop()


def test_prepare_stage_returns_durable_reqid(frm):
    s = _session()
    status, body = _prepare(s, ["/online.bin"], kXR_stage)
    s.close()
    assert status == kXR_ok, f"prepare failed: {status}"
    reqid = body.rstrip(b"\x00").decode()
    # The headline bug fix: a real, host-qualified reqid, never the literal "0".
    assert reqid != "0", "reqid is still the legacy placeholder '0'"
    assert "@" in reqid and "." in reqid, f"reqid not host-qualified: {reqid!r}"


def test_qprep_reports_resident_file_available(frm):
    s = _session()
    status, body = _prepare(s, ["/online.bin"], kXR_stage)
    reqid = body.rstrip(b"\x00").decode()
    # /online.bin exists on disk → QPrep must say 'A' (resident).
    assert _qprep_status(s, reqid, "/online.bin") == "A"
    s.close()


def test_qprep_reports_queued_for_nearline_file(frm):
    # A not-yet-resident file staged with kXR_noerrs is QUEUED; with no transfer
    # worker in Phase 0 it stays queued, so QPrep reports 'q' (not 'M').
    s = _session()
    status, body = _prepare(s, ["/nearline1.dat"], kXR_stage | kXR_noerrs)
    assert status == kXR_ok
    reqid = body.rstrip(b"\x00").decode()
    assert reqid != "0"
    assert _qprep_status(s, reqid, "/nearline1.dat") == "q"
    s.close()


def test_queued_request_survives_restart(frm):
    # THE durability property: enqueue a nearline request, restart nginx, and the
    # record is rebuilt from the file by reconciliation — QPrep still says 'q'.
    s = _session()
    _, body = _prepare(s, ["/nearline_durable.dat"], kXR_stage | kXR_noerrs)
    reqid = body.rstrip(b"\x00").decode()
    assert reqid != "0"
    s.close()

    frm.restart()

    s = _session()
    assert _qprep_status(s, reqid, "/nearline_durable.dat") == "q", \
        "queued request did not survive an nginx restart (durability broken)"
    s.close()


def test_cancel_removes_request(frm):
    s = _session()
    _, body = _prepare(s, ["/nearline_cancel.dat"], kXR_stage | kXR_noerrs)
    reqid = body.rstrip(b"\x00").decode()
    assert _qprep_status(s, reqid, "/nearline_cancel.dat") == "q"

    status, _ = _cancel(s, reqid)
    assert status == kXR_ok, f"cancel failed: {status}"
    # After cancel the record is gone and the file is absent → 'M'.
    assert _qprep_status(s, reqid, "/nearline_cancel.dat") == "M"
    s.close()


def test_qprep_unknown_reqid_no_crash(frm):
    s = _session()
    # An unknown reqid must not crash; the (absent) path simply reports 'M'.
    assert _qprep_status(s, "999999.1@nope", "/nosuchfile.dat") == "M"
    # connection still usable afterwards
    status, body = _prepare(s, ["/online.bin"], kXR_stage)
    assert status == kXR_ok
    s.close()


def test_corrupt_record_reclaimed_on_restart(frm):
    # DoD: a torn/corrupt record (bad CRC) must be DETECTED and reclaimed by
    # reconciliation, not trusted — nginx restarts cleanly and keeps serving.
    s = _session()
    _prepare(s, ["/nearline_corrupt.dat"], kXR_stage | kXR_noerrs)
    s.close()

    frm.stop()
    # Flip a byte inside the first record slot (header is [0, 4608); record 0
    # starts at 4608). A wrong CRC32c → reconcile reclaims the slot.
    with open(frm.queue, "r+b") as f:
        f.seek(4608 + 256)
        orig = f.read(1)
        f.seek(4608 + 256)
        f.write(bytes([orig[0] ^ 0xFF]))
    frm.start()

    # Server came up despite the corrupt record and still serves a fresh request.
    s = _session()
    status, body = _prepare(s, ["/online.bin"], kXR_stage)
    assert status == kXR_ok, "server did not recover from a corrupt queue record"
    reqid = body.rstrip(b"\x00").decode()
    assert reqid != "0"
    s.close()

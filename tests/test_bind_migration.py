"""§1.4 cross-worker kXR_bind secondary migration — reuseport + multi-worker.

With `listen ... reuseport` the kernel hashes each of a client's TCP
connections to a worker independently, so a secondary's kXR_bind routinely
lands on a different worker than the session's primary.  Response offloading
(§1.1) is per-event-loop, so before §1.4 a scattered bind silently fell back
to inline primary responses.  bind_migrate.c now hands the secondary's fd to
the session-owning worker (SCM_RIGHTS over a pre-fork SOCK_SEQPACKET channel),
which adopts the socket and completes the bind — so EVERY pathid-tagged read's
reply must arrive on the secondary, regardless of which worker accepted it.

Coverage (dedicated 2-worker reuseport instance — the shared fleet is 1-worker
and cannot scatter):

  * success  — 12 sequential (bind, tagged-read) rounds against one primary:
               every reply arrives on the secondary with byte-exact data, and
               brix_io_offload_total ends at 12.  Without migration a
               cross-worker bind's reply goes inline to the primary and the
               secondary read times out; P(all 12 binds land on the primary's
               worker by chance) = 2^-12 ≈ 0.02%.
  * error    — kXR_bind with an unknown sessid is refused (kXR_error) on the
               same scattered topology (owner lookup fails → local refusal).
  * security — a bound secondary remains a restricted data channel after
               migration: kXR_open on it is refused on every one of 8
               scattered secondaries.

Self-contained: launches one short-lived nginx (stream + /metrics), no shared
fleet / lifecycle harness — same profile as test_offload_metric.py.
"""

import os
import socket
import struct
import subprocess
import time
import urllib.request

import pytest

from settings import BIND_HOST, NGINX_BIN as H_NGINX
from metrics_helpers import value

import _test_session_bind_helpers as H
from ephemeral_port import free_port

OFFLOAD = "brix_io_offload_total"
STREAM = {"proto": "stream"}

NPAIRS = 12          # success rounds; false-pass odds without migration 2^-12
NSEC_SECURITY = 8    # scattered secondaries probed with kXR_open


def _free_port():
    """Lease a mock-range port and probe-bind it.  SO_REUSEADDR matches what
    nginx sets on its own listeners, so a lease recycled into TIME_WAIT by an
    earlier run of this very file still probes (and serves) fine; a port held
    by a live listener still fails and is skipped."""
    for _ in range(8):
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((BIND_HOST, free_port()))
            return s.getsockname()[1]
        except OSError:
            continue
        finally:
            s.close()
    pytest.fail("no bindable leased port after 8 attempts")


def _write_conf(tmp_path, stream_port, metrics_port):
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    logs = tmp_path / "logs"
    logs.mkdir(exist_ok=True)
    tmp = tmp_path / "tmp"
    tmp.mkdir(exist_ok=True)
    conf = tmp_path / "nginx.conf"
    conf.write_text(
        "daemon on;\n"
        "worker_processes 2;\n"
        f"pid {logs}/nginx.pid;\n"
        f"error_log {logs}/error.log info;\n"
        "events { worker_connections 64; }\n"
        "stream {\n"
        "  server {\n"
        f"    listen {BIND_HOST}:{stream_port} reuseport;\n"
        "    brix_root on;\n"
        f"    brix_export {data};\n"
        "    brix_auth none;\n"
        "    brix_allow_write on;\n"
        "    brix_data_substreams on;\n"
        "  }\n"
        "}\n"
        "http {\n"
        "  access_log off;\n"
        f"  client_body_temp_path {tmp}/cbt;\n"
        f"  proxy_temp_path {tmp}/pt;\n"
        f"  fastcgi_temp_path {tmp}/ft;\n"
        f"  uwsgi_temp_path {tmp}/ut;\n"
        f"  scgi_temp_path {tmp}/st;\n"
        "  server {\n"
        f"    listen {BIND_HOST}:{metrics_port};\n"
        "    location /metrics { brix_metrics on; }\n"
        "  }\n"
        "}\n")
    return conf, str(data)


def _nginx(*args, timeout=30):
    return subprocess.run([H_NGINX, *args], capture_output=True, text=True,
                          timeout=timeout)


def _scrape(port):
    with urllib.request.urlopen(f"http://{BIND_HOST}:{port}/metrics",
                                timeout=5) as resp:
        return resp.read().decode("utf-8", "replace")


def _launch(tmp_path):
    if not os.access(H_NGINX, os.X_OK):
        pytest.skip(f"nginx not executable: {H_NGINX}")
    sport, mport = _free_port(), _free_port()
    conf, data = _write_conf(tmp_path, sport, mport)
    t = _nginx("-p", str(tmp_path), "-c", str(conf), "-t")
    assert t.returncode == 0, f"config rejected: {t.stderr}"
    started = _nginx("-p", str(tmp_path), "-c", str(conf))
    assert started.returncode == 0, f"nginx failed to start: {started.stderr}"
    for _ in range(50):
        try:
            socket.create_connection((BIND_HOST, sport), timeout=0.5).close()
            break
        except OSError:
            time.sleep(0.1)
    return sport, mport, data, conf


def _stop(tmp_path, conf):
    _nginx("-p", str(tmp_path), "-c", str(conf), "-s", "quit")
    time.sleep(0.2)


def _bind_secondary(port, sessid):
    """Fresh connection + handshake + kXR_bind; returns (sock, pathid)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((BIND_HOST, port))
    sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    H._recv_exact(sock, 16)
    status, pathid_body = H._send_req(sock, b"\x00\x05", H.kXR_bind,
                                      body=sessid)
    return sock, status, pathid_body


def test_every_scattered_bind_offloads(tmp_path):
    """Success: on a 2-worker reuseport listener, every pathid-tagged read's
    reply arrives on its secondary — cross-worker binds included — and the
    offload counter accounts for all of them."""
    sport, mport, data_root, conf = _launch(tmp_path)
    H.ANON_HOST = BIND_HOST
    H.DATA_ROOT = data_root
    content = b"bind-migration-round!" * 97          # 2037 bytes, offloadable
    H._write_data_file("mig.bin", content)
    try:
        primary, sessid, stream = H._establish_primary(sport)
        primary.settimeout(10)
        fh = H._open_read(primary, stream, "/mig.bin")
        for i in range(NPAIRS):
            sec, status, pathid_body = _bind_secondary(sport, sessid)
            assert status == H.kXR_ok, f"round {i}: bind refused ({status})"
            pathid = pathid_body[0]
            assert 1 <= pathid <= 253, f"round {i}: bad pathid {pathid}"
            H._send_read_only(primary, bytes([0, 0x40 + i]), fh,
                              len(content), pathid)
            sec.settimeout(10)   # a timeout here = the reply went inline
            _, rstatus, rdata = H._recv_response(sec)
            assert rstatus in (H.kXR_ok, H.kXR_oksofar), \
                f"round {i}: secondary read status={rstatus}"
            assert rdata == content, f"round {i}: data mismatch"
            sec.close()
        primary.close()
        assert value(_scrape(mport), OFFLOAD, STREAM) == float(NPAIRS)
    finally:
        _stop(tmp_path, conf)


def test_unknown_sessid_bind_refused_scattered(tmp_path):
    """Error: an unknown sessid is refused wherever the bind lands (no owner
    to migrate to → local registry lookup → kXR_error), and the connection
    is not adopted anywhere."""
    sport, mport, data_root, conf = _launch(tmp_path)
    try:
        for _ in range(4):                    # land on both workers w.h.p.
            sec, status, _ = _bind_secondary(sport, os.urandom(16))
            assert status == H.kXR_error, \
                f"unknown-sessid bind not refused (status={status})"
            sec.close()
    finally:
        _stop(tmp_path, conf)


def test_migrated_secondary_stays_restricted(tmp_path):
    """Security: a bound secondary is a data channel, not a session — kXR_open
    on it must be refused on every scattered secondary (an adopted connection
    must inherit the same capability restriction as a locally-bound one)."""
    sport, mport, data_root, conf = _launch(tmp_path)
    H.ANON_HOST = BIND_HOST
    H.DATA_ROOT = data_root
    H._write_data_file("mig-sec.bin", b"restricted")
    try:
        primary, sessid, _ = H._establish_primary(sport)
        primary.settimeout(10)
        secs = []
        for i in range(NSEC_SECURITY):
            sec, status, _ = _bind_secondary(sport, sessid)
            assert status == H.kXR_ok, f"secondary {i}: bind refused"
            secs.append(sec)
        open_body = struct.pack(">HH", 0o644, H.kXR_open_read) + b"\x00" * 12
        for i, sec in enumerate(secs):
            status, _ = H._send_req(sec, b"\x00\x06", H.kXR_open,
                                    body=open_body,
                                    payload=b"/mig-sec.bin\x00")
            assert status == H.kXR_error, \
                f"secondary {i}: bound stream unexpectedly opened a file"
            sec.close()
        primary.close()
    finally:
        _stop(tmp_path, conf)

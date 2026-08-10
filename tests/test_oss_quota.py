"""brix_oss_quota — configurable kXR_Qspace oss.quota advertisement (parity audit §3.1).

The kXR_Qspace report used to hardcode ``oss.quota=-1``. ``brix_oss_quota <size>``
now advertises the site's configured space quota, so accounting tools that read
``xrdfs query space`` see the same number a stock server would report. The default
stays -1 (unlimited), byte-identical to before. Advertisement ONLY — BriX does not
itself enforce the quota (enforcement stays the larger §3.1 space-groups feature).

Coverage (the change-class trio):
  * success   — brix_oss_quota 5G: the Qspace body reads oss.quota=5368709120;
                the other oss.* keys stay present and well-formed.
  * default   — no directive: oss.quota=-1 (stock parity, unchanged).
  * error/neg — a malformed size fails nginx -t (config refused).

Self-contained: each wire case launches its own short-lived nginx on a free port
(no shared fleet / lifecycle harness), so it runs under a plain
``PYTHONPATH=tests pytest tests/test_oss_quota.py``.
"""

import os
import socket
import struct
import subprocess
import time

import pytest

from settings import BIND_HOST, NGINX_BIN

kXR_login, kXR_query = 3007, 3001
kXR_Qspace = 5
kXR_ok = 0


def _free_port():
    s = socket.socket()
    s.bind((BIND_HOST, 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _write_conf(tmp_path, quota_line, port):
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    logs = tmp_path / "logs"
    logs.mkdir(exist_ok=True)
    conf = tmp_path / "nginx.conf"
    conf.write_text(
        "worker_processes 1;\n"
        f"pid {logs}/nginx.pid;\n"
        f"error_log {logs}/error.log info;\n"
        "daemon on;\n"
        "events { worker_connections 32; }\n"
        "stream {\n"
        "  server {\n"
        f"    listen {BIND_HOST}:{port};\n"
        "    brix_root on;\n"
        f"    brix_storage_backend posix:{data};\n"
        "    brix_auth none;\n"
        f"    {quota_line}\n"
        "  }\n"
        "}\n")
    return conf


def _nginx(*args, timeout=30):
    return subprocess.run([NGINX_BIN, *args], capture_output=True, text=True,
                          timeout=timeout)


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _resp(sock):
    hdr = _recv_exact(sock, 8)
    assert hdr is not None, "connection closed mid-response"
    status = struct.unpack("!H", hdr[2:4])[0]
    dlen = struct.unpack("!I", hdr[4:8])[0]
    return status, ((_recv_exact(sock, dlen) or b"") if dlen else b"")


def _qspace(port, path="/"):
    """One kXR_query/kXR_Qspace round-trip; returns the oss.* report text."""
    sock = socket.create_connection((BIND_HOST, port), timeout=15)
    try:
        sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
        status, _ = _resp(sock)
        assert status == kXR_ok, "handshake failed"
        sock.sendall(struct.pack("!2sHI8sBBBBI", b"\x00\x01", kXR_login,
                                 0x7FFFFFFF & 12345, b"anon\x00\x00\x00\x00",
                                 0, 0, 0, 0, 0))
        status, _ = _resp(sock)
        assert status == kXR_ok, "anon login failed"
        arg = path.encode()
        sock.sendall(struct.pack("!2sHH14sI", b"\x00\x07", kXR_query,
                                 kXR_Qspace, b"\x00" * 14, len(arg)) + arg)
        status, body = _resp(sock)
        assert status == kXR_ok, f"Qspace not ok: {status}"
        return body.split(b"\x00", 1)[0].decode("latin-1")
    finally:
        sock.close()


def _report(tmp_path, quota_line):
    """Launch a short-lived nginx with `quota_line`, return its Qspace report."""
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    port = _free_port()
    conf = _write_conf(tmp_path, quota_line, port)
    t = _nginx("-p", str(tmp_path), "-c", str(conf), "-t")
    assert t.returncode == 0, f"config rejected: {t.stderr}"
    started = _nginx("-p", str(tmp_path), "-c", str(conf))
    assert started.returncode == 0, f"nginx failed to start: {started.stderr}"
    try:
        for _ in range(50):
            try:
                socket.create_connection((BIND_HOST, port), timeout=0.5).close()
                break
            except OSError:
                time.sleep(0.1)
        return _qspace(port)
    finally:
        _nginx("-p", str(tmp_path), "-c", str(conf), "-s", "quit")
        time.sleep(0.2)


def test_configured_quota_reported(tmp_path):
    """(success) the configured quota is what oss.quota advertises (5G = the byte
    count), and the other oss.* keys remain present."""
    report = _report(tmp_path, "brix_oss_quota 5G;")
    assert "oss.quota=5368709120" in report, report
    for key in ("oss.cgroup=", "oss.space=", "oss.free=", "oss.used="):
        assert key in report, f"{key} missing from report: {report}"
    assert report.count("oss.quota=") == 1, report


def test_default_quota_is_unlimited(tmp_path):
    """(default) no directive: oss.quota is still -1 (unlimited), unchanged."""
    report = _report(tmp_path, "")
    assert "oss.quota=-1" in report, report


def test_malformed_size_refused(tmp_path):
    """(error/neg) a malformed size fails nginx -t, so a bad quota can never
    reach the wire report."""
    port = _free_port()
    conf = _write_conf(tmp_path, "brix_oss_quota notasize;", port)
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    proc = _nginx("-p", str(tmp_path), "-c", str(conf), "-t")
    assert proc.returncode != 0, "a malformed brix_oss_quota size was accepted"
    assert "brix_oss_quota" in proc.stderr, proc.stderr

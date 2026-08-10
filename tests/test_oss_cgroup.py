"""brix_oss_cgroup — configurable kXR_Qspace space-group name (parity audit §3.2).

The kXR_Qspace report used to hardcode ``oss.cgroup=default``. ``brix_oss_cgroup
<name>`` now sets the space-group name a site advertises (accounting tools key
on it); default stays "default", byte-identical to before. The config setter
rejects a name carrying a CGI-structural byte (& = space / control) so the
name can never break the "&"-joined oss.* grammar or inject a second key.

Coverage (the change-class trio):
  * success      — brix_oss_cgroup mygroup: the Qspace body reads
                   "oss.cgroup=mygroup"; the other oss.* keys (space/free/
                   used/quota) are still present and well-formed.
  * error        — the default (no directive) still reports
                   "oss.cgroup=default".
  * security-neg — a name with a '&' fails nginx -t (config refused), so a
                   hostile group name can never smuggle a second oss.* key
                   like "x&oss.quota=0" into the report.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_oss_cgroup.py -v
"""

import os
import socket
import struct
import subprocess

import pytest

from settings import HOST, BIND_HOST, NGINX_BIN
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.timeout(120), pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-oss-cgroup")]

kXR_login, kXR_query = 3007, 3001
kXR_Qspace = 5
kXR_ok = 0


def _start(lifecycle, tmp_path, cgroup_line):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-oss-cgroup",
        template="nginx_lc_oss_cgroup.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": str(data),
                         "CGROUP_LINE": cgroup_line},
        reason="brix_oss_cgroup Qspace reporting"))
    return ep.port


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
    return status, (_recv_exact(sock, dlen) or b"") if dlen else b""


def _qspace(port, path="/"):
    """One kXR_query/kXR_Qspace round-trip; returns the report text."""
    sock = socket.create_connection((HOST, port), timeout=15)
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


def test_configured_cgroup_reported(lifecycle, tmp_path):
    """(success) the configured group name is what oss.cgroup reports, and the
    other oss.* keys remain present and well-formed."""
    port = _start(lifecycle, tmp_path, "brix_oss_cgroup mygroup;")
    report = _qspace(port)
    assert "oss.cgroup=mygroup" in report, report
    for key in ("oss.space=", "oss.free=", "oss.used=", "oss.quota="):
        assert key in report, f"{key} missing from report: {report}"
    # Exactly one cgroup key — no injected duplicate.
    assert report.count("oss.cgroup=") == 1, report


def test_default_is_default(lifecycle, tmp_path):
    """(error-path/default) no directive: oss.cgroup is still 'default'."""
    port = _start(lifecycle, tmp_path, "")
    report = _qspace(port)
    assert "oss.cgroup=default" in report, report


def test_cgi_structural_name_refused(tmp_path):
    """(security-neg) a group name carrying '&' fails nginx -t, so a name can
    never smuggle a second oss.* key into the report."""
    data = tmp_path / "data"
    data.mkdir()
    conf = tmp_path / "bad.conf"
    conf.write_text(
        "events { worker_connections 16; }\n"
        "stream {\n"
        "  server {\n"
        f"    listen {BIND_HOST}:1; \n"
        "    brix_root on;\n"
        f"    brix_storage_backend posix:{data};\n"
        "    brix_auth none;\n"
        "    brix_oss_cgroup \"evil&oss.quota=0\";\n"
        "  }\n"
        "}\n")
    proc = subprocess.run([NGINX_BIN, "-t", "-c", str(conf)],
                          capture_output=True, text=True, timeout=30)
    assert proc.returncode != 0, "a '&'-bearing cgroup name was accepted"
    assert "brix_oss_cgroup" in proc.stderr, proc.stderr

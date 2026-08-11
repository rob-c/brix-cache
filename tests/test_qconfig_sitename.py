"""kXR_Qconfig `sitename` key + the brix_sitename directive — parity audit §2.18.

Stock `xrdfs query config sitename` returns all.sitename — the human-readable
site/node identity monitoring and federation tooling use to label a server.
BriX previously had no way to set a sitename at all (the advertise.sitename
field existed but no directive wired it — the whole brix_cache_advertise family
is unreachable), and Qconfig fell through to echoing the literal key. This adds:

  * the `brix_sitename <name>` directive (populates the advertise.sitename slot,
    which the Pelican advertiser already reads once that feature is wired), and
  * a Qconfig `sitename` emitter that reports it — or echoes the key when unset,
    byte-identical to the pre-existing default branch (zero regression).

Coverage: configured ⇒ the name; unset ⇒ the key echo; the directive is accepted
by `nginx -t`. Self-contained (no shared fleet).
"""

import os
import socket
import struct
import subprocess
import time

import pytest

from settings import BIND_HOST, NGINX_BIN

import _test_session_bind_helpers as H

kXR_query = 3001
kXR_Qconfig = 7
kXR_QStats = 1


def _free_port():
    s = socket.socket()
    s.bind((BIND_HOST, 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _write_conf(tmp_path, extra):
    ns = tmp_path / "ns"
    ns.mkdir(exist_ok=True)
    logs = tmp_path / "logs"
    logs.mkdir(exist_ok=True)
    port = _free_port()
    conf = tmp_path / "nginx.conf"
    conf.write_text(
        "daemon on;\nworker_processes 1;\n"
        f"pid {logs}/nginx.pid;\nerror_log {logs}/error.log info;\n"
        "events { worker_connections 64; }\n"
        "stream {\n  server {\n"
        f"    listen {BIND_HOST}:{port};\n"
        "    brix_root on;\n"
        f"    brix_export {ns};\n"
        "    brix_auth none;\n"
        f"    {extra}\n"
        "  }\n}\n")
    return port, conf


def _launch(tmp_path, extra):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    port, conf = _write_conf(tmp_path, extra)
    t = subprocess.run([NGINX_BIN, "-p", str(tmp_path), "-c", str(conf), "-t"],
                       capture_output=True, text=True, timeout=30)
    assert t.returncode == 0, f"config rejected: {t.stderr}"
    r = subprocess.run([NGINX_BIN, "-p", str(tmp_path), "-c", str(conf)],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, f"nginx failed to start: {r.stderr}"
    for _ in range(50):
        try:
            socket.create_connection((BIND_HOST, port), timeout=0.5).close()
            break
        except OSError:
            time.sleep(0.1)
    return port, conf


def _stop(tmp_path, conf):
    subprocess.run([NGINX_BIN, "-p", str(tmp_path), "-c", str(conf),
                    "-s", "quit"], capture_output=True, timeout=30)
    time.sleep(0.2)


def _qconfig(port, key):
    """Send kXR_query(kXR_Qconfig, key); return the value bytes (NUL/newline
    stripped). ClientQueryRequest body: infotype[2] then reserved; payload=key."""
    H.ANON_HOST = BIND_HOST
    sock, sessid, stream = H._establish_primary(port)
    try:
        body = struct.pack(">H", kXR_Qconfig) + b"\x00" * 14
        status, resp = H._send_req(sock, stream, kXR_query, body=body,
                                   payload=key)
        assert status == H.kXR_ok, f"Qconfig failed: {status}"
        return resp.split(b"\x00", 1)[0].rstrip(b"\n")
    finally:
        sock.close()


def test_sitename_reported_when_configured(tmp_path):
    """(success) brix_sitename set ⇒ Qconfig sitename returns that exact name."""
    port, conf = _launch(tmp_path, "brix_sitename BriX-Test-Site;")
    try:
        assert _qconfig(port, b"sitename") == b"BriX-Test-Site"
        # A neighbouring key still works — proves we didn't corrupt the table.
        assert _qconfig(port, b"version").startswith(b"v")
    finally:
        _stop(tmp_path, conf)


def test_sitename_echoes_key_when_unset(tmp_path):
    """(regression) no brix_sitename ⇒ the key echo, byte-identical to before."""
    port, conf = _launch(tmp_path, "")   # no brix_sitename configured
    try:
        assert _qconfig(port, b"sitename") == b"sitename"
    finally:
        _stop(tmp_path, conf)


def _qstats_site(port):
    """kXR_query(kXR_QStats) → the site="…" attribute of the <statistics> XML."""
    import re
    H.ANON_HOST = BIND_HOST
    sock, sessid, stream = H._establish_primary(port)
    try:
        body = struct.pack(">H", kXR_QStats) + b"\x00" * 14
        status, resp = H._send_req(sock, stream, kXR_query, body=body,
                                   payload=b"a")
        assert status == H.kXR_ok, f"QStats failed: {status}"
        m = re.search(rb'site="([^"]*)"', resp)
        assert m is not None, f"no site= attribute in {resp[:120]!r}"
        return m.group(1)
    finally:
        sock.close()


def test_qstats_site_attribute_reports_sitename(tmp_path):
    """(success) the summary-monitoring <statistics site="…"> attribute — read by
    federation dashboards — now carries brix_sitename instead of empty."""
    port, conf = _launch(tmp_path, "brix_sitename Mon-Site-7;")
    try:
        assert _qstats_site(port) == b"Mon-Site-7"
    finally:
        _stop(tmp_path, conf)


def test_qstats_site_empty_when_unset(tmp_path):
    """(regression) unset ⇒ site="" (empty), byte-identical to before."""
    port, conf = _launch(tmp_path, "")
    try:
        assert _qstats_site(port) == b""
    finally:
        _stop(tmp_path, conf)


def test_directive_accepted_by_config_test(tmp_path):
    """(config) brix_sitename passes `nginx -t` (the directive is registered)."""
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip("nginx not executable")
    _port, conf = _write_conf(tmp_path, "brix_sitename Some-Site;")
    r = subprocess.run([NGINX_BIN, "-p", str(tmp_path), "-c", str(conf), "-t"],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, f"brix_sitename rejected by -t: {r.stderr}"
    assert "unknown directive" not in r.stderr

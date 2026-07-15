"""
test_pmark.py — SciTags packet marking (phase-34) end-to-end firefly tests.

Self-contained: spins up the built nginx binary with a minimal WebDAV + pmark
config, points the firefly collector at a local UDP listener, drives requests
with curl, and asserts on the captured firefly JSON.  Skips cleanly when the
nginx binary or curl is unavailable (e.g. a host that hasn't built the module).

Covers the three contract tests for this feature:
  * success         — a marked GET emits start + end firefly with the right codes
  * defsfile/map    — named experiment/activity resolve via the scitags registry
  * security-neg    — an out-of-range scitag.flow is ignored (no marking)
"""

import json
import os
import shutil
import socket
import subprocess
import time

import pytest

from config_templates import render_config
from settings import free_port, HOST, BIND_HOST

NGINX_BIN = os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
FF_PORT = int(os.environ.get("TEST_PMARK_FF_PORT") or free_port())
HTTP_PORT = int(os.environ.get("TEST_PMARK_HTTP_PORT") or free_port())


pytestmark = pytest.mark.skipif(
    not os.path.exists(NGINX_BIN) or shutil.which("curl") is None,
    reason="nginx binary (set NGINX_BIN) or curl not available",
)


class FireflyCapture:
    """Background UDP collector that records firefly datagrams as parsed JSON."""

    def __init__(self, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((BIND_HOST, port))
        self.sock.settimeout(0.3)

    def drain(self, settle=1.2):
        """Collect datagrams until the socket is quiet for `settle` seconds."""
        out = []
        deadline = time.time() + settle
        while time.time() < deadline:
            try:
                data, _ = self.sock.recvfrom(8192)
            except socket.timeout:
                continue
            text = data.decode("utf-8", "replace")
            brace = text.find("{")
            if brace >= 0:
                try:
                    out.append(json.loads(text[brace:]))
                    deadline = time.time() + settle
                except json.JSONDecodeError:
                    pass
        return out

    def close(self):
        self.sock.close()


def _write_conf(tmp_path, extra_loc):
    root = tmp_path / "data"
    root.mkdir()
    (root / "file.txt").write_text("hello-scitags-payload\n")
    conf = tmp_path / "nginx.conf"
    conf.write_text(render_config(
        "nginx_pmark_self.conf",
        BIND_HOST=BIND_HOST,
        PORT=HTTP_PORT,
        DATA_DIR=root,
        FIREFLY_HOST=HOST,
        FIREFLY_PORT=FF_PORT,
        EXTRA_LOCATION=extra_loc,
    ))
    (tmp_path / "logs").mkdir()
    return conf


def _nginx(conf, tmp_path, *args):
    return subprocess.run(
        [NGINX_BIN, "-p", str(tmp_path), "-c", str(conf), *args],
        capture_output=True, text=True, timeout=20,
    )


def _port_listening(port, timeout=0.3):
    try:
        with socket.create_connection((HOST, port), timeout=timeout):
            return True
    except OSError:
        return False


def _serve(conf, tmp_path):
    assert _nginx(conf, tmp_path, "-t").returncode == 0
    assert _nginx(conf, tmp_path).returncode == 0
    # Poll for the listener instead of a fixed 0.5s sleep. Under the -n8 fast
    # lane, a freshly forked nginx worker can take well over half a second to
    # start accepting; firing the curl before then produced NO firefly datagrams
    # ("assert 'start' in []"). Wait for a real TCP connect (up to ~15s) so the
    # request always reaches a ready server.
    deadline = time.time() + 15
    while time.time() < deadline:
        if _port_listening(HTTP_PORT):
            return
        time.sleep(0.05)
    raise AssertionError(f"pmark nginx did not begin listening on {HTTP_PORT}")


def _stop(conf, tmp_path):
    _nginx(conf, tmp_path, "-s", "stop")
    # Wait for the port to actually free so the next test's bind can't collide
    # with a still-shutting-down worker under load (instead of a fixed sleep).
    deadline = time.time() + 10
    while time.time() < deadline:
        if not _port_listening(HTTP_PORT, timeout=0.1):
            return
        time.sleep(0.05)


def test_firefly_scitag_override(tmp_path):
    """scitag.flow=129 → experiment 2, activity 1; start + end datagrams."""
    cap = FireflyCapture(FF_PORT)
    conf = _write_conf(tmp_path, "      brix_pmark_scitag_cgi on;\n"
                                 "      brix_pmark_appname pmark-test;\n")
    try:
        _serve(conf, tmp_path)
        subprocess.run(
            ["curl", "-s", f"http://{HOST}:{HTTP_PORT}/file.txt?scitag.flow=129",
             "-o", "/dev/null"], timeout=10)
        flies = cap.drain()
    finally:
        _stop(conf, tmp_path)
        cap.close()

    states = [f["flow-lifecycle"]["state"] for f in flies]
    assert "start" in states and "end" in states
    for f in flies:
        assert f["context"]["experiment-id"] == 2   # 129 >> 6
        assert f["context"]["activity-id"] == 1      # 129 & 0x3f
        assert f["context"]["application"] == "pmark-test"
        assert f["flow-id"]["protocol"] == "tcp"
    end = [f for f in flies if f["flow-lifecycle"]["state"] == "end"][0]
    assert "end-time" in end["flow-lifecycle"]
    assert end["usage"]["sent"] > 0                  # TCP_INFO byte counts present


def test_firefly_defsfile_mapping(tmp_path):
    """No scitag → default experiment + default activity resolved via defsfile."""
    defs = tmp_path / "scitags.json"
    defs.write_text(json.dumps({
        "version": 1,
        "experiments": [
            {"expName": "atlas", "expId": 2, "activities": [
                {"activityName": "default", "activityId": 1},
                {"activityName": "write", "activityId": 5}]},
        ],
    }))
    cap = FireflyCapture(FF_PORT)
    conf = _write_conf(tmp_path,
                       f"      brix_pmark_defsfile {defs};\n"
                       "      brix_pmark_map_experiment default atlas;\n"
                       "      brix_pmark_map_activity atlas default write;\n")
    try:
        _serve(conf, tmp_path)
        subprocess.run(
            ["curl", "-s", f"http://{HOST}:{HTTP_PORT}/file.txt", "-o", "/dev/null"],
            timeout=10)
        flies = cap.drain()
    finally:
        _stop(conf, tmp_path)
        cap.close()

    assert flies, "expected firefly datagrams for the default-mapped flow"
    for f in flies:
        assert f["context"]["experiment-id"] == 2    # default → atlas
        assert f["context"]["activity-id"] == 5       # atlas default activity "write"


def test_firefly_out_of_range_scitag_ignored(tmp_path):
    """scitag.flow=70000 is out of [65,65535] → flow is NOT marked (no datagram)."""
    cap = FireflyCapture(FF_PORT)
    # No defsfile / mappings: the only marking source is the (bad) client scitag.
    conf = _write_conf(tmp_path, "      brix_pmark_scitag_cgi on;\n")
    try:
        _serve(conf, tmp_path)
        rc = subprocess.run(
            ["curl", "-s", f"http://{HOST}:{HTTP_PORT}/file.txt?scitag.flow=70000",
             "-o", "/dev/null", "-w", "%{http_code}"], capture_output=True, text=True,
            timeout=10)
        flies = cap.drain(settle=0.8)
    finally:
        _stop(conf, tmp_path)
        cap.close()

    assert rc.stdout.strip() == "200"      # transfer succeeds (fail-open)
    assert flies == []                     # but nothing was marked

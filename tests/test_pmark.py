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

from settings import BIND_HOST, HOST, NGINX_BIN
from server_registry import NginxInstanceSpec
from ephemeral_port import free_port          # firefly UDP sink (in-process mock)
from fleet_lifecycle_ports import PARSE_PLACEHOLDER_PORT

FF_PORT = int(os.environ.get("TEST_PMARK_FF_PORT") or free_port())


pytestmark = [
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.skipif(
        not os.path.exists(NGINX_BIN) or shutil.which("curl") is None,
        reason="nginx binary (set NGINX_BIN) or curl not available",
    ),
    pytest.mark.xdist_group("lc-pmark"),
]


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


def _serve(lifecycle, tmp_path, extra_loc):
    """Launch a pmark WebDAV server through the registry lifecycle harness and
    return its ServerEndpoint. The data dir is seeded under tmp_path so file.txt
    exists at config-parse time."""
    root = tmp_path / "data"
    root.mkdir()
    (root / "file.txt").write_text("hello-scitags-payload\n")
    return lifecycle.start(NginxInstanceSpec(
        name="lc-pmark",
        template="nginx_lc_pmark.conf",
        protocol="webdav",
        template_values={
            "BIND_HOST": BIND_HOST,
            "DATA_DIR": str(root),
            "FIREFLY_HOST": HOST,
            "FIREFLY_PORT": FF_PORT,
            "EXTRA_LOCATION": extra_loc,
        },
        reason="SciTags packet-marking firefly emission over WebDAV"))


def test_firefly_scitag_override(lifecycle, tmp_path):
    """scitag.flow=129 → experiment 2, activity 1; start + end datagrams."""
    cap = FireflyCapture(FF_PORT)
    ep = _serve(lifecycle, tmp_path,
                "      brix_pmark_scitag_cgi on;\n"
                "      brix_pmark_appname pmark-test;\n")
    try:
        subprocess.run(
            ["curl", "-s", f"http://{HOST}:{ep.port}/file.txt?scitag.flow=129",
             "-o", "/dev/null"], timeout=10)
        flies = cap.drain()
    finally:
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


def test_firefly_defsfile_mapping(lifecycle, tmp_path):
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
    ep = _serve(lifecycle, tmp_path,
                f"      brix_pmark_defsfile {defs};\n"
                "      brix_pmark_map_experiment default atlas;\n"
                "      brix_pmark_map_activity atlas default write;\n")
    try:
        subprocess.run(
            ["curl", "-s", f"http://{HOST}:{ep.port}/file.txt", "-o", "/dev/null"],
            timeout=10)
        flies = cap.drain()
    finally:
        cap.close()

    assert flies, "expected firefly datagrams for the default-mapped flow"
    for f in flies:
        assert f["context"]["experiment-id"] == 2    # default → atlas
        assert f["context"]["activity-id"] == 5       # atlas default activity "write"


def test_firefly_out_of_range_scitag_ignored(lifecycle, tmp_path):
    """scitag.flow=70000 is out of [65,65535] → flow is NOT marked (no datagram)."""
    cap = FireflyCapture(FF_PORT)
    # No defsfile / mappings: the only marking source is the (bad) client scitag.
    ep = _serve(lifecycle, tmp_path, "      brix_pmark_scitag_cgi on;\n")
    try:
        rc = subprocess.run(
            ["curl", "-s", f"http://{HOST}:{ep.port}/file.txt?scitag.flow=70000",
             "-o", "/dev/null", "-w", "%{http_code}"], capture_output=True, text=True,
            timeout=10)
        flies = cap.drain(settle=0.8)
    finally:
        cap.close()

    assert rc.stdout.strip() == "200"      # transfer succeeds (fail-open)
    assert flies == []                     # but nothing was marked


# --------------------------------------------------------------------------- #
# phase-34 ffecho: config-time minimum-interval clamp (XRootD parity — stock  #
# pmark enforces a 30s floor on the ongoing-flow refresh).                    #
# --------------------------------------------------------------------------- #
def _echo_conf(tmp_path, echo_directive):
    """Minimal stream root:// server carrying one brix_pmark_echo directive."""
    (tmp_path / "logs").mkdir(exist_ok=True)
    root = tmp_path / "data"
    root.mkdir(exist_ok=True)
    conf = tmp_path / "nginx.conf"
    conf.write_text(
        f"""daemon off; error_log {tmp_path / 'logs' / 'e.log'} info; pid {tmp_path / 'nginx.pid'};
thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{ server {{
    listen {BIND_HOST}:{PARSE_PLACEHOLDER_PORT}; brix_root on; brix_auth none;
    brix_storage_backend posix:{root};
    brix_pmark on; {echo_directive}
}} }}
""",
        encoding="utf-8",
    )
    return conf


def _nginx_t(conf):
    r = subprocess.run(
        [NGINX_BIN, "-p", str(conf.parent), "-c", str(conf), "-t"],
        capture_output=True, text=True, timeout=30)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def test_pmark_echo_below_min_clamped_with_warning(tmp_path):
    """5s is below the 30s floor: config still loads, but warns + raises."""
    rc, out = _nginx_t(_echo_conf(tmp_path, "brix_pmark_echo 5s;"))
    assert rc == 0, out
    assert "below the 30s minimum" in out, out


def test_pmark_echo_at_min_accepted_silently(tmp_path):
    """45s satisfies the floor — no clamp warning."""
    rc, out = _nginx_t(_echo_conf(tmp_path, "brix_pmark_echo 45s;"))
    assert rc == 0, out
    assert "below the 30s minimum" not in out, out


def test_pmark_echo_off_no_warning(tmp_path):
    """0 = one-shot only (echo disabled) must not trip the clamp."""
    rc, out = _nginx_t(_echo_conf(tmp_path, "brix_pmark_echo 0;"))
    assert rc == 0, out
    assert "below the 30s minimum" not in out, out

"""test_pmark_s3.py — phase-101 W1: SciTags packet marking on the S3 protocol.

The bug this pins: the ``brix_pmark*`` family used to be hand-copied into BOTH the
webdav and s3 HTTP command tables. nginx is first-module-wins and webdav precedes
s3 in module order, so every ``brix_pmark*`` in any HTTP context was handled by
webdav's entry and S3's identical entries were dead code — a ``brix_pmark on`` in
an S3 location wrote the *webdav* module's conf while the S3 request path read its
own untouched conf, making SciTags marking on S3 traffic a silent no-op with no
config-time diagnostic possible.

W1 moved the family to the shared ``ngx_http_brix_common_module`` (registered once
for the whole HTTP plane, at server/http scope too) and adopts it into each
protocol conf via ``brix_shared_adopt_unified()``. These tests drive real S3
requests through a pmark-enabled S3 server and assert firefly datagrams appear —
which they could not before the fix.

Coverage (the change-class trio):
  * success       — an S3 GET/PUT with pmark on emits firefly datagrams; both at
                    location scope AND at server{} scope (a capability that was
                    impossible when the family was loc-only on webdav).
  * error         — ``brix_pmark_domain bogus`` fails ``nginx -t`` with the custom
                    setter's message, proving it moved verbatim.
  * security-neg  — pmark OFF (the default) on an S3 server emits NOTHING, pinning
                    both the default and that adopt-at-merge does not leak an
                    enable in from elsewhere.

The firefly UDP collector and lifecycle pattern mirror test_pmark.py (WebDAV).
"""
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import uuid

import pytest

from settings import BIND_HOST, HOST, NGINX_BIN
from server_registry import NginxInstanceSpec
from ephemeral_port import free_port

try:
    import requests
    _HAVE_REQUESTS = True
except Exception:                       # noqa: BLE001
    _HAVE_REQUESTS = False

# One UDP sink port for the module (mirrors test_pmark.py).
FF_PORT = int(os.environ.get("TEST_PMARK_S3_FF_PORT") or free_port())

pytestmark = [
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.skipif(
        not os.path.exists(NGINX_BIN) or not _HAVE_REQUESTS,
        reason="nginx binary (set NGINX_BIN) or python-requests not available",
    ),
    pytest.mark.xdist_group("lc-pmark-s3"),
]


class FireflyCapture:
    """Background UDP collector that records firefly datagrams as parsed JSON.

    Identical contract to test_pmark.py's collector: bind the sink, drain until
    the socket is quiet for `settle` seconds, return the parsed JSON objects."""

    def __init__(self, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((BIND_HOST, port))
        self.sock.settimeout(0.3)

    def drain(self, settle=1.2):
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


def _serve_s3(lifecycle, tmp_path, *, pmark_server="", pmark_loc=""):
    """Launch a pmark-capable S3 server through the lifecycle harness. The S3
    endpoint is anonymous/unsigned (no access_key), so a plain requests call is a
    valid S3 request — matching test_s3.py."""
    root = tmp_path / "data"
    root.mkdir(exist_ok=True)
    return lifecycle.start(NginxInstanceSpec(
        name="lc-pmark-s3",
        template="nginx_lc_pmark_s3.conf",
        protocol="s3",
        template_values={
            "BIND_HOST": BIND_HOST,
            "DATA_DIR": str(root),
            "FIREFLY_HOST": HOST,
            "FIREFLY_PORT": FF_PORT,
            "PMARK_SERVER": pmark_server,
            "PMARK_LOC": pmark_loc,
        },
        reason="phase-101 W1: SciTags firefly emission over S3"))


# A concrete SciTags code so a flow actually maps (129 = experiment 2, activity 1):
# without a scitag/defsfile mapping the flow is "not marked" and no firefly is sent
# (brix_pmark_flow_begin bails) — exactly as for the WebDAV firefly tests.
_SCITAG = "scitag.flow=129"


def _s3_put_get(port, key, payload, *, scitag=True):
    """PUT then GET an object on the anonymous S3 endpoint. With scitag=True the
    GET carries a scitag.flow so the flow maps and (if pmark is on) marks."""
    base = f"http://{HOST}:{port}/testbucket/{key}"
    requests.put(base, data=payload, timeout=10)
    q = f"?{_SCITAG}" if scitag else ""
    requests.get(f"{base}{q}", timeout=10)


# --------------------------------------------------------------------------- #
# 1) SUCCESS — pmark at the S3 LOCATION marks S3 traffic (the core W1 fix)
# --------------------------------------------------------------------------- #
def test_s3_pmark_location_emits_firefly(lifecycle, tmp_path):
    cap = FireflyCapture(FF_PORT)
    ep = _serve_s3(lifecycle, tmp_path, pmark_loc=(
        "            brix_pmark on;\n"
        "            brix_pmark_http_plain on;\n"
        "            brix_pmark_firefly on;\n"
        "            brix_pmark_scitag_cgi on;\n"
        "            brix_pmark_appname s3-w1;\n"))
    try:
        _s3_put_get(ep.port, f"obj_{uuid.uuid4().hex}", b"scitags-over-s3\n")
        flies = cap.drain()
    finally:
        cap.close()
    assert flies, (
        "S3 pmark emitted NO firefly — the W1 bug (S3 pmark table was dead) is "
        "back: brix_pmark on in an S3 location is not reaching the S3 conf")
    for f in flies:
        assert f["context"]["application"] == "s3-w1"
        assert f["context"]["experiment-id"] == 2   # scitag.flow=129 >> 6
        assert f["context"]["activity-id"] == 1      # 129 & 0x3f
        assert f["flow-id"]["protocol"] == "tcp"


# --------------------------------------------------------------------------- #
# 2) SUCCESS (new capability) — pmark at server{} scope marks S3 traffic.
#    Impossible before W1: the family was NGX_HTTP_LOC_CONF-only on webdav.
# --------------------------------------------------------------------------- #
def test_s3_pmark_server_scope_emits_firefly(lifecycle, tmp_path):
    cap = FireflyCapture(FF_PORT)
    ep = _serve_s3(lifecycle, tmp_path, pmark_server=(
        "        brix_pmark on;\n"
        "        brix_pmark_http_plain on;\n"
        "        brix_pmark_firefly on;\n"
        "        brix_pmark_scitag_cgi on;\n"
        "        brix_pmark_appname s3-w1-srv;\n"))
    try:
        _s3_put_get(ep.port, f"obj_{uuid.uuid4().hex}", b"scitags-server-scope\n")
        flies = cap.drain()
    finally:
        cap.close()
    assert flies, (
        "pmark set at server{} scope did not mark S3 traffic — the "
        "BRIX_HTTP_ALL_CONF scope upgrade regressed")
    for f in flies:
        assert f["context"]["application"] == "s3-w1-srv"
        assert f["context"]["experiment-id"] == 2


# --------------------------------------------------------------------------- #
# 3) ERROR — the custom setter moved verbatim: a bad domain fails nginx -t.
# --------------------------------------------------------------------------- #
def test_s3_pmark_domain_bogus_rejected():
    modules = [m for m in os.environ.get("TEST_NGINX_LOAD_MODULES", "").split(os.pathsep) if m]
    load = "".join(f"load_module {m};\n" for m in modules)
    with tempfile.TemporaryDirectory() as d:
        conf = os.path.join(d, "bad.conf")
        with open(conf, "w") as fh:
            fh.write(
                load
                + "events {}\n"
                "http { server { listen 127.0.0.1:%d;\n"
                "  location / { brix_s3 on; brix_pmark_domain bogus; } } }\n"
                % free_port())
        proc = subprocess.run([NGINX_BIN, "-t", "-c", conf, "-p", d],
                              capture_output=True, text=True, timeout=30)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, f"bogus domain should fail nginx -t: {out}"
    assert "any|local|remote" in out, \
        f"domain setter did not survive the move (wrong/no message): {out}"


# --------------------------------------------------------------------------- #
# 4) SECURITY-NEG — pmark OFF (default) on S3 emits NOTHING. Pins the default
#    and that adopt-at-merge does not leak an enable in from elsewhere.
# --------------------------------------------------------------------------- #
def test_s3_pmark_off_emits_nothing(lifecycle, tmp_path):
    cap = FireflyCapture(FF_PORT)
    # firefly_dest is set (http scope) but pmark itself is never enabled.
    ep = _serve_s3(lifecycle, tmp_path)
    try:
        _s3_put_get(ep.port, f"obj_{uuid.uuid4().hex}", b"must-not-be-marked\n")
        flies = cap.drain(settle=0.8)
    finally:
        cap.close()
    assert flies == [], \
        f"S3 with pmark OFF leaked {len(flies)} firefly datagram(s): {flies}"

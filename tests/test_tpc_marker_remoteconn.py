"""WLCG perf-marker ``RemoteConnections:`` line (parity audit §6.10).

A 202-streaming HTTP-TPC pull's Performance-Marker blocks may carry the
optional ``RemoteConnections: tcp:<ip>:<port>`` line naming where each
stripe's data actually comes from. BriX now emits it per stripe from the curl
handle's CONNECTED endpoint (CURLINFO_PRIMARY_IP/PORT), captured once on the
stream's first write callback — never from the client-supplied Source URL
text, so a hostile URL cannot be reflected into the marker stream.

Coverage (the change-class trio):
  * success      — a 3-stream COPY's marker body carries a RemoteConnections
                   line per stripe naming the https source's loopback
                   endpoint (tcp:127.0.0.1:<srcport>).
  * error        — a single-stream COPY (marker tier, no write-cb capture)
                   omits the OPTIONAL line rather than fabricating one; the
                   transfer still succeeds byte-exact.
  * security-neg — every emitted line matches the strict
                   ``tcp:<ip>:<port>`` shape: the connected numeric endpoint,
                   no reflected URL text (no scheme, no path, no hostname).

Source: an in-test https server (test PKI host certificate) with HEAD +
Range support so the multi-stream driver can split the pull.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_tpc_marker_remoteconn.py -v
"""

import http.client
import os
import re
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from settings import CA_CERT, HOST, NGINX_BIN, SERVER_CERT, SERVER_KEY
from ephemeral_port import free_port
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.timeout(120), pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-tpc-markers")]

PAYLOAD = os.urandom(96 * 1024)

REMOTE_LINE = re.compile(
    r"^RemoteConnections: tcp:(\[[0-9a-fA-F:]+\]|[0-9.]+):[0-9]+\r?$",
    re.MULTILINE)


class _RangeSource(BaseHTTPRequestHandler):
    """https origin serving PAYLOAD with HEAD + byte-range GET support."""

    def log_message(self, *args):
        pass

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(PAYLOAD)))
        self.send_header("Accept-Ranges", "bytes")
        self.end_headers()

    def do_GET(self):
        rng = self.headers.get("Range")
        body = PAYLOAD
        if rng and rng.startswith("bytes="):
            start_s, _, end_s = rng[len("bytes="):].partition("-")
            start = int(start_s)
            end = int(end_s) if end_s else len(PAYLOAD) - 1
            body = PAYLOAD[start:end + 1]
            self.send_response(206)
            self.send_header("Content-Range",
                             f"bytes {start}-{end}/{len(PAYLOAD)}")
        else:
            self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def source():
    for path in (SERVER_CERT, SERVER_KEY, CA_CERT):
        if not os.path.exists(path):
            pytest.skip(f"test PKI missing: {path}")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        ctx.load_cert_chain(SERVER_CERT, SERVER_KEY)
    except (ssl.SSLError, OSError) as exc:
        pytest.skip(f"cannot load the test host certificate: {exc}")
    httpd = ThreadingHTTPServer((HOST, free_port(HOST)), _RangeSource)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield {"url": f"https://{HOST}:{httpd.server_address[1]}/src.bin",
               "port": httpd.server_address[1]}
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=10)


@pytest.fixture()
def dest(lifecycle, tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    data = tmp_path / "data"
    data.mkdir()
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-tpc-markers",
        template="nginx_lc_tpc_markers.conf",
        protocol="webdav",
        readiness="tcp",
        template_values={"DATA_DIR": str(data), "CA_PEM": CA_CERT},
        reason="HTTP-TPC 202 markers: RemoteConnections line"))
    return {"host": ep.host, "port": ep.port, "data": data}


def _copy(dest, source_url, path, streams=None):
    """COPY-pull; returns (status, streamed_body_text)."""
    conn = http.client.HTTPConnection(dest["host"], dest["port"], timeout=120)
    try:
        headers = {"Source": source_url, "Credential": "none"}
        if streams:
            headers["X-Number-Of-Streams"] = str(streams)
        conn.request("COPY", path, headers=headers)
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", "replace")
        return resp.status, body
    finally:
        conn.close()


def test_multistream_markers_carry_remote_connections(dest, source):
    """(success) a 3-stream pull's marker body names the connected source
    endpoint per stripe, and the file lands byte-exact."""
    status, body = _copy(dest, source["url"], "/out-multi.bin", streams=3)
    assert status == 202, f"COPY not 202-streamed: {status}\n{body[:400]}"
    assert "success" in body.lower(), f"transfer failed:\n{body[-400:]}"

    lines = REMOTE_LINE.findall(body)
    assert lines, f"no RemoteConnections line in marker body:\n{body[:800]}"
    assert f"tcp:127.0.0.1:{source['port']}" in body, (  # net-literal-allow: marker body names the loopback source
        f"connected source endpoint absent:\n{body[:800]}")
    got = (dest["data"] / "out-multi.bin").read_bytes()
    assert got == PAYLOAD, "multi-stream pull corrupted the payload"


def test_single_stream_omits_optional_line(dest, source):
    """(error-path) the single-stream marker tier has no per-stream capture:
    the OPTIONAL line is omitted — never fabricated — and the transfer still
    succeeds byte-exact."""
    status, body = _copy(dest, source["url"], "/out-single.bin")
    assert status == 202, f"COPY not 202-streamed: {status}"
    assert "success" in body.lower(), f"transfer failed:\n{body[-400:]}"
    assert "RemoteConnections:" not in body, \
        "single-stream marker fabricated a RemoteConnections line"
    got = (dest["data"] / "out-single.bin").read_bytes()
    assert got == PAYLOAD, "single-stream pull corrupted the payload"


def test_remote_lines_are_strict_endpoints(dest, source):
    """(security-neg) every RemoteConnections line is the strict numeric
    tcp:<ip>:<port> shape — the CONNECTED endpoint, never reflected Source
    URL text (no scheme, no path, no hostname)."""
    status, body = _copy(dest, source["url"], "/out-strict.bin", streams=2)
    assert status == 202
    raw = [ln for ln in body.splitlines() if ln.startswith("RemoteConnections:")]
    assert raw, "expected RemoteConnections lines on a 2-stream pull"
    for line in raw:
        _assert_strict_endpoint(line)


def _assert_strict_endpoint(line):
    """One RemoteConnections line is the strict tcp:<ip>:<port> shape with no
    reflected URL text (no scheme, no path)."""
    assert any((REMOTE_LINE.match(line + "\n"), REMOTE_LINE.match(line))), \
        f"non-endpoint text leaked into marker line: {line!r}"
    assert all(("https" not in line, "/" not in line.split(":", 1)[1])), \
        f"URL text reflected into marker line: {line!r}"

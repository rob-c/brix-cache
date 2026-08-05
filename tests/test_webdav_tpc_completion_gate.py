"""HTTP-TPC (WebDAV COPY) pull completion gate — size and checksum.

Audit gap P1-6 (docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-04.md):
the native root:// plane has carried two completion gates for a pull since
Phase 58 — ``brix_tpc_require_source_size`` (refuse a source that never says how
big it is) and ``brix_tpc_verify_checksum`` (recompute the source's checksum over
what landed).  The HTTP plane had *neither*: a COPY pull committed whatever
curl produced, so a chunked source that dies mid-body, a truncating middlebox or
a corrupting one all committed silently.  That is a product gap, not just a test
gap, so this file drives the two new directives
``brix_webdav_tpc_require_source_size`` / ``brix_webdav_tpc_verify_checksum``
(src/protocols/webdav/tpc_verify.c) end to end.

The source is an in-test https server holding the test PKI host certificate —
the pull leg is https-only with ``SSL_VERIFYPEER``/``VERIFYHOST`` forced on, so
nothing weaker would even connect.  It serves five scripted behaviours over the
same payload:

    /good        Content-Length + correct Digest, full body
    /baddigest   Content-Length + a Digest that does not match the bytes
    /nodigest    Content-Length, no Digest at all
    /nolength    no Content-Length (chunked), full body
    /short       Content-Length of the WHOLE payload, chunked body with HALF

Three destinations pull from it: both gate halves on, the size half only, and
neither.  The last one is the non-vacuity control — it must still accept the
truncated and the corrupted source, which is exactly the pre-gate behaviour and
proves the refusals above come from the gate rather than from curl.

Unprivileged; throwaway registry instances, no fleet dependency.

Run (serial):
    PYTHONPATH=. python3 -m pytest test_webdav_tpc_completion_gate.py -v
"""

import http.client
import os
import ssl
import threading
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from config_parse import nginx_t
from ephemeral_port import free_port
from fleet_lifecycle_ports import SHARED_PARSE_PLACEHOLDER_PORT
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import CA_CERT, HOST, NGINX_BIN, SERVER_CERT, SERVER_KEY

pytestmark = [pytest.mark.serial, pytest.mark.timeout(300),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-tpc-gate")]

TEMPLATE = "nginx_webdav_tpc_completion_gate.conf"

# Big enough to span several curl write callbacks, not so big the half-body
# case takes measurable time.
PAYLOAD = bytes(range(256)) * 256              # 64 KiB, deterministic
ADLER = "%08x" % (zlib.adler32(PAYLOAD) & 0xFFFFFFFF)
HALF = len(PAYLOAD) // 2

GATE_BOTH = ("brix_webdav_tpc_require_source_size on;\n"
             "            brix_webdav_tpc_verify_checksum adler32;")
GATE_SIZE = "brix_webdav_tpc_require_source_size on;"
GATE_OFF = "# both halves left at their defaults (off)"


# ---------------------------------------------------------------------------
# The scripted https source
# ---------------------------------------------------------------------------

class _SourceHandler(BaseHTTPRequestHandler):
    """One handler, five behaviours keyed off the request path.

    Every response closes the connection: the destination makes two separate
    requests (the GET pull, then the gate's HEAD probe) and keep-alive adds
    nothing here but edge cases.
    """

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):        # keep pytest output clean
        pass

    def _mode(self):
        return self.path.lstrip("/").split("?")[0]

    def _headers(self, mode, chunked):
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Connection", "close")
        self.close_connection = True
        if chunked:
            self.send_header("Transfer-Encoding", "chunked")
        elif mode != "nolength":
            self.send_header("Content-Length", str(len(PAYLOAD)))
        if mode == "baddigest":
            self.send_header("Digest", "adler32=00000000")
        elif mode != "nodigest":
            self.send_header("Digest", f"adler32={ADLER}")
        self.end_headers()

    def do_HEAD(self):
        # The gate's probe: /short and /nolength differ from the GET on purpose
        # (/short over-declares, /nolength declares nothing at all).
        self._headers(self._mode(), chunked=(self._mode() == "nolength"))

    def do_GET(self):
        mode = self._mode()
        if mode in ("nolength", "short"):
            body = PAYLOAD[:HALF] if mode == "short" else PAYLOAD
            self._headers(mode, chunked=True)
            self.wfile.write(b"%x\r\n" % len(body) + body + b"\r\n0\r\n\r\n")
            return
        self._headers(mode, chunked=False)
        self.wfile.write(PAYLOAD)


@pytest.fixture(scope="module")
def source():
    """https origin on loopback, presenting the test PKI host certificate."""
    for path in (SERVER_CERT, SERVER_KEY, CA_CERT):
        if not os.path.exists(path):
            pytest.skip(f"test PKI missing: {path}")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        ctx.load_cert_chain(SERVER_CERT, SERVER_KEY)
    except (ssl.SSLError, OSError) as exc:
        pytest.skip(f"cannot load the test host certificate: {exc}")

    httpd = ThreadingHTTPServer((HOST, free_port(HOST)), _SourceHandler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"https://{HOST}:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=10)


# ---------------------------------------------------------------------------
# Destinations
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def dests():
    """The three COPY destinations, one per gate setting."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    harness = LifecycleHarness()
    made = {}
    try:
        for name, gate in (("lc-tpcgate-both", GATE_BOTH),
                           ("lc-tpcgate-size", GATE_SIZE),
                           ("lc-tpcgate-off", GATE_OFF)):
            made[name.rsplit("-", 1)[1]] = harness.start(NginxInstanceSpec(
                name=name,
                template=TEMPLATE,
                protocol="webdav",
                readiness="tcp",
                template_values={"GATE": gate, "CA_PEM": CA_CERT},
                reason="HTTP-TPC pull completion gate (audit P1-6)"))
    except Exception as exc:
        harness.close()
        pytest.skip(f"gate destinations did not start: {str(exc)[-300:]}")
    try:
        yield made
    finally:
        harness.close()


def _copy(dest, mode, source, path):
    """COPY-pull ``source/mode`` into ``path`` on ``dest``; return the status."""
    conn = http.client.HTTPConnection(dest.host, dest.port, timeout=120)
    try:
        conn.request("COPY", path, headers={
            "Source": f"{source}/{mode}",
            "Credential": "none",
        })
        resp = conn.getresponse()
        resp.read()
        return resp.status
    finally:
        conn.close()


def _get(dest, path):
    """GET ``path`` back from ``dest``; return ``(status, body)``."""
    conn = http.client.HTTPConnection(dest.host, dest.port, timeout=60)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def _errors(dest):
    log = os.path.join(dest.prefix, "logs", "error.log")
    if not os.path.exists(log):
        return ""
    with open(log, "r", errors="replace") as handle:
        return handle.read()


# ---------------------------------------------------------------------------
# Parse-time: the two directives accept what they should and reject the rest
# ---------------------------------------------------------------------------

def _parse(tmp_path, gate):
    (tmp_path / "logs").mkdir(parents=True, exist_ok=True)
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    return nginx_t(TEMPLATE, tmp_path,
                   PORT=SHARED_PARSE_PLACEHOLDER_PORT,
                   LOG_DIR=str(tmp_path / "logs"),
                   DATA_DIR=str(tmp_path / "data"),
                   CA_PEM=CA_CERT,
                   GATE=gate)


@pytest.mark.parametrize("gate", [
    "brix_webdav_tpc_require_source_size on;",
    "brix_webdav_tpc_require_source_size off;",
    "brix_webdav_tpc_verify_checksum adler32;",
    "brix_webdav_tpc_verify_checksum MD5;",          # case-folded to canonical
    "brix_webdav_tpc_verify_checksum crc32c;",
    GATE_BOTH,
])
def test_gate_directives_parse(tmp_path, gate):
    result = _parse(tmp_path, gate)
    assert result.returncode == 0, result.stderr


def test_unknown_checksum_algorithm_is_refused(tmp_path):
    """Security-negative: a typo'd algorithm must not silently disable the gate."""
    result = _parse(tmp_path, "brix_webdav_tpc_verify_checksum sha3;")
    assert result.returncode != 0
    assert "unknown algorithm" in result.stderr
    assert "[emerg]" in result.stderr


def test_duplicate_checksum_directive_is_refused(tmp_path):
    result = _parse(tmp_path, "brix_webdav_tpc_verify_checksum adler32;\n"
                              "            brix_webdav_tpc_verify_checksum md5;")
    assert result.returncode != 0
    assert "is duplicate" in result.stderr


# ---------------------------------------------------------------------------
# Live: both halves on
# ---------------------------------------------------------------------------

def test_honest_source_is_committed(dests, source):
    """Success case: correct length and correct Digest -> the pull commits."""
    dest = dests["both"]
    assert _copy(dest, "good", source, "/gate_good.dat") == 201
    assert _get(dest, "/gate_good.dat") == (200, PAYLOAD)


@pytest.mark.parametrize("mode,path,needle", [
    ("short", "/gate_short.dat", "HTTP-TPC pull truncated"),
    ("nolength", "/gate_nolength.dat", "source declared no size"),
    ("baddigest", "/gate_baddigest.dat", "HTTP-TPC checksum mismatch"),
    ("nodigest", "/gate_nodigest.dat", "source supplied no Digest"),
])
def test_dishonest_source_is_refused_and_nothing_commits(dests, source,
                                                         mode, path, needle):
    """Error + security-negative: every disagreement refuses AND commits nothing.

    A refusal that still left the staged temp in place would be worse than no
    gate at all — the caller would see 502 and the file would exist anyway — so
    the read-back is as load-bearing as the status.
    """
    dest = dests["both"]
    assert _copy(dest, mode, source, path) == 502
    assert _get(dest, path)[0] == 404
    assert needle in _errors(dest)


# ---------------------------------------------------------------------------
# Live: the halves are independent, and neither fires when off
# ---------------------------------------------------------------------------

def test_size_half_alone_ignores_a_missing_digest(dests, source):
    """The checksum half is off here, so a source with no Digest is fine —
    the two directives must not be silently coupled."""
    dest = dests["size"]
    assert _copy(dest, "nodigest", source, "/size_nodigest.dat") == 201
    assert _get(dest, "/size_nodigest.dat") == (200, PAYLOAD)


def test_size_half_alone_still_catches_truncation(dests, source):
    dest = dests["size"]
    assert _copy(dest, "short", source, "/size_short.dat") == 502
    assert _get(dest, "/size_short.dat")[0] == 404


@pytest.mark.parametrize("mode,path,expect", [
    ("short", "/off_short.dat", PAYLOAD[:HALF]),
    ("baddigest", "/off_baddigest.dat", PAYLOAD),
    ("nolength", "/off_nolength.dat", PAYLOAD),
])
def test_gates_off_accepts_the_same_sources(dests, source, mode, path, expect):
    """Non-vacuity: with both halves off — the default — the very sources the
    gate refuses are accepted, truncation and all.  This is the behaviour every
    existing deployment keeps, and it pins that the refusals above are the
    gate's doing rather than curl's."""
    dest = dests["off"]
    assert _copy(dest, mode, source, path) == 201
    assert _get(dest, path) == (200, expect)

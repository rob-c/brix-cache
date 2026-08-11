"""
Phase 24 — traffic mirroring (HTTP/WebDAV + XRootD stream).

Coverage:
  1. Source-marker checks: both mirror surfaces, the dispatch hook, the phase
     handlers, directives, and metrics are wired.
  2. Config validation: the HTTP and stream mirror directives parse; bad scheme
     / bad opcode are rejected; mirroring is off by default.
  3. HTTP/WebDAV functional: a GET fires a background shadow request (success);
     the shadow never sees the client's Authorization (security-neg / strip);
     a dead shadow is transparent to the client (error); sampling 0 mirrors
     nothing, 100 mirrors all; a write (PUT) is never mirrored.
  4. Stream functional: a kXR_stat replays to the shadow XRootD server
     (success), and a status mismatch increments the divergence counter
     (security-neg / divergence).

Registry-backed: every nginx here is a throwaway instance provisioned through
the `lifecycle` harness (templates nginx_mirror_http.conf /
nginx_mirror_stream_parse.conf / nginx_mirror_stream_pair.conf).
"""

import base64
import http.client
import json
import os
import re
import socket
import struct
import time
import urllib.request
from pathlib import Path

import pytest

from config_parse import nginx_t
from fleet_lifecycle_ports import PARSE_PLACEHOLDER_PORT, lifecycle_ports_for
from server_registry import NginxInstanceSpec
from settings import (NGINX_BIN, HOST, BIND_HOST,
                      MIRROR_SHADOW_PORT, PROXY_DEAD_UPSTREAM_PORT)

# The shadow upstream is a shared fixed-port fleet mock whose capture is global
# state, so these tests run serial (one xdist worker) and each resets it first.
# Every nginx here draws a fixed exclusive-band port from the lifecycle ledger
# (lc-mir-*); xdist_group("lc-mir") keeps those fixed ports single-driver too.
pytestmark = [
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.serial,
    pytest.mark.registry_server("mirror-shadow"),
    pytest.mark.xdist_group("lc-mir"),
]

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _require_binary():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")


def _read(rel):
    p = ROOT / rel
    assert p.exists(), f"missing {rel}"
    text = p.read_text(encoding="utf-8")
    # The per-module ngx_command_t directive table was split into per-concern
    # directives_*.h fragments (#included into the array); inline them so a
    # directive-presence check against module.c sees the full effective table.
    import re as _re
    def _inc(m):
        frag = p.parent / m.group(1)
        return frag.read_text(encoding="utf-8") if frag.exists() else m.group(0)
    return _re.sub(r'#include "(directives_[a-z0-9_]+\.h)"', _inc, text)


# --------------------------------------------------------------------------- #
# 1. Source-marker checks                                                      #
# --------------------------------------------------------------------------- #

def _parse_http(lifecycle, name, knobs):
    lifecycle.register(NginxInstanceSpec(
        name=name,
        template="nginx_mirror_http.conf",
        template_values={"BIND_HOST": BIND_HOST, "MIRROR_KNOBS": knobs},
        reason="HTTP mirror directive parse coverage",
    ))
    lifecycle.reconfigure(name)
    lifecycle.nginx_test(name)  # raises on parse failure


def _parse_stream(lifecycle, name, knobs, shadow_port):
    lifecycle.register(NginxInstanceSpec(
        name=name,
        template="nginx_mirror_stream_parse.conf",
        template_values={"BIND_HOST": BIND_HOST, "HOST": HOST,
                         "SHADOW_PORT": shadow_port, "MIRROR_KNOBS": knobs},
        reason="stream mirror directive parse coverage",
    ))
    lifecycle.reconfigure(name)
    lifecycle.nginx_test(name)



class ShadowClient:
    """Out-of-band control client for the fixed-port ``mirror-shadow`` fleet mock
    (tests/lib/mirror_shadow_server.py).

    The mirror nginx replays requests to the mock's data port; this reads the
    captured (path, headers, method, body) state and resets it between tests over
    the mock's tiny control API.  The capture is shared global state, so the suite
    runs ``serial`` and each shadow-using test ``reset()``s first.
    """

    def __init__(self, host=None, port=None):
        self.host = host or HOST
        self.port = port or MIRROR_SHADOW_PORT

    def _call(self, method, path):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=5)
        try:
            conn.request(method, path)
            return conn.getresponse().read()
        finally:
            conn.close()

    def _state(self):
        return json.loads(self._call("GET", "/__introspect"))

    def reset(self):
        self._call("POST", "/__reset")

    @property
    def received(self):
        """List of (path, headers-dict) as the shadow saw them."""
        return [(p, h) for p, h in self._state()["received"]]

    @property
    def methods(self):
        """List of (method, path) tuples."""
        return [(m, p) for m, p in self._state()["methods"]]

    def paths(self):
        return [p for p, _ in self._state()["received"]]

    def body(self, path):
        b = self._state()["bodies"].get(path)
        return base64.b64decode(b) if b is not None else None


#: One shared control client for the fixed-port shadow mock.
_shadow = ShadowClient()


def _start_mirror_primary(lifecycle, tmp_path, name, knobs, seed_files=()):
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    for n, text in seed_files:
        (data / n).write_text(text)
    endpoint = lifecycle.start(NginxInstanceSpec(
        name=name,
        template="nginx_mirror_http.conf",
        protocol="http",
        data_root=str(data),
        template_values={"BIND_HOST": BIND_HOST, "MIRROR_KNOBS": knobs},
        reason="HTTP mirror functional coverage",
    ))
    return endpoint.port


def _read_headers(s):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    return data.partition(b"\r\n\r\n")


def _content_length(headers):
    for line in headers.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            return int(line.split(b":", 1)[1])
    return 0


def _read_body(s, body, length):
    while len(body) < length:
        chunk = s.recv(4096)
        if not chunk:
            break
        body += chunk
    return body


def _read_status_and_body(s):
    """Read through Content-Length without waiting for a mirror-delayed FIN."""
    s.settimeout(4)
    headers, _, body = _read_headers(s)
    status = int(headers.split(b"\r\n", 1)[0].split()[1])
    _read_body(s, body, _content_length(headers))
    return status


def _http_get(port, path, extra_headers=""):
    with socket.create_connection((HOST, port), timeout=4) as s:
        s.sendall((f"GET {path} HTTP/1.1\r\nHost: x\r\n{extra_headers}"
                   "Connection: close\r\n\r\n").encode())
        return _read_status_and_body(s)


def _put(port, path, body):
    with socket.create_connection((HOST, port), timeout=4) as s:
        s.sendall((f"PUT {path} HTTP/1.1\r\nHost: x\r\nContent-Length: "
                   f"{len(body)}\r\nConnection: close\r\n\r\n").encode() + body)
        return _read_status_and_body(s)


def _shadow_paths():
    return _shadow.paths()


def _wait_shadow(path, timeout=6):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path in _shadow_paths():
            return True
        time.sleep(0.1)
    return False


@pytest.fixture
def http_mirror_server(lifecycle, tmp_path):
    _shadow.reset()
    port = _start_mirror_primary(
        lifecycle, tmp_path, "lc-mir-http",
        (f"            brix_mirror_url     http://{HOST}:{MIRROR_SHADOW_PORT};\n"
         "            brix_mirror_methods GET HEAD;\n"
         "            brix_mirror_sample  100;\n"
         "            brix_mirror_strip_auth on;\n"),
        seed_files=[("hello.txt", "hello mirror\n")])
    yield port, MIRROR_SHADOW_PORT


# --------------------------------------------------------------------------- #
# 3. HTTP/WebDAV functional                                                    #
# --------------------------------------------------------------------------- #


def _xrd_login(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((host, port))
    # handshake (20 bytes) + kXR_protocol
    s.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    s.sendall(struct.pack(">BB H I BB 10x I", 0, 1, 3006, 0x00000520, 0x02, 0x03, 0))
    s.recv(16)
    hdr = s.recv(8)
    dlen = struct.unpack(">I", hdr[4:8])[0]
    if dlen:
        s.recv(dlen)
    # kXR_login (username "test")
    s.sendall(struct.pack(">BB H I 8s BB B B I", 0, 1, 3007, 0,
                          b"test\x00\x00\x00\x00", 0, 0, 5, 0, 0))
    hdr = s.recv(8)
    dlen = struct.unpack(">I", hdr[4:8])[0]
    if dlen:
        s.recv(dlen)
    return s


def _xrd_stat(host, port, path):
    s = _xrd_login(host, port)
    try:
        payload = path.encode() + b"\x00"
        # kXR_stat = 3017; header: streamid[2], reqid, options, 11 reserved, fhandle[4]? -> use 16-byte body of zeros
        hdr = struct.pack(">BBH16sI", 0, 1, 3017, b"\x00" * 16, len(payload))
        s.sendall(hdr + payload)
        rhdr = s.recv(8)
        status = struct.unpack(">H", rhdr[2:4])[0]
        dlen = struct.unpack(">I", rhdr[4:8])[0]
        body = b""
        while len(body) < dlen:
            c = s.recv(dlen - len(body))
            if not c:
                break
            body += c
        return status
    finally:
        s.close()


def _scrape_metric(metrics_port, name, surface):
    try:
        with urllib.request.urlopen(
                f"http://{HOST}:{metrics_port}/metrics", timeout=4) as r:
            text = r.read().decode()
    except OSError:
        return None
    m = re.search(rf'^{re.escape(name)}{{surface="{surface}"}}\s+(\d+)',
                  text, re.MULTILINE)
    return int(m.group(1)) if m else None


def _wait_metric(metrics_port, name, surface, want, timeout=8):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = _scrape_metric(metrics_port, name, surface)
        if last is not None and last >= want:
            return last
        time.sleep(0.2)
    return last


def _start_stream_pair(lifecycle, tmp_path, name, primary_files, shadow_files):
    pdata = tmp_path / "pdata"; pdata.mkdir()
    sdata = tmp_path / "sdata"; sdata.mkdir()
    for n in primary_files:
        (pdata / n).write_text("x\n")
    for n in shadow_files:
        (sdata / n).write_text("x\n")
    # SHADOW_PORT + METRICS_PORT are real secondary listens of this one instance;
    # the harness injects them from the lc-mir-* ledger entry (by name) into the
    # template and onto endpoint.extra_ports — no dynamic allocation.
    endpoint = lifecycle.start(NginxInstanceSpec(
        name=name,
        template="nginx_mirror_stream_pair.conf",
        data_root=str(pdata),
        template_values={"BIND_HOST": BIND_HOST, "HOST": HOST,
                         "SHADOW_DATA": str(sdata)},
        reason="stream mirror + divergence functional coverage",
    ))
    return endpoint.port, endpoint.extra_ports["METRICS_PORT"]


# --------------------------------------------------------------------------- #
# 4. Stream functional                                                         #
# --------------------------------------------------------------------------- #


def _http_req(port, method, path, body=b"", extra=""):
    """Send a request and best-effort read the status; never block the test.

    The write-mirror assertions are made on the shadow side (polled), so we only
    need to deliver the request to the primary — the primary's own response
    framing (and the deferred close while a background mirror subrequest drains)
    must not hang the test.  Any read timeout/short-read returns status 0."""
    try:
        with socket.create_connection((HOST, port), timeout=4) as s:
            head = (f"{method} {path} HTTP/1.1\r\nHost: x\r\n{extra}"
                    f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n")
            s.sendall(head.encode() + body)
            s.settimeout(4)
            data = b""
            try:
                while b"\r\n\r\n" not in data:
                    c = s.recv(4096)
                    if not c:
                        break
                    data += c
            except OSError:
                pass
            if not data:
                return 0
            try:
                return int(data.split(b"\r\n", 1)[0].split()[1])
            except (IndexError, ValueError):
                return 0
    except OSError:
        return 0


def _shadow_body(path):
    return _shadow.body(path)


def _wait_shadow_method(method, path, timeout=6):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if (method, path) in _shadow.methods:
            return True
        time.sleep(0.1)
    return False


def _writes_knobs(shadow_port, writes="on",
                  methods="PUT DELETE MKCOL MOVE COPY"):
    return (
        "            brix_allow_write on;\n"
        f"            brix_mirror_url     http://{HOST}:{shadow_port};\n"
        f"            brix_mirror_methods {methods};\n"
        f"            brix_mirror_writes  {writes};\n"
        "            brix_mirror_sample  100;\n"
    )


@pytest.fixture
def http_mirror_writes_server(lifecycle, tmp_path):
    _shadow.reset()
    port = _start_mirror_primary(
        lifecycle, tmp_path, "lc-mir-writes",
        _writes_knobs(MIRROR_SHADOW_PORT))
    yield port, MIRROR_SHADOW_PORT



def _recv_exact(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise EOFError("shadow/primary closed mid-frame")
        b += c
    return b


def _xrd_resp(s):
    hdr = _recv_exact(s, 8)
    status = struct.unpack(">H", hdr[2:4])[0]
    dlen = struct.unpack(">I", hdr[4:8])[0]
    return status, (_recv_exact(s, dlen) if dlen else b"")


# Wire constants for the raw create-write open below. These were lost in a
# helper split (the reexport chain never carried them — pre-existing NameError
# at HEAD, surfaced by the phase-105 W3 run); values match the sibling raw
# helpers (_test_chkpoint_stock_framing_helpers et al.) / XProtocol.hh.
_kXR_open       = 3010
_OPEN_CREATE_WR = 0x0020 | 0x0008   # kXR_open_updt | kXR_new


def _xrd_open_wr(s, path):
    p = path.encode() + b"\x00"
    s.sendall(struct.pack(">2sHHH12sI", b"\x00\x05", _kXR_open, 0o644,
                          _OPEN_CREATE_WR, b"\x00" * 12, len(p)) + p)
    st, body = _xrd_resp(s)
    return st, body[:4]

# Re-export from split helpers
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_phase24_mirror_helpers_b")

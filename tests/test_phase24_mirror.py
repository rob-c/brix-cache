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

import os
import re
import socket
import struct
import threading
import time
import http.server
import urllib.request
from pathlib import Path

import pytest

from server_registry import NginxInstanceSpec
from settings import NGINX_BIN, free_ports, HOST, BIND_HOST

pytestmark = pytest.mark.uses_lifecycle_harness

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
    # directives_*.inc fragments (#included into the array); inline them so a
    # directive-presence check against module.c sees the full effective table.
    import re as _re
    def _inc(m):
        frag = p.parent / m.group(1)
        return frag.read_text(encoding="utf-8") if frag.exists() else m.group(0)
    return _re.sub(r'#include "(directives_[a-z0-9_]+\.inc)"', _inc, text)


# --------------------------------------------------------------------------- #
# 1. Source-marker checks                                                      #
# --------------------------------------------------------------------------- #

def test_mirror_modules_present():
    for f in ("src/net/mirror/mirror.h", "src/net/mirror/http_mirror.c",
              "src/net/mirror/http_mirror.h", "src/net/mirror/stream_mirror.c",
              "src/net/mirror/stream_mirror.h"):
        assert (ROOT / f).exists(), f
    cfg = _read("config")
    assert "src/net/mirror/http_mirror.c" in cfg
    assert "src/net/mirror/stream_mirror.c" in cfg


def test_stream_dispatch_hook_present():
    d = _read("src/protocols/root/handshake/dispatch.c")
    assert "brix_stream_mirror_maybe" in d
    sm = _read("src/net/mirror/stream_mirror.c")
    # Reuses the proven bootstrap wire builder; replays the saved request.
    assert "brix_upstream_build_bootstrap" in sm
    assert "brix_mir_send_request" in sm
    assert "mirror_stream_divergence_total" in sm


def test_http_phase_handlers_present():
    h = _read("src/net/mirror/http_mirror.c")
    assert "brix_http_mirror_precontent_handler" in h
    assert "ngx_http_subrequest" in h
    assert "NGX_HTTP_SUBREQUEST_BACKGROUND" in h
    pc = _read("src/protocols/webdav/postconfig.c")
    assert "NGX_HTTP_PRECONTENT_PHASE" in pc
    assert "brix_http_mirror_precontent_handler" in pc


def test_directives_registered():
    # phase-79 split: the clustering/traffic directive tables moved into
    # directives_net.inc on both surfaces (webdav via module_commands.c,
    # stream via module.c — each #includes its directives_net.inc).
    wd = _read("src/protocols/webdav/directives_net.inc")
    for name in ("brix_mirror_url", "brix_mirror_methods",
                 "brix_mirror_sample", "brix_mirror_strip_auth"):
        assert name in wd, name
    st = _read("src/protocols/root/stream/directives_net.inc")
    for name in ("brix_stream_mirror_url", "brix_mirror_opcodes"):
        assert name in st, name


def test_metrics_present():
    m = _read("src/observability/metrics/metrics.h")
    assert "mirror_http_total" in m
    assert "mirror_stream_divergence_total" in m
    assert "brix_mirror_requests_total" in _read("src/observability/metrics/stream.c")


# --------------------------------------------------------------------------- #
# 2. Config validation                                                         #
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


def test_http_mirror_directives_parse(lifecycle):
    s1, s2 = free_ports(2)
    _parse_http(lifecycle, "lc-mir-hparse", (
        f"            brix_mirror_url     http://{HOST}:{s1};\n"
        f"            brix_mirror_url     https://{HOST}:{s2};\n"
        "            brix_mirror_methods GET HEAD PROPFIND;\n"
        "            brix_mirror_sample  25;\n"
        "            brix_mirror_strip_auth on;\n"
        "            brix_mirror_log_diverge on;\n"
        "            brix_mirror_timeout 3s;\n"
    ))


def test_http_mirror_bad_scheme_rejected(lifecycle, tmp_path):
    port, shadow = free_ports(2)
    result = lifecycle.expect_config_failure(NginxInstanceSpec(
        name="lc-mir-badscheme",
        template="nginx_mirror_http.conf",
        template_values={
            "BIND_HOST": BIND_HOST,
            "PORT": port,
            "DATA_ROOT": str(tmp_path / "data"),
            "LOG_DIR": str(tmp_path),
            "TMP_DIR": str(tmp_path),
            "MIRROR_KNOBS": f"            brix_mirror_url ftp://{HOST}:{shadow};\n",
        },
        reason="mirror URL bad-scheme rejection coverage",
    ))
    out = (result.stdout or "") + (result.stderr or "")
    assert result.returncode != 0
    assert "http://" in out


def test_stream_mirror_directives_parse(lifecycle):
    (shadow,) = free_ports(1)
    _parse_stream(lifecycle, "lc-mir-sparse", (
        "        brix_mirror_opcodes stat locate dirlist;\n"
        "        brix_mirror_sample 50;\n"
        "        brix_mirror_log_diverge on;\n"
        "        brix_mirror_timeout 3s;\n"
    ), shadow)


def test_stream_mirror_bad_opcode_rejected(lifecycle, tmp_path):
    port, shadow = free_ports(2)
    result = lifecycle.expect_config_failure(NginxInstanceSpec(
        name="lc-mir-badop",
        template="nginx_mirror_stream_parse.conf",
        template_values={
            "BIND_HOST": BIND_HOST,
            "HOST": HOST,
            "PORT": port,
            "SHADOW_PORT": shadow,
            "DATA_ROOT": str(tmp_path / "data"),
            "LOG_DIR": str(tmp_path),
            "MIRROR_KNOBS": "        brix_mirror_opcodes bogus;\n",
        },
        reason="mirror bad-opcode rejection coverage",
    ))
    out = (result.stdout or "") + (result.stderr or "")
    assert result.returncode != 0
    assert "brix_mirror_opcodes" in out


# --------------------------------------------------------------------------- #
# Phase 24 write mirroring (W1: stream metadata) — wiring + gate               #
# --------------------------------------------------------------------------- #

def test_stream_mirror_write_opcodes_and_gate_parse(lifecycle):
    """The write opcodes + brix_mirror_writes gate parse on the stream side."""
    (shadow,) = free_ports(1)
    _parse_stream(lifecycle, "lc-mir-wparse", (
        "        brix_mirror_writes on;\n"
        "        brix_mirror_opcodes mkdir rm rmdir mv truncate chmod;\n"
    ), shadow)


def test_mirror_writes_off_by_default_and_gated_in_source():
    """mirror_writes defaults off; the gate is independent of opcode selection."""
    mh = _read("src/net/mirror/mirror.h")
    # Write bits exist but are excluded from the default opcode mask.
    assert "BRIX_MIRROR_OP_MKDIR" in mh
    assert "BRIX_MIRROR_OP_WRITE" in mh
    assert "mirror_writes" in mh
    # OP_DEFAULT/OP_ALL must NOT pull in the write bits.
    op_all = re.search(r"define\s+BRIX_MIRROR_OP_ALL\b(.*?)\n\n", mh, re.S)
    assert op_all and "MKDIR" not in op_all.group(1) and "OP_WRITE" not in op_all.group(1)
    # The stream maybe() enforces mirror_writes as a second, independent guard.
    # phase-79 split: the launch/opcode-gating half of stream_mirror.c moved
    # into stream_mirror_launch.c.
    sm = _read("src/net/mirror/stream_mirror_launch.c")
    assert "OP_WRITE_ALL" in sm and "mirror_writes" in sm
    # Default merge is 0 (off) on both surfaces.  phase-79 split: the cluster/
    # mirror merge moved from server_conf.c into server_conf_merge_cluster.c,
    # and the webdav proxy/mirror merge from config.c into config_proxy.c.
    assert "conf->mirror.mirror_writes,\n                         prev->mirror.mirror_writes, 0" \
        in _read("src/core/config/server_conf_merge_cluster.c")
    assert "prev->mirror.mirror_writes, 0" in _read("src/protocols/webdav/config_proxy.c")


# --------------------------------------------------------------------------- #
# HTTP functional helpers                                                      #
# --------------------------------------------------------------------------- #

class _ShadowHandler(http.server.BaseHTTPRequestHandler):
    received = []          # list of (path, headers-dict)
    bodies = {}            # path -> request body bytes (write methods)
    methods = []           # list of (method, path)
    lock = threading.Lock()

    def _record(self):
        with _ShadowHandler.lock:
            _ShadowHandler.received.append(
                (self.path, {k.lower(): v for k, v in self.headers.items()}))
            _ShadowHandler.methods.append((self.command, self.path))
        body = b"SHADOW\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _record_write(self):
        clen = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(clen) if clen else b""
        with _ShadowHandler.lock:
            _ShadowHandler.received.append(
                (self.path, {k.lower(): v for k, v in self.headers.items()}))
            _ShadowHandler.bodies[self.path] = body
            _ShadowHandler.methods.append((self.command, self.path))
        self.send_response(201)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = _record
    do_HEAD = _record
    do_PUT = _record_write
    do_DELETE = _record_write
    do_MKCOL = _record_write
    do_MOVE = _record_write
    do_COPY = _record_write

    def log_message(self, *a):
        pass


def _start_shadow():
    _ShadowHandler.received = []
    _ShadowHandler.bodies = {}
    _ShadowHandler.methods = []
    srv = http.server.HTTPServer((BIND_HOST, 0), _ShadowHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


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


def _read_status_and_body(s):
    """Read an HTTP response far enough to know status + full body.

    A background mirror subrequest keeps the client connection open until it
    finishes, so the trailing FIN is deferred; we must NOT block on close.
    We read headers, then exactly Content-Length body bytes, then return."""
    s.settimeout(4)
    data = b""
    while b"\r\n\r\n" not in data:
        c = s.recv(4096)
        if not c:
            break
        data += c
    head, _, rest = data.partition(b"\r\n\r\n")
    status = int(head.split(b"\r\n", 1)[0].split()[1])
    clen = 0
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            clen = int(line.split(b":", 1)[1])
    while len(rest) < clen:
        c = s.recv(4096)
        if not c:
            break
        rest += c
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
    with _ShadowHandler.lock:
        return [p for p, _ in _ShadowHandler.received]


def _wait_shadow(path, timeout=6):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path in _shadow_paths():
            return True
        time.sleep(0.1)
    return False


@pytest.fixture
def http_mirror_server(lifecycle, tmp_path):
    shadow, shadow_port = _start_shadow()
    try:
        port = _start_mirror_primary(
            lifecycle, tmp_path, "lc-mir-http",
            (f"            brix_mirror_url     http://{HOST}:{shadow_port};\n"
             "            brix_mirror_methods GET HEAD;\n"
             "            brix_mirror_sample  100;\n"
             "            brix_mirror_strip_auth on;\n"),
            seed_files=[("hello.txt", "hello mirror\n")])
        yield port, shadow_port
    finally:
        shadow.shutdown()


# --------------------------------------------------------------------------- #
# 3. HTTP/WebDAV functional                                                    #
# --------------------------------------------------------------------------- #

def test_get_fires_shadow_request(http_mirror_server):
    port, _ = http_mirror_server
    assert _http_get(port, "/hello.txt") == 200
    assert _wait_shadow("/hello.txt"), "shadow never received the mirrored GET"


def test_auth_stripped_from_shadow(http_mirror_server):
    port, _ = http_mirror_server
    status = _http_get(port, "/hello.txt",
                       extra_headers="Authorization: Bearer secret-token\r\n")
    assert status == 200
    assert _wait_shadow("/hello.txt")
    with _ShadowHandler.lock:
        for p, hdrs in _ShadowHandler.received:
            assert "authorization" not in hdrs, \
                "shadow must not receive the client's Authorization header"


def test_shadow_failure_transparent(lifecycle, tmp_path):
    # Shadow port has nothing listening → mirror connect fails, but the primary
    # GET must still succeed (the client never sees the shadow path).
    (dead_shadow,) = free_ports(1)
    port = _start_mirror_primary(
        lifecycle, tmp_path, "lc-mir-dead",
        (f"            brix_mirror_url     http://{HOST}:{dead_shadow};\n"
         "            brix_mirror_methods GET;\n"
         "            brix_mirror_sample  100;\n"
         "            brix_mirror_timeout 1s;\n"),
        seed_files=[("f.txt", "body\n")])
    assert _http_get(port, "/f.txt") == 200
    # Repeat — a failing mirror must not break subsequent requests.
    assert _http_get(port, "/f.txt") == 200


def test_write_not_mirrored(http_mirror_server):
    port, _ = http_mirror_server
    _put(port, "/uploaded.txt", b"data")
    # Give any (erroneous) mirror a chance to fire, then assert none did.
    time.sleep(1.0)
    assert "/uploaded.txt" not in _shadow_paths(), "PUT must never be mirrored"


def test_sample_zero_mirrors_nothing(lifecycle, tmp_path):
    shadow, shadow_port = _start_shadow()
    try:
        port = _start_mirror_primary(
            lifecycle, tmp_path, "lc-mir-zero",
            (f"            brix_mirror_url     http://{HOST}:{shadow_port};\n"
             "            brix_mirror_methods GET;\n"
             "            brix_mirror_sample  0;\n"),
            seed_files=[("z.txt", "z\n")])
        assert _http_get(port, "/z.txt") == 200
        time.sleep(1.0)
        assert _shadow_paths() == [], "sample 0 must mirror nothing"
    finally:
        shadow.shutdown()


# --------------------------------------------------------------------------- #
# Stream functional helpers (raw XRootD wire)                                  #
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
    shadow_port, metrics_port = free_ports(2)
    endpoint = lifecycle.start(NginxInstanceSpec(
        name=name,
        template="nginx_mirror_stream_pair.conf",
        data_root=str(pdata),
        extra_ports={"SHADOW_PORT": shadow_port, "METRICS_PORT": metrics_port},
        template_values={"BIND_HOST": BIND_HOST, "HOST": HOST,
                         "SHADOW_DATA": str(sdata)},
        reason="stream mirror + divergence functional coverage",
    ))
    return endpoint.port, metrics_port


# --------------------------------------------------------------------------- #
# 4. Stream functional                                                         #
# --------------------------------------------------------------------------- #

def test_stat_mirrored_to_shadow(lifecycle, tmp_path):
    primary, metrics = _start_stream_pair(
        lifecycle, tmp_path, "lc-mir-stream-ok",
        primary_files=["present.txt"], shadow_files=["present.txt"])
    _xrd_stat(HOST, primary, "/present.txt")
    got = _wait_metric(metrics, "brix_mirror_requests_total", "stream", 1)
    assert got is not None and got >= 1, \
        f"stream mirror request not counted (got {got})"


def test_divergence_counted(lifecycle, tmp_path):
    # Primary HAS the file (stat ok); shadow does NOT (kXR_NotFound) → divergence.
    primary, metrics = _start_stream_pair(
        lifecycle, tmp_path, "lc-mir-stream-div",
        primary_files=["only-here.txt"], shadow_files=[])
    _xrd_stat(HOST, primary, "/only-here.txt")
    got = _wait_metric(metrics, "brix_mirror_divergence_total", "stream", 1)
    assert got is not None and got >= 1, \
        f"divergence not counted (got {got})"


# --------------------------------------------------------------------------- #
# Phase 24 W2 — HTTP write-method mirroring (functional)                       #
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
    with _ShadowHandler.lock:
        return _ShadowHandler.bodies.get(path)


def _wait_shadow_method(method, path, timeout=6):
    deadline = time.time() + timeout
    while time.time() < deadline:
        with _ShadowHandler.lock:
            if (method, path) in _ShadowHandler.methods:
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
    shadow, shadow_port = _start_shadow()
    try:
        port = _start_mirror_primary(
            lifecycle, tmp_path, "lc-mir-writes",
            _writes_knobs(shadow_port))
        yield port, shadow_port
    finally:
        shadow.shutdown()


def test_put_body_mirrored_to_shadow(http_mirror_writes_server):
    """A PUT body is forwarded byte-exact to the shadow (W2 PUT body forwarding)."""
    primary, _ = http_mirror_writes_server
    body = bytes((i * 31 + 7) & 0xFF for i in range(5000))
    _http_req(primary, "PUT", "/w-up.bin", body)   # mirror fires in PRECONTENT
    assert _wait_shadow_method("PUT", "/w-up.bin"), "shadow never received the PUT"
    assert _shadow_body("/w-up.bin") == body, "shadow PUT body not byte-exact"


def test_delete_mirrored_to_shadow(http_mirror_writes_server):
    """DELETE is mirrored to the shadow (fires in PRECONTENT regardless of 404)."""
    primary, _ = http_mirror_writes_server
    _http_req(primary, "DELETE", "/w-gone.txt")
    assert _wait_shadow_method("DELETE", "/w-gone.txt"), \
        "shadow never received the DELETE"


def test_writes_off_not_mirrored(lifecycle, tmp_path):
    """With brix_mirror_writes off, a PUT is NOT replayed to the shadow."""
    shadow, shadow_port = _start_shadow()
    try:
        port = _start_mirror_primary(
            lifecycle, tmp_path, "lc-mir-writesoff",
            _writes_knobs(shadow_port, writes="off"))
        _http_req(port, "PUT", "/off.bin", b"data")
        time.sleep(1.0)
        with _ShadowHandler.lock:
            assert ("PUT", "/off.bin") not in _ShadowHandler.methods, \
                "PUT mirrored despite brix_mirror_writes off"
    finally:
        shadow.shutdown()

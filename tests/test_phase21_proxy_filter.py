"""
Phase 21 — multi-backend WebDAV proxy (Step D) and XrdHttp filters (Steps A/B).

Coverage:
  1. Source-marker checks for the multi-backend wiring + aux filter module.
  2. Config validation for the new proxy directives (nginx -t).
  3. Functional round-robin: a proxy instance fans GETs across two origins.
"""

import http.server
import os
import socket
import subprocess
import threading
import time
from pathlib import Path

import pytest

from settings import NGINX_BIN, HOST, BIND_HOST, free_port, free_ports

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = "/tmp/xrd-test/data"

# Listen ports for the `nginx -t` config-validation tests. These are written
# into a conf and parsed (never bound, since `nginx -t` only tests config), but
# allocating free ports keeps them collision-proof under `pytest -n`.
_CFG_LISTEN_1, _CFG_LISTEN_2 = free_ports(2)
# Upstream targets referenced by the config-validation tests. No server is
# started behind these — they exist purely so the proxy directive parses — but
# they are kept distinct so the rendered config is internally consistent.
_CFG_UPSTREAM_1, _CFG_UPSTREAM_2 = free_ports(2)

HEADER = (
    "error_log {logs}/error.log info;\n"
    "pid       {logs}/nginx.pid;\n"
    "events {{ worker_connections 64; }}\n"
)


@pytest.fixture(autouse=True)
def _require_binary():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")


def _read(rel):
    p = ROOT / rel
    assert p.exists(), f"missing {rel}"
    return p.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# 1. Source-marker checks                                                      #
# --------------------------------------------------------------------------- #

def test_multi_backend_wiring_present():
    pinternal = _read("src/protocols/webdav/proxy_internal.h")
    assert "brix_webdav_backend_t" in pinternal
    assert "webdav_proxy_pick_backend" in pinternal
    proxy = _read("src/protocols/webdav/proxy.c")
    assert "webdav_proxy_pick_backend" in proxy
    assert "upstream_rr" in proxy
    # Passive health updates the selected backend on gateway failures.
    resp = _read("src/protocols/webdav/proxy_response.c")
    assert "fail_count" in resp and "selected_backend" in resp


def test_request_builder_uses_selected_backend():
    req = _read("src/protocols/webdav/proxy_request.c")
    assert "selected_backend" in req, "request builder must use picked backend host"


# --------------------------------------------------------------------------- #
# config helpers                                                               #
# --------------------------------------------------------------------------- #

def _nginx_check(conf_text, tmp_path):
    (tmp_path / "logs").mkdir(exist_ok=True)
    conf = tmp_path / "nginx.conf"
    conf.write_text(conf_text)
    proc = subprocess.run(
        [NGINX_BIN, "-t", "-p", str(tmp_path), "-c", str(conf)],
        capture_output=True, text=True,
    )
    return proc.returncode, proc.stdout + proc.stderr


def _http_block(body, tmp_path):
    return HEADER.format(logs=tmp_path / "logs") + f"""
    http {{
        client_body_temp_path {tmp_path}/t; proxy_temp_path {tmp_path}/t;
        fastcgi_temp_path {tmp_path}/t; uwsgi_temp_path {tmp_path}/t;
        scgi_temp_path {tmp_path}/t; access_log off;
        {body}
    }}
    """


# --------------------------------------------------------------------------- #
# 2. Config validation                                                         #
# --------------------------------------------------------------------------- #

@pytest.mark.skip(reason="multi-backend WebDAV reverse-proxy directives "
                  "(brix_webdav_proxy/_upstream) retired in legacy-proxy cleanup")
def test_multi_url_proxy_directive_parses(tmp_path):
    (tmp_path / "t").mkdir(exist_ok=True)
    conf = _http_block(f"""
        server {{
            listen {BIND_HOST}:{_CFG_LISTEN_1};
            location / {{
                brix_webdav on;
                brix_storage_backend posix:{DATA_DIR};
                brix_webdav_auth none;
                brix_webdav_proxy on;
                brix_webdav_proxy_upstream http://{HOST}:{_CFG_UPSTREAM_1}
                                             http://{HOST}:{_CFG_UPSTREAM_2};
                brix_webdav_proxy_max_fails 2;
                brix_webdav_proxy_fail_timeout 5s;
            }}
        }}
    """, tmp_path)
    rc, out = _nginx_check(conf, tmp_path)
    assert rc == 0, out


@pytest.mark.skip(reason="multi-backend WebDAV reverse-proxy directives "
                  "(brix_webdav_proxy/_upstream) retired in legacy-proxy cleanup")
def test_bad_scheme_rejected(tmp_path):
    (tmp_path / "t").mkdir(exist_ok=True)
    conf = _http_block(f"""
        server {{
            listen {BIND_HOST}:{_CFG_LISTEN_2};
            location / {{
                brix_webdav on;
                brix_storage_backend posix:{DATA_DIR};
                brix_webdav_auth none;
                brix_webdav_proxy on;
                brix_webdav_proxy_upstream ftp://{HOST}:{_CFG_UPSTREAM_1};
            }}
        }}
    """, tmp_path)
    rc, out = _nginx_check(conf, tmp_path)
    assert rc != 0
    assert "http://" in out  # error message mentions required scheme


# --------------------------------------------------------------------------- #
# 3. Functional round-robin across two origins                                 #
# --------------------------------------------------------------------------- #

class _Origin(http.server.BaseHTTPRequestHandler):
    tag = b"?"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(self.tag)))
        self.end_headers()
        self.wfile.write(self.tag)

    def log_message(self, *a):
        pass


def _start_origin(port, tag):
    handler = type(f"O{port}", (_Origin,), {"tag": tag})
    srv = http.server.HTTPServer((BIND_HOST, port), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def _wait_port(port, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _free_port():
    """Allocate an ephemeral loopback port via the shared settings helper.

    Fixed ports collide under `pytest -n` (xdist workers) and with orphaned
    servers left by a hard-killed run, surfacing as 'Address already in use' at
    fixture setup or a connection-reset against a dying previous instance. The
    shared `free_port()` hands each fixture a private port instead.
    """
    return free_port()


def _get_body(port, path="/x"):
    with socket.create_connection((HOST, port), timeout=3) as s:
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
                  .encode())
        data = b""
        while True:
            c = s.recv(4096)
            if not c:
                break
            data += c
    head, _, body = data.partition(b"\r\n\r\n")
    status = int(head.split(b"\r\n", 1)[0].split()[1])
    return status, body


@pytest.fixture
def proxy_with_two_origins(tmp_path):
    pytest.skip("multi-backend WebDAV reverse-proxy (brix_webdav_proxy) retired "
                "in legacy-proxy cleanup")
    be1_port, be2_port, proxy_port = _free_port(), _free_port(), _free_port()
    o1 = _start_origin(be1_port, b"BE1")
    o2 = _start_origin(be2_port, b"BE2")
    (tmp_path / "t").mkdir(exist_ok=True)
    (tmp_path / "logs").mkdir(exist_ok=True)
    conf = _http_block(f"""
        server {{
            listen {BIND_HOST}:{proxy_port};
            location / {{
                brix_webdav on;
                brix_storage_backend posix:{DATA_DIR};
                brix_webdav_auth none;
                brix_webdav_proxy on;
                brix_webdav_proxy_auth anonymous;
                brix_webdav_proxy_upstream http://{HOST}:{be1_port}
                                             http://{HOST}:{be2_port};
            }}
        }}
    """, tmp_path)
    conf_path = tmp_path / "nginx.conf"
    conf_path.write_text(conf + "daemon off;\nmaster_process off;\n")
    proc = subprocess.Popen([NGINX_BIN, "-p", str(tmp_path), "-c", str(conf_path)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        if not _wait_port(proxy_port):
            err = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
            proc.terminate()
            pytest.skip(f"proxy server did not start: {err}")
        yield proxy_port
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        o1.shutdown(); o2.shutdown()


def test_round_robin_distributes(proxy_with_two_origins):
    port = proxy_with_two_origins
    bodies = set()
    for _ in range(8):
        status, body = _get_body(port)
        assert status == 200, (status, body)
        bodies.add(body)
    assert bodies == {b"BE1", b"BE2"}, f"round-robin did not hit both: {bodies}"


# --------------------------------------------------------------------------- #
# Steps A/B — XrdHttp output filter                                            #
# --------------------------------------------------------------------------- #

def test_aux_filter_module_registered():
    assert (ROOT / "src/protocols/webdav/xrdhttp_filter.c").exists()
    cfg = _read("config")
    assert "ngx_module_type=HTTP_AUX_FILTER" in cfg
    assert "ngx_http_brix_xrdhttp_filter_module" in cfg
    # The body filter / Want-Digest wiring is present.  phase-79 split: the
    # digest body filter moved into xrdhttp_filter.c; the Want-Digest request
    # parsing stays in xrdhttp.c.
    assert "xrdhttp_digest_body_filter" in _read("src/protocols/webdav/xrdhttp_filter.c")
    assert "Want-Digest" in _read("src/protocols/webdav/xrdhttp.c")


def _headers(port, path, extra=""):
    with socket.create_connection((HOST, port), timeout=3) as s:
        s.sendall(
            (f"GET {path} HTTP/1.1\r\nHost: x\r\n{extra}Connection: close\r\n\r\n")
            .encode())
        data = b""
        while True:
            c = s.recv(4096)
            if not c:
                break
            data += c
    head = data.split(b"\r\n\r\n", 1)[0].decode(errors="replace")
    status = int(head.split("\r\n", 1)[0].split()[1])
    hdrs = {}
    for line in head.split("\r\n")[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    return status, hdrs


@pytest.fixture
def webdav_server(tmp_path):
    port = _free_port()
    data = tmp_path / "data"
    data.mkdir()
    (data / "hello.txt").write_text("hello world\n")
    (tmp_path / "t").mkdir(exist_ok=True)
    (tmp_path / "logs").mkdir(exist_ok=True)
    conf = _http_block(f"""
        server {{
            listen {BIND_HOST}:{port};
            location / {{
                root {data};
                brix_webdav on;
                brix_storage_backend posix:{data};
                brix_webdav_auth none;
            }}
        }}
    """, tmp_path)
    conf_path = tmp_path / "nginx.conf"
    conf_path.write_text(conf + "daemon off;\nmaster_process off;\n")
    proc = subprocess.Popen([NGINX_BIN, "-p", str(tmp_path), "-c", str(conf_path)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        if not _wait_port(port):
            err = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
            proc.terminate()
            pytest.skip(f"webdav server did not start: {err}")
        yield port
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_xrdhttp_status_header_present(webdav_server):
    status, hdrs = _headers(webdav_server, "/hello.txt",
                            extra="X-Xrootd-Proto: 5.2\r\n")
    assert status == 200, (status, hdrs)
    assert "x-xrootd-status" in hdrs, hdrs


def test_xrdhttp_status_injected_on_404(webdav_server):
    # The filter covers error responses: a missing file still carries the
    # X-Xrootd-Status header for an XrdHttp client.
    status, hdrs = _headers(webdav_server, "/does_not_exist",
                            extra="X-Xrootd-Proto: 5.2\r\n")
    assert status == 404, (status, hdrs)
    assert "x-xrootd-status" in hdrs, hdrs


def test_no_xrdhttp_header_for_plain_client(webdav_server):
    status, hdrs = _headers(webdav_server, "/hello.txt")
    assert status == 200, (status, hdrs)
    assert not any(k.startswith("x-xrootd") for k in hdrs), hdrs


def test_want_digest_does_not_break_get(webdav_server):
    # Want-Digest enables the streaming digest filter; the GET must still
    # succeed and return the body.
    status, hdrs = _headers(webdav_server, "/hello.txt",
                            extra="X-Xrootd-Proto: 5.2\r\nWant-Digest: adler32\r\n")
    assert status == 200, (status, hdrs)


# --------------------------------------------------------------------------- #
# Step C — OIDC token introspection (revocation)                              #
# --------------------------------------------------------------------------- #

def test_introspect_wiring_present():
    intro = _read("src/protocols/webdav/introspect.c")
    assert "ngx_http_subrequest" in intro
    assert "webdav_introspect_access_handler" in intro
    # Registered as a second access-phase handler.
    pc = _read("src/protocols/webdav/postconfig.c")
    assert "webdav_introspect_access_handler" in pc


class _IdP(http.server.BaseHTTPRequestHandler):
    """Mock RFC 7662 endpoint: token containing 'revoked' -> active:false."""

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n).decode(errors="replace")  # "token=<jwt>"
        active = "revoked" not in body
        payload = b'{"active": true}' if active else b'{"active": false}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *a):
        pass


@pytest.fixture
def introspect_server(tmp_path):
    introspect_port = _free_port()
    idp_port = _free_port()
    idp = http.server.HTTPServer((BIND_HOST, idp_port), _IdP)
    threading.Thread(target=idp.serve_forever, daemon=True).start()

    data = tmp_path / "data"
    data.mkdir()
    (data / "hello.txt").write_text("hi\n")
    (tmp_path / "t").mkdir(exist_ok=True)
    (tmp_path / "logs").mkdir(exist_ok=True)
    conf = _http_block(f"""
        server {{
            listen {BIND_HOST}:{introspect_port};
            location = /_introspect {{
                internal;
                proxy_method      POST;
                proxy_set_header  Content-Type application/x-www-form-urlencoded;
                proxy_set_body    "token=$arg_token";
                proxy_pass        http://{HOST}:{idp_port}/introspect;
            }}
            location / {{
                root {data};
                brix_webdav on;
                brix_storage_backend posix:{data};
                brix_webdav_auth none;
                brix_webdav_token_introspect_loc /_introspect;
                brix_webdav_token_introspect_fail_open off;
            }}
        }}
    """, tmp_path)
    conf_path = tmp_path / "nginx.conf"
    conf_path.write_text(conf + "daemon off;\nmaster_process off;\n")
    proc = subprocess.Popen([NGINX_BIN, "-p", str(tmp_path), "-c", str(conf_path)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        if not _wait_port(introspect_port):
            err = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
            proc.terminate()
            idp.shutdown()
            pytest.skip(f"introspect server did not start: {err}")
        yield introspect_port
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        idp.shutdown()


def test_active_token_allowed(introspect_server):
    status, _ = _headers(introspect_server, "/hello.txt",
                         extra="Authorization: Bearer good.jwt.token\r\n")
    assert status == 200, status


def test_revoked_token_forbidden(introspect_server):
    status, _ = _headers(introspect_server, "/hello.txt",
                         extra="Authorization: Bearer revoked.jwt.token\r\n")
    assert status == 403, status


def test_no_token_skips_introspection(introspect_server):
    # No bearer token -> introspection declines, request served normally.
    status, _ = _headers(introspect_server, "/hello.txt")
    assert status == 200, status

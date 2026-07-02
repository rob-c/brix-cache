"""
Phase-65 bad-actor guard — ARC profile (ngx_http_xrootd_guard_module).

Self-contained: spins up a hit-counting stub backend plus an nginx with
`xrootd_guard on; xrootd_guard_profile arc;` in front of a stock proxy_pass,
and drives real HTTP through the guard.

Verifies: ACCESS-phase pre-backend bounce (signature + grammar, backend never
touched), clean ARC requests proxied untouched, LOG-phase audit lines for
backend 404 (notfound) / 401 (authfail), and that clean traffic is never
logged.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
        pytest tests/test_arc_guard.py -v -p no:xdist
"""

import http.client
import http.server
import os
import socket
import subprocess
import threading
import time

import pytest

from settings import HOST, BIND_HOST

NGINX_BIN = os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")

pytestmark = pytest.mark.timeout(120)


def _free_port():
    s = socket.socket()
    s.bind((BIND_HOST, 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _StubHandler(http.server.BaseHTTPRequestHandler):
    """Counts hits; replies with the server's configurable status."""

    def _reply(self):
        self.server.hits += 1
        status = self.server.reply_status
        body = b"stub-ok\n"
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_PUT = do_POST = do_DELETE = _reply

    def log_message(self, *args):
        pass


class StubBackend:
    """Thread-hosted stub upstream with a hit counter + settable status."""

    def __init__(self):
        self.port = _free_port()
        self.httpd = http.server.ThreadingHTTPServer(
            (BIND_HOST, self.port), _StubHandler)
        self.httpd.hits = 0
        self.httpd.reply_status = 200
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def hits(self):
        return self.httpd.hits

    @property
    def reply_status(self):
        return self.httpd.reply_status

    @reply_status.setter
    def reply_status(self, status):
        self.httpd.reply_status = status

    def reset(self):
        self.httpd.hits = 0
        self.httpd.reply_status = 200

    def stop(self):
        self.httpd.shutdown()


class AuditLog:
    """Reader for the guard audit log file."""

    def __init__(self, path):
        self.path = path

    def lines(self):
        if not os.path.exists(self.path):
            return []
        with open(self.path) as f:
            return [ln.rstrip("\n") for ln in f if ln.strip()]

    def line_count(self):
        return len(self.lines())

    def wait_for_count(self, count, timeout=5.0):
        """LOG-phase writes race the client's response read; poll briefly."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.line_count() >= count:
                return True
            time.sleep(0.05)
        return False

    def last_line_has(self, **tokens):
        lines = self.lines()
        assert lines, "audit log is empty"
        last = lines[-1]
        return all(f"{key}={val}" in last for key, val in tokens.items())


class GuardServer:
    """HTTP driver that maps a dropped connection (bounce 444) to code 444."""

    def __init__(self, base_host, port):
        self.host = base_host
        self.port = port

    def get(self, path, headers=None):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=5)
        try:
            conn.request("GET", path, headers=headers or {})
            resp = conn.getresponse()
            resp.read()
            return resp
        except (http.client.BadStatusLine, http.client.RemoteDisconnected,
                ConnectionResetError):

            class _Dropped:
                status = 444
                status_code = 444

            return _Dropped()
        finally:
            conn.close()

    def wait_ready(self):
        for _ in range(50):
            try:
                if self.get("/arex/ready") is not None:
                    return
            except Exception:
                pass
            time.sleep(0.1)


@pytest.fixture(scope="module")
def stub_backend():
    backend = StubBackend()
    yield backend
    backend.stop()


@pytest.fixture(scope="module")
def _server(tmp_path_factory, stub_backend):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")

    root = tmp_path_factory.mktemp("arcguard")
    audit_path = root / "guard-audit.log"
    guard_port = _free_port()
    conf = root / "nginx.conf"
    conf.write_text(f"""
worker_processes 1;
pid {root}/nginx.pid;
error_log {root}/error.log info;
events {{ worker_connections 64; }}
http {{
    access_log off;
    client_body_temp_path {root}/tmp;
    proxy_temp_path {root}/tmp;
    fastcgi_temp_path {root}/tmp;
    uwsgi_temp_path {root}/tmp;
    scgi_temp_path {root}/tmp;
    server {{
        listen {BIND_HOST}:{guard_port};
        location / {{
            xrootd_guard on;
            xrootd_guard_profile arc;
            xrootd_guard_audit_log {audit_path};
            proxy_pass http://{BIND_HOST}:{stub_backend.port};
        }}
    }}
}}
""")
    rc = subprocess.run([NGINX_BIN, "-t", "-c", str(conf)],
                        capture_output=True, text=True)
    if rc.returncode != 0:
        pytest.skip(f"nginx -t failed: {rc.stderr}")
    subprocess.run([NGINX_BIN, "-c", str(conf)], capture_output=True)
    server = GuardServer(HOST, guard_port)
    server.wait_ready()
    yield {"server": server, "audit": AuditLog(str(audit_path))}
    subprocess.run([NGINX_BIN, "-c", str(conf), "-s", "stop"],
                   capture_output=True)


@pytest.fixture()
def guard_server(_server, stub_backend):
    stub_backend.reset()
    return _server["server"]


@pytest.fixture()
def audit_log(_server):
    return _server["audit"]


class TestArcGuardAccess:
    def test_signature_bounced_pre_backend(self, guard_server, stub_backend):
        """A scanner signature is bounced before the backend sees it."""
        r = guard_server.get("/wp-login.php")
        assert r.status == 444, f"expected bounce, got {r.status}"
        assert stub_backend.hits == 0, "backend must never see junk"

    def test_valid_arc_request_proxied(self, guard_server, stub_backend):
        """A clean ARC REST request passes through to the backend."""
        r = guard_server.get("/arex/rest/1.0/info")
        assert r.status == 200, f"clean request failed: {r.status}"
        assert stub_backend.hits == 1, "backend should see exactly one hit"

    def test_grammar_violation_bounced(self, guard_server, stub_backend):
        """A path outside the ARC namespace is bounced pre-backend."""
        r = guard_server.get("/random/scan")
        assert r.status == 444, f"expected bounce, got {r.status}"
        assert stub_backend.hits == 0, "backend must never see off-namespace"

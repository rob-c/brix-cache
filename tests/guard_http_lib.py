"""
Shared harness for the phase-65 HTTP guard tests (test_arc_guard.py,
test_xrdhttp_guard.py): a hit-counting stub backend, an audit-log reader,
and an HTTP driver that maps nginx's 444 connection-drop to status 444.
"""

import http.client
import http.server
import os
import socket
import threading
import time

from settings import BIND_HOST

NGINX_BIN = os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")


def free_port():
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
        self.port = free_port()
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

    def wait_ready(self, probe_path="/"):
        for _ in range(50):
            try:
                if self.get(probe_path) is not None:
                    return
            except Exception:
                pass
            time.sleep(0.1)

"""
Shared harness for the phase-65 HTTP guard tests (test_arc_guard.py,
test_xrdhttp_guard.py): a hit-counting stub backend, an audit-log reader,
and an HTTP driver that maps nginx's 444 connection-drop to status 444.
"""

import http.client
import json
import os
import time

from settings import HOST, GUARD_STUB_PORT

NGINX_BIN = os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")


class StubBackend:
    """Client of the fixed-port ``guard-stub`` fleet mock (lib/guard_stub_server.py).

    Formerly a per-test in-process ThreadingHTTPServer; now the mock is a single
    registry-managed ``proc`` singleton on ``GUARD_STUB_PORT`` that every guard
    test declares (``@pytest.mark.registry_server("guard-stub")``).  This object
    is the out-of-band control client: it reads the hit counter and drives the
    reply status over the mock's tiny control API.  The counter is shared global
    state, so the two guard suites run ``serial`` and each test ``reset()``s
    first — see lib/guard_stub_server.py for the contract.
    """

    def __init__(self, host=None, port=None):
        self.host = host or HOST
        self.port = port or GUARD_STUB_PORT

    def _call(self, method, path):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=5)
        try:
            conn.request(method, path)
            resp = conn.getresponse()
            return resp.read()
        finally:
            conn.close()

    @property
    def hits(self):
        return json.loads(self._call("GET", "/__introspect"))["hits"]

    @property
    def reply_status(self):
        return json.loads(self._call("GET", "/__introspect"))["reply_status"]

    @reply_status.setter
    def reply_status(self, status):
        self._call("POST", f"/__status/{int(status)}")

    def reset(self):
        self._call("POST", "/__reset")

    def stop(self):
        """No-op: the registry owns the mock's lifecycle (it is a fleet spec)."""


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

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=5)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            resp.body = resp.read()
            return resp
        except (http.client.BadStatusLine, http.client.RemoteDisconnected,
                ConnectionResetError, BrokenPipeError):

            class _Dropped:
                status = 444
                status_code = 444
                body = b""

            return _Dropped()
        finally:
            conn.close()

    def get(self, path, headers=None):
        return self.request("GET", path, headers=headers)

    def wait_ready(self, probe_path="/"):
        for _ in range(50):
            try:
                if self.get(probe_path) is not None:
                    return
            except Exception:
                pass
            time.sleep(0.1)

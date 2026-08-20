#!/usr/bin/env python3
"""guard_stub_server.py — the hit-counting HTTP upstream for the phase-65 guard
suites (test_arc_guard.py, test_xrdhttp_guard.py), as a standalone fixed-port
``proc`` fleet spec instead of a per-test in-process thread.

The guard nginx proxies clean (non-bounced) traffic here; the tests assert the
backend saw an EXACT number of hits and drive its reply status.  Captured state
lives behind a small control API so a client (``guard_http_lib.StubBackend``)
can read it out-of-band:

    GET  /__introspect   -> {"hits": <int>, "reply_status": <int>}
    POST /__reset        -> hits:=0, reply_status:=200
    POST /__status/<n>   -> reply_status:=<n>

Any other method/path is the stub reply itself: it bumps ``hits`` and answers
with the current ``reply_status`` and a fixed body.

Because the counter and status are shared global state, the two guard suites
that use this mock are marked ``serial`` (one xdist worker, sequential), and
each test ``POST /__reset``s before it runs — so the exact-count contract holds.

Usage:  guard_stub_server.py            # binds settings.GUARD_STUB_PORT
        guard_stub_server.py <port>     # explicit port override

Runs in the foreground; the registry launcher backgrounds it and probes the
port for readiness.
"""

import http.server
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from settings import BIND_HOST, GUARD_STUB_PORT  # noqa: E402


class _Handler(http.server.BaseHTTPRequestHandler):
    def _json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _control(self):
        """Handle a control-API path; return True if it was one."""
        path = self.path.split("?", 1)[0]
        if path == "/__introspect":
            self._json({"hits": self.server.hits,
                        "reply_status": self.server.reply_status})
            return True
        if path == "/__reset":
            self.server.hits = 0
            self.server.reply_status = 200
            self._json({"ok": True})
            return True
        if path.startswith("/__status/"):
            try:
                self.server.reply_status = int(path.rsplit("/", 1)[1])
                self._json({"ok": True})
            except ValueError:
                self._json({"ok": False}, status=400)
            return True
        return False

    def _reply(self):
        if self._control():
            return
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


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else GUARD_STUB_PORT
    httpd = http.server.ThreadingHTTPServer((BIND_HOST, port), _Handler)
    httpd.hits = 0
    httpd.reply_status = 200
    httpd.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""mirror_shadow_server.py — the hit-recording shadow upstream for the phase-24
mirror suite (test_phase24_mirror.py), as a standalone fixed-port ``proc`` fleet
spec instead of a per-test in-process thread.

The mirror nginx replays selected client requests here; the tests assert which
paths/methods the shadow saw, that the client's Authorization header was
stripped, and that write bodies arrive byte-exact.  Captured state lives behind
a small control API so a client (``ShadowClient`` in test_phase24_mirror.py) can
read it out-of-band:

    GET  /__introspect   -> {"received": [[path, {header: value}], ...],
                             "methods":  [[method, path], ...],
                             "bodies":   {path: <base64 body>}}
    POST /__reset        -> clear all captured state

Any other method/path is a real mirrored request: read methods (GET/HEAD) reply
200 SHADOW; write methods (PUT/DELETE/MKCOL/MOVE/COPY) capture the body and reply
201.  Control paths (``/__*``) are intercepted before recording.

Because the capture is shared global state, the mirror suite is marked ``serial``
(one xdist worker, sequential) and each shadow-using test ``POST /__reset``s
first — so the exact-capture contract holds.

Usage:  mirror_shadow_server.py            # binds settings.MIRROR_SHADOW_PORT
        mirror_shadow_server.py <port>     # explicit port override

Runs in the foreground; the registry launcher backgrounds it and probes the port
for readiness.
"""

import base64
import http.server
import json
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from settings import BIND_HOST, MIRROR_SHADOW_PORT  # noqa: E402


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
            srv = self.server
            with srv.lock:
                self._json({
                    "received": [[p, h] for p, h in srv.received],
                    "methods": [[m, p] for m, p in srv.methods],
                    "bodies": {p: base64.b64encode(b).decode()
                               for p, b in srv.bodies.items()},
                })
            return True
        if path == "/__reset":
            srv = self.server
            with srv.lock:
                srv.received = []
                srv.bodies = {}
                srv.methods = []
            self._json({"ok": True})
            return True
        return False

    def _record(self):
        if self._control():
            return
        srv = self.server
        with srv.lock:
            srv.received.append(
                (self.path, {k.lower(): v for k, v in self.headers.items()}))
            srv.methods.append((self.command, self.path))
        body = b"SHADOW\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _record_write(self):
        clen = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(clen) if clen else b""
        srv = self.server
        with srv.lock:
            srv.received.append(
                (self.path, {k.lower(): v for k, v in self.headers.items()}))
            srv.bodies[self.path] = body
            srv.methods.append((self.command, self.path))
        self.send_response(201)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = _record
    do_HEAD = _record
    # POST carries the /__reset control path; fall through _record_write's
    # control check but never record a bare POST as a mirrored write.
    def do_POST(self):
        if self._control():
            return
        self._record_write()

    do_PUT = _record_write
    do_DELETE = _record_write
    do_MKCOL = _record_write
    do_MOVE = _record_write
    do_COPY = _record_write

    def log_message(self, *args):
        pass


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else MIRROR_SHADOW_PORT
    httpd = http.server.ThreadingHTTPServer((BIND_HOST, port), _Handler)
    httpd.lock = threading.Lock()
    httpd.received = []
    httpd.bodies = {}
    httpd.methods = []
    httpd.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())

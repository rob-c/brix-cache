#!/usr/bin/env python3
"""static_origin_server.py — a stateless ``ORIGIN-OK`` backend for the dashboard
admin-API URL-validation coverage (test_phase23_admin_api.py), as a standalone
fixed-port ``proc`` fleet spec instead of a per-test in-process thread.

The admin nginx merely needs *a* live backend to point URL-validation at; the
tests never introspect it, so there is no control API — every GET answers with a
fixed body.

Usage:  static_origin_server.py            # binds settings.STATIC_ORIGIN_PORT
        static_origin_server.py <port>     # explicit port override

Runs in the foreground; the registry launcher backgrounds it and probes the port
for readiness.
"""

import http.server
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from settings import BIND_HOST, STATIC_ORIGIN_PORT  # noqa: E402


class _Handler(http.server.BaseHTTPRequestHandler):
    tag = b"ORIGIN-OK"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(self.tag)))
        self.end_headers()
        self.wfile.write(self.tag)

    def log_message(self, *args):
        pass


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else STATIC_ORIGIN_PORT
    httpd = http.server.ThreadingHTTPServer((BIND_HOST, port), _Handler)
    httpd.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())

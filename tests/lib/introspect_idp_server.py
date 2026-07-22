#!/usr/bin/env python3
"""introspect_idp_server.py — a mock RFC 7662 OAuth token-introspection endpoint
for the phase-21 OIDC revocation coverage (test_phase21_proxy_filter.py), as a
standalone fixed-port ``proc`` fleet spec instead of a per-test in-process thread.

The introspection reply is a pure function of the presented token: a POST body
containing ``revoked`` answers ``{"active": false}``; anything else answers
``{"active": true}``.  There is no captured state, so no control API.

Usage:  introspect_idp_server.py            # binds settings.INTROSPECT_IDP_PORT
        introspect_idp_server.py <port>     # explicit port override

Runs in the foreground; the registry launcher backgrounds it and probes the port
for readiness.
"""

import http.server
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from settings import BIND_HOST, INTROSPECT_IDP_PORT  # noqa: E402


class _Handler(http.server.BaseHTTPRequestHandler):
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

    def log_message(self, *args):
        pass


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else INTROSPECT_IDP_PORT
    httpd = http.server.ThreadingHTTPServer((BIND_HOST, port), _Handler)
    httpd.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""fwd_oidc_server.py — a minimal HTTPS OIDC discovery server for the
credential-forwarding matrix (pairing A, token cells).

Stock xrootd's ztn + libXrdAccSciTokens REJECTS an http:// issuer: SciTokens
requires the OIDC discovery document (``.well-known/openid-configuration``) and
the JWKS to be served over TLS with a certificate the fetching process trusts.
This server wraps ``http.server.SimpleHTTPRequestHandler`` in an
``ssl.SSLContext`` using the shared test hostcert/hostkey (which carry
``localhost`` + ``127.0.0.1`` SANs), so a token origin can fetch
``https://localhost:PORT/.well-known/openid-configuration`` and ``/jwks.json``.

Usage:  fwd_oidc_server.py <serve_dir> <port> <certfile> <keyfile>

Runs in the foreground; the caller backgrounds it and records the PID for
scoped teardown.  Access is logged to stderr (the caller redirects it).
"""

import http.server
import os
import ssl
import sys


def main() -> int:
    if len(sys.argv) != 5:
        print("usage: fwd_oidc_server.py <dir> <port> <cert> <key>",
              file=sys.stderr)
        return 2
    serve_dir, port, cert, key = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
    os.chdir(serve_dir)

    httpd = http.server.HTTPServer(("127.0.0.1", port),
                                   http.server.SimpleHTTPRequestHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    httpd.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())

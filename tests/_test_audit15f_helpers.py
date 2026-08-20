"""Shared drive-side plumbing for the audit-15f files.

Two unrelated groups of subjects share this module.

The WebDAV TPC files (`test_audit15f_webdav_tpc_tuning.py`,
`test_audit15f_tpc_cred_forward.py`) need the same two things: a TLS pull source
that RECORDS what the destination asked it for (method, path, Range,
Authorization), and a certificate the destination will accept — TPC legs always
verify peer and host (`CURLOPT_SSL_VERIFYPEER`/`VERIFYHOST`,
tpc_curl_setup.c:42-43), and the fleet PKI is not guaranteed to exist on a
developer box.  The mock is deliberately a plain `http.server`: the point of
every assertion is what arrived on the wire, so the source must be dumb and
observable.

The CMS dead-peer files (`test_audit15f_cluster_tuning.py`,
`test_audit15f_cms_node_legs.py`) need the kernel's view of a socket:
`brix_apply_tcp_deadpeer_opts` (connection/netopt.h) applies SO_KEEPALIVE and
its probe schedule best-effort and silently, so `ss -tno`'s timer column is the
only place the option is externally visible.
"""

from __future__ import annotations

import re
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from settings import HOST


def mint_localhost_cert(tmp_path, stem="mock-source"):
    """Self-signed, CA-flagged cert SAN-bound to the loopback literal the pull
    leg dials.  It doubles as the CA file the destination is configured to
    trust, so one artefact covers both ends."""
    cert = tmp_path / f"{stem}.pem"
    key = tmp_path / f"{stem}.key"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "2",
         # The pull leg verifies these names against its own trust store.
         "-subj", "/CN=localhost",  # net-literal-allow: cert subject under test
         "-addext", f"subjectAltName=IP:{HOST},DNS:localhost"],  # net-literal-allow: cert SAN under test
        check=True, capture_output=True)
    return cert, key


class CapturingSource(BaseHTTPRequestHandler):
    """TLS pull source.  Any path answers HEAD/GET (honouring Range); a path
    starting with `/slow` dribbles a few bytes and then goes quiet for
    `server.stall_secs`, which is what a low-speed bound exists to abort."""

    protocol_version = "HTTP/1.1"

    def _record(self):
        self.server.recorded.append({
            "method": self.command,
            "path": self.path,
            "range": self.headers.get("Range"),
            "auth": self.headers.get("Authorization"),
        })

    def do_HEAD(self):
        self._record()
        self.send_response(200)
        self.send_header("Content-Length", str(len(self.server.payload)))
        self.send_header("Accept-Ranges", "bytes")
        self.end_headers()

    def do_GET(self):
        self._record()
        if self.path.startswith("/slow"):
            self._serve_stalled()
            return
        self._serve_object()

    def _serve_object(self):
        payload = self.server.payload
        start, end = 0, len(payload) - 1
        matched = re.match(r"bytes=(\d+)-(\d*)", self.headers.get("Range") or "")
        if matched:
            start = int(matched.group(1))
            if matched.group(2):
                end = int(matched.group(2))
        body = payload[start:end + 1]
        self.send_response(206 if matched else 200)
        if matched:
            self.send_header("Content-Range",
                             f"bytes {start}-{end}/{len(payload)}")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Accept-Ranges", "bytes")
        self.end_headers()
        self.wfile.write(body)

    def _serve_stalled(self):
        payload = self.server.payload
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        try:
            self.wfile.write(payload[:16])
            self.wfile.flush()
            time.sleep(self.server.stall_secs)
            self.wfile.write(payload[16:])
            self.wfile.flush()
        except OSError:
            pass                # the puller hung up — the point of /slow

    def log_message(self, *args):
        pass


def serve(handler, port, *, tls=None, payload=b"", stall_secs=0.0):
    """Start a recording mock on `port` and return it; `.recorded` is the
    request log every assertion reads."""
    server = ThreadingHTTPServer((HOST, port), handler)
    server.daemon_threads = True
    server.recorded = []
    server.payload = payload
    server.stall_secs = stall_secs
    if tls is not None:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def gets(recorded, path):
    return [row for row in recorded
            if row["method"] == "GET" and row["path"] == path]


def heads(recorded, path):
    return [row for row in recorded
            if row["method"] == "HEAD" and row["path"] == path]


# ── kernel socket timers (the dead-peer knobs' only external witness) ─────

SS_BIN = "/usr/sbin/ss"


def ss_established():
    """Established TCP rows as (local, peer, rest) triples from `ss -tno`."""
    out = subprocess.run([SS_BIN, "-tno"], capture_output=True,
                         text=True).stdout
    rows = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5 or parts[0] != "ESTAB":
            continue
        rows.append((parts[3], parts[4], " ".join(parts[5:])))
    return rows


def socket_timers(*, local_port=None, peer_port=None, timeout=6.0):
    """The trailing columns (timer:(...) among them) of the one established
    socket whose local and/or peer port match.

    A keepalive-armed socket reads `timer:(keepalive,29sec,0)`; a bare one
    carries no timer at all.  Polls, because the socket appears only once the
    peer has finished connecting.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        for local, peer, rest in ss_established():
            if local_port is not None and not local.endswith(f":{local_port}"):
                continue
            if peer_port is not None and not peer.endswith(f":{peer_port}"):
                continue
            return rest
        time.sleep(0.2)
    raise AssertionError(
        f"no established socket local={local_port} peer={peer_port}")

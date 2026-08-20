#!/usr/bin/env python3
# tests/rpm/mock_repo.py — a repository origin with a control plane, for the
# phase-104 D15.9 native mirror lane.
#
# WHAT: serves a directory tree of real repository bytes (built by
#       `brixrpm createrepo` over the D12 fixture packages) and records every
#       request, so a lane can assert what did — and did not — leave the box.
# WHY:  the mirror's whole job is "one upstream GET per object, verified at
#       the edge, never again". Neither half of that is observable from the
#       client side alone: a cache hit and a re-fetch look identical over the
#       wire, and a tampered file is only interesting if the tampering is
#       something the test chose. A plain `http.server` gives neither.
# HOW:  same control-plane shape as tests/oci/mock_registry.py — GET /ctl/log
#       for the request journal, POST /ctl/reset to clear it, POST /ctl/fault
#       to arm a fault. Faults are one-shot-until-cleared and select by path
#       regex, so a lane arms exactly the object it means:
#         tamper      — serve bytes that do NOT hash to the name they carry
#         notfound    — 404
#         error       — 503
#         hang        — sleep past any sane read timeout
#       Everything not under /ctl/ is a file read out of --root.
#
# Standalone: `python3 tests/rpm/mock_repo.py --port N --root DIR`.
import argparse
import json
import os
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

STATE = {"log": [], "fault": {"kind": "none", "path_re": None},
         "root": None, "lock": threading.Lock()}

FAULTS = ("none", "tamper", "notfound", "error", "hang")


def _fault_for(path):
    """The armed fault iff it selects `path` ('none' otherwise)."""
    with STATE["lock"]:
        fault = dict(STATE["fault"])
    if fault["kind"] == "none":
        return "none"
    pattern = fault["path_re"]
    if pattern and not re.search(pattern, path):
        return "none"
    return fault["kind"]


def _resolve(path):
    """Map a request path to a file under the served root, or None.

    O_NOFOLLOW-grade containment is not the point here (this is a fixture),
    but a mock that happily served /etc/passwd would make the mirror's own
    traversal refusal untestable: the lane could not tell a refusal from a
    404. So the resolved path must stay under the root.
    """
    root = os.path.realpath(STATE["root"])
    target = os.path.realpath(os.path.join(root, unquote(path).lstrip("/")))
    if target != root and not target.startswith(root + os.sep):
        return None
    return target if os.path.isfile(target) else None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):        # quiet: the journal IS the log
        pass

    def _record(self, method):
        with STATE["lock"]:
            STATE["log"].append({"method": method, "path": self.path,
                                 "range": self.headers.get("Range", ""),
                                 "ts": time.time()})

    def _send(self, status, body=b"", ctype="application/octet-stream",
              headers=()):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, status=200):
        self._send(status, json.dumps(obj).encode(), "application/json")

    def do_GET(self):
        if self.path.startswith("/ctl/"):
            self._ctl_get()
            return
        self._serve()

    def do_HEAD(self):
        self._serve()

    def do_POST(self):
        if not self.path.startswith("/ctl/"):
            self._send(405)
            return
        length = int(self.headers.get("Content-Length") or 0)
        payload = json.loads(self.rfile.read(length) or b"{}")
        route = urlsplit(self.path).path
        if route == "/ctl/reset":
            with STATE["lock"]:
                STATE["log"] = []
                STATE["fault"] = {"kind": "none", "path_re": None}
            self._json({"ok": True})
            return
        if route == "/ctl/fault":
            kind = payload.get("kind", "none")
            if kind not in FAULTS:
                self._json({"error": "unknown fault %r" % kind}, 400)
                return
            with STATE["lock"]:
                STATE["fault"] = {"kind": kind,
                                  "path_re": payload.get("path_re")}
            self._json({"ok": True})
            return
        self._json({"error": "no such control"}, 404)

    def _ctl_get(self):
        if urlsplit(self.path).path == "/ctl/log":
            with STATE["lock"]:
                self._json(list(STATE["log"]))
            return
        self._json({"error": "no such control"}, 404)

    def _serve(self):
        route = urlsplit(self.path).path
        self._record(self.command)
        fault = _fault_for(route)
        if fault == "notfound":
            self._send(404, b"not found\n", "text/plain")
            return
        if fault == "error":
            self._send(503, b"upstream broken\n", "text/plain")
            return
        if fault == "hang":
            time.sleep(120)
            return
        target = _resolve(route)
        if target is None:
            self._send(404, b"not found\n", "text/plain")
            return
        with open(target, "rb") as fh:
            body = fh.read()
        if fault == "tamper":
            # Same length, different bytes: a mirror that only compared sizes
            # would sail past this, which is the point of the leg.
            body = bytes((b ^ 0xFF) for b in body)
        self._send(200, body, headers=(("Accept-Ranges", "bytes"),))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--bind", default="127.0.0.1")  # net-literal-allow: standalone-spawned helper server (no tests/ on sys.path); loopback bind
    ap.add_argument("--root", required=True,
                    help="directory served as the repository origin")
    args = ap.parse_args()
    STATE["root"] = args.root
    ThreadingHTTPServer((args.bind, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()

"""The stub-server base (feature F12).

Stubs are the "other side of the wire" a test needs — an origin, an
OCSP responder, an OIDC endpoint.  The grown suite had eight scripts
sharing nothing; this base gives every stub the same four behaviours:

* **env contract** — bind address and port come from the environment
  the spawning spec provides (``BRIXTEST_PORT``, ``BRIXTEST_BIND``,
  ``BRIXTEST_STUB_NAME``); the backend adds the lane triple
  (``BRIXTEST_LANE_ROOT``/``PORT_BASE``/``PORT_SPAN``) automatically.
* **refusal to bind outside the lane** — a port outside the lane's
  range, or a non-loopback bind without an explicit opt-in, exits 2
  with a one-line reason (the F3 start error carries it as log tail).
  No stub ever becomes a bare listener some other lane trips over.
* **uniform readiness** — one ``stub.ready`` JSONL line the moment the
  socket is bound; TCP readiness probes work unchanged.
* **common access-log line** — one JSONL object per request, the shape
  the F15 event stream can ingest, instead of eight ad-hoc formats.

Subclasses override ``handle(method, path, headers, body)`` and are
run with ``python -m <module>`` via ``Cls.main()``.  Everything is
stdlib; a stub never imports the rest of BriXTest at runtime.
"""

from __future__ import annotations

import json
import os
import signal
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Mapping, Optional, Tuple

__all__ = ["Response", "StubServer"]

_LOCAL_BINDS = frozenset({"127.0.0.1", "localhost", "::1"})
Response = Tuple[int, Mapping[str, str], bytes]


class StubServer:
    """Base class for single-purpose counterpart servers."""

    default_name = "stub"

    def __init__(
        self,
        *,
        name: str,
        bind: str,
        port: int,
        port_base: Optional[int] = None,
        port_span: Optional[int] = None,
        allow_nonlocal: bool = False,
    ) -> None:
        self.name = name
        self.bind = bind
        self.port = port
        self.port_base = port_base
        self.port_span = port_span
        self.allow_nonlocal = allow_nonlocal

    # -- construction ------------------------------------------------------

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "StubServer":
        """The env contract, read once (C2).  ``BRIXTEST_PORT`` is the one
        required variable; everything else has a safe default."""
        env = os.environ if env is None else env
        raw_port = env.get("BRIXTEST_PORT", "")
        if not raw_port.isdigit() or not (0 < int(raw_port) < 65536):
            cls.refuse(
                "BRIXTEST_PORT=%r is not a TCP port — the spawning spec must "
                "set it (e.g. env={'BRIXTEST_PORT': '{port}'})" % raw_port
            )
        base = env.get("BRIXTEST_PORT_BASE", "")
        span = env.get("BRIXTEST_PORT_SPAN", "")
        return cls(
            name=env.get("BRIXTEST_STUB_NAME", cls.default_name),
            bind=env.get("BRIXTEST_BIND", "127.0.0.1"),
            port=int(raw_port),
            port_base=int(base) if base.isdigit() else None,
            port_span=int(span) if span.isdigit() else None,
            allow_nonlocal=env.get("BRIXTEST_STUB_ALLOW_NONLOCAL", "") == "1",
        )

    @staticmethod
    def refuse(reason: str) -> None:
        """Refusal-to-bind contract: one line, exit 2 — the backend's
        StartError surfaces the line as the log tail."""
        print("stub refused: %s" % reason, flush=True)
        raise SystemExit(2)

    def _check_lane(self) -> None:
        if self.bind not in _LOCAL_BINDS and not self.allow_nonlocal:
            self.refuse(
                "bind address %r is not loopback — set "
                "BRIXTEST_STUB_ALLOW_NONLOCAL=1 to mean it" % self.bind
            )
        if self.port_base is not None and self.port_span is not None:
            if not (self.port_base <= self.port < self.port_base + self.port_span):
                self.refuse(
                    "port %d is outside the lane's range %d-%d — no listeners "
                    "outside the lane" % (
                        self.port, self.port_base,
                        self.port_base + self.port_span - 1,
                    )
                )

    # -- subclass surface --------------------------------------------------

    def handle(self, method: str, path: str, headers: Mapping[str, str],
               body: bytes) -> Response:
        """Override me.  The base answers the uniform health check only."""
        if path == "/health":
            return 200, {"content-type": "text/plain"}, b"ok\n"
        return 404, {"content-type": "text/plain"}, b"not found\n"

    # -- the uniform log ---------------------------------------------------

    def emit(self, event: str, **fields: object) -> None:
        record = {"event": event, "stub": self.name,
                  "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        record.update(fields)
        print(json.dumps(record, sort_keys=True), flush=True)

    # -- serving -----------------------------------------------------------

    def serve_forever(self) -> int:
        self._check_lane()
        stub = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _dispatch(self, method: str) -> None:
                length = int(self.headers.get("content-length") or 0)
                body = self.rfile.read(length) if length else b""
                try:
                    status, headers, payload = stub.handle(
                        method, self.path, self.headers, body
                    )
                except Exception as exc:  # a stub survives its handler
                    status = 500
                    headers = {"content-type": "text/plain"}
                    payload = ("stub error: %s\n" % exc).encode()
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                if method != "HEAD":
                    self.wfile.write(payload)
                stub.emit("stub.access", method=method, path=self.path,
                          status=status, bytes=len(payload))

            def do_GET(self) -> None: self._dispatch("GET")
            def do_HEAD(self) -> None: self._dispatch("HEAD")
            def do_POST(self) -> None: self._dispatch("POST")
            def do_PUT(self) -> None: self._dispatch("PUT")
            def do_DELETE(self) -> None: self._dispatch("DELETE")

            def log_message(self, *args: object) -> None:
                pass  # emit() is the access log; stdlib's format is not

        try:
            server = ThreadingHTTPServer((self.bind, self.port), _Handler)
        except OSError as exc:
            self.refuse("cannot bind %s:%d — %s" % (self.bind, self.port, exc))
            return 2  # unreachable; refuse() raises
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
        self.emit("stub.ready", port=self.port, pid=os.getpid())
        try:
            server.serve_forever(poll_interval=0.2)
        finally:
            server.server_close()
        return 0

    @classmethod
    def main(cls) -> int:
        """The ``python -m`` entry point every stub module reuses."""
        return cls.from_env().serve_forever()

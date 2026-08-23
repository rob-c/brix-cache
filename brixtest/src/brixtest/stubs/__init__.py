"""HTTP stub base with lane validation and structured access logs."""

from __future__ import annotations

import functools
import json
import os
import signal
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Mapping, NoReturn, Optional, Tuple

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

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "StubServer":
        """Construct a stub from its process environment."""
        env = _stub_environment(env)
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
            port_base=_optional_integer(base),
            port_span=_optional_integer(span),
            allow_nonlocal=env.get("BRIXTEST_STUB_ALLOW_NONLOCAL", "") == "1",
        )

    @staticmethod
    def refuse(reason: str) -> NoReturn:
        """Report an invalid binding and exit."""
        print("stub refused: %s" % reason, flush=True)
        raise SystemExit(2)

    def _check_lane(self) -> None:
        self._check_bind()
        self._check_port()

    def _check_bind(self) -> None:
        if self.bind not in _LOCAL_BINDS and not self.allow_nonlocal:
            self.refuse(
                "bind address %r is not loopback — set "
                "BRIXTEST_STUB_ALLOW_NONLOCAL=1 to mean it" % self.bind
            )

    def _check_port(self) -> None:
        if self.port_base is None or self.port_span is None:
            return
        upper = _lane_upper(self.port_base, self.port_span)
        if self.port not in range(self.port_base, upper):
            self.refuse(
                "port %d is outside the lane's range %d-%d — no listeners "
                "outside the lane" % (
                    self.port, self.port_base,
                    _last_port(upper),
                )
            )

    def handle(self, method: str, path: str, headers: Mapping[str, str],
               body: bytes) -> Response:
        """Override me.  The base answers the uniform health check only."""
        if path == "/health":
            return 200, {"content-type": "text/plain"}, b"ok\n"
        return 404, {"content-type": "text/plain"}, b"not found\n"

    def emit(self, event: str, **fields: object) -> None:
        record = {"event": event, "stub": self.name,
                  "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        record.update(fields)
        print(json.dumps(record, sort_keys=True), flush=True)

    def serve_forever(self) -> int:
        self._check_lane()
        try:
            handler = functools.partial(_Handler, self)
            server = ThreadingHTTPServer((self.bind, self.port), handler)
        except OSError as exc:
            self.refuse("cannot bind %s:%d — %s" % (self.bind, self.port, exc))
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
        self.emit("stub.ready", port=self.port, pid=os.getpid())
        try:
            server.serve_forever(poll_interval=0.2)
        finally:
            server.server_close()
        return 0

    @classmethod
    def main(cls) -> int:
        """Run the stub configured by the process environment."""
        return cls.from_env().serve_forever()


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def __init__(self, stub: StubServer, *args: object, **kwargs: object) -> None:
        self.stub = stub
        super().__init__(*args, **kwargs)

    def _dispatch(self, method: str) -> None:
        body = self._request_body()
        status, headers, payload = self._response(method, body)
        self._write_response(method, status, headers, payload)
        self.stub.emit(
            "stub.access", method=method, path=self.path,
            status=status, bytes=len(payload),
        )

    def _request_body(self) -> bytes:
        length = int(self.headers.get("content-length") or 0)
        return self.rfile.read(length) if length else b""

    def _response(self, method: str, body: bytes) -> Response:
        try:
            return self.stub.handle(
                method, self.path, self.headers, body
            )
        except Exception as exc:
            return 500, {"content-type": "text/plain"}, (
                "stub error: %s\n" % exc
            ).encode()

    def _write_response(self, method: str, status: int, headers, payload: bytes) -> None:
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        if method != "HEAD":
            self.wfile.write(payload)

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_HEAD(self) -> None:
        self._dispatch("HEAD")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_PUT(self) -> None:
        self._dispatch("PUT")

    def do_DELETE(self) -> None:
        self._dispatch("DELETE")

    def log_message(self, *args: object) -> None:
        pass


def _stub_environment(env: Optional[Mapping[str, str]]) -> Mapping[str, str]:
    return os.environ if env is None else env


def _optional_integer(value: str) -> Optional[int]:
    return int(value) if value.isdigit() else None


def _lane_upper(base: int, span: int) -> int:
    return base + span


def _last_port(upper: int) -> int:
    return upper - 1

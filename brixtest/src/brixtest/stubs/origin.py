"""A plain HTTP origin stub (F12) — files out of its working directory.

The generic member of the measured stub inventory (the grown suite's
``static_origin_server.py``): cache, proxy, and transfer tests need
*something* upstream that serves bytes, and this is that something.
The backend starts it with the instance workdir as cwd, so a test
seeds content simply by writing files there.

Routes on top of the base's ``/health``:

* ``GET/HEAD /<path>`` — the file at ``<workdir>/<path>`` (traversal
  is refused, not resolved);
* ``POST /echo``       — the request body straight back, for
  round-trip checks that need no fixture file at all.

Run as ``python -m brixtest.stubs.origin`` under a spec whose env sets
``BRIXTEST_PORT`` (see the StubServer env contract).
"""

from __future__ import annotations

from pathlib import Path
from typing import Mapping

from brixtest.stubs import Response, StubServer

__all__ = ["OriginStub"]


class OriginStub(StubServer):
    default_name = "origin"

    def handle(self, method: str, path: str, headers: Mapping[str, str],
               body: bytes) -> Response:
        if path == "/health":
            return super().handle(method, path, headers, body)
        if method == "POST" and path == "/echo":
            return 200, {"content-type": "application/octet-stream"}, body
        if method not in ("GET", "HEAD"):
            return 405, {"content-type": "text/plain"}, b"origin is read-only\n"
        root = Path.cwd().resolve()
        target = (root / path.lstrip("/")).resolve()
        try:
            target.relative_to(root)
        except ValueError:
            return 403, {"content-type": "text/plain"}, b"path escapes the workdir\n"
        if target.is_file():
            return 200, {"content-type": "application/octet-stream"}, target.read_bytes()
        return 404, {"content-type": "text/plain"}, (
            "origin: no such file: %s\n" % path
        ).encode()


if __name__ == "__main__":
    raise SystemExit(OriginStub.main())

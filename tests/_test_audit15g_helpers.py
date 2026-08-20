"""Shared drive-side plumbing for the audit-15g files — the three §C
mid-transfer legs (reload during a cache fill, unlink during an active
transfer, eviction during an active read) and the sd_http deadline.

All of them need the same primitive the existing cache helpers do not provide:
a read that is PAUSED IN THE MIDDLE, with the fault injected while the handle
is still open and bytes are still outstanding.  `_cache_partial_helpers.
read_range` drains its whole range inside one call, which closes the exact
window these tests exist to open — so `ReadHandle` below keeps the session, the
file handle and the read cursor in the test's hands.

The wire format itself stays single-sourced: every request is built by the
`_test_a_robustness_helpers` builders, as everywhere else in the suite.

`PacedSource` is the second primitive: an http:// origin whose fill takes a
known, controllable number of seconds, so a fault can be aimed at the middle of
a fill rather than hoped into it.
"""

from __future__ import annotations

import os
import re
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from settings import HOST
from _test_a_robustness_helpers import (
    make_protocol_req, make_login_req, make_open_req, make_read_req,
    make_close_req,
)

# kXR_error errcodes this tranche discriminates between.  A missing object and
# a refused one are both status 4003 on the wire, and a test that accepted
# either would pass on a seeding slip.
KXR_ERROR = 4003
KXR_OKSOFAR = 4000
XERR_NOT_FOUND = 3011
XERR_IO_ERROR = 3007


def pattern(size, salt):
    """A deterministic byte pattern: two objects with different salts can never
    be confused for one another, and a short read is visible as a length."""
    return bytes((i * 131 + salt) & 0xFF for i in range(size))


def seed_tree(root, mapping):
    """Write `{path: blob}` under `root`, world-readable — the nginx master may
    run as root while the worker drops privilege."""
    for path, blob in mapping.items():
        target = os.path.join(str(root), path.lstrip("/"))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as fh:
            fh.write(blob)
        os.chmod(target, 0o644)
    for dirpath, dirnames, _files in os.walk(str(root)):
        os.chmod(dirpath, 0o777)
        for name in dirnames:
            os.chmod(os.path.join(dirpath, name), 0o777)


# ── an incrementally-read kXR file handle ────────────────────────────────────

class ReadError(AssertionError):
    """A kXR_error frame on a request the test expected to succeed; `.errcode`
    is the XErrorCode so callers can tell "refused" from "not there"."""

    def __init__(self, what, status, body):
        self.status = status
        self.errcode = struct.unpack("!I", body[:4])[0] if len(body) >= 4 else 0
        self.text = body[4:].split(b"\x00")[0].decode("utf-8", "replace")
        super().__init__(f"{what}: status={status} errcode={self.errcode} "
                         f"{self.text!r}")


def _recv_exact_on(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise AssertionError(f"socket closed, {n - len(buf)} short")
        buf += chunk
    return buf


def _frame_on(sock):
    _sid, status, dlen = struct.unpack(">2sHI", _recv_exact_on(sock, 8))
    return status, (_recv_exact_on(sock, dlen) if dlen else b"")


def open_session(port, *, timeout=15.0):
    """A connected, handshaken, logged-in kXR socket — the three frames every
    drive in this tranche starts with."""
    sock = socket.create_connection((HOST, port), timeout=timeout)
    sock.settimeout(timeout)
    sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    _recv_exact_on(sock, 16)                       # server hello
    sock.sendall(make_protocol_req())
    _frame_on(sock)
    sock.sendall(make_login_req())
    _frame_on(sock)
    return sock


def write_open(port, path, *, mode=0o644):
    """The errcode a create-for-write open of `path` is refused with, 0 if it
    was granted.  Used as the "is the new config live?" witness after a reload:
    `brix_allow_write` is answered on the wire, not in a log."""
    # kXR_new | kXR_open_wrto | kXR_mkpath — the stock write-open flag set.
    sock = open_session(port)
    try:
        payload = path.encode()
        sock.sendall(struct.pack(">BBH", 0, 1, 3010)
                     + struct.pack(">HH12s", mode, 0x0008 | 0x4000 | 0x0100,
                                   b"\x00" * 12)
                     + struct.pack(">I", len(payload)) + payload)
        status, body = _frame_on(sock)
        if status == 0:
            return 0
        return struct.unpack("!I", body[:4])[0] if len(body) >= 4 else -1
    finally:
        sock.close()


class ReadHandle:
    """One kXR session with one open file handle, read a chunk at a time.

    The whole point is what happens BETWEEN two `read()` calls: the object can
    be unlinked, purged by the reaper, or its server reloaded, and the next
    `read()` reports what the server actually did with an open handle whose
    backing store moved under it.
    """

    def __init__(self, port, path, *, timeout=15.0):
        self.port = port
        self.path = path
        self._sock = open_session(port, timeout=timeout)
        self._sock.sendall(make_open_req(path.encode()))
        status, body = self._frame()
        if status != 0:
            self._sock.close()
            raise ReadError(f"open {path}", status, body)
        self.fhandle = body[:4]

    # -- wire -------------------------------------------------------------
    def _frame(self):
        return _frame_on(self._sock)

    # -- reads ------------------------------------------------------------
    def read(self, off, length):
        """Read exactly [off, off+length); raises ReadError on a kXR_error."""
        self._sock.sendall(make_read_req(self.fhandle, off, length))
        data = b""
        while True:
            status, chunk = self._frame()
            data += chunk
            if status != KXR_OKSOFAR:
                break
        if status != 0:
            raise ReadError(f"read {self.path} @{off}+{length}", status, data)
        return data

    def try_read(self, off, length):
        """`read()` that returns `(bytes, errcode)` instead of raising, for the
        assertions whose whole subject is WHICH way a mid-transfer fault went.
        `errcode` is 0 on success."""
        try:
            return self.read(off, length), 0
        except ReadError as exc:
            return b"", exc.errcode

    def close(self):
        try:
            self._sock.sendall(make_close_req(self.fhandle))
            status, _body = self._frame()
            return status
        finally:
            self._sock.close()

    def abort(self):
        """Drop the connection without a kXR_close — the client going away in
        the middle of a transfer, which is what the server sees when a job is
        killed.  Distinct from `close()`: the handle is never released, so
        whatever the server was doing on its behalf is cancelled, not finished.
        """
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        try:
            self.close()
        except OSError:
            pass
        return False


def read_whole(port, path, size, *, chunk=65536):
    """Open, drain `size` bytes in `chunk`-sized reads, close — the plain
    control read every fault test compares its damaged twin against."""
    with ReadHandle(port, path) as handle:
        out = b""
        while len(out) < size:
            out += handle.read(len(out), min(chunk, size - len(out)))
        return out


def open_fails(port, path, *, timeout=15.0):
    """The errcode a fresh open of `path` is refused with, or 0 if it opened —
    the "and afterwards?" half of every mid-transfer assertion.  `timeout` has
    to exceed the server's own deadline for the fault under test, or the
    measurement is of the client's patience instead."""
    try:
        ReadHandle(port, path, timeout=timeout).close()
        return 0
    except ReadError as exc:
        return exc.errcode


# ── a paced http:// origin ───────────────────────────────────────────────────

class PacedSource(BaseHTTPRequestHandler):
    """An http:// origin that answers HEAD/ranged-GET like a static server but
    writes the body in `server.chunk`-sized pieces `server.delay` seconds
    apart, so a fill takes a known number of seconds.

    `server.recorded` logs every request; `server.hold` is an Event a test can
    clear to freeze the origin mid-body indefinitely (the sd_http deadline
    subject) and set again to release it.

    Two more faults an origin can commit, both of which a cache must survive:
    `server.absent` is a set of paths answered 404, and `server.truncate_at`
    hangs up mid-body after that many bytes while still having PROMISED the
    full Content-Length — the lie a cache must never publish as a whole object.

    `server.written` makes it a (tiny) object store as well: a PUT is kept and
    then served back, so a plane that writes THROUGH to an http:// backend can
    be asserted on the origin's copy instead of on a log line.

    `server.corrupt` is the quieter lie of the three: paths listed there are
    served back with their first byte flipped, at the SAME length the PUT
    delivered, so nothing about the framing is wrong and only a reader that
    compares content can tell.  It is what an origin that silently damages what
    it stored looks like, and the only fault a write-verification gate can
    catch that a Content-Length check cannot.
    """

    protocol_version = "HTTP/1.1"

    def _record(self):
        self.server.recorded.append({
            "method": self.command,
            "path": self.path,
            "range": self.headers.get("Range"),
            # Which credential the gateway put on the outbound leg.  For a
            # delegating export this is the whole observable: whether the
            # caller's own bearer reached the backend or was dropped on the way
            # is a header at the origin, not a line in a log.
            "authorization": self.headers.get("Authorization"),
        })

    def _key(self):
        return self.path.split("?", 1)[0]

    def _missing(self):
        return self._key() in self.server.absent \
            and self._key() not in self.server.written

    def _body_of(self):
        """What this origin holds for the requested path: whatever was PUT
        there, else the one canned payload every other path answers with."""
        body = self.server.written.get(self._key(), self.server.payload)
        if body and self._key() in self.server.corrupt:
            body = bytes([body[0] ^ 0xFF]) + body[1:]
        return body

    def do_HEAD(self):
        self._record()
        if self._missing():
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(self._body_of())))
        self.send_header("Accept-Ranges", "bytes")
        self.end_headers()

    def do_PUT(self):
        """Accept an upload and keep it, so a write THROUGH the origin can be
        asserted on the origin's own copy rather than inferred.  Bytes are
        appended: a backend that flushes an object in several PUTs is writing
        one object, and the test cares about what the origin ends up holding."""
        self._record()
        length = int(self.headers.get("Content-Length") or 0)
        blob = self.rfile.read(length) if length else b""
        self.server.written[self._key()] = \
            self.server.written.get(self._key(), b"") + blob
        self.send_response(201)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self._record()
        if self._missing():
            self.send_error(404)
            return
        payload = self._body_of()
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
        try:
            for at in range(0, len(body), self.server.chunk):
                if (self.server.truncate_at is not None
                        and at >= self.server.truncate_at):
                    # Hang up owing bytes we advertised: a premature EOF, not a
                    # short Content-Length, so only the puller can catch it.
                    self.close_connection = True
                    return
                # Freeze point: a cleared `hold` stops the body here, which is
                # what an origin that accepts and then goes silent looks like.
                self.server.hold.wait()
                self.wfile.write(body[at:at + self.server.chunk])
                self.wfile.flush()
                if self.server.delay:
                    time.sleep(self.server.delay)
        except OSError:
            pass                        # the puller hung up mid-body

    def log_message(self, *args):
        pass


def serve_paced(port, payload, *, chunk=65536, delay=0.0):
    """Start a `PacedSource` on `port` and return it."""
    server = ThreadingHTTPServer((HOST, port), PacedSource)
    server.daemon_threads = True
    server.recorded = []
    server.payload = payload
    server.chunk = chunk
    server.delay = delay
    server.absent = set()
    server.written = {}
    server.corrupt = set()
    server.truncate_at = None
    server.hold = threading.Event()
    server.hold.set()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def wait_until(predicate, *, timeout, tick=0.05, what="condition"):
    """Poll `predicate` until true; raise with `what` named when it never is.
    Every mid-transfer test waits on a background event (a fill landing, a
    reaper sweep), and a bare sleep would be either flaky or slow."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(tick)
    raise AssertionError(f"{what} did not happen within {timeout}s")

"""A shadow that keeps the mirrored request instead of answering it.

The fleet already has a mirror shadow (`mirror-shadow`, a fixed-port fleet
mock), and `test_phase24_mirror.py` uses it to prove that a GET is replayed and
that `brix_mirror_strip_auth on` removes the client's Authorization.  Two things
it cannot do are what this file exists for: it answers one status, so a
divergence — a mismatch of status CLASS between the primary and the shadow,
`net/mirror/http_mirror_request.c` — can never be produced against it, and its
capture is global fleet state shared with every other test in the session.

`RecordingShadow` is per-instance and keeps the whole header block in order,
duplicates included, because the questions here are "which Authorization did the
second host receive" and "how many were there" rather than "was one present".
"""

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

#: The loop guard the mirror stamps on every shadow request; a shadow that is
#: itself a brix server declines to mirror again when it sees this.
LOOP_GUARD = "X-Xrootd-Mirror"


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _record(self):
        self.server.record({
            "method": self.command,
            "path": self.path,
            # Ordered and duplicate-preserving: `Authorization` appearing twice
            # is a different fact from it appearing once.
            "headers": [(k, v) for k, v in self.headers.items()],
        })

    def _answer(self):
        self._record()
        body = b"shadow\n" if self.server.status < 400 else b"no such thing\n"
        try:
            self.send_response(self.server.status)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except OSError:
            # A mirror subrequest is fire-and-forget on the primary's side and
            # may hang up before the answer lands; the record is already kept,
            # and the traceback would be the only thing lost.
            pass

    do_GET = _answer
    do_HEAD = _answer
    do_PUT = _answer
    do_POST = _answer

    def log_message(self, *args):        # keep pytest output the test's own
        pass


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass                    # a hung-up mirror leg is not a test failure


class RecordingShadow:
    """One HTTP listener that answers every request with `status` and remembers
    what it was asked.

    A mirror subrequest is fired in the background and finishes on its own
    clock, so nothing here is safe to read the instant the client has its
    answer; `wait_for(path)` is how a test waits for the shadow's view of one
    request to be complete, and `settle()` is how it waits for the absence of
    one to mean something.
    """

    def __init__(self, host, port, status=200):
        self._lock = threading.Lock()
        self._seen = []
        self._server = _Server((host, port), _Handler)
        self._server.status = status
        self._server.record = self._record
        self.port = port
        self.status = status
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)
        self._thread.start()

    def _record(self, entry):
        with self._lock:
            self._seen.append(entry)

    # -- reading ------------------------------------------------------------ #
    def seen(self):
        with self._lock:
            return list(self._seen)

    def paths(self):
        return [entry["path"] for entry in self.seen()]

    def reset(self):
        with self._lock:
            self._seen = []

    def wait_for(self, path, timeout=6.0):
        """Return the shadow's record of the first request for `path`, or None
        if the mirror never dialled within the timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for entry in self.seen():
                if entry["path"] == path:
                    return entry
            time.sleep(0.02)
        return None

    def settle(self, seconds=1.0):
        """Give a mirror that should not have fired the chance to prove
        otherwise, and return everything recorded in that window."""
        time.sleep(seconds)
        return self.seen()

    def close(self):
        self._server.shutdown()
        self._server.server_close()


def headers_named(entry, name):
    """Every value the shadow received for `name`, in order.  A list rather than
    a lookup because "exactly one Authorization" is one of the assertions."""
    lowered = name.lower()
    return [value for key, value in entry["headers"] if key.lower() == lowered]

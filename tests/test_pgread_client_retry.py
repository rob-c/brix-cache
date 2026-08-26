"""Client-side pgread per-page CRC recovery (parity-audit §7.14).

A flipped bit between server and client used to abort the whole paged read
(`pgread CRC mismatch at offset N`) even though the server still holds good
bytes.  The client now decodes with the collect decoder, then re-requests each
corrupt page once the response is drained — a fresh 1-page kXR_pgread carrying
the ClientPgReadReqArgs payload {pathid=0, kXR_pgRetry} (the §1.2 wire
surface, tolerated by stock and BriX alike) — bounded at 2 attempts per page
and 16 corrupt pages per request.

Fault injection is a deterministic in-process MITM shim: it watches the
DOWNSTREAM byte flow for long runs of a sentinel byte (0xAA) — only page DATA
can contain a 4 KiB run of one value; wire framing and CRCs cannot — and
flips one bit per run for the first N occurrences.  The retry re-fetch flows
through the same shim, so "corrupt once" heals and "corrupt always" must fail
CLOSED.

  * success   — one corrupt page: the copy succeeds and is byte-exact (the
                second pass through the shim is clean)
  * error     — the page is corrupted on EVERY pass: the copy fails and no
                destination file survives
  * security  — 17 corrupt pages in one request: refused outright as a
                poisoned stream (no per-page retry storm), fail-closed

Run:
    PYTHONPATH=tests pytest tests/test_pgread_client_retry.py -v
"""

import os
import socket
import subprocess
import threading

import pytest

from settings import DATA_ROOT, NGINX_ANON_PORT, SERVER_HOST

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")

SENTINEL = 0xAA
RUN_TRIGGER = 64          # consecutive sentinel bytes that mark "inside a page"
FLIP_SKIP = 4096          # bytes to ignore after a flip (rest of that page)

pytestmark = [
    pytest.mark.requires_local_server,
    pytest.mark.timeout(120),
    pytest.mark.skipif(not os.path.exists(XRDCP),
                       reason="brix-xrdcp not built (client/bin/xrdcp)"),
]


class _BitFlipShim(threading.Thread):
    """TCP MITM: forwards both directions verbatim except one flipped bit per
    sentinel run in the DOWNSTREAM direction, for the first `flips`
    occurrences (-1 = every occurrence)."""

    def __init__(self, backend, flips):
        super().__init__(daemon=True)
        self._backend = backend
        self._flips = flips
        self.flipped = 0
        self._stop = threading.Event()
        self._lsock = socket.socket()
        self._lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._lsock.bind(("127.0.0.1", 0))  # net-literal-allow: mock shim binds loopback ephemeral by design
        self._lsock.listen(8)
        self._lsock.settimeout(0.2)
        self.port = self._lsock.getsockname()[1]

    def run(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._lsock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve, args=(conn,),
                             daemon=True).start()
        self._lsock.close()

    def _serve(self, conn):
        try:
            back = socket.create_connection(self._backend, timeout=10)
        except OSError:
            conn.close()
            return
        threading.Thread(target=self._pump, args=(conn, back, False),
                         daemon=True).start()
        self._pump(back, conn, True)
        for s in (conn, back):
            try:
                s.close()
            except OSError:
                pass

    def _may_flip(self):
        """True while this shim is still allowed to corrupt bytes (an unlimited
        budget is a negative _flips)."""
        return self._flips < 0 or self.flipped < self._flips

    def _flip_downstream(self, data, state):
        """Corrupt sentinel runs in `data` in place, carrying (run, skip) across
        chunks via the `state` dict; returns the possibly-flipped bytes."""
        buf = bytearray(data)
        for i, b in enumerate(buf):
            if state["skip"] > 0:
                state["skip"] -= 1
                continue
            if b != SENTINEL:
                state["run"] = 0
                continue
            state["run"] += 1
            if state["run"] >= RUN_TRIGGER and self._may_flip():
                buf[i] = b ^ 0x01
                self.flipped += 1
                state["run"] = 0
                state["skip"] = FLIP_SKIP
        return bytes(buf)

    def _pump(self, src, dst, downstream):
        state = {"run": 0, "skip": 0}   # sentinel run + post-flip ignore window
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                if downstream:
                    data = self._flip_downstream(data, state)
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def stop(self):
        self._stop.set()


def _stage(name, content):
    os.makedirs(DATA_ROOT, exist_ok=True)
    with open(os.path.join(DATA_ROOT, name), "wb") as f:
        f.write(content)


def _unstage(name):
    try:
        os.remove(os.path.join(DATA_ROOT, name))
    except FileNotFoundError:
        pass


def _pgcp(shim_port, name, dst):
    return subprocess.run(
        [XRDCP, "--pgrw", "--retry", "0",
         f"root://127.0.0.1:{shim_port}//{name}", str(dst)],  # net-literal-allow: URL targets the loopback mock shim
        capture_output=True, text=True, timeout=90)


# One sentinel page sandwiched between zero pages: exactly one corrupt page.
ONE_PAGE = bytes(4096) + bytes([SENTINEL]) * 4096 + bytes(4096)
# 17 sentinel pages: one flipped bit per page exceeds the 16-page cap.
FLOOD = bytes([SENTINEL]) * (4096 * 17)


class TestPgreadClientRetry:

    def test_single_corrupt_page_recovers(self, tmp_path):
        """(success) one flipped bit: the read heals via kXR_pgRetry and the
        destination is byte-exact — this exact case hard-failed before."""
        _stage("pgretry-one.bin", ONE_PAGE)
        shim = _BitFlipShim((SERVER_HOST, NGINX_ANON_PORT), flips=1)
        shim.start()
        try:
            dst = tmp_path / "out.bin"
            res = _pgcp(shim.port, "pgretry-one.bin", dst)
            assert res.returncode == 0, res.stderr
            assert dst.read_bytes() == ONE_PAGE
            assert shim.flipped == 1, "shim never corrupted the page"
        finally:
            shim.stop()
            _unstage("pgretry-one.bin")

    def test_persistent_corruption_fails_closed(self, tmp_path):
        """(error) the page is corrupted on EVERY pass: retries exhaust, the
        copy fails, and no destination file survives."""
        _stage("pgretry-all.bin", ONE_PAGE)
        shim = _BitFlipShim((SERVER_HOST, NGINX_ANON_PORT), flips=-1)
        shim.start()
        try:
            dst = tmp_path / "out.bin"
            res = _pgcp(shim.port, "pgretry-all.bin", dst)
            assert res.returncode != 0
            assert "mismatch" in res.stderr or "corrupt" in res.stderr, (
                res.stderr)
            assert not dst.exists(), "corrupt download left a destination file"
            assert shim.flipped >= 2, "retry never re-requested the page"
        finally:
            shim.stop()
            _unstage("pgretry-all.bin")

    def test_bad_page_flood_refused(self, tmp_path):
        """(security-neg) 17 corrupt pages in ONE request: the client refuses
        the poisoned stream outright instead of feeding a retry storm, and
        fails closed."""
        _stage("pgretry-flood.bin", FLOOD)
        shim = _BitFlipShim((SERVER_HOST, NGINX_ANON_PORT), flips=17)
        shim.start()
        try:
            dst = tmp_path / "out.bin"
            res = _pgcp(shim.port, "pgretry-flood.bin", dst)
            assert res.returncode != 0
            assert not dst.exists()
        finally:
            shim.stop()
            _unstage("pgretry-flood.bin")

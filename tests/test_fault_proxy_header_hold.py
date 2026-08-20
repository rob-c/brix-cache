"""
test_fault_proxy_header_hold.py — tests for the DPI header-size hold lever of
brix-fault-proxy (client/apps/diag/brix_fault_http.c fp_http_hold_* + the relay
pump glue in brix_fault_pump.c).

Real deep-packet-inspection middleboxes replicate a nasty anti-feature: they
STALL an HTTP(S) request — in whole or in part — once its *header block* crosses
a byte threshold (think a fat client-cert PEM carried in an XrdHttp request
header).  The `http header-hold <thresh> <ms> [partial|whole]` lever reproduces
that middlebox behaviour above TCP, root-free.

The 3-test ritual:

* SUCCESS  — a request whose header block reaches the threshold is stalled by the
             configured delay (whole mode delays the first byte; partial mode
             releases exactly `thresh` bytes, then holds the remainder), and the
             `held` counter / status reflect it.
* ERROR    — malformed `header-hold` arguments (missing delay, non-positive
             threshold) are rejected with an `err:` reply and arm nothing.
* SECURITY — the trigger keys on a COMPLETE, over-threshold header block only, so
             a body-only / non-HTTP segment larger than the threshold is NEVER
             held (no complete CRLFCRLF header) — the hold cannot be weaponised
             to stall arbitrary bulk data — and `clear` fully disarms it.

Self-contained: builds the tool and drives it against a throwaway capturing echo
server on ephemeral loopback ports.  No root, no fleet server.
"""

import json
import os
import socket
import subprocess
import threading
import time

import pytest
from settings import HOST

pytestmark = pytest.mark.timeout(120)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
BFP = os.path.join(CLIENT_DIR, "bin", "brix-fault-proxy")

HOLD_MS = 500                      # configured stall
HELD = HOLD_MS / 1000.0
THRESH = 2048                      # header-size trigger, in bytes


@pytest.fixture(scope="module")
def bfp():
    proc = subprocess.run(["make", "-C", CLIENT_DIR, "brix-fault-proxy"],
                          capture_output=True, text=True, timeout=120)
    if proc.returncode != 0 or not os.path.exists(BFP):
        pytest.skip(f"brix-fault-proxy build failed:\n{proc.stdout}\n{proc.stderr}")
    return BFP


def _free_port():
    from ephemeral_port import free_port
    return free_port(HOST)


def _wait_port(port, deadline=5.0):
    end = time.time() + deadline
    while time.time() < end:
        try:
            with socket.create_connection((HOST, port), timeout=0.25):
                return True
        except OSError:
            time.sleep(0.02)
    return False


class _CapEcho:
    """Streaming echo upstream that records the FIRST blob each connection sends
    (so a partial hold's released prefix can be measured on its own)."""

    def __init__(self):
        self.port = _free_port()
        self.first = []
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((HOST, self.port))
        self._srv.listen(8)
        self._stop = False
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        self._srv.settimeout(0.3)
        while not self._stop:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                continue
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        conn.settimeout(2.0)
        got_first = False
        try:
            while not self._stop:
                d = conn.recv(65536)
                if not d:
                    break
                if not got_first:
                    self.first.append(d)
                    got_first = True
                conn.sendall(d)
        except OSError:
            pass
        finally:
            conn.close()

    def close(self):
        self._stop = True
        self._srv.close()


def _spawn(bfp, target_port, extra=None):
    listen, ctl = _free_port(), _free_port()
    argv = [bfp, "--listen", str(listen), "--target", f"{HOST}:{target_port}",
            "--control", str(ctl), "--quiet"] + (extra or [])
    proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    assert _wait_port(ctl) and _wait_port(listen), "proxy never came up"
    return proc, listen, ctl


def _ctl(port, cmd):
    with socket.create_connection((HOST, port), timeout=3) as s:
        s.sendall((cmd + "\n").encode())
        out = b""
        s.settimeout(1.0)
        try:
            while True:
                d = s.recv(8192)
                if not d:
                    break
                out += d
        except socket.timeout:
            pass
        return out.decode()


def _held(ctl):
    return json.loads(_ctl(ctl, "status json"))["held"]


def _ttfb(listen, payload):
    """Send `payload`; return (time-to-first-response-byte, full echoed body)."""
    with socket.create_connection((HOST, listen), timeout=3) as s:
        t0 = time.time()
        s.sendall(payload)
        s.settimeout(3.0)
        first = s.recv(65536)
        ttfb = time.time() - t0
        out = first
        s.settimeout(0.6)
        try:
            while True:
                d = s.recv(65536)
                if not d:
                    break
                out += d
        except socket.timeout:
            pass
        return ttfb, out


def _req(header_pad):
    """An HTTP/1.1 request whose header block carries `header_pad` filler bytes."""
    return (b"GET / HTTP/1.1\r\nHost: x\r\nX-Cert: " + b"A" * header_pad +
            b"\r\n\r\n")


# --------------------------------------------------------------------------- #
# SUCCESS                                                                      #
# --------------------------------------------------------------------------- #
def test_whole_hold_stalls_oversized_header(bfp):
    echo = _CapEcho()
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        assert "ok" in _ctl(ctl, f"http header-hold {THRESH} {HOLD_MS} up")
        assert "hold=1/0" in _ctl(ctl, "status")

        # A request whose header block clears the threshold is stalled whole:
        # the very first response byte is delayed by ~HOLD_MS.
        big = _req(THRESH + 2000)
        ttfb, body = _ttfb(listen, big)
        assert body == big                       # nothing dropped, just delayed
        assert ttfb >= HELD * 0.8, f"oversized header not held (ttfb={ttfb:.3f}s)"
        assert _held(ctl) == 1

        # A small-header request sails through with no stall.
        small = _req(16)
        ttfb, body = _ttfb(listen, small)
        assert body == small
        assert ttfb < HELD * 0.5, f"small header wrongly held (ttfb={ttfb:.3f}s)"
        assert _held(ctl) == 1                   # counter unchanged
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


def test_partial_hold_releases_prefix_then_stalls(bfp):
    echo = _CapEcho()
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        assert "ok" in _ctl(ctl, f"http header-hold {THRESH} {HOLD_MS} partial up")
        echo.first.clear()

        big = _req(THRESH + 2000)
        ttfb, body = _ttfb(listen, big)
        # Partial mode releases exactly THRESH bytes up front; the withheld
        # remainder arrives HOLD_MS later, so the upstream's first read is the
        # released prefix on its own.
        assert echo.first and len(echo.first[0]) == THRESH
        assert body == big                       # every byte still forwarded
        assert _held(ctl) == 1
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


# --------------------------------------------------------------------------- #
# ERROR                                                                        #
# --------------------------------------------------------------------------- #
def test_bad_header_hold_args_are_rejected(bfp):
    echo = _CapEcho()
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        assert "err" in _ctl(ctl, "http header-hold 2048")        # missing delay
        assert "err" in _ctl(ctl, "http header-hold 0 500")       # non-positive thresh
        assert "hold=0/0" in _ctl(ctl, "status")                  # nothing armed
        big = _req(THRESH + 2000)
        ttfb, body = _ttfb(listen, big)
        assert body == big and ttfb < HELD * 0.5                  # no stall
        assert _held(ctl) == 0
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


# --------------------------------------------------------------------------- #
# SECURITY                                                                     #
# --------------------------------------------------------------------------- #
def test_body_only_segment_is_never_held(bfp):
    echo = _CapEcho()
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        _ctl(ctl, f"http header-hold {THRESH} {HOLD_MS} up")
        # A non-HTTP / body-only blob far larger than the threshold carries NO
        # complete CRLFCRLF header block, so the DPI hold must not touch it —
        # the lever keys on a real over-threshold header, never bulk data.
        blob = b"A" * (THRESH * 4)
        ttfb, body = _ttfb(listen, blob)
        assert body == blob
        assert ttfb < HELD * 0.5, f"bulk data wrongly held (ttfb={ttfb:.3f}s)"
        assert _held(ctl) == 0

        # clear fully disarms the hold.
        _ctl(ctl, "clear")
        assert "hold=0/0" in _ctl(ctl, "status")
        big = _req(THRESH + 2000)
        ttfb, body = _ttfb(listen, big)
        assert body == big and ttfb < HELD * 0.5
        assert _held(ctl) == 0
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()

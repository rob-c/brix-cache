"""
test_fault_proxy_mitm.py — tests for the extended (still root-free) MITM / DoS
levers of brix-fault-proxy (client/apps/diag/brix_fault_ext.c + the relay glue):
payload surgery (replace / inject / drop-bytes / repeat-bytes), PROXY-protocol
forgery, socket-level stress (mss / rcvbuf / stall), connection lifetime, and the
chaos monkey.

The 3-test ritual for the new surface:

* SUCCESS  — each lever changes the bytes/behaviour the peer observes exactly as
             specified: a wire rewrite, a spliced prefix, deleted/duplicated
             bytes, a forged PROXY header the upstream receives, a time-boxed
             connection, and a status line that reflects the socket levers.
* ERROR    — malformed payloads and an incomplete proxy-header spec are rejected
             with an `err:` reply and leave the stream untouched.
* SECURITY — inject/replace payloads are literal bytes (hex:/str: only, never a
             shell), so a CRLF-bearing smuggling payload lands verbatim; `clear`
             fully disarms every extended lever.

Self-contained: builds the tool and drives it against a throwaway capturing echo
server on ephemeral loopback ports. No root, no fleet server.
"""

import os
import socket
import subprocess
import threading
import time

import pytest

pytestmark = pytest.mark.timeout(120)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
BFP = os.path.join(CLIENT_DIR, "bin", "brix-fault-proxy")


@pytest.fixture(scope="module")
def bfp():
    proc = subprocess.run(["make", "-C", CLIENT_DIR, "brix-fault-proxy"],
                          capture_output=True, text=True, timeout=120)
    if proc.returncode != 0 or not os.path.exists(BFP):
        pytest.skip(f"brix-fault-proxy build failed:\n{proc.stdout}\n{proc.stderr}")
    return BFP


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _wait_port(port, deadline=5.0):
    end = time.time() + deadline
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                return True
        except OSError:
            time.sleep(0.02)
    return False


class _CapEcho:
    """Streaming echo upstream that records the FIRST blob each connection sends
    (so tests can inspect a spliced prefix or a forged PROXY header)."""

    def __init__(self):
        self.port = _free_port()
        self.first = []
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", self.port))
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
    argv = [bfp, "--listen", str(listen), "--target", f"127.0.0.1:{target_port}",
            "--control", str(ctl), "--quiet"] + (extra or [])
    proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    assert _wait_port(ctl) and _wait_port(listen), "proxy never came up"
    return proc, listen, ctl


def _ctl(port, cmd):
    with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
        s.sendall((cmd + "\n").encode())
        return s.recv(1400).decode()


def _roundtrip(listen, payload, wait=0.3):
    with socket.create_connection(("127.0.0.1", listen), timeout=3) as s:
        s.sendall(payload)
        time.sleep(wait)
        s.settimeout(1.0)
        out = b""
        try:
            while True:
                d = s.recv(65536)
                if not d:
                    break
                out += d
        except socket.timeout:
            pass
        return out


# --------------------------------------------------------------------------- #
# SUCCESS                                                                      #
# --------------------------------------------------------------------------- #
def test_replace_rewrites_the_wire(bfp):
    echo = _CapEcho()
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        assert "ok" in _ctl(ctl, "replace hex:41414141 hex:4242424242 down")
        # server echoes AAAA; the down path rewrites it to BBBBB (len may differ).
        assert _roundtrip(listen, b"AAAA") == b"BBBBB"
        _ctl(ctl, "clear")
        assert _roundtrip(listen, b"AAAA") == b"AAAA"   # disarmed
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


def test_inject_and_proxy_header_reach_upstream(bfp):
    echo = _CapEcho()
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        # One-shot inject prefixes the upstream's first read.
        echo.first.clear()
        assert "ok" in _ctl(ctl, "inject str:PWNED\\r\\n up")
        _roundtrip(listen, b"realdata")
        assert echo.first and echo.first[0].startswith(b"PWNED\r\nrealdata")

        # Forged PROXY-protocol v1 header (spoofed client source IP).
        echo.first.clear()
        assert "ok" in _ctl(ctl, "proxy-header v1 9.9.9.9:1234")
        _roundtrip(listen, b"hi")
        assert echo.first and echo.first[0].startswith(b"PROXY TCP4 9.9.9.9 ")
        assert echo.first[0].split(b"\r\n", 1)[1] == b"hi"
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


def test_drop_and_repeat_bytes(bfp):
    echo = _CapEcho()
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        _ctl(ctl, "drop-bytes 100 down")          # delete everything downstream
        assert _roundtrip(listen, b"HELLOHELLO") == b""
        _ctl(ctl, "clear")

        echo.first.clear()
        _ctl(ctl, "repeat-bytes 100 up")          # duplicate every upstream byte
        _roundtrip(listen, b"AB")
        assert echo.first and echo.first[0] == b"AABB"
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


def test_max_lifetime_guillotines_connection(bfp):
    echo = _CapEcho()
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        _ctl(ctl, "max-lifetime 300")
        s = socket.create_connection(("127.0.0.1", listen), timeout=3)
        s.sendall(b"ping")
        s.settimeout(2.0)
        start = time.time()
        # The relay severs ~300ms in; recv then returns EOF (b"") or resets.
        closed_at = None
        try:
            while time.time() - start < 2.0:
                d = s.recv(65536)
                if not d:
                    closed_at = time.time() - start
                    break
        except OSError:
            closed_at = time.time() - start
        s.close()
        assert closed_at is not None and closed_at < 1.5, "connection not time-boxed"
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


def test_socket_levers_reflected_in_status(bfp):
    echo = _CapEcho()
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        for cmd in ("mss 200", "rcvbuf 2048", "sndbuf 4096", "stall up",
                    "max-lifetime 5000", "chaos 50"):
            assert "ok" in _ctl(ctl, cmd)
        ext = [l for l in _ctl(ctl, "status").splitlines()
               if l.startswith("ext")][0]
        assert "mss=200" in ext and "rcvbuf=2048" in ext and "sndbuf=4096" in ext
        assert "stall=1/0" in ext and "maxlife=5000ms" in ext and "chaos=1" in ext
        assert "chaos=0" in [l for l in _ctl(ctl, "clear").splitlines()] or \
            "chaos=0" in _ctl(ctl, "status")   # clear stops chaos
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


# --------------------------------------------------------------------------- #
# ERROR                                                                        #
# --------------------------------------------------------------------------- #
def test_bad_payload_and_proxy_spec_rejected(bfp):
    echo = _CapEcho()
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        assert "err:" in _ctl(ctl, "replace hex:zzz hex:00 down")   # bad hex
        assert "err:" in _ctl(ctl, "inject hex:abc up")             # odd nibbles
        assert "err:" in _ctl(ctl, "proxy-header v1")               # missing SRC
        # A rejected lever must not have altered the stream.
        assert _roundtrip(listen, b"clean") == b"clean"
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


# --------------------------------------------------------------------------- #
# SECURITY                                                                     #
# --------------------------------------------------------------------------- #
def test_inject_payload_is_literal_not_shell(bfp):
    """A CRLF-bearing smuggling payload must land as raw bytes — the control
    plane never interprets it as a shell/format string."""
    echo = _CapEcho()
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        echo.first.clear()
        marker = "str:GET / HTTP/1.0\\r\\nX-Smuggle: $(id)\\r\\n\\r\\n"
        assert "ok" in _ctl(ctl, f"inject {marker} up")
        _roundtrip(listen, b"body")
        got = echo.first[0]
        assert got.startswith(b"GET / HTTP/1.0\r\nX-Smuggle: $(id)\r\n\r\nbody")
        assert b"uid=" not in got          # $(id) was never executed
        assert not os.path.exists("/tmp/bfp_mitm_pwned")
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()

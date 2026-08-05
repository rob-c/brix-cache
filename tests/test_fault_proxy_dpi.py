"""
test_fault_proxy_dpi.py — Phase-99 DPI / middlebox pathology levers
(client/apps/diag/brix_fault_cmd_dpi.c + the http body/strip levers + the relay
pump/accept glue).  These reproduce the "works in Chrome, destroys XRootD/
GridFTP/FTS" failures a mis-configured cloud DPI imposes.

Each lever gets: SUCCESS (the peer observes the pathology + the counter oracle
moves), a NO-TRIGGER / disarm check, and — where it applies — a negative that the
lever cannot be weaponised beyond its stated scope.  Self-contained against a
throwaway server on ephemeral loopback ports; no root, no fleet.
"""

import json
import os
import socket
import struct
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
                          capture_output=True, text=True, timeout=180)
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


class _Server:
    """Flexible upstream.  mode='echo' streams back; mode='canned' sends a fixed
    blob then keeps the socket open; mode='canned-close' sends then closes."""

    def __init__(self, mode="echo", canned=b""):
        self.mode = mode
        self.canned = canned
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
        conn.settimeout(3.0)
        try:
            d = conn.recv(65536)
            if d:
                self.first.append(d)
            if self.mode == "echo":
                if d:
                    conn.sendall(d)
                while not self._stop:
                    d = conn.recv(65536)
                    if not d:
                        break
                    conn.sendall(d)
            elif self.mode == "canned":
                conn.sendall(self.canned)
                while not self._stop:
                    if not conn.recv(65536):
                        break
            elif self.mode == "canned-close":
                conn.sendall(self.canned)
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


def _json(ctl):
    return json.loads(_ctl(ctl, "status json"))


def _recv_closed(s, deadline=1.0):
    """True if the peer closed/reset the connection (EOF or RST)."""
    s.settimeout(deadline)
    try:
        return s.recv(100) == b""
    except (ConnectionResetError, ConnectionError):
        return True
    except socket.timeout:
        return False


def _roundtrip(listen, payload, wait=0.4):
    with socket.create_connection(("127.0.0.1", listen), timeout=3) as s:
        try:
            s.sendall(payload)
        except (ConnectionResetError, ConnectionError, BrokenPipeError):
            return b""
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
        except (ConnectionResetError, ConnectionError):
            pass
        return out


# --------------------------------------------------------------------------- #
# A1 idle-reap                                                                 #
# --------------------------------------------------------------------------- #
def test_idle_reap_rst_kills_idle_flow(bfp):
    echo = _Server("echo")
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        assert "ok" in _ctl(ctl, "idle-reap 250 rst")
        assert "idle-reap=250/rst" in _ctl(ctl, "status")
        with socket.create_connection(("127.0.0.1", listen), timeout=3) as s:
            s.sendall(b"hello")
            time.sleep(0.2)
            assert s.recv(100) == b"hello"          # flows while active
            time.sleep(0.6)                          # go idle past the deadline
            assert _recv_closed(s)                   # RST/close observed
        assert _json(ctl)["reaped"] >= 1
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


# --------------------------------------------------------------------------- #
# A3 eat-100-continue                                                          #
# --------------------------------------------------------------------------- #
def test_eat_100_continue_swallows_interim(bfp):
    body = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
    srv = _Server("canned", canned=body)
    proc, listen, ctl = _spawn(bfp, srv.port)
    try:
        assert "ok" in _ctl(ctl, "eat-100-continue on")
        got = _roundtrip(listen, b"PUT / HTTP/1.1\r\nExpect: 100-continue\r\n\r\n")
        assert b"100 Continue" not in got and b"200 OK" in got
        assert _json(ctl)["ate_100"] >= 1
    finally:
        proc.terminate(); proc.wait(timeout=5); srv.close()


def test_eat_100_disarmed_passes_interim(bfp):
    body = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n\r\n"
    srv = _Server("canned", canned=body)
    proc, listen, ctl = _spawn(bfp, srv.port)
    try:
        got = _roundtrip(listen, b"PUT / HTTP/1.1\r\n\r\n")
        assert b"100 Continue" in got               # untouched when disarmed
        assert _json(ctl)["ate_100"] == 0
    finally:
        proc.terminate(); proc.wait(timeout=5); srv.close()


# --------------------------------------------------------------------------- #
# A4 rst-after / max-bytes                                                     #
# --------------------------------------------------------------------------- #
def test_max_bytes_guillotine(bfp):
    echo = _Server("echo")
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        assert "ok" in _ctl(ctl, "max-bytes 8 rst")
        with socket.create_connection(("127.0.0.1", listen), timeout=3) as s:
            s.sendall(b"A" * 32)                      # well over 8 bytes
            time.sleep(0.4)
            s.settimeout(1.0)
            out = b""
            try:
                while True:
                    d = s.recv(65536)
                    if not d:
                        break
                    out += d
            except (socket.timeout, ConnectionResetError, ConnectionError):
                pass
            assert len(out) < 32                      # killed mid-flow
        assert _json(ctl)["classify_kills"] >= 1
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


# --------------------------------------------------------------------------- #
# A5 drop-fin                                                                  #
# --------------------------------------------------------------------------- #
def test_drop_fin_hides_eof(bfp):
    srv = _Server("canned-close", canned=b"bye")
    proc, listen, ctl = _spawn(bfp, srv.port)
    try:
        assert "ok" in _ctl(ctl, "drop-fin down")
        with socket.create_connection(("127.0.0.1", listen), timeout=3) as s:
            s.sendall(b"hi")
            time.sleep(0.3)
            assert s.recv(100) == b"bye"              # got the data
            s.settimeout(0.5)
            with pytest.raises(socket.timeout):
                s.recv(100)                           # EOF swallowed -> no close
        assert _json(ctl)["fin_dropped"] >= 1
    finally:
        proc.terminate(); proc.wait(timeout=5); srv.close()


# --------------------------------------------------------------------------- #
# A6 classify-throttle                                                         #
# --------------------------------------------------------------------------- #
def test_classify_throttle_slow_lane(bfp):
    echo = _Server("echo")
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        # after 1 KB the flow is shunted to a 64 KB/s slow lane; a 4 KB upload
        # past the threshold is paced (~64 ms) and the counter records it.
        assert "ok" in _ctl(ctl, "classify-throttle 1024 64 up")
        _roundtrip(listen, b"A" * 4096, wait=0.4)
        assert _json(ctl)["throttled"] >= 1
        # a transfer under the threshold is never throttled (delta stays 0).
        _ctl(ctl, "clear")
        _ctl(ctl, "classify-throttle 100000 64 up")
        base = _json(ctl)["throttled"]
        _roundtrip(listen, b"A" * 512, wait=0.2)
        assert _json(ctl)["throttled"] == base
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


# --------------------------------------------------------------------------- #
# A8 hello-split-reset                                                         #
# --------------------------------------------------------------------------- #
def _client_hello(declared_len):
    # TLS record: type=0x16, version 0x0301, length; then handshake type 0x01.
    body = b"\x01" + b"\x00" * (declared_len - 1)
    return b"\x16\x03\x01" + struct.pack(">H", declared_len) + body


def test_hello_split_reset_kills_oversized(bfp):
    echo = _Server("echo")
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        assert "ok" in _ctl(ctl, "hello-split-reset 256")
        big = _client_hello(400)
        with socket.create_connection(("127.0.0.1", listen), timeout=3) as s:
            s.sendall(big)
            time.sleep(0.3)
            assert _recv_closed(s)                    # reset, never echoed
        assert _json(ctl)["hello_reset"] >= 1
        # a small ClientHello passes untouched.
        small = _client_hello(64)
        assert _roundtrip(listen, small) == small
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


# --------------------------------------------------------------------------- #
# A7 alg-rewrite                                                               #
# --------------------------------------------------------------------------- #
def test_alg_rewrite_pasv(bfp):
    # server "227" reply carries 10,0,0,1,8,73 (port 2121); rewrite to :5555.
    reply = b"227 Entering Passive Mode (10,0,0,1,8,73)\r\n"
    srv = _Server("canned", canned=reply)
    proc, listen, ctl = _spawn(bfp, srv.port)
    try:
        assert "ok" in _ctl(ctl, "alg-rewrite 10.0.0.1:2121 10.9.9.9:5555 down")
        got = _roundtrip(listen, b"PASV\r\n")
        assert b"10,9,9,9,21,179" in got              # 5555 = 21*256+179
        assert b"10,0,0,1,8,73" not in got
    finally:
        proc.terminate(); proc.wait(timeout=5); srv.close()


# --------------------------------------------------------------------------- #
# A9 syn-drop                                                                  #
# --------------------------------------------------------------------------- #
def test_syn_drop_all(bfp):
    echo = _Server("echo")
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        assert "ok" in _ctl(ctl, "syn-drop 1000000")   # drop every accept
        assert _roundtrip(listen, b"hello") == b""      # accepted then dropped
        assert _json(ctl)["syn_dropped"] >= 1
        _ctl(ctl, "syn-drop 0")
        assert _roundtrip(listen, b"hello") == b"hello"
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


# --------------------------------------------------------------------------- #
# A2 body-hold + A10 strip-header (http sub-verbs)                            #
# --------------------------------------------------------------------------- #
def test_body_hold_stalls_large_body(bfp):
    echo = _Server("echo")
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        assert "ok" in _ctl(ctl, "http body-hold 2048 400 up")
        big = b"POST / HTTP/1.1\r\n\r\n" + b"B" * 4000
        with socket.create_connection(("127.0.0.1", listen), timeout=3) as s:
            t0 = time.time()
            s.sendall(big)
            s.settimeout(3.0)
            s.recv(65536)
            assert time.time() - t0 >= 0.3            # body stalled
        assert _json(ctl)["held"] >= 1
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


def test_strip_header_removes_range(bfp):
    echo = _Server("echo")
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        echo.first.clear()
        assert "ok" in _ctl(ctl, "http strip-header Range up")
        _roundtrip(listen, b"GET / HTTP/1.1\r\nHost: x\r\nRange: bytes=0-9\r\n\r\n")
        assert echo.first and b"Range" not in echo.first[0]
        assert b"Host: x" in echo.first[0]            # other headers preserved
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()

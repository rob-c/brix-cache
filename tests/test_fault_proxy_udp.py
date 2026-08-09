"""
test_fault_proxy_udp.py — Phase-99 Wave C: the UDP relay and its "UDP vs TCP"
middlebox levers (client/apps/diag/brix_fault_udp.c).  These reproduce the class
of failure where UDP fired ahead of / alongside TCP is silently dropped, held, or
reaped by a TCP-flow-centric box while the TCP path "works".

SUCCESS: datagrams relay both ways; udp-drop loses them; udp-hold-until-tcp
delays a flow's first datagram.  DISARM restores clean relay.  Self-contained
against a throwaway UDP echo server; no root, no fleet.
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


@pytest.fixture(scope="module")
def bfp():
    proc = subprocess.run(["make", "-C", CLIENT_DIR, "brix-fault-proxy"],
                          capture_output=True, text=True, timeout=180)
    if proc.returncode != 0 or not os.path.exists(BFP):
        pytest.skip(f"brix-fault-proxy build failed:\n{proc.stdout}\n{proc.stderr}")
    return BFP


def _free_port():
    s = socket.socket()
    s.bind((HOST, 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _wait_port(port, deadline=5.0):
    end = time.time() + deadline
    while time.time() < end:
        try:
            with socket.create_connection((HOST, port), timeout=0.25):
                return True
        except OSError:
            time.sleep(0.02)
    return False


class _UdpEcho:
    """UDP echo server: bounces each datagram back to its sender."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((HOST, 0))
        self.port = self.sock.getsockname()[1]
        self._stop = False
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        self.sock.settimeout(0.3)
        while not self._stop:
            try:
                d, a = self.sock.recvfrom(65536)
            except OSError:
                continue
            try:
                self.sock.sendto(d, a)
            except OSError:
                pass

    def close(self):
        self._stop = True
        self.sock.close()


def _spawn_udp(bfp, target_port):
    # A TCP listener is still required by the proxy; the UDP relay rides alongside.
    listen, ctl, uport = _free_port(), _free_port(), _free_port()
    argv = [bfp, "--listen", str(listen), "--target", f"{HOST}:9",
            "--control", str(ctl), "--quiet",
            "--udp", f"{uport} {HOST}:{target_port}"]
    proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    assert _wait_port(ctl), "proxy control never came up"
    time.sleep(0.3)   # let the UDP listener bind
    return proc, uport, ctl


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


def _json(ctl):
    return json.loads(_ctl(ctl, "status json"))


def _udp_rt(uport, payload, timeout=1.0):
    """Send one datagram to the relay; return (reply|None, elapsed)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        t0 = time.time()
        s.sendto(payload, (HOST, uport))
        try:
            d, _ = s.recvfrom(65536)
        except socket.timeout:
            d = None
        return d, time.time() - t0
    finally:
        s.close()


def test_udp_relay_roundtrips(bfp):
    echo = _UdpEcho()
    proc, uport, ctl = _spawn_udp(bfp, echo.port)
    try:
        d, _ = _udp_rt(uport, b"ping")
        assert d == b"ping"
        j = _json(ctl)
        assert j["udp_in"] >= 1 and j["udp_out"] >= 1
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


def test_udp_drop_all(bfp):
    echo = _UdpEcho()
    proc, uport, ctl = _spawn_udp(bfp, echo.port)
    try:
        assert "ok" in _ctl(ctl, "udp-drop 1000000")
        d, _ = _udp_rt(uport, b"ping", timeout=0.5)
        assert d is None                         # every datagram lost
        assert _json(ctl)["udp_dropped"] >= 1
        _ctl(ctl, "udp-drop 0")
        d, _ = _udp_rt(uport, b"again")
        assert d == b"again"                     # disarmed -> relays
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


def test_udp_hold_until_tcp_delays_first(bfp):
    echo = _UdpEcho()
    proc, uport, ctl = _spawn_udp(bfp, echo.port)
    try:
        assert "ok" in _ctl(ctl, "udp-hold-until-tcp 400")
        d, dt = _udp_rt(uport, b"probe", timeout=2.0)
        assert d == b"probe"
        assert dt >= 0.35, f"first datagram not held (dt={dt:.3f}s)"
        assert _json(ctl)["udp_held"] >= 1
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()

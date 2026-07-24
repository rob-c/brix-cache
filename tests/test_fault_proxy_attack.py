"""
test_fault_proxy_attack.py — tests for the attack-mocking toolkit of
brix-fault-proxy (client/apps/diag/brix_fault_proxy.c): content triggers / oracle,
length-field mangling, named presets, connection flapping, global bandwidth budget,
accept-queue pressure, upstream fanout, ramps, and the JSON status snapshot.

These levers let the proxy mock a hostile client/network trying to topple the
service behind it (slowloris, rst-flood, truncate-bomb, pool-exhaust, ...) — all
still root-free and driven over the control port.

The 3-test ritual for this surface:

* SUCCESS  — a content trigger fires a control command when a byte pattern crosses
             the wire; a preset expands to real levers; a length-mangle rewrites a
             header field; flap toggles the service; JSON status reflects state.
* ERROR    — malformed trigger / mangle / ramp specs and an unknown preset are
             rejected with `err:` and leave the stream and levers untouched.
* SECURITY — a trigger's payload and command are literal (never a shell); `clear`
             fully disarms every attack lever including the background flap/ramp
             threads (no lingering out-of-service flapping after disarm).

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
    """Streaming echo upstream that records the FIRST blob each connection sends."""

    def __init__(self):
        self.port = _free_port()
        self.first = []
        self.conns = 0
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", self.port))
        self._srv.listen(16)
        self._stop = False
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        self._srv.settimeout(0.3)
        while not self._stop:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                continue
            self.conns += 1
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
        return s.recv(2048).decode()


def _attack_line(port):
    return [l for l in _ctl(port, "status").splitlines()
            if l.startswith("attack")][0]


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
def test_content_trigger_fires_oracle_command(bfp):
    """When a byte pattern crosses the wire, the armed control command runs."""
    echo = _CapEcho()
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        # Arm: on seeing "BOOM" downstream (server->client), block the service.
        assert "ok" in _ctl(ctl, "trigger down str:BOOM block")
        assert "blocked=0" in _ctl(ctl, "status")
        _roundtrip(listen, b"BOOM")            # echoed back -> downstream sees it
        time.sleep(0.2)
        st = _ctl(ctl, "status")
        assert "blocked=1" in st, "trigger did not fire its command"
        assert "triggered=1" in _attack_line(ctl)
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


def test_preset_expands_to_real_levers(bfp):
    echo = _CapEcho()
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        assert "satellite" in _ctl(ctl, "preset list")
        assert "ok" in _ctl(ctl, "preset satellite")
        st = _ctl(ctl, "status")
        # satellite = latency 600 both + jitter 40 + lossy 1
        assert "lat=600" in st and "jit=40" in st
        # An attack preset that flaps the listener out of service.
        _ctl(ctl, "clear")
        assert "ok" in _ctl(ctl, "preset lb-flap")
        assert "flap=1" in _attack_line(ctl)
        _ctl(ctl, "clear")
        assert "flap=0" in _attack_line(ctl)
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


def test_mangle_len_rewrites_field_and_counts(bfp):
    echo = _CapEcho()
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        assert "mangled=0" in _attack_line(ctl)
        _ctl(ctl, "mangle-len down 0 add 5")   # forge a length byte at offset 0
        _roundtrip(listen, b"HELLO")
        time.sleep(0.1)
        assert "mangle=0/1" in _attack_line(ctl)   # armed on the down direction
        assert "mangled=0" not in _attack_line(ctl)
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


def test_flap_toggles_service_and_json_status(bfp):
    echo = _CapEcho()
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        _ctl(ctl, "flap 80 80")
        # Over ~0.6s the service should be blocked at least once and served at
        # least once (the flap thread toggles ~every 80ms).
        served = blocked = 0
        for _ in range(12):
            try:
                r = _roundtrip(listen, b"x", wait=0.05)
            except OSError:
                r = None                       # reset/refused == out of service
            if r == b"x":
                served += 1
            else:
                blocked += 1
            time.sleep(0.02)
        assert served > 0 and blocked > 0, f"served={served} blocked={blocked}"
        j = _ctl(ctl, "status json").strip()
        assert j.startswith("{") and j.endswith("}")
        assert '"flap":1' in j and '"triggered":' in j
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


def test_global_rate_and_fanout_do_not_break_relay(bfp):
    echo = _CapEcho()
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        _ctl(ctl, "global-rate 256")
        _ctl(ctl, "fanout 3")
        base = echo.conns
        assert _roundtrip(listen, b"payload") == b"payload"
        time.sleep(0.2)
        # fanout opened extra upstream connections beyond the client's one.
        assert echo.conns >= base + 2, f"fanout opened {echo.conns - base} conns"
        assert "fanout=3" in _attack_line(ctl)
        assert "global-rate=256kbps" in _attack_line(ctl)
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


# --------------------------------------------------------------------------- #
# ERROR                                                                        #
# --------------------------------------------------------------------------- #
def test_malformed_attack_specs_rejected(bfp):
    echo = _CapEcho()
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        assert "err:" in _ctl(ctl, "preset does-not-exist")
        assert "err:" in _ctl(ctl, "trigger down")             # missing pat+cmd
        assert "err:" in _ctl(ctl, "trigger down hex:zz block")  # bad payload
        assert "err:" in _ctl(ctl, "mangle-len down 0 mul 5")  # bad op
        assert "err:" in _ctl(ctl, "ramp latency 10")          # missing args
        # None of the rejects should have altered the stream or armed a lever.
        assert _roundtrip(listen, b"clean") == b"clean"
        line = _attack_line(ctl)
        assert "trig=0/0" in line and "mangle=0/0" in line
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()


# --------------------------------------------------------------------------- #
# SECURITY                                                                     #
# --------------------------------------------------------------------------- #
def test_trigger_is_literal_and_clear_disarms_threads(bfp):
    """A trigger command is dispatched through the SAME control parser (never a
    shell), and `clear` must stop the background flap thread so the service is
    not left flapping out of existence after disarm."""
    echo = _CapEcho()
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        # The trigger command text is a control verb, not a shell line: a
        # payload/command bearing shell metacharacters is treated literally and
        # simply fails to match any control verb (no execution, no crash).
        _ctl(ctl, "trigger up str:GO $(touch /tmp/bfp_attack_pwned)")
        _roundtrip(listen, b"GO")
        time.sleep(0.2)
        assert not os.path.exists("/tmp/bfp_attack_pwned")

        # Start a fast flap, then clear: the service must be reliably reachable
        # again (flap thread stopped, listener unblocked).
        _ctl(ctl, "clear")
        _ctl(ctl, "flap 40 40")
        time.sleep(0.1)
        _ctl(ctl, "clear")
        assert "flap=0" in _attack_line(ctl)
        # Give the just-superseded flap thread a beat to exit on its unblock.
        time.sleep(0.2)
        ok = 0
        for _ in range(6):
            try:
                if _roundtrip(listen, b"z", wait=0.05) == b"z":
                    ok += 1
            except OSError:
                pass
        assert ok == 6, f"service still flapping after clear ({ok}/6 reachable)"
    finally:
        proc.terminate(); proc.wait(timeout=5); echo.close()

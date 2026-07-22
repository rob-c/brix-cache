"""
test_brix_fault_proxy.py — CLI + behaviour tests for the first-class
`brix-fault-proxy` tool (client/apps/diag/brix_fault_proxy.c).

The 3-test ritual for the new command-line surface:

* SUCCESS  — `--version`/`--help` print the house strings, and a live relay in
             front of a loopback echo server forwards bytes byte-exact while the
             control port reports and mutates the fault levers.
* ERROR    — malformed / incomplete invocations exit 2 with a usage diagnostic
             (missing required endpoints, a colon-less `--target`, and a mix of
             positional + named forms).
* SECURITY — the *unauthenticated* control port must bind to loopback by default;
             a non-loopback `--bind` is refused unless `--insecure-bind` is also
             given.

Self-contained: builds the tool via `make -C client brix-fault-proxy` and drives
it against its own throwaway echo server on ephemeral ports. No fleet server, so
no registry-server declaration is needed.
"""

import os
import socket
import subprocess
import threading
import time

import pytest

from settings import BIND_HOST, HOST

pytestmark = pytest.mark.timeout(120)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
BFP = os.path.join(CLIENT_DIR, "bin", "brix-fault-proxy")


@pytest.fixture(scope="module")
def bfp():
    """Path to a freshly built brix-fault-proxy (skip if it can't be built)."""
    proc = subprocess.run(["make", "-C", CLIENT_DIR, "brix-fault-proxy"],
                          capture_output=True, text=True, timeout=120)
    if proc.returncode != 0 or not os.path.exists(BFP):
        pytest.skip(f"brix-fault-proxy build failed:\n{proc.stdout}\n{proc.stderr}")
    return BFP


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((BIND_HOST, 0))
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


class _Echo:
    """A trivial upstream: prefixes every received blob with b'echo:'."""

    def __init__(self):
        self.port = _free_port()
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((BIND_HOST, self.port))
        self._srv.listen(8)
        self._stop = False
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()

    def _run(self):
        self._srv.settimeout(0.3)
        while not self._stop:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                continue
            try:
                data = conn.recv(4096)
                if data:
                    conn.sendall(b"echo:" + data)
            except OSError:
                pass
            finally:
                conn.close()

    def close(self):
        self._stop = True
        self._srv.close()


class _StreamEcho:
    """A streaming upstream: echoes every byte it receives, in a loop, so large
    payloads flow back through the proxy where byte-level levers apply."""

    def __init__(self):
        self.port = _free_port()
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((BIND_HOST, self.port))
        self._srv.listen(8)
        self._stop = False
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()

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
        try:
            while not self._stop:
                data = conn.recv(65536)
                if not data:
                    break
                conn.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()

    def close(self):
        self._stop = True
        self._srv.close()


def _drain(sock, want, deadline=3.0):
    """Read up to `want` bytes until the peer closes or the deadline passes."""
    sock.settimeout(0.5)
    end = time.time() + deadline
    out = b""
    while len(out) < want and time.time() < end:
        try:
            d = sock.recv(65536)
        except socket.timeout:
            continue
        except OSError:
            break
        if not d:
            break
        out += d
    return out


def _spawn(bfp, echo_port, extra=None):
    """Start a proxy in front of `echo_port`; return (proc, listen, ctl)."""
    listen, ctl = _free_port(), _free_port()
    argv = [bfp, "--listen", str(listen), "--target", f"{HOST}:{echo_port}",
            "--control", str(ctl), "--quiet"] + (extra or [])
    proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert _wait_port(ctl), "control port never came up"
    assert _wait_port(listen), "listen port never came up"
    return proc, listen, ctl


def _ctl(port, cmd):
    with socket.create_connection((HOST, port), timeout=3) as s:
        s.sendall((cmd + "\n").encode())
        return s.recv(4096).decode()


def _stat_int(ctl, key):
    """Pull an integer `key=NNN` field out of the status line."""
    for tok in _ctl(ctl, "status").replace("]", " ").replace("[", " ").split():
        if tok.startswith(key + "="):
            return int(tok.split("=", 1)[1].rstrip("B"))
    raise AssertionError(f"{key} not in status")


# --------------------------------------------------------------------------- #
# SUCCESS                                                                      #
# --------------------------------------------------------------------------- #

def test_version_and_help(bfp):
    ver = subprocess.run([bfp, "--version"], capture_output=True, text=True, timeout=10)
    assert ver.returncode == 0
    assert ver.stdout.startswith("brix-fault-proxy (BriX-Cache client) ")

    hlp = subprocess.run([bfp, "--help"], capture_output=True, text=True, timeout=10)
    assert hlp.returncode == 0
    assert "usage: brix-fault-proxy" in hlp.stdout
    # every documented lever is advertised
    for lever in ("latency", "jitter", "chunk", "drip", "lossy", "reorder",
                  "drop", "block", "unblock", "clear", "status"):
        assert lever in hlp.stdout


def test_relay_and_control_levers(bfp):
    echo = _Echo()
    listen, ctl = _free_port(), _free_port()
    proc = subprocess.Popen(
        [bfp, "--listen", str(listen), "--target", f"{HOST}:{echo.port}",
         "--control", str(ctl), "--quiet"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert _wait_port(ctl), "control port never came up"
        assert _wait_port(listen), "listen port never came up"

        # byte-exact relay through the proxy
        with socket.create_connection((HOST, listen), timeout=3) as s:
            s.sendall(b"hello")
            assert s.recv(64) == b"echo:hello"

        # levers start off, and a control command mutates one (both directions)
        assert "lat=0" in _ctl(ctl, "status")
        assert _ctl(ctl, "latency 25").strip() == "ok"
        st = _ctl(ctl, "status")
        assert "up[lat=25" in st and "down[lat=25" in st
        # float-percent lossy resolves to ppm and reports back
        _ctl(ctl, "lossy 0.5")
        assert "lossy=0.5000%" in _ctl(ctl, "status")
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        echo.close()


# --------------------------------------------------------------------------- #
# ERROR                                                                        #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("argv, needle", [
    ([], "required"),                                   # nothing supplied
    (["--listen", "1", "--control", "2"], "required"),  # no --target
    (["--listen", "1", "--target", "nocolon", "--control", "2"], "invalid --target"),
    (["--listen", "1", "a", "b", "c", "d"], "unexpected argument"),  # named+positional mix
])
def test_usage_errors_exit_2(bfp, argv, needle):
    proc = subprocess.run([bfp, *argv], capture_output=True, text=True, timeout=10)
    assert proc.returncode == 2, f"expected usage exit for {argv}: {proc.stderr}"
    assert needle in proc.stderr


# --------------------------------------------------------------------------- #
# SECURITY-NEG                                                                 #
# --------------------------------------------------------------------------- #

def test_non_loopback_bind_refused_without_optin(bfp):
    # The control port is unauthenticated: a non-loopback bind must be refused
    # unless the operator explicitly opts in with --insecure-bind.
    proc = subprocess.run(
        [bfp, "--listen", "1", "--target", f"{HOST}:2", "--control", "3",
         "--bind", "0.0.0.0"],  # net-literal-allow: non-loopback bind address is the security subject under test
        capture_output=True, text=True, timeout=10,
    )
    assert proc.returncode == 2
    assert "refusing" in proc.stderr and "non-loopback" in proc.stderr


def test_default_bind_serves_loopback(bfp):
    # With no --bind, the (unauthenticated) control port must come up on 127.0.0.1
    # and answer there — the safe default the security posture relies on. Uses the
    # positional form to also exercise back-compat argument parsing.
    echo = _Echo()
    listen, ctl = _free_port(), _free_port()
    proc = subprocess.Popen(
        [bfp, str(listen), HOST, str(echo.port), str(ctl)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert _wait_port(ctl), "loopback control port not reachable"
        assert "blocked=0" in _ctl(ctl, "status")
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        echo.close()


# --------------------------------------------------------------------------- #
# Payload corruption (killer feature #1) + directionality + counters          #
# --------------------------------------------------------------------------- #

def test_corrupt_down_directional_and_counters(bfp):
    echo = _StreamEcho()
    proc, listen, ctl = _spawn(bfp, echo.port, ["--seed", "1"])
    try:
        # Corrupt only the download path; the request path stays intact.
        assert _ctl(ctl, "corrupt 100 down").strip() == "ok"
        st = _ctl(ctl, "status")
        assert "down[" in st and "corrupt=100.0000%" in st.split("down[")[1]
        assert "corrupt=0.0000%" in st.split("down[")[0]  # up side untouched

        payload = b"A" * 20000
        with socket.create_connection((HOST, listen), timeout=3) as s:
            s.sendall(payload)
            got = _drain(s, len(payload))
        assert len(got) == len(payload), "stream length must be preserved"
        flipped = sum(1 for a, b in zip(payload, got) if a != b)
        assert flipped > 0, "download must be corrupted"

        st2 = _ctl(ctl, "status")
        assert "corrupt=0 " not in st2  # the corruption counter advanced
        assert f"up={len(payload)}B" in st2 and f"down={len(payload)}B" in st2
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        echo.close()


def test_seed_makes_corruption_reproducible(bfp):
    def run_once():
        echo = _StreamEcho()
        proc, listen, ctl = _spawn(bfp, echo.port, ["--seed", "424242"])
        try:
            _ctl(ctl, "corrupt 50 down")
            payload = bytes((i * 7) & 0xFF for i in range(4000))
            with socket.create_connection((HOST, listen), timeout=3) as s:
                s.sendall(payload)
                got = _drain(s, len(payload))
            return [i for i, (a, b) in enumerate(zip(payload, got)) if a != b]
        finally:
            proc.terminate()
            proc.wait(timeout=5)
            echo.close()

    # First connection each run has conn_id==1 → identical per-thread seed →
    # the exact same set of bit-flips.
    assert run_once() == run_once()


# --------------------------------------------------------------------------- #
# Deterministic triggers: truncate-at, fail-nth                               #
# --------------------------------------------------------------------------- #

def test_truncate_at_severs_mid_transfer(bfp):
    echo = _StreamEcho()
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        _ctl(ctl, "truncate-at 5000 down")
        with socket.create_connection((HOST, listen), timeout=3) as s:
            s.sendall(b"B" * 40000)
            got = _drain(s, 40000)
        # The download is cut once ~5000 bytes have flowed — well short of 40000.
        assert 0 < len(got) < 40000
        assert "severs=0" not in _ctl(ctl, "status")
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        echo.close()


def test_fail_nth_fails_only_that_connection(bfp):
    echo = _StreamEcho()
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        # The startup port probe already consumed some connection ids; target the
        # 2nd connection *after* the current count so the arithmetic is exact.
        # The probe's TCP connect returning (inside _spawn) does not mean the
        # proxy has ACCEPTED and counted it yet — read conns only once the
        # counter has stopped moving, or fail-nth lands one connection early.
        base = _stat_int(ctl, "conns")
        settle_end = time.time() + 2.0
        while time.time() < settle_end:
            time.sleep(0.05)
            now = _stat_int(ctl, "conns")
            if now == base:
                break
            base = now
        _ctl(ctl, f"fail-nth {base + 2}")

        def roundtrip():
            with socket.create_connection((HOST, listen), timeout=3) as s:
                s.sendall(b"ping")
                return _drain(s, 4, deadline=1.5)

        assert roundtrip() == b"ping"   # conn base+1 passes
        assert roundtrip() == b""       # conn base+2 is severed with no data
        assert roundtrip() == b"ping"   # conn base+3 passes again
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        echo.close()


# --------------------------------------------------------------------------- #
# Sever styles, black hole, bandwidth, failover                               #
# --------------------------------------------------------------------------- #

def test_reset_severs_live_connection(bfp):
    echo = _StreamEcho()
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        with socket.create_connection((HOST, listen), timeout=3) as s:
            s.sendall(b"hi")
            assert _drain(s, 2, deadline=1.5) == b"hi"
            assert _ctl(ctl, "reset").strip() == "ok"
            # After an abortive reset the live stream is torn down: the next read
            # returns EOF (b"") or raises, and abortive mode is now latched on.
            assert _drain(s, 1, deadline=1.5) == b""
        assert "abortive=1" in _ctl(ctl, "status")
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        echo.close()


def test_hang_black_holes_new_connections(bfp):
    echo = _StreamEcho()
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        _ctl(ctl, "hang")
        with socket.create_connection((HOST, listen), timeout=3) as s:
            s.sendall(b"anyone there?")
            # Black hole: the request is accepted but never relayed or answered.
            assert _drain(s, 1, deadline=1.0) == b""
        _ctl(ctl, "unhang")
        with socket.create_connection((HOST, listen), timeout=3) as s:
            s.sendall(b"now?")
            assert _drain(s, 4, deadline=1.5) == b"now?"
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        echo.close()


def test_rate_limit_throttles(bfp):
    echo = _StreamEcho()
    # 100 KB/s cap; pushing 200 KB back through must take appreciably longer than
    # an unthrottled loopback round-trip (which is sub-10 ms).
    proc, listen, ctl = _spawn(bfp, echo.port)
    try:
        _ctl(ctl, "rate 100 down")
        payload = b"C" * 200000
        start = time.time()
        with socket.create_connection((HOST, listen), timeout=5) as s:
            s.sendall(payload)
            got = _drain(s, len(payload), deadline=8.0)
        elapsed = time.time() - start
        assert len(got) == len(payload)
        assert elapsed > 0.8, f"rate cap did not throttle (took {elapsed:.2f}s)"
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        echo.close()


def test_multi_target_failover(bfp):
    # First target is dead (nothing listening); the pool must fail over to the
    # live echo so the relay still succeeds.
    echo = _StreamEcho()
    dead = _free_port()
    listen, ctl = _free_port(), _free_port()
    proc = subprocess.Popen(
        [bfp, "--listen", str(listen), "--target", f"{HOST}:{dead}",
         "--target", f"{HOST}:{echo.port}", "--control", str(ctl), "--quiet"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        assert _wait_port(ctl) and _wait_port(listen)
        got = b""
        for _ in range(4):  # a couple of round-robin picks land on the dead one
            with socket.create_connection((HOST, listen), timeout=3) as s:
                s.sendall(b"hello")
                got = _drain(s, 5, deadline=1.5)
                if got == b"hello":
                    break
        assert got == b"hello", "failover to the live target never succeeded"
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        echo.close()


def test_max_conns_refuses_over_cap(bfp):
    echo = _StreamEcho()
    proc, listen, ctl = _spawn(bfp, echo.port, ["--max-conns", "1"])
    held = None
    try:
        # Let the startup probe connection fully drain so `active` is back to 0.
        for _ in range(50):
            if _stat_int(ctl, "active") == 0:
                break
            time.sleep(0.02)
        # Hold one relay open (no upstream EOF because StreamEcho stays open).
        held = socket.create_connection((HOST, listen), timeout=3)
        held.sendall(b"hold")
        assert _drain(held, 4, deadline=1.5) == b"hold"
        time.sleep(0.2)
        # A second connection is over the cap: accepted then immediately closed.
        with socket.create_connection((HOST, listen), timeout=3) as s2:
            s2.sendall(b"second")
            assert _drain(s2, 6, deadline=1.0) == b""
        assert "refused=0" not in _ctl(ctl, "status")
    finally:
        if held is not None:
            held.close()
        proc.terminate()
        proc.wait(timeout=5)
        echo.close()


def test_help_advertises_new_levers(bfp):
    hlp = subprocess.run([bfp, "--help"], capture_output=True, text=True, timeout=10)
    assert hlp.returncode == 0
    for lever in ("corrupt", "dup", "rate", "truncate-at", "fail-nth",
                  "heal-after", "half-close", "hang", "reset", "one-shot",
                  "--seed", "--script", "--max-conns"):
        assert lever in hlp.stdout, f"{lever} missing from --help"

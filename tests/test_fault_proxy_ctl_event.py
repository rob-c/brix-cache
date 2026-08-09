"""
test_fault_proxy_ctl_event.py — the two first-party optional modules bolted onto
the v1.3.0 brix-fault-proxy core: the built-in `ctl` control-port client
subcommand (brix_fault_proxy_ctl.c) and the append-only JSONL fault-event log
(brix_fault_proxy_event.c). Both are decoupled from the core's private lever
state (they cross the boundary only through brix_fault_proxy_mods.h), so this
exercises them end-to-end against a live relay.

The 3-test ritual, per feature:

ctl subcommand
* SUCCESS  — `ctl HOST:PORT "status"` dials the control port, prints the status
             line, and exits 0; the `-` form streams a batch of verbs from stdin.
* ERROR    — an unknown verb draws an `err:` reply and the scriptable exit 3;
             too few positional args exit 2 with a usage diagnostic.
* SECURITY — a control port that cannot be reached exits 4 (the connect-failure
             contract) rather than hanging or reporting a false success.

event-log
* SUCCESS  — a configured `--event-log` records one JSONL object per discrete
             fault (refuse on a blocked accept, sever on a truncate cut), each a
             well-formed object carrying only structural metadata.
* ERROR    — an unopenable `--event-log` path fails closed at startup (exit 1, a
             runtime/environment failure — not a CLI usage error), never
             launching a relay that silently drops its audit trail.
* SECURITY — relayed payload bytes are NEVER written to the log: a known secret
             pushed through a severed transfer appears nowhere in the JSONL.

Self-contained: builds the tool via `make -C client brix-fault-proxy` and drives
it against a throwaway echo server on ephemeral ports. No fleet server, so no
registry-server declaration is needed.
"""

import json
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


class _StreamEcho:
    """A streaming upstream: echoes every byte it receives so a payload flows
    back through the proxy where the byte-level truncate lever applies."""

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


def _spawn(bfp, echo_port, extra=None):
    """Start a proxy in front of `echo_port`; return (proc, listen, ctl)."""
    listen, ctl = _free_port(), _free_port()
    argv = [bfp, "--listen", str(listen), "--target", f"{HOST}:{echo_port}",
            "--control", str(ctl), "--quiet"] + (extra or [])
    proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert _wait_port(ctl), "control port never came up"
    assert _wait_port(listen), "listen port never came up"
    return proc, listen, ctl


def _ctl_raw(port, cmd):
    """Drive the control port directly (bypassing the ctl subcommand)."""
    with socket.create_connection((HOST, port), timeout=3) as s:
        s.sendall((cmd + "\n").encode())
        return s.recv(4096).decode()


def _ctl_sub(bfp, port, cmd, stdin=None):
    """Invoke the built-in `ctl` client subcommand; return the CompletedProcess."""
    return subprocess.run(
        [bfp, "ctl", f"{HOST}:{port}", cmd if stdin is None else "-"],
        input=stdin, capture_output=True, text=True, timeout=10,
    )


# --------------------------------------------------------------------------- #
# ctl subcommand — SUCCESS                                                     #
# --------------------------------------------------------------------------- #

def test_ctl_status_success(bfp):
    """`ctl HOST:PORT status` prints the live status line and exits 0."""
    echo = _StreamEcho()
    proc, _listen, ctl = _spawn(bfp, echo.port)
    try:
        r = _ctl_sub(bfp, ctl, "status")
        assert r.returncode == 0, r.stderr
        # the same aggregate the raw control port yields, reached without `nc`
        assert "blocked=0" in r.stdout and "conns=" in r.stdout
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        echo.close()


def test_ctl_stdin_batch_mutates_lever(bfp):
    """The `-` form streams a batch of verbs from stdin; the last reply is
    surfaced and the mutation is observable on the control port afterwards."""
    echo = _StreamEcho()
    proc, _listen, ctl = _spawn(bfp, echo.port)
    try:
        r = _ctl_sub(bfp, ctl, "-", stdin="latency 25\nstatus\n")
        assert r.returncode == 0, r.stderr
        assert "up[lat=25" in _ctl_raw(ctl, "status")
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        echo.close()


# --------------------------------------------------------------------------- #
# ctl subcommand — ERROR                                                       #
# --------------------------------------------------------------------------- #

def test_ctl_unknown_verb_exits_3(bfp):
    """An `err:` reply maps to the scriptable exit code 3, distinct from a
    connect failure (4) — a script can tell 'server said no' from 'no server'."""
    echo = _StreamEcho()
    proc, _listen, ctl = _spawn(bfp, echo.port)
    try:
        r = _ctl_sub(bfp, ctl, "bogus-verb-not-a-command")
        assert r.returncode == 3, r.stdout + r.stderr
        assert "err:" in r.stdout
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        echo.close()


def test_ctl_missing_args_exits_2(bfp):
    """Too few positionals is a usage error (exit 2) with a diagnostic — never a
    silent success or a hang."""
    r = subprocess.run([bfp, "ctl", f"{HOST}:1"],
                       capture_output=True, text=True, timeout=10)
    assert r.returncode == 2
    assert "usage:" in r.stderr and "ctl" in r.stderr


# --------------------------------------------------------------------------- #
# ctl subcommand — SECURITY / NEG                                             #
# --------------------------------------------------------------------------- #

def test_ctl_connect_failure_exits_4(bfp):
    """A control port that cannot be reached exits 4 (connect-failure contract)
    rather than hanging or reporting a false success — the bounded-timeout dial
    fails fast on a dead port."""
    dead = _free_port()  # nothing is listening here
    r = _ctl_sub(bfp, dead, "status")
    assert r.returncode == 4, r.stdout + r.stderr
    assert "cannot reach" in r.stderr


# --------------------------------------------------------------------------- #
# event-log — SUCCESS                                                          #
# --------------------------------------------------------------------------- #

def test_event_log_records_refuse_and_sever(bfp, tmp_path):
    """A configured event log records one well-formed JSONL object per discrete
    fault: a `refuse` when a blocked accept turns a client away, and a `sever`
    (reason=truncate) when the byte-count cut fires mid-transfer."""
    log = tmp_path / "events.jsonl"
    echo = _StreamEcho()
    proc, listen, ctl = _spawn(bfp, echo.port, extra=["--event-log", str(log)])
    try:
        # 1) refuse: block accepts, then a connection is turned away
        assert _ctl_raw(ctl, "block").strip() == "ok"
        with socket.create_connection((HOST, listen), timeout=2) as s:
            s.settimeout(1.0)
            try:
                assert s.recv(16) == b""   # refused: immediate EOF
            except socket.timeout:
                pass

        # 2) sever: unblock, arm a 4-byte truncate, drive a transfer past it
        _ctl_raw(ctl, "unblock")
        _ctl_raw(ctl, "truncate-at 4 down")
        with socket.create_connection((HOST, listen), timeout=2) as s:
            s.settimeout(1.0)
            s.sendall(b"ABCDEFGH")
            got = b""
            try:
                while len(got) < 8:
                    chunk = s.recv(64)
                    if not chunk:
                        break
                    got += chunk
            except socket.timeout:
                pass
            assert got == b"ABCD"   # cut at the 4-byte boundary

        # the trail: parse every line as JSON, assert both events are present
        deadline = time.time() + 3.0
        events = []
        while time.time() < deadline:
            if log.exists():
                events = [json.loads(ln) for ln in
                          log.read_text().splitlines() if ln.strip()]
                if any(e["event"] == "refuse" for e in events) and \
                   any(e["event"] == "sever" for e in events):
                    break
            time.sleep(0.05)

        kinds = {e["event"] for e in events}
        assert "refuse" in kinds, events
        assert "sever" in kinds, events
        sever = next(e for e in events if e["event"] == "sever")
        assert sever["reason"] == "truncate"
        # every record is structural metadata: fixed key set, numeric conn id
        for e in events:
            # structural metadata only — numeric offsets/counts (at/count) are
            # structural, never payload bytes; the security property is that no
            # relayed byte is ever written, verified by test_log_holds_no_payload.
            assert set(e) <= {"t", "route", "conn", "dir", "event", "reason",
                              "at", "count"}
            assert isinstance(e["conn"], int)
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        echo.close()


# --------------------------------------------------------------------------- #
# event-log — ERROR                                                           #
# --------------------------------------------------------------------------- #

def test_event_log_bad_path_fails_closed(bfp, tmp_path):
    """An unopenable --event-log path fails closed at startup (exit 1, a runtime
    failure — not a CLI usage error): the proxy must not launch a relay that
    silently drops its audit trail."""
    bad = tmp_path / "no-such-dir" / "events.jsonl"   # parent does not exist
    r = subprocess.run(
        [bfp, "--listen", str(_free_port()), "--target", f"{HOST}:{_free_port()}",
         "--control", str(_free_port()), "--event-log", str(bad), "--quiet"],
        capture_output=True, text=True, timeout=10,
    )
    assert r.returncode == 1, r.stdout + r.stderr
    assert "event-log" in r.stderr
    assert not bad.exists()


# --------------------------------------------------------------------------- #
# event-log — SECURITY / NEG                                                  #
# --------------------------------------------------------------------------- #

def test_event_log_never_records_payload_bytes(bfp, tmp_path):
    """The event log is provenance, not a payload capture: a known secret pushed
    through a severed transfer must appear NOWHERE in the JSONL trail."""
    secret = b"TOPSECRET-CANARY-4c9f2a"
    log = tmp_path / "events.jsonl"
    echo = _StreamEcho()
    proc, listen, ctl = _spawn(bfp, echo.port, extra=["--event-log", str(log)])
    try:
        _ctl_raw(ctl, "truncate-at 4 down")   # sever will fire on this transfer
        with socket.create_connection((HOST, listen), timeout=2) as s:
            s.settimeout(1.0)
            s.sendall(secret)
            try:
                while s.recv(64):
                    pass
            except socket.timeout:
                pass

        # wait for the sever event to land, then scan the raw bytes of the log
        deadline = time.time() + 3.0
        raw = b""
        while time.time() < deadline:
            if log.exists():
                raw = log.read_bytes()
                if b'"sever"' in raw:
                    break
            time.sleep(0.05)
        assert b'"sever"' in raw, "sever event never recorded"
        assert secret not in raw
        # not even a prefix of the payload leaks
        assert b"TOPSECRET" not in raw and b"CANARY" not in raw
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        echo.close()

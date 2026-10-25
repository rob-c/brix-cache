"""
tests/test_net_resilience.py — client hardening against a misbehaving firewall.

WHAT: Covers the connect/handshake timeout decoupling, the retry backoff, and the
      fire-and-forget session teardown that keep a FUSE mount (and every libbrix
      tool) responsive on a network that hangs / intercepts / intermittently
      drops connections (a misbehaving inline firewall).

WHY:  The classic firewall failure is "TCP connect succeeds, then the protocol
      bytes are black-holed." Before the fix the caller hung for the full I/O
      timeout (30s) on bring-up, and teardown waited a second timeout for an
      endsess reply that never came. Bring-up must now fail in ~the (short,
      tunable) connect timeout, and exactly once (no doubling).

HOW:  nettmo_test exercises the backoff/timeout pure logic. The handshake test
      points wait41 --full at a black-hole listener (accepts the TCP connection,
      never speaks the protocol) and asserts bring-up fails in ~the connect cap.

Run:
  PYTHONPATH=tests python3 -m pytest tests/test_net_resilience.py -v
"""
import os
import socket
import subprocess
from brix_suite.client_build import client_make
from lib_py.client_toolchain import client_test_env
import sys
import time

import pytest
from settings import BIND_HOST, HOST

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
NETTMO = os.path.join(CLIENT_DIR, "bin", "nettmo_test")
WAIT41 = os.path.join(CLIENT_DIR, "bin", "wait41-brix")


def _run_env():
    """Use the selected native SDK, not an unrelated inactive Conda prefix."""
    return client_test_env()


@pytest.fixture(scope="module", autouse=True)
def _build():
    # Build the real archive first: -W libbrix.a relinks with stale members.
    result = client_make(CLIENT_DIR, "libbrix.a", "nettmo", "wait41-brix",
                         env=_run_env(), stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, timeout=300)
    assert result.returncode == 0, result.stdout.decode(errors="replace")[-3000:]
    assert os.path.exists(NETTMO) and os.path.exists(WAIT41)


def test_backoff_and_timeout_units():
    """Backoff is exponential+capped+jittered; timeout setter beats the default."""
    p = subprocess.run([NETTMO], env=_run_env(),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    err = p.stderr.decode(errors="replace")
    assert p.returncode == 0, err
    assert "FAIL" not in err, err


def _blackhole_bringup_seconds(connect_timeout_ms):
    """Time one wait41 --full bring-up against a TCP black-hole (accept, then
    swallow the protocol bytes)."""
    def listener(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((BIND_HOST, port))
        except OSError:
            sock.close()
            raise
        return sock

    from ephemeral_port import bind_port
    port, lst = bind_port(listener, BIND_HOST)
    lst.listen(8)
    try:
        env = _run_env()
        env["XRDC_CONNECT_TIMEOUT_MS"] = str(connect_timeout_ms)
        t = time.time()
        # --timeout 0 => exactly one bring-up attempt (no outer retry loop).
        p = subprocess.run(
            [WAIT41, "--timeout", "0", "--full", f"root://{HOST}:{port}"],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
        )
        return time.time() - t, p.returncode
    finally:
        lst.close()


def test_handshake_timeout_is_bounded():
    """A black-holed handshake must fail in ~the connect cap, NOT the 30s I/O
    timeout — proving bring-up is bounded by the short connect timeout."""
    elapsed, rc = _blackhole_bringup_seconds(1000)
    assert rc != 0, "bring-up should fail against a black-hole"
    assert elapsed < 4.0, f"bring-up took {elapsed:.1f}s; should be ~1s (connect cap)"


def test_handshake_timeout_tracks_the_knob_no_doubling():
    """Bring-up time tracks the connect cap at ~1x (not 2x): the teardown is
    fire-and-forget, so a black-holed endsess reply no longer doubles failure
    time. cap=4000ms ⇒ ~4s, not ~8s."""
    elapsed, rc = _blackhole_bringup_seconds(4000)
    assert rc != 0
    assert 3.0 < elapsed < 7.0, (
        f"bring-up took {elapsed:.1f}s; expected ~4s (1x the cap, no endsess doubling)"
    )

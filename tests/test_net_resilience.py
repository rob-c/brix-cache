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
import sys
import time

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
NETTMO = os.path.join(CLIENT_DIR, "bin", "nettmo_test")
WAIT41 = os.path.join(CLIENT_DIR, "bin", "wait41")


def _run_env():
    """Inherit the environment. When built against a conda toolchain (this
    project's optional codec/krb5 libs live there), make those libs resolvable
    for both the link step (PKG_CONFIG_PATH) and the runtime loader
    (LD_LIBRARY_PATH) so the build and the binaries are self-consistent. A no-op
    when CONDA_PREFIX is unset (e.g. a system / RPM build)."""
    env = dict(os.environ)
    # The interpreter's own prefix (sys.prefix) reliably points at the conda/venv
    # toolchain even when CONDA_PREFIX is not exported; fall back to it.
    prefix = env.get("CONDA_PREFIX") or sys.prefix
    pcdir = os.path.join(prefix, "lib", "pkgconfig")
    if os.path.isdir(pcdir):
        libdir = os.path.join(prefix, "lib")
        env["LD_LIBRARY_PATH"] = libdir + os.pathsep + env.get("LD_LIBRARY_PATH", "")
        env["PKG_CONFIG_PATH"] = pcdir + os.pathsep + env.get("PKG_CONFIG_PATH", "")
    return env


@pytest.fixture(scope="module", autouse=True)
def _build():
    # Build only when a binary is missing (a failed link would delete a good
    # pre-built one). The link needs optional codec/krb5 libs whose pkg-config
    # entries vary by environment; if it fails and the binaries are absent, skip.
    out = b""
    if not (os.path.exists(NETTMO) and os.path.exists(WAIT41)):
        r = subprocess.run(
            ["make", "nettmo", "wait41"],
            cwd=CLIENT_DIR, env=_run_env(),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300,
        )
        out = r.stdout
    if not (os.path.exists(NETTMO) and os.path.exists(WAIT41)):
        pytest.skip("client test binaries not built (run `make -C client nettmo "
                    f"wait41`):\n{out.decode(errors='replace')[-800:]}")


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
    lst = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lst.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lst.bind(("127.0.0.1", 0))
    port = lst.getsockname()[1]
    lst.listen(8)
    try:
        env = _run_env()
        env["XRDC_CONNECT_TIMEOUT_MS"] = str(connect_timeout_ms)
        t = time.time()
        # --timeout 0 => exactly one bring-up attempt (no outer retry loop).
        p = subprocess.run(
            [WAIT41, "--timeout", "0", "--full", f"root://127.0.0.1:{port}"],
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

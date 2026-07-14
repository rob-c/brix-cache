"""
tests/test_ipv6_fallback.py — client IPv6→IPv4 auto-downgrade on dual-stack hosts.

WHAT: Exercises the native-client connect chokepoint (brix_tcp_connect / netpref.c)
      that keeps a FUSE mount (and every other libbrix client) working — silently
      and correctly — on a dual-stack host whose IPv6 path is broken but whose
      IPv4 backend is fine. After the first IPv6 failure where IPv4 then works the
      whole session demotes to IPv4-only, logging the downgrade exactly once.

WHY:  This is the "laptop on a network with busted IPv6" scenario: the mount must
      not stall on a dead v6 address for every new socket, must keep serving over
      v4, and must say so once so an operator can see what happened.

HOW:  No real broken network needed. A getaddrinfo LD_PRELOAD shim
      (tests/c/gai_shim.c) makes the sentinel host "dualstack.invalid" resolve to
      [::1, 127.0.0.1]; the test binds an IPv4-only listener so the ::1 candidate
      is refused and the connect falls back to v4. Three modes assert: the pure
      state machine, the connect+demote path (log fires once), and the opt-out
      (XRDC_NO_IPV6_FALLBACK keeps retrying v6, never demotes, no log).

Run:
  PYTHONPATH=tests python3 -m pytest tests/test_ipv6_fallback.py -v
"""
import os
import socket
import subprocess
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
NETFB = os.path.join(CLIENT_DIR, "bin", "netfb_test")
SHIM = os.path.join(CLIENT_DIR, "bin", "gai_shim.so")
WAIT41 = os.path.join(CLIENT_DIR, "bin", "wait41-brix")

DOWNGRADE_MARK = "downgrading this session to IPv4-only"
REVERT_MARK = "reverting to dual-stack"
SENTINEL = "dualstack.invalid"   # resolved to [::1, 127.0.0.1] by gai_shim


def _ipv6_loopback_ok():
    """True if ::1 loopback can be bound — the shim's v6 candidate needs it."""
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.bind(("::1", 0))
        s.close()
        return True
    except OSError:
        return False


def _base_env():
    """Inherit env; when built against a conda toolchain, make the optional
    codec/krb5 libs resolvable for both link (PKG_CONFIG_PATH) and runtime
    (LD_LIBRARY_PATH). A no-op when CONDA_PREFIX is unset (system / RPM build)."""
    env = dict(os.environ)
    # sys.prefix reliably points at the conda/venv toolchain even when
    # CONDA_PREFIX is not exported.
    prefix = env.get("CONDA_PREFIX") or sys.prefix
    pcdir = os.path.join(prefix, "lib", "pkgconfig")
    if os.path.isdir(pcdir):
        libdir = os.path.join(prefix, "lib")
        env["LD_LIBRARY_PATH"] = libdir + os.pathsep + env.get("LD_LIBRARY_PATH", "")
        env["PKG_CONFIG_PATH"] = pcdir + os.pathsep + env.get("PKG_CONFIG_PATH", "")
    return env


@pytest.fixture(scope="module", autouse=True)
def _build():
    """Build the test driver + shim + a real shipped tool (no server needed)."""
    # Build only when a binary is missing (a failed link would delete a good
    # pre-built one). The link needs optional codec/krb5 libs whose pkg-config
    # entries vary by environment; if it fails and the binaries are absent, skip.
    out = b""
    need = [NETFB, SHIM, WAIT41]
    if not all(os.path.exists(p) for p in need):
        r = subprocess.run(
            ["make", "netfb", "gai-shim", "wait41-brix"],
            cwd=CLIENT_DIR, env=_base_env(),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300,
        )
        out = r.stdout
    if not all(os.path.exists(p) for p in need):
        pytest.skip("client test binaries not built (run `make -C client netfb "
                    f"gai-shim wait41-brix`):\n{out.decode(errors='replace')[-800:]}")


def _run(mode, *, preload=False, env_extra=None):
    env = _base_env()
    if preload:
        env["LD_PRELOAD"] = SHIM
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [NETFB, mode], env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
    )


def test_netpref_state_machine():
    """Sticky demote: AF_UNSPEC → (demote) → AF_INET, idempotent, logs once."""
    p = _run("state")
    err = p.stderr.decode(errors="replace")
    assert p.returncode == 0, err
    assert "FAIL" not in err, err
    # The one-shot log must appear exactly once even across repeated demotes.
    assert err.count(DOWNGRADE_MARK) == 1, err


def test_connect_falls_back_and_demotes():
    """Broken v6 + working v4 ⇒ connect succeeds, session demotes, logs once."""
    if not _ipv6_loopback_ok():
        pytest.skip("no usable ::1 loopback on this host")
    p = _run("connect", preload=True)
    err = p.stderr.decode(errors="replace")
    assert p.returncode == 0, err
    assert "FAIL" not in err, err
    assert err.count(DOWNGRADE_MARK) == 1, err


def test_opt_out_keeps_retrying_ipv6():
    """XRDC_NO_IPV6_FALLBACK: connect still works but never demotes / logs."""
    if not _ipv6_loopback_ok():
        pytest.skip("no usable ::1 loopback on this host")
    p = _run("disabled", preload=True, env_extra={"XRDC_NO_IPV6_FALLBACK": "1"})
    err = p.stderr.decode(errors="replace")
    assert p.returncode == 0, err
    assert "FAIL" not in err, err
    assert DOWNGRADE_MARK not in err, err


def test_wire_error_state_machine():
    """The wire-error trigger as a state machine: AF_INET error is ignored, an
    AF_INET6 error demotes, and undo_demote reverts."""
    p = _run("wirestate")
    err = p.stderr.decode(errors="replace")
    assert p.returncode == 0, err
    assert "FAIL" not in err, err
    assert err.count(DOWNGRADE_MARK) == 1, err
    assert REVERT_MARK in err, err


def test_established_ipv6_connection_drop_demotes():
    """The headline case: a connection that came up over IPv6 and then fails over
    the wire (peer drops it mid-read) drops the session to IPv4-only, logged once.
    This is what makes a FUSE mount keep working after IPv6 goes bad mid-session."""
    if not _ipv6_loopback_ok():
        pytest.skip("no usable ::1 loopback on this host")
    p = _run("wireerror")
    err = p.stderr.decode(errors="replace")
    assert p.returncode == 0, err
    assert "FAIL" not in err, err
    assert err.count(DOWNGRADE_MARK) == 1, err


def test_self_heal_on_ipv6_only_host():
    """A demoted session that then meets an IPv6-only host (no A record) must
    revert to dual-stack and still connect over IPv6 — so an optimistic wire-error
    demotion can never strand a mount whose only working path is IPv6."""
    if not _ipv6_loopback_ok():
        pytest.skip("no usable ::1 loopback on this host")
    p = _run("selfheal", preload=True)
    err = p.stderr.decode(errors="replace")
    assert p.returncode == 0, err
    assert "FAIL" not in err, err
    assert REVERT_MARK in err, err


def test_real_tool_binary_downgrades():
    """End-to-end through a real shipped tool (wait41): the shared connect path
    means ANY libbrix client — xrdcp/xrdfs/xrddiag/FUSE — downgrades, not just
    the test harness. wait41 does a bare brix_tcp_connect to the sentinel host;
    with an IPv4-only listener it must report ready AND log the downgrade once."""
    if not _ipv6_loopback_ok():
        pytest.skip("no usable ::1 loopback on this host")

    lst = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lst.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lst.bind(("127.0.0.1", 0))
    port = lst.getsockname()[1]
    lst.listen(8)
    try:
        env = _base_env()
        env["LD_PRELOAD"] = SHIM
        p = subprocess.run(
            [WAIT41, "--timeout", "5", f"root://{SENTINEL}:{port}"],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20,
        )
    finally:
        lst.close()

    out = p.stdout.decode(errors="replace")
    err = p.stderr.decode(errors="replace")
    assert p.returncode == 0, f"out={out!r} err={err!r}"
    assert "ready" in out, out
    assert err.count(DOWNGRADE_MARK) == 1, err

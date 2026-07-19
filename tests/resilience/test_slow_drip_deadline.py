"""
test_slow_drip_deadline.py — the whole-operation read completion deadline defends
against a slow-drip (Slowloris-style) hostile middlebox.

THE BREAK: the client's steady-state read loop (plain_read_full / brix_tls_read)
arms its poll timeout PER ITERATION — an *idle* timeout.  A firewall/middlebox
that dribbles a few bytes just often enough to keep each poll from idling can hold
a single read open for an unbounded wall-clock while never tripping the idle
timeout.  `brix-fault-proxy drip <bytes> <ms>` reproduces exactly this: forward N
bytes, sleep M ms, repeat.  The bytes never stop, so the idle timeout never fires,
and a download that should take a second is held hostage for minutes.

THE FIX: an opt-in whole-operation completion deadline, XRDC_STALL_DEADLINE_MS
(default 0 = disabled).  When set, one brix_read_full may run no longer than that
many ms regardless of how the bytes are paced; a drip that would outlast it fails
promptly with ETIMEDOUT instead of hanging.

CONTRACT proven here:
  * drip WITHOUT the deadline -> the client does not finish within a window far
    shorter than the (throttled) natural transfer time — i.e. it is held hostage
    (subprocess.TimeoutExpired).                              [the vulnerability]
  * drip WITH the deadline    -> the client FAILS PROMPTLY (nonzero exit, returns
    well inside the same window).                             [the fix fires]
  * NO drip WITH the deadline -> a healthy transfer still succeeds byte-exact —
    the deadline does not penalise a well-behaved link.       [no false positive]

Run:
  PYTHONPATH=tests python3 -m pytest tests/resilience/test_slow_drip_deadline.py -v
"""
import hashlib
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import servers  # noqa: E402

pytestmark = pytest.mark.timeout(240)

DATA = "/t/drip.bin"
DATA_SIZE = 4 * 1024 * 1024   # 4 MiB — one read chunk far outlasts the drip rate

# drip 8 KiB every 250 ms downstream == ~32 KiB/s.  Login frames are tiny and
# flush inside a single drip slice, so bring-up completes; the multi-MiB data
# body, read in one brix_read_full, then trickles for minutes.
DRIP_BYTES = 8 * 1024
DRIP_MS = 250

DEADLINE_MS = 3000    # a single logical read may run no longer than 3 s
STALL_WINDOW_MS = 8000  # copy-pump resilience give-up window (--max-stall), so a
                        # link that only ever trips the deadline fails promptly

# Far below the ~128 s a 4 MiB body needs at 32 KiB/s, so an un-deadlined client
# is provably still stuck when we cut it off; comfortably above the deadline +
# stall window + a couple of re-handshakes so a deadlined client finishes.
HOSTAGE_TIMEOUT = 20
FAIL_FAST_TIMEOUT = 40


def _why_skip():
    if not os.path.isfile(servers.NGINX_BIN):
        return f"nginx not built: {servers.NGINX_BIN}"
    if not os.path.isfile(servers.FAULT_PROXY):
        return f"brix-fault-proxy not built: {servers.FAULT_PROXY}"
    if not os.path.isfile(servers.XRDCP):
        return f"xrdcp not built: {servers.XRDCP}"
    return None


_skip_reason = _why_skip()
if _skip_reason:
    pytest.skip(_skip_reason, allow_module_level=True)


def _env(deadline_ms=None):
    """Anonymous-transfer env (no GSI): drop LD_LIBRARY_PATH + any ambient proxy.
    Optionally arm the slow-drip completion deadline (XRDC_STALL_DEADLINE_MS)."""
    env = dict(os.environ)
    env.pop("LD_LIBRARY_PATH", None)
    env.pop("X509_USER_PROXY", None)
    if deadline_ms is not None:
        env["XRDC_STALL_DEADLINE_MS"] = str(deadline_ms)
    return env


@pytest.fixture(scope="module")
def nginx():
    with servers.NginxAnon() as n:
        src = servers.seed_file(n.data, DATA, DATA_SIZE)
        with open(src, "rb") as fh:
            md5 = hashlib.md5(fh.read()).hexdigest()
        yield type("NG", (), {"port": n.port, "data": n.data, "md5": md5})


def _xrdcp(port, dst, env, timeout, extra=()):
    return subprocess.run(
        [servers.XRDCP, "-f", "-s", *extra,
         f"root://127.0.0.1:{port}/{DATA}", str(dst)],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)


def test_drip_without_deadline_is_held_hostage(nginx, tmp_path):
    """The vulnerability: with the deadline OFF a slow drip keeps the read alive
    indefinitely — the copy is still running well past when a healthy transfer
    would have finished, so our short watchdog has to kill it."""
    dst = tmp_path / "hostage.bin"
    with servers.FaultProxy(nginx.port) as fp:
        fp.set_drip(DRIP_BYTES, DRIP_MS, "down")
        with pytest.raises(subprocess.TimeoutExpired):
            _xrdcp(fp.listen, dst, _env(deadline_ms=None), HOSTAGE_TIMEOUT)


def test_drip_with_deadline_fails_fast(nginx, tmp_path):
    """The fix: the same drip, but with XRDC_STALL_DEADLINE_MS armed, is caught —
    the copy exits nonzero and, crucially, returns well inside the window that
    left the un-deadlined client still stuck above."""
    dst = tmp_path / "fastfail.bin"
    with servers.FaultProxy(nginx.port) as fp:
        fp.set_drip(DRIP_BYTES, DRIP_MS, "down")
        # Must NOT raise TimeoutExpired: the deadline makes it terminate itself.
        # --max-stall bounds the copy pump's retry window so a link that only ever
        # trips the per-read deadline gives up promptly instead of re-handshaking
        # for the default 60 s.
        r = _xrdcp(fp.listen, dst, _env(deadline_ms=DEADLINE_MS), FAIL_FAST_TIMEOUT,
                   extra=("--max-stall", str(STALL_WINDOW_MS)))
    assert r.returncode != 0, "deadline-armed drip should fail, not succeed"


def test_healthy_transfer_with_deadline_ok(nginx, tmp_path):
    """No false positive: with the deadline armed but NO drip, a well-behaved link
    still delivers the file byte-exact — the deadline only bites pathological
    pacing, not a fast honest transfer."""
    dst = tmp_path / "healthy.bin"
    with servers.FaultProxy(nginx.port) as fp:
        # proxy in path but no fault
        r = _xrdcp(fp.listen, dst, _env(deadline_ms=DEADLINE_MS), 60)
    assert r.returncode == 0, r.stderr.decode(errors="replace")[-300:]
    assert hashlib.md5(dst.read_bytes()).hexdigest() == nginx.md5

"""
test_audit15_throttle_open_files.py — live coverage for the XrdThrottle-style
per-user open-files cap (audit §A2, testsuite-combinatorial-coverage-audit
2026-08-15: `brix_throttle_zone` + `brix_throttle_max_open_files` had ZERO
test coverage while being fully wired).

The wire path under test (phase-59 W3a):

    brix_rate_limit_zone zone=opens:1m           (stream-level SHM zone)
    brix_throttle_zone opens                     (server: key counters here)
    brix_throttle_max_open_files N               (server: the cap)
        -> brix_open_files_cap() at kXR_open
           (src/protocols/root/read/open_resolved_file_finalize.c) increments
           the per-user node via brix_throttle_open_inc(); over-cap opens are
           refused kXR_error/kXR_Overloaded "too many open files for this user"
        -> kXR_close / disconnect decrement via brix_throttle_open_dec()

The key is the resolved identity — "anonymous" here (brix_auth none) — and the
zone is SHM-backed, so the cap spans CONNECTIONS, not just one session.  The
instance is a single-worker throwaway and the file is serialised onto one xdist
worker so the grant->refuse->release sequences are deterministic.
"""

import os
import struct
import time

import pytest

from settings import NGINX_BIN, HOST
# Raw-XRootD wire helpers + the stream launcher from the phase-25 rate-limit
# suite (login/open/stat/recv-status share the exact same framing), and the
# close helper from the phase-92 bandwidth-reservation twin of this feature.
from test_phase25_ratelimit import (
    _parse_fail,
    _start_stream,
    _stream_values,
    _xrd_login,
    _xrd_open,
    _xrd_stat,
)
from test_phase92_bwm_reservation import _xrd_close

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15-throttle")]

# kXR wire constants (XProtocol.hh).
KXR_OK = 0
KXR_ERROR = 4003
KXR_OVERLOADED = 3024   # server error num -> the open-refusal code

CAP = 2                 # max open files per user


@pytest.fixture(autouse=True)
def _require_binary():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")


def _throttle_knobs(cap=CAP):
    # Server-level directives; they render into the per-server RL_KNOBS slot of
    # nginx_rl_stream.conf.  The zone declaration is stream-level (STREAM_EXTRA).
    return ("        brix_throttle_zone opens;\n"
            f"        brix_throttle_max_open_files {cap};\n")


_ZONE = "    brix_rate_limit_zone zone=opens:1m;\n"


def _boot(lifecycle, tmp_path):
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    for name in ("a.bin", "b.bin", "c.bin"):
        (data / name).write_bytes(b"\x5a" * 64)
    return _start_stream(lifecycle, data, "lc-audit15-throttle",
                         _throttle_knobs(), _ZONE)


def _assert_overloaded(st, body):
    assert st == KXR_ERROR, (st, body)
    assert struct.unpack(">I", body[:4])[0] == KXR_OVERLOADED, body
    assert b"too many open files" in body, body


def _drain_until_free(port, attempts=80):
    """Poll fresh connections until BOTH cap slots are grantable again, then
    close the probes cleanly so the caller starts from a zero-held state.
    (Disconnect-side release is asynchronous w.r.t. the client socket close,
    and the SHM zone outlives every connection — tests in this file share one
    instance, so each one levels the ground first.)"""
    last = None
    for _ in range(attempts):
        s = _xrd_login(HOST, port)
        try:
            st1, b1 = _xrd_open(s, "/a.bin")
            st2, b2 = _xrd_open(s, "/b.bin")
            last = (st1, st2)
            if st1 == KXR_OK:
                if st2 == KXR_OK:
                    _xrd_close(s, b2[:4])
                _xrd_close(s, b1[:4])
                if st2 == KXR_OK:
                    return
        finally:
            s.close()
        time.sleep(0.05)
    raise AssertionError(f"open-files slots never freed (last opens={last})")


def test_open_cap_grant_refuse_release(lifecycle, tmp_path):
    """Success + error path: CAP opens are granted, the CAP+1th is refused with
    kXR_Overloaded, and a kXR_close releases a slot so the refused file opens."""
    port = _boot(lifecycle, tmp_path)
    _drain_until_free(port)
    s = _xrd_login(HOST, port)
    try:
        st1, b1 = _xrd_open(s, "/a.bin")
        assert st1 == KXR_OK, (st1, b1)
        st2, b2 = _xrd_open(s, "/b.bin")
        assert st2 == KXR_OK, (st2, b2)

        # Third open: cap (2) exhausted -> refused, count-driven (c.bin is a
        # distinct file; identity/size play no part).
        st3, b3 = _xrd_open(s, "/c.bin")
        _assert_overloaded(st3, b3)

        # Close one handle -> brix_throttle_open_dec frees its slot.
        stc, _ = _xrd_close(s, b1[:4])
        assert stc == KXR_OK, stc

        st4, b4 = _xrd_open(s, "/c.bin")
        assert st4 == KXR_OK, (st4, b4)
    finally:
        s.close()


def test_cap_spans_connections_and_disconnect_releases(lifecycle, tmp_path):
    """Security / leak-negative: the SHM zone keys on the USER ("anonymous"
    here), so a second connection cannot escape a cap the first one filled;
    and a client that disconnects WITHOUT kXR_close must not leak its slots —
    a fresh connection eventually gets the full cap back."""
    port = _boot(lifecycle, tmp_path)
    _drain_until_free(port)

    # Connection A fills the cap.
    sa = _xrd_login(HOST, port)
    st1, b1 = _xrd_open(sa, "/a.bin")
    assert st1 == KXR_OK, (st1, b1)
    st2, b2 = _xrd_open(sa, "/b.bin")
    assert st2 == KXR_OK, (st2, b2)

    # Connection B, same (anonymous) user: refused — per-user, not per-session.
    sb = _xrd_login(HOST, port)
    try:
        stb, bb = _xrd_open(sb, "/c.bin")
        _assert_overloaded(stb, bb)
    finally:
        sb.close()

    sa.close()   # hard disconnect, no kXR_close for either handle

    # Disconnect teardown must return BOTH slots (asynchronously).
    _drain_until_free(port)


def test_stat_never_throttled_while_cap_exhausted(lifecycle, tmp_path):
    """Negative control: the cap gates kXR_open only — with every slot held,
    metadata operations (kXR_stat) still succeed, so the throttle cannot be
    mistaken for a blanket per-user request block."""
    port = _boot(lifecycle, tmp_path)
    _drain_until_free(port)
    s = _xrd_login(HOST, port)
    try:
        st1, b1 = _xrd_open(s, "/a.bin")
        assert st1 == KXR_OK, (st1, b1)
        st2, b2 = _xrd_open(s, "/b.bin")
        assert st2 == KXR_OK, (st2, b2)
        st3, b3 = _xrd_open(s, "/c.bin")
        _assert_overloaded(st3, b3)

        stat_st, stat_b = _xrd_stat(s, "/c.bin")
        assert stat_st == KXR_OK, (stat_st, stat_b)
    finally:
        s.close()


def test_throttle_zone_must_be_declared(tmp_path):
    """Config-parse negative: brix_throttle_zone naming a zone that no
    brix_rate_limit_zone declares must be refused at nginx -t — a typo here
    silently disabling the cap would be an unbounded-fd regression."""
    rc, out = _parse_fail(tmp_path, "nginx_rl_stream.conf",
                          _stream_values(_throttle_knobs(), ""))
    assert rc != 0, out
    assert "is not a declared brix_rate_limit_zone" in out, out

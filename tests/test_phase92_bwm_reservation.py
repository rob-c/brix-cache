"""
test_phase92_bwm_reservation.py — end-to-end coverage for the phase-92 wiring of
the XrdBwm-style bandwidth-reservation engine (src/net/ratelimit/reservation.c)
into the root:// read-open path.

The engine itself (byte-precise grant/refuse/release, no over-commit, no
underflow) is unit-tested hermetically in tests/c/test_reservation.c. THIS file
exercises the live wire path that phase-92 added:

    brix_throttle_bandwidth_zone / brix_throttle_bandwidth_budget  (directives)
        -> brix_open_apply_throttle reserves the file size at kXR_open
        -> brix_free_fhandle releases the exact bytes at kXR_close / disconnect

A read open reserves its file size against the per-worker byte budget; when the
aggregate is exhausted the next open is refused with kXR_error/kXR_Overloaded,
and closing an outstanding handle returns its bytes so a reopen succeeds again.

The reservation registry is a per-WORKER static, so this instance runs with a
single worker (the template's default) and the whole file is serialised onto one
xdist worker via xdist_group so the acquire->refuse->release sequence is
deterministic across the parallel fleet.
"""

import socket
import struct
import time

import pytest

from settings import HOST
# Reuse the raw-XRootD wire helpers + the stream launcher from the phase-25
# rate-limit suite (login/open/recv-status share the exact same wire framing).
from test_phase25_ratelimit import (
    _start_stream,
    _xrd_login,
    _xrd_open,
    _xrd_recv_status,
)

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-bwm")]

# kXR wire constants (XProtocol.hh).
KXR_OK = 0
KXR_ERROR = 4003
KXR_CLOSE = 3003
KXR_OVERLOADED = 3024   # server error num -> EUSERS; the open-refusal code

FILE_BYTES = 300_000          # each read open reserves this many bytes
BUDGET = "400k"               # 409_600 bytes: one file fits, two do not


def _bwm_knobs():
    # Server-level throttle directives (NGX_STREAM_SRV_CONF) — they render into
    # the per-server RL_KNOBS slot of nginx_rl_stream.conf.
    return ("        brix_throttle_bandwidth_zone readpool;\n"
            f"        brix_throttle_bandwidth_budget {BUDGET};\n")


def _xrd_close(s, fhandle):
    # kXR_close = 3003; body: fhandle[4] fsize[8] reserved[4] = 16; no payload.
    body = fhandle[:4] + struct.pack(">q", 0) + b"\x00" * 4
    s.sendall(struct.pack(">BBH", 0, 1, KXR_CLOSE) + body + struct.pack(">I", 0))
    return _xrd_recv_status(s)


def _boot(lifecycle, tmp_path):
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    (data / "big.bin").write_bytes(b"\x5a" * FILE_BYTES)
    # A tiny file whose size never reserves anything measurable, used to prove
    # the budget-exhausted refusal is size-driven, not a blanket open block.
    (data / "tiny.bin").write_bytes(b"\x5a" * 16)
    port = _start_stream(lifecycle, data, "lc-bwm-reserve",
                         _bwm_knobs(), "")
    return port


def test_reservation_grant_refuse_release(lifecycle, tmp_path):
    """Success + error path: first read open is granted, a second open of the
    same file exhausts the budget and is refused, and closing the first handle
    releases its bytes so the reopen is granted again."""
    port = _boot(lifecycle, tmp_path)
    s = _xrd_login(HOST, port)
    try:
        # (1) First open: reserves 300000 <= 409600 -> granted.
        st1, b1 = _xrd_open(s, "/big.bin")
        assert st1 == KXR_OK, (st1, b1)
        fh1 = b1[:4]

        # (2) Second open of the same file: another 300000 -> 600000 > 409600,
        #     so the aggregate is exhausted and the open is refused.
        st2, b2 = _xrd_open(s, "/big.bin")
        assert st2 == KXR_ERROR, (st2, b2)
        assert struct.unpack(">I", b2[:4])[0] == KXR_OVERLOADED, b2

        # (3) Close the first handle -> brix_free_fhandle returns its 300000
        #     bytes to the budget.
        stc, _ = _xrd_close(s, fh1)
        assert stc == KXR_OK, stc

        # (4) Reopen: the freed budget now admits the file again.
        st3, b3 = _xrd_open(s, "/big.bin")
        assert st3 == KXR_OK, (st3, b3)
    finally:
        s.close()


def test_reservation_release_on_disconnect(lifecycle, tmp_path):
    """Security / leak-negative: a client that opens a budget-filling file and
    then DISCONNECTS without a clean kXR_close must not leak its reservation.
    brix_free_fhandle runs on disconnect (via brix_close_all_files), so a fresh
    connection can immediately reserve the same budget again."""
    port = _boot(lifecycle, tmp_path)

    # Connection A fills the budget, then drops without closing the handle.
    sa = _xrd_login(HOST, port)
    sta, ba = _xrd_open(sa, "/big.bin")
    assert sta == KXR_OK, (sta, ba)
    # A second open on the SAME connection is refused (budget full) — proves the
    # first grant is really held before we test the disconnect release.
    st_full, b_full = _xrd_open(sa, "/big.bin")
    assert st_full == KXR_ERROR, (st_full, b_full)
    assert struct.unpack(">I", b_full[:4])[0] == KXR_OVERLOADED, b_full
    sa.close()  # hard disconnect, no kXR_close

    # Peer-close teardown is asynchronous w.r.t. the client socket close, so a
    # fresh connection must eventually — not necessarily instantly — find the
    # budget freed.
    _drain_until_reservable(port)


def _drain_until_reservable(port, attempts=50):
    """Poll a fresh connection until a full-budget open is admitted again."""
    last = None
    for _ in range(attempts):
        s = _xrd_login(HOST, port)
        try:
            st, b = _xrd_open(s, "/big.bin")
            last = (st, b)
            if st == KXR_OK:
                return
        finally:
            s.close()
        time.sleep(0.05)
    raise AssertionError(
        f"budget never freed after disconnect (last open status={last})")


def test_reservation_tiny_file_never_refused(lifecycle, tmp_path):
    """Negative control: a file far smaller than the budget is always admitted,
    and repeated opens of it never trip the exhaustion refusal — the limit is
    driven by reserved file SIZE, not by open count."""
    port = _boot(lifecycle, tmp_path)
    s = _xrd_login(HOST, port)
    try:
        for i in range(8):
            st, b = _xrd_open(s, "/tiny.bin")
            assert st == KXR_OK, (i, st, b)
    finally:
        s.close()
